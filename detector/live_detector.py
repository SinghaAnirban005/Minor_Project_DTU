#!/usr/bin/env python3
"""
live_detector.py  --  Stages 10-13 of the project plan:
"Real-Time Packet Sniffing", "Live Feature Extraction", "Live Detection",
and "Automated Blocking"

WHAT THIS FILE DOES
----------------------
Every stage before this one worked on SAVED packet files (.pcap). This is
the real thing: a daemon that watches ARP traffic AS IT HAPPENS on one
network interface, and for every single packet that arrives:

  1. Computes the exact same 6 features build_dataset.py computed for the
     training data (Stage 6) -- just live, one packet at a time, instead
     of all at once from a file.
  2. Feeds those features into the model trained in Stage 7-9
     (model/arp_model.pkl) and asks it: normal, or attack?
  3. If the model says "attack", it does two things immediately:
       a. Logs the detection (who, when, which features triggered it) to
          logs/detections.csv
       b. Blocks that attacker's traffic using nftables -- a firewall
          rule that drops every packet from that MAC address at the
          network interface, not just its ARP packets.

WHY WE COMPUTE FEATURES "LIVE" INSTEAD OF REUSING STAGE 6'S CODE DIRECTLY
----------------------------------------------------------------------------
Stage 6 could look at a whole file at once. A live detector can only ever
see packets one at a time, in order, as they arrive -- it can never look
"ahead". So this file keeps the same kind of running memory (which MACs
have claimed which IP, how recently each IP has been seen) that Stage 6
built, but updates it one packet at a time, exactly as a real deployed
detector would have to.

WHY BLOCK BY MAC ADDRESS, AND HOW
--------------------------------------
Once we're confident a machine is spoofing, the most direct defence is to
stop listening to it entirely -- not just its ARP packets, but everything
it sends, since by this point it has already shown it isn't trustworthy.
nftables (Linux's firewall) can do this at the network card level, before
packets even reach the rest of the system:

    nft add rule netdev filter ingress ether saddr <attacker MAC> drop

This script creates that firewall table once at startup, then adds one
rule per attacker MAC the moment it's detected.

HOW TO RUN IT
----------------
This watches ONE interface, so you run it ON the machine/host you want to
protect. Needs root, same as every Mininet-based stage:

    sudo python3 live_detector.py --iface <interface-name>

In isolation that's just "give it an interface name" -- but normally you
won't run this by hand like that. See run_detection_demo.py in this same
folder for a script that builds the whole virtual network, starts this
detector watching the gateway's interface, launches Stage 5's attack
against it, and shows the detector catching and blocking it live.

To stop it: Ctrl+C (it cleans up its own firewall rules on exit).
"""

import argparse
import csv
import os
import sys
import time
import warnings

import joblib
import pandas as pd
from scapy.all import ARP, sniff

# scikit-learn warns that we're passing a plain list instead of a
# DataFrame with named columns (it was trained on one in train_model.py).
# Harmless here -- we build the DataFrame with the right column names
# below precisely so the model sees the same shape it was trained on.
warnings.filterwarnings("ignore", message="X does not have valid feature names")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model"))
from train_model import FEATURE_COLUMNS   # noqa: E402 -- keeps the live feature
                                            # list identical to what the model
                                            # was actually trained on

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model", "arp_model.pkl")
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
DETECTIONS_LOG = os.path.join(LOG_DIR, "detections.csv")

RATE_WINDOW_SECONDS = 5.0   # must match build_dataset.py's RATE_WINDOW_SECONDS
NFT_TABLE = "arp_guard"     # our own firewall table name, so we don't touch
                            # any other rules already on the system


class LiveFeatureTracker:
    """The 'running memory' a live detector needs, since (unlike Stage 6)
    it can only ever see packets one at a time, as they arrive -- never
    the whole file at once. Mirrors build_dataset.py's engineer_features()
    logic exactly, just updated incrementally."""

    def __init__(self):
        self.seen_macs_for_ip = {}
        self.last_mapping_for_ip = {}
        self.last_seen_time_for_ip = {}
        self.recent_times_for_ip = {}

    def compute_features(self, src_ip, src_mac, dst_ip, is_reply, now):
        macs_seen = self.seen_macs_for_ip.setdefault(src_ip, set())
        macs_seen.add(src_mac)
        claimed_ip_mac_count = len(macs_seen)

        previous_mac = self.last_mapping_for_ip.get(src_ip)
        mac_changed_from_last = int(previous_mac is not None and previous_mac != src_mac)
        self.last_mapping_for_ip[src_ip] = src_mac

        previous_time = self.last_seen_time_for_ip.get(src_ip)
        time_since_last_pkt = (now - previous_time) if previous_time is not None else -1.0
        self.last_seen_time_for_ip[src_ip] = now

        recent = self.recent_times_for_ip.setdefault(src_ip, [])
        recent.append(now)
        cutoff = now - RATE_WINDOW_SECONDS
        while recent and recent[0] < cutoff:
            recent.pop(0)
        pkt_rate_last_5s = len(recent)

        return {
            "is_reply": int(is_reply),
            "is_gratuitous": int(src_ip == dst_ip),
            "claimed_ip_mac_count": claimed_ip_mac_count,
            "mac_changed_from_last": mac_changed_from_last,
            "pkt_rate_last_5s": pkt_rate_last_5s,
            "time_since_last_pkt": time_since_last_pkt,
        }


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    is_new = not os.path.exists(DETECTIONS_LOG)
    f = open(DETECTIONS_LOG, "a", newline="")
    writer = csv.writer(f)
    if is_new:
        writer.writerow(["timestamp", "src_ip", "src_mac", "prediction", *FEATURE_COLUMNS, "action"])
    return f, writer


def setup_firewall(iface):
    """Creates our own nftables table/chain, hooked at the network card
    level (netdev, ingress) on this one interface. Running these commands
    again on an already-set-up system is safe -- 'nft add table/chain' is
    idempotent (it won't error or duplicate if it already exists)."""
    commands = [
        f"nft add table netdev {NFT_TABLE}",
        f"nft 'add chain netdev {NFT_TABLE} ingress "
        f"{{ type filter hook ingress device {iface} priority 0 ; }}'",
    ]
    for cmd in commands:
        result = os.system(cmd + " 2>/tmp/nft_setup_err.txt")
        if result != 0:
            print(f"WARNING: firewall setup command failed: {cmd}")
            print("         (see /tmp/nft_setup_err.txt). Detection will still "
                  "run and log, but automatic blocking may not actually work. "
                  "This usually means nftables' netdev/ingress support isn't "
                  "available in this environment.")
            return False
    return True


def block_mac(mac, firewall_ready):
    if not firewall_ready:
        return False
    cmd = f"nft add rule netdev {NFT_TABLE} ingress ether saddr {mac} drop 2>/tmp/nft_block_err.txt"
    return os.system(cmd) == 0


def teardown_firewall():
    os.system(f"nft delete table netdev {NFT_TABLE} 2>/dev/null")


def run(iface, duration):
    print(f"*** Loading model from {MODEL_PATH}")
    if not os.path.exists(MODEL_PATH):
        print("ERROR: no trained model found. Run model/train_model.py first.")
        return
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    print(f"*** Using {bundle['model_name']}, features: {bundle['features']}")

    tracker = LiveFeatureTracker()
    log_file, log_writer = setup_logging()
    firewall_ready = setup_firewall(iface)
    blocked_macs = set()   # so we don't spam duplicate block rules for the same MAC

    stats = {"total": 0, "flagged": 0, "blocked": 0}

    def handle_packet(pkt):
        if ARP not in pkt:
            return
        arp = pkt[ARP]
        now = time.time()
        stats["total"] += 1

        features = tracker.compute_features(
            src_ip=arp.psrc, src_mac=arp.hwsrc, dst_ip=arp.pdst,
            is_reply=(arp.op == 2), now=now,
        )
        feature_row = pd.DataFrame([[features[col] for col in FEATURE_COLUMNS]],
                                    columns=FEATURE_COLUMNS)
        prediction = int(model.predict(feature_row)[0])

        action = "none"
        if prediction == 1:
            stats["flagged"] += 1
            print(f"[DETECT] {arp.psrc} ({arp.hwsrc}) flagged as ATTACK "
                  f"-- claimed_ip_mac_count={features['claimed_ip_mac_count']}")
            if arp.hwsrc not in blocked_macs:
                success = block_mac(arp.hwsrc, firewall_ready)
                if success:
                    blocked_macs.add(arp.hwsrc)
                    stats["blocked"] += 1
                    action = "blocked"
                    print(f"[BLOCK]  firewall rule added for MAC {arp.hwsrc}")
                else:
                    action = "block_failed"
            else:
                action = "already_blocked"

        log_writer.writerow([now, arp.psrc, arp.hwsrc, prediction,
                              *[features[c] for c in FEATURE_COLUMNS], action])
        log_file.flush()

    print(f"*** Watching {iface} for ARP traffic "
          f"({'forever, Ctrl+C to stop' if not duration else f'{duration}s'})...")
    try:
        sniff(iface=iface, filter="arp", prn=handle_packet, store=False,
              timeout=duration if duration else None)
    except KeyboardInterrupt:
        pass
    finally:
        log_file.close()
        teardown_firewall()
        print(f"\n*** Stopped. Saw {stats['total']} ARP packets, "
              f"flagged {stats['flagged']}, blocked {stats['blocked']} unique MAC(s).")
        print(f"*** Full log: {DETECTIONS_LOG}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", required=True, help="interface to watch, e.g. h1-eth0")
    parser.add_argument("--duration", type=float, default=0,
                         help="seconds to run (0 = run until Ctrl+C, default)")
    args = parser.parse_args()
    run(args.iface, args.duration)