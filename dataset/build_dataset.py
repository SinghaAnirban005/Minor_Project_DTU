#!/usr/bin/env python3
"""
build_dataset.py  --  Stage 6 of the project plan: "Dataset Creation"

WHAT THIS STAGE IS FOR
-------------------------
Stages 4 and 5 gave us raw packet captures (.pcap files) -- but a machine
learning model can't read raw packets directly. It needs a table: one row
per packet, with a handful of numeric "features" describing that packet,
plus a label saying whether it was normal (0) or part of an attack (1).
That's what this script builds.

THE FEATURES WE EXTRACT (and why each one matters)
-------------------------------------------------------
For every ARP packet, in time order, we compute:

  is_reply            : 1 if this is an ARP reply ("is-at"), 0 if it's a
                         request ("who-has"). Spoofing attacks work by
                         sending *unsolicited* replies, so replies are
                         where the interesting behaviour lives.

  is_gratuitous        : 1 if the packet's sender IP equals its target IP.
                         A genuine "gratuitous ARP" announcement looks like
                         this too, but attackers also send replies that
                         were never asked for -- we approximate "nobody
                         asked for this" further down.

  claimed_ip_mac_count : running count, so far in this capture, of how many
                         DIFFERENT MAC addresses have claimed to own this
                         packet's source IP. This is the single most
                         important feature: a real IP has exactly one real
                         MAC. Stage 5 showed us that when spoofing happens,
                         the SAME IP (e.g. the gateway) gets claimed by TWO
                         different MACs. Normal traffic: this number stays
                         at 1. Spoofed traffic: this number jumps to 2+.

  mac_changed_from_last : 1 if this packet's (IP -> MAC) pairing is
                         DIFFERENT from the last mapping we saw for that
                         same IP. Catches the exact moment a forged reply
                         contradicts what we'd already learned.

  pkt_rate_last_5s     : how many ARP packets this same source IP has sent
                         in the last 5 seconds. Our attack script
                         re-poisons every couple of seconds -- a much
                         higher, steadier rate than normal, occasional
                         "who has your IP?" questions.

  time_since_last_pkt  : seconds since this source IP's previous ARP
                         packet. Spoofing floods tend to have short, very
                         regular gaps; normal traffic is sporadic.

label                 : 0 = normal (from a *_normal.pcap file)
                         1 = attack (from a *_attack.pcap file)
                         This is the "answer key" the model will learn
                         to predict from the features above.

WHERE THE LABELS COME FROM
------------------------------
We don't have to guess which packets are malicious -- we already KNOW,
because of how we generated them: anything from Stage 4's *_normal.pcap
files is genuinely normal traffic, and anything from Stage 5's
*_attack.pcap files happened while the attack was running. This is called
"ground truth" labelling, and it's only possible because we built the
attack ourselves in a lab instead of trying to label real-world traffic
by hand.

HOW TO RUN IT
----------------
No Mininet/root needed for this stage -- it just reads the .pcap files
Stage 4 and 5 already created:

    cd arp-spoofing-detector/dataset
    python3 build_dataset.py

OUTPUT
--------
    dataset/arp_dataset.csv   -- one row per ARP packet, ready for Stage 7-9
"""

import glob
import os

import pandas as pd
from scapy.all import ARP, rdpcap

CAPTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture")
OUTPUT_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arp_dataset.csv")

RATE_WINDOW_SECONDS = 5.0   # how far back pkt_rate_last_5s looks


def load_arp_packets(pcap_path, label):
    """Reads one .pcap file and returns a list of raw ARP packet facts
    (not yet the final features -- just what we can read straight off
    each packet). label is 0 for normal, 1 for attack."""
    records = []
    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        return records

    for pkt in packets:
        if ARP not in pkt:
            continue
        arp = pkt[ARP]
        records.append({
            "time": float(pkt.time),
            "src_ip": arp.psrc,
            "src_mac": arp.hwsrc,
            "dst_ip": arp.pdst,
            "op": arp.op,              # 1 = who-has (request), 2 = is-at (reply)
            "label": label,
            "source_file": os.path.basename(pcap_path),
        })
    return records


def collect_all_packets():
    records = []
    for pcap_path in sorted(glob.glob(os.path.join(CAPTURE_DIR, "*_normal.pcap"))):
        records.extend(load_arp_packets(pcap_path, label=0))
    for pcap_path in sorted(glob.glob(os.path.join(CAPTURE_DIR, "*_attack.pcap"))):
        records.extend(load_arp_packets(pcap_path, label=1))
    return records


def engineer_features(records):
    """Turns the raw per-packet facts into the ML-ready feature table
    described at the top of this file. Processes packets in time order,
    tracking a little bit of running state (seen IP->MAC mappings, recent
    packet timestamps per IP) exactly like our real-time detector will
    have to do later in Stage 10-11 -- so this logic doubles as a preview
    of how that stage works."""
    records.sort(key=lambda r: r["time"])

    seen_macs_for_ip = {}     # src_ip -> set of MACs ever claimed for it
    last_mapping_for_ip = {}  # src_ip -> most recent MAC claimed for it
    last_seen_time_for_ip = {}  # src_ip -> timestamp of its previous packet
    recent_times_for_ip = {}  # src_ip -> list of recent packet timestamps

    rows = []
    for r in records:
        ip, mac, t = r["src_ip"], r["src_mac"], r["time"]

        # --- claimed_ip_mac_count ---
        macs_seen = seen_macs_for_ip.setdefault(ip, set())
        macs_seen.add(mac)
        claimed_ip_mac_count = len(macs_seen)

        # --- mac_changed_from_last ---
        previous_mac = last_mapping_for_ip.get(ip)
        mac_changed_from_last = int(previous_mac is not None and previous_mac != mac)
        last_mapping_for_ip[ip] = mac

        # --- time_since_last_pkt ---
        previous_time = last_seen_time_for_ip.get(ip)
        time_since_last_pkt = (t - previous_time) if previous_time is not None else -1.0
        last_seen_time_for_ip[ip] = t

        # --- pkt_rate_last_5s ---
        recent = recent_times_for_ip.setdefault(ip, [])
        recent.append(t)
        cutoff = t - RATE_WINDOW_SECONDS
        while recent and recent[0] < cutoff:
            recent.pop(0)
        pkt_rate_last_5s = len(recent)

        rows.append({
            "time": t,
            "src_ip": ip,
            "src_mac": mac,
            "dst_ip": r["dst_ip"],
            "is_reply": int(r["op"] == 2),
            "is_gratuitous": int(ip == r["dst_ip"]),
            "claimed_ip_mac_count": claimed_ip_mac_count,
            "mac_changed_from_last": mac_changed_from_last,
            "pkt_rate_last_5s": pkt_rate_last_5s,
            "time_since_last_pkt": time_since_last_pkt,
            "label": r["label"],
            "source_file": r["source_file"],
        })

    return rows


def run():
    print(f"*** Reading captures from {CAPTURE_DIR}")
    records = collect_all_packets()
    print(f"*** Found {len(records)} ARP packets total "
          f"({sum(1 for r in records if r['label'] == 0)} normal, "
          f"{sum(1 for r in records if r['label'] == 1)} attack)")

    if not records:
        print("ERROR: no ARP packets found. Have you run Stage 4 and Stage 5 "
              "(generate_normal_traffic.py and simulate_attack.py) yet?")
        return

    rows = engineer_features(records)
    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_CSV, index=False)

    print(f"*** Saved {len(df)} rows to {OUTPUT_CSV}")
    print("\n*** Label balance:")
    print(df["label"].value_counts().rename({0: "normal", 1: "attack"}))
    print("\n*** First few rows:")
    print(df.head(10).to_string(index=False))


if __name__ == "__main__":
    run()