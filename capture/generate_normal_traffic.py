#!/usr/bin/env python3
"""
generate_normal_traffic.py  --  Stage 4 of the project plan:
"Normal ARP Traffic Generation"

WHAT "NORMAL ARP TRAFFIC" MEANS
---------------------------------
Whenever one computer wants to talk to another on the same LAN, it first
has to ask "who has this IP address? tell me your MAC address" -- that's
an ARP request, sent to everyone (broadcast). The computer that owns that
IP replies, truthfully, with its own real MAC address -- that's an ARP
reply. This question-and-answer pair, done honestly, is "normal" ARP
traffic. It's exactly what Stage 5's attack is going to fake.

WHAT THIS SCRIPT ACTUALLY DOES
--------------------------------
1. Builds the Stage 3 virtual LAN (gateway, victim1, victim2, attacker).
2. Starts a packet capture (tcpdump, filtered to ARP only) on every host,
   so we record ARP traffic exactly as each machine would see it arrive
   on its own network card -- which is also how our real-time detector
   will see traffic later (Stage 10).
3. For a set amount of time, repeatedly picks two of the three "normal"
   hosts (gateway, victim1, victim2 -- NOT the attacker, who stays quiet
   until Stage 5) and makes one ask the other "who has your IP?" using
   `arping`. The OS answers truthfully on its own -- we don't have to
   fake anything here, because this traffic IS genuine.
4. Stops every capture and leaves one .pcap file per host in capture/,
   ready for Stage 6 to combine and label as the "normal" class.

HOW TO RUN IT
--------------
Same requirement as Stage 3: real root access to Mininet, so run this on
your Ubuntu machine/VM, not inside a restricted sandbox.

    cd arp-spoofing-detector/capture
    sudo python3 generate_normal_traffic.py

Optional: change how long it runs and how busy it is at the top of the
file (DURATION_SECONDS, MIN/MAX_GAP_SECONDS).

WHAT YOU SHOULD SEE AFTERWARDS
---------------------------------
Four new files in capture/:
    gateway_normal.pcap   victim1_normal.pcap
    victim2_normal.pcap   attacker_normal.pcap   (near-empty -- attacker
                                                    stayed silent, as expected)

You can inspect any of them with:  sudo tcpdump -r capture/victim1_normal.pcap -n
"""

import os
import random
import shutil
import sys
import time

# So this script can be run directly without installing the project as a
# package: let it find net_builder.py, which lives next door in topology/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "topology"))
from net_builder import build_network, start_and_get_hosts   # noqa: E402

CAPTURE_DIR = os.path.dirname(os.path.abspath(__file__))

DURATION_SECONDS = 60      # how long to generate traffic for
MIN_GAP_SECONDS = 0.5      # shortest pause between ARP exchanges
MAX_GAP_SECONDS = 2.0      # longest pause between ARP exchanges

# Only these three take part in "normal" traffic -- the attacker stays
# silent in this stage, exactly like a quiet machine that hasn't attacked yet.
NORMAL_HOSTS = ["gateway", "victim1", "victim2"]


def start_capture(hosts):
    """Starts a background tcpdump on every host, ARP packets only."""
    for name, host in hosts.items():
        pcap_path = os.path.join(CAPTURE_DIR, f"{name}_normal.pcap")
        iface = f"{host.name}-eth0"
        # -U = flush to disk as packets arrive, so the file is readable
        #      even if we stop the capture abruptly.
        # & at the end = run in the background so the script keeps going.
        host.cmd(f"tcpdump -i {iface} arp -w {pcap_path} -U > /dev/null 2>&1 &")
    print(f"*** Capturing ARP traffic for every host into {CAPTURE_DIR}/*.pcap")


def stop_capture(hosts):
    """Stops the background tcpdump processes started above."""
    for host in hosts.values():
        host.cmd("pkill -f 'tcpdump -i'")
    time.sleep(1)   # give tcpdump a moment to flush and exit cleanly


def generate_traffic(hosts):
    """Repeatedly has one normal host ask another 'who has your IP?'."""
    print(f"*** Generating normal ARP traffic for {DURATION_SECONDS} seconds...")
    end_time = time.time() + DURATION_SECONDS
    exchange_count = 0

    while time.time() < end_time:
        asker_name, target_name = random.sample(NORMAL_HOSTS, 2)
        asker = hosts[asker_name]
        target_ip = target_name_to_ip(target_name)
        iface = f"{asker.name}-eth0"

        # -c 1  : send exactly one ARP request
        # -w 1  : wait up to 1 second for the reply
        # -f    : stop as soon as a reply arrives (no need to wait longer)
        asker.cmd(f"arping -c 1 -w 1 -f -I {iface} {target_ip} > /dev/null 2>&1")

        exchange_count += 1
        print(f"    [{exchange_count}] {asker_name} asked 'who has {target_ip}?' "
              f"({target_name})")

        time.sleep(random.uniform(MIN_GAP_SECONDS, MAX_GAP_SECONDS))

    print(f"*** Done. Generated {exchange_count} normal ARP request/reply exchanges.")


def target_name_to_ip(name):
    from net_builder import HOSTS
    for info in HOSTS.values():
        if info["name"] == name:
            return info["ip"].split("/")[0]
    raise ValueError(f"Unknown host name: {name}")


def check_required_tools():
    """Fails loudly, up front, instead of silently producing empty/broken
    captures later. host.cmd() output goes nowhere useful on its own, so a
    missing tool otherwise just looks like 'no traffic happened' with no
    clue why -- this catches that before we even build the network."""
    required = ["tcpdump", "arping"]
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        print("ERROR: missing required tool(s): " + ", ".join(missing))
        print("Install them with:")
        print(f"    sudo apt-get install -y {'iputils-arping' if 'arping' in missing else ''} "
              f"{'tcpdump' if 'tcpdump' in missing else ''}".replace("  ", " ").strip())
        sys.exit(1)


def check_captures_got_traffic():
    """Warns immediately if every capture came back empty, instead of
    leaving you to discover it minutes later with tcpdump -r."""
    sizes = {}
    for name in [info["name"] for info in __import__("net_builder").HOSTS.values()]:
        path = os.path.join(CAPTURE_DIR, f"{name}_normal.pcap")
        sizes[name] = os.path.getsize(path) if os.path.exists(path) else 0

    # An empty pcap is ~24 bytes (just the file header, no packets).
    if all(size <= 24 for size in sizes.values()):
        print("\nWARNING: every capture file is empty (no packets recorded).")
        print("Something likely failed silently. Things to check:")
        print("  1. Re-run 'sudo mn -c' to clear any leftover Mininet state, then try again.")
        print("  2. Confirm arping actually works: "
              "sudo python3 -c \"from net_builder import *; n=build_network(); "
              "h=start_and_get_hosts(n); print(h['victim1'].cmd('arping -c1 -I h2-eth0 10.0.0.3')); n.stop()\"")
        print("  3. Make sure Open vSwitch is running: sudo service openvswitch-switch start")
    else:
        print("\nCapture sizes (bytes):", sizes)


def run():
    check_required_tools()
    net = build_network()
    hosts = start_and_get_hosts(net)
    try:
        start_capture(hosts)
        time.sleep(1)   # let tcpdump finish starting up before we send traffic
        generate_traffic(hosts)
    finally:
        stop_capture(hosts)
        net.stop()
    check_captures_got_traffic()


if __name__ == "__main__":
    run()