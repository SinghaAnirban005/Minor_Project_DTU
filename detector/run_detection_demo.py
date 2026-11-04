#!/usr/bin/env python3
"""
run_detection_demo.py  --  the end-to-end test for Stages 10-13.

WHAT THIS SCRIPT DOES
------------------------
Puts everything together in one run:

  1. Builds the same virtual LAN as every previous stage.
  2. Starts live_detector.py watching the GATEWAY's own network interface
     -- this is the "protected" machine.
  3. A few seconds later, launches Stage 5's real attack (arp_spoof.py)
     from the attacker host, targeting victim1 and the gateway, exactly
     like simulate_attack.py did.
  4. Lets it run for a while, then stops everything and shows you the
     detector's own log of what it saw and did.

This is the moment that proves the whole project actually works end to
end: traffic -> features -> trained model -> live decision -> automatic
block, not just separate pieces tested in isolation.

HOW TO RUN IT
----------------
Needs the trained model from Stage 7-9 to already exist
(model/arp_model.pkl), and real root/Mininet access:

    sudo mn -c
    cd arp-spoofing-detector/detector
    sudo python3 run_detection_demo.py

WHAT TO LOOK FOR
--------------------
While it runs, you'll see the detector print lines like:

    [DETECT] 10.0.0.2 (6a:43:9d:a3:b6:5d) flagged as ATTACK -- claimed_ip_mac_count=2
    [BLOCK]  firewall rule added for MAC 6a:43:9d:a3:b6:5d

That's the whole pipeline working live: a forged packet arrived, the
model recognised the pattern, and a firewall rule went up automatically
-- all without any of us telling it "this one is the attacker" by hand.

Afterwards, check the full log:

    cat ../logs/detections.csv

Every row is one ARP packet the detector saw, its features, its
prediction, and what it did about it.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "topology"))
from net_builder import build_network, start_and_get_hosts, HOSTS   # noqa: E402

DETECTOR_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_detector.py")
ATTACK_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attack", "arp_spoof.py")
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")

PROTECTED_HOST = "gateway"   # whose interface the detector watches
ATTACK_VICTIM = "victim1"
ATTACK_GATEWAY = "gateway"
RUN_SECONDS = 25


def ip_for(name):
    for info in HOSTS.values():
        if info["name"] == name:
            return info["ip"].split("/")[0]
    raise ValueError(f"Unknown host name: {name}")


def run():
    if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model", "arp_model.pkl")):
        print("ERROR: model/arp_model.pkl not found. Run model/train_model.py first.")
        return

    # The '> logs/....txt' redirects below are run by the shell BEFORE
    # python even starts -- if this folder doesn't already exist, the
    # shell silently fails to create the file and the whole command never
    # runs at all (no error, no output, nothing). Creating it here
    # guarantees it exists before that ever happens.
    os.makedirs(LOG_DIR, exist_ok=True)

    net = build_network()
    hosts = start_and_get_hosts(net)
    try:
        protected = hosts[PROTECTED_HOST]
        iface = f"{protected.name}-eth0"

        print(f"*** Starting live_detector.py on {PROTECTED_HOST} ({iface})")
        protected.cmd(
            f"python3 {DETECTOR_SCRIPT} --iface {iface} --duration {RUN_SECONDS} "
            f"> {LOG_DIR}/live_detector_stdout.txt 2>&1 &"
        )
        time.sleep(2)   # let the detector finish its firewall setup before the attack starts

        attacker = hosts["attacker"]
        attacker_iface = f"{attacker.name}-eth0"
        victim_ip = ip_for(ATTACK_VICTIM)
        gateway_ip = ip_for(ATTACK_GATEWAY)
        print(f"*** Launching the attack: {ATTACK_VICTIM} <-> {ATTACK_GATEWAY}")
        attacker.cmd(
            f"python3 {ATTACK_SCRIPT} --iface {attacker_iface} "
            f"--victim-ip {victim_ip} --gateway-ip {gateway_ip} "
            f"--interval 2 --duration {RUN_SECONDS - 5} "
            f"> {LOG_DIR}/attack_stdout.txt 2>&1 &"
        )

        print(f"*** Running for {RUN_SECONDS} seconds -- watch for [DETECT] / [BLOCK] lines above...")
        for remaining in range(RUN_SECONDS, 0, -5):
            time.sleep(min(5, remaining))
        time.sleep(2)   # let the detector finish logging and tear down its firewall rules
    finally:
        net.stop()

    print("\n*** Done. Detector's own console output:")
    stdout_path = os.path.join(LOG_DIR, "live_detector_stdout.txt")
    if os.path.exists(stdout_path):
        with open(stdout_path) as f:
            print(f.read())
    print(f"*** Full detection log: {os.path.join(LOG_DIR, 'detections.csv')}")


if __name__ == "__main__":
    run()