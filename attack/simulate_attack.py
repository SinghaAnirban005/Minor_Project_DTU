#!/usr/bin/env python3
"""
simulate_attack.py  --  Stage 5 of the project plan:
"ARP Spoofing Attack Simulation"

WHAT THIS SCRIPT DOES
------------------------
1. Builds the same Stage 3 virtual LAN.
2. Starts a packet capture (ARP only) on every host, same as Stage 4,
   except files are now named *_attack.pcap instead of *_normal.pcap.
3. Launches arp_spoof.py on the ATTACKER host, targeting victim1 and the
   gateway -- this is the actual attack from the previous file.
4. While the attack runs, victim1 and the gateway keep doing ordinary
   things (a few pings) so the capture contains a realistic mix, not just
   silence plus forged packets.
5. Stops everything and leaves one .pcap file per host in capture/,
   ready for Stage 6 to combine with the Stage 4 captures and label as
   the "malicious" class.

HOW TO RUN IT
----------------
Same requirement as every stage so far -- real root access to Mininet:

    cd arp-spoofing-detector/attack
    sudo python3 simulate_attack.py

WHAT TO CHECK AFTERWARDS
----------------------------
    sudo tcpdump -r ../capture/victim1_attack.pcap -n

On a genuine testbed you should see a MIX of:
  - real ARP exchanges (victim1 <-> gateway doing normal pings)
  - repeated forged replies where the SAME IP (e.g. 10.0.0.1, the gateway)
    suddenly claims TWO DIFFERENT MAC addresses -- the real one and the
    attacker's. That contradiction (one IP, multiple MACs claimed) is
    exactly the signal Stage 6-9 will teach the ML model to recognise.

A quick way to see the contradiction yourself:

    sudo tcpdump -r ../capture/victim1_attack.pcap -n | grep "is-at"

Look at all the "is-at" lines for 10.0.0.1 (the gateway) -- if the attack
worked, you'll see more than one MAC address claimed for that same IP.
"""

import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "topology"))
from net_builder import build_network, start_and_get_hosts, HOSTS   # noqa: E402

CAPTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture")
ATTACK_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arp_spoof.py")

DURATION_SECONDS = 30       # how long the attack runs
POISON_INTERVAL = 2.0       # seconds between re-poisoning rounds

ATTACK_VICTIM = "victim1"   # which host gets attacked
ATTACK_GATEWAY = "gateway"  # the other end of the forged man-in-the-middle


def check_required_tools():
    required = ["tcpdump"]
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        print("ERROR: missing required tool(s): " + ", ".join(missing))
        print(f"Install with: sudo apt-get install -y {' '.join(missing)}")
        sys.exit(1)
    try:
        import scapy  # noqa: F401
    except ImportError:
        print("ERROR: the 'scapy' Python package isn't installed.")
        print("Install with: pip3 install --break-system-packages scapy")
        sys.exit(1)


def ip_for(name):
    for info in HOSTS.values():
        if info["name"] == name:
            return info["ip"].split("/")[0]
    raise ValueError(f"Unknown host name: {name}")


def start_capture(hosts):
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    for name, host in hosts.items():
        pcap_path = os.path.join(CAPTURE_DIR, f"{name}_attack.pcap")
        iface = f"{host.name}-eth0"
        host.cmd(f"tcpdump -i {iface} arp -w {pcap_path} -U > /dev/null 2>&1 &")
    print(f"*** Capturing ARP traffic for every host into {CAPTURE_DIR}/*_attack.pcap")


def stop_capture(hosts):
    for host in hosts.values():
        host.cmd("pkill -f 'tcpdump -i'")
    time.sleep(1)


def generate_background_normal_activity(hosts):
    """A few genuine pings between victim1 and the gateway, running
    alongside the attack, so the capture isn't JUST forged packets --
    a real attack happens while the network is still being used normally."""
    victim = hosts[ATTACK_VICTIM]
    victim.cmd(f"ping -c {max(1, int(DURATION_SECONDS // 5))} -i 5 "
               f"{ip_for(ATTACK_GATEWAY)} > /dev/null 2>&1 &")


def launch_attack(hosts):
    attacker = hosts["attacker"]
    iface = f"{attacker.name}-eth0"
    victim_ip = ip_for(ATTACK_VICTIM)
    gateway_ip = ip_for(ATTACK_GATEWAY)

    print(f"*** Launching ARP spoofing attack: attacker targets "
          f"{ATTACK_VICTIM} ({victim_ip}) <-> {ATTACK_GATEWAY} ({gateway_ip})")

    cmd = (
        f"python3 {ATTACK_SCRIPT} --iface {iface} "
        f"--victim-ip {victim_ip} --gateway-ip {gateway_ip} "
        f"--interval {POISON_INTERVAL} --duration {DURATION_SECONDS}"
    )
    # Run it and stream its own [arp_spoof] print statements to our terminal
    # so you can watch the attack happen, not just trust it silently worked.
    attacker.cmd(f"{cmd} 2>&1 | tee {CAPTURE_DIR}/attack_log.txt &")


def check_captures_got_traffic():
    sizes = {}
    for info in HOSTS.values():
        name = info["name"]
        path = os.path.join(CAPTURE_DIR, f"{name}_attack.pcap")
        sizes[name] = os.path.getsize(path) if os.path.exists(path) else 0
    if all(size <= 24 for size in sizes.values()):
        print("\nWARNING: every attack capture is empty. Check:")
        print("  1. sudo mn -c   (clear leftover Mininet state, then retry)")
        print("  2. sudo service openvswitch-switch start")
        print("  3. cat capture/attack_log.txt for errors from arp_spoof.py")
    else:
        print("\nCapture sizes (bytes):", sizes)


def run():
    check_required_tools()
    net = build_network()
    hosts = start_and_get_hosts(net)
    try:
        start_capture(hosts)
        time.sleep(1)
        generate_background_normal_activity(hosts)
        launch_attack(hosts)
        print(f"*** Running for {DURATION_SECONDS} seconds...")
        time.sleep(DURATION_SECONDS + 3)   # a little buffer past the attack's own duration
    finally:
        stop_capture(hosts)
        net.stop()
    check_captures_got_traffic()
    print(f"\nSee {CAPTURE_DIR}/attack_log.txt for the attack's own log output.")


if __name__ == "__main__":
    run()