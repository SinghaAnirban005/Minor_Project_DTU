#!/usr/bin/env python3
"""
topology.py  --  Stage 3 of the project plan: "Mininet Network Creation"

WHAT THIS FILE DOES
--------------------
It builds a small, fake (virtual) local network on your computer using Mininet.
Mininet creates real Linux processes that behave like separate computers, all
connected to one virtual switch -- exactly like a bunch of PCs plugged into
the same office switch. Because they're all on the same switch, they talk to
each other using ARP, which is exactly what we want to attack and defend.

THE NETWORK WE BUILD
---------------------

        gateway (h1)
             |
          [switch s1]
          /    |    \
     victim1  victim2  attacker
      (h2)     (h3)     (h4)

- h1 "gateway"   : stands in for the router / default gateway of the LAN.
- h2 "victim1"   : a normal computer that will send/receive normal traffic.
- h3 "victim2"   : a second normal computer (so we have more than one victim
                   to make the dataset and the demo more realistic).
- h4 "attacker"  : the host we will later use to launch ARP spoofing from
                   (Stage 5). It does nothing malicious by default -- it's
                   just a plain host until we run an attack script on it.

HOW TO RUN THIS FILE
---------------------
Mininet needs to create virtual network interfaces, which requires root.
On your own Ubuntu machine (NOT a restricted cloud sandbox) run:

    sudo python3 topology.py

That drops you into the Mininet command-line interface (the "mininet>"
prompt). From there you can type things like:

    mininet> pingall          # test that every host can reach every other host
    mininet> h2 ping h3       # ping victim2 from victim1
    mininet> h2 arp -n        # show victim1's ARP table (IP -> MAC mappings)
    mininet> xterm h4         # open a separate terminal attached to the attacker
    mininet> exit             # quit and clean up

If a previous run left things in a messy state, clean up first with:

    sudo mn -c

WHY IT MIGHT NOT WORK IN A CLOUD SANDBOX
-----------------------------------------
Mininet needs the ability to create virtual network interfaces and move
packets between them at the kernel level. Restricted containers (like some
cloud dev environments) often block this even when you're "root" inside
them. If `pingall` reports 100% dropped, that's almost certainly why --
it is NOT a bug in this script. Run it on a normal Ubuntu install or a
VirtualBox/VMware Ubuntu VM on your laptop instead; that's what the
Mininet project itself recommends for exactly this reason.
"""

from mininet.cli import CLI
from mininet.log import info
from net_builder import build_network   # shared by every stage, see net_builder.py


def run():
    net = build_network()

    info("*** Starting the network\n")
    net.start()

    info("*** Network is up. Try: pingall, or xterm h4 to open the attacker.\n")
    CLI(net)   # drops you into the interactive mininet> prompt

    info("*** Stopping the network\n")
    net.stop()


if __name__ == "__main__":
    run()