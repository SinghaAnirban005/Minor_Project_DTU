#!/usr/bin/env python3
"""
net_builder.py  --  shared network-building code used by every stage.

WHY THIS FILE EXISTS
---------------------
Stage 3's topology.py built the virtual LAN and immediately dropped you into
the interactive mininet> CLI. Stages 4 onward (traffic generation, attack
simulation, real-time detection, ...) also need that same LAN, but driven
automatically by a Python script instead of you typing commands by hand.

Rather than copy-pasting the host/switch setup into every new file, we pull
it out once, here, as a function. Every later script just does:

    from net_builder import build_network
    net = build_network()
    net.start()
    ... do stuff with net.get("h1"), net.get("h2"), etc ...
    net.stop()

This keeps the actual network layout defined in exactly one place, so if we
ever need a 5th host or a different IP range, we change it once and every
stage picks it up automatically.
"""

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.log import setLogLevel


# Central place for host names <-> IP addresses, so every script agrees.
HOSTS = {
    "h1": {"name": "gateway",  "ip": "10.0.0.1/24"},
    "h2": {"name": "victim1",  "ip": "10.0.0.2/24"},
    "h3": {"name": "victim2",  "ip": "10.0.0.3/24"},
    "h4": {"name": "attacker", "ip": "10.0.0.4/24"},
}


def build_network(verbose=True):
    """Builds (but does not start) the 4-host, 1-switch virtual LAN.

    Call .start() on the returned Mininet object before using the hosts,
    and .stop() when you're done, to clean everything up.
    """
    if verbose:
        setLogLevel("info")
    else:
        setLogLevel("warning")   # quieter output for automated scripts

    net = Mininet(switch=OVSSwitch, controller=None)

    s1 = net.addSwitch("s1")
    for host_id, info in HOSTS.items():
        net.addHost(host_id, ip=info["ip"])
        net.addLink(net.get(host_id), s1)

    return net


def start_and_get_hosts(net):
    """Starts the network (building it if needed) and returns the hosts as
    a convenient dict, e.g. hosts["gateway"] instead of net.get("h1"), so
    later scripts read naturally ("send from victim1 to gateway" instead
    of "h2 to h1")."""
    net.start()
    return {info["name"]: net.get(host_id) for host_id, info in HOSTS.items()}