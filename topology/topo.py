# topology/topo.py
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.cli import CLI

def build():
    net = Mininet(controller=None, switch=OVSBridge)
    s1 = net.addSwitch('s1')
    gw  = net.addHost('gw',  ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h1  = net.addHost('h1',  ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h2  = net.addHost('h2',  ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    atk = net.addHost('atk', ip='10.0.0.66/24', mac='00:00:00:00:00:66')
    for h in (gw, h1, h2, atk):
        net.addLink(h, s1)
    net.start()
    return net

if __name__ == '__main__':
    net = build()
    CLI(net)
    net.stop()