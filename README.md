# Minor Project DTU

This project sets up a small Mininet network for working with ARP traffic. It
currently includes an interactive four-host topology and a script that generates
and captures normal ARP request/reply traffic.

## Network

The hosts are connected to one Open vSwitch switch on the `10.0.0.0/24` network:

| Host | Role | IP address |
| --- | --- | --- |
| `h1` (`gateway`) | Gateway | `10.0.0.1` |
| `h2` (`victim1`) | Normal host | `10.0.0.2` |
| `h3` (`victim2`) | Normal host | `10.0.0.3` |
| `h4` (`attacker`) | Host reserved for later experiments | `10.0.0.4` |

## Project layout

- `topology/topology.py` builds the network and opens the Mininet CLI.
- `capture/net_builder.py` contains the shared network configuration and
  startup helpers used by the capture script.
- `capture/generate_normal_traffic.py` captures ARP packets on each host while
  `gateway`, `victim1`, and `victim2` exchange normal ARP traffic. The attacker
  remains idle.
- `capture/*_normal.pcap` contains the per-host capture files.

## Requirements

Run the project on Ubuntu with Python 3, Mininet, Open vSwitch, `tcpdump`, and
`arping` installed. Creating Mininet interfaces and capturing packets requires
root privileges. Restricted containers may not provide the required network
capabilities.

Install the packet tools if needed:

```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch tcpdump iputils-arping
```

## Run the topology

```bash
cd topology
sudo python3 topology.py
```

At the `mininet>` prompt, try `pingall` to check connectivity, or `h2 arp -n`
to inspect `victim1`'s ARP table. Enter `exit` to stop the network.

## Generate normal ARP captures

From the project root, run:

```bash
sudo python3 capture/generate_normal_traffic.py
```

The script runs for 60 seconds by default and writes one `*_normal.pcap` file
per host under `capture/`. It checks for `tcpdump` and `arping` before starting
and reports if all captures are empty. To inspect a capture, for example:

```bash
sudo tcpdump -r capture/victim1_normal.pcap -n
```

The duration and interval between ARP exchanges can be adjusted in
`capture/generate_normal_traffic.py`.

If Mininet reports stale network state after an interrupted run, clean it up
before retrying:

```bash
sudo mn -c
```
