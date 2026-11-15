# ARP Spoofing Detection with Mininet and Machine Learning

This project builds a virtual LAN in Mininet, captures ARP traffic, labels it as
normal or malicious, trains a machine-learning detector, and then runs a live
classifier that blocks suspicious source MAC addresses with nftables.

The workflow is designed around a realistic lab setup:

- generate benign ARP traffic
- simulate an ARP cache-poisoning attack
- convert packet captures into a feature dataset
- train a classifier
- detect spoofing in real time on the protected gateway
- automatically block malicious hosts

## Network topology

The shared host list in `topology/net_builder.py` defines an 8-host Mininet
network on the `10.0.0.0/24` subnet:

| Mininet host | Name | IP address | Role |
| --- | --- | --- | --- |
| `h1` | `gateway` | `10.0.0.1/24` | Protected router/gateway |
| `h2` | `victim1` | `10.0.0.2/24` | Normal host |
| `h3` | `victim2` | `10.0.0.3/24` | Normal host |
| `h4` | `victim3` | `10.0.0.4/24` | Additional normal host |
| `h5` | `victim4` | `10.0.0.5/24` | Additional normal host |
| `h6` | `victim5` | `10.0.0.6/24` | Additional normal host |
| `h7` | `victim6` | `10.0.0.7/24` | Additional normal host |
| `h8` | `attacker` | `10.0.0.8/24` | Malicious host used for spoofing |

The main demo and dataset scripts use the gateway, `victim1`, `victim2`, and
`attacker` for the normal and attack flows. The extra victim hosts remain in the
network as expansion points for future experiments.

## Project structure

- `topology/topology.py` — interactive Mininet topology that starts the LAN and
  drops into the `mininet>` prompt
- `topology/net_builder.py` — shared network-definition code used across every
  stage; builds the switch and assigns the IP addresses to each host
- `capture/generate_normal_traffic.py` — generates benign ARP traffic and saves
  per-host `*_normal.pcap` files
- `attack/arp_spoof.py` — actual ARP cache-poisoning script; sends forged reply
  packets claiming the victim and gateway are at the attacker's MAC
- `attack/simulate_attack.py` — wraps the attack into the Mininet lab setup and
  saves `*_attack.pcap` files
- `dataset/build_dataset.py` — reads the normal and attack captures, extracts
  numeric ARP features, and exports `dataset/arp_dataset.csv`
- `model/train_model.py` — trains the classifier, compares model candidates, and
  writes `model/arp_model.pkl`
- `detector/live_detector.py` — live ARP sniffer that computes features, predicts
  whether traffic is malicious, and blocks bad MAC addresses with nftables
- `detector/run_detection_demo.py` — full end-to-end demo that starts the guard,
  triggers the attack, and logs the result
- `run_pipeline.sh` — convenience pipeline for data generation and training
- `capture/` — PCAP files generated during normal and attack runs
- `dataset/` — labeled dataset CSVs
- `model/` — saved trained model files
- `logs/` — live detection logs and CSV output

## Requirements

This project is intended for Ubuntu/Linux with root access. The full Mininet
workflow depends on:

- Python 3
- Mininet
- Open vSwitch
- `tcpdump`
- `arping`
- `nftables` for live blocking
- Python packages:
  - `scapy`
  - `pandas`
  - `scikit-learn`
  - `xgboost`
  - `joblib`

Install the system tools:

```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch tcpdump iputils-arping nftables
```

Install the Python dependencies:

```bash
python3 -m pip install --break-system-packages scapy pandas scikit-learn xgboost joblib
```

If `--break-system-packages` is not needed in your environment, use the plain
`python3 -m pip install ...` form instead.

## Quick start

### 1. Start the topology

```bash
cd topology
sudo python3 topology.py
```

At the Mininet prompt, you can check connectivity:

```bash
mininet> pingall
mininet> h2 arp -n
```

Exit the Mininet session with:

```bash
mininet> exit
```

If previous Mininet runs left stale state behind, reset it first:

```bash
sudo mn -c
```

### 2. Generate normal ARP traffic

From the project root:

```bash
sudo python3 capture/generate_normal_traffic.py
```

This script records benign ARP traffic and writes files such as:

```bash
capture/gateway_normal.pcap
capture/victim1_normal.pcap
capture/victim2_normal.pcap
```

### 3. Simulate an ARP spoofing attack

```bash
cd attack
sudo python3 simulate_attack.py
```

This runs the attack from the attacker host and generates malicious capture files,
including:

```bash
../capture/gateway_attack.pcap
../capture/victim1_attack.pcap
```

### 4. Build the dataset

```bash
cd dataset
python3 build_dataset.py
```

This reads the normal and malicious captures, extracts ARP features, and writes:

```bash
dataset/arp_dataset.csv
```

### 5. Train the model

```bash
cd model
python3 train_model.py
```

This saves the trained detector to:

```bash
model/arp_model.pkl
```

### 6. Run the live detector demo

```bash
cd detector
sudo python3 run_detection_demo.py
```

This launches the full lab flow: it starts a detector on the gateway, runs the
spoofing attack, and logs detections and blocked MAC addresses.

## One-command pipeline

If you want to generate more data and train a fresh model without running each
step manually, use:

```bash
chmod +x run_pipeline.sh
./run_pipeline.sh
```

This script performs the following sequence:

- runs normal traffic capture twice
- runs attack simulation twice
- builds the combined dataset
- trains the model

It does not start the live demo; that is intended as a separate final check in
front of a reviewer or teacher.

## Manual live detection

To run the detector directly on a protected interface:

```bash
cd detector
sudo python3 live_detector.py --iface gateway-eth0
```

This uses the trained model from `model/arp_model.pkl`, inspects live ARP traffic,
and drops packets from suspicious MAC addresses via `nftables`.

## Inspecting captures

You can read a generated pcap file with `tcpdump`:

```bash
sudo tcpdump -r capture/victim1_normal.pcap -n
sudo tcpdump -r capture/victim1_attack.pcap -n
```

## Notes

- The feature extraction logic looks for conflicting MAC claims for the same IP,
  rapid ARP repetition, and unusual reply patterns.
- The model is trained on numeric ARP features rather than raw packet payloads.
- The project is a lab-oriented educational implementation and is not a
  production-grade intrusion detection system.
