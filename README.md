# SDN-Based Firewall — Complete Project Guide

**Course Project: SDN2**  
**Tools: POX Controller + Mininet + Open vSwitch**

---

## Project Overview

This project implements a controller-based firewall using the POX SDN controller and Mininet network emulator. The firewall:

- Inspects every packet hitting the controller
- Matches against a rule table (IP, MAC, port, protocol)
- Issues OpenFlow DROP rules for blocked traffic (proactive)
- Issues OpenFlow FORWARD rules for allowed traffic
- Logs every packet decision to a JSON file

---

## File Structure

```
SDN_Firewall_Project/
│
├── setup.py                        ← Run first — checks deps, copies files
│
├── pox_controller/
│   └── sdn_firewall.py             ← POX controller (COPY TO ~/pox/ext/)
│
├── mininet/
│   └── topology.py                 ← Mininet topology + automated tests
│
├── tests/
│   └── run_tests.py                ← Standalone test suite
│
├── logs/
│   └── view_log.py                 ← CLI log viewer / parser
│
└── docs/
    └── README.md                   ← This file
```

**Runtime files (auto-generated):**

```
~/sdn_firewall_log.json             ← Packet log (BLOCK / ALLOW events)
~/sdn_test_results.json             ← Test results from run_tests.py
```

---

## Prerequisites

| Tool | Install command |
|------|----------------|
| POX controller | `cd ~ && git clone https://github.com/noxrepo/pox.git` |
| Mininet | `sudo apt-get install mininet` |
| Open vSwitch | `sudo apt-get install openvswitch-switch` |
| Python 2 (for POX) | Already on most Ubuntu systems |
| Python 3 (for topology/tests) | `sudo apt-get install python3` |

> **Note:** POX uses Python 2. The topology and test scripts use Python 3. Keep them separate.

---

## Step-by-Step Setup

### Step 1 — Check your environment

```bash
python setup.py
```

Fix any issues it reports before continuing.

### Step 2 — Copy the controller into POX

```bash
python setup.py --install
# OR manually:
cp pox_controller/sdn_firewall.py ~/pox/ext/
```

### Step 3 — Start POX (Terminal 1)

```bash
cd ~/pox
python pox.py log.level --DEBUG openflow.of_01 sdn_firewall
```

Wait until you see:
```
SDN Firewall Controller — STARTED
Rules loaded : 13
```

**Do not close this terminal.**

### Step 4 — Start Mininet (Terminal 2)

```bash
cd SDN_Firewall_Project/mininet
sudo python topology.py
```

The topology will:
1. Create 4 hosts + 1 OVS switch
2. Connect the switch to POX
3. Run the automated test suite
4. Drop into Mininet CLI

---

## Network Topology

```
        10.0.0.1          10.0.0.2
           h1                h2
            \                /
             \              /
              ─────[s1]─────          ← OVS Switch (OpenFlow 1.0)
             /              \               │
            /                \             │ TCP 6633
        10.0.0.3          10.0.0.4    [c0 POX]
           h3                h4
                          (BLOCKED)
```

| Host | IP | Role |
|------|----|------|
| h1 | 10.0.0.1 | Normal host |
| h2 | 10.0.0.2 | Normal host |
| h3 | 10.0.0.3 | Normal host |
| h4 | 10.0.0.4 | Quarantined — all traffic blocked |

---

## Firewall Rules

Rules are evaluated top-to-bottom; first match wins.

| # | Source | Destination | Protocol | Port | Action |
|---|--------|-------------|----------|------|--------|
| 1 | 10.0.0.4 | * | * | * | **BLOCK** — h4 quarantine outbound |
| 2 | * | 10.0.0.4 | * | * | **BLOCK** — h4 quarantine inbound |
| 3 | * | * | TCP | 22 | **BLOCK** — SSH globally |
| 4 | * | * | TCP | 23 | **BLOCK** — Telnet globally |
| 5 | 10.0.0.1 | 10.0.0.3 | TCP | 80 | **BLOCK** — HTTP h1→h3 |
| 6 | 10.0.0.2 | * | TCP | 21 | **BLOCK** — FTP from h2 |
| 7 | 10.0.0.1 | 10.0.0.2 | ICMP | — | **ALLOW** — ping h1↔h2 |
| 8 | 10.0.0.2 | 10.0.0.1 | ICMP | — | **ALLOW** — ping h2↔h1 |
| 9 | * | * | ICMP | — | **ALLOW** — ping globally |
| 10 | 10.0.0.1 | 10.0.0.2 | TCP | 5001 | **ALLOW** — iperf h1→h2 |
| 11 | 10.0.0.1 | 10.0.0.2 | TCP | 80 | **ALLOW** — HTTP h1→h2 |
| 12 | * | * | UDP | 53 | **ALLOW** — DNS |
| 13 | * | * | * | * | **BLOCK** — default deny |

---

## Manual Tests in Mininet CLI

```bash
# ✅ Should WORK
mininet> h1 ping -c3 h2
mininet> h2 ping -c3 h3
mininet> h1 ping -c3 h3

# ❌ Should FAIL (h4 quarantine)
mininet> h4 ping h1
mininet> h1 ping h4

# ❌ Should FAIL (SSH blocked)
mininet> h1 nc -zw2 10.0.0.2 22
mininet> h2 nc -zw2 10.0.0.3 22

# ❌ Should FAIL (Telnet blocked)
mininet> h1 nc -zw2 10.0.0.2 23

# ❌ Should FAIL (HTTP h1->h3 blocked)
mininet> h1 nc -zw2 10.0.0.3 80

# ✅ Should WORK (HTTP h1->h2 allowed)
mininet> h1 nc -zw2 10.0.0.2 80

# iperf bandwidth test
mininet> h2 iperf -s -p 5001 &
mininet> h1 iperf -c 10.0.0.2 -p 5001 -t 5

# View installed flow rules on switch
mininet> sh ovs-ofctl dump-flows s1
```

---

## Viewing Logs

```bash
# Show stats
python logs/view_log.py --stats

# Show last 30 blocked packets
python logs/view_log.py --filter BLOCK --tail 30

# Show last 20 allowed packets
python logs/view_log.py --filter ALLOW --tail 20

# Show all events (last 50)
python logs/view_log.py
```

Log file location: `~/sdn_firewall_log.json`

---

## Troubleshooting

### Problem: `pingall` shows 100% dropped

**Cause:** OVS switch is not connected to the POX controller.

**Fix:**
```bash
# Check if POX is listening on port 6633
netstat -tlnp | grep 6633

# Force switch to connect to controller
sudo ovs-vsctl set-controller s1 tcp:127.0.0.1:6633

# Verify
sudo ovs-vsctl show
sudo ovs-ofctl show s1
```

### Problem: `Connection refused` on controller port 6633

**Cause:** POX is not running.

**Fix:** Start POX in Terminal 1 first, wait for "STARTED" message, then start Mininet.

### Problem: POX shows `ImportError`

**Cause:** Running POX with Python 3.

**Fix:** POX requires Python 2.
```bash
python2 pox.py log.level --DEBUG openflow.of_01 sdn_firewall
```

### Problem: `sudo: mn command not found`

**Fix:**
```bash
sudo apt-get install mininet
sudo mn --test pingall   # verify
```

### Problem: Flows not being installed

**Fix:** Check POX debug output. Make sure `openflow.of_01` is in the launch command (not `openflow.of_10`).

---

## How It Works (Flow)

```
Packet arrives at switch
        │
        ▼
Flow table lookup
        │
   Match found? ──YES──→ Execute stored action (DROP or FORWARD)
        │NO
        ▼
Send PacketIn to POX controller
        │
        ▼
sdn_firewall.py receives packet
        │
        ▼
Parse: src_ip, dst_ip, proto, ports
        │
        ▼
check_rules() — scan FIREWALL_RULES top-to-bottom
        │
  ┌─────┴─────┐
  │           │
BLOCK       ALLOW
  │           │
  ▼           ▼
Log event   Log event
Install     Install
DROP flow   FORWARD flow
(no action) + send packet out
```

---

## Project Deliverables Checklist

- [x] Rule-based filtering (IP / protocol / port)
- [x] Drop rules installed proactively via OpenFlow
- [x] Allowed vs blocked traffic tested
- [x] Blocked packet log maintained (JSON)
- [x] Log viewer tool included
- [x] Automated test suite
- [x] MAC learning table for forwarding
- [x] ARP handled correctly (flood + learn)
- [x] Default-deny last rule

---

## Adding New Rules

Edit the `FIREWALL_RULES` list in `pox_controller/sdn_firewall.py`:

```python
{
    "src_ip"  : "10.0.0.2",   # or "*" for any
    "dst_ip"  : "10.0.0.3",
    "proto"   : "tcp",         # tcp | udp | icmp | *
    "src_port": None,          # None = any
    "dst_port": 8080,
    "action"  : "BLOCK",       # BLOCK | ALLOW
    "desc"    : "Block HTTP-alt from h2 to h3",
},
```

Insert the rule ABOVE the default-deny entry. Restart POX after changes.
