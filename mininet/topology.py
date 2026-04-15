#!/usr/bin/env python3
"""
=============================================================================
  SDN Firewall — Mininet Topology
  Project : SDN2 — Controller-Based Firewall
  File    : mininet/topology.py
  Run     : sudo python topology.py
            sudo python topology.py --test   (auto-test only, no CLI)
=============================================================================
"""

import sys, time, argparse
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink

# ── Host definitions ─────────────────────────────────────────────────────────

HOSTS = [
    {"name": "h1", "ip": "10.0.0.1/24", "mac": "00:00:00:00:00:01"},
    {"name": "h2", "ip": "10.0.0.2/24", "mac": "00:00:00:00:00:02"},
    {"name": "h3", "ip": "10.0.0.3/24", "mac": "00:00:00:00:00:03"},
    {"name": "h4", "ip": "10.0.0.4/24", "mac": "00:00:00:00:00:04"},
]

CONTROLLER_IP   = "127.0.0.1"
CONTROLLER_PORT = 6633
LINK_BW_MBPS    = 10          # link bandwidth in Mbps


# ── Test definitions ─────────────────────────────────────────────────────────
# (host_name, command, expect_pass, label)
#   expect_pass = True  → traffic should succeed
#   expect_pass = False → traffic should be blocked
#   expect_pass = None  → informational (result shown but not pass/fail)

TESTS = [
    # ICMP / ping tests
    ("h1", "ping -c3 -W1 10.0.0.2", True,  "ICMP  h1 -> h2  [ALLOW]"),
    ("h2", "ping -c3 -W1 10.0.0.1", True,  "ICMP  h2 -> h1  [ALLOW]"),
    ("h1", "ping -c3 -W1 10.0.0.3", True,  "ICMP  h1 -> h3  [ALLOW]"),
    ("h4", "ping -c2 -W1 10.0.0.1", False, "ICMP  h4 -> h1  [BLOCK — h4 quarantined]"),
    ("h1", "ping -c2 -W1 10.0.0.4", False, "ICMP  h1 -> h4  [BLOCK — h4 quarantined]"),

    # TCP SSH (port 22) — blocked globally
    ("h1", "nc -zw2 10.0.0.2 22",   False, "TCP   h1 -> h2 :22  [BLOCK SSH]"),
    ("h2", "nc -zw2 10.0.0.3 22",   False, "TCP   h2 -> h3 :22  [BLOCK SSH]"),

    # TCP Telnet (port 23) — blocked globally
    ("h1", "nc -zw2 10.0.0.2 23",   False, "TCP   h1 -> h2 :23  [BLOCK Telnet]"),

    # TCP HTTP (port 80) — blocked h1->h3, allowed h1->h2
    ("h1", "nc -zw2 10.0.0.3 80",   False, "TCP   h1 -> h3 :80  [BLOCK HTTP]"),
    ("h1", "nc -zw2 10.0.0.2 80",   True,  "TCP   h1 -> h2 :80  [ALLOW HTTP]"),

    # TCP FTP (port 21) — blocked from h2
    ("h2", "nc -zw2 10.0.0.3 21",   False, "TCP   h2 -> h3 :21  [BLOCK FTP]"),

    # iperf on port 5001 — allowed h1->h2
    ("h1", "nc -zw2 10.0.0.2 5001", None,  "TCP   h1 -> h2 :5001 [INFO iperf port]"),
]


# ── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║           SDN-Based Firewall — Mininet Topology              ║
╠══════════════════════════════════════════════════════════════╣
║  Hosts:  h1=10.0.0.1   h2=10.0.0.2                          ║
║          h4=10.0.0.4   h3=10.0.0.3  ← QUARANTINED           ║
║  Switch: s1 (OVS)                                            ║
║  Controller: 127.0.0.1:6633 (POX)                            ║
╠══════════════════════════════════════════════════════════════╣
║  Firewall rules:                                             ║
║   ✅  ICMP allowed (except h4)                               ║
║   ✅  HTTP TCP:80  h1->h2 allowed                            ║
║   ✅  iperf TCP:5001 h1->h2 allowed                          ║
║   ❌  SSH  TCP:22  globally blocked                          ║
║   ❌  Telnet TCP:23 globally blocked                         ║
║   ❌  HTTP TCP:80  h1->h3 blocked                            ║
║   ❌  FTP  TCP:21  from h2 blocked                           ║
║   ❌  ALL traffic to/from h4 blocked                         ║
╚══════════════════════════════════════════════════════════════╝
"""


# ── Topology builder ─────────────────────────────────────────────────────────

def build_network():
    setLogLevel("info")

    info("*** Adding controller\n")
    net = Mininet(
        controller=lambda name: RemoteController(
            name, ip=CONTROLLER_IP, port=CONTROLLER_PORT),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False,
        waitConnected=True,
    )

    c0 = net.addController("c0")

    info("*** Adding switch\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow10")

    info("*** Adding hosts\n")
    host_objs = {}
    for h in HOSTS:
        obj = net.addHost(h["name"], ip=h["ip"], mac=h["mac"])
        host_objs[h["name"]] = obj
        net.addLink(obj, s1, bw=LINK_BW_MBPS)

    info("*** Starting network\n")
    net.start()

    # Give the switch time to connect to the controller
    info("*** Waiting 3s for controller handshake...\n")
    time.sleep(3)

    print(BANNER)
    return net, host_objs


# ── Test runner ───────────────────────────────────────────────────────────────

def run_tests(net, host_objs):
    print("\n" + "=" * 65)
    print("  AUTOMATED FIREWALL TEST SUITE")
    print("=" * 65)

    passed = failed = info_count = 0

    for h_name, cmd, expect, label in TESTS:
        host = host_objs[h_name]
        out  = host.cmd(cmd)

        is_success = ("0% packet loss" in out or
                      "open" in out.lower() or
                      (out.strip() == "" and "nc -z" in cmd and "succeeded" not in out))
        is_blocked  = ("100% packet loss" in out or
                       "Connection refused" in out or
                       "timed out" in out or
                       (out.strip() == "" and "nc -z" in cmd))

        if expect is True:
            result = "PASS" if is_success else "FAIL"
            if result == "PASS": passed += 1
            else:                failed += 1
            icon = "✅" if result == "PASS" else "❌"
        elif expect is False:
            result = "PASS" if is_blocked else "FAIL"
            if result == "PASS": passed += 1
            else:                failed += 1
            icon = "✅" if result == "PASS" else "❌"
        else:
            result = "INFO"
            info_count += 1
            icon = "ℹ️ "

        print("  %s  %-50s  %s" % (icon, label, result))

    total = passed + failed
    print("=" * 65)
    print("  Result: %d/%d tests passed  |  %d informational" % (
        passed, total, info_count))
    print("=" * 65 + "\n")

    return passed, failed


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SDN Firewall Mininet Topology")
    parser.add_argument("--test", action="store_true",
                        help="Run automated tests then exit (no CLI)")
    parser.add_argument("--no-test", action="store_true",
                        help="Skip automated tests, go straight to CLI")
    args = parser.parse_args()

    net, host_objs = build_network()

    try:
        if not args.no_test:
            run_tests(net, host_objs)

        if not args.test:
            info("\n*** Entering Mininet CLI — type 'exit' to quit\n\n")
            print("  Useful commands:")
            print("    pingall                      → test all-pairs connectivity")
            print("    h1 ping -c3 h2               → ICMP test")
            print("    h1 nc -zw2 10.0.0.2 22       → SSH (should be blocked)")
            print("    h2 iperf -s -p 5001 &        → start iperf server on h2")
            print("    h1 iperf -c 10.0.0.2 -p 5001 → iperf throughput test\n")
            CLI(net)
    finally:
        info("*** Stopping network\n")
        net.stop()


if __name__ == "__main__":
    main()
