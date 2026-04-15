#!/usr/bin/env python3
"""
=============================================================================
  SDN Firewall — Setup Script
  Project : SDN2
  File    : setup.py
  Run     : python setup.py
            python setup.py --install   (installs deps + copies controller)
=============================================================================
"""

import os, sys, shutil, subprocess, argparse

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

HOME    = os.path.expanduser("~")
POX_DIR = os.path.join(HOME, "pox")
EXT_DIR = os.path.join(POX_DIR, "ext")
SRC     = os.path.join(os.path.dirname(__file__),
                       "pox_controller", "sdn_firewall.py")


def ok(msg):   print("  %s✅%s  %s" % (GREEN,  RESET, msg))
def fail(msg): print("  %s❌%s  %s" % (RED,    RESET, msg))
def warn(msg): print("  %s⚠️ %s  %s" % (YELLOW, RESET, msg))
def step(msg): print("\n%s%s%s" % (BOLD, msg, RESET))


def check_pox():
    if os.path.isdir(POX_DIR):
        ok("POX found at %s" % POX_DIR)
        return True
    fail("POX not found at %s" % POX_DIR)
    print("       Install POX with:")
    print("         cd ~  &&  git clone https://github.com/noxrepo/pox.git")
    return False


def check_mininet():
    try:
        subprocess.run(["mn", "--version"],
                       capture_output=True, check=True, timeout=5)
        ok("Mininet is installed")
        return True
    except Exception:
        fail("Mininet not found")
        print("       Install: sudo apt-get install mininet")
        return False


def check_ovs():
    try:
        subprocess.run(["ovs-vsctl", "--version"],
                       capture_output=True, check=True, timeout=5)
        ok("Open vSwitch (OVS) found")
        return True
    except Exception:
        fail("Open vSwitch not found")
        print("       Install: sudo apt-get install openvswitch-switch")
        return False


def install_controller():
    if not os.path.isdir(EXT_DIR):
        fail("POX ext/ directory not found: %s" % EXT_DIR)
        return False
    dst = os.path.join(EXT_DIR, "sdn_firewall.py")
    shutil.copy2(SRC, dst)
    ok("Copied sdn_firewall.py → %s" % dst)
    return True


def print_run_instructions():
    print("""
%s%s  HOW TO RUN THE PROJECT%s

  ┌─ Terminal 1 (start POX controller FIRST) ─────────────────────┐
  │  cd ~/pox                                                       │
  │  python pox.py log.level --DEBUG openflow.of_01 sdn_firewall   │
  └─────────────────────────────────────────────────────────────────┘

  ┌─ Terminal 2 (start Mininet after controller is ready) ─────────┐
  │  cd SDN_Firewall_Project/mininet                                │
  │  sudo python topology.py                                        │
  └─────────────────────────────────────────────────────────────────┘

  ┌─ Terminal 3 (optional — view live logs) ───────────────────────┐
  │  python logs/view_log.py --filter BLOCK                         │
  └─────────────────────────────────────────────────────────────────┘

%s  Quick test commands in Mininet CLI:%s
    pingall                         → all-pairs ping
    h1 ping -c3 h2                  → should work
    h4 ping h1                      → should be BLOCKED
    h1 nc -zw2 10.0.0.2 22          → SSH — BLOCKED
    h2 iperf -s -p 5001 &           → start iperf server
    h1 iperf -c 10.0.0.2 -p 5001   → iperf throughput test

%s  Fix 100%% packet loss (OVS not connected):%s
    sudo ovs-vsctl set-controller s1 tcp:127.0.0.1:6633
    sudo ovs-ofctl show s1
""" % (BOLD, "\033[96m", RESET, BOLD, RESET, BOLD, RESET))


def main():
    parser = argparse.ArgumentParser(description="SDN Firewall Setup")
    parser.add_argument("--install", action="store_true",
                        help="Copy controller to POX ext/ directory")
    args = parser.parse_args()

    print("\n%s%s SDN Firewall — Setup Check%s\n" % (BOLD, "\033[96m", RESET))

    step("Checking dependencies...")
    pox_ok = check_pox()
    mn_ok  = check_mininet()
    ovs_ok = check_ovs()

    if args.install:
        step("Installing controller...")
        if pox_ok:
            install_controller()
        else:
            fail("Cannot install — POX not found")

    print_run_instructions()

    if not (pox_ok and mn_ok and ovs_ok):
        print("%s  Fix the issues above, then re-run setup.py%s\n" % (
            "\033[91m", RESET))
        sys.exit(1)
    else:
        print("%s  All checks passed — ready to run!%s\n" % (GREEN, RESET))


if __name__ == "__main__":
    main()
