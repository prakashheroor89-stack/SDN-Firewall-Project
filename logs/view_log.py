#!/usr/bin/env python3
"""
=============================================================================
  SDN Firewall — Log Viewer
  Project : SDN2 — Controller-Based Firewall
  File    : logs/view_log.py
  Run     : python logs/view_log.py
            python logs/view_log.py --filter BLOCK
            python logs/view_log.py --filter ALLOW --tail 20
            python logs/view_log.py --stats
=============================================================================
"""

import json, os, sys, argparse
from datetime import datetime

LOG_FILE = os.path.expanduser("~/sdn_firewall_log.json")

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def load_log():
    if not os.path.exists(LOG_FILE):
        print("Log file not found: %s" % LOG_FILE)
        print("Start the POX controller first.")
        sys.exit(1)
    with open(LOG_FILE) as f:
        return json.load(f)


def print_stats(data):
    s = data.get("stats", {})
    print("\n%s%s SDN Firewall — Live Statistics%s" % (BOLD, CYAN, RESET))
    print("  Packets blocked  : %s%d%s" % (RED,    s.get("blocked",    0), RESET))
    print("  Packets allowed  : %s%d%s" % (GREEN,  s.get("allowed",    0), RESET))
    print("  Drop flows pushed: %s%d%s" % (YELLOW, s.get("drop_flows", 0), RESET))
    total = s.get("blocked", 0) + s.get("allowed", 0)
    if total:
        pct = 100.0 * s.get("blocked", 0) / total
        print("  Block rate       : %.1f%%" % pct)
    print()


def print_entries(entries, tail, color):
    shown = entries[-tail:] if tail else entries
    for e in shown:
        c     = RED if e.get("action") == "BLOCK" else GREEN
        sport = str(e.get("src_port") or "*")
        dport = str(e.get("dst_port") or "*")
        print("  %s[%s]%s  %s%-5s%s  %s:%s -> %s:%s  |  %s" % (
            YELLOW, e.get("timestamp", "?"), RESET,
            c, e.get("action", "?"), RESET,
            e.get("src_ip", "?"), sport,
            e.get("dst_ip", "?"), dport,
            e.get("rule",   "?"),
        ))


def main():
    parser = argparse.ArgumentParser(description="SDN Firewall Log Viewer")
    parser.add_argument("--filter", choices=["BLOCK", "ALLOW"],
                        help="Show only BLOCK or ALLOW entries")
    parser.add_argument("--tail", type=int, default=50,
                        help="Show last N entries (default 50, 0=all)")
    parser.add_argument("--stats", action="store_true",
                        help="Show stats only")
    args = parser.parse_args()

    data = load_log()
    print_stats(data)

    if args.stats:
        return

    blocked = data.get("blocked", [])
    allowed = data.get("allowed", [])

    if args.filter == "BLOCK":
        print("%s%s  Blocked packets%s (last %d):" % (
            BOLD, RED, RESET, args.tail or len(blocked)))
        print_entries(blocked, args.tail, RED)
    elif args.filter == "ALLOW":
        print("%s%s  Allowed packets%s (last %d):" % (
            BOLD, GREEN, RESET, args.tail or len(allowed)))
        print_entries(allowed, args.tail, GREEN)
    else:
        # Merge and sort by timestamp
        all_entries = blocked + allowed
        all_entries.sort(key=lambda e: e.get("timestamp", ""))
        tail = args.tail or len(all_entries)
        print("%s%s  All packets%s (last %d):" % (BOLD, CYAN, RESET, tail))
        print_entries(all_entries, tail, CYAN)


if __name__ == "__main__":
    main()
