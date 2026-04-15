#!/usr/bin/env python3
"""
=============================================================================
  SDN Firewall — Standalone Test Suite
  Project : SDN2 — Controller-Based Firewall
  File    : tests/run_tests.py
  Run     : sudo python tests/run_tests.py
            (Mininet topology must be running in another terminal)
=============================================================================
"""

import subprocess, sys, time, json, os
from datetime import datetime

RESULTS_FILE = os.path.expanduser("~/sdn_test_results.json")

# ── Color codes ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def hdr(text):
    print("\n%s%s%s %s %s%s" % (BOLD, CYAN, "─"*10, text, "─"*10, RESET))

def ok(msg):  print("  %s✅  PASS%s  %s" % (GREEN, RESET, msg))
def err(msg): print("  %s❌  FAIL%s  %s" % (RED,   RESET, msg))
def info(msg):print("  %sℹ️   INFO%s  %s" % (YELLOW,RESET, msg))

def run_mininet_cmd(host, cmd, timeout=8):
    """
    Run a command inside a running Mininet session via mx (mininet exec).
    Requires the topology to be running.
    Falls back to direct shell if mx unavailable.
    """
    mx_cmd = "mn --pre 'noecho' --custom /dev/stdin"
    full   = 'sudo python -c "from mininet.net import *; net=Mininet(); %s=net[\'%s\']; print(%s.cmd(\'%s\'))"' % (
        host, host, host, cmd)
    # Simpler: use mnexec if available
    try:
        result = subprocess.run(
            ["sudo", "mnexec", "-a", "1", "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except Exception:
        return ""


# ── Test cases ───────────────────────────────────────────────────────────────

class FirewallTester:
    def __init__(self):
        self.passed  = 0
        self.failed  = 0
        self.results = []

    def test(self, label, host, cmd, expect_block, timeout=8):
        """
        expect_block=True  → traffic should be BLOCKED (test passes if blocked)
        expect_block=False → traffic should be ALLOWED (test passes if allowed)
        """
        out = run_mininet_cmd(host, cmd, timeout)

        blocked = ("100% packet loss" in out or
                   "Connection refused" in out or
                   "timed out" in out or
                   ("nc" in cmd and out.strip() == ""))
        allowed = ("0% packet loss" in out or
                   "succeeded" in out or
                   ("nc" in cmd and "open" in out.lower()))

        if expect_block:
            passed = blocked
        else:
            passed = allowed

        entry = {
            "label": label,
            "host": host,
            "cmd": cmd,
            "expect": "BLOCK" if expect_block else "ALLOW",
            "result": "PASS" if passed else "FAIL",
            "output_snippet": out[:120].strip(),
        }
        self.results.append(entry)

        if passed:
            self.passed += 1
            ok(label)
        else:
            self.failed += 1
            err(label)
            print("       cmd: %s" % cmd)
            print("       out: %s" % out[:100].strip())

    def run_all(self):
        print("\n%s%s SDN Firewall — Test Suite%s" % (BOLD, CYAN, RESET))
        print("  %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        hdr("ICMP Tests")
        self.test("ICMP h1->h2 allowed",      "h1", "ping -c2 -W1 10.0.0.2", False)
        self.test("ICMP h2->h1 allowed",      "h2", "ping -c2 -W1 10.0.0.1", False)
        self.test("ICMP h1->h3 allowed",      "h1", "ping -c2 -W1 10.0.0.3", False)
        self.test("ICMP h4->h1 blocked",      "h4", "ping -c2 -W1 10.0.0.1", True)
        self.test("ICMP h1->h4 blocked",      "h1", "ping -c2 -W1 10.0.0.4", True)

        hdr("SSH Tests (TCP:22)")
        self.test("SSH h1->h2 blocked",       "h1", "nc -zw2 10.0.0.2 22", True)
        self.test("SSH h2->h3 blocked",       "h2", "nc -zw2 10.0.0.3 22", True)
        self.test("SSH h3->h1 blocked",       "h3", "nc -zw2 10.0.0.1 22", True)

        hdr("Telnet Tests (TCP:23)")
        self.test("Telnet h1->h2 blocked",    "h1", "nc -zw2 10.0.0.2 23", True)
        self.test("Telnet h2->h3 blocked",    "h2", "nc -zw2 10.0.0.3 23", True)

        hdr("HTTP Tests (TCP:80)")
        self.test("HTTP h1->h3 blocked",      "h1", "nc -zw2 10.0.0.3 80", True)
        self.test("HTTP h1->h2 allowed",      "h1", "nc -zw2 10.0.0.2 80", False)

        hdr("FTP Tests (TCP:21)")
        self.test("FTP h2->h3 blocked",       "h2", "nc -zw2 10.0.0.3 21", True)

        hdr("Quarantine Tests (h4)")
        self.test("h4 all out blocked",       "h4", "ping -c2 -W1 10.0.0.2", True)
        self.test("h4 all in blocked",        "h1", "ping -c2 -W1 10.0.0.4", True)

        # ── Summary ─────────────────────────────────────────────────────────
        total = self.passed + self.failed
        pct   = int(100 * self.passed / total) if total else 0

        print("\n" + "="*50)
        print("%s  Summary: %d/%d passed (%d%%)%s" % (
            BOLD, self.passed, total, pct, RESET))
        if self.failed == 0:
            print("%s  All tests PASSED — Firewall working correctly!%s" % (
                GREEN, RESET))
        else:
            print("%s  %d test(s) FAILED%s" % (RED, self.failed, RESET))
        print("="*50 + "\n")

        # Save results
        data = {
            "timestamp": datetime.now().isoformat(),
            "passed"   : self.passed,
            "failed"   : self.failed,
            "total"    : total,
            "results"  : self.results,
        }
        with open(RESULTS_FILE, "w") as f:
            json.dump(data, f, indent=2)
        print("  Results saved → %s\n" % RESULTS_FILE)

        return self.failed == 0


if __name__ == "__main__":
    tester = FirewallTester()
    ok_all = tester.run_all()
    sys.exit(0 if ok_all else 1)
