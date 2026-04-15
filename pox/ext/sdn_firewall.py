"""
=============================================================================
  SDN-Based Firewall Controller
  Project : SDN2 — Controller-Based Firewall
  File    : pox_controller/sdn_firewall.py
  Place   : ~/pox/ext/sdn_firewall.py
  Run     : python pox.py log.level --DEBUG openflow.of_01 sdn_firewall
=============================================================================
"""

from pox.core import core
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from datetime import datetime
import json, os, threading

log = core.getLogger()

# ─────────────────────────────────────────────────────────────────────────────
#  FIREWALL RULE TABLE
#  Each rule is a dict. Fields:
#    src_ip   : "x.x.x.x" or "*" (wildcard)
#    dst_ip   : "x.x.x.x" or "*"
#    proto    : "tcp" | "udp" | "icmp" | "*"
#    src_port : int or None (None = any)
#    dst_port : int or None
#    action   : "BLOCK" | "ALLOW"
#    desc     : human-readable description
#  Rules are evaluated top-to-bottom; first match wins.
# ─────────────────────────────────────────────────────────────────────────────

FIREWALL_RULES = [

    # ── HIGH-PRIORITY BLOCK RULES ────────────────────────────────────────────
    {   # Block ALL traffic from h2 (quarantined host)
        "src_ip": "10.0.0.2", "dst_ip": "*",
        "proto": "*", "src_port": None, "dst_port": None,
        "action": "BLOCK", "desc": "Quarantine h2 — block all outbound"
    },
    {   # Block all traffic TO h2
        "src_ip": "*", "dst_ip": "10.0.0.2",
        "proto": "*", "src_port": None, "dst_port": None,
        "action": "BLOCK", "desc": "Quarantine h2 — block all inbound"
    },
    {   # Block SSH (TCP 22) globally
        "src_ip": "*", "dst_ip": "*",
        "proto": "tcp", "src_port": None, "dst_port": 22,
        "action": "BLOCK", "desc": "Block SSH globally (TCP:22)"
    },
    {   # Block Telnet (TCP 23) globally
        "src_ip": "*", "dst_ip": "*",
        "proto": "tcp", "src_port": None, "dst_port": 23,
        "action": "BLOCK", "desc": "Block Telnet globally (TCP:23)"
    },
    {   # Block HTTP from h1 to h3
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3",
        "proto": "tcp", "src_port": None, "dst_port": 80,
        "action": "BLOCK", "desc": "Block HTTP h1->h3 (TCP:80)"
    },
    {   # Block FTP from h2
        "src_ip": "10.0.0.2", "dst_ip": "*",
        "proto": "tcp", "src_port": None, "dst_port": 21,
        "action": "BLOCK", "desc": "Block FTP from h2 (TCP:21)"
    },

    # ── ALLOW RULES ──────────────────────────────────────────────────────────
    {   # Allow ICMP (ping) between h1 and h2 explicitly
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "proto": "icmp", "src_port": None, "dst_port": None,
        "action": "ALLOW", "desc": "Allow ICMP h1<->h2"
    },
    {   # Allow ICMP (ping) between h2 and h1 explicitly
        "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
        "proto": "icmp", "src_port": None, "dst_port": None,
        "action": "ALLOW", "desc": "Allow ICMP h2<->h1"
    },
    {   # Allow ICMP globally (except h4, caught above)
        "src_ip": "*", "dst_ip": "*",
        "proto": "icmp", "src_port": None, "dst_port": None,
        "action": "ALLOW", "desc": "Allow ICMP globally"
    },
    {   # Allow iperf bandwidth test h1->h2
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "proto": "tcp", "src_port": None, "dst_port": 5001,
        "action": "ALLOW", "desc": "Allow iperf h1->h2 (TCP:5001)"
    },
    {   # Allow HTTP h1->h2
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "proto": "tcp", "src_port": None, "dst_port": 80,
        "action": "ALLOW", "desc": "Allow HTTP h1->h2 (TCP:80)"
    },
    {   # Allow DNS globally
        "src_ip": "*", "dst_ip": "*",
        "proto": "udp", "src_port": None, "dst_port": 53,
        "action": "ALLOW", "desc": "Allow DNS (UDP:53)"
    },

    # ── DEFAULT DENY (must be LAST) ──────────────────────────────────────────
    {
        "src_ip": "*", "dst_ip": "*",
        "proto": "*", "src_port": None, "dst_port": None,
        "action": "BLOCK", "desc": "Default deny all"
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  LOG ENGINE
# ─────────────────────────────────────────────────────────────────────────────

LOG_FILE  = os.path.expanduser("~/sdn_firewall_log.json")
_log_lock = threading.Lock()
_blocked  = []
_allowed  = []
_stats    = {"blocked": 0, "allowed": 0, "drop_flows": 0}


def _write_log():
    with _log_lock:
        data = {
            "stats"  : _stats,
            "blocked": _blocked[-500:],
            "allowed": _allowed[-500:],
        }
        try:
            with open(LOG_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log.warning("Could not write log file: %s" % e)


def log_event(action, desc, src_ip, dst_ip, proto,
              src_port, dst_port, switch_dpid):
    entry = {
        "timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action"    : action,
        "rule"      : desc,
        "src_ip"    : str(src_ip),
        "dst_ip"    : str(dst_ip),
        "protocol"  : proto.upper() if proto else "UNKNOWN",
        "src_port"  : src_port,
        "dst_port"  : dst_port,
        "switch"    : dpidToStr(switch_dpid),
    }
    if action == "BLOCK":
        _blocked.append(entry)
        _stats["blocked"] += 1
        log.warning("[BLOCK] %s %s:%s -> %s:%s | %s" % (
            proto.upper(), src_ip, src_port or "*",
            dst_ip, dst_port or "*", desc))
    else:
        _allowed.append(entry)
        _stats["allowed"] += 1
        log.info("[ALLOW] %s %s:%s -> %s:%s | %s" % (
            proto.upper(), src_ip, src_port or "*",
            dst_ip, dst_port or "*", desc))
    _write_log()


# ─────────────────────────────────────────────────────────────────────────────
#  RULE MATCHING
# ─────────────────────────────────────────────────────────────────────────────

def _match_ip(rule_ip, pkt_ip):
    return rule_ip == "*" or str(pkt_ip) == str(rule_ip)

def _match_port(rule_port, pkt_port):
    return rule_port is None or rule_port == pkt_port

def _match_proto(rule_proto, pkt_proto):
    return rule_proto == "*" or rule_proto == pkt_proto

def check_rules(src_ip, dst_ip, proto, src_port, dst_port):
    """Return (action, description) for the first matching rule."""
    for rule in FIREWALL_RULES:
        if (_match_ip(rule["src_ip"], src_ip)   and
            _match_ip(rule["dst_ip"], dst_ip)   and
            _match_proto(rule["proto"], proto)   and
            _match_port(rule.get("src_port"), src_port) and
            _match_port(rule.get("dst_port"), dst_port)):
            return rule["action"], rule["desc"]
    return "BLOCK", "Default deny"   # fallback


# ─────────────────────────────────────────────────────────────────────────────
#  OPENFLOW HELPERS
# ─────────────────────────────────────────────────────────────────────────────

DROP_HARD_TIMEOUT  = 300   # seconds — proactive drop rule lifetime
DROP_IDLE_TIMEOUT  = 60
FWD_HARD_TIMEOUT   = 120
FWD_IDLE_TIMEOUT   = 60
DROP_PRIORITY      = 200   # higher than forward rules
FWD_PRIORITY       = 100


def _nw_proto_num(proto):
    return {"tcp": 6, "udp": 17, "icmp": 1}.get(proto, None)


def install_drop_rule(conn, src_ip, dst_ip, proto, dst_port, dpid):
    """Push a proactive drop flow so future packets never reach the controller."""
    msg = of.ofp_flow_mod()
    msg.priority     = DROP_PRIORITY
    msg.hard_timeout = DROP_HARD_TIMEOUT
    msg.idle_timeout = DROP_IDLE_TIMEOUT
    msg.match.dl_type = 0x0800   # IPv4

    if src_ip and str(src_ip) != "*":
        msg.match.nw_src = IPAddr(str(src_ip))
    if dst_ip and str(dst_ip) != "*":
        msg.match.nw_dst = IPAddr(str(dst_ip))

    proto_num = _nw_proto_num(proto)
    if proto_num:
        msg.match.nw_proto = proto_num
        if dst_port and proto in ("tcp", "udp"):
            msg.match.tp_dst = dst_port

    # No actions = DROP
    conn.send(msg)
    _stats["drop_flows"] += 1
    log.debug("  → DROP flow installed: %s %s->%s port=%s" % (
        proto, src_ip, dst_ip, dst_port))


def install_forward_rule(conn, packet, packet_in, out_port):
    """Push a proactive forward flow."""
    msg = of.ofp_flow_mod()
    msg.match        = of.ofp_match.from_packet(packet, packet_in.in_port)
    msg.priority     = FWD_PRIORITY
    msg.hard_timeout = FWD_HARD_TIMEOUT
    msg.idle_timeout = FWD_IDLE_TIMEOUT
    msg.data         = packet_in
    msg.actions.append(of.ofp_action_output(port=out_port))
    conn.send(msg)


def send_packet_out(conn, packet_in, out_port):
    """Send a single packet out (no flow rule installed)."""
    msg = of.ofp_packet_out()
    msg.data    = packet_in
    msg.in_port = packet_in.in_port
    msg.actions.append(of.ofp_action_output(port=out_port))
    conn.send(msg)


def flood(conn, packet_in):
    """Flood out all ports except the ingress port."""
    msg = of.ofp_packet_out()
    msg.data    = packet_in
    msg.in_port = packet_in.in_port
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    conn.send(msg)


# ─────────────────────────────────────────────────────────────────────────────
#  PER-SWITCH HANDLER
# ─────────────────────────────────────────────────────────────────────────────

class FirewallSwitch(object):
    """Installs firewall logic on a single OpenFlow switch."""

    def __init__(self, connection, dpid):
        self.connection = connection
        self.dpid       = dpid
        self.mac_table  = {}          # {EthAddr: port_number}
        connection.addListeners(self)
        log.info("Firewall active on switch dpid=%s" % dpidToStr(dpid))

    # ── ARP ──────────────────────────────────────────────────────────────────

    def _handle_arp(self, event, packet):
        """Learn MAC/port from ARP; flood the ARP itself."""
        self.mac_table[packet.src] = event.ofp.in_port
        flood(self.connection, event.ofp)

    # ── IPv4 ─────────────────────────────────────────────────────────────────

    def _handle_ipv4(self, event, packet):
        ip_pkt   = packet.find("ipv4")
        src_ip   = ip_pkt.srcip
        dst_ip   = ip_pkt.dstip
        proto    = "unknown"
        src_port = None
        dst_port = None

        tcp_pkt  = packet.find("tcp")
        udp_pkt  = packet.find("udp")
        icmp_pkt = packet.find("icmp")

        if tcp_pkt:
            proto    = "tcp"
            src_port = tcp_pkt.srcport
            dst_port = tcp_pkt.dstport
        elif udp_pkt:
            proto    = "udp"
            src_port = udp_pkt.srcport
            dst_port = udp_pkt.dstport
        elif icmp_pkt:
            proto    = "icmp"

        action, desc = check_rules(src_ip, dst_ip, proto, src_port, dst_port)
        log_event(action, desc, src_ip, dst_ip, proto,
                  src_port, dst_port, self.dpid)

        if action == "BLOCK":
            # Install a proactive drop rule to avoid per-packet controller hits
            install_drop_rule(self.connection,
                              src_ip, dst_ip, proto, dst_port, self.dpid)
            return   # silently drop this packet

        # ── Forward the allowed packet ────────────────────────────────────
        self.mac_table[packet.src] = event.ofp.in_port

        if packet.dst in self.mac_table:
            out_port = self.mac_table[packet.dst]
            install_forward_rule(self.connection, packet, event.ofp, out_port)
        else:
            flood(self.connection, event.ofp)

    # ── PacketIn handler ─────────────────────────────────────────────────────

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring unparsed packet")
            return

        # Learn source MAC
        self.mac_table[packet.src] = event.ofp.in_port

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet)
        elif packet.type == ethernet.IP_TYPE:
            self._handle_ipv4(event, packet)
        else:
            # Non-IP, non-ARP → flood (e.g. LLDP, IPv6)
            flood(self.connection, event.ofp)


# ─────────────────────────────────────────────────────────────────────────────
#  COMPONENT ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

class SDNFirewallController(object):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("=" * 60)
        log.info("  SDN Firewall Controller — STARTED")
        log.info("  Rules loaded : %d" % len(FIREWALL_RULES))
        log.info("  Log file     : %s" % LOG_FILE)
        log.info("=" * 60)
        for i, r in enumerate(FIREWALL_RULES, 1):
            log.info("  Rule %02d [%s] %s" % (i, r["action"], r["desc"]))
        log.info("=" * 60)

    def _handle_ConnectionUp(self, event):
        log.info("Switch connected: dpid=%s" % dpidToStr(event.dpid))
        FirewallSwitch(event.connection, event.dpid)

    def _handle_ConnectionDown(self, event):
        log.info("Switch disconnected: dpid=%s" % dpidToStr(event.dpid))


def launch():
    """Called by POX when the component is loaded."""
    core.registerNew(SDNFirewallController)
