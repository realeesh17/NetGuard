import ipaddress
from netguard.core.db import get_session
from netguard.core.models import FirewallRule

def match_ip(rule_ip: str, packet_ip: str) -> bool:
    """Check if the packet IP matches the rule IP (supporting 'any' and CIDR)."""
    if not rule_ip or rule_ip.lower() == "any":
        return True
    try:
        if "/" in rule_ip:
            network = ipaddress.ip_network(rule_ip, strict=False)
            addr = ipaddress.ip_address(packet_ip)
            return addr in network
        else:
            return rule_ip == packet_ip
    except Exception:
        return False

def match_port(rule_port_str: str, packet_port: int) -> bool:
    """Check if the packet port matches the rule port specifier (supporting 'any', single, or range)."""
    if not rule_port_str or str(rule_port_str).lower() == "any":
        return True
    try:
        if "-" in str(rule_port_str):
            start, end = map(int, str(rule_port_str).split("-"))
            return start <= packet_port <= end
        else:
            return int(rule_port_str) == packet_port
    except Exception:
        return False

def match_protocol(rule_proto: str, packet_proto: str) -> bool:
    """Check if the packet protocol matches the rule protocol (case-insensitive, supporting 'ANY')."""
    if not rule_proto or rule_proto.upper() == "ANY":
        return True
    return rule_proto.upper() == packet_proto.upper()

def evaluate_packet(packet: dict) -> tuple[str, int | None]:
    """
    Evaluate a packet against all firewall rules sorted by priority (lowest priority number first).
    Returns a tuple of (action, matched_rule_id).
    
    Args:
        packet: dict with keys: 'src_ip', 'dst_ip', 'dst_port', 'protocol'
    """
    src_ip = packet.get("src_ip")
    dst_ip = packet.get("dst_ip")
    dst_port = packet.get("dst_port")
    protocol = packet.get("protocol", "TCP")
    
    with get_session() as session:
        # Load rules ordered by priority ascending
        rules = session.query(FirewallRule).order_by(FirewallRule.priority.asc()).all()
        
        for rule in rules:
            if (match_ip(rule.src_ip, src_ip) and 
                match_port(rule.dst_port, dst_port) and 
                match_protocol(rule.protocol, protocol)):
                
                # Increment rule hit count
                rule.hit_count += 1
                session.add(rule)
                # Note: session commits when context manager exits, so we return action and rule id.
                return rule.action, rule.id
                
    # Fallback default action if no rules matched (standard default: deny)
    return "deny", None
