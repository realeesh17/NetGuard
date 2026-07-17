import time
import math
import threading
from collections import Counter, defaultdict
from netguard.core.config import Config
from netguard.core.events import log_event

# Thread-safe storage for rolling window metrics
_history_lock = threading.Lock()
# Maps src_ip -> list of (timestamp, dst_port)
port_scan_history = defaultdict(list)
# Maps src_ip -> list of (timestamp, is_syn, is_syn_ack)
syn_flood_history = defaultdict(list)

# Hardcoded static IP blacklist for demo purposes
IP_BLACKLIST = {"192.168.1.66", "10.0.0.99", "185.220.101.5"}

def calculate_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0.0
    entropy = 0.0
    length = len(s)
    counts = Counter(s)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def check_ip_blacklist(src_ip: str) -> tuple[bool, str]:
    """Check if the source IP is blacklisted."""
    if src_ip in IP_BLACKLIST:
        return True, f"Traffic detected from blacklisted IP: {src_ip}"
    return False, ""

def check_port_scan(src_ip: str, dst_port: int, now: float) -> tuple[bool, str]:
    """Track unique destination ports scanned by a source IP within a 10-second rolling window."""
    if dst_port is None:
        return False, ""
        
    with _history_lock:
        history = port_scan_history[src_ip]
        # Append current packet details
        history.append((now, dst_port))
        # Filter history to keep only last 10 seconds
        cutoff = now - 10.0
        history = [item for item in history if item[0] >= cutoff]
        port_scan_history[src_ip] = history
        
        # Count unique ports
        unique_ports = {item[1] for item in history}
        unique_count = len(unique_ports)
        
    if unique_count > Config.PORT_SCAN_THRESHOLD:
        return True, f"Port scan detected: {src_ip} touched {unique_count} unique ports in 10s"
    return False, ""

def check_syn_flood(src_ip: str, flags: str, now: float) -> tuple[bool, str]:
    """Track TCP SYN vs SYN-ACK packets to identify potential SYN floods in a 10s rolling window."""
    if not flags:
        return False, ""
        
    is_syn = "S" in flags and "A" not in flags
    is_syn_ack = "S" in flags and "A" in flags
    
    if not (is_syn or is_syn_ack):
        return False, ""
        
    with _history_lock:
        history = syn_flood_history[src_ip]
        history.append((now, is_syn, is_syn_ack))
        # Filter last 10 seconds
        cutoff = now - 10.0
        history = [item for item in history if item[0] >= cutoff]
        syn_flood_history[src_ip] = history
        
        syn_count = sum(1 for item in history if item[1])
        syn_ack_count = sum(1 for item in history if item[2])
        
    if syn_count > Config.SYN_FLOOD_THRESHOLD:
        ratio = (syn_ack_count / syn_count) if syn_count > 0 else 1.0
        if ratio < Config.SYN_ACK_RATIO_THRESHOLD:
            return True, f"SYN Flood detected: {src_ip} sent {syn_count} SYNs with {syn_ack_count} replies in 10s"
            
    return False, ""

def check_dns_tunneling(protocol: str, dst_port: int, dns_query: str) -> tuple[bool, str]:
    """Inspect DNS queries for high entropy or abnormal length indicating data exfiltration/tunneling."""
    is_dns = (protocol.upper() == "UDP" and dst_port == 53) or dns_query is not None
    if not is_dns or not dns_query:
        return False, ""
        
    query_len = len(dns_query)
    entropy = calculate_entropy(dns_query)
    
    if query_len > 50:
        return True, f"DNS Tunneling suspected: Query length is abnormally long ({query_len} chars) - '{dns_query}'"
    if entropy > 4.2 and query_len > 15:
        return True, f"DNS Tunneling suspected: High Shannon entropy ({entropy:.2f}) in query - '{dns_query}'"
        
    return False, ""

def check_abnormal_packet_size(length: int, src_ip: str) -> tuple[bool, str]:
    """Flag packets with abnormal length which can signify heavy payloads or MTU fragmentation risks."""
    if length and length > 1450:
        return True, f"Abnormal packet size warning: {length} bytes from {src_ip}"
    return False, ""

def evaluate_packet_rules(packet: dict) -> list[str]:
    """
    Run signature-based security rules on the packet.
    If a rule fires, logs the event through the event bus.
    
    Returns:
        List of strings containing the alerts triggered.
    """
    src_ip = packet.get("src_ip")
    dst_port = packet.get("dst_port")
    protocol = packet.get("protocol", "")
    flags = packet.get("flags", "")
    dns_query = packet.get("dns_query")
    length = packet.get("length", 0)
    
    if not src_ip:
        return []
        
    now = time.time()
    alerts = []
    
    # 1. Blacklist check
    blacklisted, msg = check_ip_blacklist(src_ip)
    if blacklisted:
        alerts.append(msg)
        log_event(source="sniffer", severity="critical", summary=msg, raw_data=packet)
        
    # 2. Port scan check
    port_scan, msg = check_port_scan(src_ip, dst_port, now)
    if port_scan:
        alerts.append(msg)
        log_event(source="sniffer", severity="warning", summary=msg, raw_data=packet)
        
    # 3. SYN flood check
    syn_flood, msg = check_syn_flood(src_ip, flags, now)
    if syn_flood:
        alerts.append(msg)
        log_event(source="sniffer", severity="critical", summary=msg, raw_data=packet)
        
    # 4. DNS tunneling check
    dns_tunnel, msg = check_dns_tunneling(protocol, dst_port, dns_query)
    if dns_tunnel:
        alerts.append(msg)
        log_event(source="sniffer", severity="warning", summary=msg, raw_data=packet)
        
    # 5. Packet size check
    large_packet, msg = check_abnormal_packet_size(length, src_ip)
    if large_packet:
        alerts.append(msg)
        log_event(source="sniffer", severity="warning", summary=msg, raw_data=packet)
        
    return alerts
