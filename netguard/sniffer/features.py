from netguard.sniffer.rules import calculate_entropy

def extract_features(packets: list[dict], window_duration: float = 10.0) -> list[float]:
    """
    Extract a 7-dimensional feature vector from a list of packet dicts in a rolling window.
    
    Features list:
        1. packet_rate (float): Packets per second
        2. unique_ports (float): Count of unique destination ports
        3. avg_length (float): Average packet size in bytes
        4. tcp_ratio (float): Ratio of TCP packets [0.0 - 1.0]
        5. udp_ratio (float): Ratio of UDP packets [0.0 - 1.0]
        6. icmp_ratio (float): Ratio of ICMP packets [0.0 - 1.0]
        7. avg_entropy (float): Average entropy of DNS queries/TCP flags
        
    Args:
        packets: List of packet dictionaries captured within the time window.
        window_duration: Window size in seconds.
    """
    total_packets = len(packets)
    if total_packets == 0:
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        
    packet_rate = total_packets / window_duration
    unique_ports = float(len({p["dst_port"] for p in packets if p.get("dst_port") is not None}))
    avg_length = sum(p.get("length", 0) for p in packets) / total_packets
    
    tcp_count = sum(1 for p in packets if p.get("protocol", "").upper() == "TCP")
    udp_count = sum(1 for p in packets if p.get("protocol", "").upper() == "UDP")
    icmp_count = sum(1 for p in packets if p.get("protocol", "").upper() == "ICMP")
    
    tcp_ratio = tcp_count / total_packets
    udp_ratio = udp_count / total_packets
    icmp_ratio = icmp_count / total_packets
    
    # Calculate average entropy for the payloads/signals
    total_entropy = 0.0
    for p in packets:
        signal = p.get("dns_query", "") or p.get("flags", "") or ""
        total_entropy += calculate_entropy(signal)
    avg_entropy = total_entropy / total_packets
    
    return [
        packet_rate,
        unique_ports,
        avg_length,
        tcp_ratio,
        udp_ratio,
        icmp_ratio,
        avg_entropy
    ]
