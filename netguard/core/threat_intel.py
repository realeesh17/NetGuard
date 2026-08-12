"""
Threat Intelligence & IP Risk Scoring Engine for NetGuard.

Provides IP address classification, port risk scoring, and multi-factor
threat intelligence scoring for network security event payloads.
"""

import ipaddress

# Catalog of known sensitive/high-risk ports and services
HIGH_RISK_PORTS = {
    21: {"service": "FTP", "risk_level": "high", "description": "Unencrypted File Transfer Protocol"},
    22: {"service": "SSH", "risk_level": "medium", "description": "Secure Shell Remote Access"},
    23: {"service": "Telnet", "risk_level": "critical", "description": "Unencrypted Telnet Remote Terminal"},
    25: {"service": "SMTP", "risk_level": "medium", "description": "Simple Mail Transfer Protocol"},
    53: {"service": "DNS", "risk_level": "medium", "description": "Domain Name System"},
    80: {"service": "HTTP", "risk_level": "low", "description": "Hypertext Transfer Protocol"},
    135: {"service": "RPC", "risk_level": "high", "description": "Microsoft RPC Endpoint Mapper"},
    139: {"service": "NetBIOS", "risk_level": "high", "description": "NetBIOS Session Service"},
    443: {"service": "HTTPS", "risk_level": "low", "description": "Encrypted Web Traffic"},
    445: {"service": "SMB", "risk_level": "critical", "description": "Server Message Block (Ransomware target)"},
    1433: {"service": "MS-SQL", "risk_level": "high", "description": "Microsoft SQL Server Database"},
    3306: {"service": "MySQL", "risk_level": "high", "description": "MySQL Database Server"},
    3389: {"service": "RDP", "risk_level": "critical", "description": "Remote Desktop Protocol"},
    5900: {"service": "VNC", "risk_level": "high", "description": "Virtual Network Computing Remote Desktop"},
    8080: {"service": "HTTP-Proxy", "risk_level": "medium", "description": "Alternative Web Proxy Port"}
}


def classify_ip_scope(ip_str: str) -> str:
    """
    Classify an IPv4 or IPv6 address into its network category.
    Returns: 'loopback' | 'private' | 'link_local' | 'multicast' | 'public' | 'invalid'
    """
    if not ip_str or ip_str == "any":
        return "any"
    try:
        ip_obj = ipaddress.ip_address(ip_str.split('/')[0])
        if ip_obj.is_loopback:
            return "loopback"
        elif ip_obj.is_link_local:
            return "link_local"
        elif ip_obj.is_multicast:
            return "multicast"
        elif ip_obj.is_private:
            return "private"
        elif ip_obj.is_global:
            return "public"
        else:
            return "unknown"
    except ValueError:
        return "invalid"


def get_port_risk_assessment(port: int) -> dict:
    """
    Evaluate the risk assessment for a given destination port.
    """
    try:
        port_num = int(port)
    except (ValueError, TypeError):
        return {"risk_level": "info", "service": "Unknown", "description": "Invalid port number"}

    if port_num in HIGH_RISK_PORTS:
        return HIGH_RISK_PORTS[port_num].copy()
    elif 0 <= port_num <= 1024:
        return {"service": "System Port", "risk_level": "medium", "description": "Privileged System Service Port"}
    elif 1025 <= port_num <= 49151:
        return {"service": "User Service Port", "risk_level": "low", "description": "Registered User Port"}
    else:
        return {"service": "Dynamic Port", "risk_level": "low", "description": "Ephemeral / Dynamic Port"}


def calculate_threat_score(
    is_anomaly: bool = False,
    payload_entropy: float = 0.0,
    port: int = None,
    ip_address: str = None,
    signature_alert: str = None
) -> dict:
    """
    Calculate a composite threat score (0.0 to 100.0) based on network indicators.
    """
    score = 0.0
    factors = []

    # 1. Signature alert assessment (up to +40)
    if signature_alert:
        sig_lower = str(signature_alert).lower()
        if "syn flood" in sig_lower or "dns tunnel" in sig_lower:
            score += 40.0
            factors.append(f"Critical signature detection: {signature_alert}")
        elif "scan" in sig_lower:
            score += 25.0
            factors.append(f"Reconnaissance signature: {signature_alert}")
        else:
            score += 15.0
            factors.append(f"Signature match: {signature_alert}")

    # 2. ML Anomaly indicator (+25)
    if is_anomaly:
        score += 25.0
        factors.append("Machine learning IsolationForest anomaly flagged")

    # 3. Payload entropy (+15 max for high entropy > 6.0 suggesting encryption/obfuscation)
    if payload_entropy > 6.5:
        score += 15.0
        factors.append(f"High payload entropy detected ({payload_entropy:.2f})")
    elif payload_entropy > 5.0:
        score += 8.0
        factors.append(f"Elevated payload entropy ({payload_entropy:.2f})")

    # 4. Port vulnerability score (+15 max)
    if port is not None:
        port_eval = get_port_risk_assessment(port)
        if port_eval["risk_level"] == "critical":
            score += 15.0
            factors.append(f"Targeting critical service port {port} ({port_eval['service']})")
        elif port_eval["risk_level"] == "high":
            score += 10.0
            factors.append(f"Targeting high-risk service port {port} ({port_eval['service']})")

    # 5. IP scope factor (+5 for public IP)
    if ip_address:
        scope = classify_ip_scope(ip_address)
        if scope == "public":
            score += 5.0
            factors.append("Traffic originates from or targets external public IP")

    # Cap score at 100
    final_score = min(100.0, round(score, 1))

    # Determine risk category
    if final_score >= 70.0:
        risk_category = "CRITICAL"
    elif final_score >= 45.0:
        risk_category = "HIGH"
    elif final_score >= 20.0:
        risk_category = "MEDIUM"
    else:
        risk_category = "LOW"

    return {
        "threat_score": final_score,
        "risk_category": risk_category,
        "risk_factors": factors
    }


def enrich_event_payload(raw_data: dict) -> dict:
    """
    Enrich an event raw_data dictionary with threat intelligence scoring metadata.
    """
    if raw_data is None:
        raw_data = {}
    enriched = dict(raw_data)

    src_ip = enriched.get("src_ip")
    dst_port = enriched.get("dst_port") or enriched.get("port")
    is_anomaly = enriched.get("is_anomaly", False)
    payload_entropy = enriched.get("payload_entropy", 0.0)
    sig_alert = enriched.get("signature_alert") or enriched.get("alert")

    threat_intel = calculate_threat_score(
        is_anomaly=is_anomaly,
        payload_entropy=payload_entropy,
        port=dst_port,
        ip_address=src_ip,
        signature_alert=sig_alert
    )

    if src_ip:
        threat_intel["ip_scope"] = classify_ip_scope(src_ip)
    if dst_port:
        threat_intel["port_assessment"] = get_port_risk_assessment(dst_port)

    enriched["threat_intelligence"] = threat_intel
    return enriched
