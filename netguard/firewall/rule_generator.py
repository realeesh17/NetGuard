"""
Automated Firewall Rule Recommendation Generator for NetGuard.

Analyzes detected anomalies and high-severity threat events to generate
actionable firewall blocking recommendations to mitigate ongoing attacks.
"""

from collections import Counter
from sqlalchemy import select
from netguard.core.db import get_session
from netguard.core.models import Event, PacketLog, FirewallRule

def generate_firewall_recommendations() -> list[dict]:
    """
    Scan Event and PacketLog tables for anomalous traffic patterns and generate
    recommended firewall rules.
    """
    recommendations = []
    
    with get_session() as session:
        # Load existing active rules to prevent duplicate suggestions
        existing_rules = session.query(FirewallRule).all()
        existing_ips = {r.src_ip.strip() for r in existing_rules if r.src_ip}
        
        # 1. Analyze PacketLog anomalies
        anomalous_packets = session.query(PacketLog).filter_by(is_anomaly=True).all()
        ip_counts = Counter(p.src_ip for p in anomalous_packets if p.src_ip)
        
        for src_ip, count in ip_counts.most_common(10):
            if src_ip not in existing_ips and src_ip != "127.0.0.1":
                recommendations.append({
                    "action": "deny",
                    "src_ip": src_ip,
                    "dst_port": "any",
                    "protocol": "ANY",
                    "reason": f"Automated block: {count} anomalous packet(s) detected",
                    "priority": 10,
                    "suggested_by": "ML Anomaly Engine"
                })
        
        # 2. Analyze Critical & Warning Threat Events
        critical_events = session.query(Event).filter(Event.severity.in_(["critical", "warning"])).all()
        for event in critical_events:
            raw = event.raw_data or {}
            event_ip = raw.get("src_ip")
            event_port = raw.get("dst_port") or raw.get("port")
            
            if event_ip and event_ip not in existing_ips and event_ip != "127.0.0.1":
                # Avoid duplicates within recommendations list
                if not any(r["src_ip"] == event_ip for r in recommendations):
                    recommendations.append({
                        "action": "deny",
                        "src_ip": event_ip,
                        "dst_port": str(event_port) if event_port else "any",
                        "protocol": "ANY",
                        "reason": f"Threat Event mitigation: {event.summary}",
                        "priority": 15,
                        "suggested_by": "Signature Event Engine"
                    })

    return recommendations

def apply_recommendation(rec: dict) -> dict:
    """
    Apply a recommendation dict into an active database FirewallRule.
    """
    src_ip = rec.get("src_ip")
    if not src_ip:
        raise ValueError("Recommendation must include a valid src_ip")
        
    action = rec.get("action", "deny")
    dst_port = str(rec.get("dst_port", "any"))
    protocol = rec.get("protocol", "ANY").upper()
    priority = int(rec.get("priority", 10))
    
    with get_session() as session:
        # Determine highest existing priority if needed
        existing = session.query(FirewallRule).filter_by(src_ip=src_ip, dst_port=dst_port, protocol=protocol).first()
        if existing:
            return existing.to_dict()

        rule = FirewallRule(
            priority=priority,
            action=action,
            src_ip=src_ip,
            dst_port=dst_port,
            protocol=protocol,
            hit_count=0
        )
        session.add(rule)
        session.commit()
        return rule.to_dict()
