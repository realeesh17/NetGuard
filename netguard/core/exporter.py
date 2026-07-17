import os
import json
import csv
import sys
from datetime import datetime

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from netguard.core.db import get_session
from netguard.core.models import Event, FirewallDecision, FirewallRule

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

def export_siem_logs(format_type="json"):
    """
    Export all security Events and Firewall Decisions to JSON-L or CSV formats
    suitable for SIEM ingestion (e.g., Splunk, Elasticsearch).
    """
    export_dir = os.path.join(DATA_DIR, "exports")
    os.makedirs(export_dir, exist_ok=True)
    
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. Export Events
    events_file = os.path.join(export_dir, f"siem_events_{timestamp_str}.{format_type}")
    with get_session() as session:
        events = session.query(Event).all()
        event_dicts = [e.to_dict() for e in events]
        
    # Convert datetime values to ISO string
    for d in event_dicts:
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].isoformat()
            
    if format_type.lower() == "json":
        with open(events_file, "w", encoding="utf-8") as f:
            # Export as JSON-L (one JSON object per line) - SIEM standard
            for item in event_dicts:
                f.write(json.dumps(item) + "\n")
        print(f"Exported {len(event_dicts)} security events to (JSON-L): {events_file}")
        
    elif format_type.lower() == "csv":
        if event_dicts:
            headers = event_dicts[0].keys()
            with open(events_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                for row in event_dicts:
                    # JSON serialize nested raw_data dict for CSV compatibility
                    if "raw_data" in row and isinstance(row["raw_data"], dict):
                        row["raw_data"] = json.dumps(row["raw_data"])
                    writer.writerow(row)
            print(f"Exported {len(event_dicts)} security events to (CSV): {events_file}")
        else:
            print("No events in database to export.")
            
    # 2. Export Firewall Decisions
    decisions_file = os.path.join(export_dir, f"siem_decisions_{timestamp_str}.{format_type}")
    with get_session() as session:
        decisions = session.query(FirewallDecision).all()
        decision_dicts = [{
            "id": dec.id,
            "timestamp": dec.timestamp.isoformat() if hasattr(dec.timestamp, "isoformat") else str(dec.timestamp),
            "src_ip": dec.src_ip,
            "dst_ip": dec.dst_ip,
            "dst_port": dec.dst_port,
            "protocol": dec.protocol,
            "rule_matched_id": dec.rule_matched_id,
            "action_taken": dec.action_taken
        } for dec in decisions]
        
    if format_type.lower() == "json":
        with open(decisions_file, "w", encoding="utf-8") as f:
            for item in decision_dicts:
                f.write(json.dumps(item) + "\n")
        print(f"Exported {len(decision_dicts)} firewall decisions to (JSON-L): {decisions_file}")
        
    elif format_type.lower() == "csv":
        if decision_dicts:
            headers = decision_dicts[0].keys()
            with open(decisions_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(decision_dicts)
            print(f"Exported {len(decision_dicts)} firewall decisions to (CSV): {decisions_file}")
        else:
            print("No decisions in database to export.")
            
    return events_file, decisions_file

def backup_firewall_rules(filepath=None):
    """Backup active firewall rules to a local JSON file."""
    if not filepath:
        config_dir = os.path.join(DATA_DIR, "config")
        os.makedirs(config_dir, exist_ok=True)
        filepath = os.path.join(config_dir, "firewall_rules_backup.json")
        
    with get_session() as session:
        rules = session.query(FirewallRule).order_by(FirewallRule.priority.asc()).all()
        rules_data = [{
            "priority": r.priority,
            "action": r.action,
            "src_ip": r.src_ip,
            "dst_port": r.dst_port,
            "protocol": r.protocol
        } for r in rules]
        
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(rules_data, f, indent=4)
        
    print(f"Successfully backed up {len(rules_data)} firewall rules to {filepath}")
    return filepath

def restore_firewall_rules(filepath):
    """Restore firewall rules from a JSON backup file, replacing current database rules."""
    if not os.path.exists(filepath):
        print(f"Error: Backup file not found at {filepath}")
        return False
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            rules_data = json.load(f)
            
        with get_session() as session:
            # Clear existing rules
            session.query(FirewallRule).delete()
            
            # Re-insert rules from backup
            for item in rules_data:
                rule = FirewallRule(
                    priority=item["priority"],
                    action=item["action"],
                    src_ip=item["src_ip"],
                    dst_port=item["dst_port"],
                    protocol=item["protocol"]
                )
                session.add(rule)
            session.commit()
            
        print(f"Successfully restored {len(rules_data)} firewall rules from {filepath}")
        return True
    except Exception as e:
        print(f"Error restoring rules: {e}")
        return False

if __name__ == "__main__":
    # Test script if executed directly
    print("Testing NetGuard SIEM exporter and backups...")
    export_siem_logs(format_type="json")
    backup_file = backup_firewall_rules()
