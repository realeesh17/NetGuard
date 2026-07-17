import argparse
import sys
import os

# Ensure parent directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from netguard.core.db import init_db, get_session
from netguard.core.models import FirewallRule, FirewallDecision, Event, PhishingScan
from netguard.phishing.analyze import analyze_url

def cmd_rules_list(args):
    """List all current firewall rules."""
    init_db()
    with get_session() as session:
        rules = session.query(FirewallRule).order_by(FirewallRule.priority.asc()).all()
        if not rules:
            print("No firewall rules deployed.")
            return
            
        print("\n" + "="*80)
        print(f"{'PRIORITY':<10}{'ACTION':<10}{'SRC IP/CIDR':<25}{'DST PORT':<12}{'PROTOCOL':<10}")
        print("="*80)
        for r in rules:
            print(f"{r.priority:<10}{r.action.upper():<10}{r.src_ip:<25}{r.dst_port:<12}{r.protocol.upper():<10}")
        print("="*80 + "\n")

def cmd_rules_add(args):
    """Add a new firewall rule."""
    init_db()
    action = args.action.lower()
    src_ip = args.src_ip
    dst_port = args.dst_port
    protocol = args.protocol.upper()
    
    if action not in ["allow", "deny"]:
        print("Error: Action must be either 'allow' or 'deny'")
        sys.exit(1)
        
    with get_session() as session:
        # Find next priority number
        max_priority = session.query(FirewallRule.priority).order_by(FirewallRule.priority.desc()).first()
        priority = (max_priority[0] + 1) if max_priority else 1
        
        rule = FirewallRule(
            priority=priority,
            action=action,
            src_ip=src_ip,
            dst_port=dst_port,
            protocol=protocol
        )
        session.add(rule)
        session.commit()
        print(f"Success: Deployed rule #{rule.id} [Priority: {rule.priority}] -> {action.upper()} from {src_ip} on port {dst_port} ({protocol})")

def cmd_rules_delete(args):
    """Delete a firewall rule by ID."""
    init_db()
    rule_id = args.id
    with get_session() as session:
        rule = session.query(FirewallRule).get(rule_id)
        if not rule:
            print(f"Error: Firewall rule with ID {rule_id} not found.")
            sys.exit(1)
        session.delete(rule)
        session.commit()
        print(f"Success: Deleted firewall rule with ID {rule_id}")

def cmd_stats(args):
    """Show global system traffic & security stats."""
    init_db()
    with get_session() as session:
        total_packets = session.query(FirewallDecision).count()
        allowed = session.query(FirewallDecision).filter_by(action_taken="allow").count()
        denied = session.query(FirewallDecision).filter_by(action_taken="deny").count()
        alerts = session.query(Event).filter(Event.severity.in_(["warning", "critical"])).count()
        scans = session.query(PhishingScan).count()
        
        print("\n" + "="*40)
        print(" NETGUARD SYSTEM STATUS & METRICS")
        print("="*40)
        print(f"Total Packets Processed: {total_packets}")
        print(f"Allowed Flows:           {allowed}")
        print(f"Denied Flows (Dropped):  {denied}")
        print(f"Security Alert Logs:     {alerts}")
        print(f"Phishing Scans Run:      {scans}")
        print("="*40 + "\n")

def cmd_scan(args):
    """Perform a URL phishing threat scan."""
    init_db()
    url = args.url
    print(f"Initiating phishing page threat evaluation for: {url}...")
    report = analyze_url(url)
    
    print("\n" + "="*60)
    print(f" SCAN REPORT FOR {url}")
    print("="*60)
    print(f"Verdict:      {report['verdict'].upper()}")
    print(f"Threat Score: {report['score']}%")
    print("\nEvaluation Indicators:")
    for reason in report["reasons"]:
        print(f"  - {reason}")
    print("="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="NetGuard Cyber Threat CLI Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Subcommand: rules-list
    subparsers.add_parser("rules-list", help="List all active firewall rules")
    
    # Subcommand: rules-add
    parser_add = subparsers.add_parser("rules-add", help="Add a new firewall rule")
    parser_add.add_argument("--action", required=True, choices=["allow", "deny"], help="Rule action: allow or deny")
    parser_add.add_argument("--src-ip", default="any", help="Source IP or CIDR (e.g. 192.168.1.0/24)")
    parser_add.add_argument("--dst-port", default="any", help="Destination port (e.g. 80)")
    parser_add.add_argument("--protocol", default="any", choices=["any", "TCP", "UDP", "ICMP"], help="Network protocol")
    
    # Subcommand: rules-delete
    parser_del = subparsers.add_parser("rules-delete", help="Delete a firewall rule by ID")
    parser_del.add_argument("--id", type=int, required=True, help="Firewall rule database ID")
    
    # Subcommand: stats
    subparsers.add_parser("stats", help="Display global traffic stats and threat count")
    
    # Subcommand: scan
    parser_scan = subparsers.add_parser("scan", help="Run a phishing URL evaluation")
    parser_scan.add_argument("--url", required=True, help="Target URL (e.g. http://paypal-security-check.com)")
    
    args = parser.parse_args()
    
    # Command router
    if args.command == "rules-list":
        cmd_rules_list(args)
    elif args.command == "rules-add":
        cmd_rules_add(args)
    elif args.command == "rules-delete":
        cmd_rules_delete(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "scan":
        cmd_scan(args)

if __name__ == "__main__":
    main()
