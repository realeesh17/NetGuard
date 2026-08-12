import os
import sys
import threading
from flask import Flask, jsonify, request, render_template
from flask_socketio import SocketIO

# Add project root to path to ensure imports work correctly when running directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from netguard.core.db import init_db, get_session
from netguard.core.models import FirewallRule, FirewallDecision, Event, PhishingScan
from netguard.core.events import register_event_listener
from netguard.firewall.simulate import (
    start_simulation, 
    stop_simulation, 
    start_live_firewall, 
    stop_live_firewall
)
from netguard.firewall.visualize_data import get_sankey_data
from netguard.firewall.rule_generator import generate_firewall_recommendations, apply_recommendation
from netguard.phishing.analyze import analyze_url

app = Flask(__name__, template_folder="templates")
app.config["SECRET_KEY"] = "netguard_secret_cyber_hud"
socketio = SocketIO(app, cors_allowed_origins="*")

# State tracking for modes
firewall_mode = "synthetic"  # 'synthetic' or 'live' or 'stopped'

# Initialize database schema on startup
init_db()

# Event bus integration with SocketIO
def event_bus_listener(event):
    """Callback triggered whenever an event is logged in the core event bus."""
    event_data = {
        "id": event.get("id"),
        "timestamp": event.get("timestamp").isoformat() if hasattr(event.get("timestamp"), "isoformat") else str(event.get("timestamp")),
        "source": event.get("source"),
        "severity": event.get("severity"),
        "summary": event.get("summary"),
        "raw_data": event.get("raw_data")
    }
    # Broadcast to all connected SocketIO clients
    socketio.emit("security_event", event_data)

register_event_listener(event_bus_listener)

# Web UI routes
@app.route("/")
def index():
    return render_template("index.html")

# API Routes
@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    with get_session() as session:
        # Counters
        total_packets = session.query(FirewallDecision).count()
        allowed_packets = session.query(FirewallDecision).filter_by(action_taken="allow").count()
        denied_packets = session.query(FirewallDecision).filter_by(action_taken="deny").count()
        threat_alerts = session.query(Event).filter(Event.severity.in_(["warning", "critical"])).count()
        
        # Latest alerts
        latest_events = session.query(Event).order_by(Event.id.desc()).limit(30).all()
        events_list = [{
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "source": e.source,
            "severity": e.severity,
            "summary": e.summary,
            "raw_data": e.raw_data
        } for e in latest_events]
        
        # Phishing history
        phishing_scans = session.query(PhishingScan).order_by(PhishingScan.id.desc()).limit(10).all()
        phishing_list = [{
            "id": p.id,
            "url": p.url,
            "verdict": p.verdict,
            "ml_score": p.ml_score,
            "timestamp": p.timestamp.isoformat()
        } for p in phishing_scans]
        
        return jsonify({
            "total_packets": total_packets,
            "allowed_packets": allowed_packets,
            "denied_packets": denied_packets,
            "threat_alerts": threat_alerts,
            "events": events_list,
            "phishing_scans": phishing_list,
            "firewall_mode": firewall_mode
        })

@app.route("/api/firewall/rules", methods=["GET", "POST"])
def manage_firewall_rules():
    if request.method == "GET":
        with get_session() as session:
            rules = session.query(FirewallRule).order_by(FirewallRule.priority.asc()).all()
            return jsonify([{
                "id": r.id,
                "priority": r.priority,
                "action": r.action,
                "src_ip": r.src_ip,
                "dst_port": r.dst_port,
                "protocol": r.protocol
            } for r in rules])
            
    elif request.method == "POST":
        data = request.json or {}
        action = data.get("action")
        src_ip = data.get("src_ip", "any")
        dst_port = data.get("dst_port", "any")
        protocol = data.get("protocol", "any")
        
        if not action or action not in ["allow", "deny"]:
            return jsonify({"error": "Invalid action value. Must be 'allow' or 'deny'"}), 400
            
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
            
            # Return fresh rules list
            rules = session.query(FirewallRule).order_by(FirewallRule.priority.asc()).all()
            return jsonify([{
                "id": r.id,
                "priority": r.priority,
                "action": r.action,
                "src_ip": r.src_ip,
                "dst_port": r.dst_port,
                "protocol": r.protocol
            } for r in rules]), 201

@app.route("/api/firewall/rules/<int:rule_id>", methods=["DELETE"])
def delete_firewall_rule(rule_id):
    with get_session() as session:
        rule = session.query(FirewallRule).get(rule_id)
        if not rule:
            return jsonify({"error": "Rule not found"}), 404
        session.delete(rule)
        session.commit()
        return jsonify({"message": "Rule deleted successfully"})

@app.route("/api/firewall/rules/reorder", methods=["POST"])
def reorder_firewall_rules():
    data = request.json or {}
    ordered_ids = data.get("order", [])
    
    if not ordered_ids:
        return jsonify({"error": "Missing ordered rule IDs list"}), 400
        
    with get_session() as session:
        for index, rule_id in enumerate(ordered_ids):
            rule = session.query(FirewallRule).get(int(rule_id))
            if rule:
                rule.priority = index + 1
        session.commit()
        return jsonify({"message": "Rules reordered successfully"})

@app.route("/api/firewall/mode", methods=["POST"])
def change_firewall_mode():
    global firewall_mode
    data = request.json or {}
    mode = data.get("mode")
    
    if mode not in ["synthetic", "live", "stopped"]:
        return jsonify({"error": "Invalid mode. Choose 'synthetic', 'live', or 'stopped'"}), 400
        
    if mode == firewall_mode:
        return jsonify({"status": firewall_mode})
        
    # Stop current active mode
    if firewall_mode == "synthetic":
        stop_simulation()
    elif firewall_mode == "live":
        stop_live_firewall()
        
    # Start new mode
    if mode == "synthetic":
        start_simulation(interval=0.8)
    elif mode == "live":
        start_live_firewall()
        
    firewall_mode = mode
    return jsonify({"status": firewall_mode})

@app.route("/api/firewall/sankey", methods=["GET"])
def get_sankey():
    return jsonify(get_sankey_data())

@app.route("/api/firewall/recommendations", methods=["GET"])
def get_rule_recommendations():
    recs = generate_firewall_recommendations()
    return jsonify(recs)

@app.route("/api/firewall/recommendations/apply", methods=["POST"])
def apply_rule_recommendation():
    data = request.json or {}
    try:
        rule_dict = apply_recommendation(data)
        return jsonify({"message": "Rule recommendation applied", "rule": rule_dict}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/phishing/scan", methods=["POST"])
def scan_url():
    data = request.json or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing url parameter"}), 400
        
    report = analyze_url(url)
    return jsonify(report)

# Server startup and background runner initialization
def run_app():
    global firewall_mode
    # Start synthetic traffic generator by default
    print("Starting default synthetic network traffic simulator...")
    start_simulation(interval=0.8)
    firewall_mode = "synthetic"
    
    socketio.run(app, host="127.0.0.1", port=5000, debug=False)

if __name__ == "__main__":
    run_app()
