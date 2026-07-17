import time
import random
import threading
from netguard.core.db import get_session
from netguard.core.models import FirewallDecision
from netguard.core.events import log_event
from netguard.firewall.engine import evaluate_packet

# Thread control variables
_simulation_thread = None
_simulation_running = False
_simulation_lock = threading.Lock()

def generate_random_packet() -> dict:
    """Generate a randomized packet dictionary for the simulation."""
    protocols = ["TCP", "UDP", "ICMP"]
    common_ports = [80, 443, 22, 53, 8080, 445, 139, 3306, 123]
    
    # Random source IP generator
    src_ips = [
        "192.168.1.100",  # Denied by default rule 1
        "192.168.1.50",
        "10.0.0.15",
        "8.8.8.8",
        "172.16.0.45",
        "192.168.1.200"
    ]
    
    src_ip = random.choice(src_ips)
    # 5% chance of a completely random IP
    if random.random() < 0.05:
        src_ip = f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
    dst_ip = f"192.168.1.{random.randint(1, 20)}"
    dst_port = random.choice(common_ports) if random.random() < 0.8 else random.randint(1025, 65535)
    protocol = random.choice(protocols)
    
    # Scapy-like additional fields if needed
    length = random.randint(40, 1500)
    
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length
    }

def process_and_log_packet(packet: dict):
    """Evaluate a single packet through the firewall engine and record the decision."""
    action, rule_id = evaluate_packet(packet)
    
    # Save the decision to the database
    with get_session() as session:
        decision = FirewallDecision(
            src_ip=packet["src_ip"],
            dst_ip=packet["dst_ip"],
            dst_port=packet["dst_port"],
            protocol=packet["protocol"],
            rule_matched_id=rule_id,
            action_taken=action
        )
        session.add(decision)
    
    # Emit event through the core event bus
    severity = "critical" if action == "deny" else "info"
    summary = f"Firewall: {action.upper()} packet from {packet['src_ip']} to {packet['dst_ip']}:{packet['dst_port']} (Rule #{rule_id or 'Default'})"
    
    log_event(
        source="firewall",
        severity=severity,
        summary=summary,
        raw_data={
            "src_ip": packet["src_ip"],
            "dst_ip": packet["dst_ip"],
            "dst_port": packet["dst_port"],
            "protocol": packet["protocol"],
            "length": packet.get("length", 64),
            "rule_id": rule_id,
            "action": action
        }
    )

def _simulation_loop(interval: float):
    """Internal loop for background synthetic traffic simulation."""
    global _simulation_running
    while _simulation_running:
        packet = generate_random_packet()
        process_and_log_packet(packet)
        time.sleep(interval)

def start_simulation(interval: float = 1.0):
    """Start the synthetic traffic simulation on a background thread."""
    global _simulation_thread, _simulation_running
    with _simulation_lock:
        if _simulation_running:
            return
        _simulation_running = True
        _simulation_thread = threading.Thread(
            target=_simulation_loop, 
            args=(interval,), 
            name="FirewallSimulationThread",
            daemon=True
        )
        _simulation_thread.start()
        print("Firewall simulation started.")

def stop_simulation():
    """Stop the synthetic traffic simulation."""
    global _simulation_thread, _simulation_running
    with _simulation_lock:
        if not _simulation_running:
            return
        _simulation_running = False
        if _simulation_thread:
            _simulation_thread.join(timeout=2.0)
            _simulation_thread = None
        print("Firewall simulation stopped.")

# --- LIVE MODE EXTENSION POINT ---
# This callback/loop will be updated in Prompt 4 to consume packets from the sniffer.
def handle_live_packet(scapy_packet):
    """
    Callback handler for live network packets.
    Extracts relevant headers and passes them to evaluate_packet.
    """
    # TODO: Implement live packet extraction and evaluation in Milestone 4.
    pass
