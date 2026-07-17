import unittest
import os
import tempfile
import time

# Override DB path before importing anything from netguard
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db.close()
os.environ["NETGUARD_DB_PATH"] = f"sqlite:///{temp_db.name}"

from netguard.core.db import init_db, get_session
from netguard.core.models import Event
from netguard.sniffer.rules import (
    evaluate_packet_rules,
    calculate_entropy,
    IP_BLACKLIST,
    port_scan_history,
    syn_flood_history
)
from netguard.sniffer.features import extract_features

class TestSnifferRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        # Clear database and rolling histories before each test
        with get_session() as session:
            session.query(Event).delete()
        with threading_lock_cleanup():
            port_scan_history.clear()
            syn_flood_history.clear()

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(temp_db.name)
        except Exception:
            pass

    def test_shannon_entropy(self):
        # Predictable outcomes
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_entropy("aaaaa"), 0.0)
        # High random character set has high entropy
        entropy_normal = calculate_entropy("google.com")
        entropy_high = calculate_entropy("x8f2nd9a8c7b4e1w0q.onion")
        self.assertGreater(entropy_high, entropy_normal)

    def test_ip_blacklist_trigger(self):
        bad_ip = list(IP_BLACKLIST)[0]
        packet = {"src_ip": bad_ip, "dst_ip": "192.168.1.1", "length": 64}
        alerts = evaluate_packet_rules(packet)
        
        self.assertTrue(any("blacklisted IP" in alert for alert in alerts))
        
        # Verify event was logged in DB
        with get_session() as session:
            events = session.query(Event).filter_by(source="sniffer", severity="critical").all()
            self.assertEqual(len(events), 1)
            self.assertIn(bad_ip, events[0].summary)

    def test_port_scan_trigger(self):
        src_ip = "10.0.0.95"
        # Simulate scanning 20 unique ports
        alerts = []
        for port in range(1, 22):
            packet = {
                "src_ip": src_ip,
                "dst_ip": "192.168.1.1",
                "dst_port": port,
                "protocol": "TCP",
                "length": 64
            }
            alerts.extend(evaluate_packet_rules(packet))
            
        # The last packets should trigger the port scan alert
        self.assertTrue(any("Port scan detected" in alert for alert in alerts))
        
        with get_session() as session:
            events = session.query(Event).filter_by(source="sniffer", severity="warning").all()
            self.assertGreater(len(events), 0)
            self.assertTrue(any("Port scan detected" in e.summary for e in events))

    def test_syn_flood_trigger(self):
        src_ip = "10.0.0.96"
        alerts = []
        # Send 35 SYN packets (no ACKs)
        for _ in range(35):
            packet = {
                "src_ip": src_ip,
                "dst_ip": "192.168.1.1",
                "dst_port": 80,
                "protocol": "TCP",
                "flags": "S",
                "length": 64
            }
            alerts.extend(evaluate_packet_rules(packet))
            
        self.assertTrue(any("SYN Flood detected" in alert for alert in alerts))
        
        with get_session() as session:
            events = session.query(Event).filter_by(source="sniffer", severity="critical").all()
            self.assertGreater(len(events), 0)

    def test_dns_tunneling_trigger(self):
        # 1. Test long subdomain
        long_query = "a" * 60 + ".malicious-tunnel.com"
        packet1 = {
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": "UDP",
            "dns_query": long_query,
            "length": 128
        }
        alerts = evaluate_packet_rules(packet1)
        self.assertTrue(any("DNS Tunneling suspected" in alert and "length" in alert for alert in alerts))
        
        # 2. Test high entropy query
        random_query = "x8f2nd9a8c7b4e1w0q.com"
        packet2 = {
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": "UDP",
            "dns_query": random_query,
            "length": 128
        }
        alerts2 = evaluate_packet_rules(packet2)
        self.assertTrue(any("DNS Tunneling suspected" in alert and "entropy" in alert for alert in alerts2))

    def test_abnormal_packet_size(self):
        packet = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "length": 1500,
            "protocol": "TCP"
        }
        alerts = evaluate_packet_rules(packet)
        self.assertTrue(any("Abnormal packet size" in alert for alert in alerts))

    def test_feature_extraction(self):
        packets = [
            {"src_ip": "10.0.0.1", "dst_port": 80, "protocol": "TCP", "length": 100},
            {"src_ip": "10.0.0.1", "dst_port": 443, "protocol": "TCP", "length": 200},
            {"src_ip": "10.0.0.1", "dst_port": 53, "protocol": "UDP", "dns_query": "test.com", "length": 60},
        ]
        features = extract_features(packets, window_duration=10.0)
        
        self.assertEqual(len(features), 7)
        self.assertAlmostEqual(features[0], 0.3)  # 3 pkts / 10s
        self.assertEqual(features[1], 3.0)  # 3 unique ports
        self.assertAlmostEqual(features[2], 120.0)  # (100+200+60)/3
        self.assertAlmostEqual(features[3], 2/3)  # TCP ratio
        self.assertAlmostEqual(features[4], 1/3)  # UDP ratio
        self.assertEqual(features[5], 0.0)  # ICMP ratio

# Helper context to manage cleanup cleanly
import contextlib
@contextlib.contextmanager
def threading_lock_cleanup():
    yield
