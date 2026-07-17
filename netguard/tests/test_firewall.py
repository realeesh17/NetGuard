import unittest
import os
import tempfile

# Override DB path before importing anything from netguard
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db.close()
os.environ["NETGUARD_DB_PATH"] = f"sqlite:///{temp_db.name}"

from netguard.core.db import init_db, get_session
from netguard.core.models import FirewallRule, FirewallDecision, Event
from netguard.firewall.engine import evaluate_packet, match_ip, match_port, match_protocol
from netguard.firewall.simulate import process_and_log_packet
from netguard.firewall.visualize_data import get_sankey_data

class TestFirewall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        # Clear existing rules and decisions for fresh test run
        with get_session() as session:
            session.query(FirewallRule).delete()
            session.query(FirewallDecision).delete()
            session.query(Event).delete()

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(temp_db.name)
        except Exception:
            pass

    def test_ip_matching(self):
        # Test exact match
        self.assertTrue(match_ip("192.168.1.1", "192.168.1.1"))
        self.assertFalse(match_ip("192.168.1.1", "192.168.1.2"))
        
        # Test 'any' match
        self.assertTrue(match_ip("any", "10.0.0.5"))
        self.assertTrue(match_ip("ANY", "8.8.8.8"))
        
        # Test CIDR match
        self.assertTrue(match_ip("192.168.1.0/24", "192.168.1.50"))
        self.assertTrue(match_ip("192.168.1.0/24", "192.168.1.254"))
        self.assertFalse(match_ip("192.168.1.0/24", "192.168.2.1"))
        
        # Test invalid network gracefully returning False
        self.assertFalse(match_ip("invalid_cidr/99", "192.168.1.1"))

    def test_port_matching(self):
        # Test exact match
        self.assertTrue(match_port("80", 80))
        self.assertFalse(match_port("80", 443))
        
        # Test 'any' match
        self.assertTrue(match_port("any", 22))
        self.assertTrue(match_port("ANY", 8080))
        
        # Test range match
        self.assertTrue(match_port("80-100", 90))
        self.assertTrue(match_port("80-100", 80))
        self.assertTrue(match_port("80-100", 100))
        self.assertFalse(match_port("80-100", 79))
        self.assertFalse(match_port("80-100", 101))
        
        # Test invalid port gracefully returning False
        self.assertFalse(match_port("invalid_port", 80))

    def test_protocol_matching(self):
        self.assertTrue(match_protocol("TCP", "TCP"))
        self.assertTrue(match_protocol("tcp", "TCP"))
        self.assertTrue(match_protocol("ANY", "UDP"))
        self.assertFalse(match_protocol("TCP", "UDP"))

    def test_first_match_wins(self):
        with get_session() as session:
            # Rule 1: Deny TCP to port 80 from any
            rule_deny = FirewallRule(priority=10, action="deny", src_ip="any", dst_port="80", protocol="TCP")
            # Rule 2: Allow TCP to port 80 from any (higher priority number, evaluated second)
            rule_allow = FirewallRule(priority=20, action="allow", src_ip="any", dst_port="80", protocol="TCP")
            session.add_all([rule_deny, rule_allow])
            
        packet = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80, "protocol": "TCP"}
        action, rule_id = evaluate_packet(packet)
        self.assertEqual(action, "deny")
        self.assertEqual(rule_id, rule_deny.id)
        
        # Verify hit count updated
        with get_session() as session:
            r = session.get(FirewallRule, rule_deny.id)
            self.assertEqual(r.hit_count, 1)

    def test_process_and_log_packet(self):
        with get_session() as session:
            rule = FirewallRule(priority=5, action="allow", src_ip="192.168.1.0/24", dst_port="443", protocol="TCP")
            session.add(rule)
            
        packet = {"src_ip": "192.168.1.15", "dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "TCP"}
        process_and_log_packet(packet)
        
        # Verify decision logged in DB
        with get_session() as session:
            decisions = session.query(FirewallDecision).all()
            self.assertEqual(len(decisions), 1)
            self.assertEqual(decisions[0].src_ip, "192.168.1.15")
            self.assertEqual(decisions[0].action_taken, "allow")
            self.assertEqual(decisions[0].rule_matched_id, rule.id)
            
            # Verify event emitted
            events = session.query(Event).filter_by(source="firewall").all()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].severity, "info")
            self.assertIn("ALLOW", events[0].summary)

    def test_visualize_sankey(self):
        with get_session() as session:
            rule = FirewallRule(priority=1, action="deny", src_ip="any", dst_port="22", protocol="TCP")
            session.add(rule)
            
        packet = {"src_ip": "10.0.0.50", "dst_ip": "192.168.1.1", "dst_port": 22, "protocol": "TCP"}
        process_and_log_packet(packet)
        
        sankey = get_sankey_data()
        self.assertIn("nodes", sankey)
        self.assertIn("links", sankey)
        
        # Verify nodes contain src IP, Rule and Action
        node_names = [n["name"] for n in sankey["nodes"]]
        self.assertIn("10.0.0.50", node_names)
        self.assertIn("DENY", node_names)
        
        # Verify links connect them
        self.assertEqual(len(sankey["links"]), 2)

if __name__ == "__main__":
    unittest.main()
