import unittest
from netguard.core.db import get_session
from netguard.core.models import PacketLog, Event, FirewallRule
from netguard.firewall.rule_generator import generate_firewall_recommendations, apply_recommendation

class TestRuleGenerator(unittest.TestCase):

    def setUp(self):
        with get_session() as session:
            session.query(PacketLog).delete()
            session.query(Event).delete()
            session.query(FirewallRule).delete()

    def test_generate_and_apply_recommendations(self):
        with get_session() as session:
            # Add an anomalous packet log
            pkt = PacketLog(
                src_ip="198.51.100.42",
                dst_ip="192.168.1.1",
                protocol="TCP",
                length=120,
                is_anomaly=True
            )
            # Add a critical event
            evt = Event(
                source="sniffer",
                severity="critical",
                summary="SYN Flood Attack",
                raw_data={"src_ip": "203.0.113.88", "dst_port": 80}
            )
            session.add_all([pkt, evt])

        recs = generate_firewall_recommendations()
        self.assertTrue(len(recs) >= 2)

        # Check rec values
        ips = [r["src_ip"] for r in recs]
        self.assertIn("198.51.100.42", ips)
        self.assertIn("203.0.113.88", ips)

        # Apply a recommendation
        applied = apply_recommendation(recs[0])
        self.assertEqual(applied["src_ip"], recs[0]["src_ip"])
        self.assertEqual(applied["action"], "deny")

        # Verify existing rule prevents duplicate rec
        new_recs = generate_firewall_recommendations()
        new_ips = [r["src_ip"] for r in new_recs]
        self.assertNotIn(recs[0]["src_ip"], new_ips)

if __name__ == "__main__":
    unittest.main()
