import unittest
from netguard.core.threat_intel import (
    classify_ip_scope,
    get_port_risk_assessment,
    calculate_threat_score,
    enrich_event_payload
)

class TestThreatIntel(unittest.TestCase):

    def test_classify_ip_scope(self):
        self.assertEqual(classify_ip_scope("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip_scope("192.168.1.100"), "private")
        self.assertEqual(classify_ip_scope("10.0.0.1"), "private")
        self.assertEqual(classify_ip_scope("8.8.8.8"), "public")
        self.assertEqual(classify_ip_scope("169.254.1.1"), "link_local")
        self.assertEqual(classify_ip_scope("224.0.0.1"), "multicast")
        self.assertEqual(classify_ip_scope("invalid.ip"), "invalid")
        self.assertEqual(classify_ip_scope("any"), "any")

    def test_get_port_risk_assessment(self):
        rdp_eval = get_port_risk_assessment(3389)
        self.assertEqual(rdp_eval["service"], "RDP")
        self.assertEqual(rdp_eval["risk_level"], "critical")

        smb_eval = get_port_risk_assessment(445)
        self.assertEqual(smb_eval["service"], "SMB")
        self.assertEqual(smb_eval["risk_level"], "critical")

        http_eval = get_port_risk_assessment(80)
        self.assertEqual(http_eval["risk_level"], "low")

        custom_eval = get_port_risk_assessment(54321)
        self.assertEqual(custom_eval["service"], "Dynamic Port")

    def test_calculate_threat_score(self):
        # Baseline low threat
        res_low = calculate_threat_score(is_anomaly=False, payload_entropy=1.2, port=80, ip_address="192.168.1.5")
        self.assertEqual(res_low["risk_category"], "LOW")
        self.assertLess(res_low["threat_score"], 20.0)

        # High/Critical threat
        res_high = calculate_threat_score(
            is_anomaly=True,
            payload_entropy=7.1,
            port=3389,
            ip_address="203.0.113.5",
            signature_alert="SYN Flood Attack Detected"
        )
        self.assertEqual(res_high["risk_category"], "CRITICAL")
        self.assertGreaterEqual(res_high["threat_score"], 70.0)
        self.assertTrue(len(res_high["risk_factors"]) >= 4)

    def test_enrich_event_payload(self):
        raw = {
            "src_ip": "8.8.8.8",
            "dst_port": 445,
            "is_anomaly": True,
            "signature_alert": "Port Scan"
        }
        enriched = enrich_event_payload(raw)
        self.assertIn("threat_intelligence", enriched)
        ti = enriched["threat_intelligence"]
        self.assertEqual(ti["ip_scope"], "public")
        self.assertEqual(ti["port_assessment"]["service"], "SMB")
        self.assertIn("risk_category", ti)

if __name__ == "__main__":
    unittest.main()
