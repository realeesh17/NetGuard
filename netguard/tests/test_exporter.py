import json
import unittest
from netguard.core.db import get_session
from netguard.core.models import Event
from netguard.core.exporter import export_events_json, export_events_csv, generate_markdown_audit_report

class TestExporter(unittest.TestCase):

    def setUp(self):
        with get_session() as session:
            session.query(Event).delete()
            session.add(Event(
                source="phishing",
                severity="critical",
                summary="Malicious URL scanned",
                raw_data={"url": "http://evil-phish.com"}
            ))
            session.add(Event(
                source="sniffer",
                severity="info",
                summary="Normal packet capture",
                raw_data={"length": 64}
            ))

    def test_export_json(self):
        json_data = export_events_json()
        parsed = json.loads(json_data)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["severity"], "info")  # desc limit order

    def test_export_csv(self):
        csv_data = export_events_csv()
        lines = csv_data.strip().split("\n")
        self.assertTrue(len(lines) >= 3)
        self.assertIn("Malicious URL scanned", csv_data)

    def test_generate_markdown_audit_report(self):
        report = generate_markdown_audit_report()
        self.assertIn("NetGuard Executive Security Audit Report", report)
        self.assertIn("Critical Alerts", report)
        self.assertIn("Malicious URL scanned", report)

if __name__ == "__main__":
    unittest.main()
