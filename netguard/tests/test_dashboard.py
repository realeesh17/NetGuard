import unittest
import os
import json
import tempfile

# Override DB path before importing anything from netguard
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db.close()
os.environ["NETGUARD_DB_PATH"] = f"sqlite:///{temp_db.name}"

from netguard.core.db import init_db
from netguard.dashboard.app import app

class TestDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        app.config["TESTING"] = True
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(temp_db.name)
        except Exception:
            pass

    def test_index_route(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_stats_api(self):
        response = self.client.get("/api/dashboard/stats")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("total_packets", data)
        self.assertIn("allowed_packets", data)
        self.assertIn("denied_packets", data)
        self.assertIn("threat_alerts", data)

    def test_firewall_rules_api_get(self):
        response = self.client.get("/api/firewall/rules")
        self.assertEqual(response.status_code, 200)
        rules = json.loads(response.data)
        self.assertIsInstance(rules, list)

    def test_firewall_rules_api_post(self):
        payload = {
            "action": "deny",
            "src_ip": "192.168.1.100",
            "dst_port": "22",
            "protocol": "TCP"
        }
        response = self.client.post(
            "/api/firewall/rules",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 201)
        rules = json.loads(response.data)
        # Check that our rule exists in the list
        self.assertTrue(any(r["src_ip"] == "192.168.1.100" and r["action"] == "deny" for r in rules))

if __name__ == "__main__":
    unittest.main()
