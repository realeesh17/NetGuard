import unittest
import os
import tempfile
from pathlib import Path

# Override DB path before importing anything from netguard
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db.close()
os.environ["NETGUARD_DB_PATH"] = f"sqlite:///{temp_db.name}"

from netguard.core.db import init_db, get_session
from netguard.core.models import Event, FirewallRule
from netguard.core.events import log_event, register_event_listener, unregister_event_listener

class TestCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(temp_db.name)
        except Exception:
            pass

    def test_log_event_and_retrieve(self):
        # Test event logging
        event = log_event(
            source="sniffer",
            severity="warning",
            summary="Port scan detected from 192.168.1.50",
            raw_data={"ports_scanned": [21, 22, 80, 443]}
        )
        
        self.assertIsNotNone(event.id)
        
        # Retrieve and check from DB
        with get_session() as session:
            db_event = session.get(Event, event.id)
            self.assertIsNotNone(db_event)
            self.assertEqual(db_event.source, "sniffer")
            self.assertEqual(db_event.severity, "warning")
            self.assertEqual(db_event.summary, "Port scan detected from 192.168.1.50")
            self.assertEqual(db_event.raw_data["ports_scanned"], [21, 22, 80, 443])

    def test_event_listener_callback(self):
        received_events = []

        def callback(event_dict):
            received_events.append(event_dict)

        register_event_listener(callback)
        
        log_event(
            source="firewall",
            severity="critical",
            summary="Blocked traffic from 10.0.0.5",
            raw_data={"rule_id": 1}
        )
        
        unregister_event_listener(callback)
        
        # Log another event, shouldn't be received by callback
        log_event(
            source="phishing",
            severity="info",
            summary="Clean URL scan",
            raw_data={}
        )
        
        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0]["source"], "firewall")
        self.assertEqual(received_events[0]["severity"], "critical")

    def test_prepopulated_rules(self):
        with get_session() as session:
            rules = session.query(FirewallRule).order_by(FirewallRule.priority).all()
            self.assertGreater(len(rules), 0)
            self.assertEqual(rules[0].priority, 1)
            self.assertEqual(rules[0].action, "deny")

if __name__ == "__main__":
    unittest.main()
