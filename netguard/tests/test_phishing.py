import unittest
import os
import tempfile
from unittest.mock import patch, MagicMock
from datetime import datetime

# Override DB path before importing anything from netguard
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db.close()
os.environ["NETGUARD_DB_PATH"] = f"sqlite:///{temp_db.name}"

from netguard.core.db import init_db, get_session
from netguard.core.models import PhishingScan, Event
from netguard.phishing.analyze import analyze_url

class TestPhishing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        with get_session() as session:
            session.query(PhishingScan).delete()
            session.query(Event).delete()

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(temp_db.name)
        except Exception:
            pass

    @patch("netguard.phishing.analyze.fetch_url")
    @patch("netguard.phishing.analyze.get_cert_details")
    @patch("netguard.phishing.analyze.get_domain_info")
    def test_analyze_clean_site(self, mock_whois, mock_cert, mock_fetch):
        # 1. Clean site setup
        mock_fetch.return_value = {
            "html": "<html><body><h1>Welcome to Legit Website</h1></body></html>",
            "status_code": 200,
            "redirect_chain": ["http://legit.com"],
            "error": None
        }
        mock_cert.return_value = {
            "has_cert": True,
            "issuer": "Let's Encrypt",
            "valid": True,
            "self_signed": False,
            "days_to_expiry": 180
        }
        mock_whois.return_value = {
            "domain_age_days": 1000,
            "registrar": "Namecheap Inc.",
            "expiry_date": "2028-01-01T00:00:00"
        }
        
        result = analyze_url("http://legit.com")
        self.assertEqual(result["verdict"], "legitimate")
        self.assertLess(result["score"], 35.0)
        
        # Verify saved in DB
        with get_session() as session:
            scans = session.query(PhishingScan).all()
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0].url, "http://legit.com")
            self.assertEqual(scans[0].verdict, "legitimate")

    @patch("netguard.phishing.analyze.fetch_url")
    @patch("netguard.phishing.analyze.get_cert_details")
    @patch("netguard.phishing.analyze.get_domain_info")
    def test_analyze_off_domain_form_action(self, mock_whois, mock_cert, mock_fetch):
        # 2. Site with password input submitting off-domain
        mock_fetch.return_value = {
            "html": """
            <html>
                <body>
                    <form action="http://malicious-recipient.com/login" method="POST">
                        <input type="password" name="pwd" />
                        <input type="submit" />
                    </form>
                </body>
            </html>
            """,
            "status_code": 200,
            "redirect_chain": ["http://chase-update.com"],
            "error": None
        }
        mock_cert.return_value = {
            "has_cert": False,
            "issuer": None,
            "valid": False,
            "self_signed": False,
            "days_to_expiry": 0
        }
        mock_whois.return_value = {
            "domain_age_days": 500,
            "registrar": "Public Domain Registry",
            "expiry_date": "2027-06-01"
        }
        
        result = analyze_url("http://chase-update.com")
        self.assertIn(result["verdict"], ["suspicious", "phishing"])
        self.assertTrue(any("off-domain" in r for r in result["reasons"]))
        self.assertTrue(any("insecure HTTP" in r or "password" in r for r in result["reasons"]))

    @patch("netguard.phishing.analyze.fetch_url")
    @patch("netguard.phishing.analyze.get_cert_details")
    @patch("netguard.phishing.analyze.get_domain_info")
    def test_analyze_very_young_domain(self, mock_whois, mock_cert, mock_fetch):
        # 3. Domain age < 30 days
        mock_fetch.return_value = {
            "html": "<html><body><h1>Hello World</h1></body></html>",
            "status_code": 200,
            "redirect_chain": ["http://newly-registered-paypal-security.com"],
            "error": None
        }
        mock_cert.return_value = {
            "has_cert": True,
            "issuer": "Let's Encrypt",
            "valid": True,
            "self_signed": False,
            "days_to_expiry": 89
        }
        mock_whois.return_value = {
            "domain_age_days": 10,  # 10 days old!
            "registrar": "GoDaddy.com LLC",
            "expiry_date": "2027-07-16"
        }
        
        result = analyze_url("http://newly-registered-paypal-security.com")
        self.assertIn(result["verdict"], ["suspicious", "phishing"])
        self.assertTrue(any("extremely young" in r for r in result["reasons"]))
        self.assertTrue(any("Brand name mismatch" in r for r in result["reasons"]))

if __name__ == "__main__":
    unittest.main()
