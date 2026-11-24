import unittest
from pathlib import Path

from phishscope.analyzer import analyze
from phishscope.report import build_report

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


class AnalyzerTests(unittest.TestCase):
    def test_phishing_sample_is_flagged(self):
        r = analyze((SAMPLES / "phishing_sample.eml").read_bytes(), "phishing_sample.eml")
        titles = {f["title"] for f in r["findings"]}
        self.assertEqual(r["verdict"], "Likely phishing")
        self.assertEqual(r["score"], 100)
        self.assertIn("SPF fail", titles)
        self.assertIn("Reply-To domain differs from From", titles)
        self.assertIn("Possible brand impersonation", titles)
        self.assertIn("Link text does not match destination", titles)
        self.assertIn("Attachment extension mismatch", titles)
        self.assertEqual(r["attachments"][0]["true_type"], "Windows executable (EXE/DLL)")
        self.assertEqual(len(r["attachments"][0]["sha256"]), 64)
        self.assertTrue(all(l["url"].startswith("hxxp") for l in r["links"]))

    def test_legit_sample_is_low_risk(self):
        r = analyze((SAMPLES / "legit_sample.eml").read_bytes(), "legit_sample.eml")
        self.assertEqual(r["verdict"], "Low risk")
        self.assertEqual(r["auth"], {"spf": "pass", "dkim": "pass", "dmarc": "pass"})

    def test_report_escapes_html(self):
        raw = b"From: <a@b.example>\nSubject: <script>alert(1)</script>\n\nhello"
        html = build_report(analyze(raw, "x.eml"))
        self.assertNotIn("<script>alert(1)</script>", html)


if __name__ == "__main__":
    unittest.main()
