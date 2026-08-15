import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from analyzer.heuristics import analyze_heuristics
from analyzer.scoring import calculate_risk
from analyzer.url_parser import parse_url

class PhishingAnalyzerTests(unittest.TestCase):

    def test_https_normal_url_has_no_basic_warnings(self):
        parsed = parse_url("https://example.com/")
        findings = analyze_heuristics(parsed)
        names = {item["name"] for item in findings}
        self.assertNotIn("No HTTPS", names)
        self.assertNotIn("IP Address Host", names)

    def test_ip_address_is_detected(self):
        parsed = parse_url("http://192.168.1.50/login")
        findings = analyze_heuristics(parsed)
        names = {item["name"] for item in findings}
        self.assertIn("IP Address Host", names)

    def test_at_symbol_is_detected(self):
        parsed = parse_url("https://example.com@evil.example/login")
        findings = analyze_heuristics(parsed)
        self.assertIn("@ Symbol", {item["name"] for item in findings})

    def test_shortener_is_detected(self):
        parsed = parse_url("https://bit.ly/example")
        findings = analyze_heuristics(parsed)
        self.assertIn("URL Shortener", {item["name"] for item in findings})

    def test_punycode_is_detected(self):
        parsed = parse_url("https://xn--example-9za.com")
        findings = analyze_heuristics(parsed)
        self.assertIn("Punycode / IDN", {item["name"] for item in findings})

    def test_risk_score_caps_at_100(self):
        parsed = parse_url("http://192.168.1.50@evil.example:8080/login/verify/password?redirect=https%3A%2F%2Fevil.com")
        risk = calculate_risk(analyze_heuristics(parsed))
        self.assertLessEqual(risk.score, 100)
        self.assertGreaterEqual(risk.score, 0)

    def test_invalid_url(self):
        parsed = parse_url("not a valid url")
        self.assertFalse(parsed.is_valid)

if __name__ == "__main__":
    unittest.main()
