import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import recon


class TestFataReconSuite(unittest.TestCase):
    def test_normalize_url_adds_https_and_strips_trailing_slash(self):
        self.assertEqual(recon.normalize_url("example.com/"), "https://example.com")
        self.assertEqual(recon.normalize_url("http://api.example.com/v1/"), "http://api.example.com/v1")

    def test_extract_domain_parses_hostname(self):
        self.assertEqual(recon.extract_domain("https://sub.example.com:8443/path"), "sub.example.com")
        self.assertEqual(recon.extract_domain("hackerone.com"), "hackerone.com")

    def test_security_headers_dictionary_contains_core_owasp_headers(self):
        for required in ["content-security-policy", "strict-transport-security", "x-frame-options"]:
            self.assertIn(required, recon.SECURITY_HEADERS)

    def test_boundary_payloads_cover_zero_negative_and_overflow(self):
        values = [val for _, val, _ in recon.BOUNDARY_PAYLOADS]
        self.assertIn("0", values)
        self.assertIn("-500", values)
        self.assertIn("1e308", values)

    def test_build_remediation_matrix_generates_helmet_and_zod_blueprints(self):
        findings = [
            "[HIGH] Missing security header `content-security-policy`",
            "[MEDIUM] Permissive CORS Wildcard (`Access-Control-Allow-Origin: *`)",
            "[HIGH] Unhandled HTTP 500 exception on boundary payload `id=-500`"
        ]
        recs = "\n".join(recon.build_remediation_matrix(findings))
        self.assertIn("helmet", recs)
        self.assertIn("cors", recs)
        self.assertIn("InputSchema", recs)


if __name__ == "__main__":
    unittest.main()
