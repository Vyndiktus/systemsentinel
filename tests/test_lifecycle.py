from datetime import date
import unittest
from systemsentinel.lifecycle import assess_lifecycle, defensive_references


class LifecycleScanTests(unittest.TestCase):
    def evaluate(self, distro, release, now):
        return assess_lifecycle({"ID": distro, "VERSION_ID": release}, today=now)

    def test_exact_release_standard_window(self):
        r = self.evaluate("ubuntu", "24.04", date(2026, 11, 25))
        self.assertEqual(r["status"], "standard_window")
        self.assertEqual(r["standard_until"], "2029-05")

    def test_month_only_boundary_not_guessed(self):
        r = self.evaluate("ubuntu", "24.04", date(2029, 5, 15))
        self.assertEqual(r["status"], "standard_boundary")

    def test_extended_program_requires_review(self):
        r = self.evaluate("debian", "12", date(2026, 11, 25))
        self.assertEqual(r["status"], "extended_coverage_review")

    def test_derivative_is_not_assumed_covered(self):
        r = self.evaluate("linuxmint", "22.3", date(2026, 11, 25))
        self.assertEqual(r["status"], "unknown_release")

    def test_ended_and_stale(self):
        r = self.evaluate("debian", "11", date(2027, 1, 1))
        self.assertEqual(r["status"], "published_extended_window_ended")
        self.assertTrue(self.evaluate("debian", "11", date(2027, 4, 1))["catalog_stale"])

    def test_source_references_are_not_exploitation_findings(self):
        context = defensive_references({"ID": "ubuntu"})
        self.assertEqual(context["exploitation_assessment"], "not_assessed")
        self.assertTrue(any(r["scope"] == "ubuntu" for r in context["references"]))
        self.assertFalse(any(r["scope"] == "debian" for r in context["references"]))
