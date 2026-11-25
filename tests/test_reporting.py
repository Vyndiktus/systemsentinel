import json
from pathlib import Path
import tempfile
import unittest
from systemsentinel.inventory import Package
from systemsentinel.reporting import build_report, render_html, render_json, save_report


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.report = build_report({"PRETTY_NAME": "<script>bad</script>"}, [Package("demo", "1.0", "all")],
                                   None, [], None, None)

    def test_json_roundtrip(self):
        data = json.loads(render_json(self.report))
        self.assertEqual(data["package_count"], 1)
        self.assertIsNone(data["configuration_checks"])

    def test_html_is_escaped_and_explicit_about_missing_data(self):
        html = render_html(self.report)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;bad&lt;/script&gt;", html)
        self.assertIn("Not requested", html)
        self.assertIn("No advisory database configured", html)
        self.assertIn("Individual exploitation status was not assessed", html)
        self.assertIn("demo", html)

    def test_save_report(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            save_report(path, self.report, "json")
            self.assertEqual(json.loads(path.read_text()), self.report)
