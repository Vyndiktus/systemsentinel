import contextlib
import io
import json
import unittest
from unittest.mock import patch

from systemsentinel.cli import main
from systemsentinel.inventory import InventoryError, Package, collect_packages, parse_dpkg


class InventoryTests(unittest.TestCase):
    def test_installed_only_preserves_versions_and_architecture(self):
        output = (
            "installed\tfoo\t1:2.0-1+deb12u1\tamd64\n"
            "config-files\told\t1.0\tall\n"
            "installed\tfoo\t1:2.0-1+deb12u1\ti386\n"
            "installed\tfoo\t1:2.0-1+deb12u1\tamd64\n"
        )
        self.assertEqual(parse_dpkg(output), [
            Package("foo", "1:2.0-1+deb12u1", "amd64"),
            Package("foo", "1:2.0-1+deb12u1", "i386"),
        ])

    def test_malformed_record_fails(self):
        with self.assertRaises(InventoryError):
            parse_dpkg("wrong")

    def test_unsupported_os(self):
        with self.assertRaises(InventoryError):
            collect_packages({"ID": "fedora", "ID_LIKE": ""})

    @patch("systemsentinel.cli.collect_packages", return_value=[Package("foo", "1", "all")])
    @patch("systemsentinel.cli.detect_os", return_value={"PRETTY_NAME": "Debian"})
    def test_json_distinguishes_inventory_from_advisory_scan(self, *_):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(main(["scan", "--format", "json"]), 0)
        report = json.loads(buffer.getvalue())
        self.assertEqual(report["package_count"], 1)
        self.assertEqual(report["advisory_status"], "not_configured")

    @patch("systemsentinel.cli.detect_os", side_effect=InventoryError("unavailable"))
    def test_error_exit(self, *_):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["scan"]), 1)


if __name__ == "__main__":
    unittest.main()
