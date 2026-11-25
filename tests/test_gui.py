import unittest
from unittest.mock import patch
from systemsentinel.gui import scan_local
from systemsentinel.inventory import Package


class GuiBackendTests(unittest.TestCase):
    @patch("systemsentinel.gui.collect_packages", return_value=[Package("demo", "1.0", "all")])
    @patch("systemsentinel.gui.detect_os", return_value={"ID": "debian", "VERSION_ID": "12"})
    def test_inventory_without_database(self, *_):
        _, packages, metadata, findings = scan_local()
        self.assertEqual(len(packages), 1)
        self.assertIsNone(metadata)
        self.assertEqual(findings, [])

    @patch("systemsentinel.gui.patch_findings", return_value=[{"package": "demo"}])
    @patch("systemsentinel.gui.load_snapshot", return_value=({}, {"synthetic": True}))
    @patch("systemsentinel.gui.collect_packages", return_value=[])
    @patch("systemsentinel.gui.detect_os", return_value={"ID": "debian", "VERSION_ID": "12"})
    def test_snapshot_backend(self, detect, collect, load, findings):
        _, _, _, result = scan_local("snapshot.json", "digest", True)
        load.assert_called_once_with("snapshot.json", "digest", True)
        self.assertEqual(result, [{"package": "demo"}])
