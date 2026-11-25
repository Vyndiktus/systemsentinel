import io
import json
import unittest
from unittest.mock import patch
from systemsentinel.client import check_client, compare_releases, version_key
from systemsentinel.inventory import InventoryError


class ClientTests(unittest.TestCase):
    def test_stable_after_previews_and_numeric_versions(self):
        self.assertGreater(version_key("v0.2.0"), version_key("v0.2.0-dev.10"))
        self.assertGreater(version_key("v0.1.0-dev.10"), version_key("0.1.0.dev9"))

    def test_ignores_drafts_and_unrecognized_tags(self):
        releases = [{"draft": False, "tag_name": "v0.1.0-dev.7"},
                    {"draft": True, "tag_name": "v9.9.9"},
                    {"draft": False, "tag_name": "unrelated"}]
        report = compare_releases(releases, "0.1.0.dev4")
        self.assertEqual(report["status"], "update_available")
        self.assertEqual(report["latest_tag"], "v0.1.0-dev.7")

    @patch("systemsentinel.client.build_opener")
    def test_check_current(self, factory):
        with patch("systemsentinel.client.compare_releases", wraps=compare_releases) as comparer:
            data = [{"draft": False, "tag_name": "v0.1.0-dev.4"}]
            factory.return_value.open.return_value = io.BytesIO(json.dumps(data).encode())
            report = check_client()
            self.assertEqual(report["latest_tag"], "v0.1.0-dev.4")
            comparer.assert_called_once()

    def test_malformed_response_rejected(self):
        with self.assertRaises(ValueError):
            compare_releases({"message": "rate limited"})
