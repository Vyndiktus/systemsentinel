import stat
from types import SimpleNamespace
import unittest
from systemsentinel.checks import review_metadata, audit_config


class ConfigurationTests(unittest.TestCase):
    def metadata(self, mode, uid=0):
        return lambda _: SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid)

    def test_normal_file(self):
        self.assertEqual(review_metadata("/demo", False, self.metadata(0o644))["status"], "pass")

    def test_permissive_file_requires_review(self):
        check = review_metadata("/demo", False, self.metadata(0o666))
        self.assertEqual(check["status"], "review")
        self.assertIn("writable", check["detail"])

    def test_protected_file_and_owner(self):
        check = review_metadata("/demo", True, self.metadata(0o644, 1000))
        self.assertEqual(check["status"], "review")
        self.assertIn("not owned by root", check["detail"])
        self.assertIn("other users", check["detail"])

    def test_missing_metadata_is_not_pass(self):
        def absent(_): raise FileNotFoundError()
        self.assertEqual(review_metadata("/demo", False, absent)["status"], "unavailable")

    def test_live_baseline_shape(self):
        checks = audit_config()
        self.assertEqual(len(checks), 6)
        self.assertTrue(all(item["status"] in {"pass", "review", "unavailable"} for item in checks))
