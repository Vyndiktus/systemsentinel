from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from systemsentinel.advisories import load_snapshot, patch_findings
from systemsentinel.inventory import InventoryError, Package


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "snapshot.json"
        self.snapshot = {"schema_version": 1, "generated_at": "2026-11-01T00:00:00Z",
                         "synthetic": True, "records": [{"distribution": "debian", "release": "12",
                         "package": "sentinel-demo", "fixed_version": "1:2.0-1+deb12u2",
                         "advisory": "DEMO-001", "reference": "https://example.invalid/demo"}]}
        self.path.write_text(json.dumps(self.snapshot))
        self.now = datetime(2026, 11, 25, tzinfo=timezone.utc)

    def test_synthetic_requires_opt_in(self):
        with self.assertRaises(InventoryError):
            load_snapshot(self.path, now=self.now)

    def test_digest_mismatch(self):
        with self.assertRaises(InventoryError):
            load_snapshot(self.path, "0" * 64, True, self.now)

    def test_validation_and_freshness(self):
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        _, meta = load_snapshot(self.path, digest, True, self.now)
        self.assertTrue(meta["stale"])
        self.assertTrue(meta["digest_checked"])

    def test_matching_is_distribution_specific(self):
        packages = [Package("sentinel-demo", "1:2.0-1+deb12u1", "amd64")]
        self.assertEqual(len(patch_findings(self.snapshot, {"ID": "debian", "VERSION_ID": "12"}, packages)), 1)
        self.assertEqual(patch_findings(self.snapshot, {"ID": "ubuntu", "VERSION_ID": "12"}, packages), [])

    def test_fixed_version_not_flagged(self):
        packages = [Package("sentinel-demo", "1:2.0-1+deb12u2", "amd64")]
        self.assertEqual(patch_findings(self.snapshot, {"ID": "debian", "VERSION_ID": "12"}, packages), [])
