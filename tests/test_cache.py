import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone
from systemsentinel.cache import import_snapshot, read_cache
from systemsentinel.inventory import InventoryError


class CacheTests(unittest.TestCase):
    def test_verified_import_and_rejection_preserves_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.json"
            cache = Path(folder) / "cache.json"
            source.write_text(json.dumps({"schema_version": 1,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "synthetic": True, "records": []}))
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            import_snapshot(source, digest, cache, True)
            original = cache.read_bytes()
            with self.assertRaises(InventoryError):
                import_snapshot(source, "0"*64, cache, True)
            self.assertEqual(cache.read_bytes(), original)
            snapshot, meta = read_cache(cache, True)
            self.assertTrue(snapshot["synthetic"])
            self.assertEqual(meta["sha256"], digest)
            with self.assertRaises(InventoryError):
                read_cache(cache)
            envelope = json.loads(cache.read_text())
            envelope["sha256"] = "0"*64
            cache.write_text(json.dumps(envelope))
            with self.assertRaises(InventoryError):
                read_cache(cache, True)
