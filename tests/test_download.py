from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from systemsentinel.download import download_release, ReleaseRedirect
from systemsentinel.inventory import InventoryError


class DownloadTests(unittest.TestCase):
    def test_import_and_bad_digest_preserves_cache(self):
        data = json.dumps({"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
                           "synthetic": True, "records": []}).encode()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as folder, patch("systemsentinel.download.build_opener") as factory:
            path = Path(folder) / "cache"
            factory.return_value.open.side_effect = lambda *_, **__: io.BytesIO(data)
            result = download_release("v0.1.0-dev.0", digest, True, path)
            self.assertEqual(result["release"], "v0.1.0-dev.0")
            original = path.read_bytes()
            with self.assertRaises(InventoryError):
                download_release("v0.1.0-dev.0", "0"*64, True, path)
            self.assertEqual(path.read_bytes(), original)

    def test_bad_tag_rejected(self):
        with self.assertRaises(InventoryError):
            download_release("../other", "0"*64)

    def test_untrusted_redirect_rejected(self):
        with self.assertRaises(InventoryError):
            ReleaseRedirect().redirect_request(None, None, 302, "", {}, "https://example.com/file")
