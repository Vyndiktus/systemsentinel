"""Import a user-selected snapshot release from the project database repository."""
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import URLError

from .cache import import_snapshot
from .inventory import InventoryError

BASE = "https://github.com/Vyndiktus/systemsentinel-db/releases/download"
MAX_BYTES = 32 * 1024 * 1024
ALLOWED_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}


class ReleaseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urlsplit(newurl)
        if (parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS
                or parts.username or parts.password or parts.port not in (None, 443)):
            raise InventoryError("Unexpected GitHub release redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_release(tag, digest, allow_synthetic=False, destination=None):
    if not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag):
        raise InventoryError("Invalid release tag")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise InventoryError("A trusted SHA-256 digest is required")
    url = f"{BASE}/{tag}/snapshot.json"
    try:
        opener = build_opener(ReleaseRedirect())
        request = Request(url, headers={"User-Agent": "SystemSentinel"})
        with opener.open(request, timeout=30) as response:
            data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise InventoryError("Snapshot exceeds maximum permitted size")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "snapshot.json"
            path.write_bytes(data)
            metadata = import_snapshot(path, digest, destination, allow_synthetic)
        return {**metadata, "release": tag}
    except (OSError, URLError) as exc:
        raise InventoryError(f"Database download failed: {exc}") from exc
