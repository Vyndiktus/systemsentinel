"""Explicit, atomic import of verified local snapshots."""
import base64
import json
import os
from pathlib import Path
import tempfile

from .advisories import load_snapshot
from .inventory import InventoryError


def cache_path():
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "systemsentinel" / "snapshot-envelope.json"


def import_snapshot(source, digest, destination=None, allow_synthetic=False):
    if not isinstance(digest, str) or len(digest) != 64:
        raise InventoryError("A trusted SHA-256 digest is required")
    destination = Path(destination or cache_path())
    try:
        data = Path(source).read_bytes()
        # Validate exactly the bytes that will be stored.
        with tempfile.TemporaryDirectory() as folder:
            staged = Path(folder) / "snapshot.json"
            staged.write_bytes(data)
            _, meta = load_snapshot(staged, digest, allow_synthetic)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=destination.parent, delete=False) as handle:
            temp = Path(handle.name)
            try:
                json.dump({"sha256": meta["sha256"], "data": base64.b64encode(data).decode("ascii")}, handle)
                handle.flush()
                os.fsync(handle.fileno())
                os.replace(temp, destination)
            finally:
                temp.unlink(missing_ok=True)
        return meta
    except OSError as exc:
        raise InventoryError(f"Cannot import local database: {exc}") from exc


def read_cache(source=None, allow_synthetic=False):
    source = Path(source or cache_path())
    try:
        envelope = json.loads(source.read_text())
        digest = envelope["sha256"]
        data = base64.b64decode(envelope["data"], validate=True)
        with tempfile.TemporaryDirectory() as folder:
            staged = Path(folder) / "snapshot.json"
            staged.write_bytes(data)
            snapshot, meta = load_snapshot(staged, digest, allow_synthetic)
        meta["digest_source"] = "cached_import"
        return snapshot, meta
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InventoryError(f"Cannot read cached database: {exc}") from exc
