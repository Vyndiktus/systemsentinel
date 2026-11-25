"""Offline vendor patch information; no network or system changes."""
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

from .inventory import InventoryError

FIELDS = {"distribution", "release", "package", "fixed_version", "advisory", "reference"}

def load_snapshot(path, digest=None, allow_synthetic=False, now=None):
    try:
        data = Path(path).read_bytes()
        actual_digest = hashlib.sha256(data).hexdigest()
        if digest is not None and not hmac.compare_digest(actual_digest, digest.lower()):
            raise ValueError("SHA-256 mismatch")
        snapshot = json.loads(data)
        if not isinstance(snapshot, dict) or set(snapshot) != {"schema_version", "generated_at", "synthetic", "records"}:
            raise ValueError("Invalid snapshot fields")
        if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
            raise ValueError("Unsupported snapshot schema")
        if type(snapshot["synthetic"]) is not bool or not isinstance(snapshot["records"], list):
            raise ValueError("Invalid snapshot metadata")
        if snapshot["synthetic"] and not allow_synthetic:
            raise ValueError("Synthetic snapshot requires --allow-synthetic")
        generated = datetime.fromisoformat(snapshot["generated_at"].replace("Z", "+00:00"))
        if generated.tzinfo is None:
            raise ValueError("Timestamp must include timezone")
        age = ((now or datetime.now(timezone.utc)) - generated).total_seconds() / 86400
        if age < -0.01:
            raise ValueError("Snapshot timestamp is in the future")
        for record in snapshot["records"]:
            if not isinstance(record, dict) or set(record) != FIELDS:
                raise ValueError("Invalid record fields")
            if not all(isinstance(v, str) and v.strip() for v in record.values()):
                raise ValueError("Record values must be nonempty strings")
            if record["distribution"] not in {"debian", "ubuntu"}:
                raise ValueError("Unsupported advisory distribution")
            if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", record["package"]):
                raise ValueError("Invalid package name")
            url = urlsplit(record["reference"])
            if url.scheme != "https" or not url.hostname:
                raise ValueError("Reference must be an HTTPS URL")
            result = subprocess.run(["dpkg", "--validate-version", record["fixed_version"]],
                                    capture_output=True, timeout=5)
            if result.returncode != 0:
                raise ValueError("Invalid Debian package version")
        return snapshot, {"sha256": actual_digest, "digest_checked": digest is not None,
                          "age_days": round(max(0, age), 2), "stale": age > 7,
                          "synthetic": snapshot["synthetic"]}
    except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
        raise InventoryError(f"Cannot load advisory snapshot: {exc}") from exc

def release_covered(snapshot, os_info):
    return any((record["distribution"], record["release"]) ==
               (os_info["ID"], os_info["VERSION_ID"])
               for record in snapshot["records"])


def patch_findings(snapshot, os_info, packages):
    records = {}
    for record in snapshot["records"]:
        if (record["distribution"], record["release"]) == (os_info["ID"], os_info["VERSION_ID"]):
            records.setdefault(record["package"], []).append(record)
    findings = []
    for package in packages:
        for record in records.get(package.name, []):
            try:
                result = subprocess.run(["dpkg", "--compare-versions", package.version, "lt", record["fixed_version"]],
                                        capture_output=True, timeout=5)
            except (OSError, subprocess.SubprocessError) as exc:
                raise InventoryError("Cannot compare vendor package versions") from exc
            if result.returncode == 0:
                findings.append({"package": package.name, "architecture": package.architecture,
                                 "installed_version": package.version, "fixed_version": record["fixed_version"],
                                 "advisory": record["advisory"], "reference": record["reference"],
                                 "recommendation": "Review the vendor notice and install the vendor-supported security update."})
            elif result.returncode != 1:
                raise InventoryError("Version comparison failed")
    return findings
