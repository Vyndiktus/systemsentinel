"""Read-only view of candidates from the host's existing APT package indexes."""
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from .inventory import InventoryError


def is_security_origin(origin):
    if not origin.trusted:
        return False
    if origin.origin == "Ubuntu":
        return origin.archive.endswith("-security")
    if origin.origin == "Debian":
        return origin.label == "Debian-Security"
    return False


def summarize_candidates(cache):
    results = []
    for package in cache:
        if not package.is_installed or not package.is_upgradable or package.candidate is None:
            continue
        candidate = package.candidate
        security = any(is_security_origin(origin) for origin in candidate.origins)
        results.append({
            "package": package.name,
            "installed_version": package.installed.version,
            "candidate_version": candidate.version,
            "security_pocket": security,
            "recommendation": "Review the update in your distribution's package manager.",
        })
    return sorted(results, key=lambda item: (not item["security_pocket"], item["package"]))


def index_validity(directory, now=None):
    """Summarize declared expiry for present local release files; do not authenticate or refresh."""
    now = now or datetime.now(timezone.utc)
    counts = {"within_declared_validity": 0, "expired": 0, "no_expiry": 0, "unreadable": 0}
    try:
        directory = Path(directory)
        files = set(directory.glob("*_InRelease")) | set(directory.glob("*_Release"))
    except OSError:
        files = set()
    for path in files:
        try:
            expiry = None
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for _ in range(250):
                    line = handle.readline()
                    if not line or line.startswith(("MD5Sum:", "SHA1:", "SHA256:", "SHA512:")):
                        break
                    if line.startswith("Valid-Until:"):
                        expiry = parsedate_to_datetime(line.split(":", 1)[1].strip())
                        if expiry.tzinfo is None:
                            raise ValueError("Expiry timezone missing")
                        break
            if expiry is None:
                counts["no_expiry"] += 1
            elif expiry <= now:
                counts["expired"] += 1
            else:
                counts["within_declared_validity"] += 1
        except (OSError, ValueError, TypeError, OverflowError):
            counts["unreadable"] += 1
    status = ("missing" if not files else "expired" if counts["expired"]
              else "unknown" if counts["no_expiry"] or counts["unreadable"]
              else "within_declared_validity")
    return {"status": status, "release_files": len(files), **counts,
            "note": "Local release files only; repository completeness and signatures are not rechecked."}


def validity_message(info):
    if info is None:
        return "APT index validity was not checked."
    labels = {"missing": "No local release metadata found.",
              "expired": "One or more locally cached release validity windows have expired.",
              "unknown": "Some cached releases have no readable expiry; freshness is uncertain.",
              "within_declared_validity": "Present local release files are within their declared validity windows."}
    return labels[info["status"]] + " Review repository freshness in your distribution's update manager."


def collect_update_review():
    try:
        import apt
        import apt_pkg
    except ImportError as exc:
        raise InventoryError("APT update check unavailable; use a Python interpreter with python3-apt installed") from exc
    try:
        cache = apt.Cache(memonly=True)
        return summarize_candidates(cache), index_validity(apt_pkg.config.find_dir("Dir::State::lists"))
    except Exception as exc:
        raise InventoryError(f"Cannot read APT update metadata: {exc}") from exc


def collect_updates():
    return collect_update_review()[0]
