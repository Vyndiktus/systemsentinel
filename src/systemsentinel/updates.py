"""Read-only view of candidates from the host's existing APT package indexes."""
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


def collect_updates():
    try:
        import apt
    except ImportError as exc:
        raise InventoryError("APT update check unavailable; use a Python interpreter with python3-apt installed") from exc
    try:
        return summarize_candidates(apt.Cache(memonly=True))
    except Exception as exc:
        raise InventoryError(f"Cannot read APT update metadata: {exc}") from exc
