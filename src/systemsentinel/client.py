"""Explicit, read-only application version checks using the project's GitHub releases."""
import json
import re
from urllib.request import Request, build_opener, HTTPRedirectHandler

from . import __version__
from .inventory import InventoryError

API = "https://api.github.com/repos/Vyndiktus/systemsentinel/releases?per_page=100"
RELEASES = "https://github.com/Vyndiktus/systemsentinel/releases"
MAX_BYTES = 4 * 1024 * 1024


def version_key(name):
    # Stable releases sort after development previews of the same base version.
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:(?:\.dev|-dev\.)(\d+))?", name)
    if not match:
        raise ValueError("Unrecognized application version")
    major, minor, patch = map(int, match.group(1, 2, 3))
    dev = match.group(4)
    return major, minor, patch, dev is None, int(dev or 0)


def compare_releases(releases, current=__version__):
    if not isinstance(releases, list):
        raise ValueError("Unexpected release response")
    candidates = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") is not False:
            continue
        tag = release.get("tag_name")
        if not isinstance(tag, str):
            continue
        try:
            key = version_key(tag)
        except ValueError:
            continue
        candidates.append((key, tag))
    if not candidates:
        raise ValueError("No recognized published versions")
    latest_key, latest_tag = max(candidates)
    installed = version_key(current)
    state = "update_available" if latest_key > installed else "current" if latest_key == installed else "ahead"
    return {"installed_version": current, "latest_tag": latest_tag, "status": state,
            "prerelease": not latest_key[3], "release_url": f"{RELEASES}/tag/{latest_tag}"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InventoryError("Unexpected redirect during client version check")


def check_client():
    try:
        request = Request(API, headers={"Accept": "application/vnd.github+json", "User-Agent": "SystemSentinel"})
        with build_opener(NoRedirect()).open(request, timeout=15) as response:
            data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise InventoryError("Release response exceeds maximum size")
        return compare_releases(json.loads(data))
    except (OSError, ValueError, TypeError) as exc:
        raise InventoryError(f"Client version check unavailable: {exc}") from exc
