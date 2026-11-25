"""Small, read-only baseline checks of local system-file ownership and modes."""
from pathlib import Path
import stat

BASELINE = (
    ("/etc/passwd", False),
    ("/etc/group", False),
    ("/etc/shadow", True),
    ("/etc/gshadow", True),
    ("/etc/hosts", False),
    ("/etc/fstab", False),
)


def review_metadata(path, private, stat_path=None):
    inspect = stat_path or (lambda name: Path(name).stat())
    recommendation = "Review ownership and permissions against your distribution's defaults using normal system administration tools."
    try:
        info = inspect(path)
    except OSError:
        return {"check": "System file permissions", "path": path, "status": "unavailable",
                "detail": "File absent or metadata unavailable.", "recommendation": "Confirm whether this file is expected on this host."}
    mode = stat.S_IMODE(info.st_mode)
    concerns = []
    if not stat.S_ISREG(info.st_mode):
        concerns.append("not a regular file")
    if info.st_uid != 0:
        concerns.append("not owned by root")
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        concerns.append("writable by group or others")
    if private and mode & stat.S_IRWXO:
        concerns.append("permissions granted to other users")
    return {
        "check": "System file permissions", "path": path,
        "status": "review" if concerns else "pass",
        "detail": "; ".join(concerns) if concerns else "Matches the limited baseline checks.",
        "recommendation": recommendation if concerns else "No action indicated by this check.",
    }


def audit_config():
    return [review_metadata(path, private) for path, private in BASELINE]
