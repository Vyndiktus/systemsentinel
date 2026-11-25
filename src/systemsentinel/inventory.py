"""Collect installed Debian-family packages without changing the host."""
from dataclasses import dataclass
import platform
import subprocess


class InventoryError(RuntimeError):
    """An inventory could not be collected."""


@dataclass(frozen=True, order=True)
class Package:
    name: str
    version: str
    architecture: str


def detect_os() -> dict[str, str]:
    try:
        info = platform.freedesktop_os_release()
    except OSError as exc:
        raise InventoryError("Cannot read Linux distribution information") from exc
    return {key: info.get(key, "") for key in ("ID", "ID_LIKE", "VERSION_ID", "PRETTY_NAME")}


def parse_dpkg(output: str) -> list[Package]:
    packages = set()
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            raise InventoryError("Unexpected format in dpkg-query output")
        status, name, version, architecture = fields
        if status == "installed":
            if not all((name, version, architecture)):
                raise InventoryError("Incomplete installed package record")
            packages.add(Package(name, version, architecture))
    return sorted(packages)


def collect_packages(os_info: dict[str, str]) -> list[Package]:
    family = set(os_info["ID_LIKE"].split()) | {os_info["ID"]}
    if not family.intersection({"debian", "ubuntu"}):
        raise InventoryError("Only Debian-family package inventory is supported in this release")
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${db:Status-Status}\\t${Package}\\t${Version}\\t${Architecture}\\n"],
            check=True, capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InventoryError("dpkg-query failed; inventory is unavailable") from exc
    return parse_dpkg(result.stdout)
