#!/usr/bin/env python3
"""Build an architecture-independent Debian package without installing it."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def build(destination):
    source_version = re.search(r'^version = "(\d+\.\d+\.\d+)\.dev(\d+)"$',
                               (ROOT / "pyproject.toml").read_text(), re.MULTILINE)
    if not source_version:
        raise ValueError("Expected a development version in pyproject.toml")
    version = f"{source_version.group(1)}~dev{source_version.group(2)}"
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"systemsentinel_{version}_all.deb"

    with tempfile.TemporaryDirectory() as work:
        stage = Path(work) / "package"
        control_dir = stage / "DEBIAN"
        control_dir.mkdir(parents=True)
        (control_dir / "control").write_text(f"""Package: systemsentinel
Version: {version}
Section: admin
Priority: optional
Architecture: all
Maintainer: SystemSentinel contributors <147536230+Vyndiktus@users.noreply.github.com>
Depends: python3 (>= 3.10)
Recommends: python3-apt, python3-tk
Homepage: https://github.com/Vyndiktus/systemsentinel
Description: Read-only Linux security maintenance assistant
 Inventories installed packages, reviews local APT update candidates,
 validates maintenance snapshots, and provides CLI and desktop reporting.
""")
        package_dir = stage / "usr/lib/python3/dist-packages/systemsentinel"
        shutil.copytree(ROOT / "src/systemsentinel", package_dir,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        bin_dir = stage / "usr/bin"
        bin_dir.mkdir(parents=True)
        for name, module in (("systemsentinel", "systemsentinel"), ("systemsentinel-gui", "systemsentinel.gui")):
            path = bin_dir / name
            path.write_text(f'#!/bin/sh\nexec /usr/bin/python3 -m {module} "$@"\n')
            path.chmod(0o755)
        apps = stage / "usr/share/applications"
        apps.mkdir(parents=True)
        shutil.copy2(ROOT / "desktop/systemsentinel.desktop", apps)
        docs = stage / "usr/share/doc/systemsentinel"
        docs.mkdir(parents=True)
        for filename, target in (("README.md", "README.md"), ("LICENSE", "copyright"), ("CHANGELOG.md", "CHANGELOG.md")):
            shutil.copy2(ROOT / filename, docs / target)
        for item in [stage, *stage.rglob("*")]:
            if item.is_dir() or item.parent == bin_dir:
                item.chmod(0o755)
            else:
                item.chmod(0o644)
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(output)], check=True)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    print(build(args.output))


if __name__ == "__main__":
    main()
