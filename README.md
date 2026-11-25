# SystemSentinel

A lightweight, read-only Linux security maintenance assistant for system administrators.

**Development preview:** This version inventories installed packages on Debian and Ubuntu. It also supports offline vendor patch snapshots. The companion database currently contains fictional test data only; no operational advisory feed is available yet.

## Install on Debian or Ubuntu

Download the `.deb` package from the [GitHub release page](https://github.com/Vyndiktus/systemsentinel/releases) and verify its SHA-256 digest. From the download directory:

```sh
sudo apt install ./systemsentinel_0.1.0.dev3_all.deb
systemsentinel --version
```

The package includes a SystemSentinel application-menu entry. The recommended packages enable APT update review and the desktop GUI. Server administrators can install without recommended packages if they only need inventory and offline reporting.

## Run from source

Requires Python 3.10+ and a Debian-family Linux host.

```sh
# Use --system-site-packages if you plan to use the distro's python3-apt module.
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install .
systemsentinel scan
systemsentinel scan --format json > inventory.json
```

No root privileges or network connections are required for inventory. The tool does not install, remove, or update packages. Inventory reports may contain sensitive system information; store them appropriately.

## Desktop interface

On a Linux desktop with Python Tk installed (for example, the distribution package `python3-tk`), launch:

```sh
systemsentinel-gui
```

The desktop view provides an optional snapshot file picker, a Start scan button, a package table, and vendor patch guidance. It uses the same read-only backend as the CLI. No database means inventory only.

## Offline database preview

```sh
systemsentinel scan --db ../systemsentinel-db/examples/synthetic.json --allow-synthetic --format json
```

For a trusted vendor snapshot, omit the synthetic flag and provide its independently obtained digest using `--sha256 DIGEST`. Without a digest, authenticity is not verified. Snapshots older than seven days are marked stale. Results cover only the supplied records; an empty findings list does not establish that a system is secure.

Import an independently obtained local snapshot digest to use the same data offline:

```sh
systemsentinel update --file snapshot.json --sha256 TRUSTED_DIGEST
systemsentinel db status
systemsentinel scan --offline
```

The import writes only the user's local cache; scans do not fetch or install packages. The cached digest checks accidental data corruption, not authenticity against someone who can change the entire cache. Automated vendor feed refresh and signed releases are future work. The desktop interface can also use the imported offline database.

To add a menu shortcut, install the provided `desktop/systemsentinel.desktop` into your desktop's user applications directory (typically `~/.local/share/applications/`). Ensure `systemsentinel-gui` is available on your desktop session's PATH, or set its absolute executable path in the launcher.

## Development

Run directly from the source archive even when pip is unavailable:

```sh
PYTHONPATH=src python3 -m systemsentinel scan
```


```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Roadmap

- Distribution-specific security advisory and update status, including vendor backports.
- Patch availability and defensive mitigation recommendations.
- Local configuration checks and file integrity auditing.
- Additional Linux distributions and report formats.

License: MIT.

## Local APT update review

With the distribution's optional `python3-apt` module available to your Python interpreter:

```sh
systemsentinel scan --updates --format json
```

This reads the system's existing APT indexes in memory. The GUI offers the same option. A candidate from a trusted Debian or Ubuntu security pocket is marked as such; other candidates are listed as general/other. This is an update-candidate review, not a comprehensive security advisory match. It cannot determine whether indexes are current or whether an update will actually be installed (for example because of phasing or dependencies). Review available updates using the distribution's normal update manager.

## GitHub-hosted database snapshots

To import a specific release of the companion [database repository](https://github.com/Vyndiktus/systemsentinel-db/releases), obtain its trusted SHA-256 value independently and run:

```sh
systemsentinel update --release RELEASE_TAG --sha256 TRUSTED_DIGEST
systemsentinel scan --offline
```

The update command downloads only `snapshot.json` from the named project release, verifies it, then atomically replaces the local cache. It does not send the package inventory or install anything. A failed download or verification preserves the previous cache. Fictional test snapshots require explicit test-mode opt-in and must not be used for production assessments.

Desktop users can choose **Import GitHub release…**, enter the tag and trusted digest, and then click **Start scan**.

## Basic configuration review

```sh
systemsentinel scan --config
```

The configuration baseline reviews metadata (ownership and permission bits) for six standard system files. It never reads private file contents or changes permissions. A review result calls for comparison with distribution defaults; a pass only describes this single check, not overall system security. The desktop interface offers the same option.

## Save or share a report

```sh
systemsentinel scan --config --updates --format html > report.html
systemsentinel scan --config --format json > report.json
```

The HTML report is self-contained and can be opened offline in a browser. In the GUI, click **Save report…** after a successful scan to export HTML or JSON. Reports are local files and may include private inventory information; review before sharing.
