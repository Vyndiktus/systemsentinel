# Changelog

## 0.1.0.dev1

- Added explicit reporting when a snapshot contains no records for the host's exact distribution and release.
- Added explicit import of a checksummed JSON snapshot from a named GitHub database release.

## 0.1.0.dev0

- Initial Debian-family installed-package inventory.
- Text and JSON output, command-line interface, and tests.

- Added offline snapshot validation, age reporting, optional SHA-256 verification, and distribution-specific vendor patch guidance.
- Added a companion database schema and fictional test fixture.
- Added an optional Tk desktop interface for interactive local scans.
- Added explicit verified local snapshot import and offline cache status/scanning.
- Added a Linux desktop menu launcher and cached snapshot option.
- Added optional local APT candidate review, identifying trusted Debian and Ubuntu security pockets without refreshing package indexes or installing anything.
