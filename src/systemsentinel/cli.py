"""Command-line interface."""
import argparse
import json
import sys

from . import __version__
from .advisories import load_snapshot, patch_findings, release_covered
from .cache import cache_path, import_snapshot, read_cache
from .updates import collect_update_review, validity_message
from .download import download_release
from .checks import audit_config
from .reporting import build_report, render_json, render_html
from .inventory import InventoryError, collect_packages, detect_os


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Linux package inventory")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Inventory locally installed packages")
    scan.add_argument("--format", choices=("text", "json", "html"), default="text")
    scan.add_argument("--db", help="Path to a local vendor advisory snapshot")
    scan.add_argument("--sha256", help="Expected snapshot SHA-256 from a trusted source")
    scan.add_argument("--allow-synthetic", action="store_true", help="Permit fictional data for testing only")
    scan.add_argument("--config", action="store_true", help="Audit a limited local file-permissions baseline")
    scan.add_argument("--updates", action="store_true", help="Review local APT update candidates without refreshing indexes")
    scan.add_argument("--offline", action="store_true", help="Use the previously imported local snapshot")
    update = commands.add_parser("update", help="Verify and import a local or GitHub release snapshot")
    source = update.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="Import a local JSON file")
    source.add_argument("--release", help="Download a specific SystemSentinel database release")
    update.add_argument("--sha256", required=True)
    update.add_argument("--allow-synthetic", action="store_true")
    db = commands.add_parser("db", help="Show cached database status")
    db.add_argument("action", choices=("status",))
    db.add_argument("--allow-synthetic", action="store_true")
    args = parser.parse_args(argv)
    if args.command != "scan":
        try:
            if args.command == "update":
                if args.release:
                    metadata = download_release(args.release, args.sha256, args.allow_synthetic)
                else:
                    metadata = import_snapshot(args.file, args.sha256, allow_synthetic=args.allow_synthetic)
            else:
                _, metadata = read_cache(allow_synthetic=args.allow_synthetic)
            print(json.dumps({"path": str(cache_path()), **metadata}, indent=2))
            return 0
        except InventoryError as exc:
            print(f"systemsentinel: {exc}", file=sys.stderr)
            return 1
    if args.db and args.offline:
        parser.error("--db and --offline are mutually exclusive")
    if args.offline and args.sha256:
        parser.error("--sha256 is used when importing the snapshot, not with --offline")
    if (args.sha256 or args.allow_synthetic) and not (args.db or args.offline):
        parser.error("--sha256 and --allow-synthetic require --db or --offline")
    metadata = None
    findings = []
    updates = None
    apt_status = None
    checks = None
    try:
        os_info = detect_os()
        packages = collect_packages(os_info)
        if args.config:
            checks = audit_config()
        if args.updates:
            updates, apt_status = collect_update_review()
        if args.db or args.offline:
            if args.offline:
                snapshot, metadata = read_cache(allow_synthetic=args.allow_synthetic)
            else:
                snapshot, metadata = load_snapshot(args.db, args.sha256, args.allow_synthetic)
            metadata["release_covered"] = release_covered(snapshot, os_info)
            findings = patch_findings(snapshot, os_info, packages)
    except InventoryError as exc:
        print(f"systemsentinel: {exc}", file=sys.stderr)
        return 1

    report = build_report(os_info, packages, metadata, findings, updates, checks, apt_status)
    if args.format == "json":
        print(render_json(report), end="")
    elif args.format == "html":
        print(render_html(report), end="")
    else:
        print(f"SystemSentinel {__version__} — {os_info['PRETTY_NAME']}")
        print(f"Installed packages: {len(packages)}")
        if metadata is None:
            print("No advisory database supplied; inventory only.")
        else:
            print(f"Advisory database: {report['advisory_status']}; age: {metadata['age_days']} days; stale: {metadata['stale']}")
            if not metadata["digest_checked"]:
                print("Snapshot digest was not independently checked.")
            if not metadata["release_covered"]:
                print("No records for this exact distribution and release; assessment unavailable.")
            print(f"Vendor patch findings: {len(findings)} (limited to snapshot coverage)")
            for finding in findings:
                print(f"{finding['package']}: {finding['installed_version']} -> {finding['fixed_version']} ({finding['advisory']})")
                print(f"  {finding['recommendation']} {finding['reference']}")
        if updates is not None:
            print(f"APT update candidates: {len(updates)} from existing indexes.")
            print(validity_message(apt_status))
            for update in updates:
                category = "security pocket" if update["security_pocket"] else "general/other"
                print(f"  {update['package']}: {update['installed_version']} -> {update['candidate_version']} ({category})")
        if checks is not None:
            review_count = sum(check["status"] == "review" for check in checks)
            print(f"Configuration baseline: {review_count} items to review ({len(checks)} checks).")
            for check in checks:
                print(f"  [{check['status'].upper()}] {check['path']}: {check['detail']}")
                if check["status"] != "pass":
                    print(f"    {check['recommendation']}")
        for package in packages:
            print(f"{package.name}:{package.architecture}\t{package.version}")
    return 0
