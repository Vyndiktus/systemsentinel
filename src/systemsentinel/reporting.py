"""Generate self-contained local reports for the CLI and the desktop app."""
from dataclasses import asdict
from datetime import datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import tempfile

from . import __version__


def build_report(os_info, packages, metadata, findings, updates=None, checks=None):
    status = "not_configured" if metadata is None else ("synthetic" if metadata["synthetic"] else "local_snapshot")
    return {
        "schema_version": 1,
        "application_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "distribution": os_info,
        "package_count": len(packages),
        "advisory_status": status,
        "database": metadata,
        "patch_findings": findings,
        "apt_update_candidates": updates,
        "apt_metadata_refreshed": False,
        "configuration_checks": checks,
        "packages": [asdict(package) for package in packages],
    }


def render_json(report):
    return json.dumps(report, indent=2) + "\n"


def cell(value):
    return escape(str(value), quote=True)


def table(title, items, columns):
    prefix = "<section><h2>" + cell(title) + "</h2>"
    if items is None:
        return prefix + "<p>Not requested.</p></section>"
    if not items:
        return prefix + "<p>No rows returned by this check.</p></section>"
    heading = "".join("<th scope=\"col\">" + cell(label) + "</th>" for _, label in columns)
    rows = "".join("<tr>" + "".join("<td>" + cell(item.get(key, "")) + "</td>" for key, _ in columns) + "</tr>" for item in items)
    return prefix + '<div class="scroll"><table><thead><tr>' + heading + "</tr></thead><tbody>" + rows + "</tbody></table></div></section>"


def render_html(report):
    metadata = report["database"]
    if metadata is None:
        advisory = "No advisory database configured; package inventory only."
    else:
        advisory = ("Fictional test data; not for operational use. " if metadata["synthetic"] else "Local snapshot. ")
        advisory += f"Age: {metadata['age_days']} days. "
        if metadata["stale"]:
            advisory += "Stale snapshot. "
        if not metadata["digest_checked"]:
            advisory += "Digest not independently checked. "
        if not metadata["release_covered"]:
            advisory += "No records for this exact distribution and release. "
        advisory += "Results limited to supplied data."
    updates = report["apt_update_candidates"]
    checks = report["configuration_checks"]
    security = sum(i["security_pocket"] for i in updates) if updates is not None else "Not requested"
    reviews = sum(i["status"] == "review" for i in checks) if checks is not None else "Not requested"
    style = """
    :root{color-scheme:light;--ink:#192c37;--muted:#536875;--accent:#126b70}
    body{font:15px/1.55 system-ui,sans-serif;color:var(--ink);background:#f4f7f7;max-width:1150px;margin:auto;padding:32px}
    header,section{background:white;border:1px solid #d8e3e4;border-radius:12px;padding:20px;margin:0 0 16px}
    h1,h2{margin:0 0 12px}h1{color:var(--accent)}h2{font-size:20px}
    .meta{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
    .card{border-left:4px solid var(--accent);background:#edf5f5;padding:12px}.card strong{display:block;font-size:25px}
    .scroll{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:9px;border-bottom:1px solid #dce7e7}
    th{background:#e9f2f2}td{overflow-wrap:anywhere}tr:nth-child(even){background:#f8fafa}
    @media print{body{background:white;padding:0}header,section{break-inside:auto}.scroll{overflow:visible}tr{break-inside:avoid}}
    """
    cards = "".join('<div class="card"><span>' + cell(label) + '</span><strong>' + cell(value) + '</strong></div>' for label, value in (
        ("Installed packages", report["package_count"]), ("Vendor patch findings", len(report["patch_findings"]) if metadata else "Not requested"),
        ("APT security-pocket candidates", security), ("Configuration items to review", reviews)))
    output = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
              '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
              "<title>SystemSentinel scan report</title><style>" + style + "</style></head><body>",
              "<header><h1>SystemSentinel scan report</h1><p class=\"meta\">" + cell(report["distribution"].get("PRETTY_NAME", "Linux")) +
              " · " + cell(report["generated_at"]) + " · version " + cell(report["application_version"]) + "</p>",
              '<div class="cards">' + cards + "</div><p>" + cell(advisory) + "</p>",
              "<p>APT index freshness is unknown. These limited checks do not establish overall system security. Inventory reports may contain sensitive system information.</p></header>"]
    output.append(table("Vendor patch guidance", None if metadata is None else report["patch_findings"], [
        ("package", "Package"), ("installed_version", "Installed"), ("fixed_version", "Fixed"), ("advisory", "Notice"),
        ("reference", "Vendor reference"), ("recommendation", "Recommendation")]))
    output.append(table("Available APT updates", updates, [("package", "Package"), ("installed_version", "Installed"),
        ("candidate_version", "Candidate"), ("security_pocket", "Security pocket"), ("recommendation", "Recommendation")]))
    output.append(table("Configuration baseline", checks, [("path", "Path"), ("status", "Status"), ("detail", "Details"), ("recommendation", "Recommendation")]))
    output.append(table("Installed packages", report["packages"], [("name", "Package"), ("architecture", "Architecture"), ("version", "Installed version")]))
    output.append("</body></html>")
    return "\n".join(output) + "\n"


def save_report(path, report, format_name):
    content = render_html(report) if format_name == "html" else render_json(report)
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
