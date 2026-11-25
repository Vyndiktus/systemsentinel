"""Review the local OS against the separately published vendor maintenance catalog."""
from datetime import date
from importlib.resources import files
import json
import calendar


def date_range(value):
    if len(value) == 7:
        first = date.fromisoformat(value + "-01")
        return first, date(first.year, first.month, calendar.monthrange(first.year, first.month)[1])
    exact = date.fromisoformat(value)
    return exact, exact


def assess_lifecycle(os_info, catalog=None, today=None):
    today = today or date.today()
    if catalog is None:
        catalog = json.loads(files("systemsentinel").joinpath("data", "lifecycle-v1.json").read_text(encoding="utf-8"))
    reviewed = date.fromisoformat(catalog["reviewed_on"])
    basis = {"reviewed_on": reviewed.isoformat(), "catalog_stale": (today - reviewed).days > 90,
             "note": "Release-level maintenance only; package, architecture and entitlement coverage may differ."}
    for record in catalog["records"]:
        if (record["distribution"], record["release"]) != (os_info.get("ID"), os_info.get("VERSION_ID")):
            continue
        standard_first, standard_last = date_range(record["standard_until"])
        extended_first, extended_last = date_range(record["extended_until"])
        if today > extended_last:
            status = "published_extended_window_ended"
        elif today >= extended_first:
            status = "extended_boundary"
        elif today > standard_last:
            status = "extended_coverage_review"
        elif today >= standard_first:
            status = "standard_boundary"
        else:
            status = "standard_window"
        return {**basis, **record, "status": status}
    return {**basis, "status": "unknown_release",
            "guidance": "Check the installed distribution's official lifecycle information; this exact release is not in the bundled catalog."}


def lifecycle_message(result):
    labels = {"standard_window": "Within published standard maintenance window.",
              "standard_boundary": "At the published standard maintenance boundary; confirm the exact date.",
              "extended_coverage_review": "Standard maintenance ended; verify extended coverage or upgrade.",
              "extended_boundary": "At the published extended maintenance boundary; confirm the exact date.",
              "published_extended_window_ended": "Published standard and extended windows ended; review upgrade or other support.",
              "unknown_release": "This exact distribution and release are not covered by the lifecycle catalog."}
    stale = " Catalog review is older than 90 days; recheck the vendor." if result["catalog_stale"] else ""
    return labels[result["status"]] + stale


def defensive_references(os_info):
    catalog = json.loads(files("systemsentinel").joinpath("data", "guidance-v1.json").read_text(encoding="utf-8"))
    return {"reviewed_on": catalog["reviewed_on"], "exploitation_assessment": "not_assessed",
            "references": [record for record in catalog["sources"]
                           if record["scope"] in {"general", os_info.get("ID")}]}
