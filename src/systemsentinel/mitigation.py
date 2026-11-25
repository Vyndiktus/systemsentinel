"""Interpret local maintenance evidence against a vetted defensive control catalog."""
from datetime import date
from importlib.resources import files
import json


def review_mitigations(updates, index_status, lifecycle, catalog=None):
    if catalog is None:
        catalog = json.loads(files("systemsentinel").joinpath("data", "mitigations-v1.json").read_text(encoding="utf-8"))
    rows = []
    for item in catalog["records"]:
        assessment = item["assessment"]
        if assessment == "local_update_review":
            if updates is None:
                status, evidence = "not_assessed", "APT update review was not requested."
            elif any(update["security_pocket"] for update in updates):
                status, evidence = "review", "At least one available update is from a trusted security pocket."
            else:
                status, evidence = "no_candidates_observed", "No security-pocket candidate was observed; vulnerability status is not established."
        elif assessment == "local_index_review":
            if index_status is None:
                status, evidence = "not_assessed", "Local APT release validity was not checked."
            elif index_status["status"] == "within_declared_validity":
                status, evidence = "limited_evidence", "Present files have not passed their declared validity boundaries."
            else:
                status, evidence = "review", "Local release metadata is missing, expired or of uncertain freshness."
        elif assessment == "local_lifecycle_review":
            if lifecycle["status"] == "standard_window" and not lifecycle["catalog_stale"]:
                status, evidence = "limited_evidence", "Exact release is within its published standard maintenance window."
            else:
                status, evidence = "review", "Confirm vendor lifecycle coverage and catalog freshness."
        else:
            status, evidence = "manual_review", "This control was not assessed by the scanner."
        rows.append({**item, "status": status, "evidence": evidence})
    reviewed = date.fromisoformat(catalog["reviewed_on"])
    return {"reviewed_on": catalog["reviewed_on"], "catalog_stale": (date.today() - reviewed).days > 90,
            "records": rows, "scope": "Defensive maintenance and manual control review; no exploitation or compromise assessment."}
