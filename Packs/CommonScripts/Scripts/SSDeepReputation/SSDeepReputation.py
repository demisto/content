import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, cast

REPUTATIONS = {0: "None", 1: "Good", 2: "Suspicious", 3: "Bad"}


def get_investigation_ids(indicator: dict[str, Any]) -> list[str]:
    """Get investigation IDs from indicator, supporting both 'investigationIDs' and 'investigationID' keys.

    Args:
        indicator: The indicator object

    Returns:
        List of investigation IDs
    """
    inv_ids = indicator.get("investigationIDs")
    if inv_ids is not None:
        return inv_ids if isinstance(inv_ids, list) else [inv_ids]

    inv_id = indicator.get("investigationID")
    if inv_id is not None:
        return [inv_id] if not isinstance(inv_id, list) else inv_id

    return []


def get_indicator_from_value(indicator_value: str | None) -> dict[str, Any] | None:
    try:
        if not indicator_value:
            return None
        res = demisto.executeCommand("findIndicators", {"value": indicator_value})
        if res and isinstance(res, list) and len(res) > 0:
            contents = res[0].get("Contents")
            if contents and isinstance(contents, list) and len(contents) > 0:
                return contents[0]
        return None
    except Exception:
        return None


def get_ssdeep_related_indicators(ssdeep_indicator: dict[str, Any]) -> list[dict[str, Any]]:
    related_indicators: list[dict[str, Any] | None] = [ssdeep_indicator]
    for inv_id in get_investigation_ids(ssdeep_indicator):
        try:
            res = demisto.executeCommand("getContext", {"id": inv_id})
            if res and isinstance(res, list) and len(res) > 0:
                contents = res[0].get("Contents", {})
                context = contents.get("context") if isinstance(contents, dict) else {}
                # Sanitize ssdeep value to prevent DT query syntax errors
                ssdeep_value = str(ssdeep_indicator.get("value", "")).replace("'", "\\'")
                file_obj = demisto.dt(context, f"File(val.SSDeep == '{ssdeep_value}')")
                if file_obj is None:
                    file_obj = {}
                elif isinstance(file_obj, list) and len(file_obj) > 0:
                    file_obj = file_obj[0]

                if isinstance(file_obj, dict):
                    related_indicators.append(get_indicator_from_value(file_obj.get("MD5")))
                    related_indicators.append(get_indicator_from_value(file_obj.get("SHA1")))
                    related_indicators.append(get_indicator_from_value(file_obj.get("SHA256")))
        except Exception:
            continue
    return [x for x in related_indicators if x is not None]


def main():
    ssdeep_value = demisto.args().get("input")
    current_incident_id = demisto.investigation().get("id")
    res = demisto.executeCommand(
        "similarSsdeep",
        {
            "value": ssdeep_value,
            "daysTimeFrame": int(demisto.args().get("timeFrameDays", "1")),
            "threshold": int(demisto.args().get("threshold", "50")),
        },
    )
    ssdeep_indicators: list[dict[str, Any]] = []
    if res and isinstance(res, list) and len(res) > 0:
        contents = res[0].get("Contents", [])
        if isinstance(contents, list):
            ssdeep_indicators = [
                cast(dict[str, Any], x.get("indicator") or {})
                for x in contents
                if isinstance(x, dict) and isinstance(x.get("indicator"), dict)
            ]
    ssdeep_indicator = get_indicator_from_value(ssdeep_value)
    if not ssdeep_indicator:
        # make the current ssdeep part of the current invastigation
        ssdeep_indicator = {"investigationIDs": [current_incident_id], "score": 0}
    else:
        # make sure the current ssdeep part of the current invastigation
        # Check if investigationIDs key exists (supporting both singular and plural forms)
        if "investigationIDs" not in ssdeep_indicator and "investigationID" not in ssdeep_indicator:
            # Neither key exists - create investigationIDs
            ssdeep_indicator["investigationIDs"] = [current_incident_id]
        else:
            # At least one key exists - get the IDs and check if current_incident_id is in them
            inv_ids = get_investigation_ids(ssdeep_indicator)
            if current_incident_id not in inv_ids:
                # Need to add current_incident_id
                if "investigationIDs" in ssdeep_indicator:
                    # investigationIDs exists - use setdefault for defensive programming
                    # Protects against edge case where key exists but value is None or not a list
                    ssdeep_indicator.setdefault("investigationIDs", []).append(current_incident_id)
                elif "investigationID" in ssdeep_indicator:
                    # Only investigationID exists - convert to investigationIDs and add new ID
                    existing = ssdeep_indicator.pop("investigationID")
                    existing_list = [existing] if not isinstance(existing, list) else existing
                    existing_list.append(current_incident_id)
                    ssdeep_indicator["investigationIDs"] = existing_list

    ssdeep_indicators.append(ssdeep_indicator)
    related_indicators = []
    for i in ssdeep_indicators:
        related_indicators += get_ssdeep_related_indicators(i)

    max_score = max([x.get("score", 0) for x in related_indicators])
    max_score_indicator = next(x for x in related_indicators if x.get("score", 0) == max_score)

    if isinstance(max_score, int) and max_score > ssdeep_indicator.get("score", 0) and max_score > 1:
        entry = {
            "Type": entryTypes["note"],
            "HumanReadable": f"Similarity to {REPUTATIONS[max_score_indicator['score']]}"
            f" {max_score_indicator['indicator_type']}:{max_score_indicator['value']}",
            "ReadableContentsFormat": formats["markdown"],
            "Contents": max_score,
            "ContentsFormat": formats["text"],
        }
        ec = {"DBotScore": {"Indicator": ssdeep_value, "Type": "ssdeep", "Vendor": "DBot", "Score": max_score}}
        entry["EntryContext"] = ec
        demisto.results(entry)
    else:
        demisto.results(ssdeep_indicator.get("score", 0))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
