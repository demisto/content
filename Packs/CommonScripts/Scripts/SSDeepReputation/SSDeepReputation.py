import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

REPUTATIONS = {0: "None", 1: "Good", 2: "Suspicious", 3: "Bad"}


def get_investigation_ids(indicator):
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


def get_indicator_from_value(indicator_value):
    try:
        if not indicator_value:
            return None
        res = demisto.executeCommand("findIndicators", {"value": indicator_value})
        indicator = res[0]["Contents"][0]  # type: ignore[index]
        return indicator
    except Exception:
        pass


def get_ssdeep_related_indicators(ssdeep_indicator):
    related_indicators = [ssdeep_indicator]
    for inv_id in get_investigation_ids(ssdeep_indicator):
        try:
            res = demisto.executeCommand("getContext", {"id": inv_id})
            context = res[0]["Contents"]["context"]  # type: ignore[index]
            file_obj = demisto.dt(context, f"File(val.SSDeep == '{ssdeep_indicator['value']}')")
            if file_obj is None:
                file_obj = {}
            elif type(file_obj) is list:
                file_obj = file_obj[0]
            related_indicators.append(get_indicator_from_value(file_obj.get("MD5")))  # type: ignore[union-attr]
            related_indicators.append(get_indicator_from_value(file_obj.get("SHA1")))  # type: ignore[union-attr]
            related_indicators.append(get_indicator_from_value(file_obj.get("SHA256")))  # type: ignore[union-attr]
        except Exception:
            continue
    related_indicators = [x for x in related_indicators if x is not None]
    return related_indicators


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
    ssdeep_indicators = [x["indicator"] for x in res[0]["Contents"]]  # type: ignore[index]
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
                    # investigationIDs exists - append to it
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

    max_score = max([x.get("score") for x in related_indicators])
    max_score_indicator = next(x for x in related_indicators if x.get("score", 0) == max_score)

    if max_score > ssdeep_indicator.get("score", 0) and max_score > 1:
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
