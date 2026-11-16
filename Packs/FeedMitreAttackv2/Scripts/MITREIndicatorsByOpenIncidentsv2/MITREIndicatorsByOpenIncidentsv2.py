import json
import traceback
from datetime import UTC
from typing import Any

import demistomock as demisto
from CommonServerPython import *

QUERY = 'type:"Attack Pattern" and investigationsCount:>0 and -incident.type:"MITRE ATT&CK CoA"'
TABLE_TITLE = "MITRE ATT&CK techniques by related Incidents"
TABLE_HEADERS = ["Value", "Name", "Phase Name", "Description"]
CHART_WIDGET_TYPES = {"pie", "bar", "column", "line"}
TABLE_WIDGET_TYPES = {"table", "list"}
NUMBER_WIDGET_TYPES = {"number"}
DEFAULT_CHART_SIZE = 10


def parse_date_arg(date_arg: Any, arg_name: str) -> str | None:
    """Converts a date argument (ISO, epoch, or relative such as "30 days ago") to an ISO 8601 string.

    The server only accepts absolute date formats for fromDate/toDate in searchIndicators,
    so relative values must be resolved by the script.
    """
    if not date_arg:
        return None
    parsed_date = arg_to_datetime(date_arg, arg_name=arg_name, required=False)
    if not parsed_date:
        return None
    if not parsed_date.tzinfo:
        parsed_date = parsed_date.replace(tzinfo=UTC)
    return parsed_date.isoformat()


def get_attack_patterns(from_date: str | None, to_date: str | None) -> list[dict]:
    search_indicators = IndicatorsSearcher()
    res = search_indicators.search_indicators_by_version(query=QUERY, from_date=from_date, to_date=to_date)
    return res.get("iocs") or []


def to_table_rows(iocs: list[dict]) -> list[dict]:
    return [
        {
            "Value": dict_safe_get(ind, ["value"]),
            "Name": dict_safe_get(ind, ["CustomFields", "mitreid"]),
            "Phase Name": dict_safe_get(ind, ["CustomFields", "killchainphases"]),
            "Description": dict_safe_get(ind, ["CustomFields", "description"]),
        }
        for ind in iocs
    ]


def to_chart_groups(iocs: list[dict], size: int) -> list[dict]:
    """Builds the group list expected by pie/bar/column/line widgets: [{"name": str, "data": [int]}]."""
    sorted_iocs = sorted(iocs, key=lambda ind: arg_to_number(ind.get("investigationsCount")) or 0, reverse=True)
    groups = []
    for ind in sorted_iocs[:size]:
        mitre_id = dict_safe_get(ind, ["CustomFields", "mitreid"])
        value = ind.get("value") or ""
        name = f"{mitre_id} - {value}" if mitre_id else value
        groups.append({"name": name, "data": [arg_to_number(ind.get("investigationsCount")) or 0]})
    return groups


def build_widget_result(iocs: list[dict], widget_type: str, size: int) -> Any:
    """Returns the script output in the format the requesting widget type expects."""
    if widget_type in CHART_WIDGET_TYPES:
        return json.dumps(to_chart_groups(iocs, size))
    if widget_type in TABLE_WIDGET_TYPES:
        rows = to_table_rows(iocs)
        return json.dumps({"total": len(rows), "data": rows})
    if widget_type in NUMBER_WIDGET_TYPES:
        return len(iocs)
    # Text widget, war room, or Playground: markdown table. Text widgets read the entry Contents, so it must hold the markdown.
    markdown_table = tableToMarkdown(TABLE_TITLE, to_table_rows(iocs), headers=TABLE_HEADERS)
    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["markdown"],
        "Contents": markdown_table,
        "HumanReadable": markdown_table,
    }


def main():
    try:
        args = demisto.args()
        from_date = parse_date_arg(args.get("from"), "from")
        to_date = parse_date_arg(args.get("to"), "to")
        widget_type = str(args.get("widgetType") or "").lower()
        size = arg_to_number(args.get("size")) or DEFAULT_CHART_SIZE

        iocs = get_attack_patterns(from_date, to_date)
        return_results(build_widget_result(iocs, widget_type, size))
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute MITREIndicatorsByOpenIncidents script. Error: {traceback.format_exc()}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
