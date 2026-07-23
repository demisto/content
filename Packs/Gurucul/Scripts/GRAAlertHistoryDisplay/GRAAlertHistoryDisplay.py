from datetime import datetime

import demistomock as demisto
from CommonServerPython import *

try:
    import dateparser
except ImportError:  # pragma: no cover
    dateparser = None  # type: ignore[assignment]


def _alert_id_from_incident(incident: dict) -> str:
    custom_fields = incident.get("CustomFields") or {}
    gra_alert = custom_fields.get("graalert") or ""
    for label in incident.get("labels", []):
        if label.get("type") == "alertId":
            return str(label.get("value") or "")
    if gra_alert:
        return str(gra_alert).split("-")[-1]
    return ""


def _format_history_date(raw_date) -> str:
    if raw_date is None or raw_date == "":
        return ""
    raw = str(raw_date)
    parsed = None
    if dateparser is not None:
        parsed = dateparser.parse(raw)
    if parsed is None:
        for fmt in ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(raw[:19], fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return raw
    return parsed.strftime("%Y-%m-%d %H:%M")


def _slim_history_rows(history_rows) -> list[dict]:
    if not history_rows:
        return []
    if isinstance(history_rows, dict):
        history_rows = [history_rows]
    slim = []
    for row in history_rows:
        if not isinstance(row, dict):
            continue
        slim.append(
            {
                "Action": row.get("actionName") or "",
                "Comment": row.get("comment") or "",
                "Date": _format_history_date(row.get("addedDate")),
            }
        )
    return slim


def show_alert_history():
    incident = demisto.incident()
    alert_id = _alert_id_from_incident(incident)
    if not alert_id:
        return_results("Alert id not found on this incident.")
        return

    res = execute_command("gra-alert-update-history", {"alertId": alert_id, "using": incident["sourceInstance"]})
    if not res:
        return_results("No alert history returned.")
        return

    history_rows = res
    if isinstance(res, list) and res and isinstance(res[0], dict) and "alertDetails" in res[0]:
        history_rows = res[0].get("alertDetails") or []
    elif isinstance(res, dict):
        history_rows = res.get("alertDetails") or res

    slim_rows = _slim_history_rows(history_rows)
    if not slim_rows:
        return_results("No alert history entries to display.")
        return

    md = tableToMarkdown(
        f"Alert History ({alert_id})",
        slim_rows,
        headers=["Action", "Comment", "Date"],
    )
    return_results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["markdown"],
            "Contents": slim_rows,
            "HumanReadable": md,
        }
    )


def main():
    try:
        show_alert_history()
    except Exception as ex:
        return_error(f"Failed to execute GRAAlertHistoryDisplay. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
