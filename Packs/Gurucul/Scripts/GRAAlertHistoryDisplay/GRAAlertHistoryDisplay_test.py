import demistomock as demisto
import GRAAlertHistoryDisplay
from GRAAlertHistoryDisplay import (
    _alert_id_from_incident,
    _format_history_date,
    _slim_history_rows,
    show_alert_history,
)

_INCIDENT_LABEL = {
    "id": 1,
    "sourceInstance": "instance_name",
    "labels": [{"type": "alertId", "value": "101"}],
    "CustomFields": {},
}

_INCIDENT_CUSTOM_FIELD = {
    "id": 2,
    "sourceInstance": "instance_name",
    "labels": [],
    "CustomFields": {"graalert": "AL-202"},
}


def test_alert_id_from_label():
    assert _alert_id_from_incident(_INCIDENT_LABEL) == "101"


def test_alert_id_from_graalert_fallback():
    assert _alert_id_from_incident(_INCIDENT_CUSTOM_FIELD) == "202"


def test_format_history_date_iso():
    assert _format_history_date("2026-07-12T08:15:00") == "2026-07-12 08:15"


def test_slim_history_rows():
    rows = _slim_history_rows(
        [
            {
                "actionName": "Comment",
                "comment": "Investigating",
                "addedDate": "2026-07-12T08:15:00",
            }
        ]
    )
    assert rows == [{"Action": "Comment", "Comment": "Investigating", "Date": "2026-07-12 08:15"}]


def test_show_alert_history_with_list_response(mocker):
    mocker.patch.object(demisto, "incident", return_value=_INCIDENT_LABEL)
    mocker.patch.object(
        GRAAlertHistoryDisplay,
        "execute_command",
        return_value=[{"alertDetails": [{"actionName": "Close", "comment": "done", "addedDate": "2026-07-12T08:15:00"}]}],
    )
    return_results_mocker = mocker.patch.object(GRAAlertHistoryDisplay, "return_results")

    show_alert_history()

    GRAAlertHistoryDisplay.execute_command.assert_called_once_with(
        "gra-alert-update-history",
        {"alertId": "101", "using": "instance_name"},
    )
    result = return_results_mocker.call_args[0][0]
    assert result["Contents"][0]["Action"] == "Close"
    assert "Alert History (101)" in result["HumanReadable"]


def test_show_alert_history_empty(mocker):
    mocker.patch.object(demisto, "incident", return_value=_INCIDENT_LABEL)
    mocker.patch.object(GRAAlertHistoryDisplay, "execute_command", return_value=[])
    return_results_mocker = mocker.patch.object(GRAAlertHistoryDisplay, "return_results")

    show_alert_history()

    return_results_mocker.assert_called_once_with("No alert history returned.")
