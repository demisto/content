import json

import demistomock as demisto
from CommonServerPython import *
import vega_fetch_alert_events


def test_resolve_offset_uses_args_and_custom_fields():
    custom_fields = {"vegaalerteventsoffset": 50}
    assert vega_fetch_alert_events._resolve_offset({"offset": "100"}, custom_fields) == 100
    assert vega_fetch_alert_events._resolve_offset({}, custom_fields) == 50


def test_resolve_alert_id_from_raw_json():
    incident = {
        "type": "Vega Alert",
        "CustomFields": {},
        "rawJSON": json.dumps({"id": "alert-raw", "vegaEntityType": "Vega Alert"}),
    }
    assert vega_fetch_alert_events._resolve_alert_id({}, incident, {}) == "alert-raw"


def test_resolve_alert_id_from_alertid_custom_field():
    incident = {
        "type": "Vega Alert",
        "vegaalertid": "VEGA-3409",
        "alertid": "019e1b27-513c-7dd0-a9ca-db2105bdddc4",
        "CustomFields": {},
        "rawJSON": json.dumps(
            {
                "id": "019e1b27-513c-7dd0-a9ca-db2105bdddc4",
                "vegaAlertId": "VEGA-3409",
                "vegaEntityType": "Vega Alert",
            }
        ),
    }
    custom_fields = vega_fetch_alert_events._collect_custom_fields(incident)
    assert vega_fetch_alert_events._resolve_alert_id({}, incident, custom_fields) == "019e1b27-513c-7dd0-a9ca-db2105bdddc4"


def test_load_current_incident_fetches_full_incident(mocker):
    mocker.patch("vega_fetch_alert_events.demisto.incident", return_value={"id": "123"})
    mocker.patch(
        "vega_fetch_alert_events.demisto.executeCommand",
        return_value=[
            {
                "Type": 1,
                "Contents": {
                    "data": [
                        {
                            "id": "123",
                            "type": "Vega Alert",
                            "CustomFields": {"vegaalertid": "alert-from-api"},
                        }
                    ]
                },
            }
        ],
    )

    incident = vega_fetch_alert_events._load_current_incident()

    assert incident["CustomFields"]["vegaalertid"] == "alert-from-api"


def test_main_calls_integration_with_using_brand(mocker):
    mocker.patch.object(
        vega_fetch_alert_events,
        "_load_current_incident",
        return_value={
            "id": "1",
            "type": "Vega Alert",
            "CustomFields": {"alertid": "019e1b27-513c-7dd0-a9ca-db2105bdddc4", "vegaalertid": "VEGA-3409"},
            "rawJSON": json.dumps(
                {
                    "id": "019e1b27-513c-7dd0-a9ca-db2105bdddc4",
                    "vegaAlertId": "VEGA-3409",
                    "vegaEntityType": "Vega Alert",
                }
            ),
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(vega_fetch_alert_events, "_persist_custom_fields_on_incident")
    command_entry = {
        "Type": 1,
        "Brand": "Vega",
        "HumanReadable": "### Alert Events (1)\n| actor.user.uid | timeframe |",
        "EntryContext": {
            "Vega": {
                "AlertEvents": {
                    "AlertId": "019e1b27-513c-7dd0-a9ca-db2105bdddc4",
                    "Total": 1,
                    "Offset": 0,
                    "CustomFields": {
                        "vegaalerteventsloadedfor": "019e1b27-513c-7dd0-a9ca-db2105bdddc4",
                        "vegaalerteventstotal": 1,
                        "vegaalertevents": "### Alert Events (1)\n| actor.user.uid | timeframe |",
                        "vegaalerteventsoffset": 0,
                    },
                }
            }
        },
    }
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[command_entry],
    )
    return_results_mock = mocker.patch.object(vega_fetch_alert_events, "return_results")

    vega_fetch_alert_events.main()

    execute_mock.assert_called_once()
    command_name, command_args = execute_mock.call_args[0]
    assert command_name == "vega-get-alert-events"
    assert command_args["alert_id"] == "019e1b27-513c-7dd0-a9ca-db2105bdddc4"
    assert command_args["using-brand"] == "Vega"
    return_results_mock.assert_called_once()
    command_results = return_results_mock.call_args[0][0]
    assert command_results.entry_type == EntryType.WIDGET
