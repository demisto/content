import json

import demistomock as demisto
from CommonServerPython import *
import vega_get_alert_events


def test_resolve_offset_uses_args_and_custom_fields():
    custom_fields = {"vegaalerteventsoffset": 50}
    assert vega_get_alert_events._resolve_offset({"offset": "100"}, custom_fields) == 100
    assert vega_get_alert_events._resolve_offset({}, custom_fields) == 50


def test_resolve_alert_id_from_mirror_id_and_raw_json():
    incident = {
        "type": "Vega Alert",
        "CustomFields": {"dbotmirrorid": "alert-99-alert"},
        "rawJSON": json.dumps({"id": "alert-raw", "vegaEntityType": "Vega Alert"}),
    }
    assert vega_get_alert_events._resolve_alert_id({}, incident, incident["CustomFields"]) == "alert-99"

    incident_without_mirror = {
        "CustomFields": {},
        "rawJSON": json.dumps({"id": "alert-raw", "vegaEntityType": "Vega Alert"}),
    }
    assert vega_get_alert_events._resolve_alert_id({}, incident_without_mirror, {}) == "alert-raw"


def test_resolve_alert_id_from_mirror_id_without_incident_type():
    incident = {"CustomFields": {"dbotmirrorid": "alert-99-alert"}}
    assert vega_get_alert_events._resolve_alert_id({}, incident, incident["CustomFields"]) == "alert-99"


def test_resolve_alert_id_from_flattened_custom_field():
    incident = {"vegaalertid": "alert-flat", "CustomFields": {}}
    custom_fields = vega_get_alert_events._collect_custom_fields(incident)
    assert vega_get_alert_events._resolve_alert_id({}, incident, custom_fields) == "alert-flat"


def test_load_current_incident_fetches_full_incident(mocker):
    mocker.patch("vega_get_alert_events.demisto.incident", return_value={"id": "123"})
    mocker.patch(
        "vega_get_alert_events.demisto.executeCommand",
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

    incident = vega_get_alert_events._load_current_incident()

    assert incident["CustomFields"]["vegaalertid"] == "alert-from-api"


def test_main_calls_integration_with_using_brand(mocker):
    mocker.patch.object(
        vega_get_alert_events,
        "_load_current_incident",
        return_value={"id": "1", "CustomFields": {"vegaalertid": "alert-1"}},
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(vega_get_alert_events, "_persist_custom_fields_on_incident")
    command_entry = {
        "Type": 1,
        "Brand": "Vega",
        "HumanReadable": "### Alert Events (1)\n| actor.user.uid | timeframe |",
        "EntryContext": {
            "Vega": {
                "AlertEvents": {
                    "AlertId": "alert-1",
                    "Total": 1,
                    "Offset": 0,
                    "CustomFields": {
                        "vegaalerteventsloadedfor": "alert-1",
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
    return_results_mock = mocker.patch.object(vega_get_alert_events, "return_results")

    vega_get_alert_events.main()

    execute_mock.assert_called_once()
    command_name, command_args = execute_mock.call_args[0]
    assert command_name == "vega-fetch-alert-events"
    assert command_args["using-brand"] == "Vega"
    return_results_mock.assert_called_once()
