import json
import pytest
import XSOARIncidentExporter
from XSOARIncidentExporter import (
    map_severity,
    parse_date_to_epoch_ms,
    build_description,
    build_raw_context,
    map_incident_to_alert,
    push_incidents_command,
    push_single_incident_command,
    sync_new_incidents_command,
    reset_sync_command,
    extract_alert_field,
    format_war_room_entry,
    map_xsiam_resolution,
    sync_close_status_command,
    sync_war_room_command,
    sync_war_room_for_incident,
)


def load_test_data(filename):
    with open(f"test_data/{filename}") as f:
        return json.load(f)


MOCK_INCIDENTS = load_test_data("search_incidents_response.json")["data"]


class TestMapSeverity:
    def test_low_severity(self):
        assert map_severity(1) == "Low"

    def test_medium_severity(self):
        assert map_severity(2) == "Medium"

    def test_high_severity(self):
        assert map_severity(3) == "High"

    def test_critical_severity(self):
        assert map_severity(4) == "Critical"

    def test_unknown_defaults_to_low(self):
        assert map_severity(99) == "Low"

    def test_elevate_low_to_medium(self):
        assert map_severity(1, elevate_low=True) == "Medium"

    def test_elevate_low_does_not_affect_medium(self):
        assert map_severity(2, elevate_low=True) == "Medium"


class TestParseDateToEpochMs:
    def test_valid_date(self):
        result = parse_date_to_epoch_ms("2026-09-01T12:00:00Z")
        assert isinstance(result, int)
        assert result > 0

    def test_none_returns_current_time(self):
        result = parse_date_to_epoch_ms(None)
        assert isinstance(result, int)
        assert result > 0

    def test_empty_string_returns_current_time(self):
        result = parse_date_to_epoch_ms("")
        assert isinstance(result, int)
        assert result > 0


class TestBuildDescription:
    def test_contains_incident_id(self):
        desc = build_description(MOCK_INCIDENTS[0])
        assert "XSOAR Incident ID: 100" in desc

    def test_contains_name(self):
        desc = build_description(MOCK_INCIDENTS[0])
        assert "Name: Test Incident 1" in desc

    def test_contains_close_reason_when_closed(self):
        desc = build_description(MOCK_INCIDENTS[1])
        assert "Close Reason: Resolved" in desc

    def test_contains_labels(self):
        desc = build_description(MOCK_INCIDENTS[0])
        assert "Brand: Manual" in desc


class TestBuildRawContext:
    def test_returns_valid_json(self):
        raw = build_raw_context(MOCK_INCIDENTS[0])
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_excludes_internal_keys(self):
        incident = {**MOCK_INCIDENTS[0], "ShardID": "123", "allRead": True}
        raw = build_raw_context(incident)
        parsed = json.loads(raw)
        assert "ShardID" not in parsed
        assert "allRead" not in parsed


class TestMapIncidentToAlert:
    def test_required_fields_present(self):
        alert = map_incident_to_alert(MOCK_INCIDENTS[0])
        assert alert["product"] == "XSOAR"
        assert alert["vendor"] == "Palo Alto Networks"
        assert "event_timestamp" in alert
        assert "severity" in alert
        assert "alert_name" in alert

    def test_timestamp_offset_applied(self):
        alert_no_offset = map_incident_to_alert(MOCK_INCIDENTS[0], timestamp_offset=0)
        alert_with_offset = map_incident_to_alert(MOCK_INCIDENTS[0], timestamp_offset=60)
        assert alert_with_offset["event_timestamp"] == alert_no_offset["event_timestamp"] + 60 * 60 * 1000

    def test_elevate_low(self):
        low_incident = {**MOCK_INCIDENTS[0], "severity": 1}
        alert = map_incident_to_alert(low_incident, elevate_low=True)
        assert alert["severity"] == "Medium"

    def test_xsoar_fields_mapped(self):
        alert = map_incident_to_alert(MOCK_INCIDENTS[0])
        assert alert["xsoar_incident_id"] == "100"
        assert alert["xsoar_incident_type"] == "Unclassified"


class TestPushIncidentsCommand:
    def test_no_incidents_found(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = []
        mock_xsiam = mocker.MagicMock()

        result = push_incidents_command(mock_xsiam, mock_xsoar, {}, None, 100)
        assert "No incidents found" in result.readable_output

    def test_pushes_incidents(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = MOCK_INCIDENTS
        mock_xsiam = mocker.MagicMock()

        result = push_incidents_command(mock_xsiam, mock_xsoar, {}, None, 100)
        assert mock_xsiam.insert_parsed_alerts.called
        assert "2 incident(s)" in result.readable_output


class TestPushSingleIncidentCommand:
    def test_missing_incident_id(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsiam = mocker.MagicMock()

        with pytest.raises(Exception, match="incident_id"):
            push_single_incident_command(mock_xsiam, mock_xsoar, {})

    def test_incident_not_found(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = []
        mock_xsiam = mocker.MagicMock()

        with pytest.raises(Exception, match="not found"):
            push_single_incident_command(mock_xsiam, mock_xsoar, {"incident_id": "999"})

    def test_pushes_single_incident(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = [MOCK_INCIDENTS[0]]
        mock_xsiam = mocker.MagicMock()

        result = push_single_incident_command(mock_xsiam, mock_xsoar, {"incident_id": "100"})
        assert mock_xsiam.insert_parsed_alerts.called
        assert "100" in result.readable_output


class TestSyncNewIncidentsCommand:
    def test_no_new_incidents(self, mocker):
        mocker.patch("XSOARIncidentExporter.demisto")
        from XSOARIncidentExporter import demisto as mock_demisto

        mock_demisto.getIntegrationContext.return_value = {"last_synced_id": 999}

        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = []
        mock_xsiam = mocker.MagicMock()

        result = sync_new_incidents_command(mock_xsiam, mock_xsoar, {}, None, 100)
        assert "No new incidents" in result.readable_output


class TestResetSyncCommand:
    def test_reset(self, mocker):
        mocker.patch("XSOARIncidentExporter.demisto")
        result = reset_sync_command()
        assert "reset" in result.readable_output.lower()


class TestTestModule:
    def test_ok(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsiam = mocker.MagicMock()
        assert XSOARIncidentExporter.test_module(mock_xsiam, mock_xsoar) == "ok"


class TestExtractAlertField:
    def test_extracts_simple_field(self):
        desc = "XSOAR Incident ID: 123\nName: Test"
        assert extract_alert_field(desc, "XSOAR Incident ID") == "123"

    def test_returns_empty_when_missing(self):
        assert extract_alert_field("Name: Test", "Status") == ""

    def test_extracts_field_at_end(self):
        assert extract_alert_field("Status: Done", "Status") == "Done"

    def test_extracts_multiword_value(self):
        desc = "Close Reason: False Positive\nNext: field"
        assert extract_alert_field(desc, "Close Reason") == "False Positive"


class TestMapXsiamResolution:
    def test_resolved(self):
        assert map_xsiam_resolution("Resolved") == "resolved_true_positive"

    def test_false_positive(self):
        assert map_xsiam_resolution("False Positive") == "resolved_false_positive"

    def test_duplicate(self):
        assert map_xsiam_resolution("Duplicate") == "resolved_duplicate_alert"

    def test_other(self):
        assert map_xsiam_resolution("Other") == "resolved_other"

    def test_case_insensitive(self):
        assert map_xsiam_resolution("RESOLVED") == "resolved_true_positive"

    def test_empty_maps_to_other(self):
        assert map_xsiam_resolution("") == "resolved_other"

    def test_unknown_maps_to_other(self):
        assert map_xsiam_resolution("Custom") == "resolved_other"


CLOSED_ALERT_DESC = "XSOAR Incident ID: 42\nStatus: Done\nClose Reason: Resolved\nClose Notes: Fixed the issue"

OPEN_ALERT_DESC = "XSOAR Incident ID: 43\nStatus: Active\nClose Reason: \nClose Notes: "


def _make_alert(alert_id, description, name="Test Alert"):
    return {
        "alert_id": alert_id,
        "name": name,
        "description": description,
        "events": [],
    }


class TestSyncCloseStatusCommand:
    def test_no_alerts_found(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.get_alerts.return_value = {"reply": {"alerts": [], "total_count": 0}}

        result = sync_close_status_command(mock_xsiam, {})
        assert "No open" in result.readable_output

    def test_closes_resolved_alerts(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.get_alerts.return_value = {
            "reply": {"alerts": [_make_alert(1001, CLOSED_ALERT_DESC)], "total_count": 1},
        }
        mock_xsiam.update_alerts.return_value = {"reply": True}

        result = sync_close_status_command(mock_xsiam, {})
        mock_xsiam.update_alerts.assert_called_once()
        call_args = mock_xsiam.update_alerts.call_args
        assert call_args[0][0] == [1001]
        assert call_args[0][1] == "resolved_true_positive"
        assert result.outputs["ClosedCount"] == 1

    def test_skips_open_alerts(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.get_alerts.return_value = {
            "reply": {"alerts": [_make_alert(1002, OPEN_ALERT_DESC)], "total_count": 1},
        }

        result = sync_close_status_command(mock_xsiam, {})
        mock_xsiam.update_alerts.assert_not_called()
        assert result.outputs["ClosedCount"] == 0
        assert result.outputs["SkippedCount"] == 1

    def test_mixed_alerts(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.get_alerts.return_value = {
            "reply": {
                "alerts": [
                    _make_alert(1001, CLOSED_ALERT_DESC),
                    _make_alert(1002, OPEN_ALERT_DESC),
                ],
                "total_count": 2,
            },
        }
        mock_xsiam.update_alerts.return_value = {"reply": True}

        result = sync_close_status_command(mock_xsiam, {})
        assert result.outputs["ClosedCount"] == 1
        assert result.outputs["SkippedCount"] == 1

    def test_description_from_events_fallback(self, mocker):
        mock_xsiam = mocker.MagicMock()
        alert = {
            "alert_id": 2001,
            "name": "Event Alert",
            "description": "",
            "events": [{"alert_description": CLOSED_ALERT_DESC}],
        }
        mock_xsiam.get_alerts.return_value = {
            "reply": {"alerts": [alert], "total_count": 1},
        }
        mock_xsiam.update_alerts.return_value = {"reply": True}

        result = sync_close_status_command(mock_xsiam, {})
        assert result.outputs["ClosedCount"] == 1

    def test_update_failure_recorded(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.get_alerts.return_value = {
            "reply": {"alerts": [_make_alert(1001, CLOSED_ALERT_DESC)], "total_count": 1},
        }
        mock_xsiam.update_alerts.side_effect = Exception("API error")

        result = sync_close_status_command(mock_xsiam, {})
        assert result.outputs["ClosedCount"] == 1
        assert "Failed" in result.outputs["ClosedAlerts"][0]["result"]


class TestFormatWarRoomEntry:
    def test_basic_formatting(self):
        entry = {
            "id": "42",
            "type": 1,
            "user": "admin",
            "category": "notes",
            "created": "2026-10-01T10:30:00Z",
            "contents": "test",
        }
        result = format_war_room_entry(entry)
        assert "**[XSOAR War Room]**" in result
        assert "42" in result
        assert "admin" in result
        assert "test" in result

    def test_missing_user_defaults_to_system(self):
        entry = {"id": "1", "type": 1, "user": "", "category": "", "created": "", "contents": "msg"}
        result = format_war_room_entry(entry)
        assert "system" in result

    def test_unknown_entry_type(self):
        entry = {"id": "1", "type": 99, "user": "admin", "category": "", "created": "", "contents": "msg"}
        result = format_war_room_entry(entry)
        assert "Unknown" in result


class TestSyncWarRoomForIncident:
    def test_alert_not_found(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.find_alert_by_xsoar_id.return_value = None
        mock_xsoar = mocker.MagicMock()

        result = sync_war_room_for_incident(mock_xsiam, mock_xsoar, "123")
        assert result["status"] == "alert_not_found"

    def test_missing_external_id(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.find_alert_by_xsoar_id.return_value = {"external_id": ""}
        mock_xsoar = mocker.MagicMock()

        result = sync_war_room_for_incident(mock_xsiam, mock_xsoar, "123")
        assert result["status"] == "missing_external_id"

    def test_syncs_entries(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.find_alert_by_xsoar_id.return_value = {"external_id": "alert-1"}
        mock_xsiam.get_war_room_entries.return_value = []
        mock_xsiam.insert_war_room_entry.return_value = {}

        mock_xsoar = mocker.MagicMock()
        mock_xsoar.get_war_room_entries.return_value = [
            {"id": "1", "type": 1, "user": "admin", "category": "notes", "created": "", "contents": "entry 1"},
            {"id": "2", "type": 1, "user": "admin", "category": "notes", "created": "", "contents": "entry 2"},
        ]

        result = sync_war_room_for_incident(mock_xsiam, mock_xsoar, "100")
        assert result["synced"] == 2
        assert result["skipped"] == 0

    def test_skips_already_synced(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.find_alert_by_xsoar_id.return_value = {"external_id": "alert-1"}
        mock_xsiam.get_war_room_entries.return_value = [
            {"contents": "**[XSOAR War Room]** 1 | Standard | notes | by admin | \n\nentry 1"},
        ]
        mock_xsiam.insert_war_room_entry.return_value = {}

        mock_xsoar = mocker.MagicMock()
        mock_xsoar.get_war_room_entries.return_value = [
            {"id": "1", "type": 1, "user": "admin", "category": "notes", "created": "", "contents": "entry 1"},
            {"id": "2", "type": 1, "user": "admin", "category": "notes", "created": "", "contents": "entry 2"},
        ]

        result = sync_war_room_for_incident(mock_xsiam, mock_xsoar, "100")
        assert result["synced"] == 1
        assert result["skipped"] == 1

    def test_empty_entries_skipped(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.find_alert_by_xsoar_id.return_value = {"external_id": "alert-1"}
        mock_xsiam.get_war_room_entries.return_value = []

        mock_xsoar = mocker.MagicMock()
        mock_xsoar.get_war_room_entries.return_value = [
            {"id": "1", "type": 1, "user": "admin", "category": "", "created": "", "contents": ""},
            {"id": "2", "type": 1, "user": "admin", "category": "", "created": "", "contents": "   "},
        ]

        result = sync_war_room_for_incident(mock_xsiam, mock_xsoar, "100")
        assert result["synced"] == 0


class TestSyncWarRoomCommand:
    def test_missing_incident_id(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsoar = mocker.MagicMock()

        with pytest.raises(Exception, match="incident_id"):
            sync_war_room_command(mock_xsiam, mock_xsoar, {})

    def test_alert_not_found_raises(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.find_alert_by_xsoar_id.return_value = None
        mock_xsoar = mocker.MagicMock()

        with pytest.raises(Exception, match="No XSIAM alert found"):
            sync_war_room_command(mock_xsiam, mock_xsoar, {"incident_id": "123"})

    def test_no_entries(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.find_alert_by_xsoar_id.return_value = {"external_id": "alert-1"}
        mock_xsoar = mocker.MagicMock()
        mock_xsoar.get_war_room_entries.return_value = []

        result = sync_war_room_command(mock_xsiam, mock_xsoar, {"incident_id": "123"})
        assert result.outputs["SyncedCount"] == 0

    def test_syncs_and_returns_summary(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.find_alert_by_xsoar_id.return_value = {"external_id": "alert-1"}
        mock_xsiam.get_war_room_entries.return_value = []
        mock_xsiam.insert_war_room_entry.return_value = {}

        mock_xsoar = mocker.MagicMock()
        mock_xsoar.get_war_room_entries.return_value = [
            {"id": "10", "type": 1, "user": "admin", "category": "notes", "created": "", "contents": "hello"},
        ]

        result = sync_war_room_command(mock_xsiam, mock_xsoar, {"incident_id": "100"})
        assert result.outputs["SyncedCount"] == 1
        assert result.outputs["IncidentID"] == "100"
        assert result.outputs["XSIAMAlertID"] == "alert-1"

    def test_category_filter(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.find_alert_by_xsoar_id.return_value = {"external_id": "alert-1"}
        mock_xsiam.get_war_room_entries.return_value = []
        mock_xsiam.insert_war_room_entry.return_value = {}

        mock_xsoar = mocker.MagicMock()
        mock_xsoar.get_war_room_entries.return_value = [
            {"id": "1", "type": 1, "user": "admin", "category": "notes", "created": "", "contents": "note entry"},
            {"id": "2", "type": 1, "user": "admin", "category": "chat", "created": "", "contents": "chat entry"},
        ]

        result = sync_war_room_command(mock_xsiam, mock_xsoar, {"incident_id": "100", "categories": "notes"})
        assert result.outputs["SyncedCount"] == 1
        assert result.outputs["FilteredEntries"] == 1

    def test_provided_xsiam_alert_id(self, mocker):
        mock_xsiam = mocker.MagicMock()
        mock_xsiam.get_war_room_entries.return_value = []
        mock_xsiam.insert_war_room_entry.return_value = {}

        mock_xsoar = mocker.MagicMock()
        mock_xsoar.get_war_room_entries.return_value = [
            {"id": "1", "type": 1, "user": "admin", "category": "", "created": "", "contents": "test"},
        ]

        result = sync_war_room_command(mock_xsiam, mock_xsoar, {"incident_id": "100", "xsiam_alert_id": "custom-alert-id"})
        assert result.outputs["XSIAMAlertID"] == "custom-alert-id"
        mock_xsiam.find_alert_by_xsoar_id.assert_not_called()
