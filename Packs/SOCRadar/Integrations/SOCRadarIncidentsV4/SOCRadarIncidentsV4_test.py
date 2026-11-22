import json
import pytest
from datetime import datetime, timedelta, UTC

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alarm(
    alarm_id=123,
    risk="HIGH",
    asset="TESTSOCRadar",
    status="OPEN",
    main_type="Test Type",
    sub_type="Test Sub",
    alarm_text="Test alarm",
    date="2024-01-15T10:30:00",
    tags=None,
    related_entities=None,
    company_id="456",
):
    return {
        "alarm_id": alarm_id,
        "company_id": company_id,
        "alarm_risk_level": risk,
        "alarm_asset": asset,
        "status": status,
        "date": date,
        "alarm_type_details": {
            "alarm_main_type": main_type,
            "alarm_sub_type": sub_type,
        },
        "alarm_text": alarm_text,
        "tags": tags or [],
        "alarm_related_entities": related_entities or [],
    }


def _mock_response(alarms, total_pages=1, total_records=None):
    return {
        "is_success": True,
        "data": alarms,
        "total_records": total_records if total_records is not None else len(alarms),
        "total_pages": total_pages,
        "current_page": 1,
    }


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_client():
    from SOCRadarIncidentsV4 import Client

    client = Client(
        base_url="https://platform.socradar.com/api",
        api_key="test-api-key",
        company_id="123",
        verify=False,
        proxy=False,
    )
    return client


# ---------------------------------------------------------------------------
# convert_to_demisto_severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,expected_attr",
    [
        ("low", "LOW"),
        ("medium", "MEDIUM"),
        ("high", "HIGH"),
        ("critical", "CRITICAL"),
        ("info", "INFO"),
        ("unknown", "UNKNOWN"),
    ],
)
def test_convert_to_demisto_severity(severity, expected_attr):
    from SOCRadarIncidentsV4 import convert_to_demisto_severity
    from CommonServerPython import IncidentSeverity

    result = convert_to_demisto_severity(severity)
    assert result == getattr(IncidentSeverity, expected_attr)


# ---------------------------------------------------------------------------
# parse_alarm_date
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "date_str,description",
    [
        ("2024-01-15T10:30:00.123456", "with_microseconds"),
        ("2024-01-15T10:30:00", "without_microseconds"),
        ("2024-01-15", "date_only"),
    ],
)
def test_parse_alarm_date_valid(date_str, description):
    from SOCRadarIncidentsV4 import parse_alarm_date

    result = parse_alarm_date(date_str)
    assert result is not None
    assert isinstance(result, datetime)


@pytest.mark.parametrize(
    "date_str,description",
    [
        (None, "none_date"),
        ("not-a-date", "invalid_format"),
    ],
)
def test_parse_alarm_date_invalid(date_str, description):
    from SOCRadarIncidentsV4 import parse_alarm_date

    result = parse_alarm_date(date_str)
    assert result is None


# ---------------------------------------------------------------------------
# alarm_to_incident
# ---------------------------------------------------------------------------


def test_alarm_to_incident_basic():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    incident = alarm_to_incident(alarm)

    assert "SOCRadar Alarm 123" in incident["name"]
    assert "Test Type" in incident["name"]
    assert "Test Sub" in incident["name"]
    assert "TESTSOCRadar" in incident["name"]  # asset field value
    assert incident["CustomFields"]["socradaralarmid"] == "123"
    assert incident["CustomFields"]["socradarasset"] == "TESTSOCRadar"
    assert incident["CustomFields"]["socradarstatus"] == "OPEN"
    assert incident["CustomFields"]["socradaralarmtype"] == "Test Type"


def test_alarm_to_incident_with_tags_and_entities():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm(
        tags=["tag1", "tag2"],
        related_entities=[{"key": "IP", "value": "1.2.3.4"}],
    )
    incident = alarm_to_incident(alarm)

    assert "tag1,tag2" in incident["CustomFields"]["socradartags"]
    assert "IP: 1.2.3.4" in incident["details"]


def test_alarm_to_incident_missing_fields():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = {"alarm_id": 999}
    incident = alarm_to_incident(alarm)

    assert incident["name"] == "SOCRadar Alarm 999: Unknown [N/A]"
    assert incident["CustomFields"]["socradaralarmid"] == "999"


def test_alarm_to_incident_raw_json():
    import json
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    incident = alarm_to_incident(alarm)

    raw = json.loads(incident["rawJSON"])
    assert raw["alarm_id"] == 123


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class TestClient:
    def test_client_initialization(self, mock_client):
        assert mock_client.api_key == "test-api-key"
        assert mock_client.company_id == "123"

    def test_get_headers(self, mock_client):
        headers = mock_client._get_headers()
        assert headers == {"API-Key": "test-api-key"}

    def test_search_incidents_params(self, mock_client, mocker):
        mock_http = mocker.patch.object(
            mock_client,
            "_http_request",
            return_value={
                "is_success": True,
                "data": {"alarms": [], "total_pages": 1, "total_records": 0},
            },
        )

        mock_client.search_incidents(limit=10, page=2, start_date="2024-01-01")

        call_kwargs = mock_http.call_args
        params = call_kwargs[1]["params"]
        assert params["limit"] == 10
        assert params["page"] == 2
        assert params["start_date"] == "2024-01-01"

    def test_change_alarm_status_invalid_status(self, mock_client):
        with pytest.raises(ValueError, match="Invalid status reason"):
            mock_client.change_alarm_status([1], "INVALID_STATUS")

    def test_change_alarm_status_success(self, mock_client, mocker):
        mocker.patch.object(
            mock_client,
            "_http_request",
            return_value={"is_success": True},
        )
        result = mock_client.change_alarm_status([1, 2], "RESOLVED")
        assert result["is_success"] is True

    def test_add_alarm_comment(self, mock_client, mocker):
        mocker.patch.object(
            mock_client,
            "_http_request",
            return_value={"is_success": True},
        )
        result = mock_client.add_alarm_comment(1, "user@test.com", "test comment")
        assert result["is_success"] is True

    def test_add_alarm_assignee(self, mock_client, mocker):
        mocker.patch.object(
            mock_client,
            "_http_request",
            return_value={"is_success": True},
        )
        result = mock_client.add_alarm_assignee(1, user_emails=["user@test.com"])
        assert result["is_success"] is True

    def test_add_remove_tag(self, mock_client, mocker):
        mocker.patch.object(
            mock_client,
            "_http_request",
            return_value={"is_success": True},
        )
        result = mock_client.add_remove_tag(1, "critical-tag")
        assert result["is_success"] is True


# ---------------------------------------------------------------------------
# test_module
# ---------------------------------------------------------------------------


def test_test_module_success(mock_client, mocker):
    from SOCRadarIncidentsV4 import test_module

    mocker.patch.object(mock_client, "search_incidents", return_value={"is_success": True, "data": []})
    result = test_module(mock_client)
    assert result == "ok"


def test_test_module_failure(mock_client, mocker, capfd):
    from SOCRadarIncidentsV4 import test_module

    mocker.patch.object(
        mock_client,
        "search_incidents",
        return_value={"is_success": False, "message": "Authentication failed"},
    )
    with capfd.disabled():
        result = test_module(mock_client)
    assert "Test failed" in result


def test_test_module_unauthorized(mock_client, mocker, capfd):
    from SOCRadarIncidentsV4 import test_module
    from CommonServerPython import DemistoException

    mocker.patch.object(
        mock_client,
        "search_incidents",
        side_effect=DemistoException("401 Unauthorized"),
    )
    with capfd.disabled():
        result = test_module(mock_client)
    assert "Authorization Error" in result


def test_test_module_forbidden(mock_client, mocker, capfd):
    from SOCRadarIncidentsV4 import test_module
    from CommonServerPython import DemistoException

    mocker.patch.object(mock_client, "search_incidents", side_effect=DemistoException("403 Forbidden"))
    with capfd.disabled():
        result = test_module(mock_client)
    assert "Access Denied" in result


def test_test_module_not_found(mock_client, mocker, capfd):
    from SOCRadarIncidentsV4 import test_module
    from CommonServerPython import DemistoException

    mocker.patch.object(mock_client, "search_incidents", side_effect=DemistoException("404 Not Found"))
    with capfd.disabled():
        result = test_module(mock_client)
    assert "Not Found" in result


# ---------------------------------------------------------------------------
# status_reason_map completeness
# ---------------------------------------------------------------------------


def test_status_reason_map_completeness():
    from SOCRadarIncidentsV4 import STATUS_REASON_MAP

    expected_statuses = [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED",
        "PENDING_INFO",
        "LEGAL_REVIEW",
        "VENDOR_ASSESSMENT",
        "FALSE_POSITIVE",
        "DUPLICATE",
        "PROCESSED_INTERNALLY",
        "MITIGATED",
        "NOT_APPLICABLE",
    ]
    for status in expected_statuses:
        assert status in STATUS_REASON_MAP


# ---------------------------------------------------------------------------
# fetch_incidents
# ---------------------------------------------------------------------------


def test_fetch_incidents_first_fetch(mock_client, mocker):
    """Test fetch incidents on first run"""
    from SOCRadarIncidentsV4 import fetch_incidents

    mocker.patch.object(mock_client, "search_incidents", return_value=_mock_response([_make_alarm()]))

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={},
        first_fetch_time="3 days",
        fetch_interval_minutes=1,
    )

    assert len(incidents) == 1
    assert "last_fetch" in next_run
    assert "last_alarm_ids" in next_run
    assert 123 in next_run["last_alarm_ids"]


def test_fetch_incidents_subsequent_fetch(mock_client, mocker):
    """Test fetch incidents on subsequent runs uses interval"""
    from SOCRadarIncidentsV4 import fetch_incidents

    last_fetch_time = (datetime.now() - timedelta(minutes=5)).isoformat() + "Z"
    mocker.patch.object(
        mock_client,
        "search_incidents",
        return_value=_mock_response([_make_alarm(alarm_id=200)]),
    )

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={"last_fetch": last_fetch_time, "last_alarm_ids": []},
        first_fetch_time="3 days",
        fetch_interval_minutes=1,
    )

    assert len(incidents) == 1
    assert 200 in next_run["last_alarm_ids"]


def test_fetch_incidents_with_duplicates(mock_client, mocker):
    """Test that duplicate alarm IDs are skipped"""
    from SOCRadarIncidentsV4 import fetch_incidents

    last_fetch_time = (datetime.now() - timedelta(minutes=5)).isoformat() + "Z"
    mocker.patch.object(
        mock_client,
        "search_incidents",
        return_value=_mock_response([_make_alarm(alarm_id=123)]),
    )

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={"last_fetch": last_fetch_time, "last_alarm_ids": [123]},
        first_fetch_time="3 days",
        fetch_interval_minutes=1,
    )

    assert len(incidents) == 0


def test_fetch_incidents_no_alarms(mock_client, mocker):
    """Test fetch when no alarms returned"""
    from SOCRadarIncidentsV4 import fetch_incidents

    mocker.patch.object(mock_client, "search_incidents", return_value=_mock_response([]))

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={},
        first_fetch_time="3 days",
        fetch_interval_minutes=1,
    )

    assert len(incidents) == 0
    assert "last_fetch" in next_run
    assert "last_alarm_ids" in next_run


def test_fetch_incidents_error_handling(mock_client, mocker, capfd):
    """Test fetch gracefully handles API errors"""
    from SOCRadarIncidentsV4 import fetch_incidents

    mocker.patch.object(mock_client, "search_incidents", side_effect=Exception("API Error"))

    with capfd.disabled():
        next_run, incidents = fetch_incidents(
            client=mock_client,
            max_results=100,
            last_run={},
            first_fetch_time="3 days",
            fetch_interval_minutes=1,
        )

    assert incidents == []
    assert "last_fetch" in next_run


def test_fetch_incidents_with_filters(mock_client, mocker):
    """Test fetch passes filters correctly to search_incidents"""
    from SOCRadarIncidentsV4 import fetch_incidents

    mock_search = mocker.patch.object(mock_client, "search_incidents", return_value=_mock_response([_make_alarm()]))

    fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={},
        first_fetch_time="3 days",
        fetch_interval_minutes=1,
        status=["OPEN"],
        severities=["HIGH"],
        alarm_main_types=["Phishing"],
    )

    call_kwargs = mock_search.call_args[1]
    assert call_kwargs["status"] == ["OPEN"]
    assert call_kwargs["severities"] == ["HIGH"]
    assert call_kwargs["alarm_main_types"] == ["Phishing"]


# ---------------------------------------------------------------------------
# Hourly check for alarms missed by the regular fetch window
# ---------------------------------------------------------------------------


def _hourly_check_side_effect(regular_alarms, approved_alarms):
    """Return regular-window alarms for normal calls and approved alarms for hourly-check calls."""

    def side_effect(**kwargs):
        if kwargs.get("approved_at_start"):
            return _mock_response(approved_alarms)
        return _mock_response(regular_alarms)

    return side_effect


def test_hourly_check_initialises_checkpoint_without_extra_call(mock_client, mocker):
    """
    Given: A last_run without an hourly check checkpoint (first run or upgrade).
    When: fetch_incidents runs.
    Then: The checkpoint is set to now and no hourly check request is made.
    """
    from SOCRadarIncidentsV4 import fetch_incidents

    mock_search = mocker.patch.object(mock_client, "search_incidents", return_value=_mock_response([]))
    last_fetch_time = (datetime.now() - timedelta(minutes=5)).isoformat()

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={"last_fetch": last_fetch_time, "last_alarm_ids": []},
        first_fetch_time="3 days",
    )

    assert incidents == []
    assert next_run["last_approved_check"]
    assert all(not call.kwargs.get("approved_at_start") for call in mock_search.call_args_list)


def test_hourly_check_not_due_yet(mock_client, mocker):
    """
    Given: The previous hourly check ran 10 minutes ago.
    When: fetch_incidents runs.
    Then: No hourly check request is made and the checkpoint is kept.
    """
    from SOCRadarIncidentsV4 import fetch_incidents, format_utc

    mock_search = mocker.patch.object(mock_client, "search_incidents", return_value=_mock_response([]))
    last_check = format_utc(datetime.now(UTC) - timedelta(minutes=10))

    next_run, _ = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={
            "last_fetch": (datetime.now() - timedelta(minutes=1)).isoformat(),
            "last_alarm_ids": [],
            "last_approved_check": last_check,
        },
        first_fetch_time="3 days",
    )

    assert next_run["last_approved_check"] == last_check
    assert all(not call.kwargs.get("approved_at_start") for call in mock_search.call_args_list)


def test_hourly_check_picks_up_missed_alarm_without_duplicates(mock_client, mocker):
    """
    Given: The previous hourly check ran more than an hour ago, alarm 100 was already fetched,
           and alarm 200 was not returned by the regular fetch window.
    When: fetch_incidents runs.
    Then: Only alarm 200 is created, the window overlaps the previous check, and the checkpoint advances.
    """
    from SOCRadarIncidentsV4 import APPROVED_CHECK_OVERLAP_MINUTES, fetch_incidents, format_utc, parse_checkpoint

    last_check_time = (datetime.now(UTC) - timedelta(minutes=61)).replace(microsecond=0)
    mock_search = mocker.patch.object(
        mock_client,
        "search_incidents",
        side_effect=_hourly_check_side_effect([], [_make_alarm(alarm_id=100), _make_alarm(alarm_id=200)]),
    )

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={
            "last_fetch": (datetime.now() - timedelta(minutes=1)).isoformat(),
            "last_alarm_ids": [100],
            "last_approved_check": format_utc(last_check_time),
        },
        first_fetch_time="3 days",
        status=["OPEN"],
    )

    assert [json.loads(incident["rawJSON"])["alarm_id"] for incident in incidents] == [200]
    assert 200 in next_run["last_alarm_ids"]
    assert parse_checkpoint(next_run["last_approved_check"]) > last_check_time

    hourly_call = next(call for call in mock_search.call_args_list if call.kwargs.get("approved_at_start"))
    expected_start = last_check_time - timedelta(minutes=APPROVED_CHECK_OVERLAP_MINUTES)
    assert hourly_call.kwargs["approved_at_start"] == format_utc(expected_start)
    assert hourly_call.kwargs["approved_at_end"]
    assert hourly_call.kwargs["status"] == ["OPEN"]


def test_hourly_check_failure_keeps_checkpoint_and_ids(mock_client, mocker, capfd):
    """
    Given: The hourly check is due but its API request fails.
    When: fetch_incidents runs.
    Then: The regular fetch result is kept, the checkpoint is unchanged so it is retried, and no alarm is marked as fetched.
    """
    from SOCRadarIncidentsV4 import fetch_incidents, format_utc

    def side_effect(**kwargs):
        if kwargs.get("approved_at_start"):
            raise Exception("API Error")
        return _mock_response([_make_alarm(alarm_id=300)])

    mocker.patch.object(mock_client, "search_incidents", side_effect=side_effect)
    last_check = format_utc(datetime.now(UTC) - timedelta(hours=2))

    with capfd.disabled():
        next_run, incidents = fetch_incidents(
            client=mock_client,
            max_results=100,
            last_run={
                "last_fetch": (datetime.now() - timedelta(minutes=1)).isoformat(),
                "last_alarm_ids": [],
                "last_approved_check": last_check,
            },
            first_fetch_time="3 days",
        )

    assert len(incidents) == 1
    assert next_run["last_alarm_ids"] == [300]
    assert next_run["last_approved_check"] == last_check


def test_hourly_check_budget_exhausted_keeps_checkpoint(mock_client, mocker):
    """
    Given: The hourly check is due and returns more new alarms than the remaining max_results budget.
    When: fetch_incidents runs.
    Then: Only the budget is created and the checkpoint is kept so the rest is picked up next run.
    """
    from SOCRadarIncidentsV4 import fetch_incidents, format_utc

    mocker.patch.object(
        mock_client,
        "search_incidents",
        side_effect=_hourly_check_side_effect([], [_make_alarm(alarm_id=alarm_id) for alarm_id in (1, 2, 3)]),
    )
    last_check = format_utc(datetime.now(UTC) - timedelta(hours=2))

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=2,
        last_run={
            "last_fetch": (datetime.now() - timedelta(minutes=1)).isoformat(),
            "last_alarm_ids": [],
            "last_approved_check": last_check,
        },
        first_fetch_time="3 days",
    )

    assert len(incidents) == 2
    assert next_run["last_approved_check"] == last_check
    assert sorted(next_run["last_alarm_ids"]) == [1, 2]


def test_sort_alarm_ids_for_storage_keeps_most_recent(mocker):
    """
    Given: More stored alarm IDs than the storage cap.
    When: sort_alarm_ids_for_storage is called.
    Then: The highest (most recent) alarm IDs are kept.
    """
    from SOCRadarIncidentsV4 import sort_alarm_ids_for_storage

    mocker.patch("SOCRadarIncidentsV4.MAX_STORED_ALARM_IDS", 3)

    assert sort_alarm_ids_for_storage({5, 1, 9, 7, 3}) == [9, 7, 5]


def test_search_incidents_sends_approved_at_params(mock_client, mocker):
    """
    Given: approved_at_start and approved_at_end values.
    When: search_incidents is called.
    Then: Both values are sent as request params.
    """
    mock_http = mocker.patch.object(mock_client, "_http_request", return_value={"is_success": True, "data": []})

    mock_client.search_incidents(approved_at_start="2026-11-16T20:00:00", approved_at_end="2026-11-16T21:00:00")

    params = mock_http.call_args.kwargs["params"]
    assert params["approved_at_start"] == "2026-11-16T20:00:00"
    assert params["approved_at_end"] == "2026-11-16T21:00:00"


# ---------------------------------------------------------------------------
# change_status_command
# ---------------------------------------------------------------------------


def test_change_status_command_success(mock_client, mocker):
    from SOCRadarIncidentsV4 import change_status_command

    mocker.patch.object(mock_client, "change_alarm_status", return_value={"is_success": True})

    result = change_status_command(mock_client, {"alarm_ids": "1,2", "status_reason": "RESOLVED"})
    assert "Status changed" in result.readable_output


def test_change_status_command_missing_params(mock_client):
    from SOCRadarIncidentsV4 import change_status_command

    with pytest.raises(ValueError, match="required"):
        change_status_command(mock_client, {"alarm_ids": "", "status_reason": ""})


# ---------------------------------------------------------------------------
# mark commands
# ---------------------------------------------------------------------------


def test_mark_false_positive_success(mock_client, mocker):
    from SOCRadarIncidentsV4 import mark_as_false_positive_command

    mocker.patch.object(mock_client, "change_alarm_status", return_value={"is_success": True})
    result = mark_as_false_positive_command(mock_client, {"alarm_id": "1"})
    assert "false positive" in result.readable_output


def test_mark_false_positive_missing_alarm_id(mock_client):
    from SOCRadarIncidentsV4 import mark_as_false_positive_command

    with pytest.raises(ValueError, match="alarm_id is required"):
        mark_as_false_positive_command(mock_client, {})


def test_mark_resolved_success(mock_client, mocker):
    from SOCRadarIncidentsV4 import mark_as_resolved_command

    mocker.patch.object(mock_client, "change_alarm_status", return_value={"is_success": True})
    result = mark_as_resolved_command(mock_client, {"alarm_id": "1"})
    assert "resolved" in result.readable_output


# ---------------------------------------------------------------------------
# add_comment / add_assignee / add_tag commands
# ---------------------------------------------------------------------------


def test_add_comment_success(mock_client, mocker):
    from SOCRadarIncidentsV4 import add_comment_command

    mocker.patch.object(mock_client, "add_alarm_comment", return_value={"is_success": True})
    result = add_comment_command(
        mock_client,
        {"alarm_id": "1", "user_email": "user@example.com", "comment": "test"},
    )
    assert "Comment added" in result.readable_output


def test_add_comment_missing_params(mock_client):
    from SOCRadarIncidentsV4 import add_comment_command

    with pytest.raises(ValueError):
        add_comment_command(mock_client, {"alarm_id": "1", "user_email": "", "comment": ""})


def test_add_assignee_success(mock_client, mocker):
    from SOCRadarIncidentsV4 import add_assignee_command

    mocker.patch.object(mock_client, "add_alarm_assignee", return_value={"is_success": True})
    result = add_assignee_command(mock_client, {"alarm_id": "1", "user_emails": "user@example.com"})
    assert "Assignee added" in result.readable_output


def test_add_assignee_missing_emails(mock_client):
    from SOCRadarIncidentsV4 import add_assignee_command

    with pytest.raises(ValueError, match="user_emails is required"):
        add_assignee_command(mock_client, {"alarm_id": "1", "user_emails": ""})


def test_add_tag_success(mock_client, mocker):
    from SOCRadarIncidentsV4 import add_tag_command

    mocker.patch.object(mock_client, "add_remove_tag", return_value={"is_success": True})
    result = add_tag_command(mock_client, {"alarm_id": "1", "tag": "critical"})
    assert "critical" in result.readable_output


def test_add_tag_missing_tag(mock_client):
    from SOCRadarIncidentsV4 import add_tag_command

    with pytest.raises(ValueError, match="tag is required"):
        add_tag_command(mock_client, {"alarm_id": "1", "tag": ""})


# ---------------------------------------------------------------------------
# test_fetch_command
# ---------------------------------------------------------------------------


def test_test_fetch_success(mock_client, mocker):
    from SOCRadarIncidentsV4 import test_fetch_command

    mocker.patch.object(
        mock_client,
        "search_incidents",
        return_value=_mock_response([_make_alarm()], total_records=1, total_pages=1),
    )

    result = test_fetch_command(mock_client, {"first_fetch": "3 days", "limit": "5"})
    assert "Found" in result.readable_output


def test_test_fetch_no_incidents(mock_client, mocker):
    from SOCRadarIncidentsV4 import test_fetch_command

    mocker.patch.object(mock_client, "search_incidents", return_value=_mock_response([]))

    result = test_fetch_command(mock_client, {"first_fetch": "3 days", "limit": "5"})
    assert "No incidents found" in result.readable_output


def test_client_search_incidents_error_response(mock_client, mocker, capfd):
    """Test that API error response raises DemistoException"""
    from CommonServerPython import DemistoException

    mocker.patch.object(
        mock_client,
        "_http_request",
        return_value={
            "is_success": False,
            "message": "Invalid request",
        },
    )

    with capfd.disabled(), pytest.raises(DemistoException, match="API Error"):
        mock_client.search_incidents(limit=1, page=1)


# ---------------------------------------------------------------------------
# format_value
# ---------------------------------------------------------------------------


def test_format_value_dict():
    from SOCRadarIncidentsV4 import format_value

    result = format_value({"key1": "val1", "key2": "val2"})
    assert "key1: val1" in result
    assert "key2: val2" in result


def test_format_value_nested_dict():
    from SOCRadarIncidentsV4 import format_value

    result = format_value({"parent": {"child": "value"}})
    assert "parent:" in result
    assert "  child: value" in result


def test_format_value_list():
    from SOCRadarIncidentsV4 import format_value

    result = format_value(["item1", "item2"])
    assert "- item1" in result
    assert "- item2" in result


def test_format_value_list_of_dicts():
    from SOCRadarIncidentsV4 import format_value

    result = format_value([{"k": "v"}])
    assert "-" in result[0]
    assert "k: v" in result[1]


def test_format_value_scalar():
    from SOCRadarIncidentsV4 import format_value

    result = format_value("simple_string")
    assert result == ["simple_string"]


def test_format_value_dict_with_list_value():
    from SOCRadarIncidentsV4 import format_value

    result = format_value({"items": ["a", "b"]})
    assert "items:" in result
    assert any("- a" in line for line in result)


# ---------------------------------------------------------------------------
# alarm_to_incident include_* parameters
# ---------------------------------------------------------------------------


def test_alarm_to_incident_include_mitigation():
    import json
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["alarm_type_details"]["alarm_default_mitigation_plan"] = "Do X and Y"

    incident = alarm_to_incident(alarm, include_mitigation=True)
    assert incident["CustomFields"]["socradarmitigation"] == "Do X and Y"
    raw = json.loads(incident["rawJSON"])
    assert raw.get("alarm_mitigation") == "Do X and Y"


def test_alarm_to_incident_include_response():
    import json
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["alarm_response"] = "Response steps here"

    incident = alarm_to_incident(alarm, include_response=True)
    assert incident["CustomFields"]["socradarresponse"] == "Response steps here"
    raw = json.loads(incident["rawJSON"])
    assert raw.get("alarm_response_plan") == "Response steps here"


def test_alarm_to_incident_include_detection_and_analysis():
    import json
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["alarm_type_details"]["alarm_detection_and_analysis"] = "Detection info"

    incident = alarm_to_incident(alarm, include_detection_and_analysis=True)
    assert incident["CustomFields"]["socradardetectionandanalysis"] == "Detection info"
    raw = json.loads(incident["rawJSON"])
    assert raw.get("alarm_detection_and_analysis") == "Detection info"


def test_alarm_to_incident_include_post_incident_analysis():
    import json
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["alarm_type_details"]["alarm_post_incident_analysis"] = "Post analysis"

    incident = alarm_to_incident(alarm, include_post_incident_analysis=True)
    assert incident["CustomFields"]["socradarpostincidentanalysis"] == "Post analysis"
    raw = json.loads(incident["rawJSON"])
    assert raw.get("alarm_post_incident_analysis") == "Post analysis"


def test_alarm_to_incident_include_related_assets():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["alarm_related_assets"] = [{"key": "domain", "value": ["example.com", "test.com"]}]

    incident = alarm_to_incident(alarm, include_related_assets=True)
    assert "domain: example.com || test.com" in incident["CustomFields"]["socradarrelatedassets"]


def test_alarm_to_incident_include_related_entities():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["alarm_related_entities"] = [{"key": "IP", "value": "1.2.3.4"}]

    incident = alarm_to_incident(alarm, include_related_entities=True)
    assert "IP: 1.2.3.4" in incident["CustomFields"]["socradarrelatedentities"]


def test_alarm_to_incident_include_company_id():
    import json
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    # Remove company_id from alarm to test configured_company_id fallback
    del alarm["company_id"]

    incident = alarm_to_incident(alarm, include_company_id=True, configured_company_id="789")
    assert incident["CustomFields"]["socradarcompanyid"] == "789"
    raw = json.loads(incident["rawJSON"])
    assert raw.get("company_id") == "789"


def test_alarm_to_incident_include_company_id_from_alarm():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm(company_id="456")

    incident = alarm_to_incident(alarm, include_company_id=True)
    assert incident["CustomFields"]["socradarcompanyid"] == "456"


def test_alarm_to_incident_show_content_false():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["content"] = {"key1": "value1", "key2": "value2"}

    incident = alarm_to_incident(alarm, show_content=False, include_incident_link=True)
    assert incident["CustomFields"]["socradarincidentcontent"] == ""


def test_alarm_to_incident_show_content_true():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["content"] = {"key1": "value1"}

    incident = alarm_to_incident(alarm, show_content=True, include_incident_link=True)
    assert "key1: value1" in incident["CustomFields"]["socradarincidentcontent"]


def test_alarm_to_incident_non_dict_alarm_type_details():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["alarm_type_details"] = "not-a-dict"

    incident = alarm_to_incident(alarm)
    assert "Unknown" in incident["name"]


def test_alarm_to_incident_non_dict_content():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["content"] = "not-a-dict"

    incident = alarm_to_incident(alarm, show_content=True, include_incident_link=True)
    assert incident["CustomFields"]["socradarincidentcontent"] == ""


def test_alarm_to_incident_non_list_tags():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["tags"] = "not-a-list"

    incident = alarm_to_incident(alarm)
    assert incident["CustomFields"]["socradartags"] == ""


def test_alarm_to_incident_non_list_related_entities():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["alarm_related_entities"] = "not-a-list"

    incident = alarm_to_incident(alarm)
    # Should not crash
    assert incident["name"] is not None


def test_alarm_to_incident_non_list_related_assets():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["alarm_related_assets"] = "not-a-list"

    incident = alarm_to_incident(alarm)
    assert incident["name"] is not None


def test_alarm_to_incident_no_date():
    from SOCRadarIncidentsV4 import alarm_to_incident

    alarm = _make_alarm()
    alarm["date"] = None

    incident = alarm_to_incident(alarm)
    assert incident["occurred"].endswith("Z")


# ---------------------------------------------------------------------------
# search_incidents - data as list path
# ---------------------------------------------------------------------------


def test_search_incidents_data_as_list(mock_client, mocker):
    """Test that when API returns data as a list (no total_records), it is handled."""
    mocker.patch.object(
        mock_client,
        "_http_request",
        return_value={
            "is_success": True,
            "data": [{"alarm_id": 1}, {"alarm_id": 2}],
        },
    )

    result = mock_client.search_incidents(limit=10, page=1, include_total_records=False)
    assert result["total_records"] == 2
    assert result["total_pages"] == 1
    assert len(result["data"]) == 2


def test_search_incidents_include_company_id(mock_client, mocker):
    """Test that include_company_id passes the param to the API."""
    mock_http = mocker.patch.object(
        mock_client,
        "_http_request",
        return_value={
            "is_success": True,
            "data": {"alarms": [], "total_pages": 1, "total_records": 0},
        },
    )

    mock_client.search_incidents(limit=10, page=1, include_company_id=True)

    call_kwargs = mock_http.call_args[1]
    assert call_kwargs["params"]["include_company_id"] == "true"


def test_search_incidents_no_include_company_id(mock_client, mocker):
    """Test that include_company_id=False does not add the param."""
    mock_http = mocker.patch.object(
        mock_client,
        "_http_request",
        return_value={
            "is_success": True,
            "data": {"alarms": [], "total_pages": 1, "total_records": 0},
        },
    )

    mock_client.search_incidents(limit=10, page=1, include_company_id=False)

    call_kwargs = mock_http.call_args[1]
    assert "include_company_id" not in call_kwargs["params"]


# ---------------------------------------------------------------------------
# change_alarm_status - update_related_finding_status and email
# ---------------------------------------------------------------------------


def test_change_alarm_status_with_update_related_and_email(mock_client, mocker):
    """Test change_alarm_status passes update_related_finding_status and email."""
    mock_http = mocker.patch.object(
        mock_client,
        "_http_request",
        return_value={"is_success": True},
    )

    mock_client.change_alarm_status(
        [1],
        "RESOLVED",
        comments="test",
        update_related_finding_status=True,
        email="user@example.com",
    )

    call_kwargs = mock_http.call_args[1]
    assert call_kwargs["json_data"]["update_related_finding_status"] is True
    assert call_kwargs["json_data"]["email"] == "user@example.com"


def test_change_alarm_status_with_company_id(mock_client, mocker):
    """Test change_alarm_status uses provided company_id."""
    mock_http = mocker.patch.object(
        mock_client,
        "_http_request",
        return_value={"is_success": True},
    )

    mock_client.change_alarm_status([1], "OPEN", company_id="999")

    call_kwargs = mock_http.call_args[1]
    assert "/company/999/" in call_kwargs["url_suffix"]


def test_change_alarm_status_no_company_id(mocker):
    """Test change_alarm_status raises when no company_id available."""
    from SOCRadarIncidentsV4 import Client

    client = Client(
        base_url="https://platform.socradar.com/api",
        api_key="test",
        company_id="",
        verify=False,
        proxy=False,
    )

    with pytest.raises(ValueError, match="company_id must be provided"):
        client.change_alarm_status([1], "OPEN")


def test_change_alarm_status_api_error(mock_client, mocker):
    """Test change_alarm_status raises on API error."""
    from CommonServerPython import DemistoException

    mocker.patch.object(
        mock_client,
        "_http_request",
        return_value={"is_success": False, "message": "Server error"},
    )

    with pytest.raises(DemistoException, match="API Error"):
        mock_client.change_alarm_status([1], "RESOLVED")


# ---------------------------------------------------------------------------
# change_status_command - update_related_finding_status validation
# ---------------------------------------------------------------------------


def test_change_status_command_requires_email_for_update_related(mock_client, mocker):
    """Test that email is required when update_related_finding_status is true."""
    from SOCRadarIncidentsV4 import change_status_command

    with pytest.raises(ValueError, match="email"):
        change_status_command(
            mock_client,
            {
                "alarm_ids": "1",
                "status_reason": "RESOLVED",
                "update_related_finding_status": "true",
            },
        )


def test_change_status_command_with_update_related_and_email(mock_client, mocker):
    """Test change_status_command passes update_related and email correctly."""
    from SOCRadarIncidentsV4 import change_status_command

    mocker.patch.object(mock_client, "change_alarm_status", return_value={"is_success": True})

    result = change_status_command(
        mock_client,
        {
            "alarm_ids": "1,2",
            "status_reason": "RESOLVED",
            "update_related_finding_status": "true",
            "email": "user@test.com",
        },
    )
    assert "Status changed" in result.readable_output


# ---------------------------------------------------------------------------
# fetch_incidents include parameters pass-through
# ---------------------------------------------------------------------------


def test_fetch_incidents_passes_include_params(mock_client, mocker):
    """Test that include_* params are passed to alarm_to_incident."""
    from SOCRadarIncidentsV4 import fetch_incidents

    alarm = _make_alarm()
    alarm["alarm_type_details"]["alarm_default_mitigation_plan"] = "Mitigation plan"
    alarm["alarm_response"] = "Response plan"

    mocker.patch.object(mock_client, "search_incidents", return_value=_mock_response([alarm]))

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={},
        first_fetch_time="3 days",
        include_mitigation=True,
        include_response=True,
        include_company_id=True,
        configured_company_id="999",
    )

    assert len(incidents) == 1
    cf = incidents[0]["CustomFields"]
    assert cf.get("socradarmitigation") == "Mitigation plan"
    assert cf.get("socradarresponse") == "Response plan"
    assert cf.get("socradarcompanyid") is not None


# ---------------------------------------------------------------------------
# parse_alarm_date - additional format
# ---------------------------------------------------------------------------


def test_parse_alarm_date_space_format():
    from SOCRadarIncidentsV4 import parse_alarm_date

    result = parse_alarm_date("2024-01-15 10:30:00")
    assert result is not None
    assert result.year == 2024
    assert result.month == 1
    assert result.day == 15


# ---------------------------------------------------------------------------
# test_module edge cases
# ---------------------------------------------------------------------------


def test_test_module_unexpected_exception(mock_client, mocker, capfd):
    from SOCRadarIncidentsV4 import test_module

    mocker.patch.object(mock_client, "search_incidents", side_effect=RuntimeError("unexpected"))
    with capfd.disabled():
        result = test_module(mock_client)
    assert "Unexpected error" in result


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Client methods - missing company_id
# ---------------------------------------------------------------------------


def test_add_alarm_comment_no_company_id(mocker):
    from SOCRadarIncidentsV4 import Client

    client = Client(
        base_url="https://test.com",
        api_key="k",
        company_id="",
        verify=False,
        proxy=False,
    )
    with pytest.raises(ValueError, match="company_id"):
        client.add_alarm_comment(1, "user@test.com", "comment")


def test_add_alarm_assignee_no_company_id(mocker):
    from SOCRadarIncidentsV4 import Client

    client = Client(
        base_url="https://test.com",
        api_key="k",
        company_id="",
        verify=False,
        proxy=False,
    )
    with pytest.raises(ValueError, match="company_id"):
        client.add_alarm_assignee(1, user_emails=["user@test.com"])


def test_add_remove_tag_no_company_id(mocker):
    from SOCRadarIncidentsV4 import Client

    client = Client(
        base_url="https://test.com",
        api_key="k",
        company_id="",
        verify=False,
        proxy=False,
    )
    with pytest.raises(ValueError, match="company_id"):
        client.add_remove_tag(1, "tag")


def test_parse_checkpoint_handles_naive_zulu_and_invalid_values():
    """
    Given: Checkpoint values in different formats.
    When: parse_checkpoint is called.
    Then: Naive and Z-suffixed values are read as UTC and invalid values return None.
    """
    from SOCRadarIncidentsV4 import parse_checkpoint

    expected = datetime(2026, 11, 16, 21, 0, tzinfo=UTC)
    assert parse_checkpoint("2026-11-16T21:00:00Z") == expected
    assert parse_checkpoint("2026-11-16T21:00:00") == expected
    assert parse_checkpoint("not-a-date") is None
    assert parse_checkpoint(None) is None


def test_search_incidents_retries_on_rate_limit(mock_client, mocker):
    """
    Given: A search request.
    When: search_incidents is called.
    Then: The request is sent with retries for rate limiting and transient server errors.
    """
    mock_http = mocker.patch.object(mock_client, "_http_request", return_value={"is_success": True, "data": []})

    mock_client.search_incidents()

    kwargs = mock_http.call_args.kwargs
    assert kwargs["retries"] == 3
    assert 429 in kwargs["status_list_to_retry"]


def test_fetch_approved_alarms_stops_at_page_limit(mocker):
    """
    Given: The API keeps returning full pages of already fetched alarms.
    When: fetch_approved_alarms pages through the check window.
    Then: Paging stops at MAX_APPROVED_CHECK_PAGES and the window is reported as completed.
    """
    from SOCRadarIncidentsV4 import MAX_INCIDENTS_PER_PAGE, fetch_approved_alarms

    mocker.patch("SOCRadarIncidentsV4.MAX_APPROVED_CHECK_PAGES", 3)
    page_alarms = [{"alarm_id": alarm_id} for alarm_id in range(MAX_INCIDENTS_PER_PAGE)]
    client = mocker.Mock()
    client.search_incidents.return_value = {"data": page_alarms, "total_pages": 1000}
    now = datetime.now(UTC)

    incidents, completed = fetch_approved_alarms(
        client, now - timedelta(hours=1), now, 10, {alarm["alarm_id"] for alarm in page_alarms}, {}, {}
    )

    assert incidents == []
    assert completed is True
    assert client.search_incidents.call_count == 3
