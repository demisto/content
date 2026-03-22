import pytest
from datetime import datetime, timedelta


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

    mocker.patch.object(mock_client, "search_incidents", return_value={"is_success": False, "message": "Authentication failed"})
    with capfd.disabled():
        result = test_module(mock_client)
    assert "Test failed" in result


def test_test_module_unauthorized(mock_client, mocker, capfd):
    from SOCRadarIncidentsV4 import test_module
    from CommonServerPython import DemistoException

    mocker.patch.object(mock_client, "search_incidents", side_effect=DemistoException("401 Unauthorized"))
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
    mocker.patch.object(mock_client, "search_incidents", return_value=_mock_response([_make_alarm(alarm_id=200)]))

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
    mocker.patch.object(mock_client, "search_incidents", return_value=_mock_response([_make_alarm(alarm_id=123)]))

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
    result = add_comment_command(mock_client, {"alarm_id": "1", "user_email": "user@example.com", "comment": "test"})
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
