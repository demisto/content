import pytest
import json
from CommonServerPython import *
from SOCRadarIncidentsV4MultiTenant import Client, STATUS_REASON_MAP


@pytest.fixture
def mock_client(mocker):
    """Create a mock client for testing"""
    client = Client(
        base_url="https://dummy-test.com/api",
        api_key="test_api_key",
        multi_tenant_id="test_tenant_id",
        verify=False,
        proxy=False,
    )
    return client


@pytest.fixture
def sample_alarm():
    """Sample alarm data for testing"""
    return {
        "alarm_id": 12345,
        "company_id": "67890",
        "alarm_risk_level": "HIGH",
        "alarm_asset": "test.com",
        "status": "OPEN",
        "date": "2024-01-15T10:30:00.000000",
        "alarm_type_details": {
            "alarm_main_type": "Brand Protection",
            "alarm_sub_type": "Impersonating Domain",
        },
        "alarm_text": "Suspicious domain detected",
        "tags": ["phishing", "urgent"],
        "alarm_related_entities": [
            {"key": "domain", "value": "fake-test.com"},
            {"key": "ip", "value": "192.168.1.1"},
        ],
    }


@pytest.mark.parametrize(
    "severity,expected",
    [
        pytest.param("LOW", IncidentSeverity.LOW, id="low_severity"),
        pytest.param("MEDIUM", IncidentSeverity.MEDIUM, id="medium_severity"),
        pytest.param("HIGH", IncidentSeverity.HIGH, id="high_severity"),
        pytest.param("CRITICAL", IncidentSeverity.CRITICAL, id="critical_severity"),
        pytest.param("INFO", IncidentSeverity.INFO, id="info_severity"),
        pytest.param("INVALID", IncidentSeverity.UNKNOWN, id="unknown_severity"),
    ],
)
def test_convert_to_demisto_severity(severity, expected):
    """Test severity conversion with various inputs"""
    from SOCRadarIncidentsV4MultiTenant import convert_to_demisto_severity

    assert convert_to_demisto_severity(severity) == expected


@pytest.mark.parametrize(
    "date_str,expected_year,expected_month,expected_day",
    [
        pytest.param("2024-01-15T10:30:00.123456", 2024, 1, 15, id="with_microseconds"),
        pytest.param("2024-01-15T10:30:00", 2024, 1, 15, id="without_microseconds"),
        pytest.param("2024-01-15", 2024, 1, 15, id="date_only"),
    ],
)
def test_parse_alarm_date_valid(date_str, expected_year, expected_month, expected_day):
    """Test parsing valid alarm dates"""
    from SOCRadarIncidentsV4MultiTenant import parse_alarm_date

    result = parse_alarm_date(date_str)
    assert result is not None
    assert result.year == expected_year
    assert result.month == expected_month
    assert result.day == expected_day


@pytest.mark.parametrize(
    "date_str",
    [
        pytest.param(None, id="none_date"),
        pytest.param("invalid-date", id="invalid_format"),
    ],
)
def test_parse_alarm_date_invalid(date_str):
    """Test parsing invalid alarm dates"""
    from SOCRadarIncidentsV4MultiTenant import parse_alarm_date

    result = parse_alarm_date(date_str)
    assert result is None


def test_alarm_to_incident_basic(sample_alarm):
    """Test basic alarm to incident conversion"""
    from SOCRadarIncidentsV4MultiTenant import alarm_to_incident

    incident = alarm_to_incident(sample_alarm)

    assert incident["name"] == "SOCRadar Alarm 12345: Brand Protection - Impersonating Domain [test.com]"
    assert incident["severity"] == IncidentSeverity.HIGH
    assert incident["dbotMirrorId"] == "12345"
    assert "12345" in incident["details"]
    assert "test.com" in incident["details"]


def test_alarm_to_incident_custom_fields(sample_alarm):
    """Test custom fields in alarm to incident conversion"""
    from SOCRadarIncidentsV4MultiTenant import alarm_to_incident

    incident = alarm_to_incident(sample_alarm)

    assert incident["CustomFields"]["socradaralarmid"] == "12345"
    assert incident["CustomFields"]["socradarcompanyid"] == "67890"
    assert incident["CustomFields"]["socradarstatus"] == "OPEN"
    assert incident["CustomFields"]["socradarasset"] == "test.com"
    assert incident["CustomFields"]["socradaralarmtype"] == "Brand Protection"
    assert "phishing" in incident["CustomFields"]["socradartags"]


def test_alarm_to_incident_with_missing_fields():
    """Test alarm to incident conversion with minimal data"""
    from SOCRadarIncidentsV4MultiTenant import alarm_to_incident

    minimal_alarm = {
        "alarm_id": 999,
        "company_id": "123",
    }
    incident = alarm_to_incident(minimal_alarm)

    assert incident["name"] is not None
    assert incident["CustomFields"]["socradaralarmid"] == "999"
    assert incident["CustomFields"]["socradarcompanyid"] == "123"


def test_alarm_to_incident_raw_json(sample_alarm):
    """Test raw JSON in alarm to incident conversion"""
    from SOCRadarIncidentsV4MultiTenant import alarm_to_incident

    incident = alarm_to_incident(sample_alarm)
    raw_json = json.loads(incident["rawJSON"])

    assert raw_json["alarm_id"] == 12345
    assert raw_json["company_id"] == "67890"


class TestClient:
    """Test Client class methods"""

    def test_client_initialization(self):
        """Test client initialization"""
        client = Client(
            base_url="https://dummy-test.com/api",
            api_key="test_key",
            multi_tenant_id="tenant_123",
            verify=True,
            proxy=False,
        )

        assert client.api_key == "test_key"
        assert client.multi_tenant_id == "tenant_123"

    def test_get_headers(self, mock_client):
        """Test headers generation"""
        headers = mock_client._get_headers()
        assert headers["API-Key"] == "test_api_key"

    def test_search_incidents_params(self, mock_client, mocker):
        """Test search incidents with parameters"""
        mock_response = {
            "is_success": True,
            "message": "Success",
            "data": {"alarms": [], "total_pages": 1, "total_records": 0},
        }

        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        result = mock_client.search_incidents(
            status=["OPEN"],
            severities=["HIGH"],
            limit=50,
            page=1,
        )

        assert result["is_success"] is True
        assert result["data"] == []
        assert result["total_pages"] == 1

    def test_change_alarm_status_invalid_status(self, mock_client):
        """Test change alarm status with invalid status"""
        with pytest.raises(ValueError, match="Invalid status reason"):
            mock_client.change_alarm_status([123], "INVALID_STATUS", company_id="123")

    def test_change_alarm_status_missing_company_id(self, mock_client):
        """Test change alarm status without company ID"""
        with pytest.raises(ValueError, match="company_id must be provided"):
            mock_client.change_alarm_status([123], "OPEN")


def test_change_status_command_success(mock_client, mocker):
    """Test change status command success"""
    from SOCRadarIncidentsV4MultiTenant import change_status_command

    mock_response = {"is_success": True, "message": "Status changed"}
    mocker.patch.object(mock_client, "change_alarm_status", return_value=mock_response)
    mocker.patch.object(mock_client, "get_company_id_for_alarm", return_value="123")

    args = {
        "alarm_ids": "123,456",
        "status_reason": "RESOLVED",
        "comments": "Test comment",
    }

    result = change_status_command(mock_client, args)
    assert "Status changed for 2 alarm(s)" in result.readable_output


def test_change_status_command_missing_params(mock_client):
    """Test change status command with missing parameters"""
    from SOCRadarIncidentsV4MultiTenant import change_status_command

    args = {"alarm_ids": "123"}

    with pytest.raises(ValueError, match="alarm_ids and status_reason are required"):
        change_status_command(mock_client, args)


def test_mark_false_positive_success(mock_client, mocker):
    """Test mark as false positive command success"""
    from SOCRadarIncidentsV4MultiTenant import mark_as_false_positive_command

    mock_response = {"is_success": True}
    mocker.patch.object(mock_client, "change_alarm_status", return_value=mock_response)
    mocker.patch.object(mock_client, "get_company_id_for_alarm", return_value="123")

    args = {"alarm_id": "123", "comments": "False positive"}

    result = mark_as_false_positive_command(mock_client, args)
    assert "marked as false positive" in result.readable_output


def test_mark_false_positive_missing_alarm_id(mock_client):
    """Test mark as false positive with missing alarm ID"""
    from SOCRadarIncidentsV4MultiTenant import mark_as_false_positive_command

    args = {}

    with pytest.raises(ValueError, match="alarm_id is required"):
        mark_as_false_positive_command(mock_client, args)


def test_mark_resolved_success(mock_client, mocker):
    """Test mark as resolved command success"""
    from SOCRadarIncidentsV4MultiTenant import mark_as_resolved_command

    mock_response = {"is_success": True}
    mocker.patch.object(mock_client, "change_alarm_status", return_value=mock_response)
    mocker.patch.object(mock_client, "get_company_id_for_alarm", return_value="123")

    args = {"alarm_id": "123"}

    result = mark_as_resolved_command(mock_client, args)
    assert "marked as resolved" in result.readable_output


def test_add_comment_success(mock_client, mocker):
    """Test add comment command success"""
    from SOCRadarIncidentsV4MultiTenant import add_comment_command

    mock_response = {"is_success": True}
    mocker.patch.object(mock_client, "add_alarm_comment", return_value=mock_response)
    mocker.patch.object(mock_client, "get_company_id_for_alarm", return_value="123")

    args = {
        "alarm_id": "123",
        "user_email": "test@example.com",
        "comment": "Test comment",
    }

    result = add_comment_command(mock_client, args)
    assert "Comment added to alarm 123" in result.readable_output


def test_add_comment_missing_params(mock_client, mocker):
    """Test add comment with missing parameters"""
    from SOCRadarIncidentsV4MultiTenant import add_comment_command

    mocker.patch.object(mock_client, "get_company_id_for_alarm", return_value="123")

    args = {"alarm_id": "123"}

    with pytest.raises(ValueError, match="user_email and comment are required"):
        add_comment_command(mock_client, args)


def test_add_assignee_success(mock_client, mocker):
    """Test add assignee command success"""
    from SOCRadarIncidentsV4MultiTenant import add_assignee_command

    mock_response = {"is_success": True}
    mocker.patch.object(mock_client, "add_alarm_assignee", return_value=mock_response)
    mocker.patch.object(mock_client, "get_company_id_for_alarm", return_value="123")

    args = {
        "alarm_id": "123",
        "user_emails": "user1@example.com,user2@example.com",
    }

    result = add_assignee_command(mock_client, args)
    assert "Assignee added for alarm 123" in result.readable_output


def test_add_assignee_missing_emails(mock_client, mocker):
    """Test add assignee with missing emails"""
    from SOCRadarIncidentsV4MultiTenant import add_assignee_command

    mocker.patch.object(mock_client, "get_company_id_for_alarm", return_value="123")

    args = {"alarm_id": "123"}

    with pytest.raises(ValueError, match="user_emails is required"):
        add_assignee_command(mock_client, args)


def test_add_tag_success(mock_client, mocker):
    """Test add tag command success"""
    from SOCRadarIncidentsV4MultiTenant import add_tag_command

    mock_response = {"is_success": True}
    mocker.patch.object(mock_client, "add_remove_tag", return_value=mock_response)
    mocker.patch.object(mock_client, "get_company_id_for_alarm", return_value="123")

    args = {"alarm_id": "123", "tag": "urgent"}

    result = add_tag_command(mock_client, args)
    assert "Tag 'urgent' added/removed for alarm 123" in result.readable_output


def test_add_tag_missing_tag(mock_client, mocker):
    """Test add tag with missing tag"""
    from SOCRadarIncidentsV4MultiTenant import add_tag_command

    mocker.patch.object(mock_client, "get_company_id_for_alarm", return_value="123")

    args = {"alarm_id": "123"}

    with pytest.raises(ValueError, match="tag is required"):
        add_tag_command(mock_client, args)


def test_test_fetch_success(mock_client, mocker):
    """Test the test-fetch command success"""
    from SOCRadarIncidentsV4MultiTenant import test_fetch_command

    mock_response = {
        "is_success": True,
        "data": [
            {
                "alarm_id": 123,
                "company_id": "456",
                "alarm_risk_level": "HIGH",
                "status": "OPEN",
                "alarm_asset": "test.com",
                "date": "2024-01-15T10:30:00",
                "alarm_type_details": {
                    "alarm_main_type": "Test Type",
                    "alarm_sub_type": "Test Sub",
                },
                "alarm_related_entities": [],
            }
        ],
        "total_records": 1,
        "total_pages": 1,
    }

    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

    args = {"limit": "5", "first_fetch": "3 days"}

    result = test_fetch_command(mock_client, args)
    assert "Found 1 incident(s)" in result.readable_output


def test_test_fetch_no_incidents(mock_client, mocker):
    """Test the test-fetch command with no incidents"""
    from SOCRadarIncidentsV4MultiTenant import test_fetch_command

    mock_response = {
        "is_success": True,
        "data": [],
        "total_records": 0,
        "total_pages": 0,
    }

    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

    args = {"limit": "5", "first_fetch": "3 days"}

    result = test_fetch_command(mock_client, args)
    assert "No incidents found" in result.readable_output


def test_status_reason_map_completeness():
    """Test that all expected status reasons are in the map"""
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
        assert isinstance(STATUS_REASON_MAP[status], int)


def test_test_module_success(mock_client, mocker, capfd):
    """Test the test-module command success"""
    from SOCRadarIncidentsV4MultiTenant import test_module

    mock_response = {
        "is_success": True,
        "data": [{"alarm_id": 123, "company_id": "456"}],
    }
    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

    with capfd.disabled():
        result = test_module(mock_client)
    assert result == "ok"


def test_test_module_failure(mock_client, mocker, capfd):
    """Test the test-module command failure"""
    from SOCRadarIncidentsV4MultiTenant import test_module

    mock_response = {
        "is_success": False,
        "message": "Authentication failed",
    }
    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

    with capfd.disabled():
        result = test_module(mock_client)
    assert "Test failed" in result


def test_test_module_unauthorized(mock_client, mocker, capfd):
    """Test the test-module command with 401 error"""
    from SOCRadarIncidentsV4MultiTenant import test_module

    mocker.patch.object(
        mock_client,
        "search_incidents",
        side_effect=DemistoException("401 Unauthorized"),
    )

    with capfd.disabled():
        result = test_module(mock_client)
    assert "Authorization Error" in result


def test_test_module_forbidden(mock_client, mocker, capfd):
    """Test the test-module command with 403 error"""
    from SOCRadarIncidentsV4MultiTenant import test_module

    mocker.patch.object(
        mock_client,
        "search_incidents",
        side_effect=DemistoException("403 Forbidden"),
    )

    with capfd.disabled():
        result = test_module(mock_client)
    assert "Access Denied" in result


def test_test_module_not_found(mock_client, mocker, capfd):
    """Test the test-module command with 404 error"""
    from SOCRadarIncidentsV4MultiTenant import test_module

    mocker.patch.object(
        mock_client,
        "search_incidents",
        side_effect=DemistoException("404 Not Found"),
    )

    with capfd.disabled():
        result = test_module(mock_client)
    assert "API Endpoint Not Found" in result


def test_fetch_incidents_first_fetch(mock_client, mocker):
    """Test fetch incidents on first run"""
    from SOCRadarIncidentsV4MultiTenant import fetch_incidents

    mock_response = {
        "is_success": True,
        "data": [
            {
                "alarm_id": 123,
                "company_id": "456",
                "alarm_risk_level": "HIGH",
                "alarm_asset": "test.com",
                "status": "OPEN",
                "date": "2024-01-15T10:30:00",
                "alarm_type_details": {
                    "alarm_main_type": "Test Type",
                    "alarm_sub_type": "Test Sub",
                },
                "alarm_text": "Test alarm",
                "tags": [],
                "alarm_related_entities": [],
            }
        ],
        "total_records": 1,
        "total_pages": 1,
        "current_page": 1,
    }

    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

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
    assert incidents[0]["name"] is not None


def test_fetch_incidents_subsequent_fetch(mock_client, mocker):
    """Test fetch incidents on subsequent runs"""
    from SOCRadarIncidentsV4MultiTenant import fetch_incidents
    from datetime import datetime, timedelta

    last_fetch_time = (datetime.now() - timedelta(minutes=5)).isoformat() + "Z"

    mock_response = {
        "is_success": True,
        "data": [],
        "total_records": 0,
        "total_pages": 0,
        "current_page": 1,
    }

    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={"last_fetch": last_fetch_time, "last_alarm_ids": [123, 456]},
        first_fetch_time="3 days",
        fetch_interval_minutes=1,
    )

    assert len(incidents) == 0
    assert "last_fetch" in next_run


def test_fetch_incidents_with_duplicates(mock_client, mocker):
    """Test fetch incidents with duplicate detection"""
    from SOCRadarIncidentsV4MultiTenant import fetch_incidents
    from datetime import datetime, timedelta

    last_fetch_time = (datetime.now() - timedelta(minutes=5)).isoformat() + "Z"

    mock_response = {
        "is_success": True,
        "data": [
            {
                "alarm_id": 123,  # This is a duplicate
                "company_id": "456",
                "alarm_risk_level": "HIGH",
                "alarm_asset": "test.com",
                "status": "OPEN",
                "date": "2024-01-15T10:30:00",
                "alarm_type_details": {
                    "alarm_main_type": "Test Type",
                    "alarm_sub_type": "Test Sub",
                },
                "alarm_text": "Test alarm",
                "tags": [],
                "alarm_related_entities": [],
            }
        ],
        "total_records": 1,
        "total_pages": 1,
        "current_page": 1,
    }

    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={"last_fetch": last_fetch_time, "last_alarm_ids": [123]},
        first_fetch_time="3 days",
        fetch_interval_minutes=1,
    )

    # Should skip the duplicate
    assert len(incidents) == 0


def test_fetch_incidents_with_filters(mock_client, mocker):
    """Test fetch incidents with various filters"""
    from SOCRadarIncidentsV4MultiTenant import fetch_incidents

    mock_response = {
        "is_success": True,
        "data": [],
        "total_records": 0,
        "total_pages": 0,
        "current_page": 1,
    }

    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

    next_run, incidents = fetch_incidents(
        client=mock_client,
        max_results=100,
        last_run={},
        first_fetch_time="3 days",
        fetch_interval_minutes=1,
        status=["OPEN"],
        severities=["HIGH", "CRITICAL"],
        alarm_type_ids=[1, 2, 3],
        excluded_alarm_type_ids=[4, 5],
        alarm_main_types=["Brand Protection"],
        excluded_alarm_main_types=["Test Type"],
        alarm_sub_types=["Phishing"],
        excluded_alarm_sub_types=["Test Sub"],
    )

    assert "last_fetch" in next_run


def test_fetch_incidents_error_handling(mock_client, mocker, capfd):
    """Test fetch incidents error handling"""
    from SOCRadarIncidentsV4MultiTenant import fetch_incidents

    mocker.patch.object(
        mock_client,
        "search_incidents",
        side_effect=Exception("API Error"),
    )

    with capfd.disabled():
        next_run, incidents = fetch_incidents(
            client=mock_client,
            max_results=100,
            last_run={},
            first_fetch_time="3 days",
            fetch_interval_minutes=1,
        )

    # Should return empty incidents on error
    assert len(incidents) == 0
    assert "last_fetch" in next_run


def test_client_add_alarm_comment(mock_client, mocker):
    """Test client add alarm comment method"""
    mock_response = {"is_success": True}
    mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

    result = mock_client.add_alarm_comment(
        alarm_id=123,
        user_email="test@example.com",
        comment="Test comment",
        company_id="456",
    )

    assert result["is_success"] is True


def test_client_add_alarm_assignee(mock_client, mocker):
    """Test client add alarm assignee method"""
    mock_response = {"is_success": True}
    mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

    result = mock_client.add_alarm_assignee(
        alarm_id=123,
        user_emails=["user1@example.com", "user2@example.com"],
        company_id="456",
    )

    assert result["is_success"] is True


def test_client_add_remove_tag(mock_client, mocker):
    """Test client add/remove tag method"""
    mock_response = {"is_success": True}
    mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

    result = mock_client.add_remove_tag(
        alarm_id=123,
        tag="urgent",
        company_id="456",
    )

    assert result["is_success"] is True


def test_client_get_company_id_for_alarm(mock_client, mocker):
    """Test client get company ID for alarm method"""
    mock_response = {
        "is_success": True,
        "data": [{"alarm_id": 123, "company_id": "456"}],
        "total_pages": 1,
    }
    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

    result = mock_client.get_company_id_for_alarm(123)

    assert result == "456"


def test_client_get_company_id_for_alarm_not_found(mock_client, mocker):
    """Test client get company ID for alarm when not found"""
    mock_response = {
        "is_success": True,
        "data": [],
        "total_pages": 0,
    }
    mocker.patch.object(mock_client, "search_incidents", return_value=mock_response)

    result = mock_client.get_company_id_for_alarm(999)

    assert result is None


def test_client_change_alarm_status_success(mock_client, mocker):
    """Test client change alarm status success"""
    mock_response = {"is_success": True}
    mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

    result = mock_client.change_alarm_status(
        alarm_ids=[123, 456],
        status_reason="RESOLVED",
        comments="Test",
        company_id="789",
    )

    assert result["is_success"] is True


def test_client_change_alarm_status_api_error(mock_client, mocker):
    """Test client change alarm status with API error"""
    mock_response = {"is_success": False, "message": "API Error"}
    mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

    with pytest.raises(DemistoException, match="API Error"):
        mock_client.change_alarm_status(
            alarm_ids=[123],
            status_reason="RESOLVED",
            company_id="789",
        )


def test_client_search_incidents_error_response(mock_client, mocker, capfd):
    """Test client search incidents with error response"""
    mock_response = {
        "is_success": False,
        "message": "Invalid request",
    }
    mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

    with capfd.disabled(), pytest.raises(DemistoException, match="Invalid request"):
        mock_client.search_incidents(limit=10, page=1)
