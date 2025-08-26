import pytest
from datetime import datetime
from freezegun import freeze_time
import demistomock as demisto
from CommonServerPython import *

from BitSightEventCollector import (
    Client,
    to_bitsight_date,
    findings_to_events,
    time_window,
    resolve_guid,
    fetch_events,
    bitsight_get_events_command,
    test_module,
)


@pytest.fixture
def mock_client(mocker):
    """Create a mocked BitSight client for testing."""
    # Mock HTTP requests
    mocker.patch.object(Client, "_http_request")

    client = Client(base_url="https://api.bitsighttech.com", verify=True, proxy=False, auth=("test_api_key", ""))
    
    # Mock client methods that tests use
    client.get_companies_guid = mocker.Mock()
    client.get_company_findings = mocker.Mock()
    
    return client


@pytest.fixture
def sample_findings():
    """Sample BitSight findings response data."""
    return [
        {
            "id": "finding-1",
            "first_seen": "2024-01-15",
            "last_seen": "2024-01-16",
            "risk_category": "Compromised Systems",
            "risk_vector": "Botnet Infections",
            "severity": 8.5,
            "assets": [{"asset": "192.168.1.1", "category": "high"}],
        },
        {
            "id": "finding-2",
            "first_seen": "2024-01-14",
            "last_seen": "2024-01-15",
            "risk_category": "Diligence",
            "risk_vector": "SSL Certificates",
            "severity": 3.2,
            "assets": [{"asset": "example.com", "category": "medium"}],
        },
        {
            "id": "finding-3",
            "first_seen": "2024-01-13",
            "last_seen": "2024-01-14",
            "risk_category": "User Behavior",
            "risk_vector": "File Sharing",
            "severity": 6.1,
            "assets": [{"asset": "files.example.com", "category": "low"}],
        },
        {
            "id": "finding-4",
            "first_seen": "2024-01-12",
            "last_seen": "2024-01-13",
            "risk_category": "User Behavior",
            "risk_vector": "File Sharing",
            "severity": 6.1,
            "assets": [{"asset": "files2.example.com", "category": "low"}],
        },
    ]


@pytest.fixture
def sample_companies_response():
    """Sample companies API response."""
    return {"myCompany": {"guid": "auto-detected-guid", "name": "Test Company", "customId": "test-123"}}


class TestBitSightEventCollector:
    """Test suite for BitSight Event Collector integration."""

    def test_to_bitsight_date(self):
        """
        Given: A UNIX timestamp

        When: Converting to BitSight date format

        Then: Should return YYYY-MM-DD format in UTC
        """
        # January 15, 2024 12:30:45 UTC
        timestamp = 1705321845
        result = to_bitsight_date(timestamp)

        assert result == "2024-01-15"

    def test_findings_to_events_with_first_seen(self, sample_findings):
        """
        Given: BitSight findings with first_seen dates

        When: Converting to XSIAM events

        Then: Should set _time field from first_seen and preserve all original fields
        """
        events = findings_to_events(sample_findings)

        assert len(events) == 3
        assert events[0]["_time"] == "2024-01-15T00:00:00Z"
        assert events[1]["_time"] == "2024-01-14T00:00:00Z"
        assert events[2]["_time"] == "2024-01-13T00:00:00Z"

        # Verify original fields are preserved
        assert events[0]["id"] == "finding-1"
        assert events[0]["risk_category"] == "Compromised Systems"
        assert events[0]["severity"] == 8.5

    def test_findings_to_events_without_first_seen(self):
        """
        Given: BitSight findings without first_seen dates

        When: Converting to XSIAM events

        Then: Should raise ValueError
        """
        findings = [{"id": "no-date", "severity": 5.0}]

        with pytest.raises(ValueError, match="No first_seen date found for finding no-date"):
            findings_to_events(findings)

    def test_findings_to_events_with_firstSeen_field(self):
        """
        Given: BitSight findings with firstSeen field (camelCase variant)

        When: Converting to XSIAM events

        Then: Should set _time field from firstSeen and preserve all fields
        """
        findings = [{"id": "finding-camel", "firstSeen": "2024-01-10", "risk_category": "Test", "severity": 7.5}]
        events = findings_to_events(findings)

        assert len(events) == 1
        assert events[0]["_time"] == "2024-01-10T00:00:00Z"
        assert events[0]["id"] == "finding-camel"
        assert events[0]["severity"] == 7.5

    def test_time_window_with_hours(self):
        """
        Given: A request for time window using hours

        When: Calling time_window with hours parameter

        Then: Should return proper start and end timestamps
        """
        with freeze_time("2024-01-15 12:00:00"):
            start_ts, end_ts = time_window(hours=24)

            # Should be 24 hours ago and now
            expected_start = datetime(2024, 1, 14, 12, 0, 0).timestamp()
            expected_end = datetime(2024, 1, 15, 12, 0, 0).timestamp()

            assert start_ts == int(expected_start)
            assert end_ts == int(expected_end)

    def test_time_window_with_days(self):
        """
        Given: A request for time window using days

        When: Calling time_window with days parameter

        Then: Should return proper start and end timestamps
        """
        with freeze_time("2024-01-15 12:00:00"):
            start_ts, end_ts = time_window(days=1)

            expected_start = datetime(2024, 1, 14, 12, 0, 0).timestamp()
            expected_end = datetime(2024, 1, 15, 12, 0, 0).timestamp()

            assert start_ts == int(expected_start)
            assert end_ts == int(expected_end)

    def test_time_window_invalid_params(self):
        """
        Given: Invalid parameters to time_window

        When: Calling with both hours and days or neither

        Then: Should raise ValueError
        """
        with pytest.raises(ValueError):
            time_window(hours=1, days=1)  # Both provided

        with pytest.raises(ValueError):
            time_window()  # Neither provided

    def test_resolve_guid_from_args(self, mock_client):
        """
        Given: GUID provided in command arguments

        When: Resolving company GUID

        Then: Should return the argument GUID without API call
        """
        result = resolve_guid(mock_client, "arg-guid", "param-guid")
        assert result == "arg-guid"

    def test_resolve_guid_from_params(self, mock_client):
        """
        Given: GUID provided in integration parameters but not args

        When: Resolving company GUID

        Then: Should return the parameter GUID without API call
        """
        result = resolve_guid(mock_client, None, "param-guid")
        assert result == "param-guid"

    def test_resolve_guid_from_api(self, mock_client, sample_companies_response):
        """
        Given: No GUID in args/params but available from API

        When: Resolving company GUID

        Then: Should call API and return myCompany.guid
        """
        mock_client.get_companies_guid.return_value = sample_companies_response

        result = resolve_guid(mock_client, None, None)
        assert result == "auto-detected-guid"
        mock_client.get_companies_guid.assert_called_once()

    def test_resolve_guid_no_company_found(self, mock_client):
        """
        Given: No GUID available from any source

        When: Resolving company GUID

        Then: Should raise ValueError
        """
        mock_client.get_companies_guid.return_value = {"myCompany": None}

        with pytest.raises(ValueError, match="Company GUID is required"):
            resolve_guid(mock_client, None, None)

    def test_resolve_guid_empty_api_response(self, mock_client):
        """
        Given: Empty API response from companies endpoint

        When: Resolving company GUID

        Then: Should raise ValueError
        """
        mock_client.get_companies_guid.return_value = {}

        with pytest.raises(ValueError, match="Company GUID is required"):
            resolve_guid(mock_client, None, None)

    def test_fetch_events_basic(self, mock_client, sample_findings):
        """
        Given: A client and time window for fetching events

        When: Calling fetch_events

        Then: Should return events and update last_run state
        """
        # Mock API response
        mock_client.get_company_findings.return_value = {"results": sample_findings, "links": {"next": None}}

        events, new_last_run = fetch_events(
            client=mock_client,
            guid="test-guid",
            max_fetch=100,
            last_run={},
            start_time=1705280000,  # 2024-01-15 00:00:00
            end_time=1705366400,  # 2024-01-16 00:00:00
        )

        assert len(events) == 3
        assert events[0]["_time"] == "2024-01-15T00:00:00Z"
        assert new_last_run["window_start"] == 1705280000
        assert new_last_run["offset"] == 3

    def test_fetch_events_with_pagination(self, mock_client, sample_findings):
        """
        Given: A client with existing pagination state

        When: Calling fetch_events with last_run offset

        Then: Should continue from previous offset and update state
        """
        # Mock API response
        mock_client.get_company_findings.return_value = {
            "results": sample_findings[:2],  # Only 2 results
            "links": {"next": "next_page_url"},
        }

        last_run = {"window_start": 1705280000, "offset": 10}

        events, new_last_run = fetch_events(
            client=mock_client, guid="test-guid", max_fetch=100, last_run=last_run, start_time=1705280000, end_time=1705366400
        )

        assert len(events) == 2
        assert new_last_run["offset"] == 12  # 10 + 2
        mock_client.get_company_findings.assert_called_once_with(
            "test-guid", first_seen_gte="2024-01-15", last_seen_lte="2024-01-16", limit=100, offset=10
        )

    def test_fetch_events_window_exhausted(self, mock_client):
        """
        Given: API returns no more results for current window

        When: Calling fetch_events

        Then: Should reset window to end_time and reset offset
        """
        # Mock empty response
        mock_client.get_company_findings.return_value = {"results": [], "links": {}}

        events, new_last_run = fetch_events(
            client=mock_client,
            guid="test-guid",
            max_fetch=100,
            last_run={"window_start": 1705280000, "offset": 50},
            start_time=1705280000,
            end_time=1705366400,
        )

        assert len(events) == 0
        assert new_last_run["window_start"] == 1705366400  # Moved to end_time
        assert new_last_run["offset"] == 0  # Reset offset

    def test_fetch_events_max_fetch_limit(self, mock_client, sample_findings):
        """
        Given: API returns more results than max_fetch limit

        When: Calling fetch_events with low max_fetch

        Then: Should limit results to max_fetch and update offset correctly
        """
        # Mock API response with more findings than max_fetch
        mock_client.get_company_findings.return_value = {
            "results": sample_findings,  # 3 findings
            "links": {"next": "next_page_url"},
        }

        events, new_last_run = fetch_events(
            client=mock_client,
            guid="test-guid",
            max_fetch=2,  # Limit to 2 events
            last_run={},
            start_time=1705280000,
            end_time=1705366400,
        )

        assert len(events) == 2  # Should be limited to max_fetch
        assert new_last_run["offset"] == 2  # Should track processed count

    def test_bitsight_get_events_command_without_push(self, mock_client, sample_findings, mocker):
        """
        Given: A get-events command with should_push_events=false

        When: Executing the command

        Then: Should return events in table format without pushing to XSIAM
        """
        # Mock demisto functions
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_client.get_company_findings.return_value = {"results": sample_findings}

        result = bitsight_get_events_command(client=mock_client, guid="test-guid", limit=100, should_push=False)

        assert isinstance(result, CommandResults)
        assert "Bitsight Findings Events" in result.readable_output
        assert "pushed" not in result.readable_output

    def test_bitsight_get_events_command_with_push(self, mock_client, sample_findings, mocker):
        """
        Given: A get-events command with should_push_events=true

        When: Executing the command

        Then: Should push events to XSIAM but NOT update last_run
        """
        # Mock demisto functions
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_send_events = mocker.patch("BitSightEventCollector.send_events_to_xsiam")

        mock_client.get_company_findings.return_value = {"results": sample_findings}

        result = bitsight_get_events_command(client=mock_client, guid="test-guid", limit=100, should_push=True)

        assert isinstance(result, CommandResults)
        assert "pushed" in result.readable_output
        mock_send_events.assert_called_once()
        mock_set_last_run.assert_not_called()

    def test_test_module_success(self, mock_client):
        """
        Given: Valid API credentials and optional GUID

        When: Running test-module

        Then: Should return "ok" after successful API calls
        """
        mock_client.get_companies_guid.return_value = {"myCompany": {"guid": "test"}}
        mock_client.get_company_findings.return_value = {"results": []}

        result = test_module(mock_client, "test-guid")
        assert result == "ok"

    def test_test_module_auth_error(self, mock_client):
        """
        Given: Invalid API credentials

        When: Running test-module

        Then: Should return authorization error message
        """
        mock_client.get_companies_guid.side_effect = DemistoException("Unauthorized")

        result = test_module(mock_client, None)
        assert "Authorization Error" in result

    def test_test_module_other_error(self, mock_client):
        """
        Given: API error that's not auth-related

        When: Running test-module

        Then: Should re-raise the exception
        """
        mock_client.get_companies_guid.side_effect = DemistoException("Server Error")

        with pytest.raises(DemistoException):
            test_module(mock_client, None)

    def test_client_get_companies_guid(self, mock_client):
        """
        Given: A BitSight client

        When: Calling get_companies_guid

        Then: Should make GET request to v1/companies endpoint
        """
        mock_client.get_companies_guid()
        mock_client._http_request.assert_called_once_with(method="GET", url_suffix="v1/companies")

    def test_client_get_company_findings(self, mock_client):
        """
        Given: A BitSight client and finding parameters

        When: Calling get_company_findings

        Then: Should make GET request with proper parameters
        """
        mock_client.get_company_findings(
            guid="test-guid", first_seen_gte="2024-01-15", last_seen_lte="2024-01-16", limit=100, offset=0
        )

        expected_params = {
            "first_seen_gte": "2024-01-15",
            "last_seen_lte": "2024-01-16",
            "unsampled": "true",
            "expand": "attributed_companies",
            "limit": 100,
            "offset": 0,
        }

        mock_client._http_request.assert_called_once_with(
            method="GET", url_suffix="v1/companies/test-guid/findings", params=expected_params
        )
