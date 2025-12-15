import pytest
from freezegun import freeze_time
from CommonServerPython import DemistoException, CommandResults

from BitSightEventCollector import (
    Client,
    to_bitsight_date,
    findings_to_events,
    resolve_guid,
    fetch_events,
    bitsight_get_events_command,
)


@pytest.fixture
def mock_client(mocker):
    """Create a mocked BitSight client for testing."""
    mocker.patch.object(Client, "_http_request")

    client = Client(base_url="https://api.bitsighttech.com", verify=True, proxy=False, auth=("test_api_key", ""))

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
    return {"my_company": {"guid": "auto-detected-guid", "name": "Test Company", "customId": "test-123"}}


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
        events, missing_date_findings = findings_to_events(sample_findings)

        assert len(events) == 4
        assert len(missing_date_findings) == 0
        assert events[0]["_time"] == "2024-01-15T00:00:00"
        assert events[1]["_time"] == "2024-01-14T00:00:00"
        assert events[2]["_time"] == "2024-01-13T00:00:00"

        # Verify original fields are preserved
        assert events[0]["id"] == "finding-1"
        assert events[0]["risk_category"] == "Compromised Systems"
        assert events[0]["severity"] == 8.5

    def test_findings_to_events_without_first_seen(self):
        """
        Given: BitSight findings without first_seen dates

        When: Converting to XSIAM events

        Then: Should keep events without dates and track missing date count
        """
        findings = [{"id": "no-date", "severity": 5.0}]

        events, missing_date_findings = findings_to_events(findings)

        assert len(events) == 1
        assert len(missing_date_findings) == 1
        assert missing_date_findings[0] == "no-date"
        assert events[0]["id"] == "no-date"
        assert events[0]["severity"] == 5.0
        assert "_time" not in events[0]  # No _time field added when no date available

    def test_findings_to_events_with_firstSeen_field(self):
        """
        Given: BitSight findings with firstSeen field (camelCase variant)

        When: Converting to XSIAM events

        Then: Should set _time field from firstSeen and preserve all fields
        """
        findings = [{"id": "finding-camel", "firstSeen": "2024-01-10", "risk_category": "Test", "severity": 7.5}]
        events, missing_date_findings = findings_to_events(findings)

        assert len(events) == 1
        assert len(missing_date_findings) == 0
        assert events[0]["_time"] == "2024-01-10T00:00:00"
        assert events[0]["id"] == "finding-camel"
        assert events[0]["severity"] == 7.5
        assert events[0]["risk_category"] == "Test"

    # time_window function tests removed as the function was deleted

    def test_resolve_guid_from_args(self, mock_client):
        """
        Given: GUID provided in command arguments

        When: Resolving company GUID

        Then: Should return the argument GUID without API call
        """
        result = resolve_guid(mock_client, "arg-guid", "param-guid")
        assert result == "arg-guid"

    def test_resolve_guid_from_my_company(self, mock_client):
        """
        Given: GUID provided in integration parameters but not args

        When: Resolving company GUID

        Then: Should return the parameter GUID without API call
        """
        result = resolve_guid(mock_client, None, "param-guid")
        assert result == "param-guid"

    def test_resolve_guid_from_api(self, mock_client, sample_companies_response, mocker):
        """
        Given: No GUID in args/params but available from API

        When: Resolving company GUID

        Then: Should call API and return my_company.guid
        """
        mocker.patch.object(mock_client, "get_companies_guid", return_value=sample_companies_response)

        result = resolve_guid(mock_client, None, None)
        assert result == "auto-detected-guid"
        mock_client.get_companies_guid.assert_called_once()

    def test_resolve_guid_no_guid_available(self, mock_client, mocker):
        """
        Given: No GUID available from any source

        When: Resolving company GUID

        Then: Should raise ValueError
        """
        mocker.patch.object(mock_client, "get_companies_guid", return_value={"my_company": None})

        with pytest.raises(ValueError, match="Company GUID is required"):
            resolve_guid(mock_client, None, None)

    def test_resolve_guid_empty_api_response(self, mock_client, mocker):
        """
        Given: Empty API response from companies endpoint

        When: Resolving company GUID

        Then: Should raise ValueError
        """
        mocker.patch.object(mock_client, "get_companies_guid", return_value={})

        with pytest.raises(ValueError, match="Company GUID is required"):
            resolve_guid(mock_client, None, None)

    def test_fetch_events_basic(self, mock_client, sample_findings, mocker):
        """
        Given: A client for fetching events

        When: Calling fetch_events with no lookback_days (uses current date)

        Then: Should return events and update last_run state with offset
        """
        # Mock API response
        mocker.patch.object(
            mock_client, "get_company_findings", return_value={"results": sample_findings, "links": {"next": None}}
        )

        with freeze_time("2024-01-15 12:00:00"):
            events, new_last_run, missing_date_findings = fetch_events(
                client=mock_client,
                guid="test-guid",
                max_fetch=100,
                last_run={},
            )

        assert len(events) == 4
        assert events[0]["_time"] == "2024-01-15T00:00:00"
        # Should have fixed first_fetch date and updated offset
        assert "first_fetch" in new_last_run
        assert new_last_run["offset"] == 4  # Number of events fetched

    def test_fetch_events_with_pagination(self, mock_client, sample_findings, mocker):
        """
        Given: A client with existing pagination state

        When: Calling fetch_events with last_run offset

        Then: Should continue from previous offset and increment offset.
        """
        # Mock API response
        mocker.patch.object(
            mock_client,
            "get_company_findings",
            return_value={
                "results": sample_findings[:2],  # 2 results
                "links": {"next": "next_page_url"},
            },
        )

        last_run = {"first_fetch": "2024-01-15", "offset": 10}

        with freeze_time("2024-01-16 12:00:00"):
            events, new_last_run, missing_date_findings = fetch_events(
                client=mock_client,
                guid="test-guid",
                max_fetch=100,
                last_run=last_run,
            )

        assert len(events) == 2
        assert new_last_run["offset"] == 12  # 10 + 2 (simple increment)
        assert new_last_run["first_fetch"] == "2024-01-15"  # Keep same date
        mock_client.get_company_findings.assert_called_once_with(
            "test-guid", first_seen_gte="2024-01-15", last_seen_lte="2024-01-16", limit=100, offset=10
        )

    def test_fetch_events_no_results(self, mock_client, mocker):
        """
        Given: API returns no results

        When: Calling fetch_events

        Then: Should return empty events but maintain offset state
        """
        # Mock API response
        mocker.patch.object(
            mock_client,
            "get_company_findings",
            return_value={
                "results": [],  # No results
                "links": {},  # No next link
            },
        )

        last_run = {"first_fetch": "2024-01-15", "offset": 50}

        with freeze_time("2024-01-16 12:00:00"):
            events, new_last_run, missing_date_findings = fetch_events(
                client=mock_client,
                guid="test-guid",
                max_fetch=100,
                last_run=last_run,
            )

        # Verify it called the API with correct offset
        mock_client.get_company_findings.assert_called_once_with(
            "test-guid", first_seen_gte="2024-01-15", last_seen_lte="2024-01-16", limit=100, offset=50
        )

        assert len(events) == 0
        assert new_last_run["first_fetch"] == "2024-01-15"  # Keep same date
        assert new_last_run["offset"] == 50  # Keep same offset since no new events

    def test_fetch_events_max_fetch_limit(self, mock_client, sample_findings, mocker):
        """
        Given: API returns results respecting max_fetch limit
        When: Calling fetch_events with low max_fetch

        Then: Should return limited results and update offset correctly
        """
        # Mock API response with only the limited findings (simulating API respecting limit)
        mocker.patch.object(
            mock_client,
            "get_company_findings",
            return_value={
                "results": sample_findings[:2],  # Only first 2 findings to match max_fetch=2
                "links": {"next": "next_page_url"},
            },
        )

        with freeze_time("2024-01-15 12:00:00"):
            events, new_last_run, missing_date_findings = fetch_events(
                client=mock_client,
                guid="test-guid",
                max_fetch=2,  # Limit to 2 events
                last_run={},
            )

        assert len(events) == 2  # Should be limited to max_fetch
        assert new_last_run["offset"] == 2  # Should track processed count

    def test_fetch_events_with_lookback_days(self, mock_client, sample_findings, mocker):
        """
        Given: A client with lookback_days parameter

        When: Calling fetch_events with lookback_days=2

        Then: Should calculate start date 2 days back from current time
        """
        # Mock API response
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": sample_findings})

        with freeze_time("2024-01-15 12:00:00"):
            events, new_last_run, missing_date_findings = fetch_events(
                client=mock_client,
                guid="test-guid",
                max_fetch=100,
                last_run={},
                lookback_days=2,
            )

        assert len(events) == 4
        # Should use 2024-01-13 as start date (2 days before 2024-01-15)
        mock_client.get_company_findings.assert_called_once_with(
            "test-guid", first_seen_gte="2024-01-13", last_seen_lte="2024-01-15", limit=100, offset=0
        )
        assert new_last_run["first_fetch"] == "2024-01-13"
        assert new_last_run["offset"] == 4

    def test_bitsight_get_events_command_no_push(self, mock_client, sample_findings, mocker):
        """
        Given: A get-events command with should_push_events=false

        When: Executing the command

        Then: Should return events in table format without pushing to XSIAM
        """
        # Mock API response
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": sample_findings})

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
        # Mock functions
        mock_send_events = mocker.patch("BitSightEventCollector.send_events_to_xsiam")
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": sample_findings})

        result = bitsight_get_events_command(client=mock_client, guid="test-guid", limit=100, should_push=True)

        assert isinstance(result, CommandResults)
        assert "pushed" in result.readable_output
        mock_send_events.assert_called_once()

    def test_test_module_success(self, mock_client, mocker):
        """
        Given: Valid API credentials and optional GUID

        When: Running test-module

        Then: Should return "ok" after successful API calls
        """
        mocker.patch.object(mock_client, "get_companies_guid", return_value={"my_company": {"guid": "test"}})
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": []})

        from BitSightEventCollector import test_module

        result = test_module(mock_client, "test-guid")
        assert result == "ok"

    def test_test_module_auth_error(self, mock_client, mocker):
        """
        Given: Client with authentication error

        When: Running test_module

        Then: Should raise DemistoException (handled by main function)
        """
        # Mock get_companies_guid to raise DemistoException
        mocker.patch.object(mock_client, "get_companies_guid", side_effect=DemistoException("Unauthorized"))

        from BitSightEventCollector import test_module

        # After centralized error handling, DemistoException bubbles up to main()
        with pytest.raises(DemistoException) as exc_info:
            test_module(mock_client, None)

        assert "Unauthorized" in str(exc_info.value)

    def test_test_module_other_error(self, mock_client, mocker):
        """
        Given: API error that's not auth-related

        When: Running test-module

        Then: Should re-raise the exception
        """
        mocker.patch.object(mock_client, "get_companies_guid", side_effect=DemistoException("Server Error"))

        with pytest.raises(DemistoException):
            from BitSightEventCollector import test_module

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
