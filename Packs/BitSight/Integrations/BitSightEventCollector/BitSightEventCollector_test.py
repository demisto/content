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
    resolve_first_seen_window,
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

        last_run = {"first_fetch": "2024-01-15", "offset": 10, "api_count": 10}

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
        assert "already_fetched_findings" not in new_last_run

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

        last_run = {"first_fetch": "2024-01-15", "offset": 50, "api_count": 50}

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

    def test_bitsight_get_events_command_explicit_window(self, mock_client, sample_findings, mocker):
        """
        Given: A get-events command with explicit start_date and end_date (historical window)

        When: Executing the command

        Then: Should query the API directly with that exact window (offset 0) and NOT use
              the 2-day lookback / watermark path.
        """
        mock_get_findings = mocker.patch.object(mock_client, "get_company_findings", return_value={"results": sample_findings})
        mock_fetch_events = mocker.patch("BitSightEventCollector.fetch_events")

        result = bitsight_get_events_command(
            client=mock_client,
            guid="test-guid",
            limit=100,
            should_push=False,
            start_date="2026-08-31",
            end_date="2026-09-02",
        )

        assert isinstance(result, CommandResults)
        # Must not fall through to the scheduled-fetch/watermark logic.
        mock_fetch_events.assert_not_called()
        # Must query the API with the exact explicit window and offset 0.
        _, kwargs = mock_get_findings.call_args
        assert kwargs["first_seen_gte"] == "2026-08-31"
        assert kwargs["first_seen_lte"] == "2026-09-02"
        assert kwargs["last_seen_lte"] is None
        assert kwargs["offset"] == 0

    @freeze_time("2026-09-02 12:00:00")
    def test_bitsight_get_events_command_start_date_only_defaults_end_to_today(self, mock_client, sample_findings, mocker):
        """
        Given: A get-events command with only start_date provided

        When: Executing the command

        Then: Should query from start_date up to today (end_date defaults to current date).
        """
        mock_get_findings = mocker.patch.object(mock_client, "get_company_findings", return_value={"results": sample_findings})

        bitsight_get_events_command(client=mock_client, guid="test-guid", limit=100, should_push=False, start_date="2026-08-31")

        _, kwargs = mock_get_findings.call_args
        assert kwargs["first_seen_gte"] == "2026-08-31"
        assert kwargs["first_seen_lte"] == "2026-09-02"
        assert kwargs["last_seen_lte"] is None

    @freeze_time("2026-09-02 12:00:00")
    def test_bitsight_get_events_command_end_date_only_defaults_start_to_lookback(self, mock_client, sample_findings, mocker):
        """
        Given: A get-events command with only end_date provided

        When: Executing the command

        Then: start defaults to 2 days before end_date, so the window is never inverted.
        """
        mock_get_findings = mocker.patch.object(mock_client, "get_company_findings", return_value={"results": sample_findings})

        bitsight_get_events_command(client=mock_client, guid="test-guid", limit=100, should_push=False, end_date="2026-08-01")

        _, kwargs = mock_get_findings.call_args
        assert kwargs["first_seen_gte"] == "2026-07-30"
        assert kwargs["first_seen_lte"] == "2026-08-01"

    def test_bitsight_get_events_command_start_after_end_raises(self, mock_client, mocker):
        """
        Given: A get-events command where start_date is after end_date

        When: Executing the command

        Then: A ValueError is raised and the API is not called.
        """
        mock_get_findings = mocker.patch.object(mock_client, "get_company_findings")

        with pytest.raises(ValueError, match="must not be after end_date"):
            bitsight_get_events_command(
                client=mock_client, guid="test-guid", limit=100, should_push=False, start_date="2026-09-05", end_date="2026-09-01"
            )
        mock_get_findings.assert_not_called()

    def test_resolve_first_seen_window_same_day(self):
        """
        Given: start_date equal to end_date

        When: Resolving the window

        Then: A single-day window is returned.
        """
        assert resolve_first_seen_window("2026-09-01", "2026-09-01") == ("2026-09-01", "2026-09-01")

    def test_bitsight_get_events_command_explicit_window_null_results(self, mock_client, mocker):
        """
        Given: The API returns "results": null for an explicit window

        When: Executing the command

        Then: No error is raised and no events are returned.
        """
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": None})

        result = bitsight_get_events_command(
            client=mock_client, guid="test-guid", limit=100, should_push=False, start_date="2026-08-31", end_date="2026-09-02"
        )

        assert isinstance(result, CommandResults)
        assert "No entries" in result.readable_output

    @freeze_time("2026-09-02 12:00:00")
    def test_bitsight_get_events_command_free_text_dates(self, mock_client, sample_findings, mocker):
        """
        Given: A get-events command with free-text relative dates ("3 days ago" / "now")

        When: Executing the command

        Then: arg_to_datetime should parse them relative to the current time and the API
              should be queried with the resolved YYYY-MM-DD window.
        """
        mock_get_findings = mocker.patch.object(mock_client, "get_company_findings", return_value={"results": sample_findings})

        bitsight_get_events_command(
            client=mock_client,
            guid="test-guid",
            limit=100,
            should_push=False,
            start_date="3 days ago",
            end_date="now",
        )

        _, kwargs = mock_get_findings.call_args
        assert kwargs["first_seen_gte"] == "2026-08-30"
        assert kwargs["first_seen_lte"] == "2026-09-02"
        assert kwargs["last_seen_lte"] is None
        assert kwargs["offset"] == 0

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
            "sort": "first_seen",
            "limit": 100,
            "offset": 0,
        }

        mock_client._http_request.assert_called_once_with(
            method="GET", url_suffix="v1/companies/test-guid/findings", params=expected_params
        )

    def test_client_get_company_findings_first_seen_lte(self, mock_client):
        """
        Given: A first_seen_lte bound and no last_seen_lte

        When: Calling get_company_findings

        Then: first_seen_lte is sent and last_seen_lte is not.
        """
        mock_client.get_company_findings(
            guid="test-guid", first_seen_gte="2024-01-15", last_seen_lte=None, limit=100, offset=0, first_seen_lte="2024-01-16"
        )

        _, kwargs = mock_client._http_request.call_args
        assert kwargs["params"]["first_seen_lte"] == "2024-01-16"
        assert "last_seen_lte" not in kwargs["params"]

    def test_fetch_events_findings_sharing_a_key_are_all_sent(self, mock_client, mocker):
        """
        Given: Two different findings that share rolledup_observation_id and first_seen

        When: fetch_events runs

        Then: Both findings are returned (no key-based de-duplication) and the offset advances by 2.
        """
        findings = [
            {"rolledup_observation_id": "SAME==", "first_seen": "2026-10-24", "assets": [{"asset": "a.example.com"}]},
            {"rolledup_observation_id": "SAME==", "first_seen": "2026-10-24", "assets": [{"asset": "b.example.com"}]},
        ]
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": findings, "count": 642})
        last_run = {"first_fetch": "2026-09-25", "offset": 640, "api_count": 640}

        with freeze_time("2026-10-26 12:00:00"):
            events, new_last_run, _ = fetch_events(client=mock_client, guid="test-guid", max_fetch=1000, last_run=last_run)

        assert len(events) == 2
        assert new_last_run == {"first_fetch": "2026-09-25", "offset": 642, "api_count": 642}

    def test_fetch_events_legacy_state_resets_offset_and_drops_keys(self, mock_client, mocker):
        """
        Given: A last_run saved by an older build, without api_count. It includes already_fetched_findings
               from 1.3.10 and debug keys written by diagnostic builds that ran on a customer tenant.

        When: fetch_events runs

        Then: The offset is reset to 0 once (first_fetch is kept), and only first_fetch, offset and
              api_count are saved.
        """
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": [], "count": 640})
        last_run = {
            "_debug_sort_sim": {"baseline": False},
            "first_fetch": "2026-09-25",
            "offset": 640,
            "already_fetched_findings": ["X==-#-2026-09-25"],
            "applied_fetch_start": "30 days ago",
        }

        with freeze_time("2026-10-26 12:00:00"):
            events, new_last_run, _ = fetch_events(client=mock_client, guid="test-guid", max_fetch=1000, last_run=last_run)

        assert events == []
        mock_client.get_company_findings.assert_called_once_with(
            "test-guid", first_seen_gte="2026-09-25", last_seen_lte="2026-10-26", limit=1000, offset=0
        )
        assert new_last_run == {"first_fetch": "2026-09-25", "offset": 0, "api_count": 640}

    def test_fetch_events_legacy_state_refetches_from_start(self, mock_client, sample_findings, mocker):
        """
        Given: A pre-sort last_run (offset, no api_count)

        When: Two fetches run

        Then: The first fetch starts at offset 0 and saves api_count; the second keeps its offset (no second reset).
        """
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": sample_findings, "count": 4})

        with freeze_time("2026-10-26 12:00:00"):
            _, first_run, _ = fetch_events(
                client=mock_client, guid="g", max_fetch=1000, last_run={"first_fetch": "2026-09-25", "offset": 300}
            )
            mock_client.get_company_findings.return_value = {"results": [], "count": 4}
            _, second_run, _ = fetch_events(client=mock_client, guid="g", max_fetch=1000, last_run=first_run)

        assert first_run == {"first_fetch": "2026-09-25", "offset": 4, "api_count": 4}
        assert mock_client.get_company_findings.call_args_list[0].kwargs["offset"] == 0
        assert mock_client.get_company_findings.call_args_list[1].kwargs["offset"] == 4
        assert second_run == {"first_fetch": "2026-09-25", "offset": 4, "api_count": 4}

    def test_fetch_events_null_results_and_no_count(self, mock_client, mocker):
        """
        Given: The API returns "results": null and no "count"

        When: fetch_events runs

        Then: No error is raised, the offset is unchanged and api_count is None.
        """
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": None})
        last_run = {"first_fetch": "2026-09-25", "offset": 7, "api_count": 7}

        with freeze_time("2026-10-26 12:00:00"):
            events, new_last_run, _ = fetch_events(client=mock_client, guid="g", max_fetch=1000, last_run=last_run)

        assert events == []
        assert new_last_run == {"first_fetch": "2026-09-25", "offset": 7, "api_count": None}

    def test_fetch_events_offset_above_api_count_logs_warning(self, mock_client, mocker):
        """
        Given: The API reports fewer findings than the saved offset (findings left the window)

        When: fetch_events runs

        Then: A warning is logged via demisto.info.
        """
        import BitSightEventCollector

        info = mocker.patch.object(BitSightEventCollector.demisto, "info")
        mocker.patch.object(mock_client, "get_company_findings", return_value={"results": [], "count": 5})
        last_run = {"first_fetch": "2026-09-25", "offset": 10, "api_count": 10}

        with freeze_time("2026-10-26 12:00:00"):
            fetch_events(client=mock_client, guid="g", max_fetch=1000, last_run=last_run)

        assert any("larger than the total findings" in call.args[0] for call in info.call_args_list)

    def test_fetch_events_sorted_pagination_picks_up_new_tail_finding(self, mock_client, mocker):
        """
        Given: A simulated API that returns findings sorted by first_seen, and a finding that appears
               after the first fetch (it has the newest first_seen, so it lands at the tail)

        When: Two fetches run

        Then: The second fetch returns exactly the new finding - nothing is skipped or repeated.
        """
        dataset = [{"id": f"f{i}", "first_seen": f"2026-10-0{i}"} for i in range(1, 4)]

        def fake_findings(guid, first_seen_gte, last_seen_lte, limit, offset):
            ordered = sorted(dataset, key=lambda finding: finding["first_seen"])
            return {"results": ordered[offset : offset + limit], "count": len(ordered)}

        mocker.patch.object(mock_client, "get_company_findings", side_effect=fake_findings)

        with freeze_time("2026-10-26 12:00:00"):
            first_events, first_run, _ = fetch_events(client=mock_client, guid="g", max_fetch=1000, last_run={})
            dataset.append({"id": "f-new", "first_seen": "2026-10-25"})
            second_events, second_run, _ = fetch_events(client=mock_client, guid="g", max_fetch=1000, last_run=first_run)

        assert [event["id"] for event in first_events] == ["f1", "f2", "f3"]
        assert [event["id"] for event in second_events] == ["f-new"]
        assert second_run["offset"] == 4

    def test_main_fetch_events_pushes_before_saving_last_run(self, mocker):
        """
        Given: The fetch-events command

        When: main runs

        Then: The events are pushed to XSIAM before the new last_run is saved.
        """
        import BitSightEventCollector

        calls: list[str] = []
        demisto = BitSightEventCollector.demisto
        mocker.patch.object(demisto, "params", return_value={"guid": "g", "credentials": {"identifier": "key"}})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(demisto, "getLastRun", return_value={"first_fetch": "2026-09-25", "offset": 0})
        mocker.patch.object(demisto, "setLastRun", side_effect=lambda _: calls.append("setLastRun"))
        mocker.patch.object(
            BitSightEventCollector,
            "send_events_to_xsiam",
            side_effect=lambda *args, **kwargs: calls.append("send_events_to_xsiam"),
        )
        mocker.patch.object(
            Client,
            "get_company_findings",
            return_value={"results": [{"rolledup_observation_id": "A", "first_seen": "2026-09-25"}], "count": 1},
        )

        BitSightEventCollector.main()

        assert calls == ["send_events_to_xsiam", "setLastRun"]
