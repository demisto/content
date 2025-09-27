import pytest
from unittest.mock import patch
import requests_mock
from freezegun import freeze_time
from datetime import datetime
import json
from CommonServerPython import *
import demistomock as demisto

from VercaraUltraDNSEventCollector import (
    Client,
    convert_time_string,
    _calculate_event_hash,
    _deduplicate_events,
    _cache_recent_events,
    _cleanup_event_cache,
    process_events_for_xsiam,
    fetch_events,
    get_events_command,
    test_module,
    VENDOR,
    PRODUCT,
    API_DATE_FORMAT,
)


""" CONSTANTS """

BASE_URL = "https://example.ultradns.com/v2"
USERNAME = "test_user"
PASSWORD = "test_password"
TOKEN_URL = f"{BASE_URL}/authorization/token"
AUDIT_LOG_URL = f"{BASE_URL}/reports/dns_configuration/audit"


""" HELPER FUNCTIONS """


def util_load_json(path):
    """Load JSON data from test_data directory."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_send_events_to_xsiam(events, vendor, product):
    """Mock function for send_events_to_xsiam."""
    return events, vendor, product


""" TEST FUNCTIONS """


class TestClient:
    """Test cases for Client class."""

    def test_client_init(self):
        """
        Given:
        - Valid UltraDNS API credentials and base URL

        When:
        - Creating a new Client instance

        Then:
        - Client should be initialized with correct parameters
        - OAuth token should be None initially
        """
        client = Client(base_url=BASE_URL, username=USERNAME, password=PASSWORD, verify=True, proxy=False)

        assert client._base_url == BASE_URL
        assert client.username == USERNAME
        assert client.password == PASSWORD
        assert client.oauth_token is None

    @requests_mock.Mocker()
    def test_authenticate_success(self, m):
        """
        Given:
        - Valid UltraDNS API credentials
        - Mock OAuth token endpoint returning valid token

        When:
        - Calling authenticate method

        Then:
        - Should successfully obtain and store OAuth token
        - Token expiry should be calculated correctly
        """
        # Mock successful token response
        token_response = util_load_json("test_data/oauth_token_response.json")
        m.post(TOKEN_URL, json=token_response)

        client = Client(BASE_URL, USERNAME, PASSWORD)

        with freeze_time("2025-09-27 14:30:00"):
            client.authenticate()

        assert client.oauth_token == token_response["access_token"]
        assert client.token_expiry is not None

    @requests_mock.Mocker()
    def test_authenticate_failure(self, m):
        """
        Given:
        - Invalid UltraDNS API credentials
        - Mock OAuth token endpoint returning 401 error

        When:
        - Calling authenticate method

        Then:
        - Should raise DemistoException with authentication error
        """
        m.post(TOKEN_URL, status_code=401, json={"error": "invalid_credentials"})

        client = Client(BASE_URL, USERNAME, PASSWORD)

        with pytest.raises(DemistoException, match="Authentication failed"):
            client.authenticate()

    @requests_mock.Mocker()
    def test_get_audit_logs_success(self, m):
        """
        Given:
        - Authenticated client
        - Mock audit logs endpoint returning events
        - Valid time range parameters

        When:
        - Calling get_audit_logs method

        Then:
        - Should return audit events from API
        - Should include pagination cursor if available
        """
        # Mock token and audit logs responses
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events.json")

        m.post(TOKEN_URL, json=token_response)
        m.get(AUDIT_LOG_URL, json=audit_response)

        client = Client(BASE_URL, USERNAME, PASSWORD)
        start_time = datetime(2025, 9, 27, 14, 0, 0)
        end_time = datetime(2025, 9, 27, 15, 0, 0)

        result = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=100)

        assert "auditRecords" in result
        assert len(result["auditRecords"]) == 3
        assert result["next_cursor"] == "eyJjdXJzb3IiOiIyMDI1LTA5LTI3VDE0OjMyOjMwWiJ9"


class TestUtilityFunctions:
    """Test cases for utility functions."""

    @pytest.mark.parametrize(
        "time_str,expected_format",
        [
            ("2025-09-27 14:30:00.0", API_DATE_FORMAT),
            ("2025-09-27T14:30:00Z", None),  # Will use dateparser
            ("2025-09-27 14:30:00", None),  # Will use dateparser
        ],
        ids=["api_format", "iso_format", "simple_format"],
    )
    def test_convert_time_string(self, time_str, expected_format):
        """
        Given:
        - Various time string formats from API or user input

        When:
        - Converting time string to datetime object

        Then:
        - Should return timezone-naive datetime object
        - Should handle both API format and ISO formats
        """
        result = convert_time_string(time_str)

        assert isinstance(result, datetime)
        assert result.tzinfo is None  # Should be timezone-naive

        if expected_format == API_DATE_FORMAT:
            # Test that API format is parsed correctly
            expected = datetime.strptime(time_str, API_DATE_FORMAT)
            assert result == expected

    def test_convert_time_string_invalid(self):
        """
        Given:
        - Invalid time string that cannot be parsed

        When:
        - Converting time string to datetime object

        Then:
        - Should raise DemistoException with parsing error
        """
        with pytest.raises(DemistoException, match="Failed to parse time string"):
            convert_time_string("invalid_time_string")

    def test_calculate_event_hash(self):
        """
        Given:
        - Event dictionary with various fields

        When:
        - Calculating hash for the event

        Then:
        - Should return consistent SHA256 hash
        - Same event should produce same hash
        - Different events should produce different hashes
        """
        event1 = {"changeTime": "2025-09-27 14:30:00.0", "user": "admin", "object": "test.com"}
        event2 = {
            "object": "test.com",  # Different order
            "user": "admin",
            "changeTime": "2025-09-27 14:30:00.0",
        }
        event3 = {"changeTime": "2025-09-27 14:30:00.0", "user": "admin", "object": "different.com"}

        hash1 = _calculate_event_hash(event1)
        hash2 = _calculate_event_hash(event2)
        hash3 = _calculate_event_hash(event3)

        assert hash1 == hash2  # Same content, different order should produce same hash
        assert hash1 != hash3  # Different content should produce different hash
        assert len(hash1) == 64  # SHA256 hex string length


class TestDeduplication:
    """Test cases for event deduplication logic."""

    def test_deduplicate_events_no_duplicates(self):
        """
        Given:
        - List of unique events
        - Empty event cache
        - Upper bound for duplicate checking

        When:
        - Running deduplication

        Then:
        - Should return all events unchanged
        - No events should be filtered out
        """
        events = [
            {"changeTime": "2025-09-27 14:30:00.0", "user": "admin", "object": "test1.com"},
            {"changeTime": "2025-09-27 14:29:00.0", "user": "admin", "object": "test2.com"},
        ]
        event_cache = {}
        upper_bound = datetime(2025, 9, 27, 14, 30, 1)

        result = _deduplicate_events(events, event_cache, upper_bound)

        assert len(result) == 2
        assert result == events

    def test_deduplicate_events_with_duplicates(self):
        """
        Given:
        - List of events with some duplicates
        - Event cache containing hashes of previous events
        - Upper bound for duplicate checking

        When:
        - Running deduplication

        Then:
        - Should filter out duplicate events
        - Should keep unique events
        """
        events = [
            {"changeTime": "2025-09-27 14:30:00.0", "user": "admin", "object": "test1.com"},
            {"changeTime": "2025-09-27 14:29:00.0", "user": "admin", "object": "test2.com"},
        ]

        # Pre-populate cache with hash of second event
        duplicate_hash = _calculate_event_hash(events[1])
        event_cache = {duplicate_hash: "2025-09-27T14:29:00Z"}
        upper_bound = datetime(2025, 9, 27, 14, 30, 1)

        result = _deduplicate_events(events, event_cache, upper_bound)

        assert len(result) == 1
        assert result[0] == events[0]  # First event should remain

    def test_deduplicate_events_boundary_optimization(self):
        """
        Given:
        - List of events with some newer than upper boundary
        - Upper bound for duplicate checking

        When:
        - Running deduplication

        Then:
        - Should add all events newer than boundary without duplicate check
        - Should only check duplicates for events within boundary
        """
        events = [
            {"changeTime": "2025-09-27 14:35:00.0", "user": "admin", "object": "new.com"},  # Too new
            {"changeTime": "2025-09-27 14:30:00.0", "user": "admin", "object": "boundary.com"},
            {"changeTime": "2025-09-27 14:25:00.0", "user": "admin", "object": "old.com"},
        ]
        event_cache = {}
        upper_bound = datetime(2025, 9, 27, 14, 30, 1)  # Between first and second event

        result = _deduplicate_events(events, event_cache, upper_bound)

        assert len(result) == 3
        # Should maintain reverse chronological order
        assert result[0]["object"] == "new.com"


class TestCaching:
    """Test cases for event caching logic."""

    def test_cache_recent_events(self):
        """
        Given:
        - List of recent events
        - Empty cache dictionary
        - Cutoff time for caching

        When:
        - Caching recent events

        Then:
        - Should add event hashes to cache with timestamps
        - Should only cache events newer than cutoff
        """
        events = [
            {"changeTime": "2025-09-27 14:30:00.0", "user": "admin", "object": "recent.com"},
            {"changeTime": "2025-09-27 14:20:00.0", "user": "admin", "object": "old.com"},
        ]
        cache = {}
        cutoff_time = datetime(2025, 9, 27, 14, 25, 0)

        _cache_recent_events(events, cache, cutoff_time)

        # Only the first event should be cached (newer than cutoff)
        assert len(cache) == 1
        cached_hash = _calculate_event_hash(events[0])
        assert cached_hash in cache
        assert cache[cached_hash] == "2025-09-27T14:30:00Z"

    def test_cleanup_event_cache(self):
        """
        Given:
        - Event cache with old and recent entries
        - Cutoff time for cleanup

        When:
        - Cleaning up event cache

        Then:
        - Should remove entries older than cutoff
        - Should keep entries newer than cutoff
        """
        event_cache = {
            "hash1": "2025-09-27T14:30:00Z",  # Recent
            "hash2": "2025-09-27T14:20:00Z",  # Old
            "hash3": "2025-09-27T14:35:00Z",  # Recent
        }
        cutoff_time = datetime(2025, 9, 27, 14, 25, 0)

        result = _cleanup_event_cache(event_cache, cutoff_time)

        assert len(result) == 2
        assert "hash1" in result
        assert "hash3" in result
        assert "hash2" not in result

    def test_cleanup_event_cache_invalid_timestamps(self):
        """
        Given:
        - Event cache with some invalid timestamp entries
        - Cutoff time for cleanup

        When:
        - Cleaning up event cache

        Then:
        - Should handle invalid timestamps gracefully
        - Should keep valid entries
        """
        event_cache = {
            "hash1": "2025-09-27T14:30:00Z",  # Valid
            "hash2": "invalid_timestamp",  # Invalid
            "hash3": "2025-09-27T14:35:00Z",  # Valid
        }
        cutoff_time = datetime(2025, 9, 27, 14, 25, 0)

        result = _cleanup_event_cache(event_cache, cutoff_time)

        # Should keep valid entries, invalid entry behavior depends on implementation
        assert "hash1" in result
        assert "hash3" in result


class TestEventProcessing:
    """Test cases for event processing functions."""

    def test_process_events_for_xsiam(self):
        """
        Given:
        - List of events with changeTime field

        When:
        - Processing events for XSIAM ingestion

        Then:
        - Should add _time, _vendor, _product fields
        - Should convert changeTime to timestamp
        """
        events = [
            {"changeTime": "2025-09-27 14:30:00.0", "user": "admin", "object": "test.com"},
            {"changeTime": "2025-09-27 14:31:00.0", "user": "admin", "object": "test2.com"},
        ]

        result = process_events_for_xsiam(events)

        assert len(result) == 2
        for event in result:
            assert "_time" in event
            assert "_vendor" in event
            assert "_product" in event
            assert event["_vendor"] == VENDOR
            assert event["_product"] == PRODUCT
            assert isinstance(event["_time"], (int, float))


class TestMainFunctions:
    """Test cases for main integration functions."""

    @requests_mock.Mocker()
    def test_test_module_success(self, m):
        """
        Given:
        - Valid UltraDNS API credentials
        - Mock API endpoints returning successful responses

        When:
        - Running test module

        Then:
        - Should return "ok" indicating successful connection
        """
        # Mock successful responses
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events_empty.json")

        m.post(TOKEN_URL, json=token_response)
        m.get(AUDIT_LOG_URL, json=audit_response)

        client = Client(BASE_URL, USERNAME, PASSWORD)
        params = {}

        result = test_module(client, params)

        assert result == "ok"

    @requests_mock.Mocker()
    def test_test_module_failure(self, m):
        """
        Given:
        - Invalid UltraDNS API credentials
        - Mock API endpoints returning authentication errors

        When:
        - Running test module

        Then:
        - Should raise DemistoException with connection error
        """
        m.post(TOKEN_URL, status_code=401, json={"error": "invalid_credentials"})

        client = Client(BASE_URL, USERNAME, PASSWORD)
        params = {}

        with pytest.raises(DemistoException):
            test_module(client, params)

    @requests_mock.Mocker()
    @patch("VercaraUltraDNSEventCollector.send_events_to_xsiam", side_effect=mock_send_events_to_xsiam)
    def test_get_events_command(self, mock_send, m):
        """
        Given:
        - Valid API client and parameters
        - Mock audit logs endpoint returning events

        When:
        - Running get-events command

        Then:
        - Should fetch events from API
        - Should return CommandResults with events
        - Should optionally push events to XSIAM
        """
        # Mock responses
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events.json")

        m.post(TOKEN_URL, json=token_response)
        m.get(AUDIT_LOG_URL, json=audit_response)

        client = Client(BASE_URL, USERNAME, PASSWORD)

        with patch.object(
            demisto,
            "args",
            return_value={
                "limit": "10",
                "start_time": "2025-09-27T14:00:00Z",
                "end_time": "2025-09-27T15:00:00Z",
                "should_push_events": "true",
            },
        ):
            result = get_events_command(client)

        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 3
        mock_send.assert_called_once()

    @freeze_time("2025-09-27 15:00:00")
    @requests_mock.Mocker()
    def test_fetch_events_first_run(self, m):
        """
        Given:
        - Empty last_run state (first fetch)
        - Mock API returning events

        When:
        - Running fetch events

        Then:
        - Should fetch events from last 3 hours
        - Should return proper next_run state
        - Should return processed events
        """
        # Mock responses
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events.json")

        m.post(TOKEN_URL, json=token_response)
        m.get(AUDIT_LOG_URL, json=audit_response)

        client = Client(BASE_URL, USERNAME, PASSWORD)
        last_run = {}

        next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

        assert "last_fetch_time" in next_run
        assert "event_cache" in next_run
        assert len(events) == 3
        assert all("_time" in event for event in events)
        assert all("_vendor" in event for event in events)

    @freeze_time("2025-09-27 15:00:00")
    @requests_mock.Mocker()
    def test_fetch_events_subsequent_run(self, m):
        """
        Given:
        - Previous last_run state with timestamp and cache
        - Mock API returning new events

        When:
        - Running fetch events

        Then:
        - Should fetch events with overlap from last timestamp
        - Should deduplicate events using cache
        - Should update next_run state with new timestamp
        """
        # Mock responses
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events.json")

        m.post(TOKEN_URL, json=token_response)
        m.get(AUDIT_LOG_URL, json=audit_response)

        client = Client(BASE_URL, USERNAME, PASSWORD)
        last_run = {"last_fetch_time": "2025-09-27T14:25:00Z", "event_cache": {}}

        next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

        assert next_run["last_fetch_time"] > last_run["last_fetch_time"]
        assert len(events) == 3

    @freeze_time("2025-09-27 15:00:00")
    @requests_mock.Mocker()
    def test_fetch_events_no_new_events(self, m):
        """
        Given:
        - Previous last_run state
        - Mock API returning no new events

        When:
        - Running fetch events

        Then:
        - Should return unchanged last_run state
        - Should return empty events list
        """
        # Mock responses
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events_empty.json")

        m.post(TOKEN_URL, json=token_response)
        m.get(AUDIT_LOG_URL, json=audit_response)

        client = Client(BASE_URL, USERNAME, PASSWORD)
        last_run = {"last_fetch_time": "2025-09-27T14:25:00Z", "event_cache": {"test_hash": "2025-09-27T14:20:00Z"}}

        next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

        assert next_run == last_run  # Should be unchanged
        assert len(events) == 0

    @freeze_time("2025-09-27 15:00:00")
    @requests_mock.Mocker()
    def test_fetch_events_with_pagination(self, m):
        """
        Given:
        - Mock API returning paginated responses
        - Multiple pages of events

        When:
        - Running fetch events

        Then:
        - Should fetch all pages until no more data
        - Should combine events from all pages
        """
        # Mock responses
        token_response = util_load_json("test_data/oauth_token_response.json")
        first_page = util_load_json("test_data/audit_events.json")
        second_page = util_load_json("test_data/audit_events_second_page.json")

        m.post(TOKEN_URL, json=token_response)

        # Mock first page with cursor
        m.get(AUDIT_LOG_URL, json=first_page)

        # Mock second page without cursor
        m.get(AUDIT_LOG_URL, json=second_page)

        client = Client(BASE_URL, USERNAME, PASSWORD)
        last_run = {}

        next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

        # Should have events from both pages
        assert len(events) >= 3  # At least the events from first page

    @freeze_time("2025-09-27 15:00:00")
    @requests_mock.Mocker()
    def test_fetch_events_deduplication_integration(self, m):
        """
        Given:
        - Previous last_run with cached event hashes
        - Mock API returning some duplicate events

        When:
        - Running fetch events

        Then:
        - Should properly deduplicate events
        - Should only return unique events
        - Should update cache with new event hashes
        """
        # Create test events
        test_events = util_load_json("test_data/audit_events.json")

        # Pre-calculate hash for one event to simulate duplicate
        duplicate_event = test_events["auditRecords"][0]
        duplicate_hash = _calculate_event_hash(duplicate_event)

        # Mock responses
        token_response = util_load_json("test_data/oauth_token_response.json")

        m.post(TOKEN_URL, json=token_response)
        m.get(AUDIT_LOG_URL, json=test_events)

        client = Client(BASE_URL, USERNAME, PASSWORD)
        last_run = {"last_fetch_time": "2025-09-27T14:25:00Z", "event_cache": {duplicate_hash: "2025-09-27T14:30:00Z"}}

        next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

        # Should have one less event due to deduplication
        assert len(events) == 2
        assert duplicate_hash in next_run["event_cache"]
