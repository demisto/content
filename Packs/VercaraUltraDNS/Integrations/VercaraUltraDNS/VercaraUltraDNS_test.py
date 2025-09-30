import pytest
import requests_mock
from freezegun import freeze_time
from datetime import datetime
import json
from unittest.mock import patch
from CommonServerPython import *

from VercaraUltraDNS import (
    Client,
    convert_time_string,
    _calculate_event_hash,
    _deduplicate_events,
    _cache_recent_events,
    _cleanup_event_cache,
    process_events_for_xsiam,
    fetch_events,
    get_events_command,
    VENDOR,
    PRODUCT,
)

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


@pytest.fixture
def client() -> Client:
    """
    Fixture to create and return a Client instance for testing.
    Uses mock credentials defined at the top of the file.
    """
    return Client(base_url=BASE_URL, username=USERNAME, password=PASSWORD, verify=True, proxy=False)


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
        - OAuth token should be empty initially
        """
        client = Client(base_url=BASE_URL, username=USERNAME, password=PASSWORD, verify=True, proxy=False)

        assert client._base_url == BASE_URL
        assert client.username == USERNAME
        assert client.password == PASSWORD
        assert client.access_token is None

    def test_authenticate_success(self):
        """
        Given:
        - Valid UltraDNS API credentials
        - Mock OAuth token endpoint returning valid token

        When:
        - Calling get_access_token method

        Then:
        - Should successfully obtain and store OAuth token
        - Token expiry should be calculated correctly
        """
        token_response = util_load_json("test_data/oauth_token_response.json")

        with requests_mock.Mocker() as mocker:
            mocker.post(TOKEN_URL, json=token_response)

            client = Client(BASE_URL, USERNAME, PASSWORD)

            with freeze_time("2025-09-27 14:30:00"):
                access_token = client.get_access_token()

            assert access_token == "abc_test"
            assert client.token_expires_in == 3500

    def test_authenticate_failure(self):
        """
        Given:
        - Invalid UltraDNS API credentials
        - Mock OAuth token endpoint returning 401 error

        When:
        - Calling get_access_token method

        Then:
        - Should raise DemistoException with authentication error
        """
        with requests_mock.Mocker() as mocker:
            mocker.post(TOKEN_URL, status_code=401, json={"error": "invalid_credentials"})

            client = Client(BASE_URL, USERNAME, PASSWORD)

            with pytest.raises(DemistoException):
                client.get_access_token()

    def test_get_audit_logs_success(self):
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
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events.json")

        with requests_mock.Mocker() as mocker:
            mocker.post(TOKEN_URL, json=token_response)
            mocker.get(AUDIT_LOG_URL, json=audit_response)

            client = Client(BASE_URL, USERNAME, PASSWORD)
            start_time = datetime(2025, 9, 27, 14, 0, 0)
            end_time = datetime(2025, 9, 27, 15, 0, 0)

            result = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=100)

            assert "auditRecords" in result
            assert len(result["auditRecords"]) == 3
            assert result["next_cursor"] == "cursor_123"


class TestUtilityFunctions:
    """Test cases for utility functions."""

    def test_convert_time_string_success(self):
        """
        Given:
        - Valid API time string in expected format

        When:
        - Converting time string to datetime object

        Then:
        - Should return correct timezone-naive datetime object
        """
        time_str = "2025-09-27 14:30:00.0"
        expected = datetime(2025, 9, 27, 14, 30, 0)

        result = convert_time_string(time_str)

        assert isinstance(result, datetime)
        assert result.tzinfo is None  # Should be timezone-naive
        assert result == expected

    def test_convert_time_string_invalid(self):
        """
        Given:
        - Invalid time string that cannot be parsed with API format

        When:
        - Converting time string to datetime object

        Then:
        - Should raise DemistoException with detailed parsing error
        """
        invalid_time = "2025-09-27T14:30:00"  # Wrong format (ISO instead of API)

        with pytest.raises(DemistoException, match="Failed to parse time string"):
            convert_time_string(invalid_time)

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
        event_cache = {duplicate_hash: "2025-09-27T14:29:00"}
        upper_bound = datetime(2025, 9, 27, 14, 30, 1)

        result = _deduplicate_events(events, event_cache, upper_bound)

        assert len(result) == 1
        assert result[0] == events[0]  # First event should remain

    def test_deduplicate_events_boundary_optimization(self):
        """
        Given:
        - List of events with some newer than upper boundary
        - Event cache containing hash of the "newer" event (simulating it was processed before)
        - Upper bound for duplicate checking

        When:
        - Running deduplication

        Then:
        - Should add events newer than boundary without duplicate check (ignoring cache)
        - Should check duplicates for events within boundary
        """
        events = [
            {"changeTime": "2025-09-27 14:35:00.0", "user": "admin", "object": "new.com"},  # Newer than boundary
            {"changeTime": "2025-09-27 14:30:00.0", "user": "admin", "object": "boundary.com"},
            {"changeTime": "2025-09-27 14:25:00.0", "user": "admin", "object": "old.com"},
        ]

        # Pre-populate cache with hash of the "new.com" event to test optimization
        new_event_hash = _calculate_event_hash(events[0])
        old_event_hash = _calculate_event_hash(events[2])
        event_cache = {
            new_event_hash: "2025-09-27T14:35:00",  # This should be ignored due to optimization
            old_event_hash: "2025-09-27T14:25:00",  # This should cause old.com to be filtered
        }
        upper_bound = datetime(2025, 9, 27, 14, 30, 1)  # Between first and second event

        result = _deduplicate_events(events, event_cache, upper_bound)

        # Should have 2 events: new.com (bypassed cache) and boundary.com (not in cache)
        # old.com should be filtered out due to duplicate in cache
        assert len(result) == 2
        assert result[0]["object"] == "new.com"  # Newer event kept despite being in cache (for testing only,
        # in real life it will not be in cache)
        assert result[1]["object"] == "boundary.com"  # Boundary event kept (not in cache)


class TestCaching:
    """Test cases for event caching logic."""

    def test_cache_recent_events(self):
        """
        Given:
        - List of events with different timestamps relative to cutoff
        - Empty cache dictionary
        - Cutoff time for caching

        When:
        - Caching recent events

        Then:
        - Should cache events newer than or equal to cutoff
        - Should not cache events older than cutoff
        """
        events = [
            {"changeTime": "2025-09-27 14:30:00.0", "user": "admin", "object": "recent.com"},  # Newer
            {"changeTime": "2025-09-27 14:25:00.0", "user": "admin", "object": "exact.com"},  # Equal to cutoff
            {"changeTime": "2025-09-27 14:20:00.0", "user": "admin", "object": "old.com"},  # Older
        ]

        with patch("VercaraUltraDNS._calculate_event_hash") as mock_hash:
            mock_hash.side_effect = ["hash_recent", "hash_exact", "hash_old"]

            cache = {}
            cutoff_time = datetime(2025, 9, 27, 14, 25, 0)

            _cache_recent_events(events, cache, cutoff_time)

            # Should cache 2 events: newer + equal to cutoff (>= behavior)
            assert len(cache) == 2
            assert "hash_recent" in cache
            assert "hash_exact" in cache  # Equal to cutoff should be cached
            assert "hash_old" not in cache  # Older than cutoff should not be cached

            assert cache["hash_recent"] == "2025-09-27T14:30:00"
            assert cache["hash_exact"] == "2025-09-27T14:25:00"

            # Verify hash function was called for the cached events only
            assert mock_hash.call_count == 2  # Only called for events that got cached

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
            "hash1": "2025-09-27T14:30:00",  # Recent
            "hash2": "2025-09-27T14:20:00",  # Old
            "hash3": "2025-09-27T14:35:00",  # Recent
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
            "hash1": "2025-09-27T14:30:00",  # Valid
            "hash2": "invalid_timestamp",  # Invalid
            "hash3": "2025-09-27T14:35:00",  # Valid
        }
        cutoff_time = datetime(2025, 9, 27, 14, 25, 0)

        result = _cleanup_event_cache(event_cache, cutoff_time)

        # Should keep valid entries
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
            assert isinstance(event["_time"], int | float)


class TestMainFunctions:
    """Test cases for main integration functions."""

    def test_test_module_success(self):
        """
        Given:
        - Valid UltraDNS API credentials
        - Mock API endpoints returning successful responses

        When:
        - Running test module

        Then:
        - Should return "ok" indicating successful connection
        """
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events_empty.json")

        from VercaraUltraDNS import test_module

        with requests_mock.Mocker() as mocker:
            mocker.post(TOKEN_URL, json=token_response)
            mocker.get(AUDIT_LOG_URL, json=audit_response)

            client = Client(BASE_URL, USERNAME, PASSWORD)
            result = test_module(client, {})

            assert result == "ok"

    def test_test_module_failure(self):
        """
        Given:
        - Invalid UltraDNS API credentials
        - Mock API endpoints returning authentication errors

        When:
        - Running test module

        Then:
        - Should return error message with authentication failure
        """
        from VercaraUltraDNS import test_module

        with requests_mock.Mocker() as mocker:
            mocker.post(TOKEN_URL, status_code=401, json={"error": "invalid_credentials"})

            client = Client(BASE_URL, USERNAME, PASSWORD)

            result = test_module(client, {})

            assert "Connection failed:" in result

    def test_get_events_command(self, mocker):
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
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events.json")

        # Remove next_cursor to simulate single page response
        audit_response.pop("next_cursor", None)

        mock_send = mocker.patch("VercaraUltraDNS.send_events_to_xsiam", side_effect=mock_send_events_to_xsiam)

        with requests_mock.Mocker() as requests_mocker:
            requests_mocker.post(TOKEN_URL, json=token_response)
            requests_mocker.get(AUDIT_LOG_URL, json=audit_response)

            client = Client(BASE_URL, USERNAME, PASSWORD)

            args = {
                "limit": "10",
                "start_time": "2025-09-27T14:00:00",
                "end_time": "2025-09-27T15:00:00",
                "should_push_events": "true",
            }

            events, result = get_events_command(client, args)

            assert isinstance(result, CommandResults)
            assert len(events) == 3
            mock_send.assert_called_once()

    @freeze_time("2025-09-27 15:00:00")
    def test_fetch_events_first_run(self):
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
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events.json")

        # Remove next_cursor to simulate single page response
        audit_response.pop("next_cursor", None)

        with requests_mock.Mocker() as mocker:
            mocker.post(TOKEN_URL, json=token_response)
            mocker.get(AUDIT_LOG_URL, json=audit_response)

            client = Client(BASE_URL, USERNAME, PASSWORD)
            last_run = {}

            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

            assert "last_fetch_time" in next_run
            assert "event_cache" in next_run
            assert len(events) == 3
            assert all("_time" in event for event in events)
            assert all("_vendor" in event for event in events)

    @freeze_time("2025-09-27 15:00:00")
    def test_fetch_events_no_new_events(self):
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
        token_response = util_load_json("test_data/oauth_token_response.json")
        audit_response = util_load_json("test_data/audit_events_empty.json")

        with requests_mock.Mocker() as mocker:
            mocker.post(TOKEN_URL, json=token_response)
            mocker.get(AUDIT_LOG_URL, json=audit_response)

            client = Client(BASE_URL, USERNAME, PASSWORD)
            last_run = {"last_fetch_time": "2025-09-27T14:25:00", "event_cache": {"test_hash": "2025-09-27T14:20:00"}}

            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

            assert next_run == last_run  # Should be unchanged
            assert len(events) == 0

    @freeze_time("2025-09-27 15:00:00")
    def test_fetch_events_deduplication__end_to_end(self):
        """
        Given:
        - Previous last_run with timestamp and cached event hashes
        - Mock API returning events including duplicates

        When:
        - Running fetch events

        Then:
        - Should use last_fetch_time - 3s for API call
        - Should deduplicate using cached hashes
        - Should update next_run with exact timestamp and cache values
        - Should clean up old cache entries
        """
        token_response = util_load_json("test_data/oauth_token_response.json")
        test_events = util_load_json("test_data/audit_events.json")

        # Pre-calculate hash for last event to simulate it's already cached (duplicate)
        duplicate_event = test_events["auditRecords"][2]  # 14:30:00 event (oldest)
        duplicate_hash = _calculate_event_hash(duplicate_event)

        # Pre-calculate hash for newest event for validation
        first_event = test_events["auditRecords"][0]  # 14:32:30 event (newest)
        first_hash = _calculate_event_hash(first_event)

        # Remove next_cursor to simulate single page response
        test_events.pop("next_cursor", None)

        with requests_mock.Mocker() as mocker:
            mocker.post(TOKEN_URL, json=token_response)
            mocker.get(AUDIT_LOG_URL, json=test_events)

            client = Client(BASE_URL, USERNAME, PASSWORD)

            # Setup last_run with cached duplicate and an old hash that should be cleaned up
            old_hash = "old_hash_should_be_cleaned"
            last_run = {
                "last_fetch_time": "2025-09-27T14:30:05",  # After the oldest event (14:30:00)
                "event_cache": {
                    duplicate_hash: "2025-09-27T14:30:00",  # Duplicate oldest event
                    old_hash: "2025-09-27T14:20:00",  # Old hash to be cleaned
                },
            }

            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

            # 1. Verify API called with correct lookback (last_fetch_time - 3 seconds)
            # 14:30:05 - 3 = 14:30:02
            expected_filter = "date_range%3A20250927143002-20250927150000"
            assert f"filter={expected_filter}" in mocker.last_request.url

            # 2. Verify deduplication worked - oldest event filtered, 2 returned
            assert len(events) == 2

            # 3. Verify next_run has exact timestamp of newest event
            assert next_run["last_fetch_time"] == "2025-09-27T14:32:30"  # Newest event

            # 4. Verify exact cache contents
            # Cache cutoff = newest event time (14:32:30) - (3+1)s = 14:32:26
            # Only events >= 14:32:26 should be cached
            expected_cache = {
                first_hash: "2025-09-27T14:32:30",  # Newest event cached (14:32:30 >= 14:32:26)
                # second_hash NOT cached - 14:31:15 < 14:32:26 (before cutoff)
                # duplicate_hash (14:30:00) should be cleaned up (before cutoff)
                # old_hash should be cleaned up (not present)
            }
            assert next_run["event_cache"] == expected_cache

            # 5. Verify returned events are the correct ones (not the duplicate)
            returned_timestamps = [event["changeTime"] for event in events]
            expected_timestamps = ["2025-09-27 14:32:30.0", "2025-09-27 14:31:15.0"]  # Oldest event (14:30:00) was filtered
            assert returned_timestamps == expected_timestamps
