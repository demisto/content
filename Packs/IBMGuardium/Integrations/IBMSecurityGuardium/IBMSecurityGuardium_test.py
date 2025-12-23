import pytest
import json
from IBMSecurityGuardium import (
    Client,
    extract_field_mapping,
    find_timestamp_field,
    get_event_hash,
    map_event,
    deduplicate_events,
    build_ignore_list,
    fetch_events_command,
    get_events_command,
)
from CommonServerPython import DemistoException


def util_load_json(path):
    """Load JSON file from test_data directory."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def util_create_batch_response(num_events, batch_num=1, timestamp_base="2025-01-01 10:00:00.0"):
    """
    Create a batch response with specified number of events.

    Args:
        num_events: Number of events to include in the batch
        batch_num: Batch number for unique event IDs
        timestamp_base: Base timestamp string

    Returns:
        Dictionary representing API response
    """
    base_response = util_load_json("test_data/sample_api_response.json")

    # Generate events
    events = []
    for i in range(num_events):
        # Parse base timestamp and add seconds
        from datetime import datetime, timedelta

        base_dt = datetime.strptime(timestamp_base, "%Y-%m-%d %H:%M:%S.%f")
        event_dt = base_dt + timedelta(seconds=i + (batch_num - 1) * 1000)
        timestamp = event_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Keep one decimal place

        events.append(
            {
                "results": {
                    "1": "8.8.8.8",
                    "2": "admin",
                    "3": "sqlcmd",
                    "4": "10.130.17.21",
                    "5": "MS SQL SERVER",
                    "6": "MASTER",
                    "7": timestamp,
                }
            }
        )

    base_response["result"]["data"] = events
    return base_response


BASE_URL = "https://guardium.security.ibm.com"
REPORT_ID = "test_report_id"


@pytest.fixture
def client():
    """
    Given:
        - Base URL and authentication credentials
    When:
        - Creating a Client instance
    Then:
        - Ensure the client is properly initialized
    """
    return Client(base_url=BASE_URL, auth=("key", "secret"), verify=True, proxy=False)


class TestExtractFieldMapping:
    """Tests for extract_field_mapping function"""

    def test_extract_field_mapping_with_nls_value(self):
        """
        Given:
            - API response with report headers containing nls_value
        When:
            - Calling extract_field_mapping
        Then:
            - Ensure field mapping uses nls_value (user-friendly names)
        """
        response = util_load_json("test_data/sample_api_response.json")
        result = extract_field_mapping(response)
        assert result == {
            "1": "Client IP",
            "2": "Database User",
            "3": "Source Program",
            "4": "Server IP",
            "5": "Service Name",
            "6": "Database Name",
            "7": "Session Start Time",
        }

    def test_extract_field_mapping_missing_data(self):
        """
        Given:
            - API response missing required fields
        When:
            - Calling extract_field_mapping
        Then:
            - Ensure DemistoException is raised
        """
        with pytest.raises(DemistoException, match="Failed to extract field mapping"):
            extract_field_mapping({"result": {}})


class TestFindTimestampField:
    """Tests for find_timestamp_field function"""

    @pytest.mark.parametrize(
        "event,expected_field",
        [
            ({"timestamp": "2025-06-07 16:52:57.0", "name": "test"}, "timestamp"),
            ({"created": "2025-06-07T16:52:57Z", "id": "123"}, "created"),
            ({"date": "2025-06-07", "value": "abc"}, "date"),
        ],
    )
    def test_find_timestamp_field_success(self, event, expected_field):
        """
        Given:
            - Event with various timestamp field formats
        When:
            - Calling find_timestamp_field
        Then:
            - Ensure the correct timestamp field is identified
        """
        result = find_timestamp_field(event)
        assert result == expected_field

    def test_find_timestamp_field_no_timestamp(self):
        """
        Given:
            - Event without any timestamp-like fields
        When:
            - Calling find_timestamp_field
        Then:
            - Ensure DemistoException is raised
        """
        event = {"name": "test", "count": 5, "status": "active"}
        with pytest.raises(DemistoException, match="No timestamp field found"):
            find_timestamp_field(event)


class TestGetEventHash:
    """Tests for get_event_hash function"""

    def test_get_event_hash_consistent(self):
        """
        Given:
            - Same event dictionary
        When:
            - Calling get_event_hash multiple times
        Then:
            - Ensure the hash is consistent
        """
        event = {"field1": "value1", "field2": "value2"}
        hash1 = get_event_hash(event)
        hash2 = get_event_hash(event)
        assert hash1 == hash2
        assert len(hash1) == 16

    def test_get_event_hash_different_events(self):
        """
        Given:
            - Two different events
        When:
            - Calling get_event_hash on each
        Then:
            - Ensure the hashes are different
        """
        event1 = {"field1": "value1"}
        event2 = {"field1": "value2"}
        hash1 = get_event_hash(event1)
        hash2 = get_event_hash(event2)
        assert hash1 != hash2

    def test_get_event_hash_order_independent(self):
        """
        Given:
            - Same event with fields in different order
        When:
            - Calling get_event_hash
        Then:
            - Ensure the hash is the same (order-independent)
        """
        event1 = {"field1": "value1", "field2": "value2"}
        event2 = {"field2": "value2", "field1": "value1"}
        hash1 = get_event_hash(event1)
        hash2 = get_event_hash(event2)
        assert hash1 == hash2


class TestMapEvent:
    """Tests for map_event function"""

    def test_map_event_with_mapping(self):
        """
        Given:
            - Raw event with numbered fields and field mapping
        When:
            - Calling map_event
        Then:
            - Ensure event fields are mapped to readable names
        """
        field_mapping = {"1": "ClientIP", "2": "UserName", "3": "Action"}
        raw_event = {"1": "10.0.0.1", "2": "admin", "3": "login"}
        result = map_event(raw_event, field_mapping)
        assert result == {"ClientIP": "10.0.0.1", "UserName": "admin", "Action": "login"}

    def test_map_event_unmapped_fields(self):
        """
        Given:
            - Raw event with fields not in mapping
        When:
            - Calling map_event
        Then:
            - Ensure unmapped fields keep their original keys
        """
        field_mapping = {"1": "ClientIP"}
        raw_event = {"1": "10.0.0.1", "2": "admin"}
        result = map_event(raw_event, field_mapping)
        assert result == {"ClientIP": "10.0.0.1", "2": "admin"}


class TestDeduplicateEvents:
    """Tests for deduplicate_events function"""

    def test_deduplicate_events_empty_list(self):
        """
        Given:
            - Empty events list
        When:
            - Calling deduplicate_events
        Then:
            - Ensure empty list is returned
        """
        result = deduplicate_events([], {}, "timestamp")
        assert result == []

    def test_deduplicate_events_no_duplicates(self):
        """
        Given:
            - Events with different timestamps
        When:
            - Calling deduplicate_events
        Then:
            - Ensure all events are returned
        """
        events = [
            {"timestamp": "2025-01-01 10:00:00", "id": "1"},
            {"timestamp": "2025-01-01 11:00:00", "id": "2"},
            {"timestamp": "2025-01-01 12:00:00", "id": "3"},
        ]
        last_run = {"last_fetch_time": "2025-01-01 09:00:00", "fetched_event_hashes": []}
        result = deduplicate_events(events, last_run, "timestamp")
        assert len(result) == 3

    def test_deduplicate_events_with_duplicates(self):
        """
        Given:
            - Events with same timestamp as last_fetch_time and matching hashes
        When:
            - Calling deduplicate_events
        Then:
            - Ensure duplicate events are filtered out
        """
        event1 = {"timestamp": "2025-01-01 10:00:00", "id": "1"}
        event2 = {"timestamp": "2025-01-01 10:00:00", "id": "2"}
        event3 = {"timestamp": "2025-01-01 11:00:00", "id": "3"}
        events = [event1, event2, event3]

        hash1 = get_event_hash(event1)
        last_run = {"last_fetch_time": "2025-01-01 10:00:00", "fetched_event_hashes": [hash1]}

        result = deduplicate_events(events, last_run, "timestamp")
        # event1 is filtered (duplicate), event2 and event3 are kept
        assert len(result) == 2
        # Check that event1 was filtered and event2 and event3 are in the results
        event_ids = [e["id"] for e in result]
        assert "1" not in event_ids
        assert "2" in event_ids
        assert "3" in event_ids

    def test_deduplicate_events_optimization(self):
        """
        Given:
            - Events where first event timestamp is greater than last_fetch_time
            - Both event hashes are in the ignore list
        When:
            - Calling deduplicate_events
        Then:
            - Ensure all events are added without duplicate checking (because timestamp > last_fetch_time)
        """
        event1 = {"timestamp": "2025-01-01 11:00:00", "id": "1"}
        event2 = {"timestamp": "2025-01-01 12:00:00", "id": "2"}
        events = [event1, event2]

        # Get hashes of both events and add them to the ignore list (Hypothetical scenario)
        hash1 = get_event_hash(event1)
        hash2 = get_event_hash(event2)
        last_run = {"last_fetch_time": "2025-01-01 10:00:00", "fetched_event_hashes": [hash1, hash2]}

        result = deduplicate_events(events, last_run, "timestamp")
        # Both events should be kept because their timestamps are greater than last_fetch_time
        assert len(result) == 2


class TestBuildIgnoreList:
    """Tests for build_ignore_list function"""

    def test_build_ignore_list_empty_events(self):
        """
        Given:
            - Empty events list
        When:
            - Calling build_ignore_list
        Then:
            - Ensure empty set is returned
        """
        result = build_ignore_list([], "timestamp")
        assert result == set()

    def test_build_ignore_list_single_timestamp(self):
        """
        Given:
            - Multiple events with same timestamp
        When:
            - Calling build_ignore_list
        Then:
            - Ensure all event hashes are in ignore list
        """
        events = [
            {"timestamp": "2025-01-01 10:00:00", "id": "1"},
            {"timestamp": "2025-01-01 10:00:00", "id": "2"},
            {"timestamp": "2025-01-01 10:00:00", "id": "3"},
        ]
        result = build_ignore_list(events, "timestamp")
        assert len(result) == 3

    def test_build_ignore_list_multiple_timestamps(self):
        """
        Given:
            - Events with different timestamps
        When:
            - Calling build_ignore_list
        Then:
            - Ensure only events with last timestamp are in ignore list
        """
        events = [
            {"timestamp": "2025-01-01 10:00:00", "id": "1"},
            {"timestamp": "2025-01-01 11:00:00", "id": "2"},
            {"timestamp": "2025-01-01 12:00:00", "id": "3"},
            {"timestamp": "2025-01-01 12:00:00", "id": "4"},
        ]
        result = build_ignore_list(events, "timestamp")
        assert len(result) == 2

    def test_build_ignore_list_missing_timestamp_field(self):
        """
        Given:
            - Events missing the timestamp field
        When:
            - Calling build_ignore_list
        Then:
            - Ensure DemistoException is raised
        """
        events = [{"id": "1"}]
        with pytest.raises(DemistoException, match="Timestamp field 'timestamp' not found"):
            build_ignore_list(events, "timestamp")


class TestTestModule:
    """Tests for test_module function"""

    def test_test_module_success(self, client, requests_mock):
        """
        Given:
            - Valid client and report ID
        When:
            - Calling test_module_command
        Then:
            - Ensure 'ok' is returned when API call succeeds
        """
        from IBMSecurityGuardium import test_module_command

        response = util_load_json("test_data/no_resources_response.json")

        response_text = json.dumps(response)
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=response_text)
        result = test_module_command(client, REPORT_ID)
        assert result == "ok"

    def test_test_module_auth_error(self, client, requests_mock):
        """
        Given:
            - Invalid credentials
        When:
            - Calling test_module_command
        Then:
            - Ensure authorization error message is returned
        """
        from IBMSecurityGuardium import test_module_command

        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", status_code=403, text="Forbidden")
        result = test_module_command(client, REPORT_ID)
        assert "Authorization Error" in result


class TestFetchEvents:
    """Tests for fetch_events function"""

    def test_fetch_events_first_run(self, client, requests_mock):
        """
        Given:
            - Empty last_run (first fetch)
        When:
            - Calling fetch_events_command
        Then:
            - Ensure events are fetched and next_run is set correctly
        """
        response = util_load_json("test_data/sample_api_response.json")
        response_text = json.dumps(response)
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=response_text)

        events, next_run, timestamp_field = fetch_events_command(client, REPORT_ID, max_fetch=10, last_run={})

        assert len(events) == 1
        assert "Session Start Time" in events[0]
        assert timestamp_field == "Session Start Time"
        assert next_run["last_fetch_time"] == "2025-06-07 16:52:57.0"
        assert len(next_run["fetched_event_hashes"]) == 1

    def test_fetch_events_no_events(self, client, requests_mock):
        """
        Given:
            - API response with no events
        When:
            - Calling fetch_events_command
        Then:
            - Ensure empty events list and unchanged last_run
        """
        response = util_load_json("test_data/no_resources_response.json")
        response_text = json.dumps(response)
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=response_text)

        last_run = {"last_fetch_time": "2025-06-07T15:00:00.000Z"}
        events, next_run, timestamp_field = fetch_events_command(client, REPORT_ID, max_fetch=10, last_run=last_run)

        assert len(events) == 0
        assert next_run == last_run

    def test_fetch_events_pagination_multiple_batches(self, client, requests_mock, monkeypatch):
        """
        Given:
            - max_fetch of 25 events (requires 3 batches with MAX_BATCH_SIZE=10)
        When:
            - Calling fetch_events_command
        Then:
            - Ensure offset is updated correctly for each batch
            - Ensure all batches are fetched until max_fetch is reached
            - Ensure offset increments by the number of events returned in each batch
        """
        import IBMSecurityGuardium

        monkeypatch.setattr(IBMSecurityGuardium, "MAX_BATCH_SIZE", 10)

        call_count = 0

        def mock_response(request, context):
            nonlocal call_count
            call_count += 1
            payload = request.json()
            offset = payload["offset"]
            fetch_size = payload["fetch_size"]

            # Batch 1: offset=0, fetch_size=10, return 10 events
            if offset == 0:
                assert fetch_size == 10
                return json.dumps(util_create_batch_response(10, batch_num=1))
            # Batch 2: offset=10, fetch_size=10, return 10 events
            elif offset == 10:
                assert fetch_size == 10
                return json.dumps(util_create_batch_response(10, batch_num=2))
            # Batch 3: offset=20, fetch_size=5 (remaining), return 5 events
            elif offset == 20:
                assert fetch_size == 5  # Only 5 remaining to reach max_fetch=25
                return json.dumps(util_create_batch_response(5, batch_num=3))
            else:
                context.status_code = 400
                return json.dumps({"error": f"Unexpected offset: {offset}"})

        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=mock_response)

        events, next_run, timestamp_field = fetch_events_command(client, REPORT_ID, max_fetch=25, last_run={})

        # Verify all 25 events were fetched
        assert len(events) == 25
        # Verify 3 API calls were made
        assert call_count == 3
        assert timestamp_field == "Session Start Time"

    def test_fetch_events_stops_when_less_than_batch_size_returned(self, client, requests_mock, monkeypatch):
        """
        Given:
            - API returns fewer events than requested batch_size
        When:
            - Calling fetch_events_command
        Then:
            - Ensure the loop breaks (no more API calls)
            - Ensure offset is not incremented after the break
        """
        import IBMSecurityGuardium

        monkeypatch.setattr(IBMSecurityGuardium, "MAX_BATCH_SIZE", 10)

        call_count = 0

        def mock_response(request, context):
            nonlocal call_count
            call_count += 1
            payload = request.json()
            offset = payload["offset"]

            # First batch: return 5 events (less than batch_size of 10)
            if offset == 0:
                return json.dumps(util_create_batch_response(5, batch_num=1))
            else:
                # Should not reach here
                context.status_code = 400
                return json.dumps({"error": "Should not make second API call"})

        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=mock_response)

        events, next_run, timestamp_field = fetch_events_command(client, REPORT_ID, max_fetch=100, last_run={})

        # Verify only 5 events were fetched
        assert len(events) == 5
        # Verify only 1 API call was made (loop broke after first batch)
        assert call_count == 1

    def test_fetch_events_stops_when_no_events_returned(self, client, requests_mock, monkeypatch):
        """
        Given:
            - API returns empty data array
        When:
            - Calling fetch_events_command
        Then:
            - Ensure the loop breaks immediately
            - Ensure no events are collected
        """
        import IBMSecurityGuardium

        monkeypatch.setattr(IBMSecurityGuardium, "MAX_BATCH_SIZE", 10)

        response = util_load_json("test_data/no_resources_response.json")
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=json.dumps(response))

        events, next_run, timestamp_field = fetch_events_command(client, REPORT_ID, max_fetch=100, last_run={})

        assert len(events) == 0
        assert timestamp_field == ""

    def test_fetch_events_stops_at_max_fetch_mid_batch(self, client, requests_mock, monkeypatch):
        """
        Given:
            - max_fetch=15 and batch returns 10 events in first call
            - Second batch would exceed max_fetch
        When:
            - Calling fetch_events_command
        Then:
            - Ensure only 5 events are requested in second batch
            - Ensure total events equals max_fetch exactly
            - Ensure loop stops after reaching max_fetch
        """
        import IBMSecurityGuardium

        monkeypatch.setattr(IBMSecurityGuardium, "MAX_BATCH_SIZE", 10)

        call_count = 0

        def mock_response(request, context):
            nonlocal call_count
            call_count += 1
            payload = request.json()
            offset = payload["offset"]
            fetch_size = payload["fetch_size"]

            if offset == 0:
                assert fetch_size == 10
                return json.dumps(util_create_batch_response(10, batch_num=1))
            elif offset == 10:
                # Should request only 5 (remaining to reach 15)
                assert fetch_size == 5
                return json.dumps(util_create_batch_response(5, batch_num=2))
            else:
                context.status_code = 400
                return json.dumps({"error": "Should not make third API call"})

        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=mock_response)

        events, next_run, timestamp_field = fetch_events_command(client, REPORT_ID, max_fetch=15, last_run={})

        assert len(events) == 15
        assert call_count == 2

    def test_fetch_events_field_mapping_extracted_once(self, client, requests_mock, monkeypatch):
        """
        Given:
            - Multiple batches of events
        When:
            - Calling fetch_events_command
        Then:
            - Ensure field mapping is extracted only from the first batch (offset == 0)
            - Ensure timestamp field is determined only from the first batch
        """
        import IBMSecurityGuardium

        monkeypatch.setattr(IBMSecurityGuardium, "MAX_BATCH_SIZE", 10)

        call_count = 0

        def mock_response(request, context):
            nonlocal call_count
            call_count += 1
            payload = request.json()
            offset = payload["offset"]

            # Both batches use the same structure from sample_api_response
            # First batch: full batch_size
            if offset == 0:
                return json.dumps(util_create_batch_response(10, batch_num=1))
            # Second batch: partial (triggers stop)
            else:
                return json.dumps(util_create_batch_response(3, batch_num=2))

        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=mock_response)

        events, next_run, timestamp_field = fetch_events_command(client, REPORT_ID, max_fetch=50, last_run={})

        # Verify events are properly mapped
        assert len(events) == 13  # 10 + 3
        assert "Session Start Time" in events[0]
        assert "Client IP" in events[0]
        assert timestamp_field == "Session Start Time"


class TestGetEventsCommand:
    """Tests for get_events_command function"""

    def test_get_events_command_no_events(self, client, requests_mock):
        """
        Given:
            - API response with no events
        When:
            - Calling get_events_command
        Then:
            - Ensure empty events list and timestamp_field is None
        """
        response = util_load_json("test_data/no_resources_response.json")
        response_text = json.dumps(response)
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=response_text)

        events, results, timestamp_field = get_events_command(client, REPORT_ID, {})

        assert len(events) == 0
        assert timestamp_field is None

    def test_get_events_command_invalid_time_format(self, client):
        """
        Given:
            - Invalid time format in arguments
        When:
            - Calling get_events_command
        Then:
            - Ensure DemistoException is raised
        """
        args = {"start_time": "invalid-date"}
        with pytest.raises(DemistoException, match="Invalid start_time format"):
            get_events_command(client, REPORT_ID, args)
