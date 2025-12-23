import pytest
from IBMSecurityGuardium import (
    Client,
    extract_field_mapping,
    find_timestamp_field,
    get_event_hash,
    map_event,
    deduplicate_events,
    build_ignore_list,
    fetch_events,
    get_events_command,
    test_module,
    DATE_FORMAT,
)
from CommonServerPython import DemistoException, util_load_json

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

    def test_extract_field_mapping_fallback_to_header_name(self):
        """
        Given:
            - API response with report headers missing nls_value
        When:
            - Calling extract_field_mapping
        Then:
            - Ensure field mapping falls back to header_name
        """
        response = {
            "result": {
                "report_layout": {
                    "report_headers": [
                        {"sequence": 1, "header_name": "ClientIP", "field_name": {}},
                        {"sequence": 2, "header_name": "DBUserName"},
                    ]
                }
            }
        }
        result = extract_field_mapping(response)
        assert result == {"1": "ClientIP", "2": "DBUserName"}

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
            ({"time": "16:52:57", "count": 5}, "time"),
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
        assert len(result) == 2
        assert event1 not in result
        assert event2 in result
        assert event3 in result

    def test_deduplicate_events_optimization(self):
        """
        Given:
            - Events where first event timestamp is greater than last_fetch_time
        When:
            - Calling deduplicate_events
        Then:
            - Ensure all events are added without duplicate checking
        """
        events = [
            {"timestamp": "2025-01-01 11:00:00", "id": "1"},
            {"timestamp": "2025-01-01 12:00:00", "id": "2"},
        ]
        last_run = {"last_fetch_time": "2025-01-01 10:00:00", "fetched_event_hashes": ["hash1", "hash2"]}
        result = deduplicate_events(events, last_run, "timestamp")
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
            - Calling test_module
        Then:
            - Ensure 'ok' is returned when API call succeeds
        """
        response = util_load_json("test_data/no_resources_response.json")
        import json
        response_text = json.dumps(response)
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=response_text)
        result = test_module(client, REPORT_ID)
        assert result == "ok"

    def test_test_module_auth_error(self, client, requests_mock):
        """
        Given:
            - Invalid credentials
        When:
            - Calling test_module
        Then:
            - Ensure authorization error message is returned
        """
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", status_code=403, text="Forbidden")
        result = test_module(client, REPORT_ID)
        assert "Authorization Error" in result


class TestFetchEvents:
    """Tests for fetch_events function"""

    def test_fetch_events_first_run(self, client, requests_mock):
        """
        Given:
            - Empty last_run (first fetch)
        When:
            - Calling fetch_events
        Then:
            - Ensure events are fetched and next_run is set correctly
        """
        import json
        response = util_load_json("test_data/sample_api_response.json")
        response_text = json.dumps(response)
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=response_text)
        
        events, next_run, timestamp_field = fetch_events(client, REPORT_ID, max_fetch=10, last_run={})
        
        assert len(events) == 1
        assert "Session Start Time" in events[0]
        assert timestamp_field == "Session Start Time"
        assert "last_fetch_time" in next_run
        assert "fetched_event_hashes" in next_run

    def test_fetch_events_no_events(self, client, requests_mock):
        """
        Given:
            - API response with no events
        When:
            - Calling fetch_events
        Then:
            - Ensure empty events list and unchanged last_run
        """
        import json
        response = util_load_json("test_data/no_resources_response.json")
        response_text = json.dumps(response)
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=response_text)
        
        last_run = {"last_fetch_time": "2025-06-07T15:00:00.000Z"}
        events, next_run, timestamp_field = fetch_events(client, REPORT_ID, max_fetch=10, last_run=last_run)
        
        assert len(events) == 0
        assert next_run == last_run


class TestGetEventsCommand:
    """Tests for get_events_command function"""

    def test_get_events_command_default_params(self, client, requests_mock):
        """
        Given:
            - No time range specified
        When:
            - Calling get_events_command
        Then:
            - Ensure events are fetched with default 1-hour range
        """
        import json
        response = util_load_json("test_data/sample_api_response.json")
        response_text = json.dumps(response)
        requests_mock.post(f"{BASE_URL}/api/v3/reports/run", text=response_text)
        
        events, results, timestamp_field = get_events_command(client, REPORT_ID, {})
        
        assert len(events) == 1
        assert timestamp_field == "Session Start Time"
        assert results.readable_output is not None

    def test_get_events_command_no_events(self, client, requests_mock):
        """
        Given:
            - API response with no events
        When:
            - Calling get_events_command
        Then:
            - Ensure empty events list and timestamp_field is None
        """
        import json
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
