import pytest
import json
import demistomock as demisto
from datetime import datetime, timezone
import CiscoAppDynamicsEventCollector as appdynamics
from CommonServerPython import timestamp_to_datestring
from CiscoAppDynamicsEventCollector import (
    add_fields_to_events,
    get_events,
    get_last_run,
    set_event_type_fetch_limit,
    fetch_events,
    datetime_to_api_format,
    timestamp_to_api_format,
    AUDIT,
    HEALTH_EVENT,
    EVENT_TYPES,
    DATE_FORMAT,
    Client,
    VENDOR,
    PRODUCT,
)


# Fixture for a Client instance used in multiple tests
@pytest.fixture
def client():
    return Client(base_url="", client_id="id", client_secret="secret", application_id="52", verify=True, proxy=False)


def util_load_json(name: str):
    with open(f"test_data/{name}.json", encoding="utf-8") as f:
        return json.loads(f.read())


# Dummy client used for test_module_command and get_events
class DummyClient:
    def __init__(self, num_of_audit: int = 1, num_of_health: int = 1) -> None:
        self.audit = [
            {
                AUDIT.time_field: i + 1620000000000,
                "_time": timestamp_to_datestring(i + 1620000000000, DATE_FORMAT),
            }
            for i in range(num_of_audit)
        ]

        self.health = [
            {
                HEALTH_EVENT.time_field: i + num_of_audit + 1620000000000,
                "_time": timestamp_to_datestring(i + num_of_audit + 1620000000000, DATE_FORMAT),
            }
            for i in range(num_of_health)
        ]

    def get_audit_logs(self, *args, **kwargs):
        return self.audit

    def get_health_events(self, *args, **kwargs):
        return self.health


# --- Helper Functions --------------------------------------------------
@pytest.mark.parametrize(
    "event_type_name",
    [
        (AUDIT.name),
        (HEALTH_EVENT.name),
    ],
)
def test_add_fields_to_events_basic(event_type_name):
    """
    Given:
        - Event returned from API.
    When:
        - Calling add_fields_to_events on the event.
    Then:
        - The event has a '_time' ISO string and 'SOURCE_LOG_TYPE'.
    """
    event_type = EVENT_TYPES[event_type_name]
    events = [
        {event_type.time_field: 1620000000000},
    ]
    result = add_fields_to_events(events.copy(), event_type)
    assert "_time" in result[0]
    assert "SOURCE_LOG_TYPE" in result[0]
    assert result[0]["SOURCE_LOG_TYPE"] == event_type.source_log_type
    assert result[0]["_time"] == "2021-05-03T00:00:00.000000Z"


@pytest.mark.parametrize(
    "last_run, requested, expected_output",
    [
        # Full last_run, both requested
        (
            {AUDIT.name: 1748100800000, HEALTH_EVENT.name: 1748167200000},
            [AUDIT, HEALTH_EVENT],
            {
                AUDIT.name: 1748100800000,
                HEALTH_EVENT.name: 1748167200000,
            },
        ),
        # Empty last_run, both requested
        (
            {},
            [AUDIT, HEALTH_EVENT],
            {
                AUDIT.name: 1748170800000 - (60 * 1000),
                HEALTH_EVENT.name: 1748170800000 - (60 * 1000),
            },
        ),
        # Only AUDIT present, both requested
        (
            {AUDIT.name: 1748160800000},
            [AUDIT, HEALTH_EVENT],
            {
                AUDIT.name: 1748160800000,
                HEALTH_EVENT.name: 1748170800000 - (60 * 1000),
            },
        ),
        # Both present, only AUDIT requested
        (
            {AUDIT.name: 1748170800000, HEALTH_EVENT.name: 1748170800000},
            [AUDIT],
            {
                AUDIT.name: 1748170800000,
                HEALTH_EVENT.name: 1748170800000 - (60 * 1000),
            },
        ),
    ],
)
def test_get_last_run_various(mocker, last_run, requested, expected_output):
    """
    Given:
        - Demisto.getLastRun returns raw dict and a fixed 'now'.
    When:
        - Calling get_last_run with requested types.
    Then:
        - Parsed datetimes for present types and backoff for missing types.
    """
    now = 1748170800000
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    out = get_last_run(now, requested)
    for event_type in [AUDIT, HEALTH_EVENT]:
        assert out[event_type.name] == expected_output[event_type.name]


def test_set_event_type_fetch_limit_all_and_restore(mocker):
    """
    Given:
        - Integration params requesting both types with custom limits.
    When:
        - Calling set_event_type_fetch_limit.
    Then:
        - Returns both EventTypes with updated max_fetch and updated URL suffix.
    """
    orig_audit_max = AUDIT.max_fetch
    orig_health_max = HEALTH_EVENT.max_fetch
    orig_health_url = HEALTH_EVENT.url_suffix

    params = {
        "event_types_to_fetch": f"{AUDIT.name},{HEALTH_EVENT.name}",
        "max_audit_fetch": "5",
        "max_healthrule_fetch": "7",
        "application_id": "42",
    }
    out = set_event_type_fetch_limit(params)
    names = [et.name for et in out]
    assert AUDIT.name in names
    assert HEALTH_EVENT.name in names
    assert AUDIT.max_fetch == 5
    assert HEALTH_EVENT.max_fetch == 7
    assert "applications/42" in HEALTH_EVENT.url_suffix

    AUDIT.max_fetch = orig_audit_max
    HEALTH_EVENT.max_fetch = orig_health_max
    HEALTH_EVENT.url_suffix = orig_health_url


def test_timestamp_to_api_format_audit():
    """
    Given:
        - A timestamp in milliseconds and event type AUDIT.
    When:
        - Calling timestamp_to_api_format.
    Then:
        - Returns a correctly formatted ISO8601 string with milliseconds and timezone offset '-0000'.
    """
    ts = 1718018400000
    expected = "2024-06-10T11:20:00.000-0000"
    result = timestamp_to_api_format(ts, AUDIT)
    assert result == expected


def test_timestamp_to_api_format_health_event():
    """
    Given:
        - A timestamp in milliseconds and event type HEALTH_EVENT.
    When:
        - Calling timestamp_to_api_format.
    Then:
        - Returns the timestamp as-is (int).
    """
    ts = 1718018400000
    result = timestamp_to_api_format(ts, HEALTH_EVENT)
    assert result == ts


def test_datetime_to_api_format_audit():
    """
    Given:
        - A datetime object and event type AUDIT.
    When:
        - Calling datetime_to_api_format.
    Then:
        - Returns the correctly formatted ISO8601 string with milliseconds and timezone offset '-0000'.
    """
    dt = datetime(2024, 6, 10, 12, 0, 0, 123000, tzinfo=timezone.utc)  # noqa: UP017
    expected = "2024-06-10T12:00:00.123-0000"
    result = datetime_to_api_format(dt, AUDIT)
    assert result == expected


def test_datetime_to_api_format_health_event():
    """
    Given:
        - A datetime object and event type HEALTH_EVENT.
    When:
        - Calling datetime_to_api_format.
    Then:
        - Returns the equivalent timestamp in milliseconds.
    """
    dt = datetime(2024, 6, 10, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    expected = 1718020800000
    result = datetime_to_api_format(dt, HEALTH_EVENT)
    assert result == expected


# --- get command tests ----------------------------------------------
def test_get_events_command_results(mocker):
    """
    Given:
        - Client and demisto.params patched for Audit event.
        - is_fetch_events is True.
    When:
        - Calling get_events.
    Then:
        - Send the right events to XSIAM.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "events_type_to_fetch": AUDIT.name,
            "start_date": "2025-05-25T10:00:00.000Z",
            "end_date": "2025-05-25T11:00:00.000Z",
            "limit": "1",
            "is_fetch_events": True,
        },
    )
    mock_send = mocker.patch.object(appdynamics, "send_events_to_xsiam", return_value="")
    client = DummyClient(num_of_audit=1, num_of_health=0)

    get_events(client, demisto.args(), demisto.params())

    mock_send.assert_called_once_with(
        vendor=VENDOR,
        product=PRODUCT,
        events=[{AUDIT.time_field: 1620000000000, "_time": timestamp_to_datestring(1620000000000, DATE_FORMAT)}],
    )


# --- fetch_events ------------------------------------------------
class TestRealResponse:
    raw_data_health = util_load_json("health_response")
    raw_data_audit = util_load_json("audit_response")
    n_health = len(raw_data_health)
    n_audit = len(raw_data_audit)

    def test_get_audit_logs_adds_fields(self, client, mocker):
        """
        Given:
            - The server return n_health events from the API.
        When:
            - Calling get_audit_logs.
        Then:
            - Each event has '_time' and 'SOURCE_LOG_TYPE'.
        """
        from CiscoAppDynamicsEventCollector import timestamp_to_api_format

        mocker.patch.object(client, "authorized_request", return_value=self.raw_data_audit)

        end = 1748170800000
        start = 1748170800000 - (60 * 10 * 1000)
        result = client.get_audit_logs(timestamp_to_api_format(start, AUDIT), timestamp_to_api_format(end, AUDIT))

        assert len(result) == self.n_audit
        times = [ev["_time"] for ev in result]
        assert times == sorted(times)
        assert all(event["SOURCE_LOG_TYPE"] == AUDIT.source_log_type for event in result)

    def test_fetch_events_respects_max_fetch(self, mocker):
        """
        Given:
            - One event type with max_fetch < returned batch size.
        When:
            - Calling fetch_events.
        Then:
            - Returns only up to max_fetch events and last_run is last returned.
        """
        client = DummyClient()
        mocker.patch.object(appdynamics, "get_last_run", return_value={AUDIT.name: 1})
        DummyDateTime = type("DummyDateTime", (), {"time": classmethod(lambda cls, tz=None: 1)})
        mocker.patch.object(appdynamics, "time", DummyDateTime)

        default_limit = AUDIT.max_fetch
        AUDIT.max_fetch = 2
        mocker.patch.object(client, "get_audit_logs", return_value=self.raw_data_audit)

        events, next_run = fetch_events(client, [AUDIT])
        assert len(events) == 2
        assert events == self.raw_data_audit[:2]
        assert next_run[AUDIT.name] == self.raw_data_audit[1][AUDIT.time_field] + 1
        AUDIT.max_fetch = default_limit

    def test_get_health_events_no_events(self, client, mocker):
        """
        Given:
            - authorized_request returns empty list on first call.
        When:
            - Calling get_health_events.
        Then:
            - Returns empty list without looping infinitely.
        """
        mocker.patch.object(client, "authorized_request", return_value=[])
        start = datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
        end = datetime(2025, 5, 25, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
        result = client.get_health_events(start, end)
        assert result == []

    def test_get_health_events_single_batch_less_than_limit(self, client, mocker):
        """
        Given:
            - authorized_request returns a batch smaller than HEALTH_EVENT.api_limit.
        When:
            - Calling get_health_events.
        Then:
            - Returns one batch of events.
        """
        # create small batch
        default_health_rule_api_limit = HEALTH_EVENT.api_limit
        batch = self.raw_data_health
        HEALTH_EVENT.api_limit = len(batch) + 1
        calls = []

        def fake_request(url_suffix, params, **kwargs):
            calls.append(params.copy())
            if len(calls) == 1:
                return batch
            return []

        mocker.patch.object(client, "authorized_request", side_effect=fake_request)
        start = datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
        end = datetime(2025, 5, 25, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
        result = client.get_health_events(start, end)
        assert result == batch
        # ensure only one API call
        assert len(calls) == 1

        HEALTH_EVENT.api_limit = default_health_rule_api_limit

    def test_get_health_events_multiple_batches_and_respect_api_limit(self, client, mocker):
        """
        Given:
            - First authorized_request returns exactly HEALTH_EVENT.api_limit events, second returns smaller batch.
        When:
            - Calling get_health_events.
        Then:
            - Returns concatenated batches and stops after smaller batch.
        """
        default_max_fetch = HEALTH_EVENT.max_fetch
        default_api_limit = HEALTH_EVENT.api_limit

        HEALTH_EVENT.max_fetch = self.n_health + 1
        HEALTH_EVENT.api_limit = self.n_health // 2

        batch1 = self.raw_data_health[: self.n_health // 2]
        batch2 = self.raw_data_health[self.n_health // 2 :]
        seq = [batch1, batch2, []]

        def fake_request(url_suffix, params, **kwargs):
            return seq.pop(0)

        mocker.patch.object(client, "authorized_request", side_effect=fake_request)
        start = datetime(2025, 5, 25, 10, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
        end = datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
        result = client.get_health_events(start, end)
        # result length should be len(batch1) + len(batch2)
        assert len(result) == self.n_health
        # first event time matches batch1, last matches batch2
        assert result[0][HEALTH_EVENT.time_field] == batch1[0][HEALTH_EVENT.time_field]
        assert result[-1][HEALTH_EVENT.time_field] == batch2[-1][HEALTH_EVENT.time_field]

        HEALTH_EVENT.max_fetch = default_max_fetch
        HEALTH_EVENT.api_limit = default_api_limit

    def test_get_health_events_respects_max_fetch(self, client, mocker):
        """
        Given:
            - HEALTH_EVENT.max_fetch smaller than number of events returned per batch.
        When:
            - Calling get_health_events.
        Then:
            - Loop stops when len(events) exceeds max_healthrule_fetch.
        """
        # override client's max to small value
        default_max_fetch = HEALTH_EVENT.max_fetch
        HEALTH_EVENT.max_fetch = 5
        # create a large batch
        mocker.patch.object(client, "authorized_request", return_value=self.raw_data_health)
        start = datetime(2025, 5, 25, 9, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
        end = datetime(2025, 5, 25, 10, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
        result = client.get_health_events(start, end)
        # since first call returns 10 and max is 5, loop condition allows one call then stops
        # but method does not truncate events; it returns full batch
        assert result == self.raw_data_health

        HEALTH_EVENT.max_fetch = default_max_fetch

    def test_fetch_events_multiple_types(self, client, mocker):
        """
        Given:
            - Both event types each returning several events.
        When:
            - Calling fetch_events.
        Then:
            - Returns combined events in order of types and correct last_run for each type.
        """

        def mock_authorized_request(url_suffix, params):
            if url_suffix == AUDIT.url_suffix:
                return self.raw_data_audit
            elif url_suffix == HEALTH_EVENT.url_suffix:
                return self.raw_data_health
            else:
                return []

        default_audit_max_fetch = AUDIT.max_fetch
        default_health_max_fetch = HEALTH_EVENT.max_fetch
        AUDIT.max_fetch = 3
        HEALTH_EVENT.max_fetch = 3

        mocker.patch.object(appdynamics, "get_last_run", return_value={AUDIT.name: 1, HEALTH_EVENT.name: 1})
        mocker.patch("time.time", return_value=1748250000)
        mocker.patch.object(client, "authorized_request", side_effect=mock_authorized_request)

        events, next_run = fetch_events(client, [AUDIT, HEALTH_EVENT])
        # Expect 3 audit + 3 health events
        assert len(events) == 6
        # Check ordering: first audit then health
        assert events[0]["_time"] == timestamp_to_datestring(self.raw_data_audit[0][AUDIT.time_field], DATE_FORMAT, is_utc=True)
        assert events[3]["_time"] == timestamp_to_datestring(
            self.raw_data_health[0][HEALTH_EVENT.time_field], DATE_FORMAT, is_utc=True
        )
        # last_run set to last event of each
        assert next_run[AUDIT.name] == int(self.raw_data_audit[2][AUDIT.time_field]) + 1
        assert next_run[HEALTH_EVENT.name] == int(self.raw_data_health[2][HEALTH_EVENT.time_field]) + 1

        AUDIT.max_fetch = default_audit_max_fetch
        HEALTH_EVENT.max_fetch = default_health_max_fetch


# --- Tests for fetch_events function -----------------------------------------------------------------
def test_fetch_events_no_types(mocker, client):
    """
    Given:
        - No event types to fetch.
    When:
        - Calling fetch_events.
    Then:
        - Returns empty events list and update last_run dict.
    """
    fixed_now = 1748250000
    mocker.patch("time.time", return_value=fixed_now)
    mocker.patch.object(client, "authorized_request", return_value=[])

    events, next_run = fetch_events(client, [AUDIT, HEALTH_EVENT])
    assert events == []
    assert next_run[AUDIT.name] == fixed_now * 1000 + 1
    assert next_run[HEALTH_EVENT.name] == fixed_now * 1000 + 1
