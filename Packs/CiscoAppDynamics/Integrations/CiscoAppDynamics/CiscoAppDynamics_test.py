import pytest
import demistomock as demisto
from datetime import datetime, timezone, timedelta
import CiscoAppDynamics as appdynamics
from CiscoAppDynamics import (
    add_fields_to_events,
    get_events,
    parse_iso_millis_z,
    timestamp_ms_to_iso,
    get_last_run,
    set_event_type_fetch_limit,
    fetch_events,
    AUDIT,
    HEALTH_EVENT,
    EVENT_TYPE,
    DATE_FORMAT,
    HEALTH_RULE_API_LIMIT,
    Client,
)


# Fixture for a Client instance used in multiple tests
@pytest.fixture
def client():
    return Client(base_url="", client_id="id", client_secret="secret", verify=True, proxy=False)


# Dummy client used for test_module_command and get_events
class DummyClient:
    def __init__(self, num_of_audit: int = 1, num_of_health: int = 1) -> None:
        self.audit = [{"_time": f"{i + 1620000000000}"} for i in range(num_of_audit)]
        self.health = [{"_time": f"{i + num_of_audit + 1620000000000}"} for i in range(num_of_health)]

    def get_audit_logs(self, *args, **kwargs):
        return self.audit

    def get_health_events(self, *args, **kwargs):
        return self.health


# --- Helper Functions --------------------------------------------------
@pytest.mark.parametrize("event_type_name", [("Audit"), ("Healthrule Violations Events")])
def test_add_fields_to_events_basic(event_type_name):
    """
    Given:
        - A list of events with epoch-ms timestamps and an EventType.
    When:
        - Calling add_fields_to_events.
    Then:
        - Each event has a '_time' ISO string and 'SOURCE_LOG_TYPE', and order is chronological.
    """
    event_type = EVENT_TYPE[event_type_name]
    events = [{event_type.time_field: "1620000000123"}]
    result = add_fields_to_events(events.copy(), event_type)
    assert "_time" in result[0]
    assert "SOURCE_LOG_TYPE" in result[0]
    assert result[0]["SOURCE_LOG_TYPE"] == event_type.source_log_type
    assert result[0]["_time"] == timestamp_ms_to_iso("1620000000123")


def test_get_events_command_results(mocker):
    """
    Given:
        - Client and demisto.params patched for both events.
    When:
        - Calling get_events.
    Then:
        - Returns a CommandResults object with readable_output and raw_response attributes.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "events_type_to_fetch": AUDIT.name,
            "start_date": "2025-05-25T10:00:00.000Z",
            "end_date": "2025-05-25T11:00:00.000Z",
            "limit": "1",
            "is_fetch_events": "false",
        },
    )
    client = DummyClient()
    res = get_events(client, {})  # type: ignore
    assert hasattr(res, "readable_output")
    assert isinstance(res.raw_response, list)
    assert "_time" in res.readable_output


def test_timestamp_ms_to_iso_exact():
    """
    When:
        - Calling timestamp_ms_to_iso.
    Then:
        - Formatting as wanted.
    """
    # pick a known epoch
    epoch_ms = 1600000000123
    iso = timestamp_ms_to_iso(str(epoch_ms))
    assert iso.startswith("2020-09-13T12:26:40.")  # rough check
    assert iso.endswith("Z")


def test_parse_iso_millis_z_roundtrip():
    """
    Given:
        - An ISO-8601 string with Z suffix.
    When:
        - Parsing to datetime and converting back via timestamp_ms_to_iso.
    Then:
        - The output equals the original string.
    """
    s = "2025-05-25T16:07:53.127Z"
    dt = parse_iso_millis_z(s)
    assert dt.tzinfo == timezone.utc  # noqa: UP017
    s2 = timestamp_ms_to_iso(str(int(dt.timestamp() * 1000)))
    assert s2 == s


def test_timestamp_ms_to_iso_format():
    """
    Given:
        - A known epoch milliseconds string.
    When:
        - Converting to ISO format.
    Then:
        - The result matches the expected ISO-8601 string with millisecond precision.
    """
    epoch_ms = 1600000000123
    iso = timestamp_ms_to_iso(str(epoch_ms))
    dt = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)  # noqa: UP017
    expected = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    assert iso == expected


@pytest.mark.parametrize(
    "last_run, requested, expected_output",
    [
        # full last_run, both requested
        (
            {AUDIT.name: "2025-05-25T11:00:00.000Z", HEALTH_EVENT.name: "2025-05-25T10:00:00.000Z"},
            [AUDIT, HEALTH_EVENT],
            {
                AUDIT.name: datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc),  # noqa: UP017
                HEALTH_EVENT.name: datetime(2025, 5, 25, 10, 0, 0, tzinfo=timezone.utc),  # noqa: UP017
            },
        ),
        # empty last_run, both requested
        (
            {},
            [AUDIT, HEALTH_EVENT],
            {
                AUDIT.name: datetime(2025, 5, 25, 10, 59, 0, tzinfo=timezone.utc),  # noqa: UP017
                HEALTH_EVENT.name: datetime(2025, 5, 25, 10, 59, 0, tzinfo=timezone.utc),  # noqa: UP017
            },
        ),
        # only AUDIT present, both requested
        (
            {AUDIT.name: "2025-05-25T11:00:00.000Z"},
            [AUDIT, HEALTH_EVENT],
            {
                AUDIT.name: datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc),  # noqa: UP017
                HEALTH_EVENT.name: datetime(2025, 5, 25, 10, 59, 0, tzinfo=timezone.utc),  # noqa: UP017
            },
        ),
        # both present, only AUDIT requested
        (
            {AUDIT.name: "2025-05-25T11:00:00.000Z", HEALTH_EVENT.name: "2025-05-25T11:00:00.000Z"},
            [AUDIT],
            {
                AUDIT.name: datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc),  # noqa: UP017
                HEALTH_EVENT.name: datetime(2025, 5, 25, 10, 59, 0, tzinfo=timezone.utc),  # noqa: UP017
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
    now = datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
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


# --- client.get functions ------------------------------------------------


def test_get_audit_logs_adds_fields_and_sorts(client, mocker):
    """
    Given:
         - A Client whose _authorized_request returns 100 shuffled audit events with distinct timeStamp values.
    When:
        - Calling get_audit_logs.
    Then:
        - Each event has '_time' and 'SOURCE_LOG_TYPE', and events are sorted by '_time' ascending.
    """
    import random

    timestamps = list(range(100))
    random.shuffle(timestamps)
    events = [{"timeStamp": str(ts)} for ts in timestamps]
    mocker.patch.object(client, "_authorized_request", return_value=events)

    now = datetime(2025, 5, 25, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    start = now - timedelta(minutes=10)
    result = client.get_audit_logs(start, now)

    assert len(result) == 100
    times = [ev["_time"] for ev in result]
    assert times == sorted(times)
    assert all(event["SOURCE_LOG_TYPE"] == AUDIT.source_log_type for event in result)


def test_get_audit_logs_over_24h_adjustment(client, mocker):
    """
    Given:
        - A Client and a start_time more than 24 hours before end_time.
    When:
        - Calling get_audit_logs.
    Then:
        - _authorized_request is called with startTime adjusted to endTime minus 24 hours and returns empty list.
    """
    end = datetime(2025, 5, 25, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    start = end - timedelta(days=2)
    captured = {}

    def fake_request(url_suffix, params, **kwargs):
        captured["params"] = params.copy()
        return []

    mocker.patch.object(client, "_authorized_request", side_effect=fake_request)

    result = client.get_audit_logs(start, end)
    assert result == []
    expected_start = (end - timedelta(hours=24)).strftime(DATE_FORMAT)[:-3] + "Z"
    assert captured["params"]["startTime"] == expected_start


def test_get_audit_logs_start_after_end_returns_empty(client, mocker):
    """
    Given:
        - A Client and a start_time equal to end_time.
    When:
        - Calling get_audit_logs.
    Then:
        - Returns empty list and does not call _authorized_request.
    """
    now = datetime(2025, 5, 25, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    mocker.patch.object(client, "_authorized_request", return_value=[])

    result = client.get_audit_logs(now, now)
    assert result == []
    client._authorized_request.assert_not_called()


# --- Edge cases for get_health_events ------------------------------------------------


def test_get_health_events_no_events(client, mocker):
    """
    Given:
        - _authorized_request returns empty list on first call.
    When:
        - Calling get_health_events.
    Then:
        - Returns empty list without looping infinitely.
    """
    mocker.patch.object(client, "_authorized_request", return_value=[])
    start = datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    end = datetime(2025, 5, 25, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    result = client.get_health_events(start, end)
    assert result == []


def test_get_health_events_single_batch_less_than_limit(client, mocker):
    """
    Given:
        - _authorized_request returns a batch smaller than HEALTH_RULE_API_LIMIT.
    When:
        - Calling get_health_events.
    Then:
        - Returns one batch of events.
    """
    # create small batch
    batch = [{HEALTH_EVENT.time_field: str(1000 + i)} for i in range(HEALTH_EVENT.max_fetch - 1)]
    calls = []

    def fake_request(url_suffix, params, **kwargs):
        calls.append(params.copy())
        return batch

    mocker.patch.object(client, "_authorized_request", side_effect=fake_request)
    start = datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    end = datetime(2025, 5, 25, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    result = client.get_health_events(start, end)
    assert result == batch
    # ensure only one API call
    assert len(calls) == 1


def test_get_health_events_multiple_batches_and_respect_api_limit(client, mocker):
    """
    Given:
        - First _authorized_request returns exactly HEALTH_RULE_API_LIMIT events, second returns smaller batch.
    When:
        - Calling get_health_events.
    Then:
        - Returns concatenated batches and stops after smaller batch.
    """
    default_limit = HEALTH_EVENT.max_fetch
    HEALTH_EVENT.max_fetch = 1000

    limit = HEALTH_RULE_API_LIMIT
    batch1 = [{HEALTH_EVENT.time_field: str(2000 + i)} for i in range(limit)]
    batch2 = [{HEALTH_EVENT.time_field: str(3000 + i)} for i in range(10)]
    seq = [batch1, batch2, []]

    def fake_request(url_suffix, params, **kwargs):
        return seq.pop(0)

    mocker.patch.object(client, "_authorized_request", side_effect=fake_request)
    start = datetime(2025, 5, 25, 10, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    end = datetime(2025, 5, 25, 11, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    result = client.get_health_events(start, end)
    # result length should be len(batch1) + len(batch2)
    assert len(result) == limit + 10
    # first event time matches batch1, last matches batch2
    assert result[0][HEALTH_EVENT.time_field] == batch1[0][HEALTH_EVENT.time_field]
    assert result[-1][HEALTH_EVENT.time_field] == batch2[-1][HEALTH_EVENT.time_field]

    HEALTH_EVENT.max_fetch = default_limit


def test_get_health_events_respects_max_fetch(client, mocker):
    """
    Given:
        - Max_healthrule_fetch smaller than number of events returned per batch.
    When:
        - Calling get_health_events.
    Then:
        - Loop stops when len(events) exceeds max_healthrule_fetch.
    """
    # override client's max to small value
    default_max_fetch = HEALTH_EVENT.max_fetch
    HEALTH_EVENT.max_fetch = 5
    # create a large batch
    batch = [{HEALTH_EVENT.time_field: str(4000 + i)} for i in range(10)]
    mocker.patch.object(client, "_authorized_request", return_value=batch)
    start = datetime(2025, 5, 25, 9, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    end = datetime(2025, 5, 25, 10, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    result = client.get_health_events(start, end)
    # since first call returns 10 and max is 5, loop condition allows one call then stops
    # but method does not truncate events; it returns full batch
    assert result == batch

    HEALTH_EVENT.max_fetch = default_max_fetch


# --- Tests for fetch_events function -----------------------------------------------------------------


def test_fetch_events_no_types(mocker):
    """
    Given:
        - No event types to fetch.
    When:
        - Calling fetch_events.
    Then:
        - Returns empty events list and empty last_run dict.
    """
    client = DummyClient()
    mocker.patch.object(appdynamics, "get_last_run", return_value={})
    fixed_now = datetime(2025, 5, 26, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    DummyDateTime = type("DummyDateTime", (), {"now": classmethod(lambda cls, tz=None: fixed_now)})
    mocker.patch.object(appdynamics, "datetime", DummyDateTime)

    events, next_run = fetch_events(client, [])
    assert events == []
    assert next_run == {}


def test_fetch_events_audit(mocker):
    """
    Given:
        - No event types to fetch.
    When:
        - Calling fetch_events.
    Then:
        - Returns empty events list and empty last_run dict.
    """
    client = DummyClient(num_of_audit=10, num_of_health=10)
    mocker.patch.object(appdynamics, "get_last_run", return_value={AUDIT.name: "", HEALTH_EVENT.name: ""})
    events, next_run = appdynamics.fetch_events(client, [AUDIT])
    assert len(events) == 1
    assert events == [{"_time": "1620000000000"}]
    assert next_run[AUDIT.name] == "1620000000000"


def test_fetch_events_no_events_update_last_run(mocker):
    """
    Given:
        - One event type that returns no events.
    When:
        - Calling fetch_events.
    Then:
        - Returns empty events, last_run for that type is now formatted.
    """
    client = DummyClient()
    last_dt = datetime(2025, 5, 26, 11, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    mocker.patch.object(appdynamics, "get_last_run", return_value={AUDIT.name: last_dt})
    fixed_now = datetime(2025, 5, 26, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    DummyDateTime = type("DummyDateTime", (), {"now": classmethod(lambda cls, tz=None: fixed_now)})
    mocker.patch.object(appdynamics, "datetime", DummyDateTime)
    mocker.patch.object(client, "get_audit_logs", return_value=[])

    events, next_run = fetch_events(client, [AUDIT])
    assert events == []
    expected_ts = fixed_now.strftime(DATE_FORMAT)[:-3] + "Z"
    assert next_run[AUDIT.name] == expected_ts


def test_fetch_events_respects_max_fetch(mocker):
    """
    Given:
        - One event type with max_fetch < returned batch size.
    When:
        - Calling fetch_events.
    Then:
        - Returns only up to max_fetch events and last_run is last returned.
    """
    client = DummyClient()
    start_dt = datetime(2025, 5, 26, 11, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    mocker.patch.object(appdynamics, "get_last_run", return_value={AUDIT.name: start_dt})
    fixed_now = datetime(2025, 5, 26, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    DummyDateTime = type("DummyDateTime", (), {"now": classmethod(lambda cls, tz=None: fixed_now)})
    mocker.patch.object(appdynamics, "datetime", DummyDateTime)
    # prepare events larger than max_fetch
    full_events = [{"_time": f"2025-05-26T11:0{i}:00.000Z"} for i in range(5)]
    default_limit = AUDIT.max_fetch
    AUDIT.max_fetch = 2
    mocker.patch.object(client, "get_audit_logs", return_value=full_events)

    events, next_run = fetch_events(client, [AUDIT])
    assert len(events) == 2
    assert events == full_events[:2]
    assert next_run[AUDIT.name] == full_events[1]["_time"]
    AUDIT.max_fetch = default_limit


def test_fetch_events_multiple_types(mocker):
    """
    Given:
        - Both event types each returning several events.
    When:
        - Calling fetch_events.
    Then:
        - Returns combined events in order of types and correct last_run for each type.
    """
    default_limit_audit = AUDIT.max_fetch
    default_limit_health = HEALTH_EVENT.max_fetch
    AUDIT.max_fetch = 3
    HEALTH_EVENT.max_fetch = 3
    # DummyClient returning list per init counts
    client = DummyClient(num_of_audit=5, num_of_health=4)
    # get_last_run returns empty strings (treated as initial)
    mocker.patch.object(appdynamics, "get_last_run", return_value={AUDIT.name: "", HEALTH_EVENT.name: ""})
    now_dt = datetime(2025, 5, 26, 12, 0, 0, tzinfo=timezone.utc)  # noqa: UP017
    DummyDateTime = type("DummyDateTime", (), {"now": classmethod(lambda cls, tz=None: now_dt)})
    mocker.patch.object(appdynamics, "datetime", DummyDateTime)
    events, next_run = fetch_events(client, [AUDIT, HEALTH_EVENT])
    # Expect 3 audit + 2 health events
    assert len(events) == 6
    # Check ordering: first audit then health
    assert events[0]["_time"] == "1620000000000"
    assert events[4]["_time"] == "1620000000006"
    # last_run set to last event of each
    assert next_run[AUDIT.name] == "1620000000002"
    assert next_run[HEALTH_EVENT.name] == "1620000000007"

    AUDIT.max_fetch = default_limit_audit
    HEALTH_EVENT.max_fetch = default_limit_health
