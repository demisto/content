import copy
import json
import re
from datetime import datetime, timedelta, UTC

import demistomock as demisto
import knowbe4Phisher as phisher
import pytest
from CommonServerPython import CommandResults
from freezegun import freeze_time
from test_data.mock_tests import (
    create_request_test,
    events_example,
    expected_fetch,
    expected_time,
    pagination_response,
    response_fetch,
)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


client = phisher.Client(
    base_url="https://eu.test.com/graphql",
    verify=False,
    headers={"Authorization": "Bearer  + key", "Content-Type": "application/json"},
    proxy=False,
    first_fetch_time="100 days",
)


@pytest.mark.parametrize("test_input, expected", create_request_test)
def test_create_request(test_input, expected):
    """
    Given:
    - A human readable query for GQL

    When:
    - Creating GQL request

    Then:
    - Ensure that query created as expected
    """
    res = phisher.create_gql_request(test_input)
    assert res == expected


calculate_events = [
    ('\\" reported_at:[2021-07-01T16:51:45Z TO *]\\"', "13", pagination_response[0]),
    ('\\" reported_at:[2021-07-01T16:51:45Z TO *]\\"', "31", pagination_response[1]),
]


@pytest.mark.parametrize("query, expected, return_value", calculate_events)
def test_caclulate_event(mocker, query, expected, return_value):
    """
    Given:
    - A result of api response from PhishER that contains number of messages

    When:
     - When calculating number of events before fetch

    Then:
     - Ensure that the number of messages is returned as expected
    """
    mocker.patch.object(client, "phisher_gql_request", return_value=return_value)
    result = phisher.calculate_number_of_events(client, query)
    assert result == expected
    assert "X-KB4-Integration" in client._headers
    assert client._headers["X-KB4-Integration"] == "Cortex XSOAR PhishER"


test_fetch = [
    ({"last_fetch": None}, "30 days", "50", expected_fetch[0], response_fetch[0]),
    ({"last_fetch": None}, "30 days", "50", expected_fetch[1], response_fetch[1]),
]


@pytest.mark.parametrize("last_run, first_fetch, max_fetch, expected, respon", test_fetch)
def test_fetch_incidents(mocker, last_run, first_fetch, max_fetch, expected, respon):
    """
    Given:
    - Phisher Integration Parameters

    When:
    - Fetching incidents.

    Then:
    - Ensure that the incidents returned are as expected.
    """
    mocker.patch.object(client, "phisher_gql_request", return_value=respon)
    _, result = phisher.fetch_incidents(client, last_run, first_fetch, max_fetch)
    assert result == expected


# --- Lookback / EIR-14074 tests ---

MSG_A = {
    "actionStatus": "RECEIVED",
    "category": "UNKNOWN",
    "comments": [],
    "events": [
        {"causer": "null", "createdAt": "2024-01-01T10:00:00Z", "eventType": "CREATED", "id": "evt-a1", "triggerer": "null"},
    ],
    "from": "a@example.com",
    "id": "msg-a",
    "phishmlReport": None,
    "pipelineStatus": "PROCESSED",
    "reportedAt": "2024-01-01T09:59:55Z",
    "severity": "UNKNOWN_SEVERITY",
    "subject": "Message A",
    "tags": [],
}

MSG_B = {
    "actionStatus": "RECEIVED",
    "category": "UNKNOWN",
    "comments": [],
    "events": [
        {"causer": "null", "createdAt": "2024-01-01T10:05:00Z", "eventType": "CREATED", "id": "evt-b1", "triggerer": "null"},
    ],
    "from": "b@example.com",
    "id": "msg-b",
    "phishmlReport": None,
    "pipelineStatus": "PROCESSED",
    "reportedAt": "2024-01-01T10:04:55Z",
    "severity": "UNKNOWN_SEVERITY",
    "subject": "Message B",
    "tags": [],
}


def _gql_response(messages):
    return {
        "data": {
            "phisherMessages": {"nodes": messages, "pagination": {"page": 1, "pages": 1, "per": 50, "totalCount": len(messages)}}
        }
    }


@freeze_time("2024-01-01T11:00:00Z")
def test_fetch_incidents_first_run(mocker):
    """
    Given:
    - No prior run (empty last_run), first_fetch of 7 days, 2 messages returned from API

    When:
    - fetch_incidents is called

    Then:
    - Both incidents are emitted, next_run has 'time' and 'found_incident_ids' containing both message ids
    """
    mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response([MSG_A, MSG_B]))
    next_run, incidents = phisher.fetch_incidents(client, {}, "7 days", 50)
    assert len(incidents) == 2
    assert "time" in next_run
    assert "found_incident_ids" in next_run
    assert "msg-a" in next_run["found_incident_ids"]
    assert "msg-b" in next_run["found_incident_ids"]


@freeze_time("2024-01-01T11:00:00Z")
def test_fetch_incidents_dedup_via_found_ids(mocker):
    """
    Given:
    - last_run contains msg-a in found_incident_ids, API returns both msg-a and msg-b

    When:
    - fetch_incidents is called

    Then:
    - Only msg-b is emitted (msg-a is deduped), found_incident_ids still includes msg-b
    """
    last_run = {"time": "2024-01-01T10:00:00Z", "found_incident_ids": {"msg-a": 1704067200}}
    mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response([MSG_A, MSG_B]))
    next_run, incidents = phisher.fetch_incidents(client, last_run, "7 days", 50)
    assert len(incidents) == 1
    assert incidents[0]["dbotMirrorId"] == "msg-b"
    assert "msg-b" in next_run["found_incident_ids"]


@freeze_time("2024-01-01T11:00:00Z")
def test_fetch_incidents_late_arrival_recovered(mocker):
    """
    Given:
    - last_run time is T-30min (10:30Z), look_back=60
    - API returns a message with created_at = 2024-01-01T10:05:00Z (T-55min, before last_run["time"])
    - That message is NOT in found_incident_ids

    When:
    - fetch_incidents is called with look_back=60

    Then:
    - The late-arriving message IS emitted (lookback expanded the start window to T-60min)
    """
    last_run = {"time": "2024-01-01T10:30:00Z", "found_incident_ids": {}}
    late_msg = {
        "actionStatus": "RECEIVED",
        "category": "UNKNOWN",
        "comments": [],
        "events": [
            {
                "causer": "null",
                "createdAt": "2024-01-01T10:05:00Z",
                "eventType": "CREATED",
                "id": "evt-late",
                "triggerer": "null",
            },
        ],
        "from": "late@example.com",
        "id": "msg-late",
        "phishmlReport": None,
        "pipelineStatus": "PROCESSED",
        "severity": "UNKNOWN_SEVERITY",
        "subject": "Late message",
        "tags": [],
    }
    mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response([late_msg]))
    next_run, incidents = phisher.fetch_incidents(client, last_run, "7 days", 50, look_back=60)
    assert len(incidents) == 1
    assert incidents[0]["dbotMirrorId"] == "msg-late"


@freeze_time("2024-01-01T11:00:00Z")
def test_fetch_incidents_lookback_zero_no_overlap(mocker):
    """
    Given:
    - last_run time is 10:30Z, look_back=0
    - A spy captures the GQL payload sent to phisher_gql_request

    When:
    - fetch_incidents is called with look_back=0

    Then:
    - The GQL payload contains 'reported_at:{2024-01-01T10:30:00Z TO' (no window expansion)
    """
    last_run = {"time": "2024-01-01T10:30:00Z", "found_incident_ids": {}}
    spy = mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response([]))
    phisher.fetch_incidents(client, last_run, "7 days", 50, look_back=0)
    call_arg = spy.call_args[0][0]
    assert "reported_at:{2024-01-01T10:30:00Z TO" in call_arg


@freeze_time("2024-01-01T11:00:00Z")
def test_fetch_incidents_max_fetch_truncates(mocker):
    """
    Given:
    - API returns 5 messages, max_fetch=2

    When:
    - fetch_incidents is called

    Then:
    - Only 2 incidents are emitted
    """
    msgs = [
        {
            **MSG_A,
            "id": f"msg-{i}",
            "subject": f"Msg {i}",
            "events": [
                {
                    "causer": "null",
                    "createdAt": f"2024-01-01T10:0{i}:00Z",
                    "eventType": "CREATED",
                    "id": f"evt-{i}",
                    "triggerer": "null",
                }
            ],
        }
        for i in range(5)
    ]
    mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response(msgs))
    _next_run, incidents = phisher.fetch_incidents(client, {}, "7 days", 2)
    assert len(incidents) == 2


@freeze_time("2024-01-01T11:00:00Z")
def test_fetch_incidents_legacy_last_fetch_migration(mocker):
    """
    Given:
    - last_run has legacy shape {"last_fetch": "2024-01-01T10:00:00Z"} (pre-lookback upgrade)
    - API returns msg-a

    When:
    - fetch_incidents is called

    Then:
    - msg-a is emitted (legacy time is used, not first_fetch fallback)
    - next_run has the new dict shape with 'time' and 'found_incident_ids'
    """
    # legacy state gets migrated in fetch_incidents_command; fetch_incidents itself
    # receives the already-migrated dict, so we simulate that here
    legacy_migrated = {"time": "2024-01-01T10:00:00Z", "found_incident_ids": {}}
    mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response([MSG_A]))
    next_run, incidents = phisher.fetch_incidents(client, legacy_migrated, "7 days", 50)
    assert len(incidents) == 1
    assert "time" in next_run
    assert "found_incident_ids" in next_run


@freeze_time("2024-01-01T11:00:00Z")
def test_fetch_incidents_query_uses_window(mocker):
    """
    Given:
    - last_run time is 10:30Z, look_back=0
    - now is frozen at 11:00Z

    When:
    - fetch_incidents is called

    Then:
    - GQL payload uses a closed window 'reported_at:{10:30:00Z TO 11:00:00Z}', not open-ended 'TO *'
    """
    last_run = {"time": "2024-01-01T10:30:00Z", "found_incident_ids": {}}
    spy = mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response([]))
    phisher.fetch_incidents(client, last_run, "7 days", 50, look_back=0)
    call_arg = spy.call_args[0][0]
    assert "reported_at:{2024-01-01T10:30:00Z TO 2024-01-01T11:00:00Z}" in call_arg
    assert "TO *" not in call_arg


@freeze_time("2024-01-01T11:00:00Z")
def test_fetch_incidents_cursor_uses_reported_at(mocker):
    """
    Given:
    - A message with reportedAt earlier than its CREATED event createdAt

    When:
    - fetch_incidents is called

    Then:
    - created_at_cursor is set to reportedAt, not createdAt, keeping the
      cursor coherent with the reported_at Lucene query field
    """
    last_run = {"time": "2024-01-01T09:00:00Z", "found_incident_ids": {}}
    mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response([MSG_A]))
    next_run, incidents = phisher.fetch_incidents(client, last_run, "7 days", 50)
    assert len(incidents) == 1
    raw = json.loads(incidents[0]["rawJSON"])
    assert raw["created_at_cursor"] == "2024-01-01T09:59:55Z"  # reportedAt, not createdAt (10:00:00Z)


@freeze_time("2024-01-01T11:00:00Z")
def test_test_module_returns_ok_when_no_messages(mocker):
    """
    Given:
    - A valid connection to PhishER that returns zero messages

    When:
    - test-module is called (e.g. from XSOAR integration config)

    Then:
    - "ok" is returned — empty inbox is not a failure
    """
    mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response([]))
    mocker.patch("knowbe4Phisher.demisto").getLastRun.return_value = {}
    mocker.patch.object(client, "max_fetch", 50)
    result = phisher.test_module(client)
    assert result == "ok"


@freeze_time("2024-01-01T11:00:00Z")
def test_test_module_returns_ok_when_messages_exist(mocker):
    """
    Given:
    - A valid connection to PhishER that returns messages

    When:
    - test-module is called

    Then:
    - "ok" is returned
    """
    mocker.patch.object(client, "phisher_gql_request", return_value=_gql_response([MSG_A]))
    mocker.patch("knowbe4Phisher.demisto").getLastRun.return_value = {}
    mocker.patch.object(client, "max_fetch", 50)
    result = phisher.test_module(client)
    assert result == "ok"


def test_time_creation():
    """
    Given:
    - Events example from Phisher Response

    When:
    - when fetching messages from Phisher - fetch or list of all messages

    Then:
    - Ensure that the event time is extracted as expected
    """
    result = phisher.get_created_time(events_example)
    assert result == expected_time


mock_responses = util_load_json("test_data/test_responses.json")
command_results = util_load_json("test_data/mock_responses.json")


@pytest.mark.parametrize(
    "function_to_test, function_to_mock, args, key",
    [
        (phisher.phisher_message_list_command, "phisher_gql_request", {}, "message_list_all"),
    ],
)
def test_commands_with_results(mocker, function_to_test, function_to_mock, args, key):
    expected_res = mock_responses[key]
    mocker.patch.object(client, function_to_mock, return_value=command_results[key])
    result: CommandResults = function_to_test(client, args)
    assert result.outputs == expected_res


@pytest.mark.parametrize(
    "function_to_test, function_to_mock, args, key",
    [
        (
            phisher.phisher_create_comment_command,
            "phisher_gql_request",
            {"id": "cff35e34-aeb6-4263-b592-c68fc03ea7cb", "comment": "Infinity Test"},
            "create_comment",
        ),
        (
            phisher.phisher_update_message_command,
            "phisher_gql_request",
            {"id": "cff35e34-aeb6-4263-b592-c68fc03ea7cb", "category": "SPAM", "status": "RESOLVED", "severity": "HIGH"},
            "update_message",
        ),
        (
            phisher.phisher_create_tags_command,
            "phisher_gql_request",
            {"id": "cff35e34-aeb6-4263-b592-c68fc03ea7cb", "tags": "Test Tag"},
            "create_tags",
        ),
        (
            phisher.phisher_delete_tags_command,
            "phisher_gql_request",
            {"id": "cff35e34-aeb6-4263-b592-c68fc03ea7cb", "tags": "Test Tag"},
            "delete_tags",
        ),
    ],
)
def test_commands_no_results(mocker, function_to_test, function_to_mock, args, key):
    expected_res = mock_responses[key]
    mocker.patch.object(client, function_to_mock, return_value=command_results[key])
    result = function_to_test(client, args)
    assert result == expected_res


# --- fetch-incidents-command multi-run tests ---

command_client = phisher.Client(
    base_url="https://eu.test.com/graphql",
    verify=False,
    proxy=False,
    first_fetch_time="2024-01-01T00:00:00Z",
    max_fetch=50,
)

WINDOW_PATTERN = re.compile(r"reported_at:([\[{])(\S+?) TO (\S+?)([\]}])")


def _parse_utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _late_msg(msg_id: str, reported_at: str) -> dict:
    created_at = (_parse_utc(reported_at) + timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    created_event = {
        "causer": "null",
        "createdAt": created_at,
        "eventType": "CREATED",
        "id": f"evt-{msg_id}",
        "triggerer": "null",
    }
    return {**MSG_A, "id": msg_id, "subject": f"Subject {msg_id}", "reportedAt": reported_at, "events": [created_event]}


class WindowedPhisherApi:
    """Fake PhishER search: honours the query's reported_at window and only returns a message once it is searchable."""

    def __init__(self, messages: list[tuple[dict, str]]):
        self.messages = [(node, _parse_utc(visible_from)) for node, visible_from in messages]
        self.windows: list[str] = []

    def __call__(self, payload: str) -> dict:
        match = WINDOW_PATTERN.search(payload)
        assert match, f"no reported_at window in payload: {payload}"
        open_bracket, start, end, close_bracket = match.groups()
        self.windows.append(f"{open_bracket}{start} TO {end}{close_bracket}")
        start_at, end_at, now = _parse_utc(start), _parse_utc(end), datetime.now(UTC)

        def in_window(reported_at: datetime) -> bool:
            after_start = reported_at >= start_at if open_bracket == "[" else reported_at > start_at
            before_end = reported_at <= end_at if close_bracket == "]" else reported_at < end_at
            return after_start and before_end

        nodes = [
            copy.deepcopy(node)
            for node, visible_from in self.messages
            if visible_from <= now and in_window(_parse_utc(node["reportedAt"]))
        ]
        return _gql_response(sorted(nodes, key=lambda node: node["reportedAt"]))


def run_fetch_command(mocker, params: dict, store: dict) -> list[dict]:
    """Run fetch_incidents_command once, persisting lastRun through `store` the way XSOAR does (JSON round-trip)."""
    emitted: list[dict] = []
    mocker.patch.object(demisto, "params", return_value={**params})
    mocker.patch.object(demisto, "getLastRun", return_value=json.loads(json.dumps(store.get("last_run", {}))))
    mocker.patch.object(
        demisto, "setLastRun", side_effect=lambda last_run: store.update(last_run=json.loads(json.dumps(last_run)))
    )
    mocker.patch.object(demisto, "incidents", side_effect=emitted.extend)
    phisher.fetch_incidents_command(command_client)
    return emitted


@pytest.mark.parametrize("params", [{}, {"look_back": ""}, {"look_back": "0"}])
def test_fetch_command_recovers_message_processed_after_previous_fetch(mocker, params):
    """
    Given:
    - look_back is missing/empty/0 on the instance, 5-minute fetch interval
    - a message reported 10:34:25Z that only becomes searchable at 10:34:58Z
    When:
    - fetch runs at 10:34:30Z (message not searchable yet) and again at 10:39:30Z
    Then:
    - the second run emits the message
    """
    api = WindowedPhisherApi([(_late_msg("msg-late", "2024-01-01T10:34:25Z"), "2024-01-01T10:34:58Z")])
    mocker.patch.object(command_client, "phisher_gql_request", side_effect=api)
    store = {"last_run": {"time": "2024-01-01T10:24:48Z", "found_incident_ids": {}}}
    with freeze_time("2024-01-01T10:34:30Z") as frozen:
        assert run_fetch_command(mocker, params, store) == []
        frozen.move_to("2024-01-01T10:39:30Z")
        emitted = run_fetch_command(mocker, params, store)
    assert [incident["dbotMirrorId"] for incident in emitted] == ["msg-late"], f"windows queried: {api.windows}"


@pytest.mark.parametrize("raw, expected", [(None, 15), ("", 15), ("0", 15), (0, 15), ("-5", 15), ("60", 60), (30, 30)])
def test_resolve_look_back(raw, expected):
    assert phisher.resolve_look_back(raw) == expected


def test_resolve_look_back_rejects_non_numeric():
    with pytest.raises(ValueError):
        phisher.resolve_look_back("15 minutes")


def test_fetch_command_look_back_60_recovers_late_indexed_message_once(mocker):
    """
    Given:
    - look_back=60, 5-minute fetch interval
    - a message reported 08:03:11Z that only becomes searchable at 08:21:12Z
    When:
    - fetch runs every 5 minutes from 08:02:30Z to 08:32:30Z (overlapping 60-minute windows)
    Then:
    - the message is emitted exactly once across all runs
    """
    api = WindowedPhisherApi([(_late_msg("msg-late", "2024-01-01T08:03:11Z"), "2024-01-01T08:21:12Z")])
    mocker.patch.object(command_client, "phisher_gql_request", side_effect=api)
    store = {"last_run": {"time": "2024-01-01T07:57:30Z", "found_incident_ids": {}}}
    emitted: list[dict] = []
    with freeze_time("2024-01-01T08:02:30Z") as frozen:
        for minute in range(2, 33, 5):
            frozen.move_to(f"2024-01-01T08:{minute:02d}:30Z")
            emitted.extend(run_fetch_command(mocker, {"look_back": "60"}, store))
    assert [incident["dbotMirrorId"] for incident in emitted] == ["msg-late"]


def test_fetch_command_migrates_legacy_last_run_with_default_look_back(mocker):
    """
    Given:
    - an instance still holding the pre-lookback lastRun shape {"last_fetch": ...} and no look_back param
    - a searchable message reported 10:30:00Z
    When:
    - fetch runs at 11:00:00Z
    Then:
    - the message is emitted and lastRun is stored in the lookback shape
    """
    api = WindowedPhisherApi([(_late_msg("msg-legacy", "2024-01-01T10:30:00Z"), "2024-01-01T10:30:30Z")])
    mocker.patch.object(command_client, "phisher_gql_request", side_effect=api)
    store = {"last_run": {"last_fetch": "2024-01-01T10:00:00Z"}}
    with freeze_time("2024-01-01T11:00:00Z"):
        emitted = run_fetch_command(mocker, {}, store)
    assert [incident["dbotMirrorId"] for incident in emitted] == ["msg-legacy"]
    assert api.windows[0][1:].startswith("2024-01-01T10:00:00Z TO"), f"legacy last_fetch not used: {api.windows}"
    assert "time" in store["last_run"]
    assert "found_incident_ids" in store["last_run"]
