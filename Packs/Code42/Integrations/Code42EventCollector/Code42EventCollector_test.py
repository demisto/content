import json
from unittest.mock import MagicMock
from freezegun import freeze_time
from pytest_mock import MockerFixture

import requests_toolbelt.sessions

from CommonServerPython import *
from Code42EventCollector import DATE_FORMAT

TEST_URL = "https://test.com"


def create_mocked_response(response: List[Dict] | Dict, status_code: int = 200) -> requests.Response:
    mocked_response = requests.Response()
    mocked_response._content = json.dumps(response).encode("utf-8")
    mocked_response.status_code = status_code
    return mocked_response


def create_file_events(start_id: int, start_date: str, num_of_file_events: int) -> List[Dict[str, Any]]:
    return [
        {"event": {"id": f"{i}", "inserted": (dateparser.parse(start_date) + timedelta(seconds=i)).strftime(DATE_FORMAT)}}
        for i in range(start_id, start_id + num_of_file_events)
    ]


def create_audit_logs(start_id: int, start_date: str, num_of_audit_logs: int) -> List[Dict[str, Any]]:
    return [
        {"id": f"{i}", "timestamp": (dateparser.parse(start_date) + timedelta(seconds=i)).strftime(DATE_FORMAT)}
        for i in range(start_id, start_id + num_of_audit_logs)
    ]


def get_mock_http_request_from_datetimes(datetimes: list[str]):
    def mock_request(method: str, url: str, *args, **kwargs):
        if method == "POST" and "v1/oauth" in url:
            return create_mocked_response(response={"access_token": "1234", "token_type": "bearer", "expires_in": 10000000})
        return create_mocked_response(
            response={
                "fileEvents": [{"event": {"id": f"{i}", "inserted": dt}} for i, dt in enumerate(datetimes)],
                "totalCount": len(datetimes),
            }
        )

    return mock_request


class HttpRequestsMocker:
    latest_file_event_id = 1
    latest_audit_log_id = 1

    def __init__(self, num_of_audit_logs: int = 0, num_of_file_events: int = 0):
        self.num_of_audit_logs = num_of_audit_logs
        self.num_of_file_events = num_of_file_events
        self.fetched_audit_logs = 0
        self.fetched_file_events = 0

    def valid_http_request_side_effect(self, method: str, url: str, *args, **kwargs):
        if method == "POST" and "v1/oauth" in url:
            return create_mocked_response(response={"access_token": "1234", "token_type": "bearer", "expires_in": 10000000})

        if method == "POST" and "/v1/audit/search-audit-log" in url:
            if self.fetched_audit_logs >= self.num_of_audit_logs:
                return create_mocked_response(response={"events": []})

            audit_logs = create_audit_logs(
                self.latest_audit_log_id,
                start_date=(datetime.utcfromtimestamp(kwargs["json"]["dateRange"]["startTime"])).strftime(DATE_FORMAT),
                num_of_audit_logs=min(kwargs["json"]["pageSize"], self.num_of_audit_logs),
            )

            self.fetched_audit_logs += len(audit_logs)

            self.latest_audit_log_id = int(audit_logs[-1]["id"]) + 1
            return create_mocked_response(response={"events": audit_logs})

        if method == "POST" and "/v2/file-events" in url:
            if self.fetched_file_events >= self.num_of_file_events:
                return create_mocked_response({"fileEvents": []})

            file_events = create_file_events(
                self.latest_file_event_id,
                start_date="2024-01-24 12:30:45.123456Z",
                num_of_file_events=min(kwargs["json"]["pgSize"], self.num_of_file_events),
            )

            self.fetched_file_events += len(file_events)

            self.latest_file_event_id = int(file_events[-1]["event"]["id"]) + 1
            return create_mocked_response(response={"fileEvents": file_events, "totalCount": self.num_of_file_events})
        return None


def test_the_test_module(mocker):
    """
    Given:
     - a single audit log and a single file event
     - api returns 200 ok

    When:
     - running test-module

    Then:
     - make sure the test is successful.
    """
    import Code42EventCollector

    return_results_mocker: MagicMock = mocker.patch.object(Code42EventCollector, "return_results")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")

    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=HttpRequestsMocker(num_of_file_events=1, num_of_audit_logs=1).valid_http_request_side_effect,
    )

    Code42EventCollector.main()
    assert return_results_mocker.called
    assert return_results_mocker.call_args[0][0] == "ok"


def test_fetch_events_no_last_run(mocker):
    """
    Given:
     - a single audit log and a single file event
     - api returns 200 ok

    When:
     - running fetch events

    Then:
     - make sure events are sent successfully
     - make sure last run is populated correctly
    """
    import Code42EventCollector

    send_events_mocker: MagicMock = mocker.patch.object(Code42EventCollector, "send_events_to_xsiam")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "event_types_to_fetch": "File,Audit",
        },
    )
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=HttpRequestsMocker(num_of_file_events=1, num_of_audit_logs=1).valid_http_request_side_effect,
    )

    Code42EventCollector.main()
    file_events = send_events_mocker.call_args_list[0][0][0]
    assert len(file_events) == 1
    assert file_events[0]["eventType"] == Code42EventCollector.EventType.FILE

    audit_logs = send_events_mocker.call_args_list[1][0][0]
    assert len(audit_logs) == 1
    assert audit_logs[0]["eventType"] == Code42EventCollector.EventType.AUDIT

    last_run_expected_keys = {
        Code42EventCollector.FileEventLastRun.FETCHED_IDS,
        Code42EventCollector.FileEventLastRun.TIME,
        Code42EventCollector.AuditLogLastRun.FETCHED_IDS,
        Code42EventCollector.AuditLogLastRun.TIME,
    }

    assert last_run_expected_keys == set(set_last_run_mocker.call_args_list[0][0][0].keys())


def test_fetch_events_no_last_run_max_fetch_lower_than_available_events(mocker):
    """
    Given:
     - 550 audit logs and 550 file events
     - api returns 200 ok
     - max fetch = 500

    When:
     - running fetch events

    Then:
     - make sure 500 events are sent successfully
     - make sure last run is populated correctly
    """
    import Code42EventCollector

    send_events_mocker: MagicMock = mocker.patch.object(Code42EventCollector, "send_events_to_xsiam")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_file_events_per_fetch": 500,
            "max_audit_events_per_fetch": 500,
            "event_types_to_fetch": "File,Audit",
        },
    )
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=HttpRequestsMocker(num_of_file_events=550, num_of_audit_logs=550).valid_http_request_side_effect,
    )

    Code42EventCollector.main()
    file_events = send_events_mocker.call_args_list[0][0][0]
    assert len(file_events) == 500
    for file_event in file_events:
        assert file_event["eventType"] == Code42EventCollector.EventType.FILE

    audit_logs = send_events_mocker.call_args_list[1][0][0]
    assert len(audit_logs) == 500
    for audit_log in audit_logs:
        assert audit_log["eventType"] == Code42EventCollector.EventType.AUDIT

    last_run_expected_keys = {
        Code42EventCollector.FileEventLastRun.FETCHED_IDS,
        Code42EventCollector.FileEventLastRun.TIME,
        Code42EventCollector.AuditLogLastRun.FETCHED_IDS,
        Code42EventCollector.AuditLogLastRun.TIME,
    }

    # make sure all keys in last run are valid
    assert last_run_expected_keys.issubset(set(set_last_run_mocker.call_args_list[0][0][0].keys()))


def test_fetch_events_no_last_run_no_audit_logs_yes_file_events(mocker):
    """
    Given:
     - 0 audit logs and 100 file events
     - api returns 200 ok
     - max fetch = 500

    When:
     - running fetch events

    Then:
     - make sure 100 file events are sent successfully
     - make sure no audit logs are sent
     - make sure last run is populated correctly
    """
    import Code42EventCollector

    send_events_mocker: MagicMock = mocker.patch.object(Code42EventCollector, "send_events_to_xsiam")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_file_events_per_fetch": 500,
            "max_audit_events_per_fetch": 500,
            "event_types_to_fetch": "File,Audit",
        },
    )
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=HttpRequestsMocker(num_of_file_events=100, num_of_audit_logs=0).valid_http_request_side_effect,
    )

    Code42EventCollector.main()
    file_events = send_events_mocker.call_args_list[0][0][0]
    assert len(file_events) == 100
    for file_event in file_events:
        assert file_event["eventType"] == Code42EventCollector.EventType.FILE

    audit_logs = send_events_mocker.call_args_list[1][0][0]
    assert len(audit_logs) == 0

    last_run_expected_keys = {
        Code42EventCollector.FileEventLastRun.FETCHED_IDS,
        Code42EventCollector.FileEventLastRun.TIME,
    }

    assert last_run_expected_keys == set(set_last_run_mocker.call_args_list[0][0][0].keys())


def test_fetch_events_no_last_run_yes_audit_logs_no_file_events(mocker):
    """
    Given:
     - 100 audit logs and 0 file events
     - api returns 200 ok
     - max fetch = 500

    When:
     - running fetch events

    Then:
     - make sure 100 audit logs are sent successfully
     - make sure no file events are sent
     - make sure last run is populated correctly
    """
    import Code42EventCollector

    send_events_mocker: MagicMock = mocker.patch.object(Code42EventCollector, "send_events_to_xsiam")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_file_events_per_fetch": 500,
            "max_audit_events_per_fetch": 500,
            "event_types_to_fetch": "File,Audit",
        },
    )
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=HttpRequestsMocker(num_of_file_events=0, num_of_audit_logs=100).valid_http_request_side_effect,
    )

    Code42EventCollector.main()
    file_events = send_events_mocker.call_args_list[0][0][0]
    assert len(file_events) == 0

    audit_logs = send_events_mocker.call_args_list[1][0][0]
    assert len(audit_logs) == 100
    for audit_log in audit_logs:
        assert audit_log["eventType"] == Code42EventCollector.EventType.AUDIT

    last_run_expected_keys = {
        Code42EventCollector.AuditLogLastRun.FETCHED_IDS,
        Code42EventCollector.AuditLogLastRun.TIME,
    }

    assert last_run_expected_keys == set(set_last_run_mocker.call_args_list[0][0][0].keys())


def test_fetch_events_no_last_run_no_events(mocker):
    """
    Given:
     - no audit logs | no file events
     - api returns 200 ok

    When:
     - running fetch events

    Then:
     - make sure no events were sent
    """
    import Code42EventCollector

    send_events_mocker: MagicMock = mocker.patch.object(Code42EventCollector, "send_events_to_xsiam")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "event_types_to_fetch": "File,Audit",
        },
    )
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=HttpRequestsMocker(num_of_file_events=0, num_of_audit_logs=0).valid_http_request_side_effect,
    )

    Code42EventCollector.main()

    file_events = send_events_mocker.call_args_list[0][0][0]
    assert len(file_events) == 0

    audit_logs = send_events_mocker.call_args_list[1][0][0]
    assert len(audit_logs) == 0


@freeze_time("2024-01-01 01:00:15 UTC")
def test_fetch_events_within_look_back(mocker: MockerFixture):
    """
    Given:
     - A run with incidents within the look-back time frame.

    When:
     - Running fetch events.

    Then:
     - The next-fetch should be the look-back time rounded down to the first three microsecond digits,
       and all incidents later than the next-fetch should be kept in the last-run.
    """
    from Code42EventCollector import main, FILE_EVENTS_LOOK_BACK, FileEventLastRun

    LOOK_BACK_TIME = datetime.now() - FILE_EVENTS_LOOK_BACK

    mocker.patch("Code42EventCollector.send_events_to_xsiam")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_file_events_per_fetch": 500,
            "max_audit_events_per_fetch": 500,
            "event_types_to_fetch": "File",
        },
    )
    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=get_mock_http_request_from_datetimes(
            [
                (LOOK_BACK_TIME + timedelta(seconds=-1)).strftime(DATE_FORMAT),
                (LOOK_BACK_TIME + timedelta(microseconds=500_200)).strftime(DATE_FORMAT),
                (LOOK_BACK_TIME + timedelta(microseconds=500_100)).strftime(DATE_FORMAT),
                (LOOK_BACK_TIME + timedelta(microseconds=500_300)).strftime(DATE_FORMAT),
            ]
        ),
    )
    set_last_run_mock = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "command", return_value="fetch-events")

    main()

    assert set(set_last_run_mock.call_args_list[0][0][0][FileEventLastRun.FETCHED_IDS]) == {"1", "2", "3"}
    assert set_last_run_mock.call_args_list[0][0][0][FileEventLastRun.TIME] == "2024-01-01 00:59:30.000000Z"


@freeze_time("2024-01-01 01:00:15 UTC")
def test_fetch_events_before_look_back(mocker: MockerFixture):
    """
    Given:
     - A run with incidents before the look-back time frame.

    When:
     - Running fetch events.

    Then:
     - The next-fetch should be the latest creation time rounded down to the first three microsecond digits,
       and all incidents later than the next-fetch should be kept in the last-run.
    """
    from Code42EventCollector import main, FILE_EVENTS_LOOK_BACK, FileEventLastRun

    LOOK_BACK_TIME = datetime.now() - FILE_EVENTS_LOOK_BACK

    mocker.patch("Code42EventCollector.send_events_to_xsiam")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_file_events_per_fetch": 500,
            "max_audit_events_per_fetch": 500,
            "event_types_to_fetch": "File",
        },
    )
    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=get_mock_http_request_from_datetimes(
            [
                (LOOK_BACK_TIME + timedelta(minutes=-1, microseconds=100_000)).strftime(DATE_FORMAT),
                (LOOK_BACK_TIME + timedelta(minutes=-1, microseconds=500_200)).strftime(DATE_FORMAT),
                (LOOK_BACK_TIME + timedelta(minutes=-1, microseconds=500_100)).strftime(DATE_FORMAT),
                (LOOK_BACK_TIME + timedelta(minutes=-1, microseconds=500_300)).strftime(DATE_FORMAT),
            ]
        ),
    )
    set_last_run_mock = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "command", return_value="fetch-events")

    main()

    assert set(set_last_run_mock.call_args_list[0][0][0][FileEventLastRun.FETCHED_IDS]) == {"1", "2", "3"}
    assert set_last_run_mock.call_args_list[0][0][0][FileEventLastRun.TIME] == "2024-01-01 00:58:30.500000Z"


@freeze_time("2024-01-01 01:00:15 UTC")
def test_fetch_events_empty_run(mocker: MockerFixture):
    """
    Given:
     - An empty run.

    When:
     - Running fetch events.

    Then:
     - The last-run should stay the same.
    """
    from Code42EventCollector import main

    mocker.patch("Code42EventCollector.send_events_to_xsiam")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_file_events_per_fetch": 500,
            "max_audit_events_per_fetch": 500,
            "event_types_to_fetch": "File",
        },
    )
    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession, "request", side_effect=HttpRequestsMocker().valid_http_request_side_effect
    )
    mocker.patch.object(demisto, "getLastRun", return_value={"LastRun": "previous_last_run"})
    set_last_run_mock = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "command", return_value="fetch-events")

    main()

    assert set_last_run_mock.call_args_list[0][0][0] == {"LastRun": "previous_last_run"}


def test_get_events_command(mocker):
    """
    Given:
     - 1 audit log / 1 file event
     - api returns 200 ok

    When:
     - running get_events_command

    Then:
     - make sure the events are returned as expected
    """
    import Code42EventCollector

    return_results_mocker: MagicMock = mocker.patch.object(Code42EventCollector, "return_results")

    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
        },
    )

    mocker.patch.object(
        demisto, "args", return_value={"start_date": datetime.utcnow() - timedelta(minutes=1), "event_type": "audit"}
    )

    mocker.patch.object(demisto, "command", return_value="code42-get-events")
    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=HttpRequestsMocker(num_of_file_events=1, num_of_audit_logs=1).valid_http_request_side_effect,
    )

    Code42EventCollector.main()

    command_result = return_results_mocker.call_args_list[0][0][0]
    assert command_result.outputs[0]["eventType"] == Code42EventCollector.EventType.AUDIT
    assert len(command_result.outputs) == 1
    assert command_result.outputs
    assert command_result.readable_output

    mocker.patch.object(
        demisto, "args", return_value={"start_date": datetime.utcnow() - timedelta(minutes=1), "event_type": "file"}
    )

    Code42EventCollector.main()

    command_result = return_results_mocker.call_args_list[1][0][0]
    assert len(command_result.outputs) == 1
    assert command_result.outputs[0]["eventType"] == Code42EventCollector.EventType.FILE
    assert command_result.outputs
    assert command_result.readable_output
