import gzip
import tempfile
import zipfile
from freezegun import freeze_time
import pytest
from CommonServerPython import DemistoException

from SymantecCloudSecureWebGatewayEventCollector import (
    DEFAULT_FETCH_SLEEP,
    HandlingDuplicates,
    LastRun,
    extract_logs_and_push_to_XSIAM,
    get_events_and_write_to_file_system,
    Client,
    get_fetch_interval,
    get_size_gzip_file,
    get_start_and_end_date,
    get_start_date_for_next_fetch,
    get_status_and_token_from_file,
    get_the_last_row_that_incomplete,
    calculate_next_fetch,
    parse_events,
    extract_logs_from_zip_file,
    perform_long_running_loop,
)
import demistomock as demisto
from pathlib import Path


@pytest.fixture()
def client():
    return Client("https://api.example.com", "user", "pass", False, False, None)


@pytest.fixture
def tmp_zip_file(tmpdir):
    file_contents = b""
    for _ in range(0, 10):
        file_contents += b"Hello, this is some data for the gzip file.\n"

    # Create a zip file
    zip_file_name = Path(tmpdir / "example.zip")
    with zipfile.ZipFile(zip_file_name, "w") as zip_file:
        # Create and add gzip files to the zip file
        for i in range(0, 4):  # Create three gzip files for demonstration
            gzip_file_name = Path(f"file{i}.gz")

            with gzip.open(gzip_file_name, "wb") as f:
                f.write(file_contents)

            # Add the gzip file to the zip file
            zip_file.write(gzip_file_name)

            # Remove the temporary gzip file
            gzip_file_name.unlink()
    return zip_file_name


def test_get_events_and_write_to_file_system(requests_mock, client):
    requests_mock.get(
        "https://api.example.com/reportpod/logs/sync", content=b"event1\nevent2"
    )

    params = {}
    tmp_file_path = get_events_and_write_to_file_system(client, params)

    # validate file exists and has expected content
    assert tmp_file_path.exists()
    assert tmp_file_path.read_text() == "event1\nevent2"


@pytest.mark.parametrize(
    "start_date, expected_start, expected_end",
    [
        (None, 1577836740000, 1577836800000),
        (1600, 1600, 1577836800000),
    ],
)
def test_get_start_and_end_date(start_date, expected_start, expected_end):
    """
    Given:
        - No arguments and no stored start date
        - A 'since' argument and no stored start date
        - No arguments and a stored start date
    When:
        - run the get_start_and_end_date function
          which calculates a start and end date
    Then:
        - Case 1: Ensure the start date should be 1 minute ago (ie from date 2020-01-01T00:00:00Z)
        - Case 2: Ensure the start date should be the 'since' date
        - Case 3: Ensure the start date should be the stored date
    """
    with freeze_time("2020-01-01T00:00:00Z"):
        start, end = get_start_and_end_date(start_date)

        assert start == expected_start
        assert end == expected_end


@pytest.mark.parametrize(
    "content_file, expected_status, expected_token",
    [
        (b"X-sync-status: more\r\nX-sync-token: abc123\r\n", "more", "abc123"),
        (
            (
                "".join(["abc" for i in range(700)])
                + "X-sync-status: more\r\nX-sync-token: abc123\r\n"
            ).encode(),
            "more",
            "abc123",
        ),
        (b"", "", ""),
    ],
)
def test_get_status_and_token_from_file(
    tmpdir, content_file: bytes, expected_status: str, expected_token: str
):
    """
    Given:
        - A file containing a status and a token
        - A large file containing a status and token at the end
        - An empty file
    When:
        - run the `get_status_and_token_from_file` function
    Then:
        - Cases 1-2: Ensure the status and token are extracted as expected from the file
        - Case 3: Ensure the function returns empty strings for status and token
    """
    tmp_file = Path(tmpdir / "test.zip")
    tmp_file.write_bytes(content_file)
    status, token = get_status_and_token_from_file(tmp_file)
    assert status == expected_status
    assert token == expected_token


@pytest.mark.parametrize(
    "lines, file_size, expected_line",
    [
        ([b"line1\n", b"line2"], 7, b"line2"),
        ([b"line1\n"], 5, b""),
        ([b"line1"], 0, b""),
    ],
)
def test_get_the_last_row_that_incomplete(
    lines: list[bytes], file_size: int, expected_line: bytes
):
    """
    Given:
        - A list with last incomplete log line and file size > 0.
        - A list with last complete log line.
        - A list with last incomplete log line and file size of 0.
    When:
        - run the `get_the_last_row_that_incomplete` function
    Then:
        - Ensure it returned the last line.
        - Ensure it returned an empty byte string since the last line is complete.
        - Ensure it returned an empty byte string since the file size is 0.
    """
    incomplete_line = get_the_last_row_that_incomplete(lines, file_size)
    assert incomplete_line == expected_line


@pytest.mark.parametrize(
    "data, expected_size",
    [(b"abc123", 6), (b"", 0)],
)
def test_get_size_gzip_file(tmpdir, data: bytes, expected_size: int):
    """
    Given:
        - A gzip file with content.
        - An empty gzip file.
    When:
        - run the `get_size_gzip_file` function.
    Then:
        - Ensure the file size returned as expected for both cases.
        - Ensure the file pointer returned to 0 after getting the file size.
    """
    tmp_gzip_file = Path(tmpdir / "test.gz")
    with gzip.open(tmp_gzip_file, "wb") as f:
        f.write(data)

    with gzip.open(tmp_gzip_file, "rb") as f:
        file_size = get_size_gzip_file(f)
        assert file_size == expected_size
        assert f.tell() == 0


@pytest.mark.parametrize(
    "id_, cur_time, last_time, dup_ids, expected",
    [
        ("id1", "2020-01-01 00:00:00", "2020-01-01 00:00:00", ["id1"], True),
        ("id2", "2020-01-01 00:00:00", "2020-01-01 00:00:00", ["id1"], False),
        ("id3", "2020-01-01 00:01:00", "2020-01-01 00:00:00", ["id1"], False),
    ],
)
def test_is_duplicate(id_, cur_time, last_time, dup_ids, expected):
    """
    Given:
        - A unique ID, current time, last time, and a list of duplicate IDs.
    When:
        - run the `is_duplicate` method.
    Then:
        - Case 1: Ensure the method returns True,
          since the cur_time equal to last_time
          and the ID is in the duplicate list.

        - Case 2: Ensure the method returns False,
          since the ID is not in the duplicate list.

        - Case 3: Ensure the method returns False,
          since the cur_time is greater than last_time.
    """
    handling_duplicates = HandlingDuplicates(
        max_time=last_time, events_suspected_duplicates=dup_ids
    )
    assert handling_duplicates.is_duplicate(id_, cur_time) == expected


@freeze_time("2020-01-01 00:00:00")
@pytest.mark.parametrize(
    "start_time, time_of_last_fetched_event, expected",
    [
        (0, "2020-01-01 00:00:00", 1577836800000),
        (1000, "invalid", 1000),
        (1000, None, 1000),
    ],
)
def test_get_start_date_for_next_fetch(
    start_time: int, time_of_last_fetched_event: str | None, expected
):
    """
    Given:
        - A start time and a time of last fetched event.
    When:
        - run the `get_start_date_for_next_fetch` function.
    Then:
        - Ensure that as long as the argument `time_of_last_fetched_event` is either None
          or not in datetime format, the original start_time is returned.
    """
    next_start = get_start_date_for_next_fetch(start_time, time_of_last_fetched_event)
    assert next_start == expected


@pytest.mark.parametrize(
    (
        "time_of_last_fetched_event, new_events_suspected_duplicates, handling_duplicates,"
        "expected_time_of_last_fetched_event, expected_events_suspected_duplicates, expected_token_expired"
    ),
    [
        (
            "2020-01-01 00:00:01",
            ["id_3", "id_4"],
            HandlingDuplicates(
                max_time="2020-01-01 00:00:00",
                events_suspected_duplicates=["id_1", "id_2"],
            ),
            "2020-01-01 00:00:01",
            ["id_3", "id_4"],
            False,
        ),
        (
            "2020-01-01 00:00:00",
            ["id_3", "id_4"],
            HandlingDuplicates(
                max_time="2020-01-01 00:00:00",
                events_suspected_duplicates=["id_1", "id_2"],
            ),
            "2020-01-01 00:00:00",
            ["id_1", "id_2", "id_3", "id_4"],
            True,
        ),
        (
            "2020-01-01 00:00:00",
            ["id_0", "id_1"],
            HandlingDuplicates(
                max_time="2020-01-01 00:00:01",
                events_suspected_duplicates=["id_2", "id_3"],
            ),
            "2020-01-01 00:00:01",
            ["id_2", "id_3"],
            True,
        ),
    ],
)
def test_calculate_next_fetch(
    time_of_last_fetched_event: str,
    new_events_suspected_duplicates: list[str],
    handling_duplicates: HandlingDuplicates,
    expected_time_of_last_fetched_event: str,
    expected_events_suspected_duplicates: list[str],
    expected_token_expired: bool,
):
    """
    Given:
        1. `time_of_last_fetched_event` grater than `handling_duplicates.max_time`
        2. `time_of_last_fetched_event` equal to `handling_duplicates.max_time`
        3. `time_of_last_fetched_event` less than `handling_duplicates.max_time`
    When:
        - run `calculate_next_fetch` function
    Then:
        Ensure:
        - For case 1, the `last_run_model` updated with
          new time_of_last_fetched_event and new_events_suspected_duplicates.
        - For case 2, append the new duplicate ids to existing ones.
        - For case 3, not updated time_of_last_fetched_event
          and events_suspected_duplicates in last_run_model.
    """
    last_run_model = calculate_next_fetch(
        start_date=123,
        new_token="test",
        time_of_last_fetched_event=time_of_last_fetched_event,
        new_events_suspected_duplicates=new_events_suspected_duplicates,
        handling_duplicates=handling_duplicates,
        token_expired=True,
    )

    assert (
        last_run_model.time_of_last_fetched_event == expected_time_of_last_fetched_event
    )
    assert (
        last_run_model.events_suspected_duplicates
        == expected_events_suspected_duplicates
    )
    assert last_run_model.token_expired == expected_token_expired


@pytest.mark.parametrize(
    "mock_events, expected_call",
    [
        ([b"event1"], 1),
        ([], 0),
    ],
)
def test_extract_logs_and_push_to_XSIAM(
    mocker, mock_events: list[bytes], expected_call: int
):
    """
    Given:
        - args for extract_logs_and_push_to_XSIAM function
    When:
        - run `extract_logs_and_push_to_XSIAM` function
    Then:
        - Ensure 'send_events_to_xsiam' is called with the expected number of calls
          depending on whether events are returned from `parse_events`
    """
    mocker.patch(
        "SymantecCloudSecureWebGatewayEventCollector.extract_logs_from_zip_file",
        side_effect=[[b"event1"]],
    )
    mocker.patch(
        "SymantecCloudSecureWebGatewayEventCollector.parse_events",
        return_value=(mock_events, ""),
    )
    mock_send_events_to_xsiam = mocker.patch(
        "SymantecCloudSecureWebGatewayEventCollector.send_events_to_xsiam"
    )

    extract_logs_and_push_to_XSIAM(LastRun(), "tmp/tmp", False)
    assert mock_send_events_to_xsiam.call_count == expected_call


@pytest.mark.parametrize(
    "mock_parse_events, mock_send_events_to_xsiam, expected_raise, expected_call",
    [
        (
            Exception("Parse error"),
            None,
            "Parse error",
            "Error parsing events: Parse error",
        ),
        (
            ((["event"], ""),),
            Exception("Send error"),
            "Send error",
            "Failed to send events to XSOAR. Error: Send error",
        ),
    ],
)
def test_extract_logs_and_push_to_XSIAM_failure(
    mocker,
    mock_parse_events: Exception | tuple[list[str], str],
    mock_send_events_to_xsiam: Exception | None,
    expected_raise: str,
    expected_call: str,
):
    """
    Given:
        - args for extract_logs_and_push_to_XSIAM function
    When:
        - run `extract_logs_and_push_to_XSIAM` function with mocked failures
    Then:
        - Ensure that depending on the exception
          the function `demisto.debug` is called with the expected str
    """
    mocker.patch(
        "SymantecCloudSecureWebGatewayEventCollector.extract_logs_from_zip_file",
        side_effect=[[b"event1"]],
    )
    mocker.patch(
        "SymantecCloudSecureWebGatewayEventCollector.parse_events",
        side_effect=mock_parse_events,
    )
    mock_send_events_to_xsiam = mocker.patch(
        "SymantecCloudSecureWebGatewayEventCollector.send_events_to_xsiam",
        side_effect=mock_send_events_to_xsiam,
    )
    mock_assertion = mocker.patch.object(demisto, "info")

    with pytest.raises(Exception, match=expected_raise):
        extract_logs_and_push_to_XSIAM(LastRun(), "tmp/tmp", False)

    mock_assertion.assert_called_with(expected_call)


@pytest.mark.parametrize(
    (
        "logs,token_expired, time_of_last_fetched_event,"
        "new_events_suspected_duplicates, handling_duplicates,"
        "expected_events, expected_max_value,"
        "expected_new_events_suspected_duplicates"
    ),
    [
        pytest.param(
            [
                b"log1 2020-01-01 00:00:00 -- -- -- -- -- id1",
                b"log2 2020-01-01 00:00:01 -- -- -- -- -- id2",
            ],
            False,
            "",
            [],
            HandlingDuplicates("2020-01-01 00:00:00", ["id2"]),
            [
                "log1 2020-01-01 00:00:00 -- -- -- -- -- id1",
                "log2 2020-01-01 00:00:01 -- -- -- -- -- id2",
            ],
            "2020-01-01 00:00:01",
            ["id2"],
            id="no duplicates and there should a single id in new_events_suspected_duplicates",
        ),
        pytest.param(
            [
                b"log1 2020-01-01 00:01:00 -- -- -- -- -- id1",
                b"log2 2020-01-01 00:01:01 -- -- -- -- -- id2",
                b"log2 2020-01-01 00:01:01 -- -- -- -- -- id3",
            ],
            False,
            "2020-01-01 00:00:59",
            ["id0"],
            HandlingDuplicates("2020-01-01 00:00:00", ["id2"]),
            [
                "log1 2020-01-01 00:01:00 -- -- -- -- -- id1",
                "log2 2020-01-01 00:01:01 -- -- -- -- -- id2",
                "log2 2020-01-01 00:01:01 -- -- -- -- -- id3",
            ],
            "2020-01-01 00:01:01",
            ["id2", "id3"],
            id="no duplicates and there should two ids in new_events_suspected_duplicates",
        ),
    ],
)
def test_parse_events_without_duplicates(
    logs: list[bytes],
    token_expired: bool,
    time_of_last_fetched_event: str,
    new_events_suspected_duplicates: list[str],
    handling_duplicates: HandlingDuplicates,
    expected_events: list[str],
    expected_max_value: str,
    expected_new_events_suspected_duplicates: list[str],
):
    """
    Given:
        - args for parse_events function when `token_expired` is False.
    When:
        - run `parse_events` function with mocked data
    Then:
        - Ensure that events, max_value and new_events_suspected_duplicates are as expected.
    """
    events, max_value = parse_events(
        logs=logs,
        token_expired=token_expired,
        time_of_last_fetched_event=time_of_last_fetched_event,
        new_events_suspected_duplicates=new_events_suspected_duplicates,
        handling_duplicates=handling_duplicates,
    )

    assert events == expected_events
    assert max_value == expected_max_value
    assert new_events_suspected_duplicates == expected_new_events_suspected_duplicates


@pytest.mark.parametrize(
    "logs,token_expired, time_of_last_fetched_event,"
    "new_events_suspected_duplicates, handling_duplicates,"
    "expected_events, expected_max_value,"
    "expected_new_events_suspected_duplicates",
    [
        pytest.param(
            [
                b"log1 2020-01-01 00:01:00 -- -- -- -- -- id1",
                b"log2 2020-01-01 00:01:01 -- -- -- -- -- id2",
                b"log3 2020-01-01 00:01:01 -- -- -- -- -- id3",
                b"log4 2020-01-01 00:01:01 -- -- -- -- -- id4",
            ],
            True,
            "2020-01-01 00:00:59",
            ["id0"],
            HandlingDuplicates("2020-01-01 00:01:01", ["id2", "id3"]),
            [
                "log4 2020-01-01 00:01:01 -- -- -- -- -- id4",
            ],
            "2020-01-01 00:01:01",
            ["id4"],
            id="suspected duplicates and there should a single id in new_events_suspected_duplicates",
        ),
        pytest.param(
            [
                b"log1 2020-01-01 00:01:00 -- -- -- -- -- id1",
                b"log2 2020-01-01 00:01:01 -- -- -- -- -- id2",
                b"log3 2020-01-01 00:01:01 -- -- -- -- -- id3",
                b"log4 2020-01-01 00:01:02 -- -- -- -- -- id4",
            ],
            True,
            "2020-01-01 00:00:59",
            ["id2", "id3"],
            HandlingDuplicates("2020-01-01 00:01:01", ["id2", "id3"]),
            [
                "log4 2020-01-01 00:01:02 -- -- -- -- -- id4",
            ],
            "2020-01-01 00:01:02",
            ["id4"],
            id="suspected duplicates and there should a single id in new_events_suspected_duplicates",
        ),
    ],
)
def test_parse_events_with_duplicates(
    logs: list[bytes],
    token_expired: bool,
    time_of_last_fetched_event: str,
    new_events_suspected_duplicates: list[str],
    handling_duplicates: HandlingDuplicates,
    expected_events: list[str],
    expected_max_value: str,
    expected_new_events_suspected_duplicates: list[str],
):
    """
    Given:
        - args for parse_events function when `token_expired` is True.
    When:
        - run `parse_events` function with mocked data
    Then:
        - Ensure that events, max_value and new_events_suspected_duplicates are as expected.
    """
    events, max_value = parse_events(
        logs=logs,
        token_expired=token_expired,
        time_of_last_fetched_event=time_of_last_fetched_event,
        new_events_suspected_duplicates=new_events_suspected_duplicates,
        handling_duplicates=handling_duplicates,
    )

    assert events == expected_events
    assert max_value == expected_max_value
    assert new_events_suspected_duplicates == expected_new_events_suspected_duplicates


@pytest.mark.parametrize(
    "content",
    [
        b"X-sync-status: test_status\n\rX-sync-token: test_token\n\r",
        b"X-sync-token: test_token\n\rX-sync-status: test_status\n\r",
    ],
)
def test_extract_logs_from_zip_file_without_logs(mocker, content: bytes):
    """
    Given:
        - content of the zip file when it does not contain any logs.
    When:
        - run `extract_logs_from_zip_file` function.
    Then:
        - Ensure demisto.debug is called with "No logs returned from the API" message
          and no exceptions are raised.
    """
    mock_demisto_debug = mocker.patch.object(demisto, "debug")
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tmp_file:
        tmp_file.write(content)
    path = Path(tmp_file.name)
    for _ in extract_logs_from_zip_file(path):
        pass
    mock_demisto_debug.assert_called_with("No logs returned from the API")


def test_extract_logs_from_zip_file_with_logs(tmp_zip_file: Path):
    """
    Given:
        - zip file with multiple gzip files containing logs
    When:
        - run extract_logs_from_zip_file function
    Then:
        - Ensure generator yields contents of each gzip file
    """

    events: list[bytes] = []
    for logs in extract_logs_from_zip_file(tmp_zip_file):
        events.extend(logs)
    assert len(events) == 40


@pytest.mark.parametrize(
    "fetch_interval, expected_fetch_interval",
    [
        (None, DEFAULT_FETCH_SLEEP),
        ("20", DEFAULT_FETCH_SLEEP),
        ("100", 100),
    ],
)
def test_get_fetch_interval(fetch_interval: str | None, expected_fetch_interval: int):
    """
    Given:
        - fetch_interval as str or None
    When:
        - run `get_fetch_interval` function
    Then:
        - Ensure function returns expected fetch interval
    """
    assert get_fetch_interval(fetch_interval) == expected_fetch_interval


@pytest.mark.parametrize(
    "mock_current_time, expected_mock_sleep",
    [
        ([0, 10, 10], 1),
        ([0, DEFAULT_FETCH_SLEEP, 10], 0),
        ([0, DEFAULT_FETCH_SLEEP + 5, 10], 0),
    ],
)
def test_perform_long_running_loop(
    mocker, client: Client, mock_current_time: list[int], expected_mock_sleep: int
):
    """
    Given:
        - client with default value
    When:
        - run perform_long_running_loop function
    Then:
        - Checks whether the functionality of calculating
          the sleep time between fetch and fetch works as expected
    """

    mock_sleep = mocker.patch("time.sleep")

    mocker.patch(
        "SymantecCloudSecureWebGatewayEventCollector.get_current_time_in_seconds",
        side_effect=mock_current_time,
    )
    mocker.patch(
        "SymantecCloudSecureWebGatewayEventCollector.get_integration_context",
        return_value={},
    )
    mocker.patch(
        "SymantecCloudSecureWebGatewayEventCollector.get_events_command",
        side_effect=[[], Exception],
    )

    try:
        perform_long_running_loop(client)
    except Exception:
        pass

    assert mock_sleep.call_count == expected_mock_sleep


def test_test_module(requests_mock, client: Client):
    """
    Given:
        - client with default value
    When:
        - run `test_module` function
    Then:
        - Ensure that returns `ok`
    """
    import SymantecCloudSecureWebGatewayEventCollector

    requests_mock.get(
        "https://api.example.com/reportpod/logs/sync", content=b"event1\nevent2"
    )

    assert SymantecCloudSecureWebGatewayEventCollector.test_module(client, "60") == "ok"


@pytest.mark.parametrize(
    "mock_status_code",
    [423, 429],
)
def test_test_module_blocked_and_rate_limit_exception(
    mocker, client: Client, mock_status_code: int
):
    """
    Given:
        - client with default value
    When:
        - run `test_module` function
    Then:
        - Ensure that returns `ok` when the api call
          raises exception with status code 423 or 429
    """
    import SymantecCloudSecureWebGatewayEventCollector

    class MockException:
        status_code = mock_status_code

    mocker.patch.object(
        client, "get_logs", side_effect=DemistoException("Test", res=MockException())
    )

    assert SymantecCloudSecureWebGatewayEventCollector.test_module(client, "60") == "ok"


@pytest.mark.parametrize(
    "fetch_interval, mock_exception, expected_error_message",
    [
        ("60", ValueError("Test"), "Test"),
        (
            "60",
            ValueError("HTTP Status 401"),
            "Authorization Error: make sure API Key is correctly set",
        ),
        (
            "20",
            None,
            f"The minimum fetch interval is {DEFAULT_FETCH_SLEEP} seconds"
            "Please increase the fetch_interval value and try again.",
        ),
    ],
)
def test_test_module_failure(
    mocker,
    client: Client,
    fetch_interval: str,
    mock_exception: Exception | None,
    expected_error_message: str,
):
    """
    Given:
        - client with default value
    When:
        - run `test_module` function
    Then:
        - Ensure function raises error as expected
    """
    import SymantecCloudSecureWebGatewayEventCollector

    mocker.patch.object(client, "get_logs", side_effect=mock_exception)

    with pytest.raises(ValueError, match=expected_error_message):
        SymantecCloudSecureWebGatewayEventCollector.test_module(client, fetch_interval)
