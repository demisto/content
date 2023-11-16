import gzip
from freezegun import freeze_time
import pytest
from SymantecCloudSecureWebGatewayLongRunningEventCollector import (
    LastRun,
    get_events_and_write_to_file_system,
    Client,
    get_size_gzip_file,
    get_start_and_ent_date,
    get_status_and_token_from_file_system,
    get_the_last_row_that_incomplete,
    is_duplicate,
    is_first_fetch,
)
import demistomock as demisto
from pathlib import Path


@pytest.fixture()
def client():
    return Client("https://api.example.com", "user", "pass", False, False)


def test_write_events_to_file(requests_mock, client):
    requests_mock.get(
        "https://api.example.com/reportpod/logs/sync", content=b"event1\nevent2"
    )

    params = {}
    tmp_file_path = get_events_and_write_to_file_system(client, params, LastRun())

    # validate file exists and has expected content
    assert tmp_file_path.exists()
    assert tmp_file_path.read_text() == "event1\nevent2"


@pytest.mark.parametrize(
    "args, start_date, expected_start, expected_end",
    [
        ({}, None, 1577822340000, 1577822400000),
        ({"since": "2020-01-01T00:00:00Z"}, None, 1577829600000, 1577822400000),
        ({}, 1600, 1600, 1577822400000),
    ],
)
def test_get_start_and_end_date(args, start_date, expected_start, expected_end):
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
        start, end = get_start_and_ent_date(args, start_date)

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
def test_extract_status_and_token(
    tmpdir, content_file: bytes, expected_status: str, expected_token: str
):
    """
    Given:
        - A file containing a status and a token
        - A large file containing a status and token at the end
        - An empty file
    When:
        - run the `get_status_and_token_from_file_system` function
    Then:
        - Cases 1-2: Ensure the status and token are extracted as expected from the file
        - Case 3: Ensure the function returns empty strings for status and token
    """
    tmp_file = Path(tmpdir / "test.zip")
    tmp_file.write_bytes(content_file)
    status, token = get_status_and_token_from_file_system(tmp_file)
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
def test_extract_last_incomplete_line(
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


@pytest.mark.parametrize('last_run, args, expected', [
    ({}, {}, True),
    ({'start_date': 123}, {}, False),
    ({}, {'since': '1'}, False),
    (None, {}, True),
])
def test_is_first_fetch(last_run, args, expected):
    assert is_first_fetch(last_run, args) == expected


@pytest.mark.parametrize('id_, cur_time, last_time, dup_ids, expected', [
    ('id1', '2020-01-01 00:00:00', '2020-01-01 00:00:00', ['id1'], True),
    ('id2', '2020-01-01 00:00:00', '2020-01-01 00:00:00', ['id1'], False), 
    ('id3', '2020-01-01 00:01:00', '2020-01-01 00:00:00', ['id1'], False)
])
def test_is_duplicate(id_, cur_time, last_time, dup_ids, expected):
    ''''''
    assert is_duplicate(id_, cur_time, last_time, dup_ids) == expected