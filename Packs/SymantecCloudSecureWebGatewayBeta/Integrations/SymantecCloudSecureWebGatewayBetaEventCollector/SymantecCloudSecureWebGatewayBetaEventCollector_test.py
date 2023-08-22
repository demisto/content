import pytest
from freezegun import freeze_time
from requests import Response
import demistomock as demisto
from SymantecCloudSecureWebGatewayEventCollector import (
    Client,
    is_duplicate,
    is_first_fetch,
    get_start_and_ent_date,
    get_status_and_token_from_res,
    extract_logs_from_response
)


class mockResponse(Response):
    def __init__(self, content, status_code) -> None:
        self.status_code = status_code
        self._content = content


@pytest.mark.parametrize(
    "args, expected_results",
    [
        ({"id_": "123", "cur_time": "2023-08-01 00:00:34"}, True),
        ({"id_": "123", "cur_time": "2023-08-01 00:01:34"}, True),
        ({"id_": "000", "cur_time": "2023-08-01 00:02:34"}, False),
        ({"id_": "000", "cur_time": "2023-08-01 00:01:34"}, True),
    ],
)
def test_is_duplicate(args: dict[str, str], expected_results: bool):
    """
    Given:
        - id and event time
    When:
        - run `is_duplicate` function
    Then:
        - Ensure that when given an event whose time is earlier
          than the last time of the last fetch returns True

        - Ensure that when given an event whose time is equal
          to the last time of the last fetch and its id is in the
          list of ids from the last time from the last fetch returns True

        - Ensure that when given an event whose time is later
          than the last time of the last fetch returns False

        - Ensure that when given an event whose time is equal
          to the last time of the last fetch and its id is not in the
          list of ids from the last time from the last fetch returns False
    """
    time_of_last_fetched_event = "2023-08-01 00:01:34"
    events_suspected_duplicates = ["123", "456"]

    result = is_duplicate(
        args["id_"],
        args["cur_time"],
        time_of_last_fetched_event,
        events_suspected_duplicates,
    )
    assert result == expected_results


@pytest.mark.parametrize(
    "last_run, args, expected_results",
    [
        ({}, {}, True),
        ({"start_date": None}, {}, True),
        ({"start_date": "test"}, {}, False),
        ({}, {"since": "test"}, False),
    ],
)
def test_is_first_fetch(
    last_run: dict[str, str | list[str]], args: dict[str, str], expected_results: bool
):
    """
    Given:
        - last_run, args
    When:
        - run `is_first_fetch` function
    Then:
        - Ensure that if there is no a value of
          the `start_date` and there is no `since` key
          in args returns True otherwise False
    """
    result = is_first_fetch(last_run, args)
    assert result == expected_results


@freeze_time("2023-08-01 00:01:34")
@pytest.mark.parametrize(
    "args, start_date, expected_results",
    [
        ({}, "1690837234000", {"start": 1690837234000, "end": 1690830094000}),
        ({}, None, {"start": 1690830034000, "end": 1690830094000}),
        ({"since": "1 minute"}, None, {"start": 1690837234000, "end": 1690830094000}),
    ],
)
def test_get_start_and_ent_date(
    args: dict[str, str], start_date: str, expected_results: dict[str, str]
):
    """
    Given:
        - args, start_date
    When:
        - run `get_start_and_ent_date` function
    Then:
        - Ensure the expected time is returned as timestamp
        - Ensure the expected time is returned when no start_date or since is given in args
    """
    start, end = get_start_and_ent_date(args, start_date)
    assert start == expected_results["start"]
    assert end == expected_results["end"]


@pytest.mark.parametrize(
    "response, expected_results",
    [
        (
            mockResponse(
                content=b"X-sync-token: TESTTESTTESTTESTTESTTESTTESTTEST\r\nX-sync-status: done\r\n",
                status_code=200,
            ),
            {"status": "done", "token": "TESTTESTTESTTESTTESTTESTTESTTEST"},
        ),
        (
            mockResponse(
                content=b"PX//test//test\r\nX-sync-token: TESTTESTTESTTESTTESTTESTTESTTEST\r\nX-sync-status: abort\r\n",
                status_code=200,
            ),
            {"status": "abort", "token": "TESTTESTTESTTESTTESTTESTTESTTEST"},
        )
    ],
)
def test_get_status_and_token_from_res(
    response: mockResponse, expected_results: dict[str, str]
):
    """
    Given:
        - Response
    When:
        - run `get_status_and_token_from_res` function
    Then:
        - Ensure that the `status` and `token` were successfully extracted from the response
    """
    status, token = get_status_and_token_from_res(response)
    assert status == expected_results["status"]
    assert token == expected_results["token"]


def test_extract_logs_from_response_no_events_returned(mocker):
    """
    Given:
        - mock response that is no include zip file
    When:
        - run `extract_logs_from_response` function
    Then:
        - Ensure the function doesn't crash and it prints
          a log with the info that no events were returned
    """
    mock_debug = mocker.patch.object(demisto, "debug")
    content_ = b"X-sync-token: TESTTESTTESTTESTTESTTESTTESTTEST\r\nX-sync-status: done\r\n"
    response = mockResponse(content_, 200)
    extract_logs_from_response(response)
    assert mock_debug.call_args[0][0] == "No events returned from the api"
