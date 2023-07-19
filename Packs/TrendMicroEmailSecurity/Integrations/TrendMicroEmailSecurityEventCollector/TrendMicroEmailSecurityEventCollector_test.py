import pytest
from freezegun import freeze_time
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from TrendMicroEmailSecurityEventCollector import (
    Client,
    order_first_fetch,
    managing_set_last_run,
    fetch_by_event_type,
    fetch_events_command,
    remove_sensitive_from_events,
    generate_id_for_event,
    get_event_ids_with_duplication_risk,
    deduplicate,
    NoContentException,
    DATE_FORMAT_EVENT,
    EventType,
)


@pytest.fixture()
def mock_client() -> Client:
    return Client(
        base_url="test", username="test", api_key="test", verify=False, proxy=False
    )


@pytest.mark.parametrize("first_fetch", [("3 days"), ("32 hours")])
def test_order_first_fetch(first_fetch: str):
    """
    Given:
        - Valid start time of fetch
    When:
        - run order_first_fetch function
    Then:
        - Ensure the function does not throw an error
    """
    assert order_first_fetch(first_fetch)


@pytest.mark.parametrize("first_fetch", [("7 days"), ("4321 minutes")])
def test_order_first_fetch_failure(first_fetch: str):
    """
    Given:
        - Invalid start time of fetch (earlier than 72 hours ago)
    When:
        - run order_first_fetch function
    Then:
        - Ensure that the function throws the expected error
    """
    with pytest.raises(
        ValueError,
        match="The request retrieves logs created within 72 hours at most before sending the request\n"
        "Please put in the First Fetch Time parameter a value that is at most 72 hours / 3 days",
    ):
        order_first_fetch(first_fetch)


def test_handle_error_no_content(mock_client: Client):
    """
    Given:
        - A Response object with status code 204
    When:
        - run `handle_error_no_content` method
    Then:
        - Ensure that the function throws a `NoContentException` error
    """

    class Response:
        status_code = 204

    with pytest.raises(NoContentException, match="No content"):
        mock_client.handle_error_no_content(Response())


def test_handle_error_no_content_with_other_errors(mock_client: Client):
    """
    Given:
        - A Response object with status code 404
    When:
        - run `handle_error_no_content` method
    Then:
        - Ensure the function throws an error that is not a `NoContentException`
    """

    class Response:
        status_code = 404
        reason = "test"

        def json(self):
            return {}

    with pytest.raises(DemistoException):
        mock_client.handle_error_no_content(Response())


@pytest.mark.parametrize(
    "event, expected_results",
    [
        (
            {
                "subject": "test",
                "attachments": [{"fileName": "test", "sha256": "test"}],
            },
            {"attachments": [{"sha256": "test"}]},
        ),
        ({"subject": "test", "attachments": []}, {"attachments": []}),
        ({"subject": "test", "attachments": None}, {"attachments": None}),
    ],
)
def test_remove_sensitive_from_events(event: dict, expected_results: dict):
    """
    Given:
        - Events that contain `subject` or `attachments`
    When:
        - run `remove_sensitive_from_events` function
    Then:
        - Ensure that the keys with the subject or fileName values inside
          the attachments object have been deleted if those values are present in the event
    """
    remove_sensitive_from_events(event)
    assert event == expected_results


def test__encode_authorization(mock_client: Client):
    """
    Given:
        - Dummy username and dummy API key
    When:
        - run `_encode_authorization` method
    Then:
        - Ensure the username and api key are encoded and the expected value is returned
    """
    authorization_encoded = mock_client._encode_authorization("test", "test_api_key")
    assert authorization_encoded == "dGVzdDp0ZXN0X2FwaV9rZXk="


@freeze_time("2023-07-06T15:04:05 UTC")
@pytest.mark.parametrize(
    "events, last_run, event_type, next_token",
    [
        (
            [
                {
                    "messageID": "<11111.11111.11111.1111@mx.test.com>",
                    "subject": "test-test2 - 1111",
                    "size": 3000,
                    "genTime": "2023-07-15T10:00:18Z",
                },
                {
                    "messageID": "<22222.22222.22222.2222@mx.test.com>",
                    "subject": "test1-test2 - 2222",
                    "size": 4000,
                    "genTime": "2023-07-15T10:00:18Z",
                },
                {
                    "messageID": "<33333.33333.33333.3333@mx.test.com>",
                    "subject": "test2-test2 - 3333",
                    "size": 5000,
                    "genTime": "2023-07-14T10:00:18Z",
                }
            ],
            {},
            EventType.ACCEPTED_TRAFFIC,
            "test"
        )
    ],
)
def test_managing_set_last_run(
    events: list[dict], last_run, event_type, next_token
):
    """
    Given:
        - The arguments needed for the `managing_set_last_run` function
    When:
        - run `managing_set_last_run` function
    Then:
        - Ensure that the `last_run` object returns with the `from_time`
          that matches the `event_type` when the API call returns an event with `genTime`
        - Ensure the `time_to` argument is set to be the `from_time`
          when no event returns from the api call
    """
    time_to = datetime.now()

    results = managing_set_last_run(
        events=events,
        last_run=last_run,
        time_to=time_to,
        event_type=event_type,
        next_token=next_token
    )
    assert results


@pytest.mark.parametrize(
    "event_mock, next_token, limit",
    [(({},), "abc%20abc", 1), (({"nextToken": "abc%20abc", "logs": [{}]}, {}), "", 2)],
)
def test_fetch_by_event_type_token_unquote(
    mocker, mock_client: Client, event_mock: tuple[dict], next_token: str, limit: int
):
    """
    Given:
        - next_token with quote character
    When:
        - run fetch_by_event_type function
    Then:
        - Ensure that the next_token argument sent to the API request is unquoted
    """
    mock_api = mocker.patch.object(mock_client, "get_logs", side_effect=event_mock)
    fetch_by_event_type(
        mock_client, "", "", limit, next_token, None, EventType.ACCEPTED_TRAFFIC, False
    )
    assert mock_api.call_args[0][1]["token"] == "abc abc"


@pytest.mark.parametrize(
    "event_mock, limit",
    [
        (({},), 1),
        (({"nextToken": "test", "logs": [{}]}, {}), 2),
        (({"logs": [{}]},), 1),
        (({"nextToken": "test", "logs": [{}]}, {"logs": [{}]}), 2),
        ((NoContentException(),), 1),
        (({"nextToken": "test", "logs": [{}]}, NoContentException()), 2),
    ],
)
def test_fetch_by_event_type_returned_next_token_none(
    mocker, mock_client: Client, event_mock: tuple[dict], limit: int
):
    """
    Given:
        - args for fetch_by_event_type function
    When:
        - run fetch_by_event_type function and return from api request response by event mock
    Then:
        - Ensure that if a response is returned that does not have the "logs" key
          or the "nextToken" key or returned a NoContentException even if ift occurs
          in the second iteration the function returns `next_token == None`
    """
    mocker.patch.object(mock_client, "get_logs", side_effect=event_mock)
    _, next_token = fetch_by_event_type(
        mock_client, "", "", limit, None, None, EventType.ACCEPTED_TRAFFIC, False
    )

    assert not next_token


@pytest.mark.parametrize(
    "event_mock, limit, expected_results",
    [
        pytest.param(
            ({},),
            1,
            {"len_events": 0, "call_count": 1},
            id="No logs and nextToken were returned",
        ),
        pytest.param(
            ({"nextToken": "test", "logs": [{}]}, {}),
            2,
            {"len_events": 1, "call_count": 2},
            id="No logs and nextToken were returned (second iteration)",
        ),
        pytest.param(
            ({"logs": [{}]},),
            1,
            {"len_events": 1, "call_count": 1},
            id="no nextToken returned",
        ),
        pytest.param(
            ({"nextToken": "test", "logs": [{}]}, {"logs": [{}]}),
            2,
            {"len_events": 2, "call_count": 2},
            id="no nextToken returned (second iteration)",
        ),
        pytest.param(
            (NoContentException(),),
            1,
            {"len_events": 0, "call_count": 1},
            id="NoContentException returned",
        ),
        pytest.param(
            ({"nextToken": "test", "logs": [{}]}, NoContentException()),
            2,
            {"len_events": 1, "call_count": 2},
            id="NoContentException returned (second iteration)",
        ),
        pytest.param(
            ({"nextToken": "test", "logs": [{}]}, {"nextToken": "test", "logs": [{}]}),
            2,
            {"len_events": 2, "call_count": 2, "next_token": "test"},
            id="len(events) == limit",
        ),
    ],
)
def test_fetch_by_event_type(
    mocker,
    mock_client: Client,
    event_mock: tuple[dict],
    limit: int,
    expected_results: dict,
):
    """
    Given:
        - args for fetch_by_event_type function
    When:
        - run fetch_by_event_type function and return from api request response by event mock
    Then:
        - Ensure that when no events are returned from the API
          it exits the while loop and returns 0 events.
        - Ensure that when in the second iteration no events are returned from the API,
          it exits the while loop and returns 1 event and the api call is called twice.
        - Ensure that when no `nextToken` returns from the API
          it exits the while loop and returns 1 event
        - Ensure that when in the second iteration `nextToken` does not return from the API
          it exits the while loop and returns 1 event and the api call is called twice.
        - Ensure that when `NoContentException` returns from the API
          it exits the while loop and returns 0 events
        - Ensure that when in the second iteration `NoContentException` returns from the API
          it exits the while loop and returns 1 event and the api call is called twice.
        - Ensure that when the number of events returned from the API is equal to the `limit`
          it exits the while loop and returns the returned events and the `nextToken`.
    """
    mock_api = mocker.patch.object(mock_client, "get_logs", side_effect=event_mock)
    events, next_token = fetch_by_event_type(
        mock_client, "", "", limit, None, None, EventType.ACCEPTED_TRAFFIC, False
    )

    assert len(events) == expected_results["len_events"]
    assert mock_api.call_count == expected_results["call_count"]
    assert next_token == expected_results.get("next_token")


@pytest.mark.parametrize(
    "args, first_fetch, last_run, expected_calls",
    [
        (
            {"max_fetch": 1},
            "2023-02-11T15:47:25Z",
            {},
            [
                {"limit": 1, "start": "2023-02-11T15:47:25Z"},
                {"limit": 1, "start": "2023-02-11T15:47:25Z"},
                {"limit": 1, "start": "2023-02-11T15:47:25Z"},
            ],
        ),
        (
            {
                "max_fetch": 1,
            },
            "2023-02-11T15:47:25Z",
            {
                f"time_{EventType.POLICY_LOGS.value}_from": "2023-07-11T15:47:25Z",
                f"time_{EventType.ACCEPTED_TRAFFIC.value}_from": "2023-08-11T15:47:25Z",
                f"time_{EventType.BLOCKED_TRAFFIC.value}_from": "2023-09-11T15:47:25Z",
            },
            [
                {"limit": 1, "start": "2023-08-11T15:47:25Z"},
                {"limit": 1, "start": "2023-09-11T15:47:25Z"},
                {"limit": 1, "start": "2023-07-11T15:47:25Z"},
            ],
        ),
        (
            {},
            "2023-02-11T15:47:25Z",
            {
                f"time_{EventType.ACCEPTED_TRAFFIC.value}_from": "2023-08-11T15:47:25Z",
                f"time_{EventType.BLOCKED_TRAFFIC.value}_from": "2023-09-11T15:47:25Z",
            },
            [
                {"limit": 5000, "start": "2023-08-11T15:47:25Z"},
                {"limit": 5000, "start": "2023-09-11T15:47:25Z"},
                {"limit": 5000, "start": "2023-02-11T15:47:25Z"},
            ],
        ),
    ],
)
def test_fetch_events_command(
    mocker,
    mock_client: Client,
    args: dict[str, str],
    first_fetch: str,
    last_run: dict[str, str],
    expected_calls: list,
):
    """
    Given:
        - Fetch start time and last_run object and other arguments
    When:
        - run `fetch_events_command` function
    Then:
        - Ensure the `fetch_by_event_type` function is called 3 times,
          each call with the start time and limit that match the event_type
    """
    mock_func = mocker.patch(
        "TrendMicroEmailSecurityEventCollector.fetch_by_event_type",
        return_value=([{"_time": "test", "logType": "test"}], "test"),
    )
    mocker.patch(
        "TrendMicroEmailSecurityEventCollector.managing_set_last_run", return_value={}
    )
    fetch_events_command(mock_client, args, first_fetch, last_run)

    assert mock_func.call_count == 3
    for i in range(3):
        assert mock_func.call_args_list[i][1]["limit"] == expected_calls[i]["limit"]
        assert mock_func.call_args_list[i][1]["start"] == expected_calls[i]["start"]


@pytest.mark.parametrize(
    "event, expected_results",
    [
        (
            {
                "messageID": "<11111.11111.11111.1111@mx.test.com>",
                "subject": "test-test2 - 1111",
                "size": 3000,
            },
            "<11111.11111.11111.1111@mx.test.com>test-test2 - 11113000",
        ),
        (
            {
                "messageID": "<11111.11111.11111.1111@mx.test.com>",
                "subject": None,
                "size": 3000,
            },
            "<11111.11111.11111.1111@mx.test.com>3000",
        ),
        (
            {"messageID": "<11111.11111.11111.1111@mx.test.com>", "size": 3000},
            "<11111.11111.11111.1111@mx.test.com>3000",
        ),
    ],
)
def test_generate_id_for_event(event: dict, expected_results: str):
    """
    Given:
        - event
    When:
        - run `generate_id_for_event` function
    Then:
        - Ensure that ID is returned which is created
          by concatenating 3 values included in the event
    """
    result = generate_id_for_event(event)
    assert result == expected_results


@pytest.mark.parametrize(
    "events, latest_time, expected_results",
    [
        (
            [
                {
                    "messageID": "<11111.11111.11111.1111@mx.test.com>",
                    "subject": "test-test2 - 1111",
                    "size": 3000,
                    "genTime": "2023-07-15T10:00:18Z",
                },
                {
                    "messageID": "<22222.22222.22222.2222@mx.test.com>",
                    "subject": "test1-test2 - 2222",
                    "size": 4000,
                    "genTime": "2023-07-15T10:00:18Z",
                },
                {
                    "messageID": "<33333.33333.33333.3333@mx.test.com>",
                    "subject": "test2-test2 - 3333",
                    "size": 5000,
                    "genTime": "2023-07-14T10:00:18Z",
                },
            ],
            "2023-07-15T10:00:18Z",
            {
                "<11111.11111.11111.1111@mx.test.com>test-test2 - 11113000",
                "<22222.22222.22222.2222@mx.test.com>test1-test2 - 22224000",
            },
        )
    ],
)
def test_get_event_ids_with_duplication_risk(
    events: list[dict], latest_time: str, expected_results: set[str]
):
    results = get_event_ids_with_duplication_risk(events, latest_time)
    assert len(results) == len(expected_results)
    for result in results:
        assert result in expected_results


@pytest.mark.parametrize(
    "events, ids_fetched_by_type, time_from, expected_results",
    [
        (
            [
                {
                    "messageID": "<11111.11111.11111.1111@mx.test.com>",
                    "subject": "test-test2 - 1111",
                    "size": 3000,
                    "genTime": "2023-07-15T10:00:18Z",
                },
                {
                    "messageID": "<22222.22222.22222.2222@mx.test.com>",
                    "subject": "test1-test2 - 2222",
                    "size": 4000,
                    "genTime": "2023-07-15T10:00:18Z",
                },
                {
                    "messageID": "<33333.33333.33333.3333@mx.test.com>",
                    "subject": "test2-test2 - 3333",
                    "size": 5000,
                    "genTime": "2023-07-14T10:00:18Z",
                }
            ],
            {"<11111.11111.11111.1111@mx.test.com>test-test2 - 11113000"},
            "2023-07-15T10:00:18Z",
            2
        ),
        (
            [
                {
                    "messageID": "<11111.11111.11111.1111@mx.test.com>",
                    "subject": "test-test2 - 1111",
                    "size": 3000,
                    "genTime": "2023-07-15T10:00:18Z",
                },
                {
                    "messageID": "<22222.22222.22222.2222@mx.test.com>",
                    "subject": "test1-test2 - 2222",
                    "size": 4000,
                    "genTime": "2023-07-15T10:00:18Z",
                },
                {
                    "messageID": "<33333.33333.33333.3333@mx.test.com>",
                    "subject": "test2-test2 - 3333",
                    "size": 5000,
                    "genTime": "2023-07-14T10:00:18Z",
                }
            ],
            None,
            "2023-07-15T10:00:18Z",
            3
        )
    ]
)
def test_deduplicate(events: list[dict], ids_fetched_by_type: set[str] | None, time_from: str, expected_results):
    results = deduplicate(events, ids_fetched_by_type, time_from)
    assert expected_results == len(results)
