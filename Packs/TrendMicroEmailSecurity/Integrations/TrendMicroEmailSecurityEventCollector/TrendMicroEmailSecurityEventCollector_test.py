import pytest
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from TrendMicroEmailSecurityEventCollector import (
    Client,
    order_first_fetch,
    managing_set_last_run,
    fetch_by_event_type,
    fetch_events_command,
    remove_sensitive_from_events,
    NoContentException,
    DATE_FORMAT_EVENT,
)


@pytest.fixture()
def mock_client() -> Client:
    return Client(
        base_url="test", username="test", api_key="test", verify=False, proxy=False
    )


@pytest.mark.parametrize("first_fetch", [("3 days"), ("32 hours")])
def test_order_first_fetch(first_fetch: str):
    assert order_first_fetch(first_fetch)


@pytest.mark.parametrize("first_fetch", [("7 days"), ("4321 minutes")])
def test_order_first_fetch_failure(first_fetch: str):
    with pytest.raises(
        ValueError,
        match="The request retrieves logs created within 72 hours at most before sending the request\n"
        "Please put in the First Fetch Time parameter a value that is at most 72 hours / 3 days",
    ):
        order_first_fetch(first_fetch)


def test_handle_error_no_content(mock_client: Client):
    class Response:
        status_code = 204

    with pytest.raises(NoContentException, match="No content"):
        mock_client.handle_error_no_content(Response())


def test_handle_error_no_content_with_other_errors(mock_client: Client):
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
    remove_sensitive_from_events(event)
    assert event == expected_results


# def test_generate_authorization_encoded(mock_client: Client):
#     authorization_encoded = mock_client.generate_authorization_encoded("test", "test_api_key")
#     assert authorization_encoded == ""


@pytest.mark.parametrize(
    "args, mock_exception, mock_api",
    [
        # In case the len of the event list is smaller than the limit
        (
            {
                "last_run": {},
                "len_events": 1,
                "limit": 2,
                "time_from": "2023-07-05T15:04:05Z",
                "event_type": "accepted_traffic",
                "next_token": "test_test",
            },
            None,
            {},
        ),
        # In case there is no nextToken
        (
            {
                "last_run": {},
                "len_events": 2,
                "limit": 2,
                "time_from": "2023-07-05T15:04:05Z",
                "event_type": "accepted_traffic",
                "next_token": None,
            },
            None,
            {},
        ),
        # In case the len of the event list is equal the limit
        # and when calling the api for the next event, No Content returns.
        (
            {
                "last_run": {"next_token_accepted_traffic": "test_1"},
                "len_events": 2,
                "limit": 2,
                "time_from": "2023-07-05T15:04:05Z",
                "event_type": "accepted_traffic",
                "next_token": "test_token",
            },
            NoContentException("No content"),
            {},
        ),
        # In case the len of the event list is equal the limit
        # and when calling the api for the next event, event returns.
        (
            {
                "last_run": {},
                "len_events": 2,
                "limit": 2,
                "time_from": "2023-07-05T15:04:05Z",
                "event_type": "accepted_traffic",
                "next_token": "test_token",
            },
            None,
            {"nextToken": "test", "logs": [{"genTime": "2023-07-05T16:04:05Z"}]},
        ),
    ],
)
def test_managing_set_last_run(
    mocker,
    mock_client: Client,
    args,
    mock_exception: NoContentException,
    mock_api: dict,
):
    time_to = datetime.now()
    mocker.patch.object(
        mock_client,
        "get_logs_request",
        side_effect=mock_exception,
        return_value=mock_api,
    )
    results = managing_set_last_run(
        client=mock_client,
        len_events=args["len_events"],
        limit=args["limit"],
        last_run=args["last_run"],
        time_from=args["time_from"],
        time_to=time_to,
        event_type=args["event_type"],
        next_token=args["next_token"],
    )

    expected_time_from_for_event_type = mock_api.get("logs", [{}])[0].get(
        "genTime"
    ) or (time_to + timedelta(seconds=1)).strftime(DATE_FORMAT_EVENT)
    assert (
        results.get(f"time_{args['event_type']}_from")
        == expected_time_from_for_event_type
    )


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
    mock_api = mocker.patch.object(
        mock_client, "get_logs_request", side_effect=event_mock
    )
    fetch_by_event_type(mock_client, "", "", limit, next_token, "", False)
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
    mocker.patch.object(mock_client, "get_logs_request", side_effect=event_mock)
    _, next_token = fetch_by_event_type(mock_client, "", "", limit, None, "", False)

    assert not next_token


@pytest.mark.parametrize(
    "event_mock, limit, expected_results",
    [
        (({},), 1, {"len_events": 0, "call_count": 1}),
        (
            ({"nextToken": "test", "logs": [{}]}, {}),
            2,
            {"len_events": 1, "call_count": 2},
        ),
        (({"logs": [{}]},), 1, {"len_events": 1, "call_count": 1}),
        (
            ({"nextToken": "test", "logs": [{}]}, {"logs": [{}]}),
            2,
            {"len_events": 2, "call_count": 2},
        ),
        ((NoContentException(),), 1, {"len_events": 0, "call_count": 1}),
        (
            ({"nextToken": "test", "logs": [{}]}, NoContentException()),
            2,
            {"len_events": 1, "call_count": 2},
        ),
        (
            ({"nextToken": "test", "logs": [{}]}, {"nextToken": "test", "logs": [{}]}),
            2,
            {"len_events": 2, "call_count": 2, "next_token": "test"},
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
    mock_api = mocker.patch.object(
        mock_client, "get_logs_request", side_effect=event_mock
    )
    events, next_token = fetch_by_event_type(mock_client, "", "", limit, None, "", False)

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
                "time_policy_logs_from": "2023-07-11T15:47:25Z",
                "time_accepted_traffic_from": "2023-08-11T15:47:25Z",
                "time_blocked_traffic_from": "2023-09-11T15:47:25Z",
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
                "time_accepted_traffic_from": "2023-08-11T15:47:25Z",
                "time_blocked_traffic_from": "2023-09-11T15:47:25Z",
            },
            [
                {"limit": 1000, "start": "2023-08-11T15:47:25Z"},
                {"limit": 1000, "start": "2023-09-11T15:47:25Z"},
                {"limit": 1000, "start": "2023-02-11T15:47:25Z"},
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
