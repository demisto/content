import pytest
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from TrendMicroEmailSecurityEventCollector import (
    Client,
    order_first_fetch,
    managing_set_last_run,
    NoContentException,
    DATE_FORMAT_EVENT,
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


def test_handle_error_no_content():
    client = Client(
        base_url="test", username="test", api_key="test", verify=False, proxy=False
    )

    class Response:
        status_code = 204

    with pytest.raises(NoContentException, match="No content"):
        client.handle_error_no_content(Response())


def test_handle_error_no_content_without_raises():
    client = Client(
        base_url="test", username="test", api_key="test", verify=False, proxy=False
    )

    class Response:
        status_code = 404
        reason = "test"

        def json(self):
            return {}

    with pytest.raises(DemistoException):
        client.handle_error_no_content(Response())


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
    args,
    mock_exception: NoContentException,
    mock_api: dict,
):
    time_to = datetime.now()
    mocker.patch.object(
        Client, "get_logs_request", side_effect=mock_exception, return_value=mock_api
    )
    client = Client(
        base_url="test", username="test", api_key="test", verify=False, proxy=False
    )
    results = managing_set_last_run(
        client=client,
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
    assert results.get(f"time_{args['event_type']}_from") == expected_time_from_for_event_type
