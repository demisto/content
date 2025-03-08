import pytest
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from pytest_mock import MockerFixture
from SymantecEndpointSecurity import (
    extract_events_suspected_duplicates,
    calculate_next_fetch,
    filter_duplicate_events,
    perform_long_running_loop,
    UnauthorizedToken,
    NextPointingNotAvailable,
    Client,
    test_module as _test_module,
    get_events_command,
    sleep_if_necessary,
)


def mock_client() -> Client:
    return Client(
        base_url="test",
        token="test_token",
        stream_id="test_stream_id",
        channel_id="test_channel_id",
        verify=True,
        proxy=False,
    )


@pytest.mark.parametrize(
    "events, expected_results",
    [
        (
            [
                {"uuid": "123", "log_time": "2024-10-09T12:34:56Z"},
                {"uuid": "456", "log_time": "2024-10-09T12:34:56.789Z"},
                {"uuid": "789", "log_time": "2024-10-09T12:34:55.789Z"},
            ],
            ["456"],
        )
    ],
)
def test_extract_events_suspected_duplicates(
    events: list[dict], expected_results: list[str]
):
    """
    Given
        - A list of events with timestamps
    When:
        - The `extract_events_suspected_duplicates` function is called
    Then:
        - Ensure that return a list of UUIDs for events suspected to be duplicates
    """
    assert extract_events_suspected_duplicates(events) == expected_results


@pytest.mark.parametrize(
    "integration_context, events, expected_filtered_events",
    [
        pytest.param(
            {
                "events_suspected_duplicates": ["123", "456"],
                "latest_event_time": "2024-10-09T12:34:56Z",
            },
            [
                {
                    "uuid": "123",
                    "log_time": "2024-10-09T12:34:56Z",
                    "time": "2024-10-09T12:34:56Z",
                },
                {
                    "uuid": "456",
                    "log_time": "2024-10-09T12:34:56.789Z",
                    "time": "2024-10-09T12:34:56.789Z",
                },
                {
                    "uuid": "789",
                    "log_time": "2024-10-09T12:34:55.789Z",
                    "time": "2024-10-09T12:34:55.789Z",
                },
            ],
            [
                {
                    "uuid": "456",
                    "log_time": "2024-10-09T12:34:56.789Z",
                    "time": "2024-10-09T12:34:56.789Z",
                    "_time": "2024-10-09T12:34:56.789Z"
                }
            ],
            id="Event time is equal to or less than last_event_time",
        ),
        pytest.param(
            {
                "events_suspected_duplicates": ["123"],
                "latest_event_time": "2024-10-09T12:34:56Z",
            },
            [
                {
                    "uuid": "123",
                    "log_time": "2024-10-09T12:34:56Z",
                    "time": "2024-10-09T12:34:56Z",
                },
                {
                    "uuid": "456",
                    "log_time": "2024-10-09T12:34:56.789Z",
                    "time": "2024-10-09T12:34:56.789Z",
                },
            ],
            [
                {
                    "uuid": "456",
                    "log_time": "2024-10-09T12:34:56.789Z",
                    "time": "2024-10-09T12:34:56.789Z",
                    "_time": "2024-10-09T12:34:56.789Z",
                }
            ],
            id="Events time is equal to last_event_time but one of them not include in suspected duplicates",
        ),
        pytest.param(
            {
                "events_suspected_duplicates": ["123"],
                "latest_event_time": "2024-10-09T12:34:56Z",
            },
            [
                {
                    "uuid": "456",
                    "log_time": "2024-10-09T12:35:56.789Z",
                    "time": "2024-10-09T12:35:56.789Z",
                },
            ],
            [
                {
                    "uuid": "456",
                    "log_time": "2024-10-09T12:35:56.789Z",
                    "time": "2024-10-09T12:35:56.789Z",
                    "_time": "2024-10-09T12:35:56.789Z",
                }
            ],
            id="Events time is greater than last_event_time",
        ),
    ],
)
def test_filter_duplicate_events(
    integration_context: dict[str, str],
    events: list[dict[str, str]],
    expected_filtered_events: list[dict[str, str]],
):
    """
    Given:
        - A list of events with timestamps
    When:
        - The `filter_duplicate_events` function is called
    Then:
        - Ensure that a list of the events that are not duplicates is returned
    """
    filtered_events = filter_duplicate_events(events, integration_context)
    assert filtered_events == expected_filtered_events


@pytest.mark.parametrize(
    "filtered_events, next_hash, include_last_fetch_events, last_integration_context, expected_integration_context",
    [
        (
            [
                {"uuid": "12", "log_time": "2024-10-09T12:34:56Z"},
                {"uuid": "34", "log_time": "2024-10-09T12:34:56Z"},
                {"uuid": "56", "log_time": "2024-10-09T12:34:56Z"},
            ],
            "hash_test_1",
            False,
            {
                "latest_event_time": "2024-10-09T12:34:56Z",
                "events_suspected_duplicates": ["78", "90"],
                "next_fetch": {"next": "hash_test"},
                "last_fetch_events": [],
            },
            {
                "latest_event_time": "2024-10-09T12:34:56Z",
                "events_suspected_duplicates": ["12", "34", "56", "78", "90"],
                "next_fetch": {"next": "hash_test_1"},
                "last_fetch_events": [],
            },
        )
    ],
)
def test_calculate_next_fetch_last_latest_event_time_are_equal(
    mocker: MockerFixture,
    filtered_events: list[dict[str, str]],
    next_hash: str,
    include_last_fetch_events: bool,
    last_integration_context: dict[str, str],
    expected_integration_context: dict,
):
    """
    Given:
        - A set of filtered events, next hash, and last integration context
    When:
        - The `calculate_next_fetch` function is called
    Then:
        - Ensure that updated the 'integration_context' with new events in addition to the old ones, and the next hash
    """

    integration_context = calculate_next_fetch(
        filtered_events, next_hash, include_last_fetch_events, last_integration_context
    )

    assert integration_context == expected_integration_context


def test_perform_long_running_loop_unauthorized_token(mocker: MockerFixture):
    """
    Given:
        - The `perform_long_running_loop` function is called
    When:
        - The function is called
    Then:
        - Ensure that the function runs indefinitely until the container is stopped
    """
    mocker.patch(
        "SymantecEndpointSecurity.get_events_command",
        side_effect=[UnauthorizedToken, Exception("Stop")],
    )
    mock_get_token = mocker.patch.object(Client, "_update_access_token_in_headers")
    mocker.patch("SymantecEndpointSecurity.sleep_if_necessary")
    with pytest.raises(DemistoException, match="Failed to fetch logs from API"):
        perform_long_running_loop(mock_client())
    assert mock_get_token.call_count == 2


def test_perform_long_running_loop_next_pointing_not_available(mocker: MockerFixture):
    """
    Given:
        - No args for the function call
    When:
        - The function `perform_long_running_loop` is called
    Then:
        -
    """
    mock_integration_context = {"next_fetch": {"next": "test"}}
    mocker.patch(
        "SymantecEndpointSecurity.get_events_command",
        side_effect=[NextPointingNotAvailable, Exception("Stop")],
    )
    mocker.patch.object(Client, "_update_access_token_in_headers")
    mocker.patch(
        "SymantecEndpointSecurity.get_integration_context",
        return_value=mock_integration_context,
    )
    mocker.patch("SymantecEndpointSecurity.sleep_if_necessary")
    with pytest.raises(DemistoException, match="Failed to fetch logs from API"):
        perform_long_running_loop(mock_client())
    assert mock_integration_context == {'fetch_failure_count': 1}


def test_test_module(mocker: MockerFixture):
    """
    Given:
        - Client
    When:
        - The function `test_module` is called
    Then:
        - Ensure there is no API call in the test_module function
          (see the docstring in the `test_module` function).
    """
    mock__http_request = mocker.patch.object(Client, "_http_request")
    assert _test_module() == "ok"
    mock__http_request.assert_not_called()


@pytest.mark.parametrize(
    "mock_status_code, exception_type",
    [
        (500, DemistoException),
        (401, UnauthorizedToken),
        (410, NextPointingNotAvailable),
    ],
)
def test_get_events_command_with_raises(
    mocker: MockerFixture,
    mock_status_code: int,
    exception_type: type[Exception],
):
    """
    Given:
        - Client and mock_integration_context
    When:
        - The function `get_events_command` is called
    Then:
        - Ensure that the function raises Exception based on the status code that returned from the API call
    """

    class MockException:
        status_code = mock_status_code

    mocker.patch.object(Client, "_update_access_token_in_headers")
    mocker.patch.object(
        Client, "get_events", side_effect=DemistoException("Test", res=MockException())
    )

    with pytest.raises(exception_type):
        get_events_command(mock_client(), {"next_fetch": {"next": "test"}})


@pytest.mark.parametrize(
    "start_run, end_run, call_count",
    [
        pytest.param(10, 20, 1, id="The sleep function should be called once"),
        pytest.param(10, 70, 0, id="The sleep function should not be called"),
    ]
)
def test_sleep_if_necessary(mocker: MockerFixture, start_run: int, end_run: int, call_count: int):
    """
    Given:
        - Mocked time passed duration
    When:
        - The function is called
    Then:
        - Ensure that the sleep function is called with the appropriate interval value or not called at all if unnecessary.
    """
    mock_sleep = mocker.patch("SymantecEndpointSecurity.time.sleep")
    sleep_if_necessary(end_run - start_run)
    assert mock_sleep.call_count == call_count
