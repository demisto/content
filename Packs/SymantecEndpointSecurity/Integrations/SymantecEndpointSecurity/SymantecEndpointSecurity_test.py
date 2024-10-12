import pytest
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from pytest_mock import MockerFixture
from SymantecEndpointSecurity import (
    normalize_date_format,
    extract_events_suspected_duplicates,
    update_new_integration_context,
)


@pytest.mark.parametrize(
    "date_str, expected_result",
    [
        ("2024-10-09T12:34:56.789Z", "2024-10-09T12:34:56Z"),
        ("2024-10-09T12:34:56.789324959595959959595Z", "2024-10-09T12:34:56Z"),
    ],
)
def test_normalize_date_format(date_str: str, expected_result: str):
    """
    Given:
        - A date string with microseconds
    When:
        - The `normalize_date_format` function is called
    Then:
        - Ensure that return a date string without microseconds
    """
    assert normalize_date_format(date_str) == expected_result


@pytest.mark.parametrize(
    "events, expected_results",
    [
        (
            [
                {"uuid": "123", "time": "2024-10-09T12:34:56Z"},
                {"uuid": "456", "time": "2024-10-09T12:34:56.789Z"},
                {"uuid": "789", "time": "2024-10-09T12:34:55.789Z"},
            ],
            ["123", "456"],
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
    "filtered_events, next_hash, include_last_fetch_events, last_integration_context, expected_integration_context",
    [
        (
            [
                {"uuid": "12", "time": "2024-10-09T12:34:56Z"},
                {"uuid": "34", "time": "2024-10-09T12:34:56Z"},
                {"uuid": "56", "time": "2024-10-09T12:34:56Z"},
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
def test_update_new_integration_context_last_latest_event_time_are_equal(
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
        - The `update_new_integration_context` function is called
    Then:
        - Ensure that updated the 'integration_context' with new events in addition to the old ones, and the next hash
    """
    mock_set_integration_context = mocker.patch("SymantecEndpointSecurity.set_integration_context")
    update_new_integration_context(
        filtered_events, next_hash, include_last_fetch_events, last_integration_context
    )
    
    assert mock_set_integration_context.call_args[0][0] == expected_integration_context
