import pytest
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from SymantecEndpointSecurity import (
    normalize_date_format,
    extract_events_suspected_duplicates,
)


@pytest.mark.parametrize(
    "date_str, expected_result",
    [
        ("2024-10-09T12:34:56.789Z", "2024-10-09T12:34:56Z"),
        ("2024-10-09T12:34:56.789324959595959959595Z", "2024-10-09T12:34:56Z")
    ]
)
def test_normalize_date_format(date_str: str, expected_result: str):
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
            ["123", "456"]
        )
    ]
)
def test_extract_events_suspected_duplicates(events: list[dict], expected_results: list[str]):
    assert extract_events_suspected_duplicates(events) == expected_results