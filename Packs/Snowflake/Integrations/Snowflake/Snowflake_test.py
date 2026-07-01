from datetime import datetime
from CommonServerPython import *
import pytest


@pytest.mark.parametrize(
    "time, expected_results",
    [
        (datetime(2024, 8, 14, 22, 43, 9, 851000), "2024-08-14 22:43:09.85"),
        (datetime(2024, 8, 14, 22, 43, 9), "2024-08-14 22:43:09.00"),
    ],
)
def test_convert_datetime_to_string(mocker, time, expected_results):
    """
    Given:
    - A datetime object
    - Case 1: datetime with microseconds
    - Case 2: datetime without microseconds
    When:
    - Calling convert_datetime_to_string()
    Then:
    - Ensure the datetime is converted to a string in the expected format (only 2 numbers after the decimal point)
    """
    mocker.patch.object(demisto, "params", return_value={})
    from Packs.Snowflake.Integrations.Snowflake.Snowflake import convert_datetime_to_string

    results = convert_datetime_to_string(time)
    assert results == expected_results


@pytest.mark.parametrize(
    "raw_scope, expected",
    [
        ("scope1,scope2,scope3", "scope1 scope2 scope3"),
        ("session:role:analyst,   session:role:reader", "session:role:analyst session:role:reader"),
        ("scope1, scope2 , scope3", "scope1 scope2 scope3"),
        ("", None),
        (None, None),
        (",,,", None),
        ("scope1,,scope2", "scope1 scope2"),
    ],
)
def test_parse_oauth_scope(mocker, raw_scope, expected):
    """
    Given:
    - A raw OAuth scope string (comma-separated or single)
    - Case 1: Multiple scopes comma-separated
    - Case 2: Single scope
    - Case 3: Multiple scopes with extra whitespace
    - Case 4: Empty string
    - Case 5: None value
    - Case 6: Only commas
    - Case 7: Scopes with empty entries between commas
    When:
    - Calling parse_oauth_scope()
    Then:
    - Ensure the scopes are converted to space-separated format, or None for empty input
    """
    mocker.patch.object(demisto, "params", return_value={})
    from Packs.Snowflake.Integrations.Snowflake.Snowflake import parse_oauth_scope

    result = parse_oauth_scope(raw_scope)
    assert result == expected
