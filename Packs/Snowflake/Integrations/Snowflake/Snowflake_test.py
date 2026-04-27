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
