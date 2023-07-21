import pytest

from CommonServerPython import DemistoException
from ExabeamDataLake import _handle_time_range_query


@pytest.mark.parametrize(
    "args, expected",
    [
        (
            {"start_time": 1689943882318, "end_time": 1689944782318},
            {
                "rangeQuery": {
                    "field": "@timestamp",
                    "gte": "1689943882318",
                    "lte": "1689944782318",
                }
            },
        ),
        (
            {"start_time": 1689943882318, "end_time": None},
            {"rangeQuery": {"field": "@timestamp", "gte": "1689943882318"}},
        ),
    ],
)
def test_handle_time_range_query(args: dict, expected: dict):
    assert _handle_time_range_query(**args) == expected


def test_handle_time_range_query_raise_error():
    """
    Tests that the function raises a DemistoException when start_time is greater than end_time
    """

    start_time = 1626393600
    end_time = 1626307200
    with pytest.raises(DemistoException, match="Start time must be before end time"):
        _handle_time_range_query(start_time, end_time)
