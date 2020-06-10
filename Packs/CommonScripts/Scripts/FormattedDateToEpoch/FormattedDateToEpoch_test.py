import pytest
from FormattedDateToEpoch import date_to_epoch


@pytest.mark.parametrize(
    "date,formatter,expected_result", [
        ('2020-03-31T13:19:41.000+0100', "%Y-%m-%dT%H:%M:%S.%f%z", 1585657181),
        ('2020-03-31T13:19:41.000+0000', '%Y-%m-%dT%H:%M:%S.%f%z', 1585660781),
        pytest.param("2020-03-31T13:19:41.000+0100", "%Y-%m-%dT%H:%M:%S.%f%z", 1585657181, marks=pytest.mark.xfail)
    ])
def test_date_to_epoch(date, formatter, expected_result):
    assert date_to_epoch(date, formatter) == expected_result
