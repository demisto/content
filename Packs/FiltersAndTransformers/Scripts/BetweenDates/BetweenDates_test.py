import pytest
from BetweenDates import is_between_dates

TEST_INPUTS = [
    ('2020-04-06T12:00:00', '2020-04-01T12:00:00', '2020-04-14T12:00:00', True, 'sanity 1'),
    ('2020-04-04T12:00:00', '2020-04-01T10:00:00', '2020-04-04T16:00:00', True, 'sanity 2'),
    ('2020-04-06T12:00:00', '2020-04-01T12:00:00', '2020-06-04T12:00:00', True, 'sanity 3'),

    ('2020-04-04T12:00:00', '2020-04-04T12:00:00', '2020-04-04T12:00:00', True, 'exact same date'),
    ('2020-04-04T12:00:00', '2020-04-04T12:00:00', '2020-04-04T12:00:00', True, 'same as begin date'),
    ('2020-04-04T12:00:00', '2020-04-04T12:00:00', '2020-04-04T12:00:00', True, 'same as end date'),

    ('2020-04-01T12:00:00', '2020-04-04T12:00:00', '2020-05-04T12:00:00', False, 'before begin date'),
    ('2020-05-04T12:00:00', '2020-04-04T12:00:00', '2020-04-14T12:00:00', False, 'after end date'),

    ('2020-04-04T12:00:00+01:00', '2020-04-01T12:00:00+01:00', '2020-06-04T12:00:00Z', True, 'timezone 1'),
    ('2020-04-04T12:00:00+01:00', '2020-04-01T12:00:00Z', '2020-04-04T12:00:00Z', True, 'timezone 2'),
    ('2020-04-04T12:00:00-01:00', '2020-04-01T12:00:00Z', '2020-04-04T12:00:00Z', False, 'timezone 3'),
]


@pytest.mark.parametrize("value, begin_date, end_date, expected_result, test_title", TEST_INPUTS)
def test_is_between_dates(value, begin_date, end_date, expected_result, test_title):
    assert is_between_dates(value, begin_date, end_date) == expected_result, test_title
