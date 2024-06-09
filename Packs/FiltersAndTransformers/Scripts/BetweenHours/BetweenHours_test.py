import pytest
from BetweenHours import is_between_hours

TEST_INPUTS = [
    ('12:00:00', '02:00:00', '21:00:00', True, 'sanity 1'),
    ('12:00:00', '11:10:00', '12:50:00', True, 'sanity 3'),

    ('12:00:00', '12:00:00', '12:00:00', True, 'exact same date'),
    ('12:00:00', '12:00:00', '22:00:00', True, 'same as begin date'),
    ('12:00:00', '10:00:00', '12:00:00', True, 'same as end date'),

    ('10:00:00', '12:00:00', '20:00:00', False, 'before begin date'),
    ('15:00:00', '02:00:00', '12:00:00', False, 'after end date'),

    ('23:00:00', '22:00:00', '02:00:00', True, 'between midnight 1'),
    ('01:00:00', '20:00:00', '05:00:00', True, 'between midnight 2'),

    ('17:00:00', '22:00:00', '02:00:00', False, 'before midnight'),
    ('06:00:00', '20:00:00', '05:00:00', False, 'after midnight')
]


@pytest.mark.parametrize("value, begin_time, end_time, expected_result, test_title", TEST_INPUTS)
def test_is_between_hours(value, begin_time, end_time, expected_result, test_title):
    assert is_between_hours(value, begin_time, end_time) == expected_result, test_title
