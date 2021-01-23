import time
from TimeToNextShift import get_time_to_next_shift
from freezegun import freeze_time


ROLES = [{'shifts': [{'fromDay': 6, 'fromHour': 10, 'fromMinute': 0, 'toDay': 6, 'toHour': 22, 'toMinute': 0}]}]


@freeze_time(time.ctime(1607775132))
def test_get_time_to_next_shift():
    res = get_time_to_next_shift(ROLES)
    assert res == 28068
