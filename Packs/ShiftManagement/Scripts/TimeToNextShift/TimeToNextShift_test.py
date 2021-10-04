import time
from TimeToNextShift import get_time_to_next_shift
from freezegun import freeze_time

# set shift on Saturday from 10:00 to 22:00
ROLES = [{'shifts': [{'fromDay': 6, 'fromHour': 10, 'fromMinute': 0, 'toDay': 6, 'toHour': 22, 'toMinute': 0}]}]


# set time to Saturday, December 12, 2020 12:12:12 PM
@freeze_time(time.ctime(1607775132))
def test_get_time_to_next_shift():
    res = get_time_to_next_shift(ROLES)
    assert res == 35268
