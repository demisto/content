from datetime import datetime, timedelta
import dateparser


def approximate_compare(time1, time2):
    if isinstance(time1, int):
        time1 = datetime.fromtimestamp(time1 / 1000)
    if isinstance(time2, int):
        time2 = datetime.fromtimestamp(time2 / 1000)

    return timedelta(seconds=-30) <= time1 - time2 <= timedelta(seconds=3)


def test_get_time_range():
    from AlienVault_USM_Anywhere import get_time_range
    from CommonServerPython import date_to_timestamp

    assert get_time_range(None, None, None) == (None, None)

    dt = datetime.now()
    start, end = get_time_range('Today', None, None)
    assert datetime.fromtimestamp(start / 1000).date() == dt.date() and approximate_compare(dt, end)

    dt = datetime.now()
    # should ignore the start/end time values
    start, end = get_time_range('Today', 'asfd', 'asdf')
    assert datetime.fromtimestamp(start / 1000).date() == dt.date() and approximate_compare(dt, end)

    dt = datetime.now()
    start, end = get_time_range('Yesterday', None, None)
    assert datetime.fromtimestamp(start / 1000).date() == (dt.date() - timedelta(days=1)) and approximate_compare(dt, end)

    start, end = get_time_range('Custom', '2019-12-30T01:02:03Z', '2019-12-30T04:05:06Z')
    assert ((start, end) == (date_to_timestamp(dateparser.parse('2019-12-30T01:02:03Z')),
                             date_to_timestamp(dateparser.parse('2019-12-30T04:05:06Z'))))

    start, end = get_time_range('Custom', '2019-12-30T01:02:03Z', None)
    assert (start == date_to_timestamp(dateparser.parse('2019-12-30T01:02:03Z'))
            and approximate_compare(end, datetime.now()))
