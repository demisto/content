from datetime import date, timedelta


def test_get_time_frame():
    from LogRhythmRest import get_time_frame

    date_format = "%Y-%m-%d"
    today = date.today()

    start, end = get_time_frame('Today', None, None)
    assert end.strftime(date_format) == today.strftime(date_format)
    assert start.strftime(date_format) == today.strftime(date_format)

    start, end = get_time_frame('Last2Days', None, None)
    assert end.strftime(date_format) == today.strftime(date_format)
    assert start.strftime(date_format) == (today - timedelta(days=2)).strftime(date_format)

    start, end = get_time_frame('LastWeek', None, None)
    assert end.strftime(date_format) == today.strftime(date_format)
    assert start.strftime(date_format) == (today - timedelta(days=7)).strftime(date_format)

    start, end = get_time_frame('LastMonth', None, None)
    assert end.strftime(date_format) == today.strftime(date_format)
    assert start.strftime(date_format) == (today - timedelta(days=30)).strftime(date_format)

    start, end = get_time_frame('Custom', '2019-04-01', '2019-04-20')
    assert end.strftime(date_format) == '2019-04-20'
    assert start.strftime(date_format) == '2019-04-01'
