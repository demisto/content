import datetime
from GoogleBigQuery import convert_to_string_if_datetime


def test_convert_to_string_if_datetime():
    test1 = convert_to_string_if_datetime(None)
    assert test1 is None
    now = datetime.datetime.now()
    convert_to_string_if_datetime(now)
