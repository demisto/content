import datetime
from GoogleBigQuery import convert_to_string_if_datetime


def test_convert_to_string_if_datetime():
    test_conversion_for_none = convert_to_string_if_datetime(None)
    assert test_conversion_for_none is None

    now = datetime.datetime.now()
    convert_to_string_if_datetime(now)
    test_conversion_for_empty_string = convert_to_string_if_datetime("")
    assert test_conversion_for_empty_string == ""

    today = datetime.date.today()
    convert_to_string_if_datetime(today)
    test_conversion_for_empty_string = convert_to_string_if_datetime("")
    assert test_conversion_for_empty_string == ""

def test_remove_outdated_incident_ids_keep_equal():
    """
    Given:
    -
    """
    found_incident_ids = {
        'aaa': '2020-05-05 07:07:07.000',
        'bbb': '2020-05-05 08:08:08.000',
        'ccc': '2020-05-05 08:08:09.000',
        'ddd': '2020-05-05 08:08:09.000'
    }
