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
    from GoogleBigQuery import remove_outdated_incident_ids
    found_incidents_ids = {
        'aaa': '2020-05-05 07:07:07.000',
        'bbb': '2020-05-05 08:08:08.000',
        'ccc': '2020-05-05 08:08:09.000',
        'ddd': '2020-05-05 08:08:09.001'
    }

    latest_incident_time_str = '2020-05-05 08:08:09.000'
    res = remove_outdated_incident_ids(found_incidents_ids, latest_incident_time_str)
    assert 'aaa' not in res and 'bbb' not in res
    assert 'ddd' in res


def test_remove_outdated_incident_ids_keep_equal_one_incident():
    """
    Given:
    -
    """
    from GoogleBigQuery import remove_outdated_incident_ids
    found_incidents_ids = {
        'ddd': '2020-05-05 08:08:09.001'
    }

    latest_incident_time_str = '2020-05-05 08:08:09.000'
    res = remove_outdated_incident_ids(found_incidents_ids, latest_incident_time_str)
    assert 'ddd' in res


def test_remove_outdated_incident_ids_keep_equal_no_incidents():
    """
    Given:
    -
    """
    from GoogleBigQuery import remove_outdated_incident_ids
    found_incidents_ids = {}

    latest_incident_time_str = '2020-05-05 08:08:09.000'
    res = remove_outdated_incident_ids(found_incidents_ids, latest_incident_time_str)
    assert 'aaa' not in res and 'bbb' not in res


