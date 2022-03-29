import datetime
from GoogleBigQuery import convert_to_string_if_datetime
from CommonServerPython import *


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


def test_get_max_incident_time(mocker):
    mocker.patch.object(demisto, 'params', return_value={'querytoRun': 'test'})
    from GoogleBigQuery import get_max_incident_time

    "%Y-%m-%d %H:%M:%S"
    inc_1 = {
        "rawJSON": '{"CreationTime": "2021-01-01 01:00:00"}'
    }
    inc_2 = {
        "rawJSON": '{"CreationTime": "2021-01-01 01:00:00"}'
    }
    inc_3 = {
        "rawJSON": '{"CreationTime": "2021-01-01 02:00:00"}'
    }

    incs = [inc_2, inc_3, inc_1]
    assert get_max_incident_time(incs) == '2021-01-01 02:00:00.000000'
