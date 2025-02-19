import datetime
import json

import demistomock as demisto


def test_convert_to_string():
    from GoogleBigQuery import convert_to_string
    test_conversion_for_none = convert_to_string(None)
    assert test_conversion_for_none is None

    now = datetime.datetime.now()
    convert_to_string(now)
    test_conversion_for_empty_string = convert_to_string("")
    assert test_conversion_for_empty_string == ""

    today = datetime.date.today()
    convert_to_string(today)
    test_conversion_for_empty_string = convert_to_string("")
    assert test_conversion_for_empty_string == ""

    assert convert_to_string(b'test') == 'test'
    assert convert_to_string('test') == 'test'


def test_remove_outdated_incident_ids_keep_equal():
    """
    Given:
    - Several incidents with different occurrence times.
    - A start time that is equal to the occurrence time of one of the incidents.

    When:
    - Using the remove_outdated_incident_ids function to remove outdated incidents.

    Then:
    - Incidents that date before the start time will be removed.
    - Incidents that date after it will remain.
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
    - A start time of the current run.
    - One incident with a more recent occurrence time.

    When:
    - Using the remove_outdated_incident_ids function to remove outdated incidents.

    Then:
    - The incident will remain in the result.
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
    - A start time of the current run.
    - An empty list of incidents

    When:
    - Using the remove_outdated_incident_ids function to remove outdated incidents.

    Then:
    - The function will work as expected and will successfully handle the case.
    """
    from GoogleBigQuery import remove_outdated_incident_ids
    found_incidents_ids = {}

    latest_incident_time_str = '2020-05-05 08:08:09.000'
    res = remove_outdated_incident_ids(found_incidents_ids, latest_incident_time_str)
    assert 'aaa' not in res and 'bbb' not in res


def test_verify_params_all_existing(mocker):
    """
    Given:
    - Demisto params that include the first_fetch_time, fetch_query and fetch_time_field params.

    When:
    - Activating the verify_params function.

    Then:
    - No error will be returned.
    """
    from GoogleBigQuery import verify_params
    mock_params = {
        'first_fetch_time': "1 days",
        'fetch_query': "test",
        'fetch_time_field': "test"
    }

    mocker.patch.object(demisto, 'params', return_value=mock_params)

    return_error_target = 'GoogleBigQuery.return_error'
    return_error_mock = mocker.patch(return_error_target)
    verify_params()
    assert return_error_mock.call_count == 0


def test_verify_params_first_fetch_time_missing(mocker):
    """
    Given:
    - Demisto params that don't include the first_fetch_time param.

    When:
    - Activating the verify_params function.

    Then:
    - An error will be returned.
    """
    from GoogleBigQuery import verify_params

    mock_params = {
        'fetch_query': "test",
        'fetch_time_field': "test"
    }
    mocker.patch.object(demisto, 'params', return_value=mock_params)

    return_error_target = 'GoogleBigQuery.return_error'

    return_error_mock = mocker.patch(return_error_target)
    verify_params()
    assert return_error_mock.call_count == 1

    mock_params = {
        'first_fetch_time': '',
        'fetch_query': "test",
        'fetch_time_field': "test"
    }
    mocker.patch.object(demisto, 'params', return_value=mock_params)

    verify_params()
    assert return_error_mock.call_count == 2


def test_verify_params_fetch_query_missing(mocker):
    """
    Given:
    - Demisto params that don't include the fetch_query param.

    When:
    - Activating the verify_params function.

    Then:
    - An error will be returned.
    """
    from GoogleBigQuery import verify_params

    mock_params = {
        'first_fetch_time': "1 days",
        'fetch_time_field': "test"
    }
    mocker.patch.object(demisto, 'params', return_value=mock_params)

    return_error_target = 'GoogleBigQuery.return_error'

    return_error_mock = mocker.patch(return_error_target)
    verify_params()
    assert return_error_mock.call_count == 1

    mock_params = {
        'first_fetch_time': "1 days",
        'fetch_query': "",
        'fetch_time_field': "test"
    }
    mocker.patch.object(demisto, 'params', return_value=mock_params)

    verify_params()
    assert return_error_mock.call_count == 2


def test_verify_params_fetch_time_field_missing(mocker):
    """
    Given:
    - Demisto params that don't include the fetch_time_field param.

    When:
    - Activating the verify_params function.

    Then:
    - An error will be returned.
    """
    from GoogleBigQuery import verify_params

    mock_params = {
        'first_fetch_time': "1 days",
        'fetch_query': "test",
    }
    mocker.patch.object(demisto, 'params', return_value=mock_params)

    return_error_target = 'GoogleBigQuery.return_error'

    return_error_mock = mocker.patch(return_error_target)
    verify_params()
    assert return_error_mock.call_count == 1

    mock_params = {
        'first_fetch_time': "1 days",
        'fetch_query': "test",
        'fetch_time_field': ""
    }
    mocker.patch.object(demisto, 'params', return_value=mock_params)

    verify_params()
    assert return_error_mock.call_count == 2


def test_get_max_incident_time_single_incident():
    """
    Given:
    - Several incidents with different occurrence times.

    When:
    - Activating the get_max_incident_time function.

    Then:
    - The time of the incident with the maximal time will be returned.
    """
    from GoogleBigQuery import get_max_incident_time

    incident = {
        'rawJSON': {
            'CreationTime': '2020-05-05 08:08:09'
        }
    }

    incident['rawJSON'] = json.dumps(incident['rawJSON'])
    incidents = [incident]

    assert get_max_incident_time(incidents) == '2020-05-05 08:08:09.000000'


def test_get_max_incident_time_several_incidents():
    """
    Given:
    - One incident with an occurrence time.

    When:
    - Activating the get_max_incident_time function.

    Then:
    - The case will be handled successfully.
    """
    from GoogleBigQuery import get_max_incident_time

    incident_a = {
        'rawJSON': {
            'CreationTime': '2020-05-05 08:08:09'
        }
    }

    incident_b = {
        'rawJSON': {
            'CreationTime': '2020-05-06 08:08:09'
        }
    }

    incident_c = {
        'rawJSON': {
            'CreationTime': '2020-05-06 09:08:09'
        }
    }

    incident_d = {
        'rawJSON': {
            'CreationTime': '2020-05-06 09:09:09'
        }
    }

    incident_a['rawJSON'] = json.dumps(incident_d['rawJSON'])
    incident_b['rawJSON'] = json.dumps(incident_d['rawJSON'])
    incident_c['rawJSON'] = json.dumps(incident_d['rawJSON'])
    incident_d['rawJSON'] = json.dumps(incident_d['rawJSON'])

    incidents = [incident_d, incident_a, incident_c, incident_b]

    assert get_max_incident_time(incidents) == '2020-05-06 09:09:09.000000'
