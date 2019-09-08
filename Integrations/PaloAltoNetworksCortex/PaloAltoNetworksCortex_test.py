import random
import string
import demistomock as demisto
from datetime import datetime, timedelta

""" Helper functions """


def random_string(string_length=10) -> str:
    """Generate a random string of fixed length

    Args:
        string_length (int): length of string to return

    Returns:
        str: random string
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(string_length))


def test_get_start_time(mocker):
    integration_context = {
        'stored': int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds()),
        'access_token': 'dummy'
    }
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context)

    from PaloAltoNetworksCortex import get_start_time

    five_minutes_start_time = get_start_time('minutes', 5)
    expected_response = datetime.now() - timedelta(minutes=5)
    assert five_minutes_start_time.replace(microsecond=0) == expected_response.replace(microsecond=0)

    ten_days_start_time = get_start_time('days', 10)
    expected_response = datetime.now() - timedelta(days=10)
    assert ten_days_start_time.replace(microsecond=0) == expected_response.replace(microsecond=0)

    four_weeks_start_time = get_start_time('weeks', 4)
    expected_response = datetime.now() - timedelta(weeks=4)
    assert four_weeks_start_time.replace(microsecond=0) == expected_response.replace(microsecond=0)


def test_process_incident_pairs():
    from PaloAltoNetworksCortex import process_incident_pairs
    incident_pairs = [
        (1, datetime.fromtimestamp(1)),
        (3, datetime.fromtimestamp(3)),
        (2, datetime.fromtimestamp(2)),
    ]
    incidents, max_ts = process_incident_pairs(incident_pairs, 3)
    assert incidents[2] == 3
    assert max_ts == datetime.fromtimestamp(3)
    incidents, max_ts = process_incident_pairs(incident_pairs, 2)
    assert incidents[1] == 2
    assert len(incidents) == 2
    assert max_ts == datetime.fromtimestamp(2)


def test_prepare_fetch_query(mocker):
    from PaloAltoNetworksCortex import prepare_fetch_query, main

    traps_params = {
        'fetch_query': 'Traps Threats',
    }
    mocker.patch.object(demisto, 'params',
                        return_value=traps_params)
    main()
    traps_fetch_timestamp = '2018-04-22T10:34:07.371267Z'

    traps_query = prepare_fetch_query(traps_fetch_timestamp)
    assert traps_query == "SELECT * FROM tms.threat WHERE serverTime>'2018-04-22T10:34:07.371267Z'"

    traps_params['traps_severity'] = ['critical', 'high']
    traps_query_with_severity = prepare_fetch_query(traps_fetch_timestamp)
    assert traps_query_with_severity == "SELECT * FROM tms.threat WHERE serverTime>'2018-04-22T10:34:07.371267Z' " \
                                        "AND (messageData.trapsSeverity='critical' OR messageData.trapsSeverity='high')"

    firewall_params = {
        'fetch_query': 'Firewall Threats',
    }
    mocker.patch.object(demisto, 'params',
                        return_value=firewall_params)
    main()
    firewall_fetch_timestamp = '1524383011'

    firewall_query = prepare_fetch_query(firewall_fetch_timestamp)
    assert firewall_query == "SELECT * FROM panw.threat WHERE receive_time>1524383011"

    firewall_params['firewall_severity'] = ['medium']
    firewall_query_with_severity = prepare_fetch_query(firewall_fetch_timestamp)
    assert firewall_query_with_severity == "SELECT * FROM panw.threat " \
                                           "WHERE receive_time>1524383011 AND (severity='medium')"

    firewall_params['firewall_subtype'] = ['url', 'antivirus']
    firewall_query_with_severity_and_subtype = prepare_fetch_query(firewall_fetch_timestamp)
    assert firewall_query_with_severity_and_subtype == "SELECT * FROM panw.threat WHERE receive_time>1524383011 " \
                                                       "AND (subtype='url' OR subtype='antivirus') " \
                                                       "AND (severity='medium')"

    xdr_params = {
        'fetch_query': 'Cortex XDR Analytics',
    }
    mocker.patch.object(demisto, 'params',
                        return_value=xdr_params)
    main()
    xdr_fetch_timestamp = '2018-04-22T10:34:07.371267Z'

    xdr_query = prepare_fetch_query(xdr_fetch_timestamp)
    assert xdr_query == "SELECT * FROM magnifier.alert WHERE time_generated>2018-04-22T10:34:07.371267Z " \
                        "AND sub_type.keyword = 'New'"

    xdr_params['xdr_severity'] = ['High', 'Medium']
    xdr_query_with_severity = prepare_fetch_query(xdr_fetch_timestamp)
    assert xdr_query_with_severity == "SELECT * FROM magnifier.alert WHERE " \
                                      "time_generated>2018-04-22T10:34:07.371267Z AND " \
                                      "(alert.severity.keyword='High' OR alert.severity.keyword='Medium') AND " \
                                      "sub_type.keyword = 'New'"


def test_get_encrypted():
    from PaloAltoNetworksCortex import get_encrypted
    auth_id = random_string(50)
    auth_key = random_string(32)
    get_encrypted(auth_id, auth_key)
