import random
import string
import demistomock as demisto
from datetime import datetime, timedelta
from pytest import raises
from CommonServerPython import *
from freezegun import freeze_time


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


@freeze_time("2021-2-21 21:00:00")
def test_get_start_time(mocker):
    integration_context = {
        'stored': int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds()),
        'access_token': 'dummy'
    }
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context)

    from PaloAltoNetworksCortex import get_start_time

    five_minutes_start_time = get_start_time('minutes', 5)
    expected_response = datetime.now() - timedelta(minutes=5)
    assert five_minutes_start_time == expected_response

    ten_days_start_time = get_start_time('days', 10)
    expected_response = datetime.now() - timedelta(days=10)
    assert ten_days_start_time == expected_response

    four_weeks_start_time = get_start_time('weeks', 4)
    expected_response = datetime.now() - timedelta(weeks=4)
    assert four_weeks_start_time == expected_response


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


class TestParseFunctions:
    def test_verify_table_fields(self):
        from PaloAltoNetworksCortex import verify_table_fields
        table_fields = ['risk-of-app', 'all', 'aaa', 'config_ver', '3dx', 'users', 'from']
        fields_list_all_input = 'risk-of-app,config_ver,all,users'
        fields_list_negative_input = 'xyz,risk-of-app'
        fields_list_positive_input = 'risk-of-app,config_ver,users,from'
        fields_list_positive_output = "risk-of-app,config_ver,users,'from'"
        fields_list_all_output = '*'
        # All test
        assert fields_list_all_output == verify_table_fields(fields_list_all_input, table_fields)
        # Positive test
        assert fields_list_positive_output == verify_table_fields(fields_list_positive_input, table_fields)
        # Raising exception test
        with raises(DemistoException, match='xyz is not a valid field of the query'):
            verify_table_fields(fields_list_negative_input, table_fields)

    def test_logs_human_readable_output_generator(self):
        from PaloAltoNetworksCortex import logs_human_readable_output_generator
        raw_results = [
            {
                'severity': 'emergency',
                'eventType': 'AgentSecurityEvent',
                'endPointHeader': {
                    'userName': 'Administrator',
                    'agentIp': '8.8.8.8',
                    'deviceName': 'PC123',
                    'agentTime': '2019-03-25T11:01:04.896Z'
                },
                'uuid': 'x1z2y3',
                'dstrbd1': 'dstrbd2',
                'recsize': 2825,
                'dstrbd2': 'dstrbd3',
                'facility': 'TrapsAgent'
            }
        ]
        headers_all = ['Severity', 'Event Type', 'User', 'Agent Address', 'Agent Name', 'Agent Time']
        headers_gc = ['uuid', 'recsize', 'facility']
        table_name = 'traps'
        filtered_results_all = [
            {
                'Severity': 'emergency',
                'Event Type': 'AgentSecurityEvent',
                'User': 'Administrator',
                'Agent Address': '8.8.8.8',
                'Agent Name': 'PC123',
                'Agent Time': '2019-03-25T11:01:04.896Z'
            }
        ]
        filtered_results_gc = [
            {
                'uuid': 'x1z2y3',
                'recsize': 2825,
                'facility': 'TrapsAgent'
            }
        ]
        fields_all_input = '*'
        fields_gc_input = 'uuid,recsize,facility'
        # All case test
        assert tableToMarkdown(f'Logs {table_name} table', filtered_results_all, headers=headers_all) \
            == logs_human_readable_output_generator(fields_all_input, table_name, raw_results)
        # General case test
        assert tableToMarkdown(f'Logs {table_name} table', filtered_results_gc, headers=headers_gc, removeNull=True) \
            == logs_human_readable_output_generator(fields_gc_input, table_name, raw_results)

    def test_build_where_clause(self):
        from PaloAltoNetworksCortex import build_where_clause
        table_args_dict = {'ip': ['src=', 'dst='], 'url': ['misc LIKE '], 'query': []}
        args_general_case_input = {'ip': '8.8.8.8', 'url': 'google.com', 'test': 'test'}
        args_query_case_input = {'ip': '8.8.8.8', 'test': 'test', 'query': " action='allow' AND packets='1'"}
        args_general_case_output = "src='8.8.8.8' OR dst='8.8.8.8' OR misc LIKE '*google.com*'"
        args_query_case_output = "action='allow' AND packets='1'"
        # General case test
        assert args_general_case_output == build_where_clause(args_general_case_input, table_args_dict)
        # Query case test
        assert args_query_case_output == build_where_clause(args_query_case_input, table_args_dict)

    def test_parse_tree_by_root_to_leaf_paths(self):
        from PaloAltoNetworksCortex import parse_tree_by_root_to_leaf_paths
        root = 'a'
        body = {'b': 2, 'c': 3, 'd': {'e': 5, 'f': 6, 'g': {'h': 8, 'i': 9}}}
        expected_output = {'a.b': 2, 'a.c': 3, 'a.d.e': 5, 'a.d.f': 6, 'a.d.g.h': 8, 'a.d.g.i': 9}
        assert expected_output == parse_tree_by_root_to_leaf_paths(root, body)
