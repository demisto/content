import pytest
import json
from CommonServerPython import parse_date_range

HUMAN_READABLE_TIME_FROM_EPOCH_TIME_TEST_CASES = [(1582210145000000, False, '2020-02-20T14:49:05'),
                                                  (1582210145000000, True, '2020-02-20T14:49:05Z')]

QUERY_TIMESTAMPS_TEST_CASES = [
    (
        {'start_time': '2018-04-26 00:00:00', 'end_time': '2020-04-26 00:00:00'},
        ('2018-04-26 00:00:00', '2020-04-26 00:00:00'),
        'Only start time and end time'
    ),
    (
        {'time_range': '1 days'},
        '1 days',
        'Only time range'
    ),
    (
        {'start_time': '2018-04-26 00:00:00',
         'end_time': '2020-04-26 00:00:00',
         'time_range': '1 days'},
        '1 days',
        'Both start/end time and time range'
    )
]


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


@pytest.mark.parametrize('epoch_time, utc_time, expected_response', HUMAN_READABLE_TIME_FROM_EPOCH_TIME_TEST_CASES)
def test_human_readable_time_from_epoch_time(epoch_time, utc_time, expected_response):
    from CortexDataLake import human_readable_time_from_epoch_time
    assert human_readable_time_from_epoch_time(epoch_time, utc_time=utc_time) == expected_response


@pytest.mark.parametrize('args, expected_response, test_case', QUERY_TIMESTAMPS_TEST_CASES)
def test_query_timestamp(args, expected_response, test_case):
    from CortexDataLake import query_timestamp
    if expected_response == '1 days':
        expected_start, expected_end = parse_date_range(expected_response)
        expected_start = expected_start.replace(microsecond=0)
        expected_end = expected_end.replace(microsecond=0)
        generated_start, generated_end = query_timestamp(args)
        generated_start = generated_start
        generated_end = generated_end
        assert (generated_start, generated_end) == (expected_start, expected_end), f'Failed: {test_case}'
    else:
        generated_start, generated_end = query_timestamp(args)
        assert (str(generated_start), str(generated_end)) == expected_response, f'Failed: {test_case}'


def test_parse_tree_by_root_to_leaf_paths():
    from CortexDataLake import parse_tree_by_root_to_leaf_paths
    root = 'a'
    body = {'b': 2, 'c': 3, 'd': {'e': 5, 'f': 6, 'g': {'h': 8, 'i': 9}}}
    expected_output = {'a.b': 2, 'a.c': 3, 'a.d.e': 5, 'a.d.f': 6, 'a.d.g.h': 8, 'a.d.g.i': 9}
    assert expected_output == parse_tree_by_root_to_leaf_paths(root, body)


def test_build_where_clause():
    from CortexDataLake import build_where_clause
    test_cases = [({'query': 'Test'}, 'Test'),
                  ({'source_ip': 'ip1,ip2',
                    'dest_ip': 'ip3,ip4',
                    'rule_matched': 'rule1',
                    'from_zone': 'UTC,UTC2',
                    'dest_port': '555,666',
                    'action': 'allow,unknown',
                    'file_sha_256': 'hash1,hash2',
                    'file_name': 'name1,name2'},
                   '(source_ip.value = "ip1" OR source_ip.value = "ip2") '
                   'AND (dest_ip.value = "ip3" OR dest_ip.value = "ip4") '
                   'AND (rule_matched = "rule1") '
                   'AND (from_zone = "UTC" OR from_zone = "UTC2") '
                   'AND (action.value = "allow" OR action.value = "unknown") '
                   'AND (file_sha_256 = "hash1" OR file_sha_256 = "hash2") '
                   'AND (file_name = "name1" OR file_name = "name2") '
                   'AND (dest_port = 555 OR dest_port = 666)'
                   ),
                  ({'source_ip': 'ip1', 'non_relevant_arg': 'value'}, '(source_ip.value = "ip1")')]
    for args, expected_result in test_cases:
        assert build_where_clause(args) == expected_result


def test_build_where_clause_ip_port():
    from CortexDataLake import build_where_clause
    test_cases = [({'query': 'Test'}, 'Test'),
                  ({'ip': 'ip1,ip2',
                    'port': '555,888'},
                   '(source_ip.value = "ip1" OR dest_ip.value = "ip1" OR '
                   'source_ip.value = "ip2" OR dest_ip.value = "ip2") '
                   'AND (source_port = 555 OR dest_port = 555 OR source_port = 888 OR dest_port = 888)'
                   ),
                  ({'source_ip': 'ip1', 'non_relevant_arg': 'value'}, '(source_ip.value = "ip1")')]
    for args, expected_result in test_cases:
        assert build_where_clause(args) == expected_result


def test_prepare_fetch_incidents_query():
    from CortexDataLake import prepare_fetch_incidents_query
    timestamp = '2020-02-20T16:49:05'
    firewall_subtype = ['attack', 'url']
    fetch_fields = "*"
    firewall_severity = ['Critical', 'High']
    table_name = "firewall.threat"
    fetch_limit = 10
    expected_response = 'SELECT * FROM `firewall.threat` WHERE ' \
                        'time_generated Between TIMESTAMP("2020-02-20T16:49:05") ' \
                        'AND CURRENT_TIMESTAMP AND' \
                        ' (sub_type.value = "attack" OR sub_type.value = "url") AND' \
                        ' (vendor_severity.value = "Critical" OR vendor_severity.value = "High") ' \
                        'ORDER BY time_generated ASC ' \
                        'LIMIT 10'
    assert expected_response == prepare_fetch_incidents_query(timestamp,
                                                              firewall_severity,
                                                              table_name,
                                                              firewall_subtype,
                                                              fetch_fields,
                                                              fetch_limit)


MILLISECONDS_HUMAN_READABLE_TIME_FROM_EPOCH_TIME_TEST_CASES = [(1582017903000000, '2020-02-18T09:25:03.001Z'),
                                                               (1582027208002000, '2020-02-18T12:00:08.003Z')]


@pytest.mark.parametrize('epoch_time, expected_response', MILLISECONDS_HUMAN_READABLE_TIME_FROM_EPOCH_TIME_TEST_CASES)
def test_epoch_to_timestamp_and_add_milli(epoch_time, expected_response):
    from CortexDataLake import epoch_to_timestamp_and_add_milli
    assert epoch_to_timestamp_and_add_milli(epoch_time) == expected_response


def test_get_table_name():
    from CortexDataLake import get_table_name
    query = 'SELECT pcap FROM `firewall.threat` WHERE is_packet_capture = true  AND severity = "Critical" LIMIT 10'
    assert get_table_name(query) == 'firewall.threat'
    query = 'Wrongly formmated query'
    assert get_table_name(query) == 'Unrecognized table name'


def test_query_logs_command_transform_results_1():
    """
    Given:
        - a list of CDL query results
    When
        - running query_logs_command function
    Then
        - if transform_results is not specified, CDL query results are mapped into the CDL common context (test 1)
        - if transform_results is set to false, CDL query results are returned unaltered (test 2)
    """
    from CortexDataLake import query_logs_command

    cdl_records = load_test_data('./test_data/test_query_logs_command_transform_results_original.json')
    cdl_records_xform = load_test_data('./test_data/test_query_logs_command_transform_results_xformed.json')

    class MockClient():
        def query_loggings(self, query):
            return cdl_records, []

    # test 1, with no transform_results options, should transform to common context
    _, results_xform, _ = query_logs_command({'limit': '1', 'query': 'SELECT * FROM `firewall.traffic`'}, MockClient())
    assert results_xform == {'CDL.Logging': cdl_records_xform}

    # test 2, with transform_results options, should transform to common context
    _, results_noxform, _ = query_logs_command(
        {'limit': '1', 'query': 'SELECT * FROM `firewall.traffic`', 'transform_results': 'false'},
        MockClient()
    )
    assert results_noxform == {'CDL.Logging': cdl_records}
