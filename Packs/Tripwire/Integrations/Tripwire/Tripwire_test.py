from datetime import datetime

from Tripwire import Client, fetch_incidents, get_fetch_start_time, filter_nodes, filter_elements, filter_rules, \
    filter_versions
from test_data.raw_response import VERSIONS_RAW_RESPONSE
import demistomock as demisto


"""
Fetch cases:
1. time progress - the time_detected of the last alert will be used for the next fetch
2. paging progress - page_start should be != 0
"""


def test_page_start_progress_fetch(mocker):
    """
    Given -
        alerts with the same timeDetected value
    When -
        search for versions
    Then -
        validate that the next run object contains the correct page_start
    """
    limit = 2
    last_run_date = '2020-10-20T14:17:59Z'
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE[:limit])
    mocker.patch.object(demisto, 'getLastRun', return_value={"lastRun": last_run_date})

    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)

    last_run, incidents = fetch_incidents(client=client, max_results=limit, params={})

    fetch_filter = Client.get_versions.call_args[0][0]
    assert f'pageLimit={limit}' in fetch_filter
    assert 'pageStart' not in fetch_filter
    assert last_run['lastRun'] == last_run_date
    assert last_run['page_start'] == len(incidents)
    assert last_run['fetched_ids'] == [version['id'] for version in VERSIONS_RAW_RESPONSE[:limit]]


def test_time_progress_fetch(mocker):
    """
    Given -
        alerts with different timeDetected value
    When -
        search for versions
    Then -
        validate that the next run object contains the correct page_start
    """
    limit = 3
    last_run_date = '2020-10-20T14:17:59Z'
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE[:limit])
    mocker.patch.object(demisto, 'getLastRun', return_value={"lastRun": last_run_date})

    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)

    last_run, incidents = fetch_incidents(client=client, max_results=limit, params={})

    fetch_filter = Client.get_versions.call_args[0][0]
    assert f'pageLimit={limit}' in fetch_filter
    assert 'pageStart' not in fetch_filter
    expected_last_run = datetime.strptime(VERSIONS_RAW_RESPONSE[limit - 1]['timeDetected'], '%Y-%m-%dT%H:%M:%S.000Z')
    datetime.strptime(last_run['lastRun'], '%Y-%m-%dT%H:%M:%SZ') == expected_last_run
    assert last_run['page_start'] == 0
    assert last_run['fetched_ids'] == [version['id'] for version in VERSIONS_RAW_RESPONSE[:limit]]


def test_pagination_fetch(mocker):
    """
    Given -
        get alerts with the same timeDetected value in second fetch after getting alerts with same timeDetected value
    When -
        search for versions
    Then -
        validate the pageStart are in the filter
    """
    limit = 2
    page_start = 3
    last_run_date = '2020-10-20T14:17:59Z'
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE[:limit])
    mocker.patch.object(demisto, 'getLastRun', return_value={"lastRun": last_run_date, 'page_start': page_start})

    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)

    last_run, incidents = fetch_incidents(client=client, max_results=limit, params={})

    fetch_filter = Client.get_versions.call_args[0][0]
    assert f'pageLimit={limit}' in fetch_filter
    assert f'pageStart={page_start}' in fetch_filter
    expected_last_run = datetime.strptime(VERSIONS_RAW_RESPONSE[limit - 1]['timeDetected'], '%Y-%m-%dT%H:%M:%S.000Z')
    datetime.strptime(last_run['lastRun'], '%Y-%m-%dT%H:%M:%SZ') == expected_last_run
    assert last_run['page_start'] == page_start + len(incidents)
    assert last_run['fetched_ids'] == [version['id'] for version in VERSIONS_RAW_RESPONSE[:limit]]


#   ------------------ helper fucntions -------------------

def test_get_fetch_start_time(mocker):
    """Unit test
        Given
            -
        When
            - the get_fetch_start_time is activated.
        Then
            - Validate the result are correct (the same as of the getLastRun obj).
        """
    expected_start_detected_time = "2018-10-24T14:13:20Z"
    last_run_obj = {"lastRun": expected_start_detected_time}
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run_obj)
    start_detected_time = get_fetch_start_time({}, last_run_obj)
    assert start_detected_time == expected_start_detected_time


def test_filter_nodes():
    """
    Given
        - params dict which include all the available params of the nodes-list-command.
        - expected returned string.
    When
         - the filter nodes function is activated.
    Then
        - run the filter nodes helper function.
    Validate the response of the function with the expected string.
    """
    params = {
        'node_oids': '1',
        'node_ips': '2',
        'node_mac_adresses': '3',
        'node_names': '4',
        'node_os_names': '5',
        'tags': '6',
        'limit': '7',
        'start': '8'
    }
    filter_node = filter_nodes(params)
    expected_filter = 'id=1&ipAddress=2&macAddress=3&ic_name=4&make=5&tag=6&pageLimit=7&pageStart=8'

    assert expected_filter in filter_node


def test_filter_elements():
    """
    Given
        - params dict which include all the available params of the elements-list-command.
        - expected returned string.
    When
         - the filter elements function is activated.
    Then
        - run the filter elements helper function.
    Validate the response of the function with the expected string.
    """
    params = {
        'element_oids': '1',
        'element_names': '2',
        'node_oids': '3',
        'rule_oids': '4',
        'baseline_version_ids': '5',
        'last_version_id': '6',
        'limit': '7',
        'start': '8'
    }
    filter_node = filter_elements(params)
    expected_filter = 'id=1&name=2&nodeId=3&ruleId=4&baselineVersionId=5&lastVersionId=6&pageLimit=7&pageStart=8'
    assert expected_filter in filter_node


def test_filter_rules():
    """
    Given
        - params dict which include all the available params of the rules-list-command.
        - expected returned string.
    When
         - the filter rules function is activated.
    Then
        - run the filter rules helper function.
    Validate the response of the function with the expected string.
    """
    params = {
        'rule_oids': '1',
        'rule_names': '2',
        'rule_types': '3',
        'limit': '4',
        'start': '5',
    }
    filter_rule = filter_rules(params)
    expected_filter = 'id=1&name=2&type=3&pageLimit=4&pageStart=5'
    assert expected_filter in filter_rule


def test_filter_versions():
    """
    Given
        - params dict which include all the available params of the versions-list-command.
        - expected returned string.
    When
         - the filter versions function is activated.
    Then
        - run the filter versions helper function.
    Validate the response of the function with the expected string.
    """
    params = {
        'rule_oids': '1',
        'rule_names': '2',
        'node_oids': '3',
        'version_oids': '4',
        'element_oids': '5',
        'element_names': '6',
        'node_names': '7',
        'version_hashes': '8',
        'baseline_version_ids': '9',
        'start_detected_time': '2020-11-24T17:07:27Z',
        'end_detected_time': '2020-11-24T17:07:27Z',
        'start_received_time': '2020-11-24T17:07:27Z',
        'end_received_time': '2020-11-24T17:07:27Z',
        'limit': '10',
        'start': '11',
    }
    filter_version = filter_versions(params)
    expected_filter = 'ruleId=1&ruleName=2&nodeId=3&id=4&elementId=5&elementName=6&nodeLabel=7&hash=8&baselineVersion' \
                      '=9&timeDetectedRange=2020-11-24T17:07:27Z,' \
                      '2020-11-24T17:07:27Z&timeReceivedRange=2020-11-24T17:07:27Z,' \
                      '2020-11-24T17:07:27Z&pageLimit=10&pageStart=11'
    assert expected_filter in filter_version
