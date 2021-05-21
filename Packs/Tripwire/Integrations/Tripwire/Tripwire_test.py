from datetime import datetime

from Tripwire import Client, fetch_incidents, prepare_fetch, filter_nodes, filter_elements, filter_rules, \
    filter_versions
from test_data.raw_response import VERSIONS_RAW_RESPONSE


def test_first_fetch(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        - command raw response
        When
        - mock the Clients's get session token function.
        - mock the Clients's get_versions function.
        Then
        - run the fetch incidents command using the Client
        Validate The length of the results.
        Validate that the first run of fetch incidents runs correctly using the occured time.
        """
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE)
    fetch_filter = 'ruleId=-1:1&timeReceivedRange=2020-10-19T14:20:41Z,2020-11-17T14:20:41Z'
    params = {}
    mocker.patch('Tripwire.prepare_fetch', return_value=(params, fetch_filter, "2020-10-19T14:20:41Z"))
    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)

    _, incidents = fetch_incidents(client=client, max_results=2, params=params)
    assert len(incidents) == 2
    for incident in incidents:
        assert datetime.strptime(incident.get('occurred'), '%Y-%m-%dT%H:%M:%SZ') >= datetime.strptime(
            "2020-10-19T14:20:41Z", '%Y-%m-%dT%H:%M:%SZ')


def test_second_fetch(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        - command raw response
        When
        - mock the Clients's get session token function.
        - mock the Clients's get_versions function.
        Then
        - run the fetch incidents command using the Client
        Validate The length of the results.
        Validate that the second run of fetch incidents runs correctly using the occured time and last fetch.
        """
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE)
    fetch_filter = 'ruleId=-1:1&timeReceivedRange=2020-10-21T09:20:41Z,2020-11-17T14:20:41Z'
    params = {}
    mocker.patch('Tripwire.prepare_fetch', return_value=(params, fetch_filter, "2020-10-21T09:20:41Z"))
    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)

    _, incidents = fetch_incidents(client=client, max_results=4, params=params)
    # there are 4 returned incidents however only 2 occured after last fetch
    assert len(incidents) == 2


def test_empty_fetch(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        - command raw response
        When
        - mock the Clients's get session token function.
        - mock the Clients's get_versions function.
        Then
        - run the fetch incidents command using the Client
        Validate The length of the results which should equal zero as there should be not results.
        """
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE)
    fetch_filter = 'ruleId=-1:1&timeReceivedRange=2020-10-30T09:20:41Z,2020-11-17T14:20:41Z'
    params = {}
    mocker.patch('Tripwire.prepare_fetch', return_value=(params, fetch_filter, "2020-10-30T09:20:41Z"))
    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)

    _, incidents = fetch_incidents(client=client, max_results=2, params=params)
    assert len(incidents) == 0


#   ------------------ helper fucntions -------------------

def test_prepare_fetch():
    """Unit test
        Given
        - fetch params - rule oids , node oids and fetch time
        - expected returned string.
        When
            - the prepare fetch function is activated.
        Then
        - run the prepare fetch helper function.
        Validate the response of the function with the expected string.
        """
    params = {'rule_oids': '-1:1', 'node_oids': '-1:2'}
    params, fetch_filter, _ = prepare_fetch(params, '1 day ago')
    expected_filter = 'ruleId=-1:1&nodeId=-1:2'
    assert expected_filter in fetch_filter


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
