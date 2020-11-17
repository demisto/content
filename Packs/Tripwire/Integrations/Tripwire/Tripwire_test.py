from datetime import datetime

import pytest

from Tripwire import Client, fetch_incidents
from test_data.raw_response import VERSIONS_RAW_RESPONSE


def test_first_fetch(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        - command raw response
        When
        - mock the Clients's get token function.
        - mock the Clients's tickets_list_request.
        - mock the parse_date_range function.
        Then
        - run the fetch incidents command using the Client
        Validate The length of the results.
        Validate that the first run of fetch incidents runs correctly.
        """
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE)
    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)
    fetch_filter = {'rule_oids': '-1:1',
                    'time_received_range': '2020-10-19T14:20:41Z,2020-11-17T14:20:41Z'}
    _, incidents = fetch_incidents(client=client, max_results=2, last_fetch="2020-10-19T14:20:41Z",
                                   fetch_filter=fetch_filter)
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
        - mock the Clients's get token function.
        - mock the Clients's tickets_list_request.
        - mock the parse_date_range function.
        Then
        - run the fetch incidents command using the Client
        Validate The length of the results.
        Validate that the first run of fetch incidents runs correctly.
        """
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE)
    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)
    fetch_filter = {'ruleId': '-1:1&timeReceivedRange=2020-10-30T14:20:41Z,2020-11-17T14:20:41Z'}
    _, incidents = fetch_incidents(client=client, max_results=4, last_fetch="2020-10-21T09:20:41Z",
                                   fetch_filter=fetch_filter)
    # there are 4 returned incidents however only 2 occured after last fetch
    assert len(incidents) == 2


def test_empty_fetch(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        - command raw response
        When
        - mock the Clients's get token function.
        - mock the Clients's tickets_list_request.
        - mock the parse_date_range function.
        Then
        - run the fetch incidents command using the Client
        Validate The length of the results.
        Validate that the first run of fetch incidents runs correctly.
        """
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE)
    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)
    fetch_filter = {'ruleId': '-1:1&timeReceivedRange=2020-10-30T14:20:41Z,2020-11-17T14:20:41Z'}
    _, incidents = fetch_incidents(client=client, max_results=4, last_fetch="2020-10-30T09:20:41Z",
                                   fetch_filter=fetch_filter)
    assert len(incidents) == 0

def test_empty_fetch(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        - command raw response
        When
        - mock the Clients's get token function.
        - mock the Clients's tickets_list_request.
        - mock the parse_date_range function.
        Then
        - run the fetch incidents command using the Client
        Validate The length of the results.
        Validate that the first run of fetch incidents runs correctly.
        """
    mocker.patch.object(Client, 'get_session_token')
    mocker.patch.object(Client, 'get_versions', return_value=VERSIONS_RAW_RESPONSE)
    client = Client(base_url="http://test.com", auth=("admin", "123"), verify=False, proxy=False)
    fetch_filter = {'ruleId': '-1:1&timeReceivedRange=2020-10-30T14:20:41Z,2020-11-17T14:20:41Z'}
    _, incidents = fetch_incidents(client=client, max_results=4, last_fetch="2020-10-30T09:20:41Z",
                                   fetch_filter=fetch_filter)
    assert len(incidents) == 0
