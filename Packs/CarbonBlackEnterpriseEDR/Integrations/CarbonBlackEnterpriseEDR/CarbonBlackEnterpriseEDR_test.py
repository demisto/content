import pytest
import CarbonBlackEnterpriseEDR as cbe
import demistomock as demisto
from freezegun import freeze_time

PROCESS_CASES = [
    (
        {'process_hash': '63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6',
         'process_name': None, 'event_id': None, 'query': None, 'limit': 20, 'start_time': '1 day'},  # args
        {'criteria': {'process_hash': ['63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6']}, 'rows': 20,
         'start': 0, 'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}
        # expected
    ),
    (
        {"process_name": "svchost.exe,vmtoolsd.exe", 'event_id': None, 'query': None, 'limit': 20,
         'start_time': '1 day',
         'process_hash': '63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6'},  # args
        {'criteria': {'process_hash': ['63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6'],
                      "process_name": ["svchost.exe", "vmtoolsd.exe"]}, 'rows': 20, 'start': 0,
         'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}  # expected
    )
]


@freeze_time("2020-11-04T13:34:14.758295Z")
@pytest.mark.parametrize('demisto_args,expected_results', PROCESS_CASES)
def test_create_process_search_body(mocker, demisto_args, expected_results):
    """
    Given:
        - search task's argument

    When:
        - creating a search process task

    Then:
        - validating the body sent to request is matching the search

    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")
    m = mocker.patch.object(client, '_http_request', return_value={})

    client.create_search_process_request(**demisto_args)
    assert m.call_args[1].get('json_data') == expected_results


PROCESS_BAD_CASES = [
    (
        {'process_hash': None, 'process_name': None, 'event_id': None, 'query': None, 'limit': 20},
        # args for missing parameters
        "To perform an process search, please provide at least one of the following: "
        "'process_hash', 'process_name', 'event_id' or 'query'"  # expected
    ),

]


@pytest.mark.parametrize('demisto_args,expected_error_msg', PROCESS_BAD_CASES)
def test_create_process_search_failing(mocker, requests_mock, demisto_args, expected_error_msg):
    """
    Given:
      - search task's argument

    When:
     - creating a search event by process task

    Then:
       - validating the body sent to request is matching the search
    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")
    mocker.patch.object(client, '_http_request', return_value={})

    with pytest.raises(Exception) as e:
        client.create_search_process_request(**demisto_args)
    assert str(e.value) == expected_error_msg


EVENT_CASES = [
    (
        {"process_guid": "1234", 'event_type': 'modload', 'query': None, 'limit': 20, 'start_time': '1 day'},  # args
        {'criteria': {'event_type': ['modload']}, 'rows': 20, 'start': 0,
         'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}  # expected
    ),
    (
        {"process_guid": "1234", 'event_type': 'modload', 'query': None, 'limit': 20, 'start': 20,
         'start_time': '1 day'},  # args
        {'criteria': {'event_type': ['modload']}, 'rows': 20, 'start': 20,
         'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}  # expected
    )
]


@freeze_time("2020-11-04T13:34:14.758295Z")
@pytest.mark.parametrize('demisto_args,expected_results', EVENT_CASES)
def test_create_event_by_process_search_body(mocker, demisto_args, expected_results):
    """
    Given:
        - search task's argument

    When:
        - creating a search event by process task

    Then:
        - validating the body sent to request is matching the search

    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")
    m = mocker.patch.object(client, '_http_request', return_value={})

    client.create_search_event_by_process_request(**demisto_args)
    assert m.call_args[1].get('json_data') == expected_results


EVENT_BAD_CASES = [
    (
        {"process_guid": "1234", 'event_type': 'invalid', 'query': None, 'limit': 20, 'start_time': '1 day'},
        # args for invalid parameters
        "Only the following event types can be searched: "
        "'filemod', 'netconn', 'regmod', 'modload', 'crossproc', 'childproc'"  # expected
    ),
    (
        {"process_guid": "1234", 'event_type': None, 'query': None, 'limit': 20, 'start_time': '1 day'},
        # args for missing parameters
        "To perform an event search, please provide either event_type or query."  # expected
    )
]


@pytest.mark.parametrize('demisto_args,expected_error_msg', EVENT_BAD_CASES)
def test_event_by_process_failing(mocker, requests_mock, demisto_args, expected_error_msg):
    """
    Given:
      - search task's argument

    When:
     - creating a search event by process task

    Then:
       - validating the body sent to request is matching the search
    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")
    mocker.patch.object(client, '_http_request', return_value={})

    with pytest.raises(Exception) as e:
        client.create_search_event_by_process_request(**demisto_args)
    assert str(e.value) == expected_error_msg


# Mock response from the API for testing
MOCK_THREAT_TAGS_RESPONSE = {
    'list': [
        {'tag': 'malware'},
        {'tag': 'suspicious'}
    ]
}


def test_get_threat_tags(mocker):
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")

    # Mock the _http_request method to return the mock response
    mocker.patch.object(client, '_http_request', return_value=MOCK_THREAT_TAGS_RESPONSE)
    threat_id = '123456'
    result = client.get_threat_tags(threat_id)

    # Assert that _http_request was called with the correct parameters
    client._http_request.assert_called_with('GET', f'api/alerts/v7/orgs/{client.cb_org_key}/threats/{threat_id}/tags')

    # Assert the result
    assert result == MOCK_THREAT_TAGS_RESPONSE
