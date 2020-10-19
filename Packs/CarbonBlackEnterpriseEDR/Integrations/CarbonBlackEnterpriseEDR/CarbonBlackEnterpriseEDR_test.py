import pytest
import CarbonBlackEnterpriseEDR as cbe
import demistomock as demisto

PROCESS_CASES = [
    (
        {'process_hash': '63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6',
         'process_name': None, 'event_id': None, 'query': None},  # args
        {'criteria': {'process_hash': [
            '63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6']}, 'start': 0}  # expected
    ),
    (
        {"process_name": "svchost.exe,vmtoolsd.exe", 'event_id': None, 'query': None,
         'process_hash': '63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6'},   # args
        {'criteria': {'process_hash': ['63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6'],
                      "process_name": ["svchost.exe", "vmtoolsd.exe"]}, 'start': 0}   # expected
    )
]


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


EVENT_CASES = [
    (
        {"process_guid": "1234", 'event_type': 'modload', 'query': None},  # args
        {'criteria': {'event_type': ['modload']}, 'start': 0}   # expected
    )
]


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
