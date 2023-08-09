import json
import pytest

MOCK_ID = "example_account_1675209608_43_example_search"
REDUNDANT_SEARCH_STATUS = [
    "SearchName",
    "SearchKey",
    "ID",
    "CaseName",
    "MasterToken",
    "SearchPorts",
    "SubmittedTime",
    "MaxChunk",
    "SearchType"
]


def load_json_util(filename: str) -> dict:
    with open(filename, 'r') as f:
        return json.load(f)


def check_redundancy(data: dict, keys: list) -> bool:
    for key in keys:
        if key in data.keys():
            return True
    return False


def test_sentrywire_create_search(requests_mock):
    """
    Scenario: Create a search on a SentryWire unit
    Given:
     - User has supplied valid credentials
     - User has supplied valid search parameters
    When:
     - sentrywire-create-search is called
    Then:
     - Assert prefix is correct
     - Assert number of outputs is 2
     - Assert NodeName
     - Assert SearchID
    """
    from SentryWire import Client, create_search_command
    mock_response = load_json_util('test_data/expected_responses.json').get('create_search')
    requests_mock.post('https://sentrywire:41395/v3/fmlogin', json={'rest_token': 'test'})
    requests_mock.post('https://sentrywire:41395/v3/fmsearch', json=mock_response)
    client = Client('sentrywire', '', '')
    response = create_search_command(client, args={})
    assert response.outputs_prefix == 'SentryWire.Investigator.Search'
    assert len(response.outputs) == 2
    assert response.outputs.get('NodeName')
    assert response.outputs.get('SearchID')


def test_sentrywire_delete_search(requests_mock):
    """
    Scenario: Delete a search on a SentryWire unit
    Given:
     - User has supplied valid credentials
     - User has supplied valid SearchID
    When:
     - sentrywire-delete-search is called
    Then:
     - Assert prefix is correct
     - Assert number of outputs is 2
     - Assert SearchID
     - Assert message
    """
    from SentryWire import Client, delete_search_command
    mock_response = load_json_util('test_data/expected_responses.json').get('delete_search')
    requests_mock.post('https://sentrywire:41395/v3/fmlogin', json={'rest_token': 'test'})
    requests_mock.delete('https://sentrywire:41395/v3/fmsearch', json=mock_response)
    client = Client('sentrywire', '', '')
    response = delete_search_command(client, args={'search_id': MOCK_ID})
    assert response.outputs_prefix == 'SentryWire.Investigator.Deleted'
    assert len(response.outputs) == 2
    assert response.outputs.get('SearchID')
    assert response.outputs.get('message')


@pytest.mark.parametrize('response_type', ('search_completed', 'search_pending', 'search_cancelled'))
def test_sentrywire_get_search_status(response_type, requests_mock):
    """
    Scenario: Get the status of a search completed/pending/cancelled
    Given:
     - User has provided valid SearchID/NodeName
    When:
     - sentrywire-get-search-status is called
    Then:
     - Assert prefix
     - Assert redundant fields have been removed
    """
    from SentryWire import Client, get_search_status_command
    mock_response = load_json_util('test_data/expected_responses.json').get(response_type)
    requests_mock.post('https://sentrywire:41395/v3/fmlogin', json={'rest_token': 'test'})
    requests_mock.get('https://sentrywire:41395/v3/fnsearchstatus', json=mock_response)
    client = Client('sentrywire', '', '')
    response = get_search_status_command(client, args={})
    assert response.outputs_prefix == 'SentryWire.Investigator.Status'
    assert not check_redundancy(response.outputs, REDUNDANT_SEARCH_STATUS)


def test_sentrywire_get_server_status(requests_mock):
    """
    Scenario: Get the status of a SentryWire Unit
    Given:
     - User has supplied valid credentials
    When:
     - sentrywire-get-server-status is called
    Then:
     - Assert prefix is correct
     - Assert number of outputs is 10
    """
    from SentryWire import Client, get_server_status_command
    mock_response = load_json_util('test_data/expected_responses.json').get('server_status')
    requests_mock.post('https://sentrywire:41395/v3/fmlogin', json={'rest_token': 'test'})
    requests_mock.get('https://sentrywire:41395/v3/fmping', json=mock_response)
    client = Client('sentrywire', '', '')
    response = get_server_status_command(client)
    assert response.outputs_prefix == 'SentryWire.Server'
    assert len(response.outputs) == 5
