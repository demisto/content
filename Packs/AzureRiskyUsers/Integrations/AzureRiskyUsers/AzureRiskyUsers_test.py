import pytest
from AzureRiskyUsers import Client, CLIENT_CREDENTIALS_FLOW, DEVICE_FLOW
import json


BASE_URL = 'https://graph.microsoft.com/v1.0/'
ACCESS_TOKEN_REQUEST_URL = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'


def load_mock_response(file_name: str) -> dict:
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(f'test_data/{file_name}', encoding='utf-8') as json_file:
        return json.loads(json_file.read())


def mock_client():
    return Client(client_id='client_id',
                  verify=False,
                  proxy=False,
                  authentication_type=DEVICE_FLOW)


def test_risky_users_list_command_without_pagination(requests_mock) -> None:
    """
    Scenario: List Risky Users.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - risky_users_list_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from AzureRiskyUsers import risky_users_list_command
    mock_response = load_mock_response('list_risky_users.json')
    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(f'{BASE_URL}identityProtection/riskyUsers', json=mock_response)
    result = risky_users_list_command(mock_client(), {'limit': '20'})
    assert result[0].outputs_prefix == 'AzureRiskyUsers.RiskyUser'
    assert result[0].outputs_key_field == 'id'
    assert len(result[0].raw_response) == 3


def test_risky_users_list_command_with_page_size(requests_mock) -> None:
    """
    Scenario: List Risky Users.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - risky_users_list_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from AzureRiskyUsers import risky_users_list_command
    mock_response = load_mock_response('list_risky_users.json')
    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(f'{BASE_URL}identityProtection/riskyUsers', json=mock_response)
    result = risky_users_list_command(mock_client(), {'page_size': '3'})
    assert result[0].outputs_prefix == 'AzureRiskyUsers.RiskyUser'
    assert result[0].outputs_key_field == 'id'
    assert len(result[0].raw_response) == 3
    assert result[1].outputs == {'AzureRiskyUsers(true)': {'RiskyUserListNextToken': mock_response.get('@odata.nextLink')}}


def test_risky_users_list_command_with_token(requests_mock) -> None:
    """
    Scenario: List Risky Users.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - risky_users_list_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from AzureRiskyUsers import risky_users_list_command
    mock_response = load_mock_response('list_risky_users.json')
    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requested_mock_token = requests_mock.get(f"{BASE_URL}/token", json=mock_response)
    requested_mock_without_token = requests_mock.get(f'{BASE_URL}identityProtection/riskyUsers', json=mock_response)
    result = risky_users_list_command(mock_client(), {"next_token": f"{BASE_URL}/token"})
    assert result[0].outputs_prefix == 'AzureRiskyUsers.RiskyUser'
    assert result[0].outputs_key_field == 'id'
    assert len(result[0].outputs) == 3
    assert len(result[0].raw_response) == 3
    assert result[1].outputs == {'AzureRiskyUsers(true)': {'RiskyUserListNextToken': mock_response.get('@odata.nextLink')}}
    assert requested_mock_token.call_count == 1
    assert requested_mock_without_token.call_count == 0


def test_risky_users_list_command_with_limit(requests_mock) -> None:
    """
    Scenario: List Risky Users.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - risky_users_list_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from AzureRiskyUsers import risky_users_list_command
    mock_response = load_mock_response('list_risky_users.json')
    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(f'{BASE_URL}identityProtection/riskyUsers', json=mock_response)
    result = risky_users_list_command(mock_client(), {'limit': '6'})
    assert len(result) == 1
    assert result[0].outputs_prefix == 'AzureRiskyUsers.RiskyUser'
    assert result[0].outputs_key_field == 'id'
    assert len(result[0].outputs) == 6
    assert 'RiskyUserListNextToken' not in result[0].outputs


def test_risky_users_list_command_with_order_by(requests_mock) -> None:
    """
    Scenario: List Risky Users.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - risky_users_list_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from AzureRiskyUsers import risky_users_list_command
    mock_response = load_mock_response('list_risky_users.json')
    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(f'{BASE_URL}identityProtection/riskyUsers', json=mock_response)

    args = {
        'order_by': 'riskLastUpdatedDateTime desc',
        'limit': '10'
    }

    result = risky_users_list_command(mock_client(), args)
    assert len(result) == 1
    assert result[0].outputs_prefix == 'AzureRiskyUsers.RiskyUser'
    assert result[0].outputs_key_field == 'id'

    assert result[0].outputs[0].get('id') == '111'
    assert 'RiskyUserListNextToken' not in result[0].outputs


def test_risky_users_list_command_with_updated_after(requests_mock) -> None:
    """
    Scenario: List Risky Users.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - risky_users_list_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from AzureRiskyUsers import risky_users_list_command
    mock_response = load_mock_response('list_risky_users.json')
    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(f'{BASE_URL}identityProtection/riskyUsers', json=mock_response)

    args = {
        'updated_after': '500 days ago',
        'limit': '10'
    }

    result = risky_users_list_command(mock_client(), args)
    assert len(result) == 1
    assert result[0].outputs_prefix == 'AzureRiskyUsers.RiskyUser'
    assert result[0].outputs_key_field == 'id'

    assert result[0].outputs[0].get('id') == '111'
    assert 'RiskyUserListNextToken' not in result[0].outputs


def test_risky_user_get_command(requests_mock) -> None:
    """
    Scenario: Get Risky User.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - risky_user_get_command is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
     - Ensure user ID is correct.

    """
    from AzureRiskyUsers import risky_user_get_command
    mock_response = load_mock_response('get_risky_user.json')
    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(f'{BASE_URL}identityProtection/riskyUsers/1', json=mock_response)
    result = risky_user_get_command(mock_client(), args={'id': '1'})
    assert result.outputs_prefix == 'AzureRiskyUsers.RiskyUser'
    assert result.outputs_key_field == 'id'
    assert result.raw_response.get('id') == '1'


def test_risk_detections_list_command(requests_mock) -> None:
    """
    Scenario: List Risk Detections.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - risk_detections_list_command is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
     - Ensure risk detection ID is correct.

    """
    from AzureRiskyUsers import risk_detections_list_command
    mock_response = load_mock_response('list_risk_detections.json')
    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(f'{BASE_URL}identityProtection/riskDetections', json=mock_response)
    result = risk_detections_list_command(mock_client(), {'limit': '20', 'page': '1'})
    assert result.outputs_prefix == 'AzureRiskyUsers.RiskDetection'
    assert result.outputs_key_field == 'id'
    assert result.raw_response.get('value')[0].get('id') == '1'


def test_risk_detection_get_command(requests_mock) -> None:
    """
    Scenario: Get Risk Detection.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - risk_detection_get_command is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
     - Ensure risk detection ID is correct.

    """
    from AzureRiskyUsers import risk_detection_get_command
    mock_response = load_mock_response('get_risk_detection.json')
    requests_mock.post(ACCESS_TOKEN_REQUEST_URL, json={})
    requests_mock.get(f'{BASE_URL}identityProtection/riskDetections/1', json=mock_response)
    result = risk_detection_get_command(mock_client(), args={'id': '1'})
    assert result.outputs_prefix == 'AzureRiskyUsers.RiskDetection'
    assert result.outputs_key_field == 'id'
    assert result.raw_response.get('value')[0].get('id') == '1'


def test_build_query_filter() -> None:
    """
    Scenario: Build query filter for API call.
    Given:
     - Provided valid arguments.
    When:
     - build_query_filter function is called.
    Then:
     - Ensure results are valid.
    """
    from AzureRiskyUsers import build_query_filter
    result = build_query_filter(risk_state='dismissed', risk_level='medium')
    assert result == "riskState eq 'dismissed' and riskLevel eq 'medium'"


def test_get_skip_token() -> None:
    """
    Scenario: Get skip token.
    Given:
     - Provided valid arguments.
    When:
     - get_skip_token function is called.
    Then:
     - Ensure results are valid.
    """
    from AzureRiskyUsers import get_skip_token
    result = get_skip_token(next_link=None,
                            outputs_prefix='AzureRiskyUsers.RiskyUser',
                            outputs_key_field='id',
                            readable_output='test')
    assert result.outputs_prefix == 'AzureRiskyUsers.RiskyUser'
    assert result.outputs_key_field == 'id'
    assert result.readable_output == 'test'


@pytest.mark.parametrize('authentication_type, expected_grant, expected_scope, expected_token_retrieval', [
    (DEVICE_FLOW,
     'urn:ietf:params:oauth:grant-type:device_code',
     'https://graph.microsoft.com/IdentityRiskyUser.Read.All IdentityRiskEvent.ReadWrite.All IdentityRiskyUser.Read.All'
     ' IdentityRiskyUser.ReadWrite.All offline_access',
     'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'),
    (CLIENT_CREDENTIALS_FLOW,
     'client_credentials',
     'https://graph.microsoft.com/.default',
     'https://login.microsoftonline.com//oauth2/v2.0/token')
])
def test_create_client_by_auth_type(authentication_type, expected_grant, expected_scope, expected_token_retrieval):
    """
    Test that the client is created according to the authentication type as expected.

    Given:
     - Authentication type:
        1. Device
        2. Client Credentials
    When:
     - Running the client's instructor.
    Then:
     - Verify that the client's grant type, scope, and token retrieval url are as expected.

    """
    client = Client(client_id='client_id',
                    verify=False,
                    proxy=False,
                    authentication_type=authentication_type)

    assert client.ms_client.grant_type == expected_grant
    assert client.ms_client.scope == expected_scope
    assert client.ms_client.token_retrieval_url == expected_token_retrieval


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Scenario: run test module when managed identities client id provided.
    Given:
     - User has provided managed identities client oid.
    When:
     - test-module called.
    Then:
     - Ensure the output are as expected
    """
    from AzureRiskyUsers import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import AzureRiskyUsers
    import demistomock as demisto

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    params = {
        'managed_identities_client_id': {'password': client_id},
        'authentication_type': 'Azure Managed Identities',
        'subscription_id': {'password': 'test'},
        'resource_group': 'test_resource_group'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureRiskyUsers, 'return_results')
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in AzureRiskyUsers.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


@pytest.mark.parametrize('query,filter_name,filter_value,filter_operator,expected_query', [
    ('', 'riskState', 'dismissed', 'eq', "riskState eq 'dismissed'"),
    ("riskState eq 'dismissed'", 'detectedDateTime', '2022-06-09T23:00:44.7420905Z', 'le',
     "riskState eq 'dismissed' and detectedDateTime le 2022-06-09T23:00:44.7420905Z")
])
def test_update_query(query, filter_name, filter_value, filter_operator, expected_query):
    """
    Scenario: Build query filter for API call.
    Given:
     - Provided valid arguments.
    When:
     - update_query function is called.
    Then:
     - Ensure results are valid.
    """
    from AzureRiskyUsers import update_query
    query = update_query(query, filter_name, filter_value, filter_operator)
    assert query == expected_query


def test_do_pagination_with_next_token(mocker):
    """
    Given:
      - The function arguments: response, limit:
          - The response has a nextLink URL.
          - The limit is greater than the number of results in the first response.
    When:
      - Calling the 'do_pagination' function.
    Then:
      - Assert the request url is as expected - make an API request using the nextLink URL.
      - Verify the function output is as expected
    """
    from AzureRiskyUsers import do_pagination
    mock_response = load_mock_response('list_risky_users.json')
    requests_mock = mocker.patch.object(Client, 'risky_users_list_request', return_value=mock_response)
    limit = 6
    expected_result = mock_response.get('value', []) * 2

    result = do_pagination(mock_client(), mock_response, limit)
    data = result.get('value', [])
    last_next_link = result.get('@odata.nextLink', "")
    assert requests_mock.call_count == 1
    assert data == expected_result
    assert last_next_link == mock_response.get('@odata.nextLink')


def test_do_pagination_without_next_token(mocker):
    """
    Given:
      - The function arguments: response, limit:
          - The response has a nextLink URL.
          - The limit is greater than the number of results in the first response.
    When:
      - Calling the 'do_pagination' function.
    Then:
      - Assert the request url is as expected - make an API request using the nextLink URL.
      - Verify the function output is as expected
    """
    from AzureRiskyUsers import do_pagination
    mock_response = load_mock_response('list_risky_users.json')
    mock_response["@odata.nextLink"] = None
    requests_mock = mocker.patch.object(Client, 'risky_users_list_request', return_value=mock_response)
    limit = 6
    expected_result = mock_response.get('value', [])

    result = do_pagination(mock_client(), mock_response, limit)
    data = result.get('value', [])
    last_next_link = result.get('@odata.nextLink', "")
    assert requests_mock.call_count == 0
    assert data == expected_result
    assert last_next_link == mock_response.get('@odata.nextLink')
