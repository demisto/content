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
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as json_file:
        return json.loads(json_file.read())


def mock_client():
    return Client(client_id='client_id',
                  verify=False,
                  proxy=False,
                  authentication_type=DEVICE_FLOW)


def test_risky_users_list_command(requests_mock) -> None:
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
    result = risky_users_list_command(mock_client(), {'limit': '20', 'page': '1'})
    assert result.outputs_prefix == 'AzureRiskyUsers.RiskyUser'
    assert result.outputs_key_field == 'id'
    assert len(result.raw_response) == 3


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
