import json
import demistomock as demisto
import pytest

from AzureKubernetesServices import (API_VERSION, AKSClient,
                                     clusters_addon_update, clusters_list)

app_id = 'app_id'
subscription_id = 'subscription_id'
resource_group_name = 'resource_group_name'
tenant_id = 'tentant_id'


@pytest.fixture()
def client(mocker):
    mocker.patch('AzureKubernetesServices.MicrosoftClient.get_access_token', return_value='token')
    return AKSClient(app_id, subscription_id, resource_group_name, False, False, tenant_id, None, 'Device Code')


def load_test_data(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_clusters_list(client, requests_mock):
    """
    Given:
        - AKS Client

    When:
        - Listing clusters

    Then:
        - Verify API request sent as expected
        - Verify command outputs
    """
    api_response = load_test_data('./test_data/clusters_list_response.json')
    requests_mock.get(
        f'{client.ms_client._base_url}/providers/Microsoft.ContainerService/managedClusters?api-version={API_VERSION}',
        json=api_response,
    )
    result = clusters_list(client=client, args={'subscription_id': subscription_id}, params={})
    assert result.outputs == api_response.get('value')


def test_clusters_addon_update(client, requests_mock):
    """
    Given:
        - AKS Client
        - Name and location of resource to update
        - monitoring_agent_enabled boolean argument set as 'true'

    When:
        - Updating cluster addon

    Then:
        - Verify API request sent as expected
        - Verify command outputs
    """
    resource_name = 'resource_name'
    location = 'location'
    api_response = load_test_data('./test_data/clusters_list_response.json').get('value')[0]
    requests_mock.get(
        f'{client.ms_client._base_url}/resourceGroups/{resource_group_name}/providers/Microsoft.ContainerService/'
        f'managedClusters/{resource_name}?api-version={API_VERSION}',
        json=api_response,
    )
    requests_mock.put(
        f'{client.ms_client._base_url}/resourceGroups/{resource_group_name}/providers/Microsoft.ContainerService/'
        f'managedClusters/{resource_name}?api-version={API_VERSION}',
        json=api_response,
    )
    result = clusters_addon_update(
        client=client,
        args={
            'resource_name': resource_name,
            'location': location,
            'monitoring_agent_enabled': 'true',
            'resource_group_name': resource_group_name,
            'subscription_id': subscription_id
        },
        params={}
    )
    assert requests_mock.request_history[1].json() == {
        'location': location,
        'properties': {
            'addonProfiles': {
                'omsagent': {
                    'enabled': True,
                    'config': {'logAnalyticsWorkspaceResourceID': 'workspace'}
                }
            }
        }
    }
    assert result == 'The request to update the managed cluster was sent successfully.'


@pytest.mark.parametrize('params, expected_results', [
    ({'auth_type': 'Device Code'}, "When using device code flow configuration"),
    ({'auth_type': 'Authorization Code'}, "When using user auth flow configuration")])
def test_test_module_command(mocker, params, expected_results):
    """
        Given:
            - Case 1: Integration params with 'Device' as auth_type.
            - Case 2: Integration params with 'User Auth' as auth_type.
        When:
            - Calling test-module command.
        Then
            - Assert the right exception was thrown.
            - Case 1: Should throw an exception related to Device-code-flow config and return True.
            - Case 2: Should throw an exception related to User-Auth-flow config and return True.
    """
    from AzureKubernetesServices import test_module
    import AzureKubernetesServices as aks
    mocker.patch.object(aks, "test_connection", side_effect=Exception('mocked error'))
    mocker.patch.object(demisto, 'params', return_value=params)
    with pytest.raises(Exception) as e:
        test_module(None)
    assert expected_results in str(e.value)


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Scenario: run test module when managed identities client id provided.
    Given:
     - User has provided managed identities client id.
    When:
     - test-module called.
    Then:
     - Ensure the output are as expected
    """
    from AzureKubernetesServices import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import AzureKubernetesServices

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'auth_type': 'Azure Managed Identities',
        'subscription_id': {'password': 'test'},
        'resource_group': 'test_resource_group'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureKubernetesServices, 'return_results')
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in AzureKubernetesServices.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.management_azure]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


def test_test_module_command_with_client_credentials(mocker):
    import AzureKubernetesServices
    from AzureKubernetesServices import main
    mocked_params = {
        'client_id': 'client_id',
        'client_secret': 'client_secret',
        'tenant_id': tenant_id,
        'subscription_id': subscription_id,
        'auth_type': 'Client Credentials'
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureKubernetesServices, 'return_results')
    mocker.patch('AzureKubernetesServices.MicrosoftClient.get_access_token', return_value='token')

    main()

    assert 'ok' in AzureKubernetesServices.return_results.call_args[0][0]


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-ks--generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from AzureKubernetesServices import main
    import AzureKubernetesServices

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'redirect_uri': redirect_uri,
        'auth_type': 'Authorization Code',
        'tenant_id': tenant_id,
        'app_id': client_id,
        'credentials': {
            'identifier': client_id,
            'password': 'client_secret'
        }
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='azure-ks-generate-login-url')
    mocker.patch.object(AzureKubernetesServices, 'return_results')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   'response_type=code&scope=offline_access%20https://management.azure.com/.default' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri})'
    res = AzureKubernetesServices.return_results.call_args[0][0].readable_output
    assert expected_url in res, "Login URL is incorrect"
