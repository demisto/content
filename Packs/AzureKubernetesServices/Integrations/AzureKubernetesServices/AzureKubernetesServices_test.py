import io
import json

import pytest

from AzureKubernetesServices import (API_VERSION, AKSClient,
                                     clusters_addon_update, clusters_list)

app_id = 'app_id'
subscription_id = 'subscription_id'
resource_group_name = 'resource_group_name'


@pytest.fixture()
def client(mocker):
    mocker.patch('AzureKubernetesServices.MicrosoftClient.get_access_token', return_value='token')
    return AKSClient(app_id, subscription_id, resource_group_name, False, False)


def load_test_data(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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
    result = clusters_list(client=client)
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
        }
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
