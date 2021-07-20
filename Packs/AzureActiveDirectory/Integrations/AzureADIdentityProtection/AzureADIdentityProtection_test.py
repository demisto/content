import json

import pytest

from AzureADIdentityProtection import (AADClient, azure_ad_identity_protection_risk_detection_list_command,
                                       azure_ad_identity_protection_risky_users_list_command,
                                       azure_ad_identity_protection_risky_users_history_list_command)

app_id = 'app_id'
subscription_id = 'subscription_id'
resource_group_name = 'resource_group_name'

dummy_user_id = 'dummy_id'


@pytest.fixture()
def client(mocker):
    mocker.patch('AzureADIdentityProtection.MicrosoftClient.get_access_token', return_value='token')
    return AADClient(app_id, subscription_id, resource_group_name, verify=False, proxy=False)


@pytest.mark.parametrize('command,test_data_file,url_suffix,next_link_description,kwargs', (
        (
                azure_ad_identity_protection_risk_detection_list_command,
                'test_data/risk_detections_response.json',
                'riskDetections',
                'risk_detection_list',
                {}
        ),
        (
                azure_ad_identity_protection_risky_users_list_command,
                'test_data/risky_users_response.json',
                'RiskyUsers',
                'risky_user_list',
                {}
        ),
        (
                azure_ad_identity_protection_risky_users_history_list_command,
                'test_data/risky_user_history_response.json',
                f'RiskyUsers/{dummy_user_id}/history',
                'risky_users_history_list',
                {'user_id': dummy_user_id}
        )

))
def test_list_risks(client, requests_mock, command, test_data_file, url_suffix, next_link_description, kwargs):
    """
    Given:
        - AAD Client

    When:
        - Listing (risks, risky users, user history)

    Then:
        - Verify API request sent as expected
        - Verify command outputs
    """
    with open(test_data_file) as f:
        api_response = json.load(f)

    requests_mock.get(f'{client.ms_client._base_url}/{url_suffix}?$top=50', json=api_response)
    result = command(client, limit=50, **kwargs)

    expected_values = api_response.get('value')
    actual_values = result.outputs.get('AAD_Identity_Protection.values(val.id === obj.id)')
    assert actual_values == expected_values

    expected_next_link = api_response.get('@odata.nextLink')
    actual_next_url = result.outputs.get(
        f'AAD_Identity_Protection.NextLink(val.Description === "{next_link_description}")', {}
    ).get('URL')

    if expected_next_link:  # risky_users_history_list does not have next link
        assert actual_next_url == expected_next_link

# def test_clusters_addon_update(client, requests_mock):
#     """
#     Given:
#         - AKS Client
#         - Name and location of resource to update
#         - monitoring_agent_enabled boolean argument set as 'true'
#
#     When:
#         - Updating cluster addon
#
#     Then:
#         - Verify API request sent as expected
#         - Verify command outputs
#     """
#
#
#     resource_name = 'resource_name'
#     location = 'location'
#
#     requests_mock.get(
#         f'{client.ms_client._base_url}/resourceGroups/{resource_group_name}/providers/Microsoft.ContainerService/'
#         f'managedClusters/{resource_name}?api-version={API_VERSION}',
#         json=api_response,
#     )
#     requests_mock.put(
#         f'{client.ms_client._base_url}/resourceGroups/{resource_group_name}/providers/Microsoft.ContainerService/'
#         f'managedClusters/{resource_name}?api-version={API_VERSION}',
#         json=api_response,
#     )
#     result = clusters_addon_update(
#         client=client,
#         args={
#             'resource_name': resource_name,
#             'location': location,
#             'monitoring_agent_enabled': 'true',
#         }
#     )
#     assert requests_mock.request_history[1].json() == {
#         'location': location,
#         'properties': {
#             'addonProfiles': {
#                 'omsagent': {
#                     'enabled': True,
#                     'config': {'logAnalyticsWorkspaceResourceID': 'workspace'}
#                 }
#             }
#         }
#     }
#     assert result == 'The request to update the managed cluster was sent successfully.'
