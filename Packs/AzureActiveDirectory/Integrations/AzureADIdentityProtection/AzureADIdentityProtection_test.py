import json

import pytest

from AzureADIdentityProtection import (AADClient, azure_ad_identity_protection_risk_detection_list_command)

app_id = 'app_id'
subscription_id = 'subscription_id'
resource_group_name = 'resource_group_name'


@pytest.fixture()
def client(mocker):
    mocker.patch('AzureADIdentityProtection.MicrosoftClient.get_access_token', return_value='token')
    return AADClient(app_id, subscription_id, resource_group_name, verify=False, proxy=False)


def test_list_risks(client, requests_mock):
    """
    Given:
        - AAD Client

    When:
        - Listing risks

    Then:
        - Verify API request sent as expected
        - Verify command outputs
    """
    with open('test_data/risky_users_response.json') as f:
        api_response = json.load(f)
    # response = requests.post(self.token_retrieval_url, data, verify=self.verify)

    requests_mock.get(f'{client.ms_client._base_url}/riskDetections?$top=50', json=api_response)
    result = azure_ad_identity_protection_risk_detection_list_command(client, limit=50)

    expected_values = api_response.get('value')
    actual_values = result.outputs.get('AAD_Identity_Protection.values(val.id === obj.id)')
    assert actual_values == expected_values

    expected_next_link = api_response.get('@odata.nextLink')
    actual_next_url = result.outputs['AAD_Identity_Protection.NextLink(val.Description === "risk_detection_list")'][
        'URL']
    assert actual_next_url == expected_next_link


