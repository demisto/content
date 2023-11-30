import pytest

from AzureSecurityCenter_v2 import MsClient, get_atp_command, get_aps_command, update_atp_command, \
    get_secure_scores_command

# get atp command data
GET_ATP_COMMAND_RAW_RESPONSE = {'properties': {'isEnabled': False},
                                'id': '/subscriptions/subscription_id/resourceGroups/resource_group'
                                      '/providers/Microsoft.Storage/storageAccounts/storage_account/providers'
                                      '/Microsoft.Security/advancedThreatProtectionSettings/current',
                                'name': 'current', 'type': 'Microsoft.Security/advancedThreatProtectionSettings'}
EXPECTED_GET_ATP_COMMAND_CONTEXT = {'AzureSecurityCenter.AdvancedThreatProtection(val.ID && val.ID === obj.ID)': {
    'ID': '/subscriptions/subscription_id/resourceGroups/resource_group/providers/Microsoft.Storage'
          '/storageAccounts/storage_account/providers/Microsoft.Security/advancedThreatProtectionSettings/current',
    'Name': 'current', 'IsEnabled': None}}

# get aps command data
GET_APS_RAW_RESPONSE = {
    'id': '/subscriptions/subscription_id/providers/Microsoft.Security/autoProvisioningSettings/default',
    'name': 'default', 'type': 'Microsoft.Security/autoProvisioningSettings', 'properties': {'autoProvision': 'Off'}}

EXPECTED_GET_APS_CONTEXT = {'AzureSecurityCenter.AutoProvisioningSetting(val.ID && val.ID === obj.ID)': [
    {'Name': 'default', 'AutoProvision': 'Off',
     'ID': '/subscriptions/subscription_id/providers/Microsoft.Security/autoProvisioningSettings/default'}]}

# Update atp command data
UPDATE_ATP_RAW = {'properties': {'isEnabled': True},
                  'id': '/subscriptions/subscription_id/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft'
                        '.Storage/storageAccounts/storage_account/providers/Microsoft.Security'
                        '/advancedThreatProtectionSettings/current',
                  'name': 'current', 'type': 'Microsoft.Security/advancedThreatProtectionSettings'}

EXPECTED_UPDATE_ATP_CONTEXT = {'AzureSecurityCenter.AdvancedThreatProtection(val.ID && val.ID === obj.ID)': {
    'ID': '/subscriptions/subscription_id/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Storage'
          '/storageAccounts/storage_account/providers/Microsoft.Security/advancedThreatProtectionSettings/current',
    'Name': 'current', 'IsEnabled': None}}

# Get secure score command data
GET_SECURE_SCORE_RAW_RESPONSE = {
    'id': '/subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/providers/Microsoft.Security/secureScores/ascScore',
    'name': 'ascScore', 'type': 'Microsoft.Security/secureScores',
    'properties': {'displayName': 'ASC score', 'score': {'max': 58, 'current': 14.51, 'percentage': 0.2502},
                   'weight': 199}}

EXPECTED_GET_SECURE_SCORE_CONTEXT = {'Azure.Securescore(val.ID && val.ID === obj.ID)': {'displayName': 'ASC score',
                                                                                        'score': {'max': 58,
                                                                                                  'current': 14.51,
                                                                                                  'percentage': 0.2502},
                                                                                        'weight': 199}}

client = MsClient(
    server="url", tenant_id="tenant", auth_id="auth_id", enc_key="enc_key", app_name="APP_NAME", verify="verify",
    proxy="proxy", self_deployed="self_deployed", subscription_id="subscription_id", ok_codes=(1, 3),
    certificate_thumbprint=None, private_key=None)


def test_get_atp_command(mocker):
    mocker.patch.object(client, 'get_atp', return_value=GET_ATP_COMMAND_RAW_RESPONSE)
    args = {"resource_group_name": 'test',
            "setting_name": 'test',
            "storage_account": 'test'}
    _, ec, _ = get_atp_command(client, args)
    assert ec == EXPECTED_GET_ATP_COMMAND_CONTEXT


def test_update_atp_command(mocker):
    mocker.patch.object(client, 'update_atp', return_value=UPDATE_ATP_RAW)
    args = {"resource_group_name": "test",
            "setting_name": "test",
            "is_enabled": "test",
            "storage_account": "test"}
    _, ec, _ = update_atp_command(client, args)
    assert ec == EXPECTED_UPDATE_ATP_CONTEXT


def test_get_aps_command(mocker):
    mocker.patch.object(client, 'get_aps', return_value=GET_APS_RAW_RESPONSE)
    args = {"setting_name": 'test'}
    _, ec, _ = get_aps_command(client, args)
    assert ec == EXPECTED_GET_APS_CONTEXT


def test_get_secure_score_command(mocker):
    mocker.patch.object(client, 'get_secure_scores', return_value=GET_SECURE_SCORE_RAW_RESPONSE)
    args = {"secure_score_name": 'ascScore'}
    _, ec, _ = get_secure_scores_command(client, args)
    assert ec == EXPECTED_GET_SECURE_SCORE_CONTEXT


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    from AzureSecurityCenter_v2 import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import demistomock as demisto
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f'^{Resources.management_azure}.*'), json={'value': []})

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'resource_group': 'test_resource_group',
        'server_url': Resources.management_azure,
        'credentials_auth_id': {'password': 'example'}
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in demisto.results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.management_azure]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs
