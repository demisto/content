from AzureSecurityCenter_v2 import MsClient, get_atp_command, get_aps_command, update_atp_command


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
client = MsClient(
    server="url", tenant_id="tenant", auth_id="auth_id", enc_key="enc_key", app_name="APP_NAME", verify="verify",
    proxy="proxy", self_deployed="self_deployed", subscription_id="subscription_id", ok_codes=(1, 3))


def test_get_atp_command(mocker):
    mocker.patch.object(client, 'get_atp', return_value=GET_ATP_COMMAND_RAW_RESPONSE)
    args = {"resource_group_name": 'test',
            "setting_name": 'test',
            "storage_account": 'test'}
    _, ec, _ = get_atp_command(client, args)
    assert EXPECTED_GET_ATP_COMMAND_CONTEXT == ec


def test_update_atp_command(mocker):
    mocker.patch.object(client, 'update_atp', return_value=UPDATE_ATP_RAW)
    args = {"resource_group_name": "test",
            "setting_name": "test",
            "is_enabled": "test",
            "storage_account": "test"}
    _, ec, _ = update_atp_command(client, args)
    assert EXPECTED_UPDATE_ATP_CONTEXT == ec


def test_get_aps_command(mocker):
    mocker.patch.object(client, 'get_aps', return_value=GET_APS_RAW_RESPONSE)
    args = {"setting_name": 'test'}
    _, ec, _ = get_aps_command(client, args)
    assert EXPECTED_GET_APS_CONTEXT == ec
