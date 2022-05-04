import base64
import json
import re
import traceback
from typing import Any, Dict, List, Optional, Tuple

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

register_module_line('Microsoft Graph Device Management', 'start', __line__())


''' IMPORTS '''

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBAL VARS '''

SPECIAL_HEADERS: dict = {
    'id': 'ID',
    'userId': 'User ID',
    'osVersion': 'OS Version',
    'imei': 'IMEI',
    'meid': 'MEID'
}

HEADERS: dict = {
    'raw_device': ['id', 'userId', 'deviceName', 'operatingSystem', 'osVersion', 'emailAddress',
                   'manufacturer', 'model', 'imei', 'meid'],
}


''' CLIENT '''


class MsGraphClient:
    def __init__(self, self_deployed, tenant_id, auth_and_token_url, enc_key, app_name, base_url, use_ssl, proxy,
                 ok_codes, certificate_thumbprint, private_key):
        self.ms_client = MicrosoftClient(self_deployed=self_deployed, tenant_id=tenant_id, auth_id=auth_and_token_url,
                                         enc_key=enc_key, app_name=app_name, base_url=base_url, verify=use_ssl,
                                         proxy=proxy, ok_codes=ok_codes, certificate_thumbprint=certificate_thumbprint,
                                         private_key=private_key)

    def list_managed_devices(self, limit: int) -> Tuple[list, Any]:
        url_suffix: str = '/deviceManagement/managedDevices'
        raw_response = self.ms_client.http_request('GET', url_suffix)
        return raw_response.get('value', [])[:limit], raw_response

    def find_managed_device(self, device_name: str) -> Tuple[Any, str]:
        url_suffix: str = f"/deviceManagement/managedDevices?$filter=deviceName eq '{device_name}'"
        raw_response = self.ms_client.http_request('GET', url_suffix)
        return raw_response.get('value', []), raw_response

    def get_managed_device(self, device_id: str) -> Tuple[Any, str]:
        url_suffix: str = f'/deviceManagement/managedDevices/{device_id}'
        return self.ms_client.http_request('GET', url_suffix), device_id

    def make_action(self, device_id: str, action: str, body: str = None) -> None:
        url_suffix: str = f'deviceManagement/managedDevices/{device_id}/{action}'
        self.ms_client.http_request('POST', url_suffix, data=body, return_empty_response=True)

    def delete_user_from_shared_apple_device(self, user_principal_name: str, device_id: str, action: str) -> None:
        body: dict = {'userPrincipalName': user_principal_name}
        self.make_action(device_id, action, json.dumps(body))

    def clean_windows_device(self, keep_user_data: bool, device_id: str, action: str) -> None:
        body: dict = {'keepUserData': keep_user_data}
        self.make_action(device_id, action, json.dumps(body))

    def windows_device_defender_scan(self, quick_scan: bool, device_id: str, action: str) -> None:
        body: dict = {'quickScan': quick_scan}
        self.make_action(device_id, action, json.dumps(body))

    def wipe_device(self, keep_enrollment_data: bool, keep_user_data: bool, mac_os_unlock_code: str,
                    device_id: str, action: str) -> None:
        body: dict = {
            'keepEnrollmentData': keep_enrollment_data,
            'keepUserData': keep_user_data
        }
        if mac_os_unlock_code:
            body['macOsUnlockCode'] = mac_os_unlock_code
        self.make_action(device_id, action, json.dumps(body))

    def update_windows_device_account(self, device_account_password: str, password_rotation_enabled: bool,
                                      calendar_sync_enabled: bool, device_account_email: str, exchange_server: str,
                                      session_initiation_protocal_address: str, device_id: str, action: str) -> None:
        body: dict = {
            'updateWindowsDeviceAccountActionParameter': {
                '@odata.type': 'microsoft.graph.updateWindowsDeviceAccountActionParameter',
                'deviceAccount': {
                    '@odata.type': 'microsoft.graph.windowsDeviceAccount',
                    'password': device_account_password
                },
                'passwordRotationEnabled': password_rotation_enabled,
                'calendarSyncEnabled': calendar_sync_enabled,
                'deviceAccountEmail': device_account_email,
                'exchangeServer': exchange_server,
                'sessionInitiationProtocalAddress': session_initiation_protocal_address
            }
        }
        self.make_action(device_id, action, json.dumps(body))


''' HELPER FUNCTIONS '''


def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    :param int_to_parse: The argument to be parsed into integer
    :param err_msg: The error message to show in case of failure
    :return: The integer
    """
    try:
        res: int = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


def parse_device_action_results(raw_device_action_results: list) -> list:
    """
    Parses a list of device action results
    :param raw_device_action_results: The raw list of device action results
    :return: The parsed list of device action results
    """
    action_results: list = list()
    for device_action_result in raw_device_action_results:
        action_result = assign_params(**{
            'Name': device_action_result.get('actionName'),
            'State': device_action_result.get('actionState'),
            'StartDateTime': device_action_result.get('startDateTime'),
            'LastUpdatedDateTime': device_action_result.get('lastUpdatedDateTime')
        })
        if action_result:
            action_results.append(action_result)
    return action_results


def build_device_object(raw_device: dict) -> dict:
    """
    Builds a device context object
    :param raw_device: The raw device object
    :return: The device context object
    """
    device_action_results: list = raw_device.get('deviceActionResults', []) if raw_device.get('deviceActionResults') \
        else []
    conf_manager_client_enabled_features: dict = raw_device.get('configurationManagerClientEnabledFeatures', {}) \
        if raw_device.get('configurationManagerClientEnabledFeatures') else {}
    device_health_attestation_state: dict = raw_device.get('deviceHealthAttestationState', {}) \
        if raw_device.get('deviceHealthAttestationState') else {}
    return assign_params(**{
        'ID': raw_device.get('id'),
        'UserID': raw_device.get('userId'),
        'Name': raw_device.get('deviceName'),
        'ManagedDeviceOwnerType': raw_device.get('managedDeviceOwnerType'),
        'ActionResults': parse_device_action_results(device_action_results),
        'EnrolledDateTime': raw_device.get('enrolledDateTime'),
        'LastSyncDateTime': raw_device.get('lastSyncDateTime'),
        'OperatingSystem': raw_device.get('operatingSystem'),
        'ComplianceState': raw_device.get('complianceState'),
        'JailBroken': raw_device.get('jailBroken'),
        'ManagementAgent': raw_device.get('managementAgent'),
        'OSVersion': raw_device.get('osVersion'),
        'EASDeviceID': raw_device.get('easDeviceId'),
        'EASActivationDateTime': raw_device.get('easActivationDateTime'),
        'ActivationLockBypassCode': raw_device.get('activationLockBypassCode'),
        'EmailAddress': raw_device.get('emailAddress'),
        'AzureADDeviceID': raw_device.get('azureADDeviceId'),
        'CategoryDisplayName': raw_device.get('deviceCategoryDisplayName'),
        'ExchangeAccessState': raw_device.get('exchangeAccessState'),
        'ExchangeAccessStateReason': raw_device.get('exchangeAccessStateReason'),
        'IsSupervised': raw_device.get('isSupervised'),
        'IsEncrypted': raw_device.get('isEncrypted'),
        'UserPrincipalName': raw_device.get('userPrincipalName'),
        'Model': raw_device.get('model'),
        'Manufacturer': raw_device.get('manufacturer'),
        'IMEI': raw_device.get('imei'),
        'SerialNumber': raw_device.get('serialNumber'),
        'PhoneNumber': raw_device.get('phoneNumber'),
        'AndroidSecurityPatchLevel': raw_device.get('androidSecurityPatchLevel'),
        'ConfigurationManagerClientEnabledFeatures': assign_params(**{
            'Inventory': conf_manager_client_enabled_features.get('inventory'),
            'ModernApps': conf_manager_client_enabled_features.get('modernApps'),
            'ResourceAccess': conf_manager_client_enabled_features.get('resourceAccess'),
            'DeviceConfiguration': conf_manager_client_enabled_features.get('deviceConfiguration'),
            'CompliancePolicy': conf_manager_client_enabled_features.get('compliancePolicy'),
            'WindowsUpdateForBusiness': conf_manager_client_enabled_features.get('windowsUpdatesForBusiness')
        }),
        'WiFiMacAddress': raw_device.get('wiFiMacAddress'),
        'HealthAttestationState': assign_params(**{
            'LastUpdateDateTime': device_health_attestation_state.get('lastUpdateDateTime'),
            'IssuedDateTime': device_health_attestation_state.get('issuedDateTime'),
            'ResetCount': device_health_attestation_state.get('resetCount'),
            'RestartCount': device_health_attestation_state.get('restartCount'),
            'BitLockerStatus': device_health_attestation_state.get('bitLockerStatus'),
            'BootManagerVersion': device_health_attestation_state.get('bootManagerVersion'),
            'SecureBoot': device_health_attestation_state.get('secureBoot'),
            'BootDebugging': device_health_attestation_state.get('bootDebugging'),
            'OperatingSystemKernelDebugging': device_health_attestation_state.get('operatingSystemKernelDebugging'),
            'CodeIntegrity': device_health_attestation_state.get('codeIntegrity'),
            'TestSigning': device_health_attestation_state.get('testSigning'),
            'SafeMode': device_health_attestation_state.get('safeMode'),
            'WindowsPE': device_health_attestation_state.get('windowsPE'),
            'EarlyLaunchAntiMalwareDriverProtection':
                device_health_attestation_state.get('earlyLaunchAntiMalwareDriverProtection'),
            'VirtualSecureMode': device_health_attestation_state.get('virtualSecureMode'),
            'PCRHashAlgorithm': device_health_attestation_state.get('pcrHashAlgorithm'),
            'BootAppSecurityVersion': device_health_attestation_state.get('bootAppSecurityVersion'),
            'BootManagerSecurityVersion': device_health_attestation_state.get('bootManagerSecurityVersion'),
            'TPMVersion': device_health_attestation_state.get('tpmVersion'),
            'PCR0': device_health_attestation_state.get('pcr0'),
            'SecureBootConfigurationPolicyFingerPrint':
                device_health_attestation_state.get('secureBootConfigurationPolicyFingerPrint'),
            'CodeIntegrityPolicy': device_health_attestation_state.get('codeIntegrityPolicy'),
            'BootRevisionListInfo': device_health_attestation_state.get('bootRevisionListInfo'),
            'OperatingSystemRevListInfo': device_health_attestation_state.get('operatingSystemRevListInfo'),
            'HealthStatusMismatchInfo': device_health_attestation_state.get('healthStatusMismatchInfo'),
            'HealthAttestationSupportedStatus': device_health_attestation_state.get('healthAttestationSupportedStatus')
        }),
        'SubscriberCarrier': raw_device.get('subscriberCarrier'),
        'MEID': raw_device.get('meid'),
        'TotalStorageSpaceInBytes': raw_device.get('totalStorageSpaceInBytes'),
        'FreeStorageSpaceInBytes': raw_device.get('freeStorageSpaceInBytes'),
        'ManagedDeviceName': raw_device.get('managedDeviceName'),
        'PartnerReportedThreatState': raw_device.get('partnerReportedThreatState')
    })


''' COMMANDS '''


def list_managed_devices_command(client: MsGraphClient, args: dict) -> None:
    limit: int = try_parse_integer(args.get('limit', 10), err_msg='This value for limit must be an integer.')
    list_raw_devices, raw_response = client.list_managed_devices(limit)
    list_devices: list = [build_device_object(device) for device in list_raw_devices if device]
    entry_context: dict = {'MSGraphDeviceManagement.Device(val.ID === obj.ID)': list_devices}
    human_readable: str = 'No managed devices found.'
    if list_devices:
        name: str = 'List managed devices'
        if len(list_devices) == 1:
            name = f'Managed device {list_devices[0].get("Name", "")}'
        human_readable = tableToMarkdown(name=name, t=list_raw_devices, headers=HEADERS['raw_device'],
                                         headerTransform=lambda h: SPECIAL_HEADERS.get(h, pascalToSpace(h)),
                                         removeNull=True)
    return_outputs(human_readable, entry_context, raw_response)


def find_managed_device_command(client: MsGraphClient, args: dict) -> None:
    device_name: str = str(args.get('device_name'))
    list_raw_devices, raw_response = client.find_managed_device(device_name)
    list_devices: list = [build_device_object(device) for device in list_raw_devices if device]
    entry_context: dict = {'MSGraphDeviceManagement.Device(val.ID === obj.ID)': list_devices}
    human_readable: str = f'Managed device {device_name} not found.'
    if list_devices:
        name: str = 'List managed devices'
        if len(list_devices) == 1:
            name = f'Managed device {list_devices[0].get("Name", "")}'
        human_readable = tableToMarkdown(name=name, t=list_raw_devices, headers=HEADERS['raw_device'],
                                         headerTransform=lambda h: SPECIAL_HEADERS.get(h, pascalToSpace(h)),
                                         removeNull=True)
    return_outputs(human_readable, entry_context, raw_response)


def get_managed_device_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    raw_response, device_id = client.get_managed_device(device_id)
    device: dict = build_device_object(raw_response)
    entry_context: dict = {'MSGraphDeviceManagement.Device(val.ID === obj.ID)': device}
    device_name: str = device.get('Name', '')
    human_readable: str = f'Managed device {device_id} not found.'
    if device:
        human_readable = tableToMarkdown(name=f'Managed device {device_name}', t=raw_response,
                                         headers=HEADERS['raw_device'],
                                         headerTransform=lambda h: SPECIAL_HEADERS.get(h, pascalToSpace(h)),
                                         removeNull=True)
    return_outputs(human_readable, entry_context, raw_response)


def disable_lost_mode_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'disableLostMode')
    return_outputs('Device disable lost mode action activated successfully.', {}, {})


def locate_device_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'locateDevice')
    return_outputs('Locate device action activated successfully.', {}, {})


def sync_device_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'syncDevice')
    return_outputs('Sync device action activated successfully.', {}, {})


def device_reboot_now_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'rebootNow')
    return_outputs('Device reboot now action activated successfully.', {}, {})


def device_shutdown_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'shutDown')
    return_outputs('Device shutdown action activated successfully.', {}, {})


def device_bypass_activation_lock_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'bypassActivationLock')
    return_outputs('Device bypass activation lock action activated successfully.', {}, {})


def device_retire_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'retire')
    return_outputs('Retire device action activated successfully.', {}, {})


def device_reset_passcode_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'resetPasscode')
    return_outputs('Device reset passcode action activated successfully.', {}, {})


def device_remote_lock_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'remoteLock')
    return_outputs('Device remote lock action activated successfully.', {}, {})


def device_request_remote_assistance_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'requestRemoteAssistance')
    return_outputs('Device request remote assistance action activated successfully.', {}, {})


def device_recover_passcode_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'recoverPasscode')
    return_outputs('Device recover passcode action activated successfully.', {}, {})


def logout_shared_apple_device_active_user_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'logoutSharedAppleDeviceActiveUser')
    return_outputs('Logout shard apple device active user action activated successfully.', {}, {})


def delete_user_from_shared_apple_device_command(client: MsGraphClient, args: dict) -> None:
    user_principal_name: str = str(args.get('user_principal_name'))
    device_id: str = str(args.get('device_id'))
    client.delete_user_from_shared_apple_device(user_principal_name, device_id, 'deleteUserFromSharedAppleDevice')
    return_outputs('Delete user from shared apple device action activated successfully.', {}, {})


def windows_device_defender_update_signatures_command(client: MsGraphClient, args: dict) -> None:
    device_id: str = str(args.get('device_id'))
    client.make_action(device_id, 'windowsDefenderUpdateSignatures')
    return_outputs('Windows device defender update signatures action activated successfully.', {}, {})


def clean_windows_device_command(client: MsGraphClient, args: dict) -> None:
    keep_user_data: bool = bool(args.get('keep_user_data'))
    device_id: str = str(args.get('device_id'))
    client.clean_windows_device(keep_user_data, device_id, 'cleanWindowsDevice')
    return_outputs('Clean windows device action activated successfully.', {}, {})


def windows_device_defender_scan_command(client: MsGraphClient, args: dict) -> None:
    quick_scan: bool = bool(args.get('quick_scan'))
    device_id: str = str(args.get('device_id'))
    client.windows_device_defender_scan(quick_scan, device_id, 'windowsDefenderScan')
    return_outputs('Windows device defender scan action activated successfully.', {}, {})


def wipe_device_command(client: MsGraphClient, args: dict) -> None:
    keep_enrollment_data: bool = bool(args.get('keep_enrollment_data'))
    keep_user_data: bool = bool(args.get('keep_user_data'))
    mac_os_unlock_code: str = str(args.get('mac_os_unlock_code'))
    device_id: str = str(args.get('device_id'))
    client.wipe_device(keep_enrollment_data, keep_user_data, mac_os_unlock_code, device_id, 'wipe')
    return_outputs('Wipe device action activated successfully.', {}, {})


def update_windows_device_account_command(client: MsGraphClient, args: dict) -> None:
    device_account_password: str = str(args.get('device_account_password'))
    password_rotation_enabled: bool = bool(args.get('password_rotation_enabled'))
    calendar_sync_enabled: bool = bool(args.get('calendar_sync_enabled'))
    device_account_email: str = str(args.get('device_account_email'))
    exchange_server: str = str(args.get('exchange_server'))
    session_initiation_protocal_address: str = str(args.get('session_initiation_protocal_address'))
    device_id: str = str(args.get('device_id'))
    client.update_windows_device_account(device_account_password, password_rotation_enabled, calendar_sync_enabled,
                                         device_account_email, exchange_server, session_initiation_protocal_address,
                                         device_id, 'updateWindowsDeviceAccount')
    return_outputs('Update windows device account action activated successfully.', {}, {})


''' MAIN '''


def main():
    args: dict = demisto.args()
    params: dict = demisto.params()
    self_deployed: bool = params.get('self_deployed', False)
    tenant_id: str = params.get('tenant_id', '')
    auth_and_token_url: str = params.get('auth_id', '')
    enc_key: str = params.get('enc_key', '')
    base_url: str = urljoin(params.get('url', ''), '/v1.0')
    app_name: str = 'ms-graph-device-management'
    ok_codes: tuple = (200, 201, 202, 204)
    use_ssl: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)
    certificate_thumbprint: str = params.get('certificate_thumbprint', '')
    private_key: str = params.get('private_key', '')
    if not self_deployed and not enc_key:
        raise DemistoException('Key must be provided. For further information see '
                               'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
    elif not enc_key and not (certificate_thumbprint and private_key):
        raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')

    client: MsGraphClient = MsGraphClient(self_deployed, tenant_id, auth_and_token_url, enc_key, app_name, base_url,
                                          use_ssl, proxy, ok_codes, certificate_thumbprint=certificate_thumbprint,
                                          private_key=private_key)

    command: str = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            client.ms_client.get_access_token()
            demisto.results('ok')
        elif command == 'msgraph-list-managed-devices':
            list_managed_devices_command(client, args)
        elif command == 'msgraph-get-managed-device-by-id':
            get_managed_device_command(client, args)
        elif command == 'msgraph-device-disable-lost-mode':
            disable_lost_mode_command(client, args)
        elif command == 'msgraph-locate-device':
            locate_device_command(client, args)
        elif command == 'msgraph-sync-device':
            sync_device_command(client, args)
        elif command == 'msgraph-device-reboot-now':
            device_reboot_now_command(client, args)
        elif command == 'msgraph-device-shutdown':
            device_shutdown_command(client, args)
        elif command == 'msgraph-device-bypass-activation-lock':
            device_bypass_activation_lock_command(client, args)
        elif command == 'msgraph-device-retire':
            device_retire_command(client, args)
        elif command == 'msgraph-device-reset-passcode':
            device_reset_passcode_command(client, args)
        elif command == 'msgraph-device-remote-lock':
            device_remote_lock_command(client, args)
        elif command == 'msgraph-device-request-remote-assistance':
            device_request_remote_assistance_command(client, args)
        elif command == 'msgraph-device-recover-passcode':
            device_recover_passcode_command(client, args)
        elif command == 'msgraph-logout-shared-apple-device-active-user':
            logout_shared_apple_device_active_user_command(client, args)
        elif command == 'msgraph-delete-user-from-shared-apple-device':
            delete_user_from_shared_apple_device_command(client, args)
        elif command == 'msgraph-windows-device-defender-update-signatures':
            windows_device_defender_update_signatures_command(client, args)
        elif command == 'msgraph-clean-windows-device':
            clean_windows_device_command(client, args)
        elif command == 'msgraph-windows-device-defender-scan':
            windows_device_defender_scan_command(client, args)
        elif command == 'msgraph-wipe-device':
            wipe_device_command(client, args)
        elif command == 'msgraph-update-windows-device-account':
            update_windows_device_account_command(client, args)
        elif command == 'msgraph-find-managed-device-by-name':
            find_managed_device_command(client, args)

    # log exceptions
    except Exception as err:
        return_error(str(err))


### GENERATED CODE ###: from MicrosoftApiModule import *  # noqa: E402
# This code was inserted in place of an API module.
register_module_line('MicrosoftApiModule', 'start', __line__(), wrapper=-3)


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'
    security_center_apt_service = 'https://securitycenter.onmicrosoft.com/windowsatpservice/.default'
    management_azure = 'https://management.azure.com/.default'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
REGEX_SEARCH_URL = r'(?P<url>https?://[^\s]+)'
SESSION_STATE = 'session_state'
TOKEN_RETRIEVAL_ENDPOINTS = {
    'com': 'https://login.microsoftonline.com',
    'gcc-high': 'https://login.microsoftonline.us',
    'dod': 'https://login.microsoftonline.us',
    'de': 'https://login.microsoftonline.de',
    'cn': 'https://login.chinacloudapi.cn',
}
GRAPH_ENDPOINTS = {
    'com': 'https://graph.microsoft.com',
    'gcc-high': 'https://graph.microsoft.us',
    'dod': 'https://dod-graph.microsoft.us',
    'de': 'https://graph.microsoft.de',
    'cn': 'https://microsoftgraph.chinacloudapi.cn'
}
GRAPH_BASE_ENDPOINTS = {
    'https://graph.microsoft.com': 'com',
    'https://graph.microsoft.us': 'gcc-high',
    'https://dod-graph.microsoft.us': 'dod',
    'https://graph.microsoft.de': 'de',
    'https://microsoftgraph.chinacloudapi.cn': 'cn'
}


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: Optional[str] = '',
                 token_retrieval_url: str = '{endpoint}/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = '{graph_endpoint}/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 timeout: Optional[int] = None,
                 azure_ad_endpoint: str = '{endpoint}',
                 endpoint: str = 'com',
                 certificate_thumbprint: Optional[str] = None,
                 private_key: Optional[str] = None,
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
            certificate_thumbprint: Certificate's thumbprint that's associated to the app
            private_key: Private key of the certificate
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        self.endpoint = endpoint
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id,
                                                                  endpoint=TOKEN_RETRIEVAL_ENDPOINTS[self.endpoint])
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope.format(graph_endpoint=GRAPH_ENDPOINTS[self.endpoint])
            self.redirect_uri = redirect_uri
            if certificate_thumbprint and private_key:
                try:
                    import msal  # pylint: disable=E0401
                    self.jwt = msal.oauth2cli.assertion.JwtAssertionCreator(
                        private_key,
                        'RS256',
                        certificate_thumbprint
                    ).create_normal_assertion(audience=self.token_retrieval_url, issuer=self.client_id)
                except ModuleNotFoundError:
                    raise DemistoException('Unable to use certificate authentication because `msal` is missing.')
            else:
                self.jwt = None

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify
        self.azure_ad_endpoint = azure_ad_endpoint.format(endpoint=TOKEN_RETRIEVAL_ENDPOINTS[self.endpoint])
        self.timeout = timeout  # type: ignore

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        if 'ok_codes' not in kwargs and not self._ok_codes:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)

        if self.timeout:
            kwargs['timeout'] = self.timeout

        response = super()._http_request(  # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = 'Not Found - 404 Response'
            raise NotFoundError(error_message)

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def get_access_token(self, resource: str = '', scope: Optional[str] = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Args:
            resource (str): The resource identifier for which the generated token will have access to.
            scope (str): A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        if self.multi_resource:
            access_token = integration_context.get(resource)
        else:
            access_token = integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        if self.auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                for resource_str in self.resources:
                    access_token, expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(
                refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _oproxy_authorize(self, resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope,
                'resource': resource
            },
            verify=self.verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self,
                                 refresh_token: str = '',
                                 scope: Optional[str] = None,
                                 integration_context: Optional[dict] = None
                                 ) -> Tuple[str, int, str]:
        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            else:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                      resource)
                    self.resource_to_access_token[resource] = access_token

                return '', expires_in, refresh_token
        elif self.grant_type == DEVICE_CODE:
            return self._get_token_device_code(refresh_token, scope, integration_context)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            if self.multi_resource:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_client_credentials(
                        resource=resource)
                    self.resource_to_access_token[resource] = access_token
                return '', expires_in, refresh_token
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None,
                                                    resource: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope: A scope to add to the headers. Else will get self.scope.
            resource: A resource to add to the headers. Else will get self.resource.
        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        if self.jwt:
            data.pop('client_secret', None)
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = self.jwt

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource or resource:
            data['resource'] = resource or self.resource  # type: ignore

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource=self.resource if not resource else resource,
            redirect_uri=self.redirect_uri
        )

        if self.jwt:
            data.pop('client_secret', None)
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = self.jwt

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            if SESSION_STATE in self.auth_code:
                raise ValueError('Malformed auth_code parameter: Please copy the auth code from the redirected uri '
                                 'without any additional info and without the "session_state" query parameter.')
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_token_device_code(
            self, refresh_token: str = '', scope: Optional[str] = None, integration_context: Optional[dict] = None
    ) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'scope': scope
        }

        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = DEVICE_CODE
            if integration_context:
                data['code'] = integration_context.get('device_code')

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            demisto.error(str(response))
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: Optional[str]) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key

            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = MicrosoftClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> Dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            headers = get_x_content_info_headers()
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers

    def device_auth_request(self) -> dict:
        response_json = {}
        try:
            response = requests.post(
                url=f'{self.azure_ad_endpoint}/organizations/oauth2/v2.0/devicecode',
                data={
                    'client_id': self.client_id,
                    'scope': self.scope
                },
                verify=self.verify
            )
            if not response.ok:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')
        set_integration_context({'device_code': response_json.get('device_code')})
        return response_json

    def start_auth(self, complete_command: str) -> str:
        response = self.device_auth_request()
        message = response.get('message', '')
        re_search = re.search(REGEX_SEARCH_URL, message)
        url = re_search.group('url') if re_search else None
        user_code = response.get('user_code')

        return f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
and enter the code **{user_code}** to authenticate.
2. Run the **{complete_command}** command in the War Room."""


class NotFoundError(Exception):
    """Exception raised for 404 - Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


register_module_line('MicrosoftApiModule', 'end', __line__(), wrapper=1)
### END GENERATED CODE ###

if __name__ in ['__main__', 'builtins']:
    main()
