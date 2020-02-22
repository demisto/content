import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
from typing import Tuple, Any, Union

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''

HEADERS: dict = {
    'raw_device': ['id', 'userId', 'deviceName', 'operatingSystem', 'osVersion', 'emailAddress',
                   'manufacturer', 'model', 'imei', 'meid'],
    'device': ['ID', 'User ID', 'Device Name', 'Operating System', 'OS Version', 'Email Address',
               'Manufacturer', 'Model', 'IMEI', 'MEID']
}

SPECIAL_ACTIONS: dict = {
    'shutdown': {
        'camel_case_form': 'shutDown',
        'body_generating_function': 'build_request_body_generic'
    },
    'update-windows-device-account': {
        'camel_case_form': 'updateWindowsDeviceAccount',
        'body_generating_function': 'build_request_body_update_windows_device_account'
    }
}


''' CLIENT '''


class MsGraphClient:
    def __init__(self, ms_client):
        self.ms_client = ms_client

    def make_request(self, method, url_suffix, resp_type='json', data=None):
        """
        Performs a simple http request
        :param method: The method of the request
        :param url_suffix: The url suffix to add to base url
        :param resp_type: The expected type of the response (Can be empty)
        :param data: The request's body
        :return: The request's response
        """
        return self.ms_client.http_request(method, url_suffix, data=data, resp_type=resp_type)


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
    return [
        assign_params(**{
            'Name': device_action_result.get('actionName'),
            'State': device_action_result.get('actionState'),
            'StartDateTime': device_action_result.get('startDateTime'),
            'LastUpdatedDateTime': device_action_result.get('lastUpdatedDateTime')
        }) for device_action_result in raw_device_action_results
    ]


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


def build_device_human_readable(device: dict) -> dict:
    """
    Builds a device human readable object
    :param device: The raw device object
    :return: The device human readable object
    """
    device_human_readable: dict = dict()
    for header in HEADERS['raw_device']:
        index: int = HEADERS['raw_device'].index(header)
        device_human_readable[HEADERS['device'][index]] = device.get(header)
    return assign_params(**device_human_readable)


def dash_to_camelcase(action: str) -> Union[str, Any]:
    """
    Convert a dashed separated string to camel case
    :param action: The dashed string to convert (e.g. hello-world)
    :return: The camel cased string (e.g. helloWorld)
    """

    if not isinstance(action, str):
        return action

    if action in SPECIAL_ACTIONS.keys():
        return SPECIAL_ACTIONS[action]['camel_case_form']

    components = action.split('-')
    return components[0] + ''.join(x.title() for x in components[1:])


def build_request_body_generic(args: dict) -> dict:
    """
    Builds the http request body of a generic command (make_action_command)
    :param args: demisto.args
    :return: The body of the http request
    """
    return {dash_to_camelcase(k): v for k, v in args.items() if k != 'device-id'}


def build_request_body_update_windows_device_account(args: dict) -> dict:
    """
    Builds the http request body of msgraph-update-windows-device-account command
    :param args: demisto.args
    :return: The body of the http request
    """
    body: dict = {dash_to_camelcase(k): v for k, v in args.items() if k not in ['device-id', 'device-account-password']}
    body.update({
        'deviceAcount': {
            '@odata.type': 'microsoft.graph.windowsDeviceAccount',
            'password': args.get('device-account-password')
        }
    })
    return {'updateWindowsDeviceAccountActionParameter': body}


def build_request_body(args: dict, action: str) -> Union[dict, None]:
    """
    Build the body of the http request to send to MS Graph API
    :param args: demisto.args
    :param action: the action name
    :return: The body of the http request
    """
    body: dict = dict()
    err_msg: str = str()
    if action in SPECIAL_ACTIONS.keys():
        try:
            body = eval(f'{SPECIAL_ACTIONS["body_generating_function"]}(args)')
        except NameError:
            err_msg = f'Not implemented function {SPECIAL_ACTIONS["body_generating_function"]}.'
            demisto.debug(err_msg)
            raise NameError(err_msg)
        except TypeError:
            err_msg = f'Check number of arguments / argument types for function ' \
                           f'{SPECIAL_ACTIONS["body_generating_function"]}'
            demisto.debug(err_msg)
            raise TypeError(err_msg)
    else:
        body = build_request_body_generic(args)

    return body if body else None


def get_action(demisto_command: str) -> str:
    """
    Parses the action name from the command being executed
    :param demisto_command: The command being executed
    :return: The action name
    """
    try:
        command: str = demisto_command.split('msgraph-')[1]
        return command if not command.startswith('device-') else command.split('device-')[1]
    except IndexError:
        err_msg: str = f'Command {demisto_command} is not of format msgraph-command'
        demisto.debug(err_msg)
        raise DemistoException(err_msg)


''' COMMANDS '''


def list_managed_devices_command(client: MsGraphClient, args: dict) -> Tuple[str, dict, dict]:
    url_suffix: str = '/deviceManagement/managedDevices'
    limit: int = try_parse_integer(args.get('limit', 10), err_msg='This value for limit must be an integer.')
    raw_response = client.make_request('GET', url_suffix)
    list_raw_devices: list = raw_response.get('value', [])[:limit]
    list_devices: list = [build_device_object(device) for device in list_raw_devices if device]
    list_devices_hr: list = [build_device_human_readable(device) for device in list_raw_devices if device]
    entry_context: dict = {'MSGraphDeviceManagement.Device(val.ID === obj.ID)': list_devices}
    human_readable: str = tableToMarkdown('List managed devices', list_devices_hr, headers=HEADERS['device'])
    return human_readable, entry_context, raw_response


def get_managed_device_command(client: MsGraphClient, args: dict) -> Tuple[str, dict, dict]:
    url_suffix: str = f'/deviceManagement/managedDevices/{args.get("device-id")}'
    raw_response = client.make_request('GET', url_suffix)
    device: dict = build_device_object(raw_response)
    device_hr: dict = build_device_human_readable(raw_response)
    entry_context: dict = {'MSGraphDeviceManagement.Device(val.ID === obj.ID)': device}
    device_name: str = device.get('Name', '')
    human_readable: str = tableToMarkdown(f'Managed device {device_name}', device_hr, headers=HEADERS['device'])
    return human_readable, entry_context, raw_response


def make_action_command(client: MsGraphClient, args: dict) -> Tuple[str, dict, dict]:
    action: str = get_action(demisto.command())
    body: Union[dict, None] = build_request_body(args, action)
    url_suffix: str = f'deviceManagement/managedDevices/{args.get("device-id")}/{dash_to_camelcase(action)}'
    client.make_request('POST', url_suffix, data=body, resp_type='None')
    return f'Device {action.replace("-", " ")} action activated successfully.', {}, {}


''' MAIN '''


def main():
    args: dict = demisto.args()
    params: dict = demisto.params()
    self_deployed: bool = params.get('self_deployed', False)
    tenant_id: str = params.get('tenant_id', '')
    auth_and_token_url: str = params.get('auth_id', '')
    enc_key: str = params.get('enc_key', '')
    # remove trailing slash to prevent wrong URL path to service
    url: str = params.get('url', '')
    server: str = url[:-1] if (url and url.endswith('/')) else url
    # service base URL
    base_url: str = server + '/v1.0'
    app_name: str = 'ms-graph-device-management'
    ok_codes: tuple = (200, 201, 202, 204)
    use_ssl: bool = not params.get('insecure', False)
    proxy: dict = handle_proxy()

    if self_deployed:
        app_url: str = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        ms_client = MicrosoftClient.from_self_deployed(tenant_id, auth_and_token_url, enc_key, app_url=app_url,
                                                       scope='https://graph.microsoft.com/.default',
                                                       base_url=base_url, verify=use_ssl,
                                                       proxy=proxy, ok_codes=ok_codes)
    else:
        # params related to oproxy
        ms_client = MicrosoftClient.from_oproxy(auth_and_token_url, enc_key, app_name,
                                                tenant_id=tenant_id, base_url=base_url, verify=use_ssl,
                                                proxy=proxy, ok_codes=ok_codes)

    client: MsGraphClient = MsGraphClient(ms_client)

    commands: dict = {
        'msgraph-list-managed-devices': list_managed_devices_command,
        'msgraph-get-managed-device-by-id': get_managed_device_command,
        'msgraph-device-disable-lost-mode': make_action_command,
        'msgraph-locate-device': make_action_command,
        'msgraph-sync-device': make_action_command,
        'msgraph-device-reboot-now': make_action_command,
        'msgraph-device-shutdown': make_action_command,
        'msgraph-device-bypass-activation-lock': make_action_command,
        'msgraph-device-retire': make_action_command,
        'msgraph-device-reset-passcode': make_action_command,
        'msgraph-device-remote-lock': make_action_command,
        'msgraph-device-request-remote-assistance': make_action_command,
        'msgraph-device-recover-passcode': make_action_command,
        'msgraph-device-logout-shared-apple-device-active-user': make_action_command,
        'msgraph-device-delete-user-from-shared-apple-device': make_action_command,
        'msgraph-device-windows-defender-update-signatures': make_action_command,
        'msgraph-clean-windows-device': make_action_command,
        'msgraph-device-windows-defender-scan': make_action_command,
        'msgraph-device-wipe': make_action_command,
        'msgraph-update-windows-device-account': make_action_command
    }
    command: str = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            client.ms_client.get_access_token()
            demisto.results('ok')
        else:
            # run the command
            human_readable, entry_context, raw_response = commands[command](client, args)
            # create a war room entry
            return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    # log exceptions
    except Exception as err:
        return_error(str(err))


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtins']:
    main()
