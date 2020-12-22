import json
from typing import Any, Dict, List, Tuple

import dateutil.parser
import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

'''Constants'''

STANDARD_DEVICE_FIELDS = ','.join(['common.uuid', 'common.compliant', 'common.id', 'common.imei', 'common.imsi',
                                   'common.last_connected_at', 'user.sam_account_name',
                                   'common.manufacturer', 'common.model', 'common.quarantined_reasons',
                                   'common.noncompliance_reasons', 'common.owner', 'common.platform',
                                   'common.SerialNumber', 'common.mdm_managed',
                                   'common.device_is_compromised', 'common.wifi_mac_address',
                                   'ios.iPhone MAC_ADDRESS_EN0', 'ios.Current MCC', 'ios.iPhone UDID',
                                   'common.current_country_code', 'common.home_country_code',
                                   'common.current_country_name', 'common.home_country_name',
                                   'common.quarantined', 'common.quarantined_reasons',
                                   'common.registration_date', 'common.status',
                                   'user.display_name', 'user.email_address', 'user.user_id', 'common.security_state'])
FETCH_INCIDENTS_DEVICE_QUERY = 'common.status = \"ACTIVE\" AND (common.quarantined = true OR common.compliant = ' \
                               'false OR common.security_state != \"Ok\")'

# Incident Severity Constants

SEVERITY_LOW = 1
SEVERITY_MEDIUM = 2
SEVERITY_HIGH = 3
SEVERITY_CRITICAL = 4

# This is just for tracking, not actually shown to the user
DEFAULT_ACTION_NOTE = 'Message sent through XSOAR-Integration'


class MobileIronCoreClient(BaseClient):
    """
    Client class to interact with the MobileIron Core API
    """

    def get_device_data_page(self, page: int = 0, per_page: int = 50, query: str = None,
                             fields: str = None, admin_space_id: str = None) -> Dict:
        """
            Gets a single page of Devices

            :return: the complete API response
            :rtype: ``Dict``
        """
        return self._http_request(
            method='GET',
            url_suffix='/api/v2/devices',
            params={
                'adminDeviceSpaceId': admin_space_id,
                'query': query,
                'fields': fields,
                'limit': per_page,
                'offset': page
            })

    def get_devices_data(self, admin_space_id: str, query: str = None, fields: str = None, max_fetch: int = None) -> \
            List[Any]:
        """
            Gets the Devices Data from MobileIron Core

            :type query: ``str``
            :param query: Conditions in the Core API Call

            :type fields: ``str``
            :param fields: Attributes to be retrieved

            :type admin_space_id: ``str``
            :param admin_space_id: Admin Space ID

            :type max_fetch: ``int``
            :param max_fetch: Cap on how many devices should be fetched from the API

            :return: list containing all device info as returned from the API
            :rtype: ``List``
        """

        if not admin_space_id:
            raise ValueError('admin_space_id not specified')
        has_more = True
        results = []
        page = 0
        while has_more:
            response = self.get_device_data_page(page=page, query=query, fields=fields, admin_space_id=admin_space_id)
            page += 1
            has_more = response['hasMore']
            results += response['results']
            if max_fetch and len(results) > max_fetch:
                return results[:max_fetch]

        return results

    def execute_device_action(self, device_id: str, admin_space_id: str, command_action: str) -> Dict[str, Any]:
        """
            Execute device action.

            :type command_action: ``str``
            :param command_action: Action String based on the action to be performed over MobileIron Core.

            :type device_id: ``str``
            :param device_id: DeviceID on which the actions should be performed..

            :type admin_space_id: ``str``
            :param admin_space_id: Admin Space ID

            :return: dict containing the scan results as returned from the API
            :rtype: ``Dict[str, Any]``
        """

        if not device_id:
            raise ValueError('device_id not specified')

        if not admin_space_id:
            raise ValueError('admin_space_id not specified')

        if not command_action:
            raise ValueError('command_action not specified')

        method_type = 'PUT'
        if command_action == 'WIPE_DEVICE':
            action_url_suffix = 'wipe'
        elif command_action == 'RETIRE':
            action_url_suffix = 'retire'
        elif command_action == 'WAKE_UP':
            action_url_suffix = 'wakeup'
        else:
            action_url_suffix = 'action'
            method_type = 'POST'

        payload = {'deviceUuids': [device_id], 'note': DEFAULT_ACTION_NOTE}

        return self._http_request(
            method=method_type,
            url_suffix=f'/api/v2/devices/{action_url_suffix}',
            params={
                'adminDeviceSpaceId': admin_space_id,
                'actionType': command_action
            },
            json_data=payload
        )

    def send_message_action(self, device_id: str, admin_space_id: str, message: str, message_mode: str = 'pns',
                            message_subject: str = '') -> \
            Dict[str, Any]:
        """
            Execute send message action to MobileIron CORE based on the conditions.

            :type device_id: ``str``
            :param device_id: DeviceID on which the actions should be performed..

            :type admin_space_id: ``str``
            :param admin_space_id: Admin Space ID

            :type message: ``str``
            :param message: Message to send to the specified devices.

            :type message_mode: ``str``
            :param message_mode: Mode of the message:
                                • pns (push notifications)
                                • sms
                                • email (email takes the subject parameter, too)

            :type message_subject: ``str``
            :param message_subject: Provide if desired when the message mode is email.

            :return: dict containing the scan results as returned from the API
            :rtype: ``Dict[str, Any]``
        """

        if not device_id:
            raise ValueError('device_id not specified')

        if not admin_space_id:
            raise ValueError('admin_space_id not specified')

        payload = {'deviceUuids': [device_id], 'note': DEFAULT_ACTION_NOTE,
                   'additionalParameters': {'message': message, 'mode': message_mode, 'subject': message_subject}}
        return self._http_request(
            method='POST',
            url_suffix='/api/v2/devices/action',
            params={
                'adminDeviceSpaceId': admin_space_id,
                'actionType': 'SEND_MESSAGE'
            },
            json_data=payload
        )

    def ping(self):
        """
            Executes PING ´to check for the connection with MobileIron CORE.

            :return: Ping Response
            :rtype:
        """
        return self._http_request(
            method='GET',
            url_suffix='/api/v2/ping'
        )


def resolve_device_incident_severity(device_info: Dict[str, Any]) -> Tuple[str, int]:
    """
        Gets the severity based on following conditions

        :type device_info: ``json``
        :param device_info: Dictionary containing the device information

        return : 'int'
        return param: returns severity to be set on the incident
    """

    security_state = device_info['common.security_state']
    if security_state != 'Ok':
        return f'Security State - {security_state}', SEVERITY_CRITICAL
    elif not device_info['common.compliant']:
        return 'Non-Compliant device', SEVERITY_HIGH
    elif device_info['common.quarantined']:
        return 'Quarantined device', SEVERITY_LOW

    raise ValueError('Unable to determine severity. The device does not contain any fields which indicate an issue')


def validate_action_response(response) -> str:
    validation = response["successful"]
    if validation:
        return 'Command has been executed successfully'
    else:
        raise DemistoException(
            'API indicated that the request was not successful. Make sure the device id provided is valid')


def execute_device_action_command(client: MobileIronCoreClient,
                                  action: str) -> str:
    """
        Returns results for a MobileIron Device Action

        :type client: ``MobileIronCoreClient``
        :param client: MobileIron client to use

        :type action: ``str``
        :param action: Device Specific Action, one of the following actions are allowed:
            - Retire a device
            - Wipe a device - This is potentially a destructive action
            - Send a message
            - Force Checkin a device
            - ENABLE_VOICE_ROAMING (iOS)
            - DISABLE_VOICE_ROAMING (iOS)
            - ENABLE_DATA_ROAMING (iOS)
            - DISABLE_DATA_ROAMING (iOS)
            - ENABLE_PERSONAL_HOTSPOT (iOS)
            - DISABLE_PERSONAL_HOTSPOT (iOS)
            - UPDATE_OS (iOS)
            - UNLOCK_APP_CONNECT_CONTAINER (Android)
            - UNLOCK_DEVICE_ONLY (Android, iOS)

        :return:
            Status of the request. In case of issues executing this request an exception will be raised.
        :rtype: ``str``
    """

    params = demisto.params()
    args = demisto.args()
    device_id = args.get('device_id')
    admin_space_id = params.get('admin_space_id')
    response = client.execute_device_action(device_id=device_id, admin_space_id=admin_space_id, command_action=action)
    return validate_action_response(response)


def execute_test_module_command(client: MobileIronCoreClient):
    """
        This definition is for test command - get Ping response from Core

        :return: 'ok'
        :rtype: string.
    """
    response = client.ping()
    if response and response.get('results'):
        return 'ok'


def execute_fetch_incidents_command(client):
    """
        runs the fetch incidents task.

        :type client: ``Client``
        :param client: MobileIron client to use
    """
    params = demisto.params()

    admin_space_id = params.get('admin_space_id')
    incident_type = params.get('incidentType')
    max_fetch = min(int(params.get('max_fetch')), 200)
    incidents = fetch_incidents(client=client, admin_space_id=admin_space_id, incident_type=incident_type,
                                max_fetch=max_fetch)
    demisto.incidents(incidents)


def fetch_incidents(client: MobileIronCoreClient, admin_space_id: str,
                    incident_type: str, max_fetch: int) -> List[Dict[str, Any]]:
    """
        This function returns incidents after analyzing the response data

        This function has to implement the logic of making sure that incidents are
        fetched based on analyzing the response data. By default it's invoked by
        XSOAR every minute. It will use last_run to save the timestamp of the last
        incident it processed.

        :type client: ``Client``
        :param client: MobileIron Core client to use

        :type admin_space_id: ``str``
        :param admin_space_id: Admin Space ID

        :type max_fetch: ``int``
        :param max_fetch: Cap on how many items should be fetched from the API

        :type incident_type: ``str``
        :param incident_type: Incident Type. This is configured in the instance settings when adding
        an instance.

        :return:
            incidents are returned in the form of dict
    """

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    """get the devices data from Core Call API response"""
    devices = client.get_devices_data(admin_space_id=admin_space_id,
                                      max_fetch=max_fetch,
                                      query=FETCH_INCIDENTS_DEVICE_QUERY, fields=STANDARD_DEVICE_FIELDS)
    for device in devices:
        # Rename keys for device attributes
        message, severity = resolve_device_incident_severity(device)
        incident_name = f'MobileIron Device Alert - {message}'

        incident = {
            'name': incident_name,
            'rawJSON': json.dumps(device),
            'type': incident_type,
            'severity': severity
        }
        incidents.append(incident)

    return incidents


def execute_get_device_by_field_command(client: MobileIronCoreClient, field_name: str,
                                        field_value: str) -> CommandResults:
    """Returns a specific device by providing field to filter for and the value to find

        :type client: ``MobileIronCoreClient``
        :param client: MobileIron UEM API client to use

        :type field_name: ``str``
        :param field_name: name of the field to query for

        :type field_value: ``str``
        :param field_value: value of the field to query for

        :return:
            A ``CommandResults`` object that is then passed to ``return_results``,
            that contains the device data

        :rtype: ``CommandResults``
        """
    params = demisto.params()
    args = demisto.args()
    additional_fields = args.get('additional_fields')
    if additional_fields:
        fields = ','.join([STANDARD_DEVICE_FIELDS, additional_fields])
    else:
        fields = STANDARD_DEVICE_FIELDS

    admin_space_id = params.get('admin_space_id')

    query = f'{field_name}="{field_value}"'

    devices_data_response = client.get_devices_data(admin_space_id=admin_space_id, query=query, fields=fields)
    device = next(iter(devices_data_response), None)

    return CommandResults(
        outputs_prefix='MobileIronCore.Device',
        outputs_key_field='common.id',
        outputs=device
    )


def execute_get_devices_data_command(client: MobileIronCoreClient, query: str) -> CommandResults:
    """get-devices command: Returns a list of all devices in the mobileiron system based on the query provided. This command might
    execute multiple API calls if there are a large amount of device to fetch

    :type client: ``MobileIronCoreClient``
    :param client: MobileIron UEM API client to use

    :type query: ``str``
    :param query: query to execute

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the device data

    :rtype: ``CommandResults``
    """
    params = demisto.params()
    args = demisto.args()
    max_fetch = min(int(params.get('max_fetch', 50)), 200)
    max_fetch = int(args.get('max_fetch')) if max_fetch else None
    additional_fields = args.get('additional_fields')
    if additional_fields:
        fields = ','.join([STANDARD_DEVICE_FIELDS, additional_fields])
    else:
        fields = STANDARD_DEVICE_FIELDS

    admin_space_id = params.get('admin_space_id')

    devices_data_response = client.get_devices_data(admin_space_id=admin_space_id, query=query, fields=fields,
                                                    max_fetch=max_fetch)

    return CommandResults(
        # readable_output=readable_output,
        outputs_prefix='MobileIronCore.Device',
        outputs_key_field='common.id',
        outputs=devices_data_response
    )


def execute_send_message_command(client: MobileIronCoreClient) -> str:
    """mobileiron-update-os command: Returns results for a MobileIron Send Message Action

    :type client: ``MobileIronCoreClient``
    :param client: MobileIron client to use

    :return:
        A ``CommandResults`` compatible to return ``return_results()``,
        that contains an action result
        A Dict of entries also compatible to ``return_results()``

    :rtype: ``CommandResults``
    """
    params = demisto.params()
    args = demisto.args()
    device_id = args.get('device_id')
    admin_space_id = params.get('admin_space_id')
    message = args.get('message')
    subject = args.get('subject')
    message_mode = args.get('message_type')

    response = client.send_message_action(device_id=device_id, admin_space_id=admin_space_id, message=message,
                                          message_mode=message_mode, message_subject=subject)
    return validate_action_response(response)


def main():
    # if your MobileIronClient class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the MobileIronClient constructor
    params = demisto.params()
    args = demisto.args()
    verify_certificate = not params.get('insecure', False)

    # if your MobileIronClient class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the MobileIronClient constructor
    proxy = params.get('proxy', False)
    base_url = params.get('url')
    credentials = params.get('credentials')
    username = credentials.get('identifier')
    password = credentials.get('password')

    try:
        client = MobileIronCoreClient(
            base_url=base_url,
            auth=(username, password),
            verify=verify_certificate,
            proxy=proxy)

        command_methods = {
            'test-module': lambda: execute_test_module_command(client),
            'fetch-incidents': lambda: execute_fetch_incidents_command(client),
            'mobileiron-core-get-devices-data': lambda: execute_get_devices_data_command(client,
                                                                                         query=args.get('query')),
            'mobileiron-core-get-device-by-uuid': lambda:
            execute_get_device_by_field_command(client,
                                                field_name='common.uuid',
                                                field_value=args.get('device_uuid')),
            'mobileiron-core-get-device-by-serial': lambda:
            execute_get_device_by_field_command(client,
                                                field_name='common.SerialNumber',
                                                field_value=args.get('device_serial')),
            'mobileiron-core-get-device-by-mac': lambda:
            execute_get_device_by_field_command(client,
                                                field_name='common.wifi_mac_address',
                                                field_value=args.get('device_mac')),
            'mobileiron-core-get-device-by-ip': lambda:
            execute_get_device_by_field_command(client,
                                                field_name='common.ip_address',
                                                field_value=args.get('device_ip')),
            'mobileiron-core-unlock-device-only': lambda: execute_device_action_command(client, "UNLOCK_DEVICE_ONLY"),
            'mobileiron-core-enable-voice-roaming': lambda: execute_device_action_command(client,
                                                                                          "ENABLE_VOICE_ROAMING"),
            'mobileiron-core-disable-voice-roaming': lambda: execute_device_action_command(client,
                                                                                           "DISABLE_VOICE_ROAMING"),
            'mobileiron-core-enable-data-roaming': lambda: execute_device_action_command(client, "ENABLE_DATA_ROAMING"),
            'mobileiron-core-disable-data-roaming': lambda: execute_device_action_command(client,
                                                                                          "DISABLE_DATA_ROAMING"),
            'mobileiron-core-enable-personal-hotspot': lambda: execute_device_action_command(client,
                                                                                             "ENABLE_PERSONAL_HOTSPOT"),
            'mobileiron-core-disable-personal-hotspot': lambda: execute_device_action_command(client,
                                                                                              "DISABLE_PERSONAL_HOTSPOT"),
            'mobileiron-core-send-message': lambda: execute_send_message_command(client),
            'mobileiron-core-update-os': lambda: execute_device_action_command(client, "UPDATE_OS"),
            'mobileiron-core-unlock-app-connect-container': lambda: execute_device_action_command(
                client,
                "UNLOCK_APP_CONNECT_CONTAINER"
            ),
            'mobileiron-core-retire-device': lambda: execute_device_action_command(client, "RETIRE"),
            'mobileiron-core-wipe-device': lambda: execute_device_action_command(client, "WIPE_DEVICE"),
            'mobileiron-core-force-checkin': lambda: execute_device_action_command(client, "WAKE_UP")
        }
        command_method = command_methods.get(demisto.command())
        if not command_method:
            raise DemistoException(f'command not recognised - {demisto.command()}')

        result = command_method()
        if result:
            return_results(result)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
