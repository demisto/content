from typing import Any, Dict, List, Tuple

import dateutil.parser
import urllib3

# Disable insecure warnings
from CommonServerPython import *

urllib3.disable_warnings()

'''CONSTANTS'''

FETCH_INCIDENTS_QUERY = 'registrationState=ACTIVE and (quarantined=true or jailbroken=true or complianceState=false)'

SEVERITY_LOW = 1
SEVERITY_MEDIUM = 2
SEVERITY_HIGH = 3
SEVERITY_CRITICAL = 4


class MobileIronCloudClient(BaseClient):
    """
        MobileIronCloudClient class to interact with the MobileIron Cloud Service API
    """

    def get_device_by_id(self, device_id: str, partition_id: str = None) -> Dict[str, Any]:
        """
            Gets a single device by id
        """
        response = self._http_request(
            method='GET',
            url_suffix=f'/api/v1/device/{device_id}',
            params={
                'dmPartitionId': partition_id
            }
        )
        return response['result']

    def get_device_data_page(self, start: int = 0, rows: int = 50, query: str = None,
                             partition_id: str = None) -> Dict:
        """
            Gets all the pages of device data from MobileIron Cloud
        """
        return self._http_request(
            method='GET',
            url_suffix='/api/v1/device',
            params={
                'dmPartitionId': partition_id,
                'fq': query,
                'rows': rows,
                'start': start
            }
        )

    def get_devices_data(self, partition_id: str, query: str = None, max_fetch: int = None) -> List[Any]:
        """
            Gets the Devices Data from MobileIron Cloud

            :type query: ``str``
            :param query: Conditions in the CLoud API Call

            :type partition_id: ``str``
            :param partition_id: Space ID, usually the global space id is sufficient

            :type max_fetch: ``int``
            :param max_fetch: Cap on how many devices should be fetched from the API

            :return: list containing all device info as returned from the API
            :rtype: ``List``
        """

        if not partition_id:
            raise ValueError('partition_id not specified')

        has_more = True
        results = []
        rows = 50
        start = 0
        while has_more:
            response = self.get_device_data_page(rows=rows, start=start, query=query, partition_id=partition_id)
            total_count = response['result']['totalCount']
            start += rows
            results += response['result']['searchResults']
            has_more = len(results) < total_count
            if max_fetch and len(results) >= max_fetch:
                return results[:max_fetch]

        return results

    def execute_device_action(self, action: str, device_id: str) -> Dict[str, Any]:
        """Execute actions to MobileIron Cloud based on the conditions.

        :type action: ``str``
        :param action: Action String based on the action to be performed over MobileIron Cloud.
        :type device_id: ``str``
        :param device_id: DeviceID on which the actions should be performed.

        :return: dict containing the results as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        if not device_id:
            raise ValueError('device_id not specified')

        data = {'ids': device_id}
        return self._http_request(
            method='PUT',
            url_suffix=f'/api/v1/device/{action}',
            data=data
        )

    def send_message(self, device_id: str, partition_id: str, message: str,
                     message_type: str = None, subject: str = None) -> Dict[str, Any]:
        """Send an email or/and a push message to the user of the specific device

        :type message_type: ``str``
        :param message_type: only options email or push are allowed

        :type subject: ``str``
        :param subject: Subject of the email message.

        :type message: ``str``
        :param message: Message to the user. In the case of email, this is the body,
        in case of push this is the complete message

        :type partition_id: ``str``
        :param partition_id: Partition ID of the tenant that contains the device.

        :type device_id: ``str``
        :param device_id: DeviceID on which the actions should be performed.

        :return: dict containing the results as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        if not message:
            raise ValueError('message not specified')

        if message_type not in ['email', 'push']:
            raise ValueError('message_type not valid, choose between \'email\' or \'push\'')

        if not partition_id:
            raise ValueError('partition_id not specified')

        should_send_mail = True if message_type == 'email' else False
        data = {
            'sendPushNotification': not should_send_mail,
            'sendEmail': should_send_mail,
            'emailSubject': subject,
            'pushNotificationMessage': message.replace(' ', '+'),
            'emailBody': message,
            'dmPartitionId': partition_id,
            'deviceIds': device_id
        }
        return self._http_request(
            method='PUT',
            url_suffix='/api/v1/device/message',
            data=data
        )

    def get_tenant_partitions(self):
        """
        An API call used to fetch all the partitions within the tenant.
        Usually of importance is the defaultPartition.

        :return: response containing a list of partition information
        """

        response = self._http_request(
            method='GET',
            url_suffix='/api/v1/tenant/partition/device'
        )
        return response['result']['searchResults']


'''HELPER FUNCTIONS'''


def validate_action_response(response):
    if response['errors'] or response['result'] != 1:
        raise ValueError(f'Failed to perform the action on the device. Got: {response}')


def get_partition_id(client) -> str:
    params = demisto.params()
    id_from_params = params.get('partition_id')
    if id_from_params:
        return id_from_params

    integration_context = demisto.getIntegrationContext()

    credentials = params.get('credentials')
    username = credentials.get('identifier')
    if integration_context and integration_context.get('for_user') == username:
        return integration_context.get('default_partition_id')

    spaces = client.get_tenant_partitions()
    space = next(item for item in spaces if item["defaultPartition"])
    api_partition_id = str(space['id'])

    demisto.setIntegrationContext({
        'for_user': username,
        'default_partition_id': api_partition_id
    })

    return api_partition_id


def resolve_device_incident_severity(device: Dict[str, Any]) -> Tuple[str, int]:
    """
    Function to find the device severity based on device properties

    :type device: ``Dict[str, Any]``
    :param device:
        a dictionary containing all the device properties

    :return:
        an int value marking the incident severity determined from the device properties

    :rtype: ``int``

    """

    if device.get('jailbroken'):
        return 'Jailbroken device', SEVERITY_CRITICAL
    if not device.get('complianceState'):
        message = compose_non_compliance_message(device)
        return message, SEVERITY_HIGH
    if device.get('quarantined'):
        return 'Quarantined device', SEVERITY_LOW

    raise ValueError('Unable to determine severity. The device does not contain any fields which indicate an issue')


def compose_non_compliance_message(device):
    base_message = 'Non Compliant Device'
    list_of_policies = device['violatedPolicies']
    if list_of_policies:
        message = ', '.join(list_of_policies)
        return f'{base_message} - {message}'
    return base_message


'''COMMAND FUNCTIONS'''


def execute_device_action_command(client: MobileIronCloudClient, action: str) -> str:
    """
        Runs the specified device action against the mobileiron API for a particular device

        :type client: ``MobileIronCloudClient``
        :param client: MobileIron client to use

        :type action: ``str``
        :param action: Action String based on the action to be performed over MobileIron Cloud.
        Following actions are allowed:
        - retire
        - unlock
        - wipe
        - forceCheckin

        :return:
            A ``CommandResults`` compatible to return ``return_results()``,
            that contains a Post action result
            A Dict of entries also compatible to ``return_results()``

        :rtype: ``CommandResults``
    """

    device_id = demisto.args().get('device_id')
    response = client.execute_device_action(action=action, device_id=device_id)

    validate_action_response(response)

    return 'Action was performed successfully'


def execute_send_message_command(client: MobileIronCloudClient) -> str:
    """mobileiron-send-message command: Returns results for a MobileIron PostAction

    :type client: ``MobileIronCloudClient``
    :param client: MobileIron client to use

    :return:
        A ``CommandResults`` compatible to return ``return_results()``,
        that contains a Post action result
        A Dict of entries also compatible to ``return_results()``

    :rtype: ``CommandResults``
    """
    args = demisto.args()
    message_type = args.get('message_type')
    device_id = args.get('device_id')
    partition_id = get_partition_id(client)
    message = args.get('message')
    subject = args.get('subject')

    response = client.send_message(device_id=device_id, partition_id=partition_id, message=message,
                                   message_type=message_type, subject=subject)
    validate_action_response(response)

    return 'Message was sent successfully'


def execute_test_module_command(client: MobileIronCloudClient):
    """ This definition is for test command to get Ping response from Cloud"""

    response = client.get_tenant_partitions()
    if response:
        return 'ok'


def execute_get_device_by_id_command(client: MobileIronCloudClient) -> CommandResults:
    device_id = demisto.args().get('device_id')
    partition_id = get_partition_id(client)
    device = client.get_device_by_id(device_id=device_id, partition_id=partition_id)
    return CommandResults(
        outputs_prefix='MobileIronCloud.Device',
        outputs_key_field='id',
        outputs=device
    )


def execute_get_devices_data_command(client: MobileIronCloudClient) -> CommandResults:
    """Returns a list of all devices from mobileiron system

    :type client: ``MobileIronCloudClient``
    :param client: MobileIron UEM client to use

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the device data

    :rtype: ``CommandResults``
    """
    args = demisto.args()
    query = args.get('query')
    max_fetch = args.get('max_fetch')
    max_fetch = int(max_fetch) if max_fetch else None
    partition_id = get_partition_id(client)
    devices = client.get_devices_data(partition_id=partition_id, query=query, max_fetch=max_fetch)
    return CommandResults(
        outputs_prefix='MobileIronCloud.Device',
        outputs_key_field='id',
        outputs=devices
    )


def execute_get_device_by_field_command(client: MobileIronCloudClient,
                                        field_name: str, field_value: str) -> CommandResults:
    """Returns a single device based on the property name matching the provided value

    :type client: ``MobileIronCloudClient``
    :param client: MobileIron UEM client to use

    :type field_name: ``str``
    :param field_name: name of the field to query for

    :type field_value: ``str``
    :param field_value: value of the field to query for

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the device data

    :rtype: ``CommandResults``
    """
    query = f'{field_name}={field_value}'
    partition_id = get_partition_id(client)
    devices = client.get_devices_data(partition_id=partition_id, query=query)
    device = next(iter(devices), None)
    return CommandResults(
        outputs_prefix='MobileIronCloud.Device',
        outputs_key_field='id',
        outputs=device
    )


def fetch_incidents(client: MobileIronCloudClient, partition_id: str,
                    incident_type: str, max_fetch: int) -> List[Dict[str, Any]]:
    """This function returns incidents after analyzing the response data

    This function has to implement the logic of making sure that incidents are
    fetched based on analyzing the response data.

    :type partition_id: ``str``
    :param partition_id: Partition ID of the tenant that contains the device.

    :type incident_type: ``str``
    :param incident_type: Incident Type to create, configured in the instance settings

    :type max_fetch: ``int``
    :param max_fetch: Cap on how many devices should be fetched from the API

    :type client: ``MobileIronCloudClient``
    :param client: MobileIron client to use

    :return:
        incidents are returned in the form of dict
    """

    incidents = []
    devices = client.get_devices_data(partition_id=partition_id, query=FETCH_INCIDENTS_QUERY, max_fetch=max_fetch)
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


def execute_fetch_incidents_command(client):
    params = demisto.params()
    max_fetch = min(int(params.get('max_fetch')), 200)

    partition_id = get_partition_id(client)
    incident_type = params.get('incidentType')
    incidents = fetch_incidents(client=client, partition_id=partition_id, incident_type=incident_type,
                                max_fetch=max_fetch)
    demisto.incidents(incidents)


'''MAIN FUNCTION'''


def main():
    params = demisto.params()
    args = demisto.args()
    credentials = params.get('credentials')
    username = credentials.get('identifier')
    password = credentials.get('password')
    base_url = params.get('url')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    try:
        client = MobileIronCloudClient(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)
        command_methods = {
            'test-module': lambda: execute_test_module_command(client),
            'fetch-incidents': lambda: execute_fetch_incidents_command(client),
            'mobileiron-cloud-get-devices-data': lambda: execute_get_devices_data_command(client),
            'mobileiron-cloud-get-device-by-mac': lambda:
            execute_get_device_by_field_command(client, field_name='wifiMacAddress',
                                                field_value=args.get("device_mac")),
            'mobileiron-cloud-get-device-by-serial': lambda:
            execute_get_device_by_field_command(client, field_name='serialNumber',
                                                field_value=args.get("device_serial")),
            'mobileiron-cloud-get-device-by-id': lambda: execute_get_device_by_id_command(client),
            'mobileiron-cloud-unlock-device': lambda: execute_device_action_command(client, "unlock"),
            'mobileiron-cloud-retire-device': lambda: execute_device_action_command(client, "retire"),
            'mobileiron-cloud-wipe-device': lambda: execute_device_action_command(client, "wipe"),
            'mobileiron-cloud-force-check-in': lambda: execute_device_action_command(client, "forceCheckin"),
            'mobileiron-cloud-send-message': lambda: execute_send_message_command(client)
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
