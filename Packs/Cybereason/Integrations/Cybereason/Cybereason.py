import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests
import os
import json
from datetime import datetime, timedelta
import time
import re
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''
SERVER = demisto.params().get('server', '')
if SERVER.endswith('/'):
    SERVER = SERVER[:-1]

USERNAME = demisto.params().get('credentials', {}).get('identifier')
PASSWORD = demisto.params().get('credentials', {}).get('password')
USE_SSL = not demisto.params().get('unsecure', False)
CERTIFICATE = demisto.params().get('credentials', {}).get('credentials', {}).get('sshkey')
FETCH_TIME_DEFAULT = '3 days'
FETCH_TIME = demisto.params().get('fetch_time', FETCH_TIME_DEFAULT)
FETCH_TIME = FETCH_TIME if FETCH_TIME and FETCH_TIME.strip() else FETCH_TIME_DEFAULT
FETCH_BY = demisto.params().get('fetch_by', 'MALOP CREATION TIME')
IS_EPP_ENABLED = argToBoolean(demisto.params().get('enable_epp_poll', False))

STATUS_MAP = {
    'To Review': 'TODO',
    'Remediated': 'CLOSED',
    'Unread': 'UNREAD',
    'Not Relevant': 'FP',
    'Open': 'OPEN'
}

INVESTIGATION_STATUS_MAP = {
    'Pending': 'Pending',
    'Reopened': 'ReOpened',
    'Under Investigation': 'UnderInvestigation',
    'On Hold': 'OnHold',
    'Closed': 'Closed'
}

# Field = the name as received from CR API, Header = The name which will be mapped to Demisto command,
# Type = Data that is received from CR API
PROCESS_INFO = [
    {'field': 'elementDisplayName', 'header': 'Name', 'type': 'filterData'},
    {'field': 'imageFile.maliciousClassificationType', 'header': 'Malicious', 'type': 'simple'},
    {'field': 'creationTime', 'header': 'Creation Time', 'type': 'time'},
    {'field': 'endTime', 'header': 'End Time', 'type': 'time'},
    {'field': 'commandLine', 'header': 'Command Line', 'type': 'simple'},
    {'field': 'isImageFileSignedAndVerified', 'header': 'Signed and Verified', 'type': 'simple'},
    {'field': 'productType', 'header': 'Product Type', 'type': 'simple'},
    {'field': 'children', 'header': 'Children', 'type': 'simple'},
    {'field': 'parentProcess', 'header': 'Parent', 'type': 'element'},
    {'field': 'ownerMachine', 'header': 'Owner Machine', 'type': 'element'},
    {'field': 'calculatedUser', 'header': 'User', 'type': 'element'},
    {'field': 'imageFile', 'header': 'Image File', 'type': 'element'},
    {'field': 'imageFile.sha1String', 'header': 'SHA1', 'type': 'simple'},
    {'field': 'imageFile.md5String', 'header': 'MD5', 'type': 'simple'},
    {'field': 'imageFile.companyName', 'header': 'Company Name', 'type': 'simple'},
    {'field': 'imageFile.productName', 'header': 'Product Name', 'type': 'simple'}
]

PROCESS_FIELDS = [element['field'] for element in PROCESS_INFO]

PROCESS_HEADERS = [element['header'] for element in PROCESS_INFO]

MALOP_HEADERS = [
    'GUID', 'Link', 'CreationTime', 'Status', 'LastUpdateTime', 'DecisionFailure', 'Suspects', 'AffectedMachine', 'InvolvedHash']

SINGLE_MALOP_HEADERS = [
    'GUID', 'Link', 'CreationTime', 'Status', 'LastUpdateTime', 'InvolvedHash']

DOMAIN_HEADERS = [
    'Name', 'Reputation', 'IsInternalDomain', 'WasEverResolved', 'WasEverResolvedAsASecondLevelDomain', 'Malicious',
    'SuspicionsCount']

USER_HEADERS = ['Username', 'Domain', 'LastMachineLoggedInTo', 'Organization', 'LocalSystem']

SENSOR_HEADERS = ['MachineID', 'MachineName', 'MachineFQDN', 'GroupID', 'GroupName']

PROCESS_URL_HEADERS = ['URL', 'ProcessID']

CONNECTION_INFO = [
    {'field': 'elementDisplayName', 'header': 'Name', 'type': 'simple'},
    {'field': 'direction', 'header': 'Direction', 'type': 'simple'},
    {'field': 'serverAddress', 'header': 'Server Address', 'type': 'simple'},
    {'field': 'serverPort', 'header': 'Server Port', 'type': 'simple'},
    {'field': 'portType', 'header': 'Port Type', 'type': 'simple'},
    {'field': 'aggregatedReceivedBytesCount', 'header': 'Received Bytes', 'type': 'simple'},
    {'field': 'aggregatedTransmittedBytesCount', 'header': 'Transmitted Bytes', 'type': 'simple'},
    {'field': 'remoteAddressCountryName', 'header': 'Remote Country', 'type': 'simple'},
    {'field': 'ownerMachine', 'header': 'Owner Machine', 'type': 'element'},
    {'field': 'ownerProcess', 'header': 'Owner Process', 'type': 'element'},
    {'field': 'calculatedCreationTime', 'header': 'Creation Time', 'type': 'time'},
    {'field': 'endTime', 'header': 'End Time', 'type': 'time'}
]

CONNECTION_FIELDS = [element['field'] for element in CONNECTION_INFO]

CONNECTION_HEADERS = [element['header'] for element in CONNECTION_INFO]

JSESSIONID = ''

HEADERS = {
    'Content-Type': 'application/json',
    'Connection': 'close',
    'Cookie': f"JSESSIONID={JSESSIONID}"
}


''' HELPER FUNCTIONS '''


def build_query(query_fields: list, path: list, template_context: str = 'SPECIFIC') -> dict:
    limit = demisto.getArg('limit')
    results_limit = int(limit) if limit else 10000
    group_limit = int(limit) if limit else 100

    query = {
        'customFields': query_fields,
        'perFeatureLimit': 100,
        'perGroupLimit': group_limit,
        'queryPath': path,
        'queryTimeout': 120000,
        'templateContext': template_context,
        'totalResultLimit': results_limit
    }

    return query


class Client(BaseClient):
    def __init__(self, base_url, verify, headers, proxy):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def cybereason_api_call(
        self, method: str, url_suffix: str, data: dict = None, json_body: Any = None, headers: dict = HEADERS,
            return_json: bool = True, custom_response: bool = False,
            retries: int = 0, backoff_factor: int = 5) -> Any:
        demisto.info(f'running request with url={SERVER + url_suffix}. API Query: {json_body}')

        try:
            res = self._http_request(
                method,
                url_suffix=url_suffix,
                data=data,
                json_data=json_body,
                resp_type='response',
                headers=headers,
                error_handler=self.error_handler,
                retries=retries,
                backoff_factor=backoff_factor
            )
            if custom_response:
                return res
            if res.status_code not in [200, 204]:
                raise Exception('Your request failed with the following error: ' + str(res.content)
                                + '. Response Status code: ' + str(res.status_code))
        except Exception as e:
            raise Exception(e)

        if return_json:
            try:
                return res.json()
            except Exception as e:
                error_content = res.content
                error_msg = ''
                if 'Login' in str(error_content):
                    error_msg = 'Authentication failed, verify the credentials are correct.'
                raise ValueError(
                    f'Failed to process the API response. {str(error_msg)} {str(error_content)} - {str(e)}')
        return None

    def error_handler(self, res: requests.Response):
        # Handle error responses gracefully
        command = demisto.command()
        if res.status_code == 500:
            if command == 'cybereason-download-file':
                raise Exception('The given Batch ID has expired')
            elif command == 'cybereason-close-file-batch-id':
                raise Exception('The given Batch ID does not exist')


def translate_timestamp(timestamp: str) -> str:
    return datetime.fromtimestamp(int(timestamp) / 1000).isoformat()


def update_output(output: dict, simple_values: dict, element_values: dict, info_dict: list) -> dict:
    for info in info_dict:
        info_type = info.get('type', '')

        if info_type == 'simple':
            output[info['header']] = dict_safe_get(simple_values, [info.get('field'), 'values', 0])

        elif info_type == 'element':
            output[info['header']] = dict_safe_get(element_values, [info.get('field'), 'elementValues', 0, 'name'])

        elif info_type == 'time':
            time_stamp_str = dict_safe_get(simple_values, [info.get('field'), 'values', 0], default_return_value='',
                                           return_type=str)
            output[info['header']] = translate_timestamp(time_stamp_str) if time_stamp_str else ''

    return output


def get_pylum_id(client: Client, machine: str) -> str:
    query_fields = ['pylumId']
    path = [
        {
            'requestedType': 'Machine',
            'filters': [
                {'facetName': 'elementDisplayName', 'values': [machine]}
            ],
            'isResult': True
        }
    ]
    json_body = build_query(query_fields, path)
    response = client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    data = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
    pylum_id = dict_safe_get(list(data.values()), [0, 'simpleValues', 'pylumId', 'values', 0])
    if not pylum_id:
        raise ValueError('Could not find machine')

    return pylum_id


def get_machine_guid(client: Client, machine_name: str) -> str:
    query_fields = ['elementDisplayName']
    path = [
        {
            'requestedType': 'Machine',
            'filters': [
                {'facetName': 'elementDisplayName', 'values': [machine_name]}
            ],
            'isResult': True
        }
    ]
    json_body = build_query(query_fields, path)
    response = client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    data = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)

    return dict_safe_get(list(data.keys()), [0])


''' FUNCTIONS '''


def is_probe_connected_command(client: Client, args: dict, is_remediation_command: bool = False) -> Any:
    machine = str(args.get('machine'))
    is_connected = False

    response = is_probe_connected(client, machine)

    elements = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)

    for value in list(elements.values()):
        machine_name = dict_safe_get(value, ['simpleValues', 'elementDisplayName', 'values', 0],
                                     default_return_value='', return_type=str)
        if machine_name.upper() == machine.upper():
            is_connected = True
            break

    if is_remediation_command:
        return is_connected

    return CommandResults(
        readable_output=f'{is_connected}',
        outputs_prefix='Cybereason.Machine',
        outputs_key_field='Name',
        outputs={
            'isConnected': is_connected,
            'Name': machine
        })


def is_probe_connected(client: Client, machine: str) -> dict:
    query_fields = ['elementDisplayName']
    path = [
        {
            'requestedType': 'Machine',
            'filters': [
                {'facetName': 'elementDisplayName', 'values': [machine]},
                {'facetName': 'isActiveProbeConnected', 'values': [True]}
            ],
            'isResult': True
        }
    ]
    json_body = build_query(query_fields, path)

    return client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)


def query_processes_command(client: Client, args: dict):
    machine = str(args.get('machine'))
    process_name = args.get('processName')
    only_suspicious = args.get('onlySuspicious')
    has_incoming_connection = args.get('hasIncomingConnection')
    has_outgoing_connection = args.get('hasOutgoingConnection')
    has_external_connection = args.get('hasExternalConnection')
    unsigned_unknown_reputation = args.get('unsignedUnknownReputation')
    from_temporary_folder = args.get('fromTemporaryFolder')
    privileges_escalation = args.get('privilegesEscalation')
    maclicious_psexec = args.get('maliciousPsExec')

    response = query_processes(client, machine, process_name, only_suspicious, has_incoming_connection, has_outgoing_connection,
                               has_external_connection, unsigned_unknown_reputation, from_temporary_folder,
                               privileges_escalation, maclicious_psexec)
    elements = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
    outputs = []
    for item in list(elements.values()):
        if not isinstance(item, dict):
            raise ValueError("Cybereason raw response is not valid, item in elements is not a dict")

        simple_values = item.get('simpleValues', {})
        element_values = item.get('elementValues', {})

        output = {}
        for info in PROCESS_INFO:
            if info.get('type') == 'filterData':
                output[info['header']] = dict_safe_get(item, ['filterData', 'groupByValue'])

        output = update_output(output, simple_values, element_values, PROCESS_INFO)
        outputs.append(output)

    context = []
    for output in outputs:
        # Remove whitespaces from dictionary keys
        context.append({key.translate({32: None}): value for key, value in output.items()})

    return CommandResults(
        readable_output=tableToMarkdown('Cybereason Processes', outputs, headers=PROCESS_HEADERS),
        outputs_prefix='Cybereason.Process',
        outputs_key_field='Name',
        outputs=context)


def query_processes(client: Client, machine: str, process_name: Any, only_suspicious: str = None,
                    has_incoming_connection: str = None, has_outgoing_connection: str = None, has_external_connection: str = None,
                    unsigned_unknown_reputation: str = None, from_temporary_folder: str = None,
                    privileges_escalation: str = None, maclicious_psexec: str = None) -> dict:
    machine_filters = []
    process_filters = []

    if machine:
        machine_filters.append({'facetName': 'elementDisplayName', 'values': [machine]})

    if process_name:
        process_filters.append({'facetName': 'elementDisplayName', 'values': [process_name]})

    if only_suspicious and only_suspicious == 'true':
        process_filters.append({'facetName': 'hasSuspicions', 'values': [True]})

    if has_incoming_connection == 'true':
        process_filters.append({'facetName': 'hasIncomingConnection', 'values': [True]})

    if has_outgoing_connection == 'true':
        process_filters.append({'facetName': 'hasOutgoingConnection', 'values': [True]})

    if has_external_connection == 'true':
        process_filters.append({'facetName': 'hasExternalConnection', 'values': [True]})

    if unsigned_unknown_reputation == 'true':
        process_filters.append({'facetName': 'unknownUnsignedEvidence', 'values': [True]})

    if from_temporary_folder == 'true':
        process_filters.append({'facetName': 'runningFromTempEvidence', 'values': [True]})

    if privileges_escalation == 'true':
        process_filters.append({'facetName': 'privilegeEscalationSuspicion', 'values': [True]})

    if maclicious_psexec == 'true':
        process_filters.append({'facetName': 'executedByPsexecSuspicion', 'values': [True]})

    path = [
        {
            'requestedType': 'Machine',
            'filters': machine_filters,
            'connectionFeature': {'elementInstanceType': 'Machine', 'featureName': 'processes'}
        },
        {
            'requestedType': 'Process',
            'filters': process_filters,
            'isResult': True
        }
    ]

    json_body = build_query(PROCESS_FIELDS, path)

    return client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)


def query_connections_command(client: Client, args: dict):
    machine = argToList(args.get('machine'))
    ip = argToList(args.get('ip'))

    if ip and machine:
        raise Exception('Too many arguments given.')
    elif not ip and not machine:
        raise Exception('Not enough arguments given.')

    if machine:
        input_list = machine
    else:
        input_list = ip

    for filter_input in input_list:
        response = query_connections(client, machine, ip, filter_input)
        elements = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
        outputs = []

        for item in list(elements.values()):
            simple_values = dict_safe_get(item, ['simpleValues'], default_return_value={}, return_type=dict)
            element_values = dict_safe_get(item, ['elementValues'], default_return_value={}, return_type=dict)

            output = update_output({}, simple_values, element_values, CONNECTION_INFO)
            outputs.append(output)

        context = []
        for output in outputs:
            # Remove whitespaces from dictionary keys
            context.append({key.translate({32: None}): value for key, value in output.items()})

        return CommandResults(
            readable_output=tableToMarkdown(f'Cybereason Connections for: {filter_input}', outputs),
            outputs_prefix='Cybereason.Connection',
            outputs_key_field='Name',
            outputs=context)
    return None


def query_connections(client: Client, machine: str, ip: str, filter_input: str) -> dict:
    if machine:
        path = [
            {
                'requestedType': 'Connection',
                'filters': [],
                'connectionFeature': {
                    'elementInstanceType': 'Connection',
                    'featureName': 'ownerMachine'
                },
                'isResult': True
            },
            {
                'requestedType': 'Machine',
                'filters': [{
                    'facetName': 'elementDisplayName',
                    'values': [filter_input],
                    'filterType': 'Equals'
                }]
            }
        ]
    elif ip:
        path = [
            {
                'requestedType': 'Connection',
                'filters':
                    [{
                        'facetName': 'elementDisplayName',
                        'values': [filter_input]
                    }],
                'isResult': True
            }
        ]
    else:
        path = [{}]

    json_body = build_query(CONNECTION_FIELDS, path)
    response = client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)

    return response


def query_malops_command(client: Client, args: dict):
    total_result_limit = arg_to_number(args.get('totalResultLimit'))
    per_group_limit = arg_to_number(args.get('perGroupLimit'))
    template_context = args.get('templateContext')
    filters = json.loads(str(args.get('filters'))) if args.get('filters') else []
    within_last_days = args.get('withinLastDays')
    guid_list = argToList(args.get('malopGuid'))

    if within_last_days:
        current_timestamp = time.time()
        current_datetime = datetime.fromtimestamp(current_timestamp)
        within_last_days_datetime = current_datetime - timedelta(days=int(within_last_days))
        within_last_days_timestamp = (time.mktime(
            within_last_days_datetime.timetuple()) + within_last_days_datetime.microsecond / 1E6)  # Converting datetime to time
        within_last_days_timestamp *= 1000
        filters.append({
            'facetName': 'malopLastUpdateTime',
            'values': [within_last_days_timestamp],
            'filterType': 'GreaterThan'
        })

    malop_process_type, malop_loggon_session_type = query_malops(client, total_result_limit, per_group_limit,
                                                                 template_context, filters, guid_list=guid_list)
    outputs = []

    data: dict = {}
    for response in (malop_process_type, malop_loggon_session_type):
        data = response.get('data', {}) if response else {}
        malops_map = dict_safe_get(data, ['resultIdToElementDataMap'], default_return_value={}, return_type=dict)
        if not data or not malops_map:
            continue

        for guid, malop in malops_map.items():
            simple_values = dict_safe_get(malop, ['simpleValues'], {}, dict)
            management_status = dict_safe_get(simple_values, ['managementStatus', 'values', 0],
                                              default_return_value='',
                                              return_type=str)

            if management_status.upper() == 'CLOSED':
                continue

            creation_time = translate_timestamp(dict_safe_get(simple_values, ['creationTime', 'values', 0]))
            malop_last_update_time = translate_timestamp(
                dict_safe_get(simple_values, ['malopLastUpdateTime', 'values', 0]))
            raw_decision_failure = dict_safe_get(simple_values, ['decisionFeature', 'values', 0],
                                                 default_return_value='', return_type=str)
            decision_failure = raw_decision_failure.replace('Process.', '')
            raw_suspects = dict_safe_get(malop, ['elementValues', 'suspects'], default_return_value={},
                                         return_type=dict)
            suspects_string = ''
            if raw_suspects:
                suspects = dict_safe_get(raw_suspects, ['elementValues', 0], default_return_value={}, return_type=dict)
                suspects_string = f"{suspects.get('elementType')}: {suspects.get('name')}"

            affected_machines = []
            elementValues = dict_safe_get(malop, ['elementValues', 'affectedMachines', 'elementValues'],
                                          default_return_value=[], return_type=list)
            for machine in elementValues:
                if not isinstance(machine, dict):
                    raise ValueError("Cybereason raw response is not valid, machine in elementValues is not a dict")

                affected_machines.append(machine.get('name', ''))

            involved_hashes = []  # type: List[str]
            cause_elements_amount = dict_safe_get(simple_values, ['rootCauseElementHashes', 'totalValues'])
            if cause_elements_amount != 0:
                involved_hashes.append(cause_elements_amount)

            malop_output = {
                'GUID': guid,
                'Link': SERVER + '/#/malop/' + guid,
                'CreationTime': creation_time,
                'DecisionFailure': re.sub(r'\([^)]*\)', '', decision_failure),
                'Suspects': suspects_string,
                'LastUpdateTime': malop_last_update_time,
                'Status': management_status,
                'AffectedMachine': affected_machines,
                'InvolvedHash': involved_hashes
            }
            outputs.append(malop_output)

    return CommandResults(
        readable_output=tableToMarkdown('Cybereason Malops', outputs, headers=MALOP_HEADERS) if outputs else 'No malops found',
        outputs_prefix='Cybereason.Malops',
        outputs_key_field='GUID',
        outputs=outputs)


def poll_malops(client: Client, start_time):
    end_time = round(datetime.now().timestamp()) * 1000
    json_body = {"startTime": start_time, "endTime": end_time}
    api_response = client.cybereason_api_call('POST', '/rest/detection/inbox', json_body=json_body)
    demisto.debug(f"Fetching the length of rest/dectection malops : {len(api_response)}")
    return api_response


def get_non_edr_malop_data(client, start_time):
    malop_data = poll_malops(client, start_time)
    non_edr_malop_data = []
    for malops in malop_data['malops']:
        if not malops.get('edr'):
            non_edr_malop_data.append(malops)

    malop_data.clear()
    demisto.debug(f"Total count of EPP Malops fetched is: {len(non_edr_malop_data)}")
    return non_edr_malop_data


def query_malops(
    client: Client, total_result_limit: int = None, per_group_limit: int = None, template_context: str = None,
        filters: list = None, guid_list: str = None) -> Any:
    json_body = {
        'totalResultLimit': int(total_result_limit) if total_result_limit else 10000,
        'perGroupLimit': int(per_group_limit) if per_group_limit else 10000,
        'perFeatureLimit': 100,
        'templateContext': template_context or 'MALOP',
        'queryPath': [
            {
                'requestedType': None,
                'guidList': guid_list,
                'result': True,
                'filters': filters
            }
        ]
    }
    # By Cybereason documentation - Inorder to get all malops, The client should send 2 requests as follow:
    # First request - "MalopProcess"
    json_body['queryPath'][0]['requestedType'] = "MalopProcess"  # type: ignore
    malop_process_type = client.cybereason_api_call('POST', '/rest/crimes/unified', json_body=json_body)
    # Second request - "MalopLogonSession"
    json_body['queryPath'][0]['requestedType'] = "MalopLogonSession"  # type: ignore
    malop_loggon_session_type = client.cybereason_api_call('POST', '/rest/crimes/unified', json_body=json_body)

    return malop_process_type, malop_loggon_session_type


def isolate_machine_command(client: Client, args: dict):
    machine = str(args.get('machine'))
    response, pylum_id = isolate_machine(client, machine)
    result = response.get(pylum_id)
    if result == 'Succeeded':
        return [
            CommandResults(
                readable_output='Machine was isolated successfully.',
                outputs_prefix='Cybereason',
                outputs_key_field='Machine',
                outputs={
                    'Machine': machine,
                    'IsIsolated': True
                }
            )
        ]
    else:
        raise Exception('Failed to isolate machine.')


def isolate_machine(client: Client, machine: str) -> Any:
    pylum_id = get_pylum_id(client, machine)

    cmd_url = '/rest/monitor/global/commands/isolate'
    json_body = {
        'pylumIds': [pylum_id]

    }
    response = client.cybereason_api_call('POST', cmd_url, json_body=json_body)

    return response, pylum_id


def unisolate_machine_command(client: Client, args: dict):
    machine = str(args.get('machine'))
    response, pylum_id = unisolate_machine(client, machine)
    result = response.get(pylum_id)
    if result == 'Succeeded':
        return [
            CommandResults(
                readable_output='Machine was un-isolated successfully.',
                outputs_prefix='Cybereason',
                outputs_key_field='Machine',
                outputs={
                    'Machine': machine,
                    'IsIsolated': False
                }
            )
        ]
    else:
        raise Exception('Failed to un-isolate machine.')


def unisolate_machine(client: Client, machine: str) -> Any:
    pylum_id = get_pylum_id(client, machine)
    cmd_url = '/rest/monitor/global/commands/un-isolate'
    json_body = {
        'pylumIds': [pylum_id]

    }
    response = client.cybereason_api_call('POST', cmd_url, json_body=json_body)

    return response, pylum_id


def malop_processes_command(client: Client, args: dict):
    malop_guids = args.get('malopGuids')
    machine_name = str(args.get('machineName'))
    date_time = str(args.get('dateTime'))

    milliseconds = 0
    filter_input = []

    if date_time != 'None':
        date_time_parser = dateparser.parse(date_time)
        if not date_time_parser:
            demisto.info("Returning all the processes since the entered date is not valid.")
        if date_time_parser:
            epoch_time = date_time_parser.timestamp()
            milliseconds = int(epoch_time) * 1000
        filter_input = [{"facetName": "creationTime", "filterType": "GreaterThan", "values": [milliseconds], "isResult": True}]

    if isinstance(malop_guids, str):
        malop_guids = malop_guids.split(',')
    elif not isinstance(malop_guids, list):
        raise Exception('malopGuids must be array of strings')

    machine_name_list = [machine.lower() for machine in argToList(machine_name)]

    response = malop_processes(client, malop_guids, filter_input)
    elements = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
    outputs = []

    for item in list(elements.values()):
        simple_values = dict_safe_get(item, ['simpleValues'], default_return_value={}, return_type=dict)
        element_values = dict_safe_get(item, ['elementValues'], default_return_value={}, return_type=dict)
        if machine_name_list != ['none']:
            machine_list = dict_safe_get(element_values, ['ownerMachine', 'elementValues'], default_return_value=[],
                                         return_type=list)
            wanted_machine = False
            for machine in machine_list:
                current_machine_name = machine.get('name', '').lower()
                if current_machine_name in machine_name_list:
                    wanted_machine = True
                    break

            if not wanted_machine:
                continue

            output = {}
            for info in PROCESS_INFO:
                if info.get('type', '') == 'filterData':
                    output[info['header']] = dict_safe_get(item, ['filterData', 'groupByValue'])

            output = update_output(output, simple_values, element_values, PROCESS_INFO)
            outputs.append(output)
        else:
            output = {}
            for info in PROCESS_INFO:
                if info.get('type', '') == 'filterData':
                    output[info['header']] = dict_safe_get(item, ['filterData', 'groupByValue'])

            output = update_output(output, simple_values, element_values, PROCESS_INFO)
            outputs.append(output)

    context = []
    for output in outputs:
        # Remove whitespaces from dictionary keys
        context.append({key.translate({32: None}): value for key, value in output.items()})
    demisto.debug(f"context, {context}")
    demisto.debug(f"outputs, {outputs}")
    return CommandResults(
        readable_output=tableToMarkdown('Cybereason Malop Processes', outputs, headers=PROCESS_HEADERS, removeNull=True),
        outputs_prefix='Cybereason.Process',
        outputs_key_field='Name',
        outputs=context)


def malop_processes(client: Client, malop_guids: list, filter_value: list) -> dict:
    json_body = {
        'queryPath': [
            {
                'requestedType': 'MalopProcess',
                'filters': [],
                'guidList': malop_guids,
                'connectionFeature': {
                    'elementInstanceType': 'MalopProcess',
                    'featureName': 'suspects'
                }
            },
            {
                'requestedType': 'Process',
                'filters': filter_value,
                'isResult': True
            }
        ],
        'totalResultLimit': 1000,
        'perGroupLimit': 1200,
        'perFeatureLimit': 1200,
        'templateContext': 'MALOP',
        'queryTimeout': None
    }
    return client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)


def add_comment_command(client: Client, args: dict):
    comment = str(args.get('comment')) if args.get('comment') else ''
    malop_guid = str(args.get('malopGuid'))
    try:
        add_comment(client, malop_guid, comment.encode('utf-8'))
        return CommandResults(readable_output='Comment added successfully')
    except Exception as e:
        raise Exception('Failed to add new comment. Orignal Error: ' + str(e))


def add_comment(client: Client, malop_guid: str, comment: Any):
    cmd_url = '/rest/crimes/comment/' + malop_guid
    client.cybereason_api_call('POST', cmd_url, data=comment, return_json=False)


def update_malop_status_command(client: Client, args: dict):
    status = str(args.get('status'))
    malop_guid = str(args.get('malopGuid'))

    if status not in STATUS_MAP:
        raise Exception(
            'Invalid status. Given status must be one of the following: To Review,Unread,Remediated or Not Relevant')

    update_malop_status(client, malop_guid, status)

    return CommandResults(
        readable_output=f'Successfully updated malop {malop_guid} to status {status}',
        outputs_prefix='Cybereason.Malops',
        outputs_key_field='GUID',
        outputs={
            'GUID': malop_guid,
            'Status': status
        })


def update_malop_status(client: Client, malop_guid: str, status: str) -> None:
    api_status = STATUS_MAP[status]

    json_body = {malop_guid: api_status}

    response = client.cybereason_api_call('POST', '/rest/crimes/status', json_body=json_body)
    if response['status'] != 'SUCCESS':
        raise Exception(f"Failed to update malop {malop_guid} status to {status}. Message: {response['message']}")


def prevent_file_command(client: Client, args: dict):
    file_hash = str(args.get('md5')) if args.get('md5') else ''
    response = prevent_file(client, file_hash)
    if response['outcome'] == 'success':

        return CommandResults(
            readable_output='File was prevented successfully',
            outputs_prefix='Cybereason.Process',
            outputs_key_field='MD5',
            outputs={
                'MD5': file_hash,
                'Prevent': True
            })
    else:
        raise Exception('Failed to prevent file')


def prevent_file(client: Client, file_hash: str) -> dict:
    json_body = [{
        'keys': [file_hash],
        'maliciousType': 'blacklist',
        'remove': False,
        'prevent': True
    }]

    return client.cybereason_api_call('POST', '/rest/classification/update', json_body=json_body)


def unprevent_file_command(client: Client, args: dict):
    file_hash = str(args.get('md5'))
    response = unprevent_file(client, file_hash)
    if response['outcome'] == 'success':

        return CommandResults(
            readable_output='File was unprevented successfully',
            outputs_prefix='Cybereason.Process',
            outputs_key_field='MD5',
            outputs={
                'MD5': file_hash,
                'Prevent': False
            })
    else:
        raise Exception('Failed to unprevent file')


def unprevent_file(client: Client, file_hash: str) -> dict:
    json_body = [{
        'keys': [str(file_hash)],
        'remove': True,
        'prevent': False
    }]

    return client.cybereason_api_call('POST', '/rest/classification/update', json_body=json_body)


def available_remediation_actions_command(client: Client, args: dict):
    malop_guid = args.get('malopGuid')
    json_body = {
        "detectionEventMalopGuids": [],
        "processMalopGuids": [malop_guid]
    }

    response = client.cybereason_api_call('POST', '/rest/detection/custom-remediation', json_body=json_body)
    if response:
        cybereason_outputs = []
        data_list = dict_safe_get(response, ['data'], default_return_value={}, return_type=list)
        if data_list:
            for data in data_list:
                uniqueId = data["uniqueId"]
                remediationType = data["remediationType"]
                targetName = data["targetName"]
                targetID = data["targetId"]
                machineName = data["machineName"]
                malopType = data["malopType"]
                malopId = data["malopId"]
                machineConnected = data["machineConnected"]
                cybereason_outputs.append({
                    'UniqueId': uniqueId,
                    'RemediationType': remediationType,
                    'TargetName': targetName,
                    'TargetID': targetID,
                    'MachineName': machineName,
                    'MalopType': malopType,
                    'MalopId': malopId,
                    "MachineConnected": machineConnected
                })

    return CommandResults(readable_output=tableToMarkdown(f'Cybereason available remediation actions for malop {malop_guid}:',
                                                          cybereason_outputs, removeNull=False),
                          outputs_prefix='Cybereason.Remediation',
                          outputs_key_field='TargetID', outputs=cybereason_outputs)


def kill_process_command(client: Client, args: dict):
    malop_guid = str(args.get('malopGuid'))
    machine_name = str(args.get('machine'))
    target_id = str(args.get('targetId'))
    user_name = str(args.get('userName'))
    comment = str(args.get('comment')) if args.get('comment') else 'Kill Process Remediation Action Succeeded'
    remediation_action = 'KILL_PROCESS'
    is_machine_connected = is_probe_connected_command(client, args, is_remediation_command=True)
    if is_machine_connected is True:
        response = get_remediation_action(client, malop_guid, machine_name, target_id, remediation_action)
        action_status = get_remediation_action_status(client, user_name, malop_guid, response, comment)
        if dict_safe_get(action_status, ['Remediation status']) == 'SUCCESS':
            success_response = f'''Kill process remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            return CommandResults(readable_output=success_response)
        elif dict_safe_get(action_status, ['Remediation status']) == 'FAILURE':
            failure_response = f'''Kill process remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Reason: {dict_safe_get(
                    action_status, ['Reason'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            raise DemistoException(failure_response)
        return None
    else:
        raise DemistoException('Machine must be connected to Cybereason in order to perform this action.')


def quarantine_file_command(client: Client, args: dict):
    malop_guid = str(args.get('malopGuid'))
    machine_name = str(args.get('machine'))
    target_id = str(args.get('targetId'))
    user_name = str(args.get('userName'))
    comment = str(args.get('comment')) if args.get('comment') else 'Quarantine File Remediation Action Succeeded'
    remediation_action = 'QUARANTINE_FILE'
    is_machine_connected = is_probe_connected_command(client, args, is_remediation_command=True)
    if is_machine_connected is True:
        response = get_remediation_action(client, malop_guid, machine_name, target_id, remediation_action)
        action_status = get_remediation_action_status(client, user_name, malop_guid, response, comment)
        if dict_safe_get(action_status, ['Remediation status']) == 'SUCCESS':
            success_response = f'''Quarantine file remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            return CommandResults(readable_output=success_response)
        elif dict_safe_get(action_status, ['Remediation status']) == 'FAILURE':
            failure_response = f'''Quarantine file remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Reason: {dict_safe_get(
                    action_status, ['Reason'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            raise DemistoException(failure_response)
        return None
    else:
        raise DemistoException('Machine must be connected to Cybereason in order to perform this action.')


def unquarantine_file_command(client: Client, args: dict):
    malop_guid = str(args.get('malopGuid'))
    machine_name = str(args.get('machine'))
    target_id = str(args.get('targetId'))
    user_name = str(args.get('userName'))
    comment = str(args.get('comment')) if args.get('comment') else 'Unquarantine File Remediation Action Succeded'
    remediation_action = 'UNQUARANTINE_FILE'
    is_machine_connected = is_probe_connected_command(client, args, is_remediation_command=True)
    if is_machine_connected is True:
        response = get_remediation_action(client, malop_guid, machine_name, target_id, remediation_action)
        action_status = get_remediation_action_status(client, user_name, malop_guid, response, comment)
        if dict_safe_get(action_status, ['Remediation status']) == 'SUCCESS':
            success_response = f'''Unquarantine file remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            return CommandResults(readable_output=success_response)
        elif dict_safe_get(action_status, ['Remediation status']) == 'FAILURE':
            failure_response = f'''Unquarantine file remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Reason: {dict_safe_get(
                    action_status, ['Reason'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            raise DemistoException(failure_response)
        return None
    else:
        raise DemistoException('Machine must be connected to Cybereason in order to perform this action.')


def block_file_command(client: Client, args: dict):
    malop_guid = str(args.get('malopGuid'))
    machine_name = str(args.get('machine'))
    target_id = str(args.get('targetId'))
    user_name = str(args.get('userName'))
    comment = str(args.get('comment')) if args.get('comment') else 'Block File Remediation Action Succeeded'
    remediation_action = 'BLOCK_FILE'
    is_machine_connected = is_probe_connected_command(client, args, is_remediation_command=True)
    if is_machine_connected is True:
        response = get_remediation_action(client, malop_guid, machine_name, target_id, remediation_action)
        action_status = get_remediation_action_status(client, user_name, malop_guid, response, comment)
        if dict_safe_get(action_status, ['Remediation status']) == 'SUCCESS':
            success_response = f'''Block file remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            return CommandResults(readable_output=success_response)
        elif dict_safe_get(action_status, ['Remediation status']) == 'FAILURE':
            failure_response = f'''Block file remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Reason: {dict_safe_get(
                    action_status, ['Reason'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            raise DemistoException(failure_response)
        return None
    else:
        raise DemistoException('Machine must be connected to Cybereason in order to perform this action.')


def delete_registry_key_command(client: Client, args: dict):
    malop_guid = str(args.get('malopGuid'))
    machine_name = str(args.get('machine'))
    target_id = str(args.get('targetId'))
    user_name = str(args.get('userName'))
    comment = str(args.get('comment')) if args.get('comment') else 'Delete Registry Key Remediation Action Succeeded'
    remediation_action = 'DELETE_REGISTRY_KEY'
    is_machine_connected = is_probe_connected_command(client, args, is_remediation_command=True)
    if is_machine_connected is True:
        response = get_remediation_action(client, malop_guid, machine_name, target_id, remediation_action)
        action_status = get_remediation_action_status(client, user_name, malop_guid, response, comment)
        if dict_safe_get(action_status, ['Remediation status']) == 'SUCCESS':
            success_response = f'''Delete registry key remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            return CommandResults(readable_output=success_response)
        elif dict_safe_get(action_status, ['Remediation status']) == 'FAILURE':
            failure_response = f'''Delete registry key remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Reason: {dict_safe_get(
                    action_status, ['Reason'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            raise DemistoException(failure_response)
        return None
    else:
        raise DemistoException('Machine must be connected to Cybereason in order to perform this action.')


def kill_prevent_unsuspend_command(client: Client, args: dict):
    malop_guid = str(args.get('malopGuid'))
    machine_name = str(args.get('machine'))
    target_id = str(args.get('targetId'))
    user_name = str(args.get('userName'))
    comment = str(args.get('comment')) if args.get('comment') else 'Kill Prevent Unsuspend Remediation Action Succeeded'
    remediation_action = 'KILL_PREVENT_UNSUSPEND'
    is_machine_connected = is_probe_connected_command(client, args, is_remediation_command=True)
    if is_machine_connected is True:
        response = get_remediation_action(client, malop_guid, machine_name, target_id, remediation_action)
        action_status = get_remediation_action_status(client, user_name, malop_guid, response, comment)
        if dict_safe_get(action_status, ['Remediation status']) == 'SUCCESS':
            success_response = f'''Kill prevent unsuspend remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            return CommandResults(readable_output=success_response)
        elif dict_safe_get(action_status, ['Remediation status']) == 'FAILURE':
            failure_response = f'''Kill prevent unsuspend remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n" Reason: {dict_safe_get(
                    action_status, ['Reason'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            raise DemistoException(failure_response)
        return None
    else:
        raise DemistoException('Machine must be connected to Cybereason in order to perform this action.')


def unsuspend_process_command(client: Client, args: dict):
    malop_guid = str(args.get('malopGuid'))
    machine_name = str(args.get('machine'))
    target_id = str(args.get('targetId'))
    user_name = str(args.get('userName'))
    comment = str(args.get('comment')) if args.get('comment') else 'Unsuspend Process Remediation Action Succeeded'
    remediation_action = 'UNSUSPEND_PROCESS'
    is_machine_connected = is_probe_connected_command(client, args, is_remediation_command=True)
    if is_machine_connected is True:
        response = get_remediation_action(client, malop_guid, machine_name, target_id, remediation_action)
        action_status = get_remediation_action_status(client, user_name, malop_guid, response, comment)
        if dict_safe_get(action_status, ['Remediation status']) == 'SUCCESS':
            success_response = f'''Unsuspend process remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            return CommandResults(readable_output=success_response)
        elif dict_safe_get(action_status, ['Remediation status']) == 'FAILURE':
            failure_response = f'''Unsuspend process remediation action status is: {dict_safe_get(
                action_status, ['Remediation status'])} \n Reason: {dict_safe_get(
                    action_status, ['Reason'])} \n Remediation ID: {dict_safe_get(action_status, ['Remediation ID'])}'''
            raise DemistoException(failure_response)
        return None
    else:
        raise DemistoException('Machine must be connected to Cybereason in order to perform this action.')


def get_remediation_action(client: Client, malop_guid: str, machine_name: str, target_id: str, remediation_action: str) -> dict:
    machine_guid = get_machine_guid(client, machine_name)
    json_body = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: [
                {
                    'targetId': target_id,
                    'actionType': remediation_action
                }
            ]
        }
    }

    return client.cybereason_api_call('POST', '/rest/remediate', json_body=json_body)


def get_remediation_action_status(
        client: Client, user_name: str, malop_guid: str, response: dict, comment: str) -> dict:
    remediation_id = dict_safe_get(response, ['remediationId'])
    progress_api_response = get_remediation_action_progress(client, user_name, malop_guid, remediation_id)
    status = dict_safe_get(progress_api_response, ['Remediation status'])
    if status == 'SUCCESS':
        add_comment(client, malop_guid, comment.encode('utf-8'))
    progress_api_response["Remediation ID"] = remediation_id
    return progress_api_response


def get_remediation_action_progress(
        client: Client, username: str, malop_id: str, remediation_id: str) -> dict:
    final_response = ''
    final_response = client.cybereason_api_call(
        'GET', '/rest/remediate/progress/' + username + '/' + str(malop_id) + '/' + remediation_id,
        retries=3, backoff_factor=5)
    statusLog_lenght = len(dict_safe_get(final_response, ['statusLog']))
    if statusLog_lenght == 0:
        raise Exception("The given target ID is incorrect.")
    else:
        statusLog_final_response = dict_safe_get(final_response, ['statusLog', statusLog_lenght - 1])
        statusLog_final_error = dict_safe_get(statusLog_final_response, ['error'])
        statusLog_final_status = dict_safe_get(statusLog_final_response, ['status'])
        if statusLog_final_error is None:
            return {"Remediation status": statusLog_final_status}
        else:
            return {"Remediation status": statusLog_final_status, "Reason": dict_safe_get(statusLog_final_error, ['message'])}


def query_file_command(client: Client, args: dict) -> Any:
    file_hash_list = argToList(args.get('file_hash'))
    for file_hash in file_hash_list:

        filters = []

        hash_type = get_hash_type(file_hash)
        if hash_type == 'sha1':
            filters.append({
                'facetName': 'sha1String',
                'values': [file_hash],
                'filterType': 'ContainsIgnoreCase'
            })
        elif hash_type == 'md5':
            filters.append({
                'facetName': 'md5String',
                'values': [file_hash],
                'filterType': 'ContainsIgnoreCase'
            })
        else:
            raise Exception('Hash type is not supported.')

        data = query_file(client, filters)

        if data:
            cybereason_outputs = []
            files = dict_safe_get(data, ['resultIdToElementDataMap'], {}, dict)
            for fname, fstat in files.items():
                raw_machine_details = dict_safe_get(get_file_machine_details(client, fname), ['data', 'resultIdToElementDataMap'],
                                                    default_return_value={}, return_type=dict)
                machine_details = dict_safe_get(raw_machine_details, dict_safe_get(list(raw_machine_details.keys()), [0]),
                                                default_return_value={}, return_type=dict)
                simple_values = dict_safe_get(fstat, ['simpleValues'], default_return_value={}, return_type=dict)
                file_name = dict_safe_get(simple_values, ['elementDisplayName', 'values', 0])
                md5 = dict_safe_get(simple_values, ['md5String', 'values', 0])
                sha1 = dict_safe_get(simple_values, ['sha1String', 'values', 0])
                path = dict_safe_get(simple_values, ['correctedPath', 'values', 0])
                machine = dict_safe_get(fstat, ['elementValues', 'ownerMachine', 'elementValues', 0, 'name'])

                machine_element_values = dict_safe_get(
                    machine_details, ['elementValues'], default_return_value={}, return_type=dict)
                machine_simple_values = dict_safe_get(
                    machine_details, ['simpleValues'], default_return_value={}, return_type=dict)

                os_version = dict_safe_get(machine_simple_values, ['ownerMachine.osVersionType', 'values', 0])
                raw_suspicions = dict_safe_get(machine_details, ['suspicions'], default_return_value={}, return_type=dict)

                suspicions = {}
                for key, value in raw_suspicions.items():
                    suspicions[key] = timestamp_to_datestring(value)

                evidences = []
                for key in list(machine_element_values.keys()):
                    if 'evidence' in key.lower():
                        evidences.append(key)
                for key in list(machine_simple_values.keys()):
                    if 'evidence' in key.lower():
                        evidences.append(key)

                company_name = None
                if 'companyName' in simple_values:
                    company_name = dict_safe_get(simple_values, ['companyName', 'values', 0])

                created_time = None
                if 'createdTime' in simple_values:
                    created_time = timestamp_to_datestring(dict_safe_get(simple_values, ['createdTime', 'values', 0]))

                modified_time = None
                if 'modifiedTime' in simple_values:
                    modified_time = timestamp_to_datestring(dict_safe_get(simple_values, ['modifiedTime', 'values', 0]))

                is_signed = None
                if 'isSigned' in simple_values:
                    is_signed = dict_safe_get(simple_values, ['isSigned', 'values', 0]) == 'true'

                cybereason_outputs.append({
                    'Name': file_name,
                    'CreationTime': created_time,
                    'ModifiedTime': modified_time,
                    'Malicious': fstat.get('isMalicious'),
                    'MD5': md5,
                    'SHA1': sha1,
                    'Path': path,
                    'Machine': machine,
                    'SuspicionsCount': machine_details.get('suspicionCount'),
                    'IsConnected': (dict_safe_get(
                        machine_simple_values, ['ownerMachine.isActiveProbeConnected', 'values', 0]) == 'true'),
                    'OSVersion': os_version,
                    'Suspicion': suspicions,
                    'Evidence': evidences,
                    'Signed': is_signed,
                    'Company': company_name
                })

            return CommandResults(
                readable_output=tableToMarkdown(
                    f'Cybereason file query results for the file hash: {file_hash}', cybereason_outputs, removeNull=True),
                outputs_prefix='Cybereason.File',
                outputs_key_field='Name',
                outputs=cybereason_outputs)
        else:
            raise DemistoException('No results found.')
    return None


def query_file(client: Client, filters: list) -> dict:
    query_fields = ['md5String', 'ownerMachine', 'avRemediationStatus', 'isSigned', 'signatureVerified',
                    'sha1String', 'maliciousClassificationType', 'createdTime', 'modifiedTime', 'size', 'correctedPath',
                    'productName', 'productVersion', 'companyName', 'internalName', 'elementDisplayName']
    path = [
        {
            'requestedType': 'File',
            'filters': filters,
            'isResult': True
        }
    ]
    json_body = build_query(query_fields, path)
    response = client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    if response.get('status') == 'SUCCESS' and 'data' in response:
        return response['data']
    else:
        raise Exception('Error occurred while trying to query the file.')


def get_file_machine_details(client: Client, file_guid: str) -> dict:
    query_fields = ["ownerMachine", "self", "elementDisplayName", "correctedPath", "canonizedPath", "mount",
                    "mountedAs", "createdTime", "modifiedTime", "md5String", "sha1String", "productType", "companyName",
                    "productName", "productVersion", "signerInternalOrExternal", "signedInternalOrExternal",
                    "signatureVerifiedInternalOrExternal", "signedByMicrosoft", "extensionType", "size",
                    "avRemediationStatus", "classificationDetectionName", "avScanTime", "relatedToMalop",
                    "isSuspicious", "maliciousClassificationType", "classificationBlocking", "isDownloadedFromInternet",
                    "downloadedFromDomain", "downloadedFromIpAddress", "downloadedFromUrl", "downloadedFromUrlReferrer",
                    "downloadedFromEmailFrom", "downloadedFromEmailMessageId", "downloadedFromEmailSubject",
                    "ownerMachine.isActiveProbeConnected", "ownerMachine.osVersionType", "quarantineVersion",
                    "originalVersion"]

    path = [
        {
            'requestedType': 'File',
            'guidList': [file_guid],
            'result': True
        }
    ]
    json_body = build_query(query_fields, path, template_context='DETAILS')

    return client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)


def query_domain_command(client: Client, args: dict) -> Any:
    domain_list = argToList(args.get('domain'))
    for domain_input in domain_list:

        filters = [{
            'facetName': 'elementDisplayName',
            'values': [domain_input],
            'filterType': 'ContainsIgnoreCase'
        }]

        data = query_domain(client, filters)
        if data:
            cybereason_outputs = []
            domains = dict_safe_get(data, ['resultIdToElementDataMap'], default_return_value={}, return_type=dict)
            for domain in list(domains.values()):
                if not isinstance(domain, dict):
                    raise ValueError("Cybereason raw response is not valid, domain in domains.values() is not dict")

                simple_values = dict_safe_get(domain, ['simpleValues'], default_return_value={}, return_type=dict)
                reputation = dict_safe_get(simple_values, ['maliciousClassificationType', 'values', 0])
                is_internal_domain = dict_safe_get(simple_values, ['isInternalDomain', 'values', 0]) == 'true'
                was_ever_resolved = dict_safe_get(simple_values, ['everResolvedDomain', 'values', 0]) == 'true'
                was_ever_resolved_as = dict_safe_get(simple_values, ['everResolvedSecondLevelDomain', 'values', 0]) == 'true'
                malicious = domain.get('isMalicious')
                suspicions_count = domain.get('suspicionCount')

                cybereason_outputs.append({
                    'Name': domain_input,
                    'Reputation': reputation,
                    'Malicious': malicious,
                    'SuspicionsCount': suspicions_count,
                    'IsInternalDomain': is_internal_domain,
                    'WasEverResolved': was_ever_resolved,
                    'WasEverResolvedAsASecondLevelDomain': was_ever_resolved_as
                })

            return CommandResults(
                readable_output=tableToMarkdown(
                    f'Cybereason domain query results for the domain: {domain_input}',
                    cybereason_outputs, headers=DOMAIN_HEADERS),
                outputs_prefix='Cybereason.Domain',
                outputs_key_field='Name',
                outputs=cybereason_outputs)
        else:
            raise DemistoException('No results found.')
    return None


def query_domain(client: Client, filters: list) -> dict:
    query_fields = ['maliciousClassificationType', 'isInternalDomain',
                    'everResolvedDomain', 'everResolvedSecondLevelDomain', 'elementDisplayName']
    path = [
        {
            'requestedType': 'DomainName',
            'filters': filters,
            'isResult': True
        }
    ]
    json_body = build_query(query_fields, path)
    response = client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    if response.get('status', '') == 'SUCCESS' and 'data' in response:
        return response['data']
    else:
        raise Exception('Error occurred while trying to query the file.')


def query_user_command(client: Client, args: dict):
    username_list = argToList(args.get('username'))
    for username in username_list:

        filters = [{
            'facetName': 'elementDisplayName',
            'values': [username],
            'filterType': 'ContainsIgnoreCase'
        }]

        data = query_user(client, filters)

        if data:
            cybereason_outputs = []
            users = dict_safe_get(data, ['resultIdToElementDataMap'], default_return_value={}, return_type=dict)

            for user in list(users.values()):
                simple_values = dict_safe_get(user, ['simpleValues'], default_return_value={}, return_type=dict)
                element_values = dict_safe_get(user, ['elementValues'], default_return_value={}, return_type=dict)

                domain = dict_safe_get(simple_values, ['domain', 'values', 0])
                local_system = dict_safe_get(simple_values, ['isLocalSystem', 'values', 0]) == 'true'
                machine = dict_safe_get(element_values, ['ownerMachine', 'elementValues', 0, 'name'])
                organization = dict_safe_get(element_values, ['ownerOrganization', 'elementValues', 0, 'name'])

                cybereason_outputs.append({
                    'Username': username,
                    'Domain': domain,
                    'LastMachineLoggedInTo': machine,
                    'Organization': organization,
                    'LocalSystem': local_system
                })

            return CommandResults(
                readable_output=tableToMarkdown(
                    f'Cybereason user query results for the username: {username}', cybereason_outputs, headers=USER_HEADERS),
                outputs_prefix='Cybereason.User',
                outputs_key_field='Username',
                outputs=cybereason_outputs)
        else:
            raise DemistoException('No results found.')
    return None


def query_user(client: Client, filters: list) -> dict:
    query_fields = ['domain', 'ownerMachine', 'ownerOrganization', 'isLocalSystem', 'elementDisplayName']
    path = [
        {
            'requestedType': 'User',
            'filters': filters,
            'isResult': True
        }
    ]

    json_body = build_query(query_fields, path)

    response = client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    if response.get('status', '') == 'SUCCESS' and 'data' in response:
        return response['data']
    else:
        raise Exception('Error occurred while trying to query the file.')


def archive_sensor_command(client: Client, args: dict):
    sensor_id = args.get('sensorID')
    archive_reason = args.get('archiveReason')

    data = {
        "sensorsIds": [sensor_id],
        "argument": archive_reason
    }
    response = client.cybereason_api_call(
        'POST', '/rest/sensors/action/archive', json_body=data, return_json=False, custom_response=True)

    if response.status_code == 204:
        output = f"The selected Sensor with Sensor ID: {sensor_id} is not available for archive."
    elif response.status_code == 200:
        output = ""
        try:
            response_json = response.json()
            output = "Sensor archive status: "
            output += "Failed Actions: " + str(response_json['globalStats']['stats']['Failed']) + '. '
            output += "Succeeded Actions: " + str(response_json['globalStats']['stats']['Succeeded'])
        except Exception as e:
            raise Exception("Exception occurred while processing response for Archive action: " + str(e))
    else:
        try:
            json_response = response.json()
            raise DemistoException(f"Could not archive Sensor. The received response is {json_response}")
        except Exception:
            raise Exception(
                'Your request failed with the following error: ' + response.content + '. Response Status code: ' + str(
                    response.status_code))
    return CommandResults(readable_output=output)


def unarchive_sensor_command(client: Client, args: dict):
    sensor_id = args.get('sensorID')
    unarchive_reason = args.get('unarchiveReason')
    data = {
        "sensorsIds": [sensor_id],
        "argument": unarchive_reason
    }
    response = client.cybereason_api_call(
        'POST', '/rest/sensors/action/unarchive', json_body=data, return_json=False, custom_response=True)
    if response.status_code == 204:
        output = f"The selected Sensor with Sensor ID: {sensor_id} is not available for unarchive."
    elif response.status_code == 200:
        output = ""
        try:
            response_json = response.json()
            output = "Sensor unarchive status: "
            output += "Failed Actions: " + str(response_json['globalStats']['stats']['Failed']) + '. '
            output += "Succeeded Actions: " + str(response_json['globalStats']['stats']['Succeeded'])
        except Exception as e:
            raise Exception("Exception occurred while processing response for Unarchive action: " + str(e))
    else:
        try:
            json_response = response.json()
            raise DemistoException(f"Could not unarchive Sensor. The received response is {json_response}")
        except Exception:
            raise Exception(
                'Your request failed with the following error: ' + response.content + '. Response Status code: ' + str(
                    response.status_code))
    return CommandResults(readable_output=output)


def delete_sensor_command(client: Client, args: dict):
    sensor_id = args.get('sensorID')

    data = {
        "sensorsIds": [sensor_id]
    }
    response = client.cybereason_api_call(
        'POST', '/rest/sensors/action/delete', json_body=data, return_json=False, custom_response=True)

    if response.status_code == 204:
        output = f"The selected Sensor with Sensor ID: {sensor_id} is not available for deleting."
    elif response.status_code == 200:
        output = "Sensor deleted successfully."
    else:
        try:
            json_response = response.json()
            raise DemistoException(f"Could not delete Sensor. The received response is {json_response}")
        except Exception:
            raise Exception(
                'Your request failed with the following error: ' + response.content + '. Response Status code: ' + str(
                    response.status_code))
    return CommandResults(readable_output=output)


def malop_to_incident(malop: str) -> dict:
    if not isinstance(malop, dict):
        raise ValueError("Cybereason raw response is not valid, malop is not dict")

    status = 0
    malopStatus = ""
    if malop.get('status', ''):
        malopStatus = (malop.get('status', 'UNREAD'))
    elif malop.get('simpleValues', ''):
        malopStatus = (malop.get('simpleValues', {}).get('managementStatus', {}).get('values', ['UNREAD'])[0])

    if (malopStatus == "Remediated") or (malopStatus == "TODO"):
        status = 1
    elif (malopStatus == "Closed") or (malopStatus == "RESOLVED"):
        status = 2
    else:
        status = 0

    guid_string = malop.get('guidString', '')
    if not guid_string:
        guid_string = malop.get('guid', '')

    if malop.get("isEdr", '') or malop.get("edr", '') or malop.get('simpleValues', ''):
        link = SERVER + '/#/malop/' + guid_string
        isEdr = True
    else:
        link = SERVER + '/#/detection-malop/' + guid_string
        isEdr = False

    if simple_values := malop.get('simpleValues'):
        malopCreationTime = simple_values.get('creationTime', {}).get('values', ['2010-01-01'])[0]
        malopUpdateTime = simple_values.get('malopLastUpdateTime', {}).get('values', ['2010-01-01'])[0]
    else:
        malopCreationTime = str(malop.get('creationTime', '2010-01-01'))
        malopUpdateTime = str(malop.get('lastUpdateTime', '2010-01-01'))

    if element_values := malop.get('elementValues'):
        if root_cause_elements := element_values.get('rootCauseElements', {}).get('elementValues', []):
            rootCauseElementName = root_cause_elements[0].get('name', '')
            rootCauseElementType = root_cause_elements[0].get('elementType', '')
        else:
            rootCauseElementName = ''
            rootCauseElementType = ''
    else:
        rootCauseElementName = malop.get('primaryRootCauseName', '')
        rootCauseElementType = malop.get('rootCauseElementType', '')

    if malop_detection_type := malop.get('malopDetectionType'):
        detectionType = malop_detection_type
    else:
        detectionType = (malop.get('simpleValues', {}).get('detectionType', {}).get('values', [''])[0])

    malopGroup = malop.get('group', '')

    severity = malop.get('severity', '')

    incident = {
        'rawJSON': json.dumps(malop),
        'name': 'Cybereason Malop ' + guid_string,
        'dbotmirrorid': guid_string,
        'CustomFields': {
            'malopcreationtime': malopCreationTime,
            'malopupdatetime': malopUpdateTime,
            'maloprootcauseelementname': rootCauseElementName,
            'maloprootcauseelementtype': rootCauseElementType,
            'malopseverity': severity,
            'malopdetectiontype': detectionType,
            'malopedr': isEdr,
            'malopurl': link,
            'malopgroup': malopGroup
        },
        'labels': [{'type': 'GUID', 'value': guid_string}],
        'status': status}

    return incident


def fetch_incidents(client: Client):
    last_run = demisto.getLastRun()

    if last_run and last_run.get('creation_time'):
        last_update_time = int(last_run.get('creation_time'))
    else:
        # In first run
        last_update_time, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    max_update_time = int(last_update_time)

    if FETCH_BY == 'MALOP UPDATE TIME':
        filters = [{
            'facetName': 'malopLastUpdateTime',
            'values': [last_update_time],
            'filterType': 'GreaterThan'
        }]
    elif FETCH_BY == 'MALOP CREATION TIME':
        filters = [{
            'facetName': 'creationTime',
            'values': [last_update_time],
            'filterType': 'GreaterThan'
        }]
    else:
        raise Exception('Given filter to fetch by is invalid.')

    malop_process_type, malop_loggon_session_type = query_malops(client, total_result_limit=10000, per_group_limit=10000,
                                                                 filters=filters)
    incidents = []

    for response in (malop_process_type, malop_loggon_session_type):
        malops = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={},
                               return_type=dict)

        for malop in list(malops.values()):
            simple_values = dict_safe_get(malop, ['simpleValues'], default_return_value={}, return_type=dict)
            simple_values.pop('iconBase64', None)
            simple_values.pop('malopActivityTypes', None)
            malop_update_time = int(dict_safe_get(simple_values, ['malopLastUpdateTime', 'values', 0]))
            if int(malop_update_time) > int(max_update_time):
                max_update_time = malop_update_time

            guid_string = malop.get('guidString', '')
            if not guid_string:
                guid_string = malop.get('guid', '')

            try:
                incident = malop_to_incident(malop)
            except Exception:
                demisto.debug(f"edr malop got failed to convert into incident : {guid_string} and malop : {malop}")
                continue
            incidents.append(incident)

    # Enable Polling for Cybereason EPP Malops
    non_edr = get_non_edr_malop_data(client, last_update_time)
    if IS_EPP_ENABLED:
        demisto.info(f"Fetching EPP malop is enabled: {IS_EPP_ENABLED}")
        for non_edr_malops in non_edr:
            malop_update_time = dict_safe_get(non_edr_malops, ['lastUpdateTime'])

            if malop_update_time > max_update_time:
                max_update_time = malop_update_time

            guid_string = non_edr_malops.get('guidString', '')
            if not guid_string:
                guid_string = non_edr_malops.get('guid', '')

            try:
                incident = malop_to_incident(non_edr_malops)
            except Exception:
                demisto.debug(f"non edr malop got failed to convert into incident : {guid_string} and malop : {non_edr_malops}")
                continue
            incidents.append(incident)
        demisto.debug(f"Fetching the length of incidents list if epp in enabled : {len(incidents)}")

    demisto.setLastRun({
        'creation_time': max_update_time
    })

    demisto.incidents(incidents)


def login(client: Client):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close',
    }
    data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    client.cybereason_api_call('POST', '/login.html', data=data, headers=headers, custom_response=True, return_json=False)
    JSESSIONID = client._session.cookies.get("JSESSIONID")
    creation_time = int(time.time())
    return JSESSIONID, creation_time


def validate_jsession(client: Client):
    creation_time = int(time.time())
    integration_context = get_integration_context()
    token = integration_context.get('jsession_id')
    valid_until = integration_context.get('valid_until')
    demisto.debug(f"token: {token} and valid until: {valid_until}")
    if token and valid_until and creation_time < valid_until:
        demisto.debug(f"Token is still valid - did not expire. token: {token}")
        HEADERS["Cookie"] = f"JSESSIONID={token}"
        return
    token, creation_time = login(client)
    integration_context = {
        'jsession_id': token,
        'valid_until': creation_time + 28000
    }
    set_integration_context(integration_context)
    HEADERS["Cookie"] = f"JSESSIONID={token}"


def client_certificate():
    cert = CERTIFICATE

    if 'Bag Attributes' not in cert:
        raise Exception('Could not find Bag Attributes')
    if '-----BEGIN CERTIFICATE-----' not in cert:
        raise Exception('Could not find certificate file')
    if '-----BEGIN RSA PRIVATE KEY-----' in cert:  # guardrails-disable-line
        i = cert.index('-----BEGIN RSA PRIVATE KEY-----')  # guardrails-disable-line
    else:
        raise Exception('Could not find certificate key')
    client_cert = cert[:i]
    client_key = cert[i:]

    f = open('client.cert', 'wb')
    f.write(client_cert)
    f.flush()
    f.close()
    f = open('client.pem', 'wb')
    f.write(client_key)
    f.close()
    client_cert_file = os.path.abspath('client.cert')
    client_key_file = os.path.abspath('client.pem')

    session.cert = (client_cert_file, client_key_file)

    # Time to check if we are logged on
    response = session.get(url=SERVER)
    if response.status_code != 200 and response.status_code != 302:
        raise Exception("Failed to connect to server")

    # First time we may get a redirect, but second time should be 200
    response = session.get(url=SERVER)
    if response.status_code != 200:
        raise Exception("Failed to login with certificate. Expected response 200. Got: " + str(response.status_code))


def logout(client: Client):
    demisto.debug("Logout function is getting called")
    client.cybereason_api_call('GET', '/logout', return_json=False)


''' EXECUTION CODE '''

LOG(f'command is {demisto.command()}')

session = requests.session()


def get_file_guids(client: Client, malop_id: str) -> dict:
    """Get all File GUIDs for the given malop"""
    processes = fetch_malop_processes(client, malop_id)
    img_file_guids = fetch_imagefile_guids(client, processes)
    return img_file_guids


def fetch_malop_processes(client: Client, malop_id: str) -> list:
    json_body = {
        "queryPath": [
            {
                "requestedType": "MalopProcess",
                "filters": [],
                "guidList": [malop_id],
                "connectionFeature": {
                    "elementInstanceType": "MalopProcess",
                    "featureName": "suspects"
                }
            },
            {
                "requestedType": "Process",
                "filters": [],
                "isResult": True
            }
        ],
        "totalResultLimit": 1000,
        "perGroupLimit": 1200,
        "perFeatureLimit": 1200,
        "templateContext": "DETAILS",
        "queryTimeout": None,
        "customFields": [
            "maliciousByDualExtensionByFileRootCause",
            "creationTime",
            "endTime",
            "elementDisplayName"
        ]
    }
    response = client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    try:
        result = response['data']['resultIdToElementDataMap']
    except Exception as e:
        raise ValueError(f"Exception when parsing JSON response: {str(e)}")
    return list(result.keys())


def fetch_imagefile_guids(client: Client, processes: list) -> dict:
    json_body = {
        "queryPath": [
            {
                "requestedType": "Process",
                "guidList": processes,
                "result": True
            }
        ],
        "totalResultLimit": 1000,
        "perGroupLimit": 1000,
        "perFeatureLimit": 100,
        "templateContext": "DETAILS",
        "customFields": [
            "ownerMachine", "calculatedUser", "parentProcess", "execedBy", "service", "self", "openedFiles", "children",
            "elementDisplayName", "applicablePid", "tid", "creationTime", "firstSeenTime", "lastSeenTime", "endTime",
            "commandLine", "decodedCommandLine", "imageFilePath", "iconBase64", "isAggregate", "isServiceHost",
            "isDotNetProtected", "imageFile", "imageFile.extensionType", "imageFile.correctedPath", "imageFile.sha1String",
            "imageFile.md5String", "imageFile.productType", "imageFile.companyName", "imageFile.productName",
            "imageFile.signerInternalOrExternal", "imageFile.avRemediationStatus", "imageFile.comments", "fileAccessEvents",
            "registryEvents", "hookedFunctions", "productType", "imageFile.signedInternalOrExternal",
            "imageFile.signatureVerifiedInternalOrExternal", "imageFile.maliciousClassificationType",
            "imageFile.isDownloadedFromInternet", "imageFile.downloadedFromDomain", "imageFile.downloadedFromIpAddress",
            "imageFile.downloadedFromUrl", "imageFile.downloadedFromUrlReferrer", "imageFile.downloadedFromEmailFrom",
            "imageFile.downloadedFromEmailMessageId", "imageFile.downloadedFromEmailSubject",
            "ownerMachine.isActiveProbeConnected", "ownerMachine.osType", "ownerMachine.osVersionType",
            "ownerMachine.deviceModel", "childrenCreatedByThread", "failedToAccess", "autorun", "loadedModules",
            "markedForPrevention", "executionPrevented", "ransomwareAutoRemediationSuspended", "ransomwareAffectedFiles",
            "totalNumOfInstances", "lastMinuteNumOfInstances", "lastSeenTimeStamp", "cveEventsStr", "isExectuedByWmi",
            "wmiQueryStrings", "wmiPersistentObjects", "createdByWmi.wmiOperation", "createdByWmi.clientPid",
            "createdByWmi.isLocal", "createdByWmi.clientProcess", "createdByWmi.clientMachine", "injectionMethod",
            "originInjector", "hostProcess", "creatorThread", "hostedChildren", "isInjectingProcess", "injectedChildren",
            "isFullProcessMemoryDump", "creatorProcess", "createdChildren", "seenCreation", "newProcess", "processRatio",
            "hashRatio", "connections", "listeningConnections", "externalConnections", "internalConnections", "localConnections",
            "dynamicConfigurationConnections", "incomingConnections", "outgoingConnections",
            "absoluteHighVolumeExternalConnections", "totalNumberOfConnections", "totalTransmittedBytes", "totalReceivedBytes",
            "resolvedDnsQueriesDomainToIp", "resolvedDnsQueriesDomainToDomain", "resolvedDnsQueriesIpToDomain",
            "unresolvedDnsQueriesFromIp", "unresolvedDnsQueriesFromDomain", "cpuTime", "memoryUsage", "hasVisibleWindows",
            "integrity", "isHidden", "logonSession", "remoteSession", "isWhiteListClassification", "matchedWhiteListRuleIds"]
    }
    response = client.cybereason_api_call('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    img_file_guids = {}
    result = response['data']['resultIdToElementDataMap']
    try:
        for _process, details in list(result.items()):
            image_files = ('' if details['elementValues']['imageFile']['elementValues'] is None else details[
                'elementValues']['imageFile']['elementValues'])
            for image_file in image_files:
                img_file_guids[image_file['name']] = image_file['guid']  # type: ignore[index]
    except Exception as e:
        demisto.error(str(e))
    return img_file_guids


def start_fetchfile_command(client: Client, args: dict):
    malop_id = str(args.get('malopGUID'))
    user_name = str(args.get('userName'))
    response = get_file_guids(client, malop_id)
    for _filename, file_guid in list(response.items()):
        api_response = start_fetchfile(client, file_guid, user_name)
        try:
            if api_response['status'] == "SUCCESS":
                return CommandResults(readable_output="Successfully started fetching file for the given malop")
        except Exception:
            raise Exception("Failed to start fetch file process")
    return None


def start_fetchfile(client: Client, element_id: str, user_name: str) -> dict:
    json_body = {
        'elementGuids': [element_id],
        'initiatorUserName': user_name
    }
    return client.cybereason_api_call('POST', '/rest/fetchfile/start', json_body=json_body)


def fetchfile_progress_command(client: Client, args: dict):
    malop_id = str(args.get('malopGuid'))
    response = get_file_guids(client, malop_id)
    new_malop_comments = get_batch_id(client, response)
    filename = []
    status = []
    message = []
    output_message = []
    for item in range(len(new_malop_comments)):
        filename.append(new_malop_comments[item].get("name"))
        status.append(new_malop_comments[item].get("isSuccess"))
        message.append(new_malop_comments[item].get("message"))
        if status[item] is True:
            output_message.append('Filename: ' + str(filename) + ' Status: ' + str(status) + ' Batch ID: ' + str(message))
        else:
            output_message.append(str(message))

    return CommandResults(
        readable_output=str(output_message),
        outputs_prefix='Cybereason.Download.Progress',
        outputs_key_field='fileName',
        outputs={
            'fileName': filename,
            'status': status,
            'batchID': message,
            'MalopID': malop_id
        })


def get_batch_id(client: Client, suspect_files_guids: dict) -> list:
    new_malop_comments = []
    progress_response = fetchfile_progress(client)
    result = progress_response
    for file_status in result['data']:
        if file_status['fileName'] in list(suspect_files_guids.keys()) and file_status['succeeded'] is True:
            batch_id = file_status['batchId']
            file_name = file_status['fileName']
            new_malop_comments.append({"isSuccess": True, "message": batch_id, "name": file_name})
            del suspect_files_guids[file_status['fileName']]
    for suspect_file in list(suspect_files_guids.keys()):
        malop_comment = f'Could not download the file {suspect_file} from source machine, even after waiting for 80 seconds.'
        demisto.info(malop_comment)

    if not new_malop_comments:
        raise DemistoException(malop_comment)
    else:
        return new_malop_comments


def fetchfile_progress(client: Client):
    return client.cybereason_api_call(
        'GET', '/rest/fetchfile/downloads/progress', retries=3, backoff_factor=5)


def download_fetchfile_command(client: Client, args: dict):
    batch_id = str(args.get('batchID'))
    response = download_fetchfile(client, batch_id)
    if response.status_code == 200:
        file_download = fileResult('download.zip', response.content)
        return file_download
    else:
        error_message = f"request failed with the following error: {response.content} Response Status code:{response.status_code}"
        raise DemistoException(error_message)


def download_fetchfile(client: Client, batch_id: str) -> Any:
    url = f'/rest/fetchfile/getfiles/{batch_id}'
    return client.cybereason_api_call('GET', url, custom_response=True, return_json=False)


def close_fetchfile_command(client: Client, args: dict):
    batch_id = str(args.get('batchID'))
    response = close_fetchfile(client, batch_id)
    try:
        if response.json()['status'] == 'SUCCESS':
            return CommandResults(readable_output='Successfully aborts a file download operation that is in progress.')
    except Exception:
        raise Exception('The given Batch ID does not exist')


def close_fetchfile(client: Client, batch_id: str) -> Any:
    url = f'/rest/fetchfile/close/{batch_id}'
    return client.cybereason_api_call('GET', url, custom_response=True, return_json=False)


def malware_query_command(client: Client, args: dict):
    needs_attention = bool(argToBoolean(args.get('needsAttention'))) if args.get('needsAttention') else False
    malware_type = str(args.get('type'))
    malware_status = str(args.get('status'))
    time_stamp = str(args.get('timestamp'))
    limit_range = arg_to_number(args.get('limit'))
    if limit_range:
        if limit_range > 0:
            filter_response = malware_query_filter(client, needs_attention, malware_type, malware_status, time_stamp, limit_range)
            return CommandResults(raw_response=filter_response)
        return None
    else:
        raise DemistoException("Limit cannot be zero or a negative number.")


def malware_query_filter(
        client: Client, needs_attention: bool, malware_type: str, malware_status: str, time_stamp: str,
        limit_range: Optional[int]) -> dict:
    query = []
    if needs_attention:
        query.append({"fieldName": "needsAttention", "operator": "Is", "values": [bool(needs_attention)]})
    if malware_type != 'None':
        types = malware_type.split(",")
        query.append({"fieldName": "type", "operator": "Equals", "values": types})
    if malware_status != 'None':
        is_status = malware_status.split(",")
        query.append({"fieldName": "status", "operator": "Equals", "values": is_status})
    if time_stamp != 'None':
        query.append({"fieldName": "timestamp", "operator": "GreaterThan", "values": [arg_to_number(time_stamp)]})
    response = malware_query(client, query, limit_range)
    return response


def malware_query(client: Client, action_values: list, limit: Optional[int]) -> dict:
    json_body = {"filters": action_values, "sortingFieldName": "timestamp", "sortDirection": "DESC", "limit": limit, "offset": 0}

    return client.cybereason_api_call('POST', '/rest/malware/query', json_body=json_body)


def start_host_scan_command(client: Client, args: dict):
    sensor_ids = argToList(args.get('sensorID'))
    argument = args.get('scanType')
    json_body = {
        "sensorsIds": sensor_ids,
        "argument": argument
    }
    response = client.cybereason_api_call(
        'POST', '/rest/sensors/action/schedulerScan', json_body=json_body, return_json=False, custom_response=True)
    if response.status_code == 204:
        return CommandResults(
            readable_output=f"Given Sensor ID/ID's {sensor_ids} is/are not available for scanning.")
    elif response.status_code == 200:
        try:
            response_json = response.json()
            batch_id = dict_safe_get(response_json, ['batchId'])
            return CommandResults(readable_output=f'Scanning initiation successful. Batch ID: {batch_id}')
        except Exception as e:
            raise Exception("Exception occurred while processing response for scanning a host: " + str(e))
    else:
        try:
            json_response = response.json()
            raise DemistoException('Could not scan the host. The received response is' + json_response)
        except Exception:
            raise Exception(
                'Your request failed with the following error: ' + response.content + '. Response Status code: ' + str(
                    response.status_code))


def fetch_scan_status_command(client: Client, args: dict):
    batch_id = str(args.get('batchID'))
    action_response = client.cybereason_api_call('GET', '/rest/sensors/allActions')
    output = "The given batch ID does not match with any actions on sensors."
    for item in action_response:
        if dict_safe_get(item, ['batchId']) == int(batch_id):
            output = item
            break
    return CommandResults(raw_response=output)


def get_sensor_id_command(client: Client, args: dict):
    machine_name = str(args.get('machineName'))
    json_body = {}
    if machine_name:
        json_body = {
            "filters": [
                {
                    "fieldName": "machineName",
                    "operator": "Equals",
                    "values": [machine_name]
                }
            ]
        }
    response = client.cybereason_api_call('POST', '/rest/sensors/query', json_body=json_body)
    if dict_safe_get(response, ['sensors']) == []:
        raise DemistoException("Could not find any Sensor ID for the machine" + machine_name)
    else:
        output = {}
        for single_sensor in response['sensors']:
            output[single_sensor['machineName']] = single_sensor['sensorId']
        return CommandResults(readable_output=f"Available Sensor IDs are {output}")


def get_machine_details_command(client: Client, args: dict):
    machine_name = str(args.get('machineName'))
    json_body = get_machine_details_command_pagination_params(args)
    json_body["filters"] = [{"fieldName": "machineName", "operator": "Equals", "values": [machine_name]}]
    response = client.cybereason_api_call('POST', '/rest/sensors/query', json_body=json_body)
    empty_output_message = f'No Machine Details found for the given Machine Name: {machine_name}'

    if dict_safe_get(response, ['sensors']) == []:
        return CommandResults(readable_output=empty_output_message)
    else:
        outputs = []
        for single_sensor in response.get('sensors'):
            outputs.append({
                "MachineID": single_sensor.get("sensorId"),
                "MachineName": single_sensor.get("machineName"),
                "MachineFQDN": single_sensor.get("fqdn"),
                "GroupID": single_sensor.get("groupId"),
                "GroupName": single_sensor.get("groupName")
            })
        return CommandResults(
            readable_output=tableToMarkdown(
                'Machine Details', outputs, headers=SENSOR_HEADERS) if outputs else empty_output_message,
            outputs_prefix='Cybereason.Sensor',
            outputs_key_field='MachineID',
            outputs=outputs)


def query_malop_management_command(client: Client, args: dict):
    malop_guid = args.get('malopGuid')
    json_body = {
        "search": {
            "malop": {
                "guid": f'{malop_guid}'
            }
        },
        "pagination": {
            "offset": 0
        },
        "range": {
            "from": 0,
            "to": 9999999999999
        }
    }
    response = client.cybereason_api_call('POST', '/rest/mmng/v2/malops', json_body=json_body)
    if dict_safe_get(response, ['data', 'data']) == []:
        raise DemistoException(f"Could not find details for the provided MalopGuid {malop_guid}")
    else:
        outputs = []
        for single_malop in response["data"]["data"]:
            guid = single_malop.get("guid", "")
            creation_time = single_malop.get("creationTime", "")
            malop_last_update_time = single_malop.get("lastUpdateTime", "")
            management_status = single_malop.get("investigationStatus", "")
            involved_hashes = single_malop.get("rootCauseElementHashes", [])
            if single_malop["isEdr"]:
                link = SERVER + '/#/malop/' + guid
            else:
                link = SERVER + '/#/detection-malop/' + guid
            malop_output = {
                'GUID': guid,
                'Link': link,
                'CreationTime': creation_time,
                'LastUpdateTime': malop_last_update_time,
                'Status': management_status,
                'InvolvedHash': involved_hashes
            }
            outputs.append(malop_output)
        return CommandResults(
            readable_output=tableToMarkdown('Cybereason Malop', outputs, headers=SINGLE_MALOP_HEADERS)
            if outputs else 'No malop found',
            outputs_prefix='Cybereason.Malops',
            outputs_key_field='GUID',
            outputs=outputs)


def cybereason_process_attack_tree_command(client: Client, args: dict):
    process_guid_list = argToList(args.get('processGuid'))
    outputs = []
    for guid in process_guid_list:
        url = SERVER + "/#/processTree?guid=" + guid + "&viewedGuids=" + guid + "&rootType=Process"
        process_output = {
            'ProcessID': guid,
            'URL': url,
        }
        outputs.append(process_output)
    empty_output_message = 'No Process Details found for the given ProcessID'
    return CommandResults(
        readable_output=tableToMarkdown('Process Attack Tree URL', outputs, headers=PROCESS_URL_HEADERS)
        if outputs else empty_output_message,
        outputs_prefix='Cybereason.Process',
        outputs_key_field='ProcessID',
        outputs=outputs)


def update_malop_investigation_status_command(client: Client, args: dict):
    malop_guid = str(args.get('malopGuid'))
    investigation_status = str(args.get('investigationStatus'))

    if investigation_status not in INVESTIGATION_STATUS_MAP.keys():
        raise Exception(f"Invalid investigation status. Must be one of: {', '.join(INVESTIGATION_STATUS_MAP.keys())}")

    update_malop_investigation_status(client, malop_guid, investigation_status)

    return CommandResults(
        readable_output=f'Successfully updated malop {malop_guid} to investigation status "{investigation_status}"!',
        outputs_prefix='Cybereason.Malops',
        outputs_key_field='GUID',
        outputs={
            'GUID': malop_guid,
            'InvestigationStatus': investigation_status
        })


def update_malop_investigation_status(client: Client, malop_guid: str, investigation_status: str) -> None:
    json_body = {"investigationStatus": INVESTIGATION_STATUS_MAP[investigation_status]}

    response = client.cybereason_api_call('PUT', f'/rest/mmng/v2/malops/{malop_guid}', json_body=json_body)
    if response['status'] != 'SUCCESS':
        raise DemistoException(f"Failed to update malop {malop_guid} to \"{investigation_status}\": {response['message']}")


def get_machine_details_command_pagination_params(args: dict) -> dict:
    '''
        Generate pagination parameters for fetching machine details based on the given arguments.

        This function calculates the 'limit' and 'offset' parameters for pagination
        based on the provided 'page' and 'pageSize' arguments. If 'page' and 'pageSize'
        are valid integer values, the function returns a dictionary containing 'limit'
        and 'offset' calculated accordingly. If 'page' or 'pageSize' are not valid integers,
        the function falls back to using the 'limit' argument or defaults to 50 with an
        'offset' of 0.

        Args:
            args (dict): The demisto.args() dictionary containing the optional arguments for
            pagination: 'page', 'pageSize', 'limit'.

        Returns:
            dict: A dictionary containing the calculated 'limit' and 'offset' parameters
                for pagination.
    '''
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('pageSize'))
    if isinstance(page, int) and isinstance(page_size, int):
        return {
            'limit': page_size,
            'offset': (page - 1) * page_size
        }

    else:
        return {
            'limit': arg_to_number(args.get('limit', 50)),
            'offset': 0
        }


def main():
    auth = ''
    params = demisto.params()
    args = demisto.args()
    proxy = params.get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=SERVER,
            verify=USE_SSL,
            headers=HEADERS,
            proxy=proxy
        )

        if CERTIFICATE:
            client_certificate()
            auth = 'CERT'
        elif USERNAME and PASSWORD:
            validate_jsession(client)
            auth = 'BASIC'
        else:
            raise Exception('No credentials were provided')

        if demisto.command() == 'test-module':
            # Tests connectivity and credentails on login
            query_user(client, [])
            return_results('ok')

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(client)

        elif demisto.command() == 'cybereason-is-probe-connected':
            return_results(is_probe_connected_command(client, args))

        elif demisto.command() == 'cybereason-query-processes':
            return_results(query_processes_command(client, args))

        elif demisto.command() == 'cybereason-query-malops':
            return_results(query_malops_command(client, args))

        elif demisto.command() == 'cybereason-query-connections':
            return_results(query_connections_command(client, args))

        elif demisto.command() == 'cybereason-isolate-machine':
            return_results(isolate_machine_command(client, args))

        elif demisto.command() == 'cybereason-unisolate-machine':
            return_results(unisolate_machine_command(client, args))

        elif demisto.command() == 'cybereason-malop-processes':
            return_results(malop_processes_command(client, args))

        elif demisto.command() == 'cybereason-add-comment':
            return_results(add_comment_command(client, args))

        elif demisto.command() == 'cybereason-update-malop-status':
            return_results(update_malop_status_command(client, args))

        elif demisto.command() == 'cybereason-prevent-file':
            return_results(prevent_file_command(client, args))

        elif demisto.command() == 'cybereason-unprevent-file':
            return_results(unprevent_file_command(client, args))

        elif demisto.command() == 'cybereason-available-remediation-actions':
            return_results(available_remediation_actions_command(client, args))

        elif demisto.command() == 'cybereason-kill-process':
            return_results(kill_process_command(client, args))

        elif demisto.command() == 'cybereason-quarantine-file':
            return_results(quarantine_file_command(client, args))

        elif demisto.command() == 'cybereason-unquarantine-file':
            return_results(unquarantine_file_command(client, args))

        elif demisto.command() == 'cybereason-block-file':
            return_results(block_file_command(client, args))

        elif demisto.command() == 'cybereason-delete-registry-key':
            return_results(delete_registry_key_command(client, args))

        elif demisto.command() == 'cybereason-kill-prevent-unsuspend':
            return_results(kill_prevent_unsuspend_command(client, args))

        elif demisto.command() == 'cybereason-unsuspend-process':
            return_results(unsuspend_process_command(client, args))

        elif demisto.command() == 'cybereason-query-file':
            return_results(query_file_command(client, args))

        elif demisto.command() == 'cybereason-query-domain':
            return_results(query_domain_command(client, args))

        elif demisto.command() == 'cybereason-query-user':
            return_results(query_user_command(client, args))

        elif demisto.command() == 'cybereason-start-fetchfile':
            return_results(start_fetchfile_command(client, args))

        elif demisto.command() == 'cybereason-fetchfile-progress':
            return_results(fetchfile_progress_command(client, args))

        elif demisto.command() == 'cybereason-download-file':
            return_results(download_fetchfile_command(client, args))

        elif demisto.command() == 'cybereason-close-file-batch-id':
            return_results(close_fetchfile_command(client, args))

        elif demisto.command() == 'cybereason-archive-sensor':
            return_results(archive_sensor_command(client, args))

        elif demisto.command() == 'cybereason-unarchive-sensor':
            return_results(unarchive_sensor_command(client, args))

        elif demisto.command() == 'cybereason-delete-sensor':
            return_results(delete_sensor_command(client, args))

        elif demisto.command() == 'cybereason-malware-query':
            return_results(malware_query_command(client, args))

        elif demisto.command() == 'cybereason-start-host-scan':
            return_results(start_host_scan_command(client, args))

        elif demisto.command() == 'cybereason-fetch-scan-status':
            return_results(fetch_scan_status_command(client, args))

        elif demisto.command() == 'cybereason-get-sensor-id':
            return_results(get_sensor_id_command(client, args))

        elif demisto.command() == 'cybereason-get-machine-details':
            return_results(get_machine_details_command(client, args))

        elif demisto.command() == 'cybereason-query-malop-management':
            return_results(query_malop_management_command(client, args))

        elif demisto.command() == 'cybereason-process-attack-tree':
            return_results(cybereason_process_attack_tree_command(client, args))

        elif demisto.command() == 'cybereason-update-malop-investigation-status':
            return_results(update_malop_investigation_status_command(client, args))

        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')
    finally:
        if auth and auth == 'CERT':
            os.remove(os.path.abspath('client.pem'))
            os.remove(os.path.abspath('client.cert'))


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
