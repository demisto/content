import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests
import os
import json
from datetime import datetime, timedelta
import time
import re
import sys

# Define utf8 as default encoding
reload(sys)
sys.setdefaultencoding('utf8')  # pylint: disable=maybe-no-member

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
SERVER = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
USERNAME = demisto.params().get('credentials', {}).get('identifier')
PASSWORD = demisto.params().get('credentials', {}).get('password')
USE_SSL = not demisto.params().get('unsecure', False)
CERTIFICATE = demisto.params().get('credentials', {}).get('credentials', {}).get('sshkey')
FETCH_TIME_DEFAULT = '3 days'
FETCH_TIME = demisto.params().get('fetch_time', FETCH_TIME_DEFAULT)
FETCH_TIME = FETCH_TIME if FETCH_TIME and FETCH_TIME.strip() else FETCH_TIME_DEFAULT
FETCH_BY = demisto.params().get('fetch_by', 'MALOP CREATION TIME')

STATUS_MAP = {
    'To Review': 'TODO',
    'Remediated': 'CLOSED',
    'Unread': 'UNREAD',
    'Not Relevant': 'FP',
    'Open': 'OPEN'
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

HEADERS = {
    'Content-Type': 'application/json',
    'Connection': 'close'
}

''' HELPER FUNCTIONS '''


def build_query(query_fields, path, template_context='SPECIFIC'):
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


def http_request(method, url_suffix, data=None, json_body=None, headers=HEADERS, return_json=True, custom_response=False):
    LOG('running request with url=%s' % (SERVER + url_suffix))
    try:
        res = session.request(
            method,
            SERVER + url_suffix,
            headers=headers,
            data=data,
            json=json_body,
            verify=USE_SSL
        )
        if custom_response:
            return res
        if res.status_code not in {200, 204}:
            raise Exception('Your request failed with the following error: ' + res.content + '. Response Status code: ' + str(res.status_code))

    except Exception as e:
        LOG(e)
        raise

    if return_json:
        try:
            return res.json()
        except Exception as e:
            error_content = res.content
            error_msg = ''
            if 'Login' in str(error_content):
                error_msg = 'Authentication failed, verify the credentials are correct.'
            raise ValueError('Failed to process the API response. {} {} - {}'.format(error_msg, error_content, str(e)))


def translate_timestamp(timestamp):
    return datetime.fromtimestamp(int(timestamp) / 1000).isoformat()


def update_output(output, simple_values, element_values, info_dict):
    for info in info_dict:
        info_type = info.get('type', '')

        if info_type == 'simple':
            output[info['header']] = dict_safe_get(simple_values, [info.get('field'), 'values', 0])

        elif info_type == 'element':
            output[info['header']] = dict_safe_get(element_values, [info.get('field'), 'elementValues', 0, 'name'])

        elif info_type == 'time':
            time_stamp_str = dict_safe_get(simple_values, [info.get('field'), 'values', 0], default_return_value=u'',
                                           return_type=unicode)
            output[info['header']] = translate_timestamp(time_stamp_str) if time_stamp_str else ''

    return output


def get_pylum_id(machine):
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
    response = http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    data = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
    pylum_id = dict_safe_get(data.values(), [0, 'simpleValues', 'pylumId', 'values', 0])
    if not pylum_id:
        raise ValueError('Could not find machine')

    return pylum_id


def get_machine_guid(machine_name):
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
    response = http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    data = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)

    return dict_safe_get(data.keys(), [0])


''' FUNCTIONS '''


def is_probe_connected_command(is_remediation_commmand=False):
    machine = demisto.getArg('machine')
    is_connected = False

    response = is_probe_connected(machine)

    elements = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)

    for value in elements.values():
        machine_name = dict_safe_get(value, ['simpleValues', 'elementDisplayName', 'values', 0],
                                     default_return_value=u'', return_type=unicode)
        if machine_name.upper() == machine.upper():
            is_connected = True
            break

    if is_remediation_commmand:
        return is_connected

    ec = {
        'Cybereason.Machine(val.Name && val.Name === obj.Name)': {
            'isConnected': is_connected,
            'Name': machine
        }
    }
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': is_connected,
        'EntryContext': ec
    })


def is_probe_connected(machine):
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

    return http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)


def query_processes_command():
    machine = demisto.getArg('machine')
    process_name = demisto.getArg('processName')
    only_suspicious = demisto.getArg('onlySuspicious')
    has_incoming_connection = demisto.getArg('hasIncomingConnection')
    has_outgoing_connection = demisto.getArg('hasOutgoingConnection')
    has_external_connection = demisto.getArg('hasExternalConnection')
    unsigned_unknown_reputation = demisto.getArg('unsignedUnknownReputation')
    from_temporary_folder = demisto.getArg('fromTemporaryFolder')
    privileges_escalation = demisto.getArg('privilegesEscalation')
    maclicious_psexec = demisto.getArg('maliciousPsExec')

    response = query_processes(machine, process_name, only_suspicious, has_incoming_connection, has_outgoing_connection,
                               has_external_connection, unsigned_unknown_reputation, from_temporary_folder,
                               privileges_escalation, maclicious_psexec)
    elements = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
    outputs = []
    for item in elements.values():
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
        context.append({key.translate(None, ' '): value for key, value in output.iteritems()})

    ec = {
        'Process': context
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Cybereason Processes', outputs, PROCESS_HEADERS),
        'EntryContext': ec
    })


def query_processes(machine, process_name, only_suspicious=None, has_incoming_connection=None,
                    has_outgoing_connection=None, has_external_connection=None, unsigned_unknown_reputation=None,
                    from_temporary_folder=None, privileges_escalation=None, maclicious_psexec=None):
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

    return http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)


def query_connections_command():
    machine = demisto.getArg('machine')
    ip = demisto.getArg('ip')

    if ip and machine:
        raise Exception('Too many arguments given.')
    elif not ip and not machine:
        raise Exception('Not enough arguments given.')

    if machine:
        input_list = machine.split(",")
    else:
        input_list = ip.split(",")

    for filter_input in input_list:
        response = query_connections(machine, ip, filter_input)
        elements = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
        outputs = []

        for item in elements.values():
            simple_values = dict_safe_get(item, ['simpleValues'], default_return_value={}, return_type=dict)
            element_values = dict_safe_get(item, ['elementValues'], default_return_value={}, return_type=dict)

            output = update_output({}, simple_values, element_values, CONNECTION_INFO)
            outputs.append(output)

        context = []
        for output in outputs:
            # Remove whitespaces from dictionary keys
            context.append({key.translate(None, ' '): value for key, value in output.iteritems()})

        ec = {
            'Connection': context
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Cybereason Connections for: {}'.format(filter_input), outputs),
            'EntryContext': ec
        })


def query_connections(machine, ip, filter_input):
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
    response = http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)

    return response


def query_malops_command():
    total_result_limit = demisto.getArg('totalResultLimit')
    per_group_limit = demisto.getArg('perGroupLimit')
    template_context = demisto.getArg('templateContext')
    filters = json.loads(demisto.getArg('filters')) if demisto.getArg('filters') else []
    within_last_days = demisto.getArg('withinLastDays')
    guid_list = argToList(demisto.getArg('malopGuid'))

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

    malop_process_type, malop_loggon_session_type = query_malops(total_result_limit, per_group_limit,
                                                                 template_context, filters, guid_list=guid_list)
    outputs = []

    for response in (malop_process_type, malop_loggon_session_type):
        data = response.get('data', {})
        malops_map = dict_safe_get(data, ['resultIdToElementDataMap'], default_return_value={}, return_type=dict)
        if not data or not malops_map:
            continue

        for guid, malop in malops_map.iteritems():
            simple_values = dict_safe_get(malop, ['simpleValues'], {}, dict)
            management_status = dict_safe_get(simple_values, ['managementStatus', 'values', 0],
                                              default_return_value=u'',
                                              return_type=unicode)

            if management_status.upper() == u'CLOSED':
                continue

            creation_time = translate_timestamp(dict_safe_get(simple_values, ['creationTime', 'values', 0]))
            malop_last_update_time = translate_timestamp(
                dict_safe_get(simple_values, ['malopLastUpdateTime', 'values', 0]))
            raw_decision_failure = dict_safe_get(simple_values, ['decisionFeature', 'values', 0],
                                                 default_return_value=u'', return_type=unicode)
            decision_failure = raw_decision_failure.replace('Process.', '')
            raw_suspects = dict_safe_get(malop, ['elementValues', 'suspects'], default_return_value={},
                                         return_type=dict)
            suspects_string = ''
            if raw_suspects:
                suspects = dict_safe_get(raw_suspects, ['elementValues', 0], default_return_value={}, return_type=dict)
                suspects_string = '{}: {}'.format(suspects.get('elementType'), suspects.get('name'))

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

    ec = {
        'Cybereason.Malops(val.GUID && val.GUID === obj.GUID)': outputs
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Cybereason Malops',
                                         outputs,
                                         ['GUID', 'Link', 'CreationTime', 'Status',
                                          'LastUpdateTime', 'DecisionFailure', 'Suspects',
                                          'AffectedMachine', 'InvolvedHash']) if outputs else 'No malops found',
        'EntryContext': ec
    })


def query_malops(total_result_limit=None, per_group_limit=None, template_context=None, filters=None, guid_list=None):
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
    malop_process_type = http_request('POST', '/rest/crimes/unified', json_body=json_body)
    # Second request - "MalopLogonSession"
    json_body['queryPath'][0]['requestedType'] = "MalopLogonSession"  # type: ignore
    malop_loggon_session_type = http_request('POST', '/rest/crimes/unified', json_body=json_body)

    return malop_process_type, malop_loggon_session_type


def isolate_machine_command():
    machine = demisto.getArg('machine')
    response, pylum_id = isolate_machine(machine)
    result = response.get(pylum_id)
    if result == 'Succeeded':
        ec = {
            'Cybereason(val.Machine && val.Machine === obj.Machine)': {
                'Machine': machine,
                'IsIsolated': True
            },
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': {
                'Hostname': machine
            }
        }
        demisto.results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': response,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'Machine was isolated successfully.',
            'EntryContext': ec
        })
    else:
        raise Exception('Failed to isolate machine.')


def isolate_machine(machine):
    pylum_id = get_pylum_id(machine)

    cmd_url = '/rest/monitor/global/commands/isolate'
    json_body = {
        'pylumIds': [pylum_id]

    }
    response = http_request('POST', cmd_url, json_body=json_body)

    return response, pylum_id


def unisolate_machine_command():
    machine = demisto.getArg('machine')
    response, pylum_id = unisolate_machine(machine)
    result = response.get(pylum_id)
    if result == 'Succeeded':
        ec = {
            'Cybereason(val.Machine && val.Machine === obj.Machine)': {
                'Machine': machine,
                'IsIsolated': False
            },
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': {
                'Hostname': machine
            }
        }
        demisto.results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': response,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'Machine was un-isolated successfully.',
            'EntryContext': ec
        })
    else:
        raise Exception('Failed to un-isolate machine.')


def unisolate_machine(machine):
    pylum_id = get_pylum_id(machine)
    cmd_url = '/rest/monitor/global/commands/un-isolate'
    json_body = {
        'pylumIds': [pylum_id]

    }
    response = http_request('POST', cmd_url, json_body=json_body)

    return response, pylum_id


def malop_processes_command():
    malop_guids = demisto.getArg('malopGuids')
    machine_name = demisto.getArg('machineName')

    if isinstance(malop_guids, unicode):
        malop_guids = malop_guids.split(',')
    elif not isinstance(malop_guids, list):
        raise Exception('malopGuids must be array of strings')

    machine_name_list = [machine.lower() for machine in argToList(machine_name)]

    response = malop_processes(malop_guids)
    elements = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
    outputs = []

    for item in elements.values():
        simple_values = dict_safe_get(item, ['simpleValues'], default_return_value={}, return_type=dict)
        element_values = dict_safe_get(item, ['elementValues'], default_return_value={}, return_type=dict)

        if machine_name_list:
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

    context = []
    for output in outputs:
        # Remove whitespaces from dictionary keys
        context.append({key.translate(None, ' '): value for key, value in output.iteritems()})

    ec = {
        'Process': context
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Cybereason Malop Processes', outputs, PROCESS_HEADERS, removeNull=True),
        'EntryContext': ec
    })


def malop_processes(malop_guids):
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
                'filters': [],
                'isResult': True
            }
        ],
        'totalResultLimit': 1000,
        'perGroupLimit': 1200,
        'perFeatureLimit': 1200,
        'templateContext': 'MALOP',
        'queryTimeout': None
    }

    return http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)


def add_comment_command():
    comment = demisto.getArg('comment') if demisto.getArg('comment') else ''
    malop_guid = demisto.getArg('malopGuid')
    try:
        add_comment(malop_guid, comment.encode('utf-8'))
        demisto.results('Comment added successfully')
    except Exception as e:
        raise Exception('Failed to add new comment. Orignal Error: ' + e.message)


def add_comment(malop_guid, comment):
    cmd_url = '/rest/crimes/comment/' + malop_guid
    http_request('POST', cmd_url, data=comment, return_json=False)


def update_malop_status_command():
    status = demisto.getArg('status')
    malop_guid = demisto.getArg('malopGuid')

    if status not in STATUS_MAP:
        raise Exception(
            'Invalid status. Given status must be one of the following: To Review,Unread,Remediated or Not Relevant')

    update_malop_status(malop_guid, status)

    ec = {
        'Cybereason.Malops(val.GUID && val.GUID == {})'.format(malop_guid): {
            'GUID': malop_guid,
            'Status': status
        }
    }
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': 'Successfully updated malop {0} to status {1}'.format(malop_guid, status),
        'ContentsFormat': formats['text'],
        'EntryContext': ec
    })


def update_malop_status(malop_guid, status):
    api_status = STATUS_MAP[status]

    json_body = {malop_guid: api_status}

    response = http_request('POST', '/rest/crimes/status', json_body=json_body)
    if response['status'] != 'SUCCESS':
        raise Exception('Failed to update malop {0} status to {1}. Message: {2}'.format(malop_guid, status,
                                                                                        response['message']))


def prevent_file_command():
    file_hash = demisto.getArg('md5') if demisto.getArg('md5') else ''
    response = prevent_file(file_hash)
    if response['outcome'] == 'success':
        ec = {
            'Process(val.MD5 && val.MD5 === obj.MD5)': {
                'MD5': file_hash,
                'Prevent': True
            }
        }
        entry = {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': response,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'File was prevented successfully',
            'EntryContext': ec
        }
        demisto.results(entry)
    else:
        raise Exception('Failed to prevent file')


def prevent_file(file_hash):
    json_body = [{
        'keys': [file_hash],
        'maliciousType': 'blacklist',
        'remove': False,
        'prevent': True
    }]

    return http_request('POST', '/rest/classification/update', json_body=json_body)


def unprevent_file_command():
    file_hash = demisto.getArg('md5')
    response = unprevent_file(file_hash)
    if response['outcome'] == 'success':
        ec = {
            'Process(val.MD5 && val.MD5 === obj.MD5)': {
                'MD5': file_hash,
                'Prevent': False
            }
        }
        entry = {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': response,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'File was unprevented successfully',
            'EntryContext': ec
        }
        demisto.results(entry)
    else:
        raise Exception('Failed to unprevent file')


def unprevent_file(file_hash):
    json_body = [{
        'keys': [str(file_hash)],
        'remove': True,
        'prevent': False
    }]

    return http_request('POST', '/rest/classification/update', json_body=json_body)


def kill_process_command():
    machine_name = demisto.getArg('machine')
    file_content = demisto.getArg('file')
    malop_guid = demisto.getArg('malop')
    user_name = demisto.getArg('userName')
    is_machine_conntected = is_probe_connected_command(is_remediation_commmand=True)
    if is_machine_conntected == True:
        operation_status = get_kill_process_status(malop_guid, machine_name, file_content, user_name)
        success_status = []
        failure_status = []
        pending_status = []
        for item in operation_status:
            status = item["status"]
            target_Id = item["targetId"]
            if status == "SUCCESS":
                success_status.append({"Target ID": target_Id})
            elif status == "FAILURE":
                reason = item["error"]["message"]
                error_type = item["error"]["errorType"]
                failure_status.append({"Target ID": target_Id, "Message": reason, "Error Type": error_type})
            else:
                pending_status.append({"Timeout while fetching progress for kill process operation on target ID: ": target_Id})
        demisto.results("Success responses (if any):" + "\n{}".format(success_status) + "\n\n" + "Failure responses (if any):" + "\n{}".format(failure_status) + "\n\n" + "Pending responses (if any):" + "\n{}".format(pending_status))
    else:
        demisto.results('Machine must be connected to Cybereason in order to perform this action.')


def get_kill_process_status(malop_guid, machine_name, file_content, user_name):
    machine_guid = get_machine_guid(machine_name)
    all_machine_guid = []
    procceses = query_processes(machine_name, file_content)
    process_data = dict_safe_get(procceses, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
    for process_guid in process_data.keys():
        all_machine_guid.append({"targetId": process_guid, "actionType": 'KILL_PROCESS'})
    response = kill_process(malop_guid, machine_guid, all_machine_guid)
    remediation_Id = dict_safe_get(response, ['remediationId'])
    progress_api_response = get_remediation_action_progress(user_name, malop_guid, remediation_Id)
    return progress_api_response['statusLog']


def kill_process(malop_guid, machine_guid, process_guid):
    json_body = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: process_guid
        }
    }

    return http_request('POST', '/rest/remediate', json_body=json_body)


def quarantine_file_command():
    machine_name = demisto.getArg('machine')
    malop_guid = demisto.getArg('malop')
    user_name = demisto.getArg('userName')
    is_machine_conntected = is_probe_connected_command(is_remediation_commmand=True)
    if is_machine_conntected == True:
        files_list = get_quarantine_status(malop_guid, machine_name, user_name)
        result = []
        for item in range(len(files_list)):
            status = files_list[item].get("Status")
            filename = files_list[item].get("FileName")
            if status == "SUCCESS":
                result.append("The quarantine file operation for '{1}' is {0}".format(str(status), str(filename)))
            elif status == "FAILURE":
                result.append("The quarantine file operation for '{1}' is {0}".format(str(status), str(filename)))
            else:
                result.append("Timeout while fetching progress for quarantine operation on file '{}'".format(str(filename)))
        demisto.results(result)
    else:
        demisto.results('Machine must be connected to Cybereason in order to perform this action.')


def get_quarantine_status(malop_guid, machine_name, user_name):
    machine_guid = get_machine_guid(machine_name)
    all_file_guids = get_file_guids(malop_guid)
    final_status = []
    for filename, file_guid in all_file_guids.items():
        response = quarantine_file(malop_guid, machine_guid, file_guid)
        if dict_safe_get(response, ['statusLog', 0, 'error', 'errorType']) == "INVALID_ARGUMENT":
            demisto.results("{0}, please provide correct input for file '{1}'.".format(dict_safe_get(response, ['statusLog', 0, 'error', 'errorType']), str(filename)))
        else:
            remediation_Id = response['remediationId']
            timeout_sec = 60
            interval_sec = 10
            all_file_status = []
            while timeout_sec > 0:
                progress_api_response = get_remediation_action_progress(user_name, malop_guid, remediation_Id)
                remediation_resp = dict_safe_get(progress_api_response, ['statusLog', 2, 'status'])
                all_file_status.append({"Status": remediation_resp, "FileName": filename})
                time.sleep(interval_sec)
                timeout_sec = timeout_sec - interval_sec
            final_status.append(all_file_status[-1])
    return final_status


def quarantine_file(malop_guid, machine_guid, process_guid):
    json_body = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: [{
                'targetId': process_guid,
                'actionType': 'QUARANTINE_FILE'
            }]
        }
    }

    return http_request('POST', '/rest/remediate', json_body=json_body)


def block_file_command():
    machine_name = demisto.getArg('machine')
    malop_guid = demisto.getArg('malop')
    user_name = demisto.getArg('userName')
    is_machine_conntected = is_probe_connected_command(is_remediation_commmand=True)
    if is_machine_conntected == True:
        files_list = get_block_file_status(malop_guid, machine_name, user_name)
        result = []
        for item in range(len(files_list)):
            status = files_list[item].get("Status")
            filename = files_list[item].get("FileName")
            if status == "SUCCESS":
                result.append("The block file operation for '{1}' is {0}".format(str(status), str(filename)))
            elif status == "FAILURE":
                result.append("The block file operation for '{1}' is {0}".format(str(status), str(filename)))
            else:
                result.append("Timeout while fetching progress for block operation on file '{}'".format(str(filename)))
        demisto.results(result)
    else:
        demisto.results('Machine must be connected to Cybereason in order to perform this action.')


def get_block_file_status(malop_guid, machine_name, user_name):
    machine_guid = get_machine_guid(machine_name)
    all_file_guids = get_file_guids(malop_guid)
    final_status = []
    for filename, file_guid in all_file_guids.items():
        response = block_file(malop_guid, machine_guid, file_guid)
        if dict_safe_get(response, ['statusLog', 0, 'error', 'errorType']) == "INVALID_ARGUMENT":
            demisto.results("{0}, please provide correct input for file '{1}'.".format(dict_safe_get(response, ['statusLog', 0, 'error', 'errorType']), str(filename)))
        else:
            remediation_Id = response['remediationId']
            timeout_sec = 60
            interval_sec = 10
            all_file_status = []
            while timeout_sec > 0:
                progress_api_response = get_remediation_action_progress(user_name, malop_guid, remediation_Id)
                remediation_resp = dict_safe_get(progress_api_response, ['statusLog', 2, 'status'])
                all_file_status.append({"Status": remediation_resp, "FileName": filename})
                time.sleep(interval_sec)
                timeout_sec = timeout_sec - interval_sec
            final_status.append(all_file_status[-1])
    return final_status


def block_file(malop_guid, machine_guid, process_guid):
    json_body = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: [{
                'targetId': process_guid,
                'actionType': 'BLOCK_FILE'
            }]
        }
    }

    return http_request('POST', '/rest/remediate', json_body=json_body)


def get_remediation_action_progress(username, malop_id, remediation_id):
    return http_request('GET', '/rest/remediate/progress/' + username + '/' +str(malop_id) + '/' + remediation_id)


def delete_registry_key_command():
    machine_name = demisto.getArg('machine')
    file_content = demisto.getArg('file')
    malop_guid = demisto.getArg('malop')
    user_name = demisto.getArg('userName')
    is_machine_conntected = is_probe_connected_command(is_remediation_commmand=True)
    if is_machine_conntected == True:
        operation_status = get_delete_registry_key_status(malop_guid, machine_name, file_content, user_name)
        success_status = []
        failure_status = []
        pending_status = []
        for item in operation_status:
            status = item["status"]
            target_Id = item["targetId"]
            if status == "SUCCESS":
                success_status.append({"Target ID": target_Id})
            elif status == "FAILURE":
                reason = item["error"]["message"]
                error_type = item["error"]["errorType"]
                failure_status.append({"Target ID": target_Id, "Message": reason, "Error Type": error_type})
            else:
                pending_status.append({"Timeout while fetching progress for delete registry key operation on target ID: ": target_Id})
        demisto.results("Success responses (if any):" + "\n{}".format(success_status) + "\n\n" + "Failure responses (if any):" + "\n{}".format(failure_status) + "\n\n" + "Pending responses (if any):" + "\n{}".format(pending_status))
    else:
        demisto.results('Machine must be connected to Cybereason in order to perform this action.')


def get_delete_registry_key_status(malop_guid, machine_name, file_content, user_name):
    machine_guid = get_machine_guid(machine_name)
    all_machine_guid = []
    procceses = query_processes(machine_name, file_content)
    process_data = dict_safe_get(procceses, ['data', 'resultIdToElementDataMap'], default_return_value={}, return_type=dict)
    for process_guid in process_data.keys():
        all_machine_guid.append({"targetId": process_guid, "actionType": 'DELETE_REGISTRY_KEY'})
    response = delete_registry_key(malop_guid, machine_guid, all_machine_guid)
    remediation_Id = dict_safe_get(response, ['remediationId'])
    progress_api_response = get_remediation_action_progress(user_name, malop_guid, remediation_Id)
    return progress_api_response['statusLog']


def delete_registry_key(malop_guid, machine_guid, process_guid):
    json_body = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: process_guid
        }
    }

    return http_request('POST', '/rest/remediate', json_body=json_body)


def query_file_command():
    file_hash_input = demisto.getArg('file_hash')
    file_hash_list = file_hash_input.split(",")
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

        data = query_file(filters)

        if data:
            cybereason_outputs = []
            file_outputs = []
            endpoint_outputs = []
            files = dict_safe_get(data, ['resultIdToElementDataMap'], {}, dict)
            for fname, fstat in files.iteritems():
                raw_machine_details = dict_safe_get(get_file_machine_details(fname), ['data', 'resultIdToElementDataMap'],
                                                    default_return_value={}, return_type=dict)
                machine_details = dict_safe_get(raw_machine_details, dict_safe_get(raw_machine_details.keys(), [0]),
                                                default_return_value={}, return_type=dict)
                simple_values = dict_safe_get(fstat, ['simpleValues'], default_return_value={}, return_type=dict)
                file_name = dict_safe_get(simple_values, ['elementDisplayName', 'values', 0])
                md5 = dict_safe_get(simple_values, ['md5String', 'values', 0])
                sha1 = dict_safe_get(simple_values, ['sha1String', 'values', 0])
                path = dict_safe_get(simple_values, ['correctedPath', 'values', 0])
                machine = dict_safe_get(fstat, ['elementValues', 'ownerMachine', 'elementValues', 0, 'name'])

                machine_element_values = dict_safe_get(machine_details, ['elementValues'], default_return_value={},
                                                    return_type=dict)
                machine_simple_values = dict_safe_get(machine_details, ['simpleValues'], default_return_value={},
                                                    return_type=dict)

                os_version = dict_safe_get(machine_simple_values, ['ownerMachine.osVersionType', 'values', 0])
                raw_suspicions = dict_safe_get(machine_details, ['suspicions'], default_return_value={}, return_type=dict)

                suspicions = {}
                for key, value in raw_suspicions.iteritems():
                    suspicions[key] = timestamp_to_datestring(value)

                evidences = []
                for key in machine_element_values.keys():
                    if 'evidence' in key.lower():
                        evidences.append(key)
                for key in machine_simple_values.keys():
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
                    is_signed = True if dict_safe_get(simple_values, ['isSigned', 'values', 0]) == 'true' else False

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
                    'IsConnected': (dict_safe_get(machine_simple_values,
                                                ['ownerMachine.isActiveProbeConnected', 'values', 0]) == 'true'),
                    'OSVersion': os_version,
                    'Suspicion': suspicions,
                    'Evidence': evidences,
                    'Signed': is_signed,
                    'Company': company_name
                })

                file_outputs.append({
                    'Name': fname,
                    'MD5': md5,
                    'SHA1': sha1,
                    'Path': path,
                    'Hostname': machine
                })
                endpoint_outputs.append({
                    'Hostname': machine,
                    'OSVersion': os_version
                })
            ec = {'Cybereason.File(val.MD5 && val.MD5===obj.MD5 || val.SHA1 && val.SHA1===obj.SHA1)': cybereason_outputs,
                'Endpoint(val.Hostname===obj.Hostname)': endpoint_outputs,
                outputPaths['file']: file_outputs}

            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': data,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown('Cybereason file query results for the file hash: {}'.format(file_hash), cybereason_outputs, removeNull=True),
                'EntryContext': ec
            })
        else:
            demisto.results('No results found.')


def query_file(filters):
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
    response = http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    if response.get('status') == 'SUCCESS' and 'data' in response:
        return response['data']
    else:
        raise Exception('Error occurred while trying to query the file.')


def get_file_machine_details(file_guid):
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

    return http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)


def query_domain_command():
    domain_input_value = demisto.getArg('domain')
    domain_list = domain_input_value.split(",")
    for domain_input in domain_list:

        filters = [{
            'facetName': 'elementDisplayName',
            'values': [domain_input],
            'filterType': 'ContainsIgnoreCase'
        }]

        data = query_domain(filters)

        if data:
            cybereason_outputs = []
            domain_outputs = []
            domains = dict_safe_get(data, ['resultIdToElementDataMap'], default_return_value={}, return_type=dict)
            for domain in domains.values():
                if not isinstance(domain, dict):
                    raise ValueError("Cybereason raw response is not valid, domain in domains.values() is not dict")

                simple_values = dict_safe_get(domain, ['simpleValues'], default_return_value={}, return_type=dict)
                reputation = dict_safe_get(simple_values, ['maliciousClassificationType', 'values', 0])
                is_internal_domain = dict_safe_get(simple_values, ['isInternalDomain', 'values', 0]) == 'true'
                was_ever_resolved = dict_safe_get(simple_values, ['everResolvedDomain', 'values', 0]) == 'true'
                was_ever_resolved_as = dict_safe_get(simple_values,
                                                    ['everResolvedSecondLevelDomain', 'values', 0]) == 'true'
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

                domain_outputs.append({
                    'Name': domain_input,
                })

            ec = {'Cybereason.Domain(val.Name && val.Name===obj.Name)': cybereason_outputs,
                outputPaths['domain']: domain_outputs}

            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': data,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown('Cybereason domain query results for the domain: {}'.format(domain_input), cybereason_outputs,
                                                ['Name', 'Reputation', 'IsInternalDomain', 'WasEverResolved',
                                                'WasEverResolvedAsASecondLevelDomain', 'Malicious',
                                                'SuspicionsCount']),
                'EntryContext': ec
            })
        else:
            demisto.results('No results found.')


def query_domain(filters):
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
    response = http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    if response.get('status', '') == 'SUCCESS' and 'data' in response:
        return response['data']
    else:
        raise Exception('Error occurred while trying to query the file.')


def query_user_command():
    username_input = demisto.getArg('username')
    username_list = username_input.split(",")
    for username in username_list:

        filters = [{
            'facetName': 'elementDisplayName',
            'values': [username],
            'filterType': 'ContainsIgnoreCase'
        }]

        data = query_user(filters)

        if data:
            cybereason_outputs = []
            users = dict_safe_get(data, ['resultIdToElementDataMap'], default_return_value={}, return_type=dict)

            for user in users.values():
                simple_values = dict_safe_get(user, ['simpleValues'], default_return_value={}, return_type=dict)
                element_values = dict_safe_get(user, ['elementValues'], default_return_value={}, return_type=dict)

                domain = dict_safe_get(simple_values, ['domain', 'values', 0])
                local_system = True if dict_safe_get(simple_values, ['isLocalSystem', 'values', 0]) == 'true' else False
                machine = dict_safe_get(element_values, ['ownerMachine', 'elementValues', 0, 'name'])
                organization = dict_safe_get(element_values, ['ownerOrganization', 'elementValues', 0, 'name'])

                cybereason_outputs.append({
                    'Username': username,
                    'Domain': domain,
                    'LastMachineLoggedInTo': machine,
                    'Organization': organization,
                    'LocalSystem': local_system
                })

                ec = {
                    'Cybereason.User(val.Username && val.Username===obj.Username)': cybereason_outputs
                }

                demisto.results({
                    'ContentsFormat': formats['json'],
                    'Type': entryTypes['note'],
                    'Contents': data,
                    'ReadableContentsFormat': formats['markdown'],
                    'HumanReadable': tableToMarkdown('Cybereason user query results for the username: {}'.format(username), cybereason_outputs,
                                                    ['Username', 'Domain', 'LastMachineLoggedInTo', 'Organization',
                                                    'LocalSystem']),
                    'EntryContext': ec
                })
        else:
            demisto.results('No results found.')


def query_user(filters):
    query_fields = ['domain', 'ownerMachine', 'ownerOrganization', 'isLocalSystem', 'elementDisplayName']
    path = [
        {
            'requestedType': 'User',
            'filters': filters,
            'isResult': True
        }
    ]

    json_body = build_query(query_fields, path)

    response = http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    if response.get('status', '') == 'SUCCESS' and 'data' in response:
        return response['data']
    else:
        raise Exception('Error occurred while trying to query the file.')


def archive_sensor():
    sensor_id = demisto.getArg('sensorID')
    archive_reason = demisto.getArg('archiveReason')

    data = {
        "sensorsIds": [sensor_id],
        "argument": archive_reason
    }
    response = http_request('POST', '/rest/sensors/action/archive', json_body=data, return_json=False, custom_response=True)

    if response.status_code == 204:
        output = "The selected Sensor with Sensor ID: {sensor_id} is not available for archive.".format(sensor_id=sensor_id)
    elif response.status_code == 200:
        output = ""
        try:
            response_json = response.json()
            output = "Sensor archive status: "
            output += "Failed Actions: " + str(response_json['globalStats']['stats']['Failed']) + '. '
            output += "Succeeded Actions: " + str(response_json['globalStats']['stats']['Succeeded'])
        except Exception as e:
            output = "Exception occurred while processing response for Archive action: " + str(e)
    else:
        try:
            json_response = res.json()
            output = "Could not archive Sensor. The received response is {json_response}".format(json_response=json_response)
        except Exception as e:
            raise Exception('Your request failed with the following error: ' + response.content + '. Response Status code: ' + str(response.status_code))
    demisto.results(output)


def unarchive_sensor():
    sensor_id = demisto.getArg('sensorID')
    unarchive_reason = demisto.getArg('unarchiveReason')
    data = {
        "sensorsIds": [sensor_id],
        "argument": unarchive_reason
    }
    response = http_request('POST', '/rest/sensors/action/unarchive', json_body=data, return_json=False, custom_response=True)
    if response.status_code == 204:
        output = "The selected Sensor with Sensor ID: {sensor_id} is not available for unarchive.".format(sensor_id=sensor_id)
    elif response.status_code == 200:
        output = ""
        try:
            response_json = response.json()
            output = "Sensor unarchive status: "
            output += "Failed Actions: " + str(response_json['globalStats']['stats']['Failed']) + '. '
            output += "Succeeded Actions: " + str(response_json['globalStats']['stats']['Succeeded'])
        except Exception as e:
            output = "Exception occurred while processing response for Unarchive action: " + str(e)
    else:
        try:
            json_response = res.json()
            output = "Could not unarchive Sensor. The received response is {json_response}".format(json_response=json_response)
        except Exception as e:
            raise Exception('Your request failed with the following error: ' + response.content + '. Response Status code: ' + str(response.status_code))
    demisto.results(output)


def delete_sensor():
    sensor_id = demisto.getArg('sensorID')

    data = {
        "sensorsIds": [sensor_id]
    }
    response = http_request('POST', '/rest/sensors/action/delete', json_body=data, return_json=False, custom_response=True)

    if response.status_code == 204:
        output = "The selected Sensor with Sensor ID: {sensor_id} is not available for deleting.".format(sensor_id=sensor_id)
    elif response.status_code == 200:
        output = "Sensor deleted successfully."
    else:
        try:
            json_response = res.json()
            output = "Could not delete Sensor. The received response is {json_response}".format(json_response=json_response)
        except Exception as e:
            raise Exception('Your request failed with the following error: ' + response.content + '. Response Status code: ' + str(response.status_code))
    demisto.results(output)


def malop_to_incident(malop):
    if not isinstance(malop, dict):
        raise ValueError("Cybereason raw response is not valid, malop is not dict")

    guid_string = malop.get('guidString', '')
    incident = {
        'rawJSON': json.dumps(malop),
        'name': 'Cybereason Malop ' + guid_string,
        'labels': [{'type': 'GUID', 'value': guid_string}]}

    return incident


def fetch_incidents():
    last_run = demisto.getLastRun()

    if last_run and last_run.get('creation_time'):
        last_update_time = int(last_run.get('creation_time'))
    else:
        # In first run
        last_update_time, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    max_update_time = last_update_time

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

    malop_process_type, malop_loggon_session_type = query_malops(total_result_limit=10000, per_group_limit=10000,
                                                                 filters=filters)
    incidents = []

    for response in (malop_process_type, malop_loggon_session_type):
        malops = dict_safe_get(response, ['data', 'resultIdToElementDataMap'], default_return_value={},
                               return_type=dict)

        for malop in malops.values():
            simple_values = dict_safe_get(malop, ['simpleValues'], default_return_value={}, return_type=dict)
            simple_values.pop('iconBase64', None)
            simple_values.pop('malopActivityTypes', None)
            malop_update_time = dict_safe_get(simple_values, ['malopLastUpdateTime', 'values', 0])
            if malop_update_time > max_update_time:
                max_update_time = malop_update_time

            incident = malop_to_incident(malop)
            incidents.append(incident)

    demisto.setLastRun({
        'creation_time': max_update_time
    })

    demisto.incidents(incidents)


def login():
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close'
    }
    data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    http_request('POST', '/login.html', data=data, headers=headers, return_json=False)


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


def logout():
    http_request('GET', '/logout', return_json=False)


''' EXECUTION CODE '''

LOG('command is %s' % (demisto.command(),))

session = requests.session()


def get_file_guids(malop_id):
    """Get all File GUIDs for the given malop"""
    processes = fetch_malop_processes(malop_id)
    img_file_guids = fetch_imagefile_guids(processes)
    return img_file_guids


def fetch_malop_processes(malop_id):
    json_body = {
        "queryPath":[
            {
                "requestedType":"MalopProcess",
                "filters":[],
                "guidList":[malop_id],
                "connectionFeature":{
                    "elementInstanceType":"MalopProcess",
                    "featureName":"suspects"
                }
            },
            {
                "requestedType":"Process",
                "filters":[],
                "isResult":True
            }
        ],
        "totalResultLimit":1000,
        "perGroupLimit":1200,
        "perFeatureLimit":1200,
        "templateContext":"DETAILS",
        "queryTimeout": None,
        "customFields":[
            "maliciousByDualExtensionByFileRootCause",
            "creationTime",
            "endTime",
            "elementDisplayName"
        ]
    }
    response = http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    try:
        result = response['data']['resultIdToElementDataMap']
    except Exception as e:
        raise ValueError("Exception when parsing JSON response: {}".format(str(e)))
    return list(result.keys())


def fetch_imagefile_guids(processes):
    json_body = {
        "queryPath":[
            {
                "requestedType":"Process",
                "guidList":processes,
                "result":True
            }
        ],
        "totalResultLimit":1000,
        "perGroupLimit":1000,
        "perFeatureLimit":100,
        "templateContext":"DETAILS",
        "customFields":["ownerMachine","calculatedUser","parentProcess","execedBy","service","self","openedFiles","children","elementDisplayName","applicablePid","tid","creationTime","firstSeenTime","lastSeenTime","endTime","commandLine","decodedCommandLine","imageFilePath","iconBase64","isAggregate","isServiceHost","isDotNetProtected","imageFile","imageFile.extensionType","imageFile.correctedPath","imageFile.sha1String","imageFile.md5String","imageFile.productType","imageFile.companyName","imageFile.productName","imageFile.signerInternalOrExternal","imageFile.avRemediationStatus","imageFile.comments","fileAccessEvents","registryEvents","hookedFunctions","productType","imageFile.signedInternalOrExternal","imageFile.signatureVerifiedInternalOrExternal","imageFile.maliciousClassificationType","imageFile.isDownloadedFromInternet","imageFile.downloadedFromDomain","imageFile.downloadedFromIpAddress","imageFile.downloadedFromUrl","imageFile.downloadedFromUrlReferrer","imageFile.downloadedFromEmailFrom","imageFile.downloadedFromEmailMessageId","imageFile.downloadedFromEmailSubject","ownerMachine.isActiveProbeConnected","ownerMachine.osType","ownerMachine.osVersionType","ownerMachine.deviceModel","childrenCreatedByThread","failedToAccess","autorun","loadedModules","markedForPrevention","executionPrevented","ransomwareAutoRemediationSuspended","ransomwareAffectedFiles","totalNumOfInstances","lastMinuteNumOfInstances","lastSeenTimeStamp","cveEventsStr","isExectuedByWmi","wmiQueryStrings","wmiPersistentObjects","createdByWmi.wmiOperation","createdByWmi.clientPid","createdByWmi.isLocal","createdByWmi.clientProcess","createdByWmi.clientMachine","injectionMethod","originInjector","hostProcess","creatorThread","hostedChildren","isInjectingProcess","injectedChildren","isFullProcessMemoryDump","creatorProcess","createdChildren","seenCreation","newProcess","processRatio","hashRatio","connections","listeningConnections","externalConnections","internalConnections","localConnections","dynamicConfigurationConnections","incomingConnections","outgoingConnections","absoluteHighVolumeExternalConnections","totalNumberOfConnections","totalTransmittedBytes","totalReceivedBytes","resolvedDnsQueriesDomainToIp","resolvedDnsQueriesDomainToDomain","resolvedDnsQueriesIpToDomain","unresolvedDnsQueriesFromIp","unresolvedDnsQueriesFromDomain","cpuTime","memoryUsage","hasVisibleWindows","integrity","isHidden","logonSession","remoteSession","isWhiteListClassification","matchedWhiteListRuleIds"]
    }
    response = http_request('POST', '/rest/visualsearch/query/simple', json_body=json_body)
    img_file_guids = dict()
    result = response['data']['resultIdToElementDataMap']
    try:
        for process, details in result.items():
            image_files= ('' if details['elementValues']['imageFile']['elementValues'] is None else details['elementValues']['imageFile']['elementValues'])           
            for image_file in image_files:
                img_file_guids[image_file['name']] = image_file['guid']
    except Exception as e:
        demisto.log(str(e))
    return img_file_guids


def start_fetchfile_command():
    malop_id = demisto.getArg('malopGUID')
    user_name = demisto.getArg('userName')
    response = get_file_guids(malop_id)
    for filename, file_guid in response.items():
        resp = start_fetchfile(file_guid, user_name)
        try:
            if resp['status'] == "SUCCESS":
                demisto.results("Successfully started fetching file for the given malop")
        except Exception as e:
            raise Exception ("Failed to start fetch file process")


def start_fetchfile(element_id, user_name):
    data = {
        'elementGuids': [element_id],
        'initiatorUserName':user_name
    }
    return http_request('POST', '/rest/fetchfile/start', data = json.dumps(data))


def fetchfile_progress_command():
    malop_id = demisto.getArg('malopGuid')
    response = get_file_guids(malop_id)
    timeout_sec = 60
    interval_sec = 10
    new_malop_comments = get_batch_id(response, timeout_sec, interval_sec)
    filename=[]
    status = []
    message = []
    for item in range(len(new_malop_comments)):
        filename.append(new_malop_comments[item].get("name"))
        status.append(new_malop_comments[item].get("isSuccess"))
        message.append(new_malop_comments[item].get("message"))
    ec = {
        'Download.progress(val.MalopID && val.MalopID === obj.MalopID)': {
            'fileName': filename,
            'status': status,
            'batchID': message,
            'MalopID': malop_id
        }
    }
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': new_malop_comments,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Filename: ' + str(filename) + ' Status: ' + str(status) + ' Batch ID: ' + str(message),
        'EntryContext': ec
    })


def get_batch_id(suspect_files_guids, timeout_seconds, interval_seconds):
    new_malop_comments = []
    passed_seconds = timeout_seconds
    progress_response = fetchfile_progress()
    while passed_seconds > 0:
        result = progress_response
        for file_status in result['data']:
            if file_status['fileName'] in suspect_files_guids.keys() and file_status['succeeded'] == True:
                batch_id = file_status['batchId']
                file_name = file_status['fileName']
                new_malop_comments.append({ "isSuccess": True, "message": batch_id, "name": file_name})
                del suspect_files_guids[file_status['fileName']]
        time.sleep(interval_seconds) # Sleep for 10 seconds before next call
        passed_seconds = passed_seconds - interval_seconds
    for suspect_file in suspect_files_guids.keys():
        malop_comment = "Could not download the file {} from source machine, even after waiting for {} seconds.".format(suspect_file, timeout_seconds)
        new_malop_comments.append({ "isSuccess": False, "message": malop_comment})
    return new_malop_comments


def fetchfile_progress():
    return http_request('GET', '/rest/fetchfile/downloads/progress')


def download_fetchfile_command():
    batch_id = demisto.getArg('batchID')
    demisto.log('Downloading the file with this Batch ID: {}'.format(batch_id))
    response = download_fetchfile(batch_id)
    if response.status_code == 200:
        file_download = fileResult('download.zip', response.content)
        demisto.results(file_download)
    elif response.status_code == 500:
        demisto.results('The given Batch ID has expired')
    else:
        demisto.results('Your request failed with the following error: ' + response.content + '. Response Status code: ' + str(response.status_code))


def download_fetchfile(batch_id):
    url = '/rest/fetchfile/getfiles/{batch_id}'.format(batch_id=batch_id)
    return http_request('GET', url, custom_response=True,return_json=False)


def close_fetchfile_command():
    batch_id = demisto.getArg('batchID')
    resp = close_fetchfile(batch_id)
    try:
        if resp.json()['status'] == 'SUCCESS':
            demisto.results('Successfully aborts a file download operation that is in progress.')
    except Exception as e:
        raise Exception('The given Batch ID does not exist')


def close_fetchfile(batch_id):
    url = '/rest/fetchfile/close/{batch_id}'.format(batch_id=batch_id)
    return http_request('GET', url, custom_response=True,return_json=False)


def malware_query_command():
    needs_attention = demisto.getArg('needsAttention')
    malware_type = demisto.getArg('type')
    malware_status = demisto.getArg('status')
    time_stamp = demisto.getArg('timestamp')
    limit_range = demisto.getArg('limit')
    limit_range = int(limit_range)
    if limit_range > 0:
        filter_response = malware_query_filter(needs_attention, malware_type, malware_status, time_stamp, limit_range)
        demisto.results(filter_response)
    else:
        raise Exception("Limit cannot be zero or a negative number.")


def malware_query_filter(needs_attention, malware_type, malware_status, time_stamp, limit_range):
    query = []
    if bool(needs_attention) == True:
        query.append({"fieldName": "needsAttention","operator": "Is","values": [bool(needs_attention)]})
    if bool(malware_type) == True:
        types = malware_type.split(",")
        query.append({"fieldName": "type","operator": "Equals","values": types})
    if bool(malware_status) == True:
        is_status = malware_status.split(",")
        query.append({"fieldName": "status","operator": "Equals","values": is_status})
    if bool(time_stamp) == True:
        query.append({"fieldName": "timestamp","operator": "GreaterThan","values": [int(time_stamp)]})
    response = malware_query(query, limit_range)
    return response


def malware_query(action_values, limit):
    json_body = {"filters": action_values,"sortingFieldName":"timestamp","sortDirection":"DESC","limit":limit,"offset":0}

    return http_request('POST', '/rest/malware/query', json_body=json_body)


def main():
    auth = ''
    try:
        if CERTIFICATE:
            client_certificate()
            auth = 'CERT'
        elif USERNAME and PASSWORD:
            login()
            auth = 'BASIC'
        else:
            raise Exception('No credentials were provided')

        if demisto.command() == 'test-module':
            # Tests connectivity and credentails on login
            query_user([])
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()

        elif demisto.command() == 'cybereason-is-probe-connected':
            is_probe_connected_command()

        elif demisto.command() == 'cybereason-query-processes':
            query_processes_command()

        elif demisto.command() == 'cybereason-query-malops':
            query_malops_command()

        elif demisto.command() == 'cybereason-query-connections':
            query_connections_command()

        elif demisto.command() == 'cybereason-isolate-machine':
            isolate_machine_command()

        elif demisto.command() == 'cybereason-unisolate-machine':
            unisolate_machine_command()

        elif demisto.command() == 'cybereason-malop-processes':
            malop_processes_command()

        elif demisto.command() == 'cybereason-add-comment':
            add_comment_command()

        elif demisto.command() == 'cybereason-update-malop-status':
            update_malop_status_command()

        elif demisto.command() == 'cybereason-prevent-file':
            prevent_file_command()

        elif demisto.command() == 'cybereason-unprevent-file':
            unprevent_file_command()

        elif demisto.command() == 'cybereason-kill-process':
            kill_process_command()

        elif demisto.command() == 'cybereason-quarantine-file':
            quarantine_file_command()

        elif demisto.command() == 'cybereason-delete-registry-key':
            delete_registry_key_command()

        elif demisto.command() == 'cybereason-block-file':
            block_file_command()

        elif demisto.command() == 'cybereason-query-file':
            query_file_command()

        elif demisto.command() == 'cybereason-query-domain':
            query_domain_command()

        elif demisto.command() == 'cybereason-query-user':
            query_user_command()

        elif demisto.command() == 'cybereason-start-fetchfile':
            start_fetchfile_command()

        elif demisto.command() == 'cybereason-fetchfile-progress':
            fetchfile_progress_command()
             
        elif demisto.command() == 'cybereason-download-file':
            download_fetchfile_command()

        elif demisto.command() == 'cybereason-close-file-batch-id':
            close_fetchfile_command()

        elif demisto.command() == 'cybereason-archive-sensor':
            archive_sensor()

        elif demisto.command() == 'cybereason-unarchive-sensor':
            unarchive_sensor()

        elif demisto.command() == 'cybereason-delete-sensor':
            delete_sensor()

        elif demisto.command() == 'cybereason-malware-query':
            malware_query_command()

    except Exception as e:
        return_error(str(e))
    finally:
        logout()
        if auth and auth == 'CERT':
            os.remove(os.path.abspath('client.pem'))
            os.remove(os.path.abspath('client.cert'))


if __name__ in ('__builtin__', 'builtins'):
    main()
