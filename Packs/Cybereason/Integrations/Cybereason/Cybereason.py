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


def http_request(method, url_suffix, data=None, json_body=None, headers=HEADERS, return_json=True):
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
        if res.status_code not in {200, 204}:
            raise Exception('Your request failed with the following error: ' + res.content + str(res.status_code))
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

    response = query_connections(machine, ip)
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
        'HumanReadable': tableToMarkdown('Cybereason Connections', outputs),
        'EntryContext': ec
    })


def query_connections(machine, ip):
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
                    'values': [machine],
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
                        'values': [ip]
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
                if item.get('type', '') == 'filterData':
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

    is_machine_conntected = is_probe_connected_command(is_remediation_commmand=True)
    if not is_machine_conntected:
        raise Exception('Machine must be connected to Cybereason in order to perform this action.')

    machine_guid = get_machine_guid(machine_name)
    procceses = query_processes(machine_name, file_content)
    process_data = dict_safe_get(procceses, ['data', 'resultIdToElementDataMap'], default_return_value={},
                                 return_type=dict)
    for process_guid in process_data.keys():
        response = kill_process(malop_guid, machine_guid, process_guid)
        status = dict_safe_get(response, ['statusLog', 0, 'status'])
        # response
        demisto.results('Request to kill process {0} was sent successfully and now in status {1}'.format(process_guid,
                                                                                                         status))


def kill_process(malop_guid, machine_guid, process_guid):
    json_body = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: [{
                'targetId': process_guid,
                'actionType': 'KILL_PROCESS'
            }]
        }
    }

    return http_request('POST', '/rest/remediate', json_body=json_body)


def quarantine_file_command():
    machine_name = demisto.getArg('machine')
    file_content = demisto.getArg('file')
    malop_guid = demisto.getArg('malop')

    is_machine_conntected = is_probe_connected_command(is_remediation_commmand=True)
    if not is_machine_conntected:
        raise Exception('Machine must be connected to Cybereason in order to perform this action.')

    machine_guid = get_machine_guid(machine_name)
    procceses = query_processes(machine_name, file_content)
    process_data = dict_safe_get(procceses, ['data', 'resultIdToElementDataMap'], default_return_value={},
                                 return_type=dict)

    for process_guid in process_data.keys():
        response = kill_process(malop_guid, machine_guid, process_guid)
        status = dict_safe_get(response, ['statusLog', 0, 'status'])
        demisto.results(status)


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


def delete_registry_key_command():
    machine_name = demisto.getArg('machine')
    file_content = demisto.getArg('file')
    malop_guid = demisto.getArg('malop')

    machine_guid = get_machine_guid(machine_name)
    procceses = query_processes(machine_name, file_content)
    process_data = dict_safe_get(procceses, ['data', 'resultIdToElementDataMap'], default_return_value={},
                                 return_type=dict)

    for process_guid in process_data.keys():
        response = delete_registry_key(malop_guid, machine_guid, process_guid)
        status = dict_safe_get(response, ['statusLog', 0, 'status'])
        demisto.results(status)


def delete_registry_key(malop_guid, machine_guid, process_guid):
    json_body = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: [{
                'targetId': process_guid,
                'actionType': 'DELETE_REGISTRY_KEY'
            }]
        }
    }

    return http_request('POST', '/rest/remediate', json_body=json_body)


def query_file_command():
    file_hash = demisto.getArg('file_hash')

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
            'HumanReadable': tableToMarkdown('Cybereason file query results', cybereason_outputs, removeNull=True),
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
    domain_input = demisto.getArg('domain')

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
            'HumanReadable': tableToMarkdown('Cybereason domain query results', cybereason_outputs,
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
    username = demisto.getArg('username')

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
                'HumanReadable': tableToMarkdown('Cybereason user query results', cybereason_outputs,
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

        elif demisto.command() == 'cybereason-kill-process':  # To be added as a command in the future
            kill_process_command()

        elif demisto.command() == 'cybereason-quarantine-file':  # To be added as a command in the future
            quarantine_file_command()

        elif demisto.command() == 'cybereason-delete-registry-key':  # To be added as a command in the future
            delete_registry_key_command()

        elif demisto.command() == 'cybereason-query-file':
            query_file_command()

        elif demisto.command() == 'cybereason-query-domain':
            query_domain_command()

        elif demisto.command() == 'cybereason-query-user':
            query_user_command()

    except Exception as e:
        return_error(str(e))
    finally:
        logout()
        if auth and auth == 'CERT':
            os.remove(os.path.abspath('client.pem'))
            os.remove(os.path.abspath('client.cert'))


if __name__ in ('__builtin__', 'builtins'):
    main()
