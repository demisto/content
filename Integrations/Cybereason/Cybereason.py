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

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
SERVER = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
USE_SSL = not demisto.params().get('unsecure', False)
CERTIFICATE = demisto.params().get('credentials').get('credentials').get('sshkey')
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

    limit = demisto.args().get('limit')
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


def http_request(method, url_suffix, data=None, json=None, headers=HEADERS):
    LOG('running request with url=%s' % (SERVER + url_suffix))
    try:
        res = session.request(
            method,
            SERVER + url_suffix,
            headers=headers,
            data=data,
            json=json,
            verify=USE_SSL
        )
        if res.status_code not in {200, 204}:
            raise Exception('Your request failed with the following error: ' + res.content + str(res.status_code))
    except Exception, e:
        LOG(e)
        raise
    return res


def translate_timestamp(timestamp):
    return datetime.fromtimestamp(int(timestamp) / 1000).isoformat()


def update_output(output, simple_values, element_values, info_dict):
    for i in range(len(info_dict)):
        info_type = info_dict[i]['type']
        if info_type == 'simple':
            field = simple_values.get(info_dict[i]['field'])
            if field:
                output[info_dict[i]['header']] = field['values'][0]
        elif info_type == 'element':
            field = element_values.get(info_dict[i]['field'])
            if field:
                output[info_dict[i]['header']] = field['elementValues'][0]['name']
        elif info_type == 'time':
            field = simple_values.get(info_dict[i]['field'])
            if field:
                output[info_dict[i]['header']] = translate_timestamp(field['values'][0])
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
    json = build_query(query_fields, path)
    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    data = response['data'].get('resultIdToElementDataMap')

    if not data:
        return_error('Could not find machine')

    guid = data.keys()[0]
    simple_values = data[guid]['simpleValues']
    pylum_id = simple_values['pylumId']['values'][0]
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
    json = build_query(query_fields, path)
    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    data = response['data'].get('resultIdToElementDataMap')
    if not data:
        return_error('Could not find machine')
    machine_guid = data.keys()[0]
    return machine_guid


''' FUNCTIONS '''


def is_probe_connected_command(is_remediation_commmand=False):

    machine = demisto.args().get('machine')
    is_connected = False

    response = is_probe_connected(machine)

    elements = response['data']['resultIdToElementDataMap']

    for key, value in elements.iteritems():
        machine_name = value['simpleValues']['elementDisplayName']['values'][0]
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
    json = build_query(query_fields, path)
    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def query_processes_command():

    machine = demisto.args().get('machine')
    process_name = demisto.args().get('processName')
    only_suspicious = demisto.args().get('onlySuspicious')
    has_incoming_connection = demisto.args().get('hasIncomingConnection')
    has_outgoing_connection = demisto.args().get('hasOutgoingConnection')
    has_external_connection = demisto.args().get('hasExternalConnection')
    unsigned_unknown_reputation = demisto.args().get('unsignedUnknownReputation')
    from_temporary_folder = demisto.args().get('fromTemporaryFolder')
    privileges_escalation = demisto.args().get('privilegesEscalation')
    maclicious_psexec = demisto.args().get('maliciousPsExec')

    response = query_processes(machine, process_name, only_suspicious, has_incoming_connection, has_outgoing_connection,
                               has_external_connection, unsigned_unknown_reputation, from_temporary_folder,
                               privileges_escalation, maclicious_psexec)
    elements = response['data']['resultIdToElementDataMap']
    outputs = []
    for element in elements:

        simple_values = elements[element]['simpleValues']
        element_values = elements[element]['elementValues']

        output = {}
        for i in range(len(PROCESS_INFO)):
            if PROCESS_INFO[i]['type'] == 'filterData':
                output[PROCESS_INFO[i]['header']] = elements[element]['filterData']['groupByValue']

        output = update_output(output, simple_values, element_values, PROCESS_INFO)
        outputs.append(output)

    context = []
    for output in outputs:
        # Remove whitespaces from dictionary keys
        context.append({k.translate(None, ' '): v for k, v in output.iteritems()})
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

    json = build_query(PROCESS_FIELDS, path)
    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def query_connections_command():

    machine = demisto.args().get('machine')
    ip = demisto.args().get('ip')
    if ip and machine:
        demisto.results('Too many arguments given.')
        return
    elif not ip and not machine:
        demisto.results('Not enough arguments given.')
        return

    response = query_connections(machine, ip)
    elements = response['data']['resultIdToElementDataMap']
    outputs = []

    for element in elements:

        simple_values = elements[element]['simpleValues']
        element_values = elements[element]['elementValues']

        output = {}  # type: Dict[Any,Any]
        output = update_output(output, simple_values, element_values, CONNECTION_INFO)
        outputs.append(output)

    context = []
    for output in outputs:
        # Remove whitespaces from dictionary keys
        context.append({k.translate(None, ' '): v for k, v in output.iteritems()})
    ec = {
        'Connection': context
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Cybereason Connections', outputs, CONNECTION_HEADERS),
        'EntryContext': ec
    })


def query_connections(machine, ip):

    if machine:
        path = [
            {
                'requestedType': 'Connection',
                'filters': [],
                'connectionFeature':
                {
                    'elementInstanceType': 'Connection',
                    'featureName': 'ownerMachine'
                },
                'isResult': True
            },
            {
                'requestedType': 'Machine',
                'filters':
                [{
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

    json = build_query(CONNECTION_FIELDS, path)
    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def query_malops_command():

    total_result_limit = demisto.args().get('totalResultLimit')
    per_group_limit = demisto.args().get('perGroupLimit')
    template_context = demisto.args().get('templateContext')
    filters = demisto.args().get('filters', [])
    within_last_days = demisto.args().get('withinLastDays')
    guid_list = argToList(demisto.args().get('malopGuid'))

    if within_last_days:
        current_timestamp = time.time()
        current_datetime = datetime.fromtimestamp(current_timestamp)
        within_last_days_datetime = current_datetime - timedelta(days=int(within_last_days))
        within_last_days_timestamp = time.mktime(within_last_days_datetime.timetuple()) + \
            within_last_days_datetime.microsecond / 1E6  # Converting datetime to time
        within_last_days_timestamp = within_last_days_timestamp * 1000
        filters.append({
            'facetName': 'malopLastUpdateTime',
            'values': [within_last_days_timestamp],
            'filterType': 'GreaterThan'
        })

    response = query_malops(total_result_limit, per_group_limit, template_context, filters, guid_list=guid_list)
    data = response['data']
    malops_map = data.get('resultIdToElementDataMap')
    if not data or not malops_map:
        demisto.results('No malops found')
        return

    outputs = []
    for malop_id in malops_map:
        malop = malops_map[malop_id]
        management_status = malop['simpleValues']['managementStatus']['values'][0]

        if management_status and management_status.lower() == 'closed':
            continue

        creation_time = translate_timestamp(malop['simpleValues']['creationTime']['values'][0])
        malop_last_update_time = translate_timestamp(malop['simpleValues']['malopLastUpdateTime']['values'][0])
        decision_failure = malop['simpleValues']['decisionFeature']['values'][0].replace('Process.', '')

        suspects_string = ''
        raw_suspects = malop['elementValues'].get('suspects')
        if raw_suspects:
            suspects = raw_suspects['elementValues'][0]
            suspects_string = '{}: {}'.format(suspects['elementType'], suspects['name'])

        affected_machines = []
        for machine in malop['elementValues']['affectedMachines']['elementValues']:
            machine_name = machine.get('name', '')
            affected_machines.append(machine_name)

        involved_hashes = []  # type: List[str]
        if 'rootCauseElementHashes' in malop['simpleValues']:
            if malop['simpleValues']['rootCauseElementHashes']['totalValues'] != 0:
                involved_hashes.extend(malop['simpleValues']['rootCauseElementHashes']['values'])

        malop_output = {
            'GUID': malop_id,
            'Link': SERVER + '/#/malop/' + malop_id,
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
        'HumanReadable': tableToMarkdown('Cybereason Malops', outputs, ['GUID', 'Link', 'CreationTime', 'Status',
                                                                        'LastUpdateTime', 'DecisionFailure', 'Suspects',
                                                                        'AffectedMachine', 'InvolvedHash']),
        'EntryContext': ec
    })


def query_malops(total_result_limit=None, per_group_limit=None, template_context=None, filters=None, guid_list=[]):

    body = {
        'totalResultLimit': int(total_result_limit) if total_result_limit else 10000,
        'perGroupLimit': int(per_group_limit) if per_group_limit else 10000,
        'perFeatureLimit': 100,
        'templateContext': template_context or 'MALOP',
        'queryPath': [
            {
                'requestedType': 'MalopProcess',
                'guidList': guid_list,
                'result': True,
                'filters': filters or None
            }
        ]
    }
    cmd_url = '/rest/crimes/unified'
    response = http_request('POST', cmd_url, json=body)
    try:
        return response.json()
    except Exception:
        raise Exception('Failed to parse query malop response as JSON: {}'.format(response.text))


def isolate_machine_command():

    machine = demisto.args().get('machine')
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
        return_error('Failed to isolate machine.')


def isolate_machine(machine):

    pylum_id = get_pylum_id(machine)

    cmd_url = '/rest/monitor/global/commands/isolate'
    json = {
        'pylumIds': [pylum_id]

    }
    response = http_request('POST', cmd_url, json=json).json()
    return response, pylum_id


def unisolate_machine_command():

    machine = demisto.args().get('machine')
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
        return_error('Failed to un-isolate machine.')


def unisolate_machine(machine):

    pylum_id = get_pylum_id(machine)
    cmd_url = '/rest/monitor/global/commands/un-isolate'
    json = {
        'pylumIds': [pylum_id]

    }
    response = http_request('POST', cmd_url, json=json).json()
    return response, pylum_id


def malop_processes_command():

    malop_guids = demisto.args().get('malopGuids')
    machine_name = demisto.args().get('machineName')

    if isinstance(malop_guids, unicode):
        malop_guids = malop_guids.split(',')
    elif not isinstance(malop_guids, list):
        return_error('malopGuids must be array of strings')

    machine_name_list = [machine.lower() for machine in argToList(machine_name)]

    response = malop_processes(malop_guids)
    elements = response['data']['resultIdToElementDataMap']
    outputs = []

    for element in elements:

        simple_values = elements[element]['simpleValues']
        element_values = elements[element]['elementValues']

        if machine_name_list:
            owner_machine = element_values.get('ownerMachine', {})
            machine_list = owner_machine.get('elementValues', [])
            wanted_machine = False
            for machine in machine_list:
                current_machine_name = machine.get('name', '').lower()
                if current_machine_name in machine_name_list:
                    wanted_machine = True
                    break

            if not wanted_machine:
                continue

        output = {}
        for i in range(len(PROCESS_INFO)):
            if PROCESS_INFO[i]['type'] == 'filterData':
                output[PROCESS_INFO[i]['header']] = elements[element]['filterData']['groupByValue']

        output = update_output(output, simple_values, element_values, PROCESS_INFO)
        outputs.append(output)

    context = []
    for output in outputs:
        # Remove whitespaces from dictionary keys
        context.append({k.translate(None, ' '): v for k, v in output.iteritems()})
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

    json = {
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
    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def add_comment_command():
    comment = demisto.args().get('comment')
    malop_guid = demisto.args().get('malopGuid')
    try:
        add_comment(malop_guid, comment.encode('utf-8'))
        demisto.results('Comment added successfully')
    except Exception, e:
        return_error('Failed to add new comment. Orignal Error: ' + e.message)


def add_comment(malop_guid, comment):
    cmd_url = '/rest/crimes/comment/' + malop_guid
    http_request('POST', cmd_url, data=comment)


def update_malop_status_command():

    status = demisto.args().get('status')
    malop_guid = demisto.args().get('malopGuid')

    if status not in STATUS_MAP:
        return_error('Invalid status. Given status must be one of the following: To Review,Unread,Remediated or Not Relevant')

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

    json = {}
    json[malop_guid] = api_status

    cmd_url = '/rest/crimes/status'
    response = http_request('POST', cmd_url, json=json).json()
    if response['status'] != 'SUCCESS':
        return_error('Failed to update malop {0} status to {1}. Message: {2}'.format(malop_guid, status,
                                                                                     response['message']))


def prevent_file_command():

    file_hash = demisto.args()['md5']
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

    json = [{
        'keys': [str(file_hash)],
        'maliciousType': 'blacklist',
        'remove': False,
        'prevent': True
    }]
    cmd_url = '/rest/classification/update'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def unprevent_file_command():
    file_hash = demisto.args()['md5']
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
        return_error('Failed to unprevent file')


def unprevent_file(file_hash):

    json = [{
        'keys': [str(file_hash)],
        'remove': True,
        'prevent': False
    }]
    cmd_url = '/rest/classification/update'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def kill_process_command():

    machine_name = demisto.args()['machine']
    file_name = demisto.args()['file']
    malop_guid = demisto.args()['malop']

    is_machine_conntected = is_probe_connected_command(is_remediation_commmand=True)
    if is_machine_conntected is False:
        return_error('Machine must be connected to Cybereason in order to perform this action.')

    machine_guid = get_machine_guid(machine_name)
    procceses = query_processes(machine_name, file_name)
    process_data = procceses['data'].get('resultIdToElementDataMap')
    if not process_data:
        return_error('Could not find process')
    processes = process_data.keys()
    for process_guid in processes:
        response = kill_process(malop_guid, machine_guid, process_guid)
        status_log = response['statusLog'][0]
        status = status_log['status']
        # response
        demisto.results('Request to kill process {0} was sent successfully and now in status {1}'.format(process_guid,
                                                                                                         status))


def kill_process(malop_guid, machine_guid, process_guid):

    json = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: [{
                'targetId': process_guid,
                'actionType': 'KILL_PROCESS'
            }]
        }
    }

    cmd_url = '/rest/remediate'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def quarantine_file_command():

    machine_name = demisto.args()['machine']
    file_name = demisto.args()['file']
    malop_guid = demisto.args()['malop']

    is_machine_conntected = is_probe_connected_command(is_remediation_commmand=True)
    if is_machine_conntected is False:
        return_error('Machine must be connected to Cybereason in order to perform this action.')

    machine_guid = get_machine_guid(machine_name)
    procceses = query_processes(machine_name, file_name)
    process_data = procceses['data'].get('resultIdToElementDataMap')
    if not process_data:
        return_error('Could not find process')
    processes = process_data.keys()
    for process_guid in processes:
        response = kill_process(malop_guid, machine_guid, process_guid)
        status_log = response['statusLog'][0]
        status = status_log['status']
        demisto.results(status)


def quarantine_file(malop_guid, machine_guid, process_guid):

    json = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: [{
                'targetId': process_guid,
                'actionType': 'QUARANTINE_FILE'
            }]
        }
    }

    cmd_url = '/rest/remediate'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def delete_registry_key_command():

    machine_name = demisto.args()['machine']
    file_name = demisto.args()['file']
    malop_guid = demisto.args()['malop']

    machine_guid = get_machine_guid(machine_name)
    procceses = query_processes(machine_name, file_name)
    process_data = procceses['data'].get('resultIdToElementDataMap')
    if not process_data:
        return_error('Could not find process')
    processes = process_data.keys()
    for process_guid in processes:
        response = delete_registry_key(malop_guid, machine_guid, process_guid)
        status_log = response['statusLog'][0]
        status = status_log['status']
        demisto.results(status)


def delete_registry_key(malop_guid, machine_guid, process_guid):

    json = {
        'malopId': malop_guid,
        'actionsByMachine': {
            machine_guid: [{
                'targetId': process_guid,
                'actionType': 'DELETE_REGISTRY_KEY'
            }]
        }
    }

    cmd_url = '/rest/remediate'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def query_file_command():

    file_hash = demisto.args().get('file_hash')

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
        return_error('Hash type is not supported.')

    data = query_file(filters)

    if data:
        cybereason_outputs = []
        file_outputs = []
        endpoint_outputs = []
        files = data.get('resultIdToElementDataMap')
        for file in files.keys():

            raw_machine_details = get_file_machine_details(file)['data']['resultIdToElementDataMap']
            machine_details = raw_machine_details[raw_machine_details.keys()[0]]
            simple_values = files[file]['simpleValues']

            file_name = simple_values['elementDisplayName']['values'][0]
            md5 = simple_values['md5String']['values'][0]
            sha1 = simple_values['sha1String']['values'][0]
            path = simple_values['correctedPath']['values'][0]
            machine = files[file].get('elementValues', {}).get('ownerMachine', {}).get('elementValues')[0]['name']

            machine_element_values = machine_details['elementValues']
            machine_simple_values = machine_details['simpleValues']
            os_version = machine_simple_values['ownerMachine.osVersionType']['values'][0]

            raw_suspicions = machine_details['suspicions']
            suspicions = {}
            if raw_suspicions:
                for key in raw_suspicions.keys():
                    suspicions[key] = timestamp_to_datestring(raw_suspicions[key])

            evidences = []
            for key in machine_element_values:
                if 'evidence' in key.lower():
                    evidences.append(key)
            for key in machine_simple_values:
                if 'evidence' in key.lower():
                    evidences.append(key)

            company_name = None
            if 'companyName' in simple_values:
                company_name = simple_values['companyName']['values'][0]

            cybereason_outputs.append({
                'Name': file_name,
                'CreationTime': timestamp_to_datestring(simple_values['createdTime']['values'][0]),
                'ModifiedTime': timestamp_to_datestring(simple_values['modifiedTime']['values'][0]),
                'Malicious': files[file]['isMalicious'],
                'MD5': md5,
                'SHA1': sha1,
                'Path': path,
                'Machine': machine,
                'SuspicionsCount': machine_details['suspicionCount'],
                'IsConnected': (machine_simple_values['ownerMachine.isActiveProbeConnected']['values'][0] == 'true'),
                'OSVersion': os_version,
                'Suspicion': suspicions,
                'Evidence': evidences,
                'Signed': True if simple_values['isSigned']['values'][0] == 'true' else False,
                'Company': company_name
            })

            file_outputs.append({
                'Name': file_name,
                'MD5': md5,
                'SHA1': sha1,
                'Path': path,
                'Hostname': machine
            })
            endpoint_outputs.append({
                'Hostname': machine,
                'OSVersion': os_version
            })

            ec = {
                'Cybereason.File(val.MD5 && val.MD5===obj.MD5 || val.SHA1 && val.SHA1===obj.SHA1)': cybereason_outputs,
                'Endpoint(val.Hostname===obj.Hostname)': endpoint_outputs
            }
            ec[outputPaths['file']] = file_outputs

            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': data,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown('Cybereason file query results', cybereason_outputs),
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
    json = build_query(query_fields, path)
    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    if response.get('status', '') == 'SUCCESS' and 'data' in response:
        return response['data']
    else:
        return_error('Error occurred while trying to query the file.')


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
    json = build_query(query_fields, path, template_context='DETAILS')

    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    return response


def query_domain_command():

    domain_input = demisto.args().get('domain')

    filters = [{
        'facetName': 'elementDisplayName',
        'values': [domain_input],
        'filterType': 'ContainsIgnoreCase'
    }]

    data = query_domain(filters)

    if data:
        cybereason_outputs = []
        domain_outputs = []
        domains = data.get('resultIdToElementDataMap')
        for domain in domains.keys():

            simple_values = domains[domain]['simpleValues']

            reputation = simple_values['maliciousClassificationType']['values'][0]
            is_internal_domain = simple_values['isInternalDomain']['values'][0] == 'true'
            was_ever_resolved = simple_values['everResolvedDomain']['values'][0] == 'true'
            was_ever_resolved_as = simple_values['everResolvedSecondLevelDomain']['values'][0] == 'true'
            malicious = domains[domain].get('isMalicious')
            suspicions_count = domains[domain].get('suspicionCount')

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

            ec = {
                'Cybereason.Domain(val.Name && val.Name===obj.Name)': cybereason_outputs
            }
            ec[outputPaths['domain']] = domain_outputs

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
    json = build_query(query_fields, path)
    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    if response.get('status', '') == 'SUCCESS' and 'data' in response:
        return response['data']
    else:
        return_error('Error occurred while trying to query the file.')


def query_user_command():

    username = demisto.args().get('username')

    filters = [{
        'facetName': 'elementDisplayName',
        'values': [username],
        'filterType': 'ContainsIgnoreCase'
    }]

    data = query_user(filters)

    if data:
        cybereason_outputs = []
        users = data.get('resultIdToElementDataMap')
        for user in users.keys():

            simple_values = users[user]['simpleValues']
            element_values = users[user]['elementValues']

            domain = simple_values['domain']['values'][0]
            local_system = True if simple_values['isLocalSystem']['values'][0] == 'true' else False
            machine = element_values['ownerMachine']['elementValues'][0]['name']
            organization = element_values['ownerOrganization']['elementValues'][0]['name']

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
    json = build_query(query_fields, path)
    cmd_url = '/rest/visualsearch/query/simple'
    response = http_request('POST', cmd_url, json=json).json()
    if response.get('status', '') == 'SUCCESS' and 'data' in response:
        return response['data']
    else:
        return_error('Error occurred while trying to query the file.')


def malop_to_incident(malop):

    incident = {}  # type: Dict[Any, Any]
    incident['rawJSON'] = json.dumps(malop)
    incident['name'] = 'Cybereason Malop ' + malop['guidString']
    incident['labels'] = [{'type': 'GUID', 'value': malop['guidString']}]
    return incident


def fetch_incidents():

    last_run = demisto.getLastRun()

    if last_run and last_run['creation_time']:
        last_update_time = int(last_run['creation_time'])
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
        return_error('Given filter to fetch by is invalid.')

    data = query_malops(total_result_limit=10000, per_group_limit=10000, filters=filters)['data']
    malops = data['resultIdToElementDataMap']

    incidents = []

    for malop in malops:
        malops[malop]['simpleValues'].pop('iconBase64', None)
        malops[malop]['simpleValues'].pop('malopActivityTypes', None)
        malop_update_time = malops[malop]['simpleValues']['malopLastUpdateTime']['values'][0]

        incident = malop_to_incident(malops[malop])
        incidents.append(incident)
        if malop_update_time > max_update_time:
            max_update_time = malop_update_time

    demisto.setLastRun({
        'creation_time': max_update_time
    })

    demisto.incidents(incidents)


def login():
    cmd_url = '/login.html'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close'
    }
    data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    http_request('POST', cmd_url, data=data, headers=headers)


def client_certificate():
    cert = CERTIFICATE

    if 'Bag Attributes' not in cert:
        return_error('Could not find Bag Attributes')
    if '-----BEGIN CERTIFICATE-----' not in cert:
        return_error('Could not find certificate file')
    if '-----BEGIN RSA PRIVATE KEY-----' in cert:  # guardrails-disable-line
        i = cert.index('-----BEGIN RSA PRIVATE KEY-----')  # guardrails-disable-line
    else:
        return_error('Could not find certificate key')
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
        return_error("Failed to connect to server")

    # First time we may get a redirect, but second time should be 200
    response = session.get(url=SERVER)
    if response.status_code != 200:
        return_error("Failed to login with certificate. Expected response 200. Got: " + str(response.status_code))


def logout():
    cmd_url = '/logout'
    http_request('GET', cmd_url)


''' EXECUTION CODE '''

LOG('command is %s' % (demisto.command(), ))

session = requests.session()


if CERTIFICATE:
    client_certificate()
    AUTH = 'CERT'
if USERNAME and PASSWORD:
    login()
    AUTH = 'BASIC'
else:
    return_error('No credentials were provided')

try:
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
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)
finally:
    logout()
    if AUTH == 'CERT':
        os.remove(os.path.abspath('client.pem'))
        os.remove(os.path.abspath('client.cert'))
