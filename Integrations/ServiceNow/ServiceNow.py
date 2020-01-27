import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import re
import requests
import json
from datetime import datetime
import shutil

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


def get_server_url():
    url = demisto.params()['url']
    url = re.sub('/[\/]+$/', '', url)
    url = re.sub('\/$', '', url)
    return url


''' GLOBAL VARIABLES '''

DEFAULTS = {
    'limit': 10,
    'offset': 0,
    'fetch_limit': 10,
    'fetch_time': '10 minutes',
    'ticket_type': 'incident'
}

USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
VERIFY_SSL = not demisto.params().get('insecure', False)
API = '/api/now/'
VERSION = demisto.params().get('api_version')
PARAMS_TICKET_TYPE = demisto.params().get('ticket_type', DEFAULTS['ticket_type'])
FETCH_TIME = demisto.params().get('fetch_time').strip()
SYSPARM_QUERY = demisto.params().get('sysparm_query')
SYSPARM_LIMIT = demisto.params().get('fetch_limit', DEFAULTS['fetch_limit'])
TIMESTAMP_FIELD = demisto.params().get('timestamp_field', 'opened_at')
TICKET_TYPE = demisto.params().get('ticket_type', DEFAULTS['ticket_type'])
GET_ATTACHMENTS = demisto.params().get('get_attachments', False)

if VERSION:
    API += VERSION + '/'

SERVER_URL = get_server_url() + API

TICKET_STATES = {
    'incident': {
        '1': '1 - New',
        '2': '2 - In Progress',
        '3': '3 - On Hold',
        '4': '4 - Awaiting Caller',
        '5': '5 - Awaiting Evidence',
        '6': '6 - Resolved',
        '7': '7 - Closed',
        '8': '8 - Canceled'
    },
    'problem': {
        '1': '1 - Open',
        '2': '2 - Known Error',
        '3': '3 - Pending Change',
        '4': '4 - Closed/Resolved'
    },
    'change_request': {
        '-5': '-5 - New',
        '-4': '-4 - Assess',
        '-3': '-3 - Authorize',
        '-2': '-2 - Scheduled',
        '-1': '-1 - Implement',
        '0': '0 - Review',
        '3': '3 - Closed',
        '4': '4 - Canceled'
    },
    'sc_task': {
        '-5': '-5 - Pending',
        '1': '1 - Open',
        '2': '2 - Work In Progress',
        '3': '3 - Closed Complete',
        '4': '4 - Closed Incomplete',
        '7': '7 - Closed Skipped'
    },
    'sc_request': {
        '1': '1 - Approved',
        '3': '3 - Closed',
        '4': '4 - Rejected'
    }
}

TICKET_SEVERITY = {
    '1': '1 - High',
    '2': '2 - Medium',
    '3': '3 - Low'
}

TICKET_PRIORITY = {
    '1': '1 - Critical',
    '2': '2 - High',
    '3': '3 - Moderate',
    '4': '4 - Low',
    '5': '5 - Planning'
}

COMPUTER_STATUS = {
    '1': 'In use',
    '2': 'On order',
    '3': 'On maintenance',
    '6': 'In stock/In transit',
    '7': 'Retired',
    '100': 'Missing'
}

# Map SNOW severity to Demisto severity for incident creation
SEVERITY_MAP = {
    '1': 3,
    '2': 2,
    '3': 1
}

SNOW_ARGS = ['active', 'activity_due', 'opened_at', 'short_description', 'additional_assignee_list', 'approval_history',
             'approval_set', 'assigned_to', 'assignment_group',
             'business_duration', 'business_service', 'business_stc', 'calendar_duration', 'calendar_stc', 'caller_id',
             'caused_by', 'close_code', 'close_notes',
             'closed_at', 'closed_by', 'cmdb_ci', 'comments', 'comments_and_work_notes', 'company', 'contact_type',
             'correlation_display', 'correlation_id',
             'delivery_plan', 'delivery_task', 'description', 'due_date', 'expected_start', 'follow_up', 'group_list',
             'hold_reason', 'impact', 'incident_state',
             'knowledge', 'location', 'made_sla', 'notify', 'order', 'parent', 'parent_incident', 'priority',
             'problem_id', 'resolved_at', 'resolved_by', 'rfc',
             'severity', 'sla_due', 'state', 'subcategory', 'sys_tags', 'time_worked', 'urgency', 'user_input',
             'watch_list', 'work_end', 'work_notes', 'work_notes_list',
             'work_start', 'impact', 'incident_state', 'title', 'type', 'change_type', 'category', 'state', 'caller']

# Every table in ServiceNow should have those fields
DEFAULT_RECORD_FIELDS = {
    'sys_id': 'ID',
    'sys_updated_by': 'UpdatedBy',
    'sys_updated_on': 'UpdatedAt',
    'sys_created_by': 'CreatedBy',
    'sys_created_on': 'CreatedAt'
}

DEPRECATED_COMMANDS = ['servicenow-get', 'servicenow-incident-get',
                       'servicenow-create', 'servicenow-incident-create',
                       'servicenow-update', 'servicenow-query',
                       'servicenow-incidents-query', 'servicenow-incident-update']

''' HELPER FUNCTIONS '''


def send_request(path, method='get', body=None, params=None, headers=None, file=None):
    body = body if body is not None else {}
    params = params if params is not None else {}

    url = '{}{}'.format(SERVER_URL, path)
    if not headers:
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    if file:
        # Not supported in v2
        url = url.replace('v2', 'v1')
        try:
            file_entry = file['id']
            file_name = file['name']
            shutil.copy(demisto.getFilePath(file_entry)['path'], file_name)
            with open(file_name, 'rb') as f:
                files = {'file': f}
                res = requests.request(method, url, headers=headers, params=params, data=body, files=files,
                                       auth=(USERNAME, PASSWORD), verify=VERIFY_SSL)
            shutil.rmtree(demisto.getFilePath(file_entry)['name'], ignore_errors=True)
        except Exception as e:
            raise Exception('Failed to upload file - ' + str(e))
    else:
        res = requests.request(method, url, headers=headers, data=json.dumps(body) if body else {}, params=params,
                               auth=(USERNAME, PASSWORD), verify=VERIFY_SSL)

    try:
        obj = res.json()
    except Exception as e:
        if not res.content:
            return ''
        raise Exception('Error parsing reply - {} - {}'.format(res.content, str(e)))

    if 'error' in obj:
        message = obj.get('error', {}).get('message')
        details = obj.get('error', {}).get('detail')
        if message == 'No Record found':
            return {
                # Return an empty results array
                'result': []
            }
        raise Exception('ServiceNow Error: {}, details: {}'.format(message, details))

    if res.status_code < 200 or res.status_code >= 300:
        raise Exception('Got status code {} with url {} with body {} with headers {}'
                        .format(str(res.status_code), url, str(res.content), str(res.headers)))

    return obj


def get_table_name(ticket_type=None):
    if ticket_type:
        return ticket_type
    else:
        if PARAMS_TICKET_TYPE:
            return PARAMS_TICKET_TYPE
        else:
            return 'incident'


def create_ticket_context(data, ticket_type):
    context = {
        'ID': data.get('sys_id'),
        'Summary': data.get('short_description'),
        'Number': data.get('number'),
        'CreatedOn': data.get('sys_created_on'),
        'Active': data.get('active'),
        'AdditionalComments': data.get('comments'),
        'CloseCode': data.get('close_code'),
        'OpenedAt': data.get('opened_at')
    }

    # These fields refer to records in the database, the value is their system ID.
    if 'closed_by' in data:
        context['ResolvedBy'] = data['closed_by']['value'] if 'value' in data['closed_by'] else ''
    if 'opened_by' in data:
        context['OpenedBy'] = data['opened_by']['value'] if 'value' in data['opened_by'] else ''
        context['Creator'] = data['opened_by']['value'] if 'value' in data['opened_by'] else ''
    if 'assigned_to' in data:
        context['Assignee'] = data['assigned_to']['value'] if 'value' in data['assigned_to'] else ''

    # Try to map fields
    if 'priority' in data:
        # Backward compatibility
        if demisto.command() in DEPRECATED_COMMANDS:
            context['Priority'] = data['priority']
        else:
            context['Priority'] = TICKET_PRIORITY.get(data['priority'], data['priority'])
    if 'state' in data:
        mapped_state = data['state']
        # Backward compatibility
        if demisto.command() not in DEPRECATED_COMMANDS:
            if ticket_type in TICKET_STATES:
                mapped_state = TICKET_STATES[ticket_type].get(data['state'], mapped_state)
        context['State'] = mapped_state

    return createContext(context, removeNull=True)


def get_ticket_context(data, ticket_type):
    if not isinstance(data, list):
        return create_ticket_context(data, ticket_type)

    tickets = []
    for d in data:
        tickets.append(create_ticket_context(d, ticket_type))
    return tickets


def get_ticket_human_readable(tickets, ticket_type):
    if not isinstance(tickets, list):
        tickets = [tickets]

    result = []
    for ticket in tickets:

        hr = {
            'Number': ticket.get('number'),
            'System ID': ticket['sys_id'],
            'Created On': ticket.get('sys_created_on'),
            'Created By': ticket.get('sys_created_by'),
            'Active': ticket.get('active'),
            'Close Notes': ticket.get('close_notes'),
            'Close Code': ticket.get('close_code'),
            'Description': ticket.get('description'),
            'Opened At': ticket.get('opened_at'),
            'Due Date': ticket.get('due_date'),
            # This field refers to a record in the database, the value is its system ID.
            'Resolved By': ticket.get('closed_by', {}).get('value') if isinstance(ticket.get('closed_by'), dict)
            else ticket.get('closed_by'),
            'Resolved At': ticket.get('resolved_at'),
            'SLA Due': ticket.get('sla_due'),
            'Short Description': ticket.get('short_description'),
            'Additional Comments': ticket.get('comments')
        }

        # Try to map the fields
        if 'impact' in ticket:
            hr['Impact'] = TICKET_SEVERITY.get(ticket['impact'], ticket['impact'])
        if 'urgency' in ticket:
            hr['Urgency'] = TICKET_SEVERITY.get(ticket['urgency'], ticket['urgency'])
        if 'severity' in ticket:
            hr['Severity'] = TICKET_SEVERITY.get(ticket['severity'], ticket['severity'])
        if 'priority' in ticket:
            hr['Priority'] = TICKET_PRIORITY.get(ticket['priority'], ticket['priority'])
        if 'state' in ticket:
            mapped_state = ticket['state']
            if ticket_type in TICKET_STATES:
                mapped_state = TICKET_STATES[ticket_type].get(ticket['state'], mapped_state)
            hr['State'] = mapped_state
        result.append(hr)
    return result


def get_ticket_fields(template, ticket_type):
    # Inverse the keys and values of those dictionaries to map the arguments to their corresponding values in ServiceNow
    args = unicode_to_str_recur(demisto.args())
    inv_severity = {v: k for k, v in TICKET_SEVERITY.iteritems()}
    inv_priority = {v: k for k, v in TICKET_PRIORITY.iteritems()}
    states = TICKET_STATES.get(ticket_type)
    inv_states = {v: k for k, v in states.iteritems()} if states else {}

    body = {}
    for arg in SNOW_ARGS:
        input_arg = args.get(arg)
        if input_arg:
            if arg in ['impact', 'urgency', 'severity']:
                body[arg] = inv_severity.get(input_arg, input_arg)
            elif arg == 'priority':
                body[arg] = inv_priority.get(input_arg, input_arg)
            elif arg == 'state':
                body[arg] = inv_states.get(input_arg, input_arg)
            else:
                body[arg] = input_arg
        elif template and arg in template:
            body[arg] = template[arg]

    return body


def get_body(fields, custom_fields):
    body = {}

    if fields:
        for field in fields:
            body[field] = fields[field]

    if custom_fields:
        for field in custom_fields:
            # custom fields begin with "u_"
            if field.startswith('u_'):
                body[field] = custom_fields[field]
            else:
                body['u_' + field] = custom_fields[field]

    return body


def split_fields(fields):
    dic_fields = {}

    if fields:
        # As received by the command
        arr_fields = fields.split(';')

        for f in arr_fields:
            field = f.split('=')
            if len(field) > 1:
                dic_fields[field[0]] = field[1]

    return dic_fields


# Converts unicode elements of obj (incl. dictionary and list) to string recursively
def unicode_to_str_recur(obj):
    if isinstance(obj, dict):
        obj = {unicode_to_str_recur(k): unicode_to_str_recur(v) for k, v in obj.iteritems()}
    elif isinstance(obj, list):
        obj = map(unicode_to_str_recur, obj)
    elif isinstance(obj, unicode):
        obj = obj.encode('utf-8')
    return obj


# Converts to an str
def convert_to_str(obj):
    if isinstance(obj, unicode):
        return obj.encode('utf-8')
    try:
        return str(obj)
    except ValueError:
        return obj


''' FUNCTIONS '''


def get_template(name):
    query_params = {'sysparm_limit': 1, 'sysparm_query': 'name=' + name}

    ticket_type = 'sys_template'
    path = 'table/' + ticket_type
    res = send_request('GET', path, params=query_params)

    if len(res['result']) == 0:
        raise ValueError("Incorrect template name")

    template = res['result'][0]['template'].split('^')
    dic_template = {}

    for i in range(len(template) - 1):
        template_value = template[i].split('=')
        if len(template_value) > 1:
            dic_template[template_value[0]] = template_value[1]

    return dic_template


def get_ticket_command():
    args = unicode_to_str_recur(demisto.args())
    ticket_type = get_table_name(args.get('ticket_type'))
    ticket_id = args.get('id')
    number = args.get('number')
    get_attachments = args.get('get_attachments', 'false')

    res = get(ticket_type, ticket_id, number)
    if not res or 'result' not in res:
        return 'Cannot find ticket'

    if isinstance(res['result'], list):
        if len(res['result']) == 0:
            return 'Cannot find ticket'
        ticket = res['result'][0]
    else:
        ticket = res['result']

    entries = []  # type: List[Dict]

    if get_attachments.lower() != 'false':
        entries = get_ticket_attachment_entries(ticket['sys_id'])

    hr = get_ticket_human_readable(ticket, ticket_type)
    context = get_ticket_context(ticket, ticket_type)

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow ticket', hr, headers=headers, removeNull=True),
        'EntryContext': {
            'Ticket(val.ID===obj.ID)': context,
            'ServiceNow.Ticket(val.ID===obj.ID)': context
        }
    }

    entries.append(entry)

    return entries


def get_record_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = args['table_name']
    record_id = args['id']
    fields = args.get('fields')

    res = get(table_name, record_id)

    if not res or 'result' not in res:
        return 'Cannot find record'

    if isinstance(res['result'], list):
        if len(res['result']) == 0:
            return 'Cannot find record'
        record = res['result'][0]
    else:
        record = res['result']

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json']
    }

    if fields:
        fields = argToList(fields)
        if 'sys_id' not in fields:
            # ID is added by default
            fields.append('sys_id')
        # filter the record for the required fields
        record = dict(filter(lambda kv_pair: kv_pair[0] in fields, record.items()))
        for k, v in record.iteritems():
            if isinstance(v, dict):
                # For objects that refer to a record in the database, take their value(system ID).
                record[k] = v.get('value', record[k])
        record['ID'] = record.pop('sys_id')
        entry['ReadableContentsFormat'] = formats['markdown']
        entry['HumanReadable'] = tableToMarkdown('ServiceNow record', record, removeNull=True)
        entry['EntryContext'] = {
            'ServiceNow.Record(val.ID===obj.ID)': createContext(record)
        }
    else:
        mapped_record = {DEFAULT_RECORD_FIELDS[k]: record[k] for k in DEFAULT_RECORD_FIELDS if k in record}
        entry['ReadableContentsFormat'] = formats['markdown']
        entry['HumanReadable'] = tableToMarkdown('ServiceNow record' + record_id, mapped_record, removeNull=True)
        entry['EntryContext'] = {
            'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_record)
        }

    return entry


def get(table_name, record_id, number=None):
    path = None
    query_params = {}  # type: Dict
    if record_id:
        path = 'table/' + table_name + '/' + record_id
    elif number:
        path = 'table/' + table_name
        query_params = {
            'number': number
        }
    else:
        # Only in cases where the table is of type ticket
        raise ValueError('servicenow-get-ticket requires either ticket ID (sys_id) or ticket number')

    return send_request(path, 'get', params=query_params)


def get_ticket_attachments(ticket_id):
    path = 'attachment'
    query_params = {
        'sysparm_query': 'table_sys_id=' + ticket_id
    }

    return send_request(path, 'get', params=query_params)


def get_ticket_attachment_entries(ticket_id):
    entries = []
    links = []  # type: List[Tuple[str, str]]
    attachments_res = get_ticket_attachments(ticket_id)
    if 'result' in attachments_res and len(attachments_res['result']) > 0:
        attachments = attachments_res['result']
        links = [(attachment['download_link'], attachment['file_name']) for attachment in attachments]

    for link in links:
        file_res = requests.get(link[0], auth=(USERNAME, PASSWORD), verify=VERIFY_SSL)
        if file_res is not None:
            entries.append(fileResult(link[1], file_res.content))

    return entries


def update_ticket_command():
    args = unicode_to_str_recur(demisto.args())
    custom_fields = split_fields(args.get('custom_fields'))
    template = args.get('template')
    ticket_type = get_table_name(args.get('ticket_type'))
    ticket_id = args['id']

    if template:
        template = get_template(template)
    fields = get_ticket_fields(template, ticket_type)

    res = update(ticket_type, ticket_id, fields, custom_fields)

    if not res or 'result' not in res:
        return_error('Unable to retrieve response')

    hr = get_ticket_human_readable(res['result'], ticket_type)
    context = get_ticket_context(res['result'], ticket_type)

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow ticket updated successfully\nTicket type: ' + ticket_type,
                                         hr, removeNull=True),
        'EntryContext': {
            'ServiceNow.Ticket(val.ID===obj.ID)': context
        }
    }

    return entry


def update_record_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = args['table_name']
    record_id = args['id']
    fields = args.get('fields', {})
    custom_fields = args.get('custom_fields')

    if fields:
        fields = split_fields(fields)
    if custom_fields:
        custom_fields = split_fields(custom_fields)

    res = update(table_name, record_id, fields, custom_fields)

    if not res or 'result' not in res:
        return 'Could not retrieve record'

    result = res['result']

    mapped_record = {DEFAULT_RECORD_FIELDS[k]: result[k] for k in DEFAULT_RECORD_FIELDS if k in result}
    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow record updated successfully', mapped_record, removeNull=True),
        'EntryContext': {
            'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_record)
        }
    }

    return entry


def update(table_name, record_id, fields, custom_fields):
    body = get_body(fields, custom_fields)
    path = 'table/' + table_name + '/' + record_id

    return send_request(path, 'patch', body=body)


def create_ticket_command():
    args = unicode_to_str_recur(demisto.args())
    custom_fields = split_fields(args.get('custom_fields'))
    template = args.get('template')
    ticket_type = get_table_name(args.get('ticket_type'))

    if template:
        template = get_template(template)
    fields = get_ticket_fields(template, ticket_type)

    res = create(ticket_type, fields, custom_fields)

    if not res or 'result' not in res:
        return_error('Unable to retrieve response')

    hr = get_ticket_human_readable(res['result'], ticket_type)
    context = get_ticket_context(res['result'], ticket_type)

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow ticket created successfully', hr,
                                         headers=headers, removeNull=True),
        'EntryContext': {
            'Ticket(val.ID===obj.ID)': context,
            'ServiceNow.Ticket(val.ID===obj.ID)': context
        }
    }

    return entry


def create_record_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = args['table_name']
    fields = args.get('fields')
    custom_fields = args.get('custom_fields')

    if fields:
        fields = split_fields(fields)
    if custom_fields:
        custom_fields = split_fields(custom_fields)

    res = create(table_name, fields, custom_fields)

    if not res or 'result' not in res:
        return 'Could not retrieve record'

    result = res['result']

    mapped_record = {DEFAULT_RECORD_FIELDS[k]: result[k] for k in DEFAULT_RECORD_FIELDS if k in result}
    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow record created successfully', mapped_record, removeNull=True),
        'EntryContext': {
            'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_record)
        }
    }

    return entry


def create(table_name, fields, custom_fields):
    body = get_body(fields, custom_fields)
    path = 'table/' + table_name

    return send_request(path, 'post', body=body)


def delete_ticket_command():
    args = unicode_to_str_recur(demisto.args())
    ticket_id = args['id']
    ticket_type = get_table_name(args.get('ticket_type'))

    res = delete(ticket_type, ticket_id)

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Ticket with ID ' + ticket_id + ' was successfully deleted.'
    }

    return entry


def delete_record_command():
    args = unicode_to_str_recur(demisto.args())
    record_id = args['id']
    table_name = args.get('table_name')

    res = delete(table_name, record_id)

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Record with ID ' + record_id + ' was successfully deleted.'
    }

    return entry


def delete(table_name, record_id):
    path = 'table/' + table_name + '/' + record_id

    return send_request(path, 'delete')


def add_link_command():
    args = unicode_to_str_recur(demisto.args())
    ticket_id = args['id']
    key = 'comments' if args.get('post-as-comment', 'false').lower() == 'true' else 'work_notes'
    text = args.get('text', args['link'])
    link = '[code]<a class="web" target="_blank" href="' + args['link'] + '" >' + text + '</a>[/code]'
    ticket_type = get_table_name(args.get('ticket_type'))

    res = add_link(ticket_id, ticket_type, key, link)

    if not res or 'result' not in res:
        return_error('Unable to retrieve response')

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']

    hr = get_ticket_human_readable(res['result'], ticket_type)
    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Link successfully added to ServiceNow ticket', hr,
                                         headers=headers, removeNull=True)
    }

    return entry


def add_link(ticket_id, ticket_type, key, link):
    body = {}
    body[key] = link
    path = 'table/' + ticket_type + '/' + ticket_id

    return send_request(path, 'patch', body=body)


def add_comment_command():
    args = unicode_to_str_recur(demisto.args())
    ticket_id = args['id']
    key = 'comments' if args.get('post-as-comment', 'false').lower() == 'true' else 'work_notes'
    text = args['comment']
    ticket_type = get_table_name(args.get('ticket_type'))

    res = add_comment(ticket_id, ticket_type, key, text)

    if not res or 'result' not in res:
        return_error('Unable to retrieve response')

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']

    hr = get_ticket_human_readable(res['result'], ticket_type)
    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Comment successfully added to ServiceNow ticket', hr,
                                         headers=headers, removeNull=True)
    }

    return entry


def add_comment(ticket_id, ticket_type, key, text):
    body = {}
    body[key] = text
    path = 'table/' + ticket_type + '/' + ticket_id

    return send_request(path, 'patch', body=body)


def get_ticket_notes_command():
    args = unicode_to_str_recur(demisto.args())
    ticket_id = args['id']
    limit = args.get('limit')
    offset = args.get('offset')

    comments_query = 'element_id=' + ticket_id + '^element=comments^ORelement=work_notes'

    res = query('sys_journal_field', limit, offset, comments_query)

    if not res or 'result' not in res:
        return 'No results found'

    headers = ['Value', 'CreatedOn', 'CreatedBy', 'Type']

    mapped_notes = [{
        'Value': n.get('value'),
        'CreatedOn': n.get('sys_created_on'),
        'CreatedBy': n.get('sys_created_by'),
        'Type': 'Work Note' if n.get('element', '') == 'work_notes' else 'Comment'
    } for n in res['result']]

    if not mapped_notes:
        return 'No results found'

    ticket = {
        'ID': ticket_id,
        'Note': mapped_notes
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow notes for ticket ' + ticket_id, mapped_notes, headers=headers,
                                         headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': {
            'ServiceNow.Ticket(val.ID===obj.ID)': createContext(ticket, removeNull=True)
        }
    }

    return entry


def query_tickets_command():
    args = unicode_to_str_recur(demisto.args())
    sysparm_limit = args.get('limit', DEFAULTS['limit'])
    sysparm_query = args.get('query')
    sysparm_offset = args.get('offset', DEFAULTS['offset'])

    if not sysparm_query:
        # backward compatibility
        sysparm_query = args.get('sysparm_query')
    ticket_type = get_table_name(args.get('ticket_type'))

    res = query(ticket_type, sysparm_limit, sysparm_offset, sysparm_query)

    if not res or 'result' not in res or len(res['result']) == 0:
        return 'No results found'

    hr = get_ticket_human_readable(res['result'], ticket_type)
    context = get_ticket_context(res['result'], ticket_type)

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow tickets', hr, headers=headers, removeNull=True),
        'EntryContext': {
            'Ticket(val.ID===obj.ID)': context,
            'ServiceNow.Ticket(val.ID===obj.ID)': context
        }
    }

    return entry


def query_table_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = args['table_name']
    sysparm_limit = args.get('limit', DEFAULTS['limit'])
    sysparm_query = args.get('query')
    sysparm_offset = args.get('offset', DEFAULTS['offset'])
    fields = args.get('fields')

    res = query(table_name, sysparm_limit, sysparm_offset, sysparm_query)

    if not res or 'result' not in res or len(res['result']) == 0:
        return 'No results found'

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json']
    }

    result = res['result']

    if fields:
        fields = argToList(fields)
        if 'sys_id' not in fields:
            # ID is added by default
            fields.append('sys_id')
        # Filter the records according to the given fields
        records = [dict(filter(lambda kv_pair: kv_pair[0] in fields, r.iteritems())) for r in res['result']]
        for r in records:
            r['ID'] = r.pop('sys_id')
            for k, v in r.iteritems():
                if isinstance(v, dict):
                    # For objects that refer to a record in the database, take their value (system ID).
                    r[k] = v.get('value', v)
        entry['ReadableContentsFormat'] = formats['markdown']
        entry['HumanReadable'] = tableToMarkdown('ServiceNow records', records, removeNull=True)
        entry['EntryContext'] = {
            'ServiceNow.Record(val.ID===obj.ID)': createContext(records)
        }
    else:
        mapped_records = [{DEFAULT_RECORD_FIELDS[k]: r[k] for k in DEFAULT_RECORD_FIELDS if k in r} for r in result]
        entry['ReadableContentsFormat'] = formats['markdown']
        entry['HumanReadable'] = tableToMarkdown('ServiceNow records', mapped_records, removeNull=True)
        entry['EntryContext'] = {
            'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_records)
        }

    return entry


def query(table_name, sysparm_limit, sysparm_offset, sysparm_query):
    query_params = {}
    query_params['sysparm_limit'] = sysparm_limit
    query_params['sysparm_offset'] = sysparm_offset
    if sysparm_query:
        query_params['sysparm_query'] = sysparm_query

    path = 'table/' + table_name

    return send_request(path, 'get', params=query_params)


def upload_file_command():
    args = unicode_to_str_recur(demisto.args())
    ticket_type = get_table_name(args.get('ticket_type'))
    ticket_id = args['id']
    file_id = args['file_id']
    file_name = args.get('file_name', demisto.dt(demisto.context(), "File(val.EntryID=='" + file_id + "').Name"))

    # in case of info file
    if not file_name:
        file_name = demisto.dt(demisto.context(), "InfoFile(val.EntryID=='" + file_id + "').Name")

    if not file_name:
        return_error('Could not find the file')

    file_name = file_name[0] if isinstance(file_name, list) else file_name

    res = upload_file(ticket_id, file_id, file_name, ticket_type)

    if not res or 'result' not in res or not res['result']:
        return_error('Unable to retrieve response')

    hr = {
        'Filename': res['result'].get('file_name'),
        'Download link': res['result'].get('download_link'),
        'System ID': res['result'].get('sys_id')
    }

    context = {
        'ID': ticket_id,
        'File': {}
    }
    context['File']['Filename'] = res['result'].get('file_name')
    context['File']['Link'] = res['result'].get('download_link')
    context['File']['SystemID'] = res['result'].get('sys_id')

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('File uploaded successfully', hr),
        'EntryContext': {
            'ServiceNow.Ticket(val.ID===obj.ID)': context,
            'Ticket(val.ID===obj.ID)': context
        }
    }

    return entry


def upload_file(ticket_id, file_id, file_name, ticket_type):
    headers = {
        'Accept': 'application/json'
    }

    body = {
        'table_name': ticket_type,
        'table_sys_id': ticket_id,
        'file_name': file_name
    }

    path = 'attachment/upload'

    return send_request(path, 'post', headers=headers, body=body, file={'id': file_id, 'name': file_name})


# Deprecated
def get_computer_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = 'cmdb_ci_computer'
    computer_name = args['computerName']

    res = query(table_name, None, 0, 'u_code=' + computer_name)

    if not res or 'result' not in res:
        return 'Cannot find computer'
    elif isinstance(res['result'], list):
        if len(res['result']) == 0:
            return 'Cannot find computer'
        computer = res['result'][0]
    else:
        computer = res['result']

    if computer['u_code'] != computer_name:
        return 'Computer not found'

    hr = {
        'ID': computer['sys_id'],
        'u_code (computer name)': computer['u_code'],
        'Support group': computer['support_group'],
        'Operating System': computer['os'],
        'Comments': computer['comments']
    }

    ec = createContext(computer, removeNull=True)
    if 'support_group' in computer:
        ec['support_group'] = computer['support_group']['value'] if 'value' in computer['support_group'] else ''

    entry = {
        'Type': entryTypes['note'],
        'Contents': computer,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow Computer', hr),
        'EntryContext': {
            'ServiceNowComputer(val.sys_id==obj.sys_id)': ec,
        }
    }

    return entry


def query_computers_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = 'cmdb_ci_computer'
    computer_id = args.get('computer_id')
    computer_name = args.get('computer_name')
    asset_tag = args.get('asset_tag')
    computer_query = args.get('query', {})
    offset = args.get('offset', DEFAULTS['offset'])
    limit = args.get('limit', DEFAULTS['limit'])

    if computer_id:
        res = get(table_name, computer_id)
    else:
        if computer_name:
            computer_query = 'name=' + computer_name
        elif asset_tag:
            computer_query = 'asset_tag=' + asset_tag

        res = query(table_name, limit, offset, computer_query)

    if not res or 'result' not in res:
        return 'No computers found'

    computers = res['result']
    if not isinstance(computers, list):
        computers = [computers]

    if len(computers) == 0:
        return 'No computers found'

    headers = ['ID', 'AssetTag', 'Name', 'DisplayName', 'SupportGroup', 'OperatingSystem', 'Company', 'AssignedTo',
               'State', 'Cost', 'Comments']

    mapped_computers = [{
        'ID': computer.get('sys_id'),
        'AssetTag': computer.get('asset_tag'),
        'Name': computer.get('name'),
        'DisplayName': '{} - {}'.format(computer.get('asset_tag', ''), computer.get('name', '')),
        'SupportGroup': computer.get('support_group'),
        'OperatingSystem': computer.get('os'),
        'Company': computer.get('company', {}).get('value')
        if isinstance(computer.get('company'), dict) else computer.get('company'),
        'AssignedTo': computer.get('assigned_to', {}).get('value')
        if isinstance(computer.get('assigned_to'), dict) else computer.get('assigned_to'),
        'State': COMPUTER_STATUS.get(computer.get('install_status', ''), computer.get('install_status')),
        'Cost': '{} {}'.format(computer.get('cost', ''), computer.get('cost_cc', '')).rstrip(),
        'Comments': computer.get('comments')
    } for computer in computers]

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow Computers', mapped_computers, headers=headers,
                                         removeNull=True, headerTransform=pascalToSpace),
        'EntryContext': {
            'ServiceNow.Computer(val.ID===obj.ID)': createContext(mapped_computers, removeNull=True),
        }
    }

    return entry


def query_groups_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = 'sys_user_group'
    group_id = args.get('group_id')
    group_name = args.get('group_name')
    group_query = args.get('query', {})
    offset = args.get('offset', DEFAULTS['offset'])
    limit = args.get('limit', DEFAULTS['limit'])

    if group_id:
        res = get(table_name, group_id)
    else:
        if group_name:
            group_query = 'name=' + group_name
        res = query(table_name, limit, offset, group_query)

    if not res or 'result' not in res:
        return 'No groups found'

    groups = res['result']
    if not isinstance(groups, list):
        groups = [groups]

    if len(groups) == 0:
        return 'No groups found'

    headers = ['ID', 'Description', 'Name', 'Active', 'Manager', 'Updated']

    mapped_groups = [{
        'ID': group.get('sys_id'),
        'Description': group.get('description'),
        'Name': group.get('name'),
        'Active': group.get('active'),
        'Manager': group.get('manager', {}).get('value')
        if isinstance(group.get('manager'), dict) else group.get('manager'),
        'Updated': group.get('sys_updated_on'),
    } for group in groups]

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow Groups', mapped_groups, headers=headers,
                                         removeNull=True, headerTransform=pascalToSpace),
        'EntryContext': {
            'ServiceNow.Group(val.ID===obj.ID)': createContext(mapped_groups, removeNull=True),
        }
    }

    return entry


def query_users_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = 'sys_user'
    user_id = args.get('user_id')
    user_name = args.get('user_name')
    user_query = args.get('query', {})
    offset = args.get('offset', DEFAULTS['offset'])
    limit = args.get('limit', DEFAULTS['limit'])

    if user_id:
        res = get(table_name, user_id)
    else:
        if user_name:
            user_query = 'user_name=' + user_name
        res = query(table_name, limit, offset, user_query)

    if not res or 'result' not in res:
        return 'No users found'
    res = unicode_to_str_recur(res)

    users = res['result']
    if not isinstance(users, list):
        users = [users]

    if len(users) == 0:
        return 'No users found'

    headers = ['ID', 'Name', 'UserName', 'Email', 'Created', 'Updated']

    mapped_users = [{
        'ID': user.get('sys_id'),
        'Name': '{} {}'.format(user.get('first_name', ''), user.get('last_name', '')).rstrip(),
        'UserName': user.get('user_name'),
        'Email': user.get('email'),
        'Created': user.get('sys_created_on'),
        'Updated': user.get('sys_updated_on'),
    } for user in users]
    mapped_users = unicode_to_str_recur(mapped_users)
    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow Users', mapped_users, headers=headers, removeNull=True,
                                         headerTransform=pascalToSpace),
        'EntryContext': {
            'ServiceNow.User(val.ID===obj.ID)': createContext(mapped_users, removeNull=True),
        }
    }

    return entry


# Deprecated
def get_groups_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = 'sys_user_group'
    group_name = args['name']
    res = query(table_name, None, 0, 'name=' + group_name)

    if not res or 'result' not in res:
        return 'No groups found'

    hr_groups = []
    context_groups = []

    for group in res['result']:
        if group['name'] == group_name:
            hr_groups.append({
                'ID': group['sys_id'],
                'Name': group['name'],
                'Description': group['description'],
                'Email': group['email'],
                'Active': group['active'],
                'Manager': ['manager']
            })
            context_groups.append({
                'GroupId': group['sys_id'],
                'GroupName': group['name']
            })

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow Group', hr_groups),
        'EntryContext': {
            'ServiceNowGroups(val.GroupId==obj.GroupId)': context_groups,
        }
    }

    return entry


def list_table_fields_command():
    args = unicode_to_str_recur(demisto.args())
    table_name = args['table_name']

    res = get_table_fields(table_name)

    if not res or 'result' not in res:
        return 'Cannot find table'

    if len(res['result']) == 0:
        return 'Table contains no records'

    fields = [{'Name': k} for k, v in res['result'][0].iteritems()]

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow Table fields - ' + table_name, fields),
        'EntryContext': {
            'ServiceNow.Field': createContext(fields),
        }
    }

    return entry


def get_table_fields(table_name):
    # Get one record
    path = 'table/' + table_name + '?sysparm_limit=1'
    res = send_request(path, 'GET')

    return res


def get_table_name_command():
    args = unicode_to_str_recur(demisto.args())
    label = args['label']
    offset = args.get('offset', DEFAULTS['offset'])
    limit = args.get('limit', DEFAULTS['limit'])

    table_query = 'label=' + label

    res = query('sys_db_object', limit, offset, table_query)

    if not res or 'result' not in res:
        return 'Cannot find table'

    tables = res['result']

    if len(tables) == 0:
        return 'Cannot find table'

    headers = ['ID', 'Name', 'SystemName']

    mapped_tables = [{
        'ID': table.get('sys_id'),
        'Name': table.get('name'),
        'SystemName': table.get('sys_name')
    } for table in tables]

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow Tables for label - ' + label, mapped_tables,
                                         headers=headers, headerTransform=pascalToSpace),
        'EntryContext': {
            'ServiceNow.Table(val.ID===obj.ID)': createContext(mapped_tables),
        }
    }

    return entry


def fetch_incidents():
    query_params = {}
    incidents = []
    if FETCH_TIME:
        fetch_time = FETCH_TIME
    else:
        fetch_time = DEFAULTS['fetch_time']

    last_run = demisto.getLastRun()
    if 'time' not in last_run:
        snow_time, _ = parse_date_range(fetch_time, '%Y-%m-%d %H:%M:%S')
    else:
        snow_time = last_run['time']

    query = ''
    if SYSPARM_QUERY:
        query += SYSPARM_QUERY + '^'
    query += 'ORDERBY{0}^{0}>{1}'.format(TIMESTAMP_FIELD, snow_time)

    if query:
        query_params['sysparm_query'] = query

    query_params['sysparm_limit'] = SYSPARM_LIMIT

    path = 'table/' + TICKET_TYPE
    res = send_request(path, 'get', params=query_params)

    count = 0
    parsed_snow_time = datetime.strptime(snow_time, '%Y-%m-%d %H:%M:%S')

    for result in res.get('result', []):
        labels = []

        if TIMESTAMP_FIELD not in result:
            raise ValueError("The timestamp field [{}]"
                             " does not exist in the ticket".format(TIMESTAMP_FIELD))

        if count > SYSPARM_LIMIT:
            break

        try:
            if datetime.strptime(result[TIMESTAMP_FIELD], '%Y-%m-%d %H:%M:%S') < parsed_snow_time:
                continue
        except Exception:
            pass

        for k, v in result.iteritems():
            if isinstance(v, basestring):
                labels.append({
                    'type': k,
                    'value': v
                })
            else:
                labels.append({
                    'type': k,
                    'value': json.dumps(v)
                })

        severity = SEVERITY_MAP.get(result.get('severity', ''), 0)

        file_names = []
        if GET_ATTACHMENTS:
            file_entries = get_ticket_attachment_entries(result['sys_id'])
            for file_result in file_entries:
                if file_result['Type'] == entryTypes['error']:
                    raise Exception('Error getting attachment: ' + str(file_result['Contents']))
                file_names.append({
                    'path': file_result['FileID'],
                    'name': file_result['File']
                })

        incidents.append({
            'name': 'ServiceNow Incident ' + result.get('number'),
            'labels': labels,
            'details': json.dumps(result),
            'severity': severity,
            'attachment': file_names,
            'rawJSON': json.dumps(result)
        })

        count += 1
        snow_time = result[TIMESTAMP_FIELD]

    demisto.incidents(incidents)
    demisto.setLastRun({'time': snow_time})


def test_module():
    # Validate fetch_time parameter is valid (if not, parse_date_range will raise the error message)
    parse_date_range(FETCH_TIME, '%Y-%m-%d %H:%M:%S')

    path = 'table/' + TICKET_TYPE + '?sysparm_limit=1'
    res = send_request(path, 'GET')
    if 'result' not in res:
        return_error('ServiceNow error: ' + str(res))
    ticket = res['result']
    if ticket and demisto.params().get('isFetch'):
        if isinstance(ticket, list):
            ticket = ticket[0]
        if TIMESTAMP_FIELD not in ticket:
            raise ValueError("The timestamp field [{}]"
                             " does not exist in the ticket".format(TIMESTAMP_FIELD))


LOG('Executing command ' + demisto.command())
raise_exception = False
try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'fetch-incidents':
        raise_exception = True
        fetch_incidents()
    elif demisto.command() == 'servicenow-get' or \
            demisto.command() == 'servicenow-incident-update' or demisto.command() == 'servicenow-get-ticket':
        demisto.results(get_ticket_command())
    elif demisto.command() == 'servicenow-update' or \
            demisto.command() == 'servicenow-incident-update' or demisto.command() == 'servicenow-update-ticket':
        demisto.results(update_ticket_command())
    elif demisto.command() == 'servicenow-create' or \
            demisto.command() == 'servicenow-incident-create' or demisto.command() == 'servicenow-create-ticket':
        demisto.results(create_ticket_command())
    elif demisto.command() == 'servicenow-delete-ticket':
        demisto.results(delete_ticket_command())
    elif demisto.command() == 'servicenow-add-link' or demisto.command() == 'servicenow-incident-add-link':
        demisto.results(add_link_command())
    elif demisto.command() == 'servicenow-add-comment' or demisto.command() == 'servicenow-incident-add-comment':
        demisto.results(add_comment_command())
    elif demisto.command() == 'servicenow-query' or \
            demisto.command() == 'servicenow-incidents-query' or demisto.command() == 'servicenow-query-tickets':
        demisto.results(query_tickets_command())
    elif demisto.command() == 'servicenow-upload-file' or demisto.command() == 'servicenow-incident-upload-file':
        demisto.results(upload_file_command())
    elif demisto.command() == 'servicenow-query-table':
        demisto.results(query_table_command())
    elif demisto.command() == 'servicenow-get-computer':
        demisto.results(get_computer_command())
    elif demisto.command() == 'servicenow-query-computers':
        demisto.results(query_computers_command())
    elif demisto.command() == 'servicenow-query-groups':
        demisto.results(query_groups_command())
    elif demisto.command() == 'servicenow-query-users':
        demisto.results(query_users_command())
    elif demisto.command() == 'servicenow-get-groups':
        demisto.results(get_groups_command())
    elif demisto.command() == 'servicenow-get-record':
        demisto.results(get_record_command())
    elif demisto.command() == 'servicenow-update-record':
        demisto.results(update_record_command())
    elif demisto.command() == 'servicenow-create-record':
        demisto.results(create_record_command())
    elif demisto.command() == 'servicenow-delete-record':
        demisto.results(delete_record_command())
    if demisto.command() == 'servicenow-list-table-fields':
        demisto.results(list_table_fields_command())
    if demisto.command() == 'servicenow-get-table-name':
        demisto.results(get_table_name_command())
    if demisto.command() == 'servicenow-get-ticket-notes':
        demisto.results(get_ticket_notes_command())
except Exception as e:
    LOG(e)
    LOG.print_log()
    if not raise_exception:
        return_error(str(e))
    else:
        raise
