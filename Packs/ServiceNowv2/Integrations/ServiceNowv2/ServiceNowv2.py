import shutil
from typing import List, Tuple, Dict, Callable, Any

from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

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

TICKET_PRIORITY = {
    '1': '1 - Critical',
    '2': '2 - High',
    '3': '3 - Moderate',
    '4': '4 - Low',
    '5': '5 - Planning'
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


def get_server_url(server_url: str) -> str:
    url = server_url
    url = re.sub('/[/]+$/', '', url)
    url = re.sub('/$', '', url)
    return url


def create_ticket_context(data: dict) -> dict:
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
        context['Priority'] = TICKET_PRIORITY.get(data['priority'], data['priority'])
    if 'state' in data:
        context['State'] = data['state']

    return createContext(context, removeNull=True)


def get_ticket_context(data) -> dict:
    if not isinstance(data, list):
        return create_ticket_context(data)

    tickets = []
    for d in data:
        tickets.append(create_ticket_context(d))
    return tickets


def get_ticket_human_readable(tickets, ticket_type: str) -> list:
    if not isinstance(tickets, list):
        tickets = [tickets]

    ticket_severity = {
        '1': '1 - High',
        '2': '2 - Medium',
        '3': '3 - Low'
    }

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
            hr['Impact'] = ticket_severity.get(ticket['impact'], ticket['impact'])
        if 'urgency' in ticket:
            hr['Urgency'] = ticket_severity.get(ticket['urgency'], ticket['urgency'])
        if 'severity' in ticket:
            hr['Severity'] = ticket_severity.get(ticket['severity'], ticket['severity'])
        if 'priority' in ticket:
            hr['Priority'] = TICKET_PRIORITY.get(ticket['priority'], ticket['priority'])
        if 'state' in ticket:
            mapped_state = ticket['state']
            if ticket_type in TICKET_STATES:
                mapped_state = TICKET_STATES[ticket_type].get(ticket['state'], mapped_state)
            hr['State'] = mapped_state
        result.append(hr)
    return result


def get_ticket_fields(args: dict, template_name: dict, ticket_type: str) -> dict:
    """Inverse the keys and values of those dictionaries
    to map the arguments to their corresponding values in ServiceNow

    Args:
        args: Demisto args
        template_name: ticket template name
        ticket_type: ticket type

    Returns:
        ticket fields
    """
    ticket_severity = {
        '1': '1 - High',
        '2': '2 - Medium',
        '3': '3 - Low'
    }

    inv_severity = {v: k for k, v in ticket_severity.items()}
    inv_priority = {v: k for k, v in TICKET_PRIORITY.items()}
    states = TICKET_STATES.get(ticket_type)
    inv_states = {v: k for k, v in states.items()} if states else {}

    ticket_fields = {}
    for arg in SNOW_ARGS:
        input_arg = args.get(arg)
        if input_arg:
            if arg in ['impact', 'urgency', 'severity']:
                ticket_fields[arg] = inv_severity.get(input_arg, input_arg)
            elif arg == 'priority':
                ticket_fields[arg] = inv_priority.get(input_arg, input_arg)
            elif arg == 'state':
                ticket_fields[arg] = inv_states.get(input_arg, input_arg)
            else:
                ticket_fields[arg] = input_arg
        elif template_name and arg in template_name:
            ticket_fields[arg] = template_name[arg]

    return ticket_fields


def get_body(fields: dict, custom_fields: dict) -> dict:
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


def split_fields(fields: str) -> dict:
    dic_fields = {}

    if fields:
        # As received by the command
        arr_fields = fields.split(';')

        for f in arr_fields:
            field = f.split('=')
            if len(field) > 1:
                dic_fields[field[0]] = field[1]

    return dic_fields


class Client(BaseClient):
    """
    Client to use in the ServiceNow integration. Overrides BaseClient.
    """

    def __init__(self, server_url: str, username: str, password: str, verify: bool, proxy: bool, fetch_time: str,
                 sysparm_query: str, sysparm_limit: int, timestamp_field: str, ticket_type: str, get_attachments: bool):
        self._base_url = server_url
        self._verify = verify
        self._username = username
        self._password = password
        self._proxies = handle_proxy() if proxy else None
        self.fetch_time = fetch_time
        self.timestamp_field = timestamp_field
        self.ticket_type = ticket_type
        self.get_attachments = get_attachments
        self.sys_param_query = sysparm_query
        self.sys_param_limit = sysparm_limit
        self.sys_param_offset = 10

    def send_request(self, path: str, method: str = 'get', body: dict = None, params: dict = None,
                     headers: dict = None, file=None):
        """
        Generic request to ServiceNow.
        """
        body = body if body is not None else {}
        params = params if params is not None else {}

        url = f'{self._base_url}{path}'
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
                                           auth=(self._username, self._password), verify=self._verify)
                shutil.rmtree(demisto.getFilePath(file_entry)['name'], ignore_errors=True)
            except Exception as e:
                raise Exception('Failed to upload file - ' + str(e))
        else:
            res = requests.request(method, url, headers=headers, data=json.dumps(body) if body else {}, params=params,
                                   auth=(self._username, self._password), verify=self._verify)

        try:
            obj = res.json()
        except Exception as err:
            if not res.content:
                return ''
            raise Exception(f'Error parsing reply - {str(res.content)} - {str(err)}')

        if 'error' in obj:
            message = obj.get('error', {}).get('message')
            details = obj.get('error', {}).get('detail')
            if message == 'No Record found':
                return {
                    # Return an empty results array
                    'result': []
                }
            raise Exception(f'ServiceNow Error: {message}, details: {details}')

        if res.status_code < 200 or res.status_code >= 300:
            raise Exception(f'Got status code {str(res.status_code)} with url {url} with body {str(res.content)}'
                            f' with headers {str(res.headers)}')

        return obj

    def get_table_name(self, ticket_type: str = '') -> str:
        """Get the relevant table name from th client.

        Args:
            ticket_type: ticket type

        Returns:
            the ticket_type if given or the client ticket type
        """
        if ticket_type:
            return ticket_type
        return self.ticket_type

    def get_template(self, template_name: str) -> dict:
        """Get a ticket by sending a GET request.
        Args:
            template_name: ticket template name

        Returns:
            the ticket template
        """
        query_params = {'sysparm_limit': 1, 'sysparm_query': f'name={template_name}'}

        result = self.send_request('GET', 'table/sys_template', params=query_params)

        if len(result['result']) == 0:
            raise ValueError("Incorrect template name.")

        template = result['result'][0]['template'].split('^')
        dic_template = {}

        for i in range(len(template) - 1):
            template_value = template[i].split('=')
            if len(template_value) > 1:
                dic_template[template_value[0]] = template_value[1]

        return dic_template

    def get_ticket_attachments(self, ticket_id: str) -> dict:
        """Get ticket attachments by sending a GET request.

        Args:
            ticket_id: ticket id

        Returns:
            Response from API.
        """
        return self.send_request('attachment', 'GET', params={'sysparm_query': f'table_sys_id={ticket_id}'})

    def get_ticket_attachment_entries(self, ticket_id: str) -> list:
        """Get ticket attachments, including file attachments
        by sending a GET request and using the get_ticket_attachments class function.

        Args:
            ticket_id: ticket id

        Returns:
            Array of attachments entries.
        """
        entries = []
        links = []  # type: List[Tuple[str, str]]
        attachments_res = self.get_ticket_attachments(ticket_id)
        if 'result' in attachments_res and len(attachments_res['result']) > 0:
            attachments = attachments_res['result']
            links = [(attachment['download_link'], attachment['file_name']) for attachment in attachments]

        for link in links:
            file_res = requests.get(link[0], auth=(self._username, self._password), verify=self._verify)
            if file_res is not None:
                entries.append(fileResult(link[1], file_res.content))

        return entries

    def get(self, table_name: str, record_id: str, custom_fields: str = '', number: str = None) -> dict:
        """Get a ticket by sending a GET request.

        Args:
            table_name: the table name
            record_id: the record ID
            custom_fields: custom fields of the record to query
            number: record number

        Returns:
            Response from API.
        """
        query_params = {}  # type: Dict
        if record_id:
            path = 'table/' + table_name + '/' + record_id
        elif number:
            path = 'table/' + table_name
            query_params = {
                'number': number
            }
        elif custom_fields:
            path = 'table/' + table_name
            custom_fields_dict = {
                k: v.strip('"') for k, v in [i.split("=", 1) for i in custom_fields.split(',')]
            }
            query_params = custom_fields_dict
        else:
            # Only in cases where the table is of type ticket
            raise ValueError('servicenow-get-ticket requires either ticket ID (sys_id) or ticket number.')

        return self.send_request(path, 'GET', params=query_params)

    def update(self, table_name: str, record_id: str, fields: dict, custom_fields: dict) -> dict:
        """Updates a ticket or a record by sending a PATCH request.

        Args:
            table_name: table name
            record_id: record id
            fields: fields to update
            custom_fields: custom_fields to update

        Returns:
            Response from API.
        """
        body = get_body(fields, custom_fields)
        return self.send_request(f'table/{table_name}/{record_id}', 'PATCH', body=body)

    def create(self, table_name: str, fields: dict, custom_fields: dict) -> dict:
        """Creates a ticket or a record by sending a POST request.

        Args:
        table_name: table name
        record_id: record id
        fields: fields to update
        custom_fields: custom_fields to update

        Returns:
            Response from API.
        """
        body = get_body(fields, custom_fields)
        return self.send_request(f'table/{table_name}', 'POST', body=body)

    def delete(self, table_name: str, record_id: str) -> dict:
        """Deletes a ticket or a record by sending a DELETE request.

        Args:
        table_name: table name
        record_id: record id

        Returns:
            Response from API.
        """
        return self.send_request(f'table/{table_name}/{record_id}', 'DELETE')

    def add_link(self, ticket_id: str, ticket_type: str, key: str, link: str) -> dict:
        """Adds a link to a ticket by sending a PATCH request.

        Args:
        ticket_id: ticket ID
        ticket_type: ticket type
        key: link key
        link: link str

        Returns:
            Response from API.
        """
        return self.send_request(f'table/{ticket_type}/{ticket_id}', 'PATCH', body={key: link})

    def add_comment(self, ticket_id: str, ticket_type: str, key: str, text: str) -> dict:
        """Adds a comment to a ticket by sending a PATCH request.

        Args:
        ticket_id: ticket ID
        ticket_type: ticket type
        key: link key
        link: link str

        Returns:
            Response from API.
        """
        return self.send_request(f'table/{ticket_type}/{ticket_id}', 'PATCH', body={key: text})

    def upload_file(self, ticket_id: str, file_id: str, file_name: str, ticket_type: str) -> dict:
        """Adds a file to a ticket by sending a POST request.

        Args:
        ticket_id: ticket ID
        file_id: file ID
        file_name: file name
        ticket_type: ticket type

        Returns:
            Response from API.
        """
        body = {
            'table_name': ticket_type,
            'table_sys_id': ticket_id,
            'file_name': file_name
        }

        return self.send_request('attachment/upload', 'POST', headers={'Accept': 'application/json'},
                                 body=body, file={'id': file_id, 'name': file_name})

    def query(self, table_name: str, sys_param_limit: str, sys_param_offset: str, sys_param_query: str) -> dict:
        """Query tickets by sending a PATCH request.

        Args:
        table_name: table name
        sys_param_limit: limit the number of results
        sys_param_offset: offset the results
        sys_param_query: the query

        Returns:
            Response from API.
        """
        query_params = {'sysparm_limit': sys_param_limit, 'sysparm_offset': sys_param_offset}
        if sys_param_query:
            query_params['sysparm_query'] = sys_param_query
        return self.send_request(f'table/{table_name}', 'GET', params=query_params)

    def get_table_fields(self, table_name: str) -> dict:
        """Get table fields by sending a GET request.

        Args:
        table_name: table name

        Returns:
            Response from API.
        """
        return self.send_request(f'table/{table_name}?sysparm_limit=1', 'GET')


def get_ticket_command(client: Client, args: dict):
    """Get a ticket.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))
    ticket_id = str(args.get('id', ''))
    number = str(args.get('number', ''))
    get_attachments = args.get('get_attachments', 'false')
    custom_fields = str(args.get('custom_fields', ''))

    result = client.get(ticket_type, ticket_id, custom_fields, number)
    if not result or 'result' not in result:
        return 'Ticket was not found.', {}, {}

    if isinstance(result['result'], list):
        if len(result['result']) == 0:
            return 'Ticket was not found.', {}, {}
        ticket = result['result'][0]
    else:
        ticket = result['result']

    entries = []  # type: List[Dict]

    if get_attachments.lower() != 'false':
        entries = client.get_ticket_attachment_entries(ticket.get('sys_id'))

    hr = get_ticket_human_readable(ticket, ticket_type)
    context = get_ticket_context(ticket)

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']

    entry = {
        'Type': entryTypes['note'],
        'Contents': result,
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


def update_ticket_command(client: Client, args: dict) -> Tuple[Any, Dict, Dict]:
    """Update a ticket.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    custom_fields = split_fields(str(args.get('custom_fields', '')))
    template_name = str(args.get('template', ''))
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))
    ticket_id = str(args.get('id', ''))

    if template_name:
        template_dict = client.get_template(template_name)
    fields = get_ticket_fields(args, template_dict, ticket_type)

    result = client.update(ticket_type, ticket_id, fields, custom_fields)

    if not result or 'result' not in result:
        raise Exception('Unable to retrieve response.')

    hr = get_ticket_human_readable(result['result'], ticket_type)
    human_readable = tableToMarkdown(f'ServiceNow ticket updated successfully\nTicket type: {ticket_type}',
                                     t=hr, removeNull=True)
    entry_context = get_ticket_context(result['result'])

    return human_readable, entry_context, result


def create_ticket_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Create a ticket.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    custom_fields = split_fields(str(args.get('custom_fields', '')))
    template = args.get('template')
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))

    if template:
        template = client.get_template(template)
    fields = get_ticket_fields(args, template, ticket_type)

    result = client.create(ticket_type, fields, custom_fields)

    if not result or 'result' not in result:
        raise Exception('Unable to retrieve response.')

    hr = get_ticket_human_readable(result['result'], ticket_type)
    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On',
               'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']
    human_readable = tableToMarkdown('ServiceNow ticket was created successfully.', t=hr,
                                     headers=headers, removeNull=True)
    entry_context = get_ticket_context(result['result'])

    return human_readable, entry_context, result


def delete_ticket_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Delete a ticket.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    ticket_id = str(args.get('id', ''))
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))

    result = client.delete(ticket_type, ticket_id)

    return f'Ticket with ID {ticket_id} was successfully deleted.', {}, result


def get_record_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Get a record.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    table_name = str(args.get('table_name', ''))
    record_id = str(args.get('id', ''))
    fields = str(args.get('fields', ''))

    result = client.get(table_name, record_id)

    if not result or 'result' not in result:
        return f'ServiceNow record with ID {record_id} was not found.', {}, {}

    if isinstance(result['result'], list):
        if len(result['result']) == 0:
            return f'ServiceNow record with ID {record_id} was not found.', {}, result
        record = result['result'][0]
    else:
        record = result['result']

    if fields:
        list_fields = argToList(fields)
        if 'sys_id' not in list_fields:
            # ID is added by default
            list_fields.append('sys_id')
        # filter the record for the required fields
        record = dict([kv_pair for kv_pair in list(record.items()) if kv_pair[0] in list_fields])
        for k, v in record.items():
            if isinstance(v, dict):
                # For objects that refer to a record in the database, take their value(system ID).
                record[k] = v.get('value', record[k])
        record['ID'] = record.pop('sys_id')
        human_readable = tableToMarkdown('ServiceNow record', record, removeNull=True)
        entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(record)}
    else:
        mapped_record = {DEFAULT_RECORD_FIELDS[k]: record[k] for k in DEFAULT_RECORD_FIELDS if k in record}
        human_readable = tableToMarkdown(f'ServiceNow record {record_id}', mapped_record, removeNull=True)
        entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_record)}

    return human_readable, entry_context, result


def create_record_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Any]:
    """Create a record.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    table_name = str(args.get('table_name', ''))
    fields_str = str(args.get('fields', ''))
    custom_fields_str = str(args.get('custom_fields', ''))

    if fields_str:
        fields: dict = split_fields(fields_str)
    if custom_fields_str:
        custom_fields: dict = split_fields(custom_fields_str)

    result = client.create(table_name, fields, custom_fields)

    if not result or 'result' not in result:
        return 'Could not create record.', {}, {}

    record = result.get('result', {})

    mapped_record = {DEFAULT_RECORD_FIELDS[k]: result[k] for k in DEFAULT_RECORD_FIELDS if k in record}

    human_readable = tableToMarkdown('ServiceNow record created successfully', mapped_record, removeNull=True),
    entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_record)}

    return human_readable, entry_context, record


def update_record_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any]]:
    """Update a record.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    table_name = str(args.get('table_name', ''))
    record_id = str(args.get('id', ''))
    fields_str = str(args.get('fields', ''))
    custom_fields_str = str(args.get('custom_fields', ''))

    if fields_str:
        fields: dict = split_fields(fields_str)
    if custom_fields_str:
        custom_fields: dict = split_fields(custom_fields_str)

    result = client.update(table_name, record_id, fields, custom_fields)

    if not result or 'result' not in result:
        return 'Could not retrieve record.', {}, {}

    record = result.get('result', {})
    mapped_record = {DEFAULT_RECORD_FIELDS[k]: record[k] for k in DEFAULT_RECORD_FIELDS if k in record}
    human_readable = tableToMarkdown(f'ServiceNow record with ID {record_id} updated successfully',
                                     t=mapped_record, removeNull=True),
    entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_record)}

    return human_readable, entry_context, record


def delete_record_command(client: Client, args: dict) -> Tuple[str, Dict[Any, Any], Dict]:
    """Delete a record.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    record_id = str(args.get('id', ''))
    table_name = str(args.get('table_name', ''))

    result = client.delete(table_name, record_id)

    return f'ServiceNow record with ID {record_id} was successfully deleted.', {}, result


def add_link_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Add a link.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    ticket_id = str(args.get('id', ''))
    key = 'comments' if args.get('post-as-comment', 'false').lower() == 'true' else 'work_notes'
    link_argument = str(args.get('link', ''))
    text = args.get('text', link_argument)
    link = f'[code]<a class="web" target="_blank" href="{link_argument}" >{text}</a>[/code]'
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))

    result = client.add_link(ticket_id, ticket_type, key, link)

    if not result or 'result' not in result:
        raise Exception('Unable to retrieve response.')

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code', 'Description', 'Opened At', 'Due Date', 'Resolved By',
               'Resolved At', 'SLA Due', 'Short Description', 'Additional Comments']
    hr_ = get_ticket_human_readable(result['result'], ticket_type)
    human_readable = tableToMarkdown('Link successfully added to ServiceNow ticket', t=hr_,
                                     headers=headers, removeNull=True)

    return human_readable, {}, result


def add_comment_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Add a comment.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    ticket_id = str(args.get('id', ''))
    key = 'comments' if args.get('post-as-comment', 'false').lower() == 'true' else 'work_notes'
    text = str(args.get('comment', ''))
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))

    result = client.add_comment(ticket_id, ticket_type, key, text)

    if not result or 'result' not in result:
        return_error('Unable to retrieve response')

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']
    hr_ = get_ticket_human_readable(result['result'], ticket_type)
    human_readable = tableToMarkdown('Comment successfully added to ServiceNow ticket', t=hr_,
                                     headers=headers, removeNull=True)

    return human_readable, {}, result


def upload_file_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Upload a file.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))
    ticket_id = str(args.get('id', ''))
    file_id = str(args.get('file_id', ''))

    file_name = args.get('file_name', demisto.dt(demisto.context(), "File(val.EntryID=='" + file_id + "').Name"))
    if not file_name:  # in case of info file
        file_name = demisto.dt(demisto.context(), "InfoFile(val.EntryID=='" + file_id + "').Name")
    if not file_name:
        raise Exception('Could not find the file. Please add a file to the incident.')
    file_name = file_name[0] if isinstance(file_name, list) else file_name

    result = client.upload_file(ticket_id, file_id, file_name, ticket_type)

    if not result or 'result' not in result or not result['result']:
        raise Exception('Unable to upload file.')
    result: dict = result.get('result', {})

    hr_ = {
        'Filename': result.get('file_name'),
        'Download link': result.get('download_link'),
        'System ID': result.get('sys_id')
    }
    human_readable = tableToMarkdown(f'File uploaded successfully to ticket {ticket_id}.', hr_)
    context = {
        'ID': ticket_id,
        'File': {
            'Filename': result.get('file_name'),
            'Link': result.get('download_link'),
            'SystemID': result.get('sys_id')
        }
    }
    entry_context = {
        'ServiceNow.Ticket(val.ID===obj.ID)': context,
        'Ticket(val.ID===obj.ID)': context
    }

    return human_readable, entry_context, result


def query_tickets_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Query tickets.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    sys_param_limit = args.get('limit', client.sys_param_limit)
    sys_param_offset = args.get('offset', client.sys_param_offset)
    sys_param_query = str(args.get('query', ''))

    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))

    result = client.query(ticket_type, sys_param_limit, sys_param_offset, sys_param_query)

    if not result or 'result' not in result or len(result['result']) == 0:
        return 'No ServiceNow tickets matched the query.', {}, {}
    tickets = result.get('result', {})
    hr_ = get_ticket_human_readable(tickets, ticket_type)
    context = get_ticket_context(tickets)

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']

    human_readable = tableToMarkdown('ServiceNow tickets', t=hr_, headers=headers, removeNull=True)
    entry_context = {
        'Ticket(val.ID===obj.ID)': context,
        'ServiceNow.Ticket(val.ID===obj.ID)': context
    }

    return human_readable, entry_context, tickets


def get_ticket_notes_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Get the ticket's note.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    ticket_id = args.get('id')
    sys_param_limit = args.get('limit', client.sys_param_limit)
    sys_param_offset = args.get('offset', client.sys_param_offset)

    sys_param_query = f'element_id={ticket_id}^element=comments^ORelement=work_notes'

    result = client.query('sys_journal_field', sys_param_limit, sys_param_offset, sys_param_query)

    if not result or 'result' not in result:
        return f'No comment found on ticket {ticket_id}.', {}, {}

    headers = ['Value', 'CreatedOn', 'CreatedBy', 'Type']

    mapped_notes = [{
        'Value': note.get('value'),
        'CreatedOn': note.get('sys_created_on'),
        'CreatedBy': note.get('sys_created_by'),
        'Type': 'Work Note' if note.get('element', '') == 'work_notes' else 'Comment'
    } for note in result['result']]

    if not mapped_notes:
        return f'No comment found on ticket {ticket_id}.', {}, {}

    ticket = {
        'ID': ticket_id,
        'Note': mapped_notes
    }

    human_readable = tableToMarkdown(f'ServiceNow notes for ticket {ticket_id}', t=mapped_notes, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    entry_context = {'ServiceNow.Ticket(val.ID===obj.ID)': createContext(ticket, removeNull=True)}

    return human_readable, entry_context, result


def query_table_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Query a table.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    table_name = str(args.get('table_name', ''))
    sys_param_limit = args.get('limit', client.sys_param_limit)
    sys_param_query = str(args.get('query', ''))
    sys_param_offset = args.get('offset', client.sys_param_offset)
    fields = args.get('fields')

    result = client.query(table_name, sys_param_limit, sys_param_offset, sys_param_query)
    if not result or 'result' not in result or len(result['result']) == 0:
        return 'No results found', {}, {}
    table_entries = result.get('result', {})

    if fields:
        fields = argToList(fields)
        if 'sys_id' not in fields:
            # ID is added by default
            fields.append('sys_id')
        # Filter the records according to the given fields
        records = [dict([kv_pair for kv_pair in iter(r.items()) if kv_pair[0] in fields]) for r in table_entries]
        for r in records:
            r['ID'] = r.pop('sys_id')
            for k, v in r.items():
                if isinstance(v, dict):
                    # For objects that refer to a record in the database, take their value (system ID).
                    r[k] = v.get('value', v)
        human_readable = tableToMarkdown('ServiceNow records', records, removeNull=True)
        entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(records)}
    else:
        mapped_records = [{DEFAULT_RECORD_FIELDS[k]: r[k] for k in DEFAULT_RECORD_FIELDS if k in r}
                          for r in table_entries]
        human_readable = tableToMarkdown('ServiceNow records', mapped_records, removeNull=True)
        entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_records)}

    return human_readable, entry_context, table_entries


def query_computers_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any]]:
    """Query computers.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    table_name = 'cmdb_ci_computer'
    computer_id = args.get('computer_id', None)
    computer_name = args.get('computer_name', None)
    asset_tag = args.get('asset_tag', None)
    computer_query = args.get('query', {})
    offset = args.get('offset', client.sys_param_offset)
    limit = args.get('limit', client.sys_param_limit)

    if computer_id:
        result = client.get(table_name, computer_id)
    else:
        if computer_name:
            computer_query = f'name={computer_name}'
        elif asset_tag:
            computer_query = f'asset_tag={asset_tag}'

        result = client.query(table_name, limit, offset, computer_query)

    if not result or 'result' not in result:
        return 'No computers found.', {}, {}

    computers = result.get('result', {})
    if not isinstance(computers, list):
        computers = [computers]

    if len(computers) == 0:
        return 'No computers found.', {}, {}

    computer_statuses = {
        '1': 'In use',
        '2': 'On order',
        '3': 'On maintenance',
        '6': 'In stock/In transit',
        '7': 'Retired',
        '100': 'Missing'
    }

    mapped_computers = [{
        'ID': computer.get('sys_id'),
        'AssetTag': computer.get('asset_tag'),
        'Name': computer.get('name'),
        'DisplayName': f"{computer.get('asset_tag', '')} - {computer.get('name', '')}",
        'SupportGroup': computer.get('support_group'),
        'OperatingSystem': computer.get('os'),
        'Company': computer.get('company', {}).get('value')
        if isinstance(computer.get('company'), dict) else computer.get('company'),
        'AssignedTo': computer.get('assigned_to', {}).get('value')
        if isinstance(computer.get('assigned_to'), dict) else computer.get('assigned_to'),
        'State': computer_statuses.get(computer.get('install_status', ''), computer.get('install_status')),
        'Cost': f"{computer.get('cost', '').rstrip()} {computer.get('cost_cc', '').rstrip()}",
        'Comments': computer.get('comments')
    } for computer in computers]

    headers = ['ID', 'AssetTag', 'Name', 'DisplayName', 'SupportGroup', 'OperatingSystem', 'Company', 'AssignedTo',
               'State', 'Cost', 'Comments']
    human_readable = tableToMarkdown('ServiceNow Computers', t=mapped_computers, headers=headers,
                                     removeNull=True, headerTransform=pascalToSpace),
    entry_context = {'ServiceNow.Computer(val.ID===obj.ID)': createContext(mapped_computers, removeNull=True)}

    return human_readable, entry_context, computers


def query_groups_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any]]:
    """Query groups.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    table_name = 'sys_user_group'
    group_id = args.get('group_id')
    group_name = args.get('group_name')
    group_query = args.get('query', {})
    offset = args.get('offset', client.sys_param_offset)
    limit = args.get('limit', client.sys_param_limit)

    if group_id:
        result = client.get(table_name, group_id)
    else:
        if group_name:
            group_query = f'name={group_name}'
        result = client.query(table_name, limit, offset, group_query)

    if not result or 'result' not in result:
        return 'No groups found.', {}, {}

    groups = result.get('result', {})
    if not isinstance(groups, list):
        groups = [groups]

    if len(groups) == 0:
        return 'No groups found.', {}, {}

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

    human_readable = tableToMarkdown('ServiceNow Groups', t=mapped_groups, headers=headers,
                                     removeNull=True, headerTransform=pascalToSpace),
    entry_context = {'ServiceNow.Group(val.ID===obj.ID)': createContext(mapped_groups, removeNull=True)}

    return human_readable, entry_context, groups


def query_users_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any]]:
    """Query users.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    table_name = 'sys_user'
    user_id = args.get('user_id')
    user_name = args.get('user_name')
    user_query = args.get('query', {})
    offset = args.get('offset', client.sys_param_offset)
    limit = args.get('limit', client.sys_param_limit)

    if user_id:
        result = client.get(table_name, user_id)
    else:
        if user_name:
            user_query = f'user_name={user_name}'
        result = client.query(table_name, limit, offset, user_query)

    if not result or 'result' not in result:
        return 'No users found.', {}, {}

    users = result.get('result', {})
    if not isinstance(users, list):
        users = [users]

    if len(users) == 0:
        return 'No users found.', {}, {}

    mapped_users = [{
        'ID': user.get('sys_id'),
        'Name': f"{user.get('first_name', '').rstrip()} {user.get('last_name', '').rstrip()}",
        'UserName': user.get('user_name'),
        'Email': user.get('email'),
        'Created': user.get('sys_created_on'),
        'Updated': user.get('sys_updated_on'),
    } for user in users]

    headers = ['ID', 'Name', 'UserName', 'Email', 'Created', 'Updated']
    human_readable = tableToMarkdown('ServiceNow Users', t=mapped_users, headers=headers, removeNull=True,
                                     headerTransform=pascalToSpace)
    entry_context = {'ServiceNow.User(val.ID===obj.ID)': createContext(mapped_users, removeNull=True)}

    return human_readable, entry_context, users


def list_table_fields_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any]]:
    """List table fields.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    table_name = str(args.get('table_name', ''))

    result = client.get_table_fields(table_name)

    if not result or 'result' not in result:
        return 'Table was not found.', {}, {}

    if len(result['result']) == 0:
        return 'Table contains no records.', {}, {}

    fields = [{'Name': k} for k, v in result['result'][0].items()]

    human_readable = tableToMarkdown(f'ServiceNow Table fields - {table_name}', fields),
    entry_context = {'ServiceNow.Field': createContext(fields)}

    return human_readable, entry_context, result


def get_table_name_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any]]:
    """List table fields.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    label = args.get('label')
    offset = args.get('offset', client.sys_param_offset)
    limit = args.get('limit', client.sys_param_limit)
    table_query = f'label={label}'

    result = client.query('sys_db_object', limit, offset, table_query)

    if not result or 'result' not in result:
        return 'Table was not found.', {}, {}
    tables = result.get('result', {})
    if len(tables) == 0:
        return 'Table was not found.', {}, {}

    headers = ['ID', 'Name', 'SystemName']

    mapped_tables = [{
        'ID': table.get('sys_id'),
        'Name': table.get('name'),
        'SystemName': table.get('sys_name')
    } for table in tables]

    human_readable = tableToMarkdown(f'ServiceNow Tables for label - {label}', t=mapped_tables,
                                     headers=headers, headerTransform=pascalToSpace),
    entry_context = {'ServiceNow.Table(val.ID===obj.ID)': createContext(mapped_tables)}

    return human_readable, entry_context, result


def fetch_incidents(client: Client):
    query_params = {}
    incidents = []

    last_run = demisto.getLastRun()
    if 'time' not in last_run:
        snow_time, _ = parse_date_range(client.fetch_time, '%Y-%m-%d %H:%M:%S')
    else:
        snow_time = last_run['time']

    query = ''
    if client.sys_param_query:
        query += f'{client.sys_param_query}^'
    query += f'ORDERBY{client.timestamp_field}^{client.timestamp_field}>{snow_time}'

    if query:
        query_params['sysparm_query'] = query
    query_params['sysparm_limit'] = str(client.sys_param_limit)
    res = client.send_request(f'table/{client.ticket_type}', 'GET', params=query_params)

    count = 0
    parsed_snow_time = datetime.strptime(snow_time, '%Y-%m-%d %H:%M:%S')

    severity_map = {'1': 3, '2': 2, '3': 1}  # Map SNOW severity to Demisto severity for incident creation

    for result in res.get('result', []):
        labels = []

        if client.timestamp_field not in result:
            raise ValueError(f"The timestamp field [{client.timestamp_field}] does not exist in the ticket")

        if count > client.sys_param_limit:
            break

        try:
            if datetime.strptime(result[client.timestamp_field], '%Y-%m-%d %H:%M:%S') < parsed_snow_time:
                continue
        except Exception:
            pass

        for k, v in result.items():
            if isinstance(v, str):
                labels.append({
                    'type': k,
                    'value': v
                })
            else:
                labels.append({
                    'type': k,
                    'value': json.dumps(v)
                })

        severity = severity_map.get(result.get('severity', ''), 0)

        file_names = []
        if client.get_attachments:
            file_entries = client.get_ticket_attachment_entries(result['sys_id'])
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
        snow_time = result[client.timestamp_field]

    demisto.incidents(incidents)
    demisto.setLastRun({'time': snow_time})


def test_module(client: Client, *_):
    # Validate fetch_time parameter is valid (if not, parse_date_range will raise the error message)
    parse_date_range(client.fetch_time, '%Y-%m-%d %H:%M:%S')

    result = client.send_request(f'table/{client.ticket_type}?sysparm_limit=1', 'GET')
    if 'result' not in result:
        raise Exception('ServiceNow error: ' + str(result))
    ticket = result.get('result')
    if ticket and demisto.params().get('isFetch'):
        if isinstance(ticket, list):
            ticket = ticket[0]
        if client.timestamp_field not in ticket:
            raise ValueError(f"The timestamp field [{client.timestamp_field}] does not exist in the ticket.")
    demisto.results('ok')
    return '', {}, {}


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    command = demisto.command()
    LOG(f'Executing command {command}')

    params = demisto.params()
    username = params['credentials']['identifier']
    password = params['credentials']['password']
    verify = not params.get('insecure', False)
    proxy = demisto.params().get('proxy') is True

    version = params.get('api_version')
    if version:
        api = f'/api/now/{version}/'
    else:
        api = '/api/now/'
    server_url = params.get('url')
    server_url = f'{get_server_url(server_url)}{api}'

    fetch_time = params.get('fetch_time', '10 minutes').strip()
    sysparm_query = params.get('sysparm_query')
    sysparm_limit = int(params.get('fetch_limit', 10))
    timestamp_field = params.get('timestamp_field', 'opened_at')
    ticket_type = params.get('ticket_type', 'incident')
    get_attachments = params.get('get_attachments', False)

    raise_exception = False
    try:
        client = Client(server_url, username, password, verify, proxy, fetch_time, sysparm_query, sysparm_limit,
                        timestamp_field, ticket_type, get_attachments)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'servicenow-update-ticket': update_ticket_command,
            'servicenow-create-ticket': create_ticket_command,
            'servicenow-delete-ticket': delete_ticket_command,
            'servicenow-query-tickets': query_tickets_command,
            'servicenow-add-link': add_link_command,
            'servicenow-add-comment': add_comment_command,
            'servicenow-upload-file': upload_file_command,
            'servicenow-get-ticket-notes': get_ticket_notes_command,
            'servicenow-get-record': get_record_command,
            'servicenow-update-record': update_record_command,
            'servicenow-create-record': create_record_command,
            'servicenow-delete-record': delete_record_command,
            'servicenow-query-table': query_table_command,
            'servicenow-query-computers': query_computers_command,
            'servicenow-query-groups': query_groups_command,
            'servicenow-query-users': query_users_command,
            'servicenow-list-table-fields': list_table_fields_command,
            'servicenow-get-table-name': get_table_name_command
        }
        args = demisto.args()
        if command == 'fetch-incidents':
            raise_exception = True
            fetch_incidents(client)
        elif command == 'servicenow-get-ticket':
            get_ticket_command(client, args)
        elif command in commands:
            md_, ec_, raw_response = commands[command](client, args)
            return_outputs(md_, ec_, raw_response)
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        LOG(err)
        LOG.print_log()
        if not raise_exception:
            return_error(str(err))
        else:
            raise


if __name__ in ["__builtin__", "builtins"]:
    main()
