import os
import shutil
import dateparser
from urllib import parse
from typing import List, Tuple, Dict, Callable, Any, Union, Optional

from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

COMMAND_NOT_IMPLEMENTED_MSG = 'Command not implemented'

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
    },
}

TICKET_APPROVAL = {
    'sc_req_item': {
        'waiting_for_approval': 'Waiting for approval',
        'approved': 'Approved',
        'requested': 'Requested',
        'rejected': 'Rejected',
        'not requested': 'Not Yet Requested'
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
             'approval', 'approval_set', 'assigned_to', 'assignment_group',
             'business_duration', 'business_service', 'business_stc', 'change_type', 'category', 'caller',
             'calendar_duration', 'calendar_stc', 'caller_id', 'caused_by', 'close_code', 'close_notes',
             'closed_at', 'closed_by', 'cmdb_ci', 'comments', 'comments_and_work_notes', 'company', 'contact_type',
             'correlation_display', 'correlation_id', 'delivery_plan', 'delivery_task', 'description', 'due_date',
             'expected_start', 'follow_up', 'group_list', 'hold_reason', 'impact', 'incident_state',
             'knowledge', 'location', 'made_sla', 'notify', 'order', 'parent', 'parent_incident', 'priority',
             'problem_id', 'reassignment_count', 'reopen_count', 'resolved_at', 'resolved_by', 'rfc',
             'severity', 'sla_due', 'state', 'subcategory', 'sys_tags', 'sys_updated_by', 'sys_updated_on',
             'time_worked', 'title', 'type', 'urgency', 'user_input', 'watch_list', 'work_end', 'work_notes',
             'work_notes_list', 'work_start']

# Every table in ServiceNow should have those fields
DEFAULT_RECORD_FIELDS = {
    'sys_id': 'ID',
    'sys_updated_by': 'UpdatedBy',
    'sys_updated_on': 'UpdatedAt',
    'sys_created_by': 'CreatedBy',
    'sys_created_on': 'CreatedAt'
}


MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> int:
    """
    Converts an XSOAR argument to a timestamp (seconds from epoch).
    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False``.

    Args:
        arg: argument to convert
        arg_name: argument name.
        required: throws exception if ``True`` and argument provided is None

    Returns:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    """
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def get_server_url(server_url: str) -> str:
    url = server_url
    url = re.sub('/[/]+$/', '', url)
    url = re.sub('/$', '', url)
    return url


def get_item_human_readable(data: dict) -> dict:
    """Get item human readable.

    Args:
        data: item data.

    Returns:
        item human readable.
    """
    item = {
        'ID': data.get('sys_id', ''),
        'Name': data.get('name', ''),
        'Description': data.get('short_description', ''),
        'Price': data.get('price', ''),
        'Variables': []
    }
    variables = data.get('variables')
    if variables and isinstance(variables, list):
        for var in variables:
            if var:
                pretty_variables = {
                    'Question': var.get('label', ''),
                    'Type': var.get('display_type', ''),
                    'Name': var.get('name', ''),
                    'Mandatory': var.get('mandatory', '')
                }
                item['Variables'].append(pretty_variables)
    return item


def create_ticket_context(data: dict, additional_fields: list = None) -> Any:
    """Create ticket context.

    Args:
        data: ticket data.
        additional_fields: additional fields to extract from the ticket

    Returns:
        ticket context.
    """
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
    if additional_fields:
        for additional_field in additional_fields:
            if additional_field in data.keys() and camelize_string(additional_field) not in context.keys():
                context[additional_field] = data.get(additional_field)

    # These fields refer to records in the database, the value is their system ID.
    closed_by = data.get('closed_by')
    if closed_by:
        if isinstance(closed_by, dict):
            context['ResolvedBy'] = closed_by.get('value', '')
        else:
            context['ResolvedBy'] = closed_by
    opened_by = data.get('opened_by')
    if opened_by:
        if isinstance(opened_by, dict):
            context['OpenedBy'] = opened_by.get('value', '')
            context['Creator'] = opened_by.get('value', '')
        else:
            context['OpenedBy'] = opened_by
            context['Creator'] = opened_by
    assigned_to = data.get('assigned_to')
    if assigned_to:
        if isinstance(assigned_to, dict):
            context['Assignee'] = assigned_to.get('value', '')
        else:
            context['Assignee'] = assigned_to

    # Try to map fields
    priority = data.get('priority')
    if priority:
        context['Priority'] = TICKET_PRIORITY.get(priority, priority)
    state = data.get('state')
    if state:
        context['State'] = state

    return createContext(context, removeNull=True)


def get_ticket_context(data: Any, additional_fields: list = None) -> Any:
    """Manager of ticket context creation.

    Args:
        data: ticket data. in the form of a dict or a list of dict.
        additional_fields: additional fields to extract from the ticket

    Returns:
        ticket context. in the form of a dict or a list of dict.
    """
    if not isinstance(data, list):
        return create_ticket_context(data, additional_fields)

    tickets = []
    for d in data:
        tickets.append(create_ticket_context(d, additional_fields))
    return tickets


def get_ticket_human_readable(tickets, ticket_type: str, additional_fields: list = None) -> list:
    """Get ticket human readable.

    Args:
        tickets: tickets data. in the form of a dict or a list of dict.
        ticket_type: ticket type.
        additional_fields: additional fields to extract from the ticket

    Returns:
        ticket human readable.
    """
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
            'System ID': ticket.get('sys_id'),
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
        impact = ticket.get('impact', '')
        if impact:
            hr['Impact'] = ticket_severity.get(impact, impact)
        urgency = ticket.get('urgency', '')
        if urgency:
            hr['Urgency'] = ticket_severity.get(urgency, urgency)
        severity = ticket.get('severity', '')
        if severity:
            hr['Severity'] = ticket_severity.get(severity, severity)
        priority = ticket.get('priority', '')
        if priority:
            hr['Priority'] = TICKET_PRIORITY.get(priority, priority)

        state = ticket.get('state', '')
        if state:
            mapped_state = state
            if ticket_type in TICKET_STATES:
                mapped_state = TICKET_STATES[ticket_type].get(state, mapped_state)
            hr['State'] = mapped_state
        approval = ticket.get('approval', '')
        if approval:
            mapped_approval = approval
            if ticket_type in TICKET_APPROVAL:
                mapped_approval = TICKET_APPROVAL[ticket_type].get(ticket.get('approval'), mapped_approval)
                # Approval will be added to the markdown only in the necessary ticket types
                hr['Approval'] = mapped_approval

        if additional_fields:
            for additional_field in additional_fields:
                hr[additional_field] = ticket.get(additional_field)
        result.append(hr)

    return result


def get_ticket_fields(args: dict, template_name: dict = {}, ticket_type: str = '') -> dict:
    """Inverse the keys and values of those dictionaries
    to map the arguments to their corresponding values in ServiceNow.

    Args:
        args: Demisto args
        template_name: ticket template name
        ticket_type: ticket type

    Returns:
        ticket fields.
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
    approval = TICKET_APPROVAL.get(ticket_type)
    inv_approval = {v: k for k, v in approval.items()} if approval else {}

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
            elif arg == 'approval':
                ticket_fields[arg] = inv_approval.get(input_arg, input_arg)
            elif arg == 'change_type':
                # this change is required in order to use type 'Standard' as well.
                ticket_fields['type'] = input_arg
            else:
                ticket_fields[arg] = input_arg
        elif template_name and arg in template_name:
            ticket_fields[arg] = template_name[arg]

    return ticket_fields


def generate_body(fields: dict = {}, custom_fields: dict = {}) -> dict:
    """Generates a body from fields and custom fields.

    Args:
        fields: fields data.
        custom_fields: custom fields data.

    Returns:
        body object for SNOW requests.
    """
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


def split_fields(fields: str = '', delimiter: str = ';') -> dict:
    """Split str fields of Demisto arguments to SNOW request fields by the char ';'.

    Args:
        fields: fields in a string representation.
        delimiter: the delimiter to use to separate the fields.
    Returns:
        dic_fields object for SNOW requests.
    """
    dic_fields = {}

    if fields:
        if '=' not in fields:
            raise Exception(
                f"The argument: {fields}.\nmust contain a '=' to specify the keys and values. e.g: key=val.")
        arr_fields = fields.split(delimiter)
        for f in arr_fields:
            field = f.split('=', 1)  # a field might include a '=' sign in the value. thus, splitting only once.
            if len(field) > 1:
                dic_fields[field[0]] = field[1]

    return dic_fields


def build_query_for_request_params(query):
    """Split query that contains '&' to a list of queries.

    Args:
        query: query (Example: "id=5&status=1")

    Returns:
        List of sub queries. (Example: ["id=5", "status=1"])
    """

    if '&' in query:
        query_params = []  # type: ignore
        query_args = parse.parse_qsl(query)
        for arg in query_args:
            query_params.append(parse.urlencode([arg]))  # type: ignore
        return query_params
    else:
        return query


class Client(BaseClient):
    """
    Client to use in the ServiceNow integration. Overrides BaseClient.
    """

    def __init__(self, server_url: str, sc_server_url: str, username: str, password: str, verify: bool, fetch_time: str,
                 sysparm_query: str, sysparm_limit: int, timestamp_field: str, ticket_type: str, get_attachments: bool,
                 incident_name: str, oauth_params: dict = None, version: str = None):
        """

        Args:
            server_url: SNOW server url
            sc_server_url: SNOW Service Catalog url
            username: SNOW username
            password: SNOW password
            oauth_params: (optional) the parameters for the ServiceNowClient that should be used to create an
                          access token when using OAuth2 authentication.
            verify: whether to verify the request
            fetch_time: first time fetch for fetch_incidents
            sysparm_query: system query
            sysparm_limit: system limit
            timestamp_field: timestamp field for fetch_incidents
            ticket_type: default ticket type
            get_attachments: whether to get ticket attachments by default
            incident_name: the ServiceNow ticket field to be set as the incident name
        """
        oauth_params = oauth_params if oauth_params else {}
        self._base_url = server_url
        self._sc_server_url = sc_server_url
        self._version = version
        self._verify = verify
        self._username = username
        self._password = password
        self._proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        self.use_oauth = True if oauth_params else False
        self.fetch_time = fetch_time
        self.timestamp_field = timestamp_field
        self.ticket_type = ticket_type
        self.get_attachments = get_attachments
        self.incident_name = incident_name
        self.sys_param_query = sysparm_query
        self.sys_param_limit = sysparm_limit
        self.sys_param_offset = 0

        if self.use_oauth:  # if user selected the `Use OAuth` checkbox, OAuth2 authentication should be used
            self.snow_client: ServiceNowClient = ServiceNowClient(credentials=oauth_params.get('credentials', {}),
                                                                  use_oauth=self.use_oauth,
                                                                  client_id=oauth_params.get('client_id', ''),
                                                                  client_secret=oauth_params.get('client_secret', ''),
                                                                  url=oauth_params.get('url', ''),
                                                                  verify=oauth_params.get('verify', False),
                                                                  proxy=oauth_params.get('proxy', False),
                                                                  headers=oauth_params.get('headers', ''))
        else:
            self._auth = (self._username, self._password)

    def send_request(self, path: str, method: str = 'GET', body: dict = None, params: dict = None,
                     headers: dict = None, file=None, sc_api: bool = False):
        """Generic request to ServiceNow.

        Args:
            path: API path
            method: request method
            body: request body
            params: request params
            headers: request headers
            file: request  file
            sc_api: Whether to send the request to the SC API

        Returns:
            response from API
        """
        body = body if body is not None else {}
        params = params if params is not None else {}
        # if sc_api is set to true, then sending the request to the 'Service Catalog' instead of the 'now' API.
        url = f'{self._base_url}{path}' if not sc_api else f'{self._sc_server_url}{path}'

        if not headers:
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        max_retries = 3
        num_of_tries = 0
        while num_of_tries < max_retries:
            if file:
                # Not supported in v2
                url = url.replace('v2', 'v1')
                try:
                    file_entry = file['id']
                    file_name = file['name']
                    shutil.copy(demisto.getFilePath(file_entry)['path'], file_name)
                    with open(file_name, 'rb') as f:
                        if self.use_oauth:
                            access_token = self.snow_client.get_access_token()
                            headers.update({
                                'Authorization': f'Bearer {access_token}'
                            })
                            res = requests.request(method, url, headers=headers, data=body, params=params,
                                                   files={'file': f}, verify=self._verify, proxies=self._proxies)
                        else:
                            res = requests.request(method, url, headers=headers, data=body, params=params,
                                                   files={'file': f}, auth=self._auth,
                                                   verify=self._verify, proxies=self._proxies)
                    shutil.rmtree(demisto.getFilePath(file_entry)['name'], ignore_errors=True)
                except Exception as err:
                    raise Exception('Failed to upload file - ' + str(err))
            else:
                if self.use_oauth:
                    access_token = self.snow_client.get_access_token()
                    headers.update({
                        'Authorization': f'Bearer {access_token}'
                    })
                    res = requests.request(method, url, headers=headers, data=json.dumps(body) if body else {},
                                           params=params, verify=self._verify, proxies=self._proxies)
                else:
                    res = requests.request(method, url, headers=headers, data=json.dumps(body) if body else {},
                                           params=params, auth=self._auth, verify=self._verify, proxies=self._proxies)

            if "Instance Hibernating page" in res.text:
                raise DemistoException(
                    "A connection was established but the instance is in hibernate mode.\n"
                    "Please wake your instance and try again.")
            try:
                json_res = res.json()
            except Exception as err:
                if res.status_code == 201:
                    return "The ticket was successfully created."
                if not res.content:
                    return ''
                raise Exception(f'Error parsing reply - {str(res.content)} - {str(err)}')

            if 'error' in json_res:
                message = json_res.get('error', {}).get('message')
                details = json_res.get('error', {}).get('detail')
                if message == 'No Record found':
                    return {'result': []}  # Return an empty results array
                if res.status_code == 401:
                    demisto.debug(f'Got status code 401 - {json_res}. Retrying ...')
                else:
                    raise Exception(f'ServiceNow Error: {message}, details: {details}')

            if res.status_code < 200 or res.status_code >= 300:
                if res.status_code != 401 or num_of_tries == (max_retries - 1):
                    raise Exception(
                        f'Got status code {str(res.status_code)} with url {url} with body {str(res.content)}'
                        f' with headers {str(res.headers)}')
            else:
                break
            num_of_tries += 1

        return json_res

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

        result = self.send_request('table/sys_template', 'GET', params=query_params)

        if len(result['result']) == 0:
            raise ValueError("Incorrect template name.")

        template = result['result'][0].get('template', '').split('^')
        dic_template = {}

        for i in range(len(template) - 1):
            template_value = template[i].split('=')
            if len(template_value) > 1:
                dic_template[template_value[0]] = template_value[1]

        return dic_template

    def get_ticket_attachments(self, ticket_id: str, sys_created_on: Optional[str] = None) -> dict:
        """Get ticket attachments by sending a GET request.

        Args:
            ticket_id: ticket id
            sys_created_on: string, when the attachment was created

        Returns:
            Response from API.
        """
        query = f'table_sys_id={ticket_id}'
        if sys_created_on:
            query += f'^sys_created_on>{sys_created_on}'
        return self.send_request('attachment', 'GET', params={'sysparm_query': query})

    def get_ticket_attachment_entries(self, ticket_id: str, sys_created_on: Optional[str] = None) -> list:
        """Get ticket attachments, including file attachments
        by sending a GET request and using the get_ticket_attachments class function.

        Args:
            ticket_id: ticket id
            sys_created_on: string, when the attachment was created

        Returns:
            Array of attachments entries.
        """
        entries = []
        links = []  # type: List[Tuple[str, str]]
        attachments_res = self.get_ticket_attachments(ticket_id, sys_created_on)
        if 'result' in attachments_res and len(attachments_res['result']) > 0:
            attachments = attachments_res['result']
            links = [(attachment.get('download_link', ''), attachment.get('file_name', ''))
                     for attachment in attachments]

        for link in links:
            file_res = requests.get(link[0], auth=(self._username, self._password), verify=self._verify,
                                    proxies=self._proxies)
            if file_res is not None:
                entries.append(fileResult(link[1], file_res.content))

        return entries

    def get(self, table_name: str, record_id: str, custom_fields: dict = {}, number: str = None) -> dict:
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
            path = f'table/{table_name}/{record_id}'
        elif number:
            path = f'table/{table_name}'
            query_params = {
                'number': number
            }
        elif custom_fields:
            path = f'table/{table_name}'
            query_params = custom_fields
        else:
            # Only in cases where the table is of type ticket
            raise ValueError('servicenow-get-ticket requires either ticket ID (sys_id) or ticket number.')

        return self.send_request(path, 'GET', params=query_params)

    def update(self, table_name: str, record_id: str, fields: dict = {}, custom_fields: dict = {},
               input_display_value: bool = False) -> dict:
        """Updates a ticket or a record by sending a PATCH request.

        Args:
            table_name: table name
            record_id: record id
            fields: fields to update
            custom_fields: custom_fields to update
            input_display_value: whether to set field values using the display value or the actual value.
        Returns:
            Response from API.
        """
        body = generate_body(fields, custom_fields)
        query_params = {'sysparm_input_display_value': input_display_value}
        return self.send_request(f'table/{table_name}/{record_id}', 'PATCH', params=query_params, body=body)

    def create(self, table_name: str, fields: dict = {}, custom_fields: dict = {},
               input_display_value: bool = False):
        """Creates a ticket or a record by sending a POST request.

        Args:
        table_name: table name
        record_id: record id
        fields: fields to update
        custom_fields: custom_fields to update
        input_display_value: whether to set field values using the display value or the actual value.

        Returns:
            Response from API.
        """
        body = generate_body(fields, custom_fields)
        query_params = {'sysparm_input_display_value': input_display_value}
        return self.send_request(f'table/{table_name}', 'POST', params=query_params, body=body)

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

    def add_tag(self, ticket_id: str, tag_id: str, title: str, ticket_type: str) -> dict:
        """Adds a tag to a ticket by sending a POST request.

        Args:
            ticket_id: ticket id
            tag_id:  tag id
            title: tag title
            ticket_type: ticket type

        Returns:
            Response from API.
        """
        body = {'label': tag_id, 'table': ticket_type, 'table_key': ticket_id, 'title': title}
        return self.send_request('/table/label_entry', 'POST', body=body)

    def query(self, table_name: str, sys_param_limit: str, sys_param_offset: str, sys_param_query: str,
              system_params: dict = {}, sysparm_fields: Optional[str] = None) -> dict:
        """Query records by sending a GET request.

        Args:
        table_name: table name
        sys_param_limit: limit the number of results
        sys_param_offset: offset the results
        sys_param_query: the query
        system_params: system parameters
        sysparm_fields: Comma-separated list of field names to return in the response.

        Returns:
            Response from API.
        """

        query_params = {'sysparm_limit': sys_param_limit, 'sysparm_offset': sys_param_offset}
        if sys_param_query:
            query_params['sysparm_query'] = build_query_for_request_params(sys_param_query)
        if system_params:
            query_params.update(system_params)
        if sysparm_fields:
            query_params['sysparm_fields'] = sysparm_fields
        demisto.debug(f'Running query records with the params: {query_params}')
        return self.send_request(f'table/{table_name}', 'GET', params=query_params)

    def get_table_fields(self, table_name: str) -> dict:
        """Get table fields by sending a GET request.

        Args:
        table_name: table name

        Returns:
            Response from API.
        """
        return self.send_request(f'table/{table_name}?sysparm_limit=1', 'GET')

    def get_item_details(self, id_: str) -> dict:
        """Get item details from service catalog by sending a GET request to the Service Catalog API.

        Args:
        id_: item id

        Returns:
            Response from API.
        """
        return self.send_request(f'servicecatalog/items/{id_}', 'GET', sc_api=True)

    def create_item_order(self, id_: str, quantity: str, variables: dict = {}) -> dict:
        """Create item order in the service catalog by sending a POST request to the Service Catalog API.

        Args:
        id_: item id
        quantity: order quantity
        variables: order variables

        Returns:
            Response from API.
        """
        body = {'sysparm_quantity': quantity, 'variables': variables}
        return self.send_request(f'servicecatalog/items/{id_}/order_now', 'POST', body=body, sc_api=True)

    def document_route_to_table_request(self, queue_id: str, document_table: str, document_id: str) -> dict:
        """Routes a document(ticket/incident) to a queue by sending a GET request.

        Args:
        queue_id: Queue ID.
        document_table: Document table.
        document_id: Document ID.

        Returns:
            Response from API.
        """
        body = {'document_sys_id': document_id, 'document_table': document_table}
        return self.send_request(f'awa/queues/{queue_id}/work_item', 'POST', body=body)


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
    fields_delimiter = args.get('fields_delimiter', ';')
    custom_fields = split_fields(str(args.get('custom_fields', '')), fields_delimiter)
    additional_fields = argToList(str(args.get('additional_fields', '')))

    result = client.get(ticket_type, ticket_id, generate_body({}, custom_fields), number)
    if not result or 'result' not in result:
        return 'Ticket was not found.'

    if isinstance(result['result'], list):
        if len(result['result']) == 0:
            return 'Ticket was not found.'
        ticket = result['result'][0]
    else:
        ticket = result['result']

    entries = []  # type: List[Dict]

    if get_attachments.lower() != 'false':
        entries = client.get_ticket_attachment_entries(ticket.get('sys_id'))

    hr = get_ticket_human_readable(ticket, ticket_type, additional_fields)
    context = get_ticket_context(ticket, additional_fields)

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Approval',
               'Created On', 'Created By', 'Active', 'Close Notes', 'Close Code', 'Description', 'Opened At',
               'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description', 'Additional Comments']
    if additional_fields:
        headers.extend(additional_fields)

    entry = {
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ServiceNow ticket', hr, headers=headers, removeNull=True),
        'EntryContext': {
            'Ticket(val.ID===obj.ID)': context,
            'ServiceNow.Ticket(val.ID===obj.ID)': context
        },
        'IgnoreAutoExtract': True
    }
    entries.append(entry)
    return entries


def update_ticket_command(client: Client, args: dict) -> Tuple[Any, Dict, Dict, bool]:
    """Update a ticket.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    fields_delimiter = args.get('fields_delimiter', ';')
    custom_fields = split_fields(str(args.get('custom_fields', '')), fields_delimiter)
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))
    ticket_id = str(args.get('id', ''))
    additional_fields = split_fields(str(args.get('additional_fields', '')), fields_delimiter)
    additional_fields_keys = list(additional_fields.keys())
    fields = get_ticket_fields(args, ticket_type=ticket_type)
    fields.update(additional_fields)
    input_display_value = argToBoolean(args.get('input_display_value', 'false'))

    result = client.update(ticket_type, ticket_id, fields, custom_fields, input_display_value)
    if not result or 'result' not in result:
        raise Exception('Unable to retrieve response.')
    ticket = result['result']

    hr_ = get_ticket_human_readable(ticket, ticket_type, additional_fields_keys)
    human_readable = tableToMarkdown(f'ServiceNow ticket updated successfully\nTicket type: {ticket_type}',
                                     t=hr_, removeNull=True)

    # make the modified fields the user inserted as arguments show in the context
    if additional_fields:
        additional_fields_keys = list(set(additional_fields_keys).union(set(args.keys())))
    else:
        additional_fields_keys = list(args.keys())

    entry_context = {'ServiceNow.Ticket(val.ID===obj.ID)': get_ticket_context(ticket, additional_fields_keys)}

    return human_readable, entry_context, result, True


def create_ticket_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
    """Create a ticket.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    fields_delimiter = args.get('fields_delimiter', ';')
    custom_fields = split_fields(str(args.get('custom_fields', '')), fields_delimiter)
    template = args.get('template')
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))
    additional_fields = split_fields(str(args.get('additional_fields', '')), fields_delimiter)
    additional_fields_keys = list(additional_fields.keys())
    input_display_value = argToBoolean(args.get('input_display_value', 'false'))

    if template:
        template = client.get_template(template)
    fields = get_ticket_fields(args, template, ticket_type)
    if additional_fields:
        fields.update(additional_fields)

    result = client.create(ticket_type, fields, custom_fields, input_display_value)

    if not result or 'result' not in result:
        if 'successfully' in result:
            return result, {}, {}, True
        raise Exception('Unable to retrieve response.')
    ticket = result['result']

    hr_ = get_ticket_human_readable(ticket, ticket_type, additional_fields_keys)
    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Approval',
               'Created On', 'Created By', 'Active', 'Close Notes', 'Close Code', 'Description', 'Opened At',
               'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description', 'Additional Comments']
    if additional_fields:
        headers.extend(additional_fields_keys)
    human_readable = tableToMarkdown('ServiceNow ticket was created successfully.', t=hr_,
                                     headers=headers, removeNull=True)

    # make the modified fields the user inserted as arguments show in the context
    if additional_fields:
        additional_fields_keys = list(set(additional_fields_keys).union(set(args.keys())))
    else:
        additional_fields_keys = list(args.keys())

    created_ticket_context = get_ticket_context(ticket, additional_fields_keys)
    entry_context = {
        'Ticket(val.ID===obj.ID)': created_ticket_context,
        'ServiceNow.Ticket(val.ID===obj.ID)': created_ticket_context
    }

    return human_readable, entry_context, result, True


def delete_ticket_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
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

    return f'Ticket with ID {ticket_id} was successfully deleted.', {}, result, True


def query_tickets_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
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
    system_params = split_fields(args.get('system_params', ''))
    additional_fields = argToList(str(args.get('additional_fields')))

    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))

    result = client.query(ticket_type, sys_param_limit, sys_param_offset, sys_param_query, system_params)

    if not result or 'result' not in result or len(result['result']) == 0:
        return 'No ServiceNow tickets matched the query.', {}, {}, True
    tickets = result.get('result', {})
    hr_ = get_ticket_human_readable(tickets, ticket_type, additional_fields)
    context = get_ticket_context(tickets, additional_fields)

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code', 'Description', 'Opened At', 'Due Date', 'Resolved By',
               'Resolved At', 'SLA Due', 'Short Description', 'Additional Comments']
    if additional_fields:
        headers.extend(additional_fields)
    human_readable = tableToMarkdown('ServiceNow tickets', t=hr_, headers=headers, removeNull=True)
    entry_context = {
        'Ticket(val.ID===obj.ID)': context,
        'ServiceNow.Ticket(val.ID===obj.ID)': context
    }

    return human_readable, entry_context, result, True


def add_link_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
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

    return human_readable, {}, result, True


def add_comment_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
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
        raise Exception('Unable to retrieve response.')

    headers = ['System ID', 'Number', 'Impact', 'Urgency', 'Severity', 'Priority', 'State', 'Created On', 'Created By',
               'Active', 'Close Notes', 'Close Code',
               'Description', 'Opened At', 'Due Date', 'Resolved By', 'Resolved At', 'SLA Due', 'Short Description',
               'Additional Comments']
    hr_ = get_ticket_human_readable(result['result'], ticket_type)
    human_readable = tableToMarkdown('Comment successfully added to ServiceNow ticket', t=hr_,
                                     headers=headers, removeNull=True)

    return human_readable, {}, result, True


def upload_file_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
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

    file_name = args.get('file_name')
    if not file_name:
        file_data = demisto.getFilePath(file_id)
        file_name = file_data.get('name')

    result = client.upload_file(ticket_id, file_id, file_name, ticket_type)

    if not result or 'result' not in result or not result['result']:
        raise Exception('Unable to upload file.')
    uploaded_file_resp = result.get('result', {})

    hr_ = {
        'Filename': uploaded_file_resp.get('file_name'),
        'Download link': uploaded_file_resp.get('download_link'),
        'System ID': uploaded_file_resp.get('sys_id')
    }
    human_readable = tableToMarkdown(f'File uploaded successfully to ticket {ticket_id}.', t=hr_)
    context = {
        'ID': ticket_id,
        'File': {
            'Filename': uploaded_file_resp.get('file_name'),
            'Link': uploaded_file_resp.get('download_link'),
            'SystemID': uploaded_file_resp.get('sys_id')
        }
    }
    entry_context = {
        'ServiceNow.Ticket(val.ID===obj.ID)': context,
        'Ticket(val.ID===obj.ID)': context
    }

    return human_readable, entry_context, result, True


def add_tag_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
    """Add tag to a ticket.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    ticket_id = str(args.get('id', ''))
    tag_id = str(args.get('tag_id', ''))
    title = str(args.get('title', ''))
    ticket_type = client.get_table_name(str(args.get('ticket_type', '')))

    result = client.add_tag(ticket_id, tag_id, title, ticket_type)
    if not result or 'result' not in result:
        raise Exception(f'Could not add tag {title} to ticket {ticket_id}.')

    added_tag_resp = result.get('result', {})
    hr_ = {
        'Title': added_tag_resp.get('title'),
        'Ticket ID': added_tag_resp.get('id_display'),
        'Ticket Type': added_tag_resp.get('id_type'),
        'Tag ID': added_tag_resp.get('sys_id'),
    }
    human_readable = tableToMarkdown(f'Tag {tag_id} was added successfully to ticket {ticket_id}.', t=hr_)
    context = {
        'ID': ticket_id,
        'TagTitle': added_tag_resp.get('title'),
        'TagID': added_tag_resp.get('sys_id'),
    }
    entry_context = {'ServiceNow.Ticket(val.ID===obj.ID)': context}

    return human_readable, entry_context, result, True


def get_ticket_notes_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
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
        return f'No comment found on ticket {ticket_id}.', {}, {}, True

    headers = ['Value', 'CreatedOn', 'CreatedBy', 'Type']

    mapped_notes = [{
        'Value': note.get('value'),
        'CreatedOn': note.get('sys_created_on'),
        'CreatedBy': note.get('sys_created_by'),
        'Type': 'Work Note' if note.get('element', '') == 'work_notes' else 'Comment'
    } for note in result['result']]

    if not mapped_notes:
        return f'No comment found on ticket {ticket_id}.', {}, {}, True

    ticket = {
        'ID': ticket_id,
        'Note': mapped_notes
    }

    human_readable = tableToMarkdown(f'ServiceNow notes for ticket {ticket_id}', t=mapped_notes, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    entry_context = {'ServiceNow.Ticket(val.ID===obj.ID)': createContext(ticket, removeNull=True)}

    return human_readable, entry_context, result, True


def get_record_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
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
        return f'ServiceNow record with ID {record_id} was not found.', {}, {}, True

    if isinstance(result['result'], list):
        if len(result['result']) == 0:
            return f'ServiceNow record with ID {record_id} was not found.', {}, result, True
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

    return human_readable, entry_context, result, True


def create_record_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Any, bool]:
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
    input_display_value = argToBoolean(args.get('input_display_value', 'false'))
    fields_delimiter = args.get('fields_delimiter', ';')

    fields = {}
    if fields_str:
        fields = split_fields(fields_str, fields_delimiter)
    custom_fields = {}
    if custom_fields_str:
        custom_fields = split_fields(custom_fields_str, fields_delimiter)

    result = client.create(table_name, fields, custom_fields, input_display_value)

    if not result or 'result' not in result:
        return 'Could not create record.', {}, {}, True

    record = result.get('result', {})
    mapped_record = {DEFAULT_RECORD_FIELDS[k]: record[k] for k in DEFAULT_RECORD_FIELDS if k in record}

    human_readable = tableToMarkdown('ServiceNow record created successfully', mapped_record, removeNull=True)
    entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_record)}

    return human_readable, entry_context, result, True


def update_record_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
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
    input_display_value = argToBoolean(args.get('input_display_value', 'false'))
    fields_delimiter = args.get('fields_delimiter', ';')

    fields = {}
    if fields_str:
        fields = split_fields(fields_str, fields_delimiter)
    custom_fields = {}
    if custom_fields_str:
        custom_fields = split_fields(custom_fields_str, fields_delimiter)

    result = client.update(table_name, record_id, fields, custom_fields, input_display_value)

    if not result or 'result' not in result:
        return 'Could not retrieve record.', {}, {}, True

    record = result.get('result', {})
    mapped_record = {DEFAULT_RECORD_FIELDS[k]: record[k] for k in DEFAULT_RECORD_FIELDS if k in record}
    human_readable = tableToMarkdown(f'ServiceNow record with ID {record_id} updated successfully',
                                     t=mapped_record, removeNull=True)
    entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_record)}

    return human_readable, entry_context, result, True


def delete_record_command(client: Client, args: dict) -> Tuple[str, Dict[Any, Any], Dict, bool]:
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

    return f'ServiceNow record with ID {record_id} was successfully deleted.', {}, result, True


def query_table_command(client: Client, args: dict) -> Tuple[str, Dict, Dict, bool]:
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
    system_params = split_fields(args.get('system_params', ''))
    sys_param_offset = args.get('offset', client.sys_param_offset)
    fields = args.get('fields')

    result = client.query(table_name, sys_param_limit, sys_param_offset, sys_param_query, system_params)
    if not result or 'result' not in result or len(result['result']) == 0:
        return 'No results found', {}, {}, False
    table_entries = result.get('result', {})

    if fields:
        fields = argToList(fields)
        if 'sys_id' not in fields:
            # ID is added by default
            fields.append('sys_id')
        # Filter the records according to the given fields
        records = [dict([kv_pair for kv_pair in iter(r.items()) if kv_pair[0] in fields]) for r in table_entries]
        for record in records:
            record['ID'] = record.pop('sys_id')
            for k, v in record.items():
                if isinstance(v, dict):
                    # For objects that refer to a record in the database, take their value (system ID).
                    record[k] = v.get('value', v)
        human_readable = tableToMarkdown('ServiceNow records', records, removeNull=True)
        entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(records)}
    else:
        mapped_records = [{DEFAULT_RECORD_FIELDS[k]: r[k] for k in DEFAULT_RECORD_FIELDS if k in r}
                          for r in table_entries]
        human_readable = tableToMarkdown('ServiceNow records', mapped_records, removeNull=True)
        entry_context = {'ServiceNow.Record(val.ID===obj.ID)': createContext(mapped_records)}

    return human_readable, entry_context, result, False


def query_computers_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
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
        return 'No computers found.', {}, {}, False

    computers = result.get('result', {})
    if not isinstance(computers, list):
        computers = [computers]

    if len(computers) == 0:
        return 'No computers found.', {}, {}, False

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
                                     removeNull=True, headerTransform=pascalToSpace)
    entry_context = {'ServiceNow.Computer(val.ID===obj.ID)': createContext(mapped_computers, removeNull=True)}

    return human_readable, entry_context, result, False


def query_groups_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
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
        return 'No groups found.', {}, {}, False

    groups = result.get('result', {})
    if not isinstance(groups, list):
        groups = [groups]

    if len(groups) == 0:
        return 'No groups found.', {}, {}, False

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
                                     removeNull=True, headerTransform=pascalToSpace)
    entry_context = {'ServiceNow.Group(val.ID===obj.ID)': createContext(mapped_groups, removeNull=True)}

    return human_readable, entry_context, result, False


def query_users_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
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
        return 'No users found.', {}, {}, False

    users = result.get('result', {})
    if not isinstance(users, list):
        users = [users]

    if len(users) == 0:
        return 'No users found.', {}, {}, False

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

    return human_readable, entry_context, result, False


def list_table_fields_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
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
        return 'Table was not found.', {}, {}, False

    if len(result['result']) == 0:
        return 'Table contains no records.', {}, {}, False

    fields = [{'Name': k} for k, v in result['result'][0].items()]

    human_readable = tableToMarkdown(f'ServiceNow Table fields - {table_name}', fields)
    entry_context = {'ServiceNow.Field': createContext(fields)}

    return human_readable, entry_context, result, False


def get_table_name_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
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
        return 'Table was not found.', {}, {}, False
    tables = result.get('result', {})
    if len(tables) == 0:
        return 'Table was not found.', {}, {}, False

    headers = ['ID', 'Name', 'SystemName']

    mapped_tables = [{
        'ID': table.get('sys_id'),
        'Name': table.get('name'),
        'SystemName': table.get('sys_name')
    } for table in tables]

    human_readable = tableToMarkdown(f'ServiceNow Tables for label - {label}', t=mapped_tables,
                                     headers=headers, headerTransform=pascalToSpace)
    entry_context = {'ServiceNow.Table(val.ID===obj.ID)': createContext(mapped_tables)}

    return human_readable, entry_context, result, False


def query_items_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
    """Query items.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    table_name = 'sc_cat_item'
    limit = args.get('limit', client.sys_param_limit)
    offset = args.get('offset', client.sys_param_offset)
    name = str(args.get('name', ''))
    items_query = f'nameLIKE{name}' if name else ''

    result = client.query(table_name, limit, offset, items_query)
    if not result or 'result' not in result:
        return 'No items were found.', {}, {}, True
    items = result.get('result', {})
    if not isinstance(items, list):
        items_list = [items]
    else:
        items_list = items
    if len(items_list) == 0:
        return 'No items were found.', {}, {}, True

    mapped_items = []
    for item in items_list:
        mapped_items.append(get_item_human_readable(item))

    headers = ['ID', 'Name', 'Price', 'Description']
    human_readable = tableToMarkdown('ServiceNow Catalog Items', mapped_items, headers=headers,
                                     removeNull=True, headerTransform=pascalToSpace)
    entry_context = {'ServiceNow.CatalogItem(val.ID===obj.ID)': createContext(mapped_items, removeNull=True)}

    return human_readable, entry_context, result, True


def get_item_details_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
    """Get item details.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    id_ = str(args.get('id', ''))
    result = client.get_item_details(id_)
    if not result or 'result' not in result:
        return 'Item was not found.', {}, {}, True
    item = result.get('result', {})
    mapped_item = get_item_human_readable(item)

    human_readable = tableToMarkdown('ServiceNow Catalog Item', t=mapped_item, headers=['ID', 'Name', 'Description'],
                                     removeNull=True, headerTransform=pascalToSpace)
    if mapped_item.get('Variables'):
        human_readable += tableToMarkdown('Item Variables', t=mapped_item.get('Variables'),
                                          headers=['Question', 'Type', 'Name', 'Mandatory'],
                                          removeNull=True, headerTransform=pascalToSpace)
    entry_context = {'ServiceNow.CatalogItem(val.ID===obj.ID)': createContext(mapped_item, removeNull=True)}
    return human_readable, entry_context, result, True


def create_order_item_command(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
    """Create item order.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    id_ = str(args.get('id', ''))
    quantity = str(args.get('quantity', '1'))
    variables = split_fields(str(args.get('variables', '')))

    result = client.create_item_order(id_, quantity, variables)
    if not result or 'result' not in result:
        return 'Order item was not created.', {}, {}, True
    order_item = result.get('result', {})

    mapped_item = {
        'ID': order_item.get('sys_id'),
        'RequestNumber': order_item.get('request_number')
    }
    human_readable = tableToMarkdown('ServiceNow Order Request', mapped_item,
                                     removeNull=True, headerTransform=pascalToSpace)
    entry_context = {'ServiceNow.OrderRequest(val.ID===obj.ID)': createContext(mapped_item, removeNull=True)}

    return human_readable, entry_context, result, True


def document_route_to_table(client: Client, args: dict) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any], bool]:
    """Document routes to table.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    queue_id = str(args.get('queue_id', ''))
    document_table = str(args.get('document_table', ''))
    document_id = str(args.get('document_id', ''))

    result = client.document_route_to_table_request(queue_id, document_table, document_id)
    if not result or 'result' not in result:
        return 'Route to table was not found.', {}, {}, True

    route = result.get('result', {})
    context = {
        'DisplayName': route.get('display_name'),
        'DocumentID': route.get('document_id'),
        'DocumentTable': route.get('document_table'),
        'QueueID': route.get('queue'),
        'WorkItemID': route.get('sys_id')
    }

    headers = ['DisplayName', 'DocumentID', 'DocumentTable', 'QueueID', 'WorkItemID']
    human_readable = tableToMarkdown('ServiceNow Queue', t=context, headers=headers, removeNull=True,
                                     headerTransform=pascalToSpace)
    entry_context = {'ServiceNow.WorkItem(val.WorkItemID===obj.WorkItemID)': createContext(context, removeNull=True)}

    return human_readable, entry_context, result, True


def fetch_incidents(client: Client) -> list:
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

    demisto.info(f'Fetching ServiceNow incidents. with the query params: {str(query_params)}')
    res = client.send_request(f'table/{client.ticket_type}', 'GET', params=query_params)

    count = 0
    parsed_snow_time = datetime.strptime(snow_time, '%Y-%m-%d %H:%M:%S')

    severity_map = {'1': 3, '2': 2, '3': 1}  # Map SNOW severity to Demisto severity for incident creation

    for result in res.get('result', []):
        labels = []

        result['mirror_direction'] = MIRROR_DIRECTION.get(demisto.params().get('mirror_direction'))
        result['mirror_tags'] = [
            demisto.params().get('comment_tag'),
            demisto.params().get('file_tag'),
            demisto.params().get('work_notes_tag')
        ]
        result['mirror_instance'] = demisto.integrationInstance()

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
            file_entries = client.get_ticket_attachment_entries(result.get('sys_id', ''))
            if isinstance(file_entries, list):
                for file_result in file_entries:
                    if file_result['Type'] == entryTypes['error']:
                        raise Exception(f"Error getting attachment: {str(file_result.get('Contents', ''))}")
                    file_names.append({
                        'path': file_result.get('FileID', ''),
                        'name': file_result.get('File', '')
                    })

        incidents.append({
            'name': f"ServiceNow Incident {result.get(client.incident_name)}",
            'labels': labels,
            'details': json.dumps(result),
            'severity': severity,
            'attachment': file_names,
            'rawJSON': json.dumps(result)
        })

        count += 1
        snow_time = result.get(client.timestamp_field)

    demisto.setLastRun({'time': snow_time})
    return incidents


def test_instance(client: Client):
    """
    The function that executes the logic for the instance testing. If the instance wasn't configured correctly, this
    function will raise an exception and cause the test_module/oauth_test_module function to fail.
    """
    # Validate fetch_time parameter is valid (if not, parse_date_range will raise the error message)
    parse_date_range(client.fetch_time, '%Y-%m-%d %H:%M:%S')

    result = client.send_request(f'table/{client.ticket_type}', params={'sysparm_limit': 1}, method='GET')
    if 'result' not in result:
        raise Exception('ServiceNow error: ' + str(result))
    ticket = result.get('result')
    if ticket and demisto.params().get('isFetch'):
        if isinstance(ticket, list):
            ticket = ticket[0]
        if client.timestamp_field not in ticket:
            raise ValueError(f"The timestamp field [{client.timestamp_field}] does not exist in the ticket.")
        if client.incident_name not in ticket:
            raise ValueError(f"The field [{client.incident_name}] does not exist in the ticket.")


def test_module(client: Client, *_) -> Tuple[str, Dict[Any, Any], Dict[Any, Any], bool]:
    """
    Test the instance configurations when using basic authorization.
    """
    # Notify the user that test button can't be used when using OAuth 2.0:
    if client.use_oauth:
        raise Exception('Test button cannot be used when using OAuth 2.0. Please use the !servicenow-oauth-login '
                        'command followed by the !servicenow-oauth-test command to test the instance.')

    if client._version == 'v2' and client.get_attachments:
        raise DemistoException('Retrieving incident attachments is not supported when using the V2 API.')

    test_instance(client)
    return 'ok', {}, {}, True


def oauth_test_module(client: Client, *_) -> Tuple[str, Dict[Any, Any], Dict[Any, Any], bool]:
    """
    Test the instance configurations when using OAuth authentication.
    """
    if not client.use_oauth:
        raise Exception('!servicenow-oauth-test command should be used only when using OAuth 2.0 authorization.\n '
                        'Please select the `Use OAuth Login` checkbox in the instance configuration before running '
                        'this command.')

    test_instance(client)
    hr = '### Instance Configured Successfully.\n'
    return hr, {}, {}, True


def login_command(client: Client, args: Dict[str, Any]) -> Tuple[str, Dict[Any, Any], Dict[Any, Any], bool]:
    """
    Login the user using OAuth authorization
    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    # Verify that the user checked the `Use OAuth` checkbox:
    if not client.use_oauth:
        raise Exception('!servicenow-oauth-login command can be used only when using OAuth 2.0 authorization.\n Please '
                        'select the `Use OAuth Login` checkbox in the instance configuration before running this '
                        'command.')

    username = args.get('username', '')
    password = args.get('password', '')
    try:
        client.snow_client.login(username, password)
        hr = '### Logged in successfully.\n A refresh token was saved to the integration context. This token will be ' \
             'used to generate a new access token once the current one expires.'
    except Exception as e:
        return_error(f'Failed to login. Please verify that the provided username and password are correct, and that you '
                     f'entered the correct client id and client secret in the instance configuration (see ? for'
                     f'correct usage when using OAuth).\n\n{e}')
    return hr, {}, {}, True


def get_remote_data_command(client: Client, args: Dict[str, Any], params: Dict) -> Union[List[Dict[str, Any]], str]:
    """
    get-remote-data command: Returns an updated incident and entries
    Args:
        client: XSOAR client to use
        args:
            id: incident id to retrieve
            lastUpdate: when was the last time we retrieved data

    Returns:
        List[Dict[str, Any]]: first entry is the incident (which can be completely empty) and the new entries.
    """

    ticket_id = args.get('id', '')
    demisto.debug(f'Getting update for remote {ticket_id}')
    last_update = arg_to_timestamp(
        arg=args.get('lastUpdate'),
        arg_name='lastUpdate',
        required=True
    )
    demisto.debug(f'last_update is {last_update}')

    ticket_type = client.ticket_type
    result = client.get(ticket_type, ticket_id)

    if not result or 'result' not in result:
        return 'Ticket was not found.'

    if isinstance(result['result'], list):
        if len(result['result']) == 0:
            return 'Ticket was not found.'

        ticket = result['result'][0]

    else:
        ticket = result['result']

    ticket_last_update = arg_to_timestamp(
        arg=ticket.get('sys_updated_on'),
        arg_name='sys_updated_on',
        required=False
    )

    demisto.debug(f'ticket_last_update is {ticket_last_update}')

    if last_update > ticket_last_update:
        demisto.debug('Nothing new in the ticket')
        ticket = {}

    else:
        demisto.debug(f'ticket is updated: {ticket}')

    # get latest comments and files
    entries = []
    file_entries = client.get_ticket_attachment_entries(ticket_id, datetime.fromtimestamp(last_update))  # type: ignore
    if file_entries:
        for file in file_entries:
            if '_mirrored_from_xsoar' not in file.get('File'):
                entries.append(file)

    sys_param_limit = args.get('limit', client.sys_param_limit)
    sys_param_offset = args.get('offset', client.sys_param_offset)

    sys_param_query = f'element_id={ticket_id}^sys_created_on>' \
        f'{datetime.fromtimestamp(last_update)}^element=comments^ORelement=work_notes'

    comments_result = client.query('sys_journal_field', sys_param_limit, sys_param_offset, sys_param_query)
    demisto.debug(f'Comments result is {comments_result}')

    if not comments_result or 'result' not in comments_result:
        demisto.debug(f'Pull result is {ticket}')
        return [ticket] + entries

    for note in comments_result.get('result', []):
        if 'Mirrored from Cortex XSOAR' not in note.get('value'):
            comments_context = {'comments_and_work_notes': note.get('value')}
            entries.append({
                'Type': note.get('type'),
                'Category': note.get('category'),
                'Contents': note.get('value'),
                'ContentsFormat': note.get('format'),
                'Tags': note.get('tags'),
                'Note': True,
                'EntryContext': comments_context
            })
    # Parse user dict to email
    assigned_to = ticket.get('assigned_to', {})
    caller = ticket.get('caller_id', {})
    assignment_group = ticket.get('assignment_group', {})

    if assignment_group:
        group_result = client.get('sys_user_group', assignment_group.get('value'))
        group = group_result.get('result', {})
        group_name = group.get('name')
        ticket['assignment_group'] = group_name

    if assigned_to:
        user_result = client.get('sys_user', assigned_to.get('value'))
        user = user_result.get('result', {})
        user_email = user.get('email')
        ticket['assigned_to'] = user_email

    if caller:
        user_result = client.get('sys_user', caller.get('value'))
        user = user_result.get('result', {})
        user_email = user.get('email')
        ticket['caller_id'] = user_email

    if ticket.get('resolved_by') or ticket.get('closed_at'):
        if params.get('close_incident'):
            demisto.debug(f'ticket is closed: {ticket}')
            entries.append({
                'Type': EntryType.NOTE,
                'Contents': {
                    'dbotIncidentClose': True,
                    'closeReason': f'From ServiceNow: {ticket.get("close_notes")}'
                },
                'ContentsFormat': EntryFormat.JSON
            })

    demisto.debug(f'Pull result is {ticket}')
    return [ticket] + entries


def update_remote_system_command(client: Client, args: Dict[str, Any], params: Dict[str, Any]) -> str:
    """
    This command pushes local changes to the remote system.
    Args:
        client:  XSOAR Client to use.
        args:
            args['data']: the data to send to the remote system
            args['entries']: the entries to send to the remote system
            args['incident_changed']: boolean telling us if the local incident indeed changed or not
            args['remote_incident_id']: the remote incident id
        params:
            entry_tags: the tags to pass to the entries (to separate between comments and work_notes)

    Returns: The remote incident id - ticket_id

    """
    parsed_args = UpdateRemoteSystemArgs(args)
    if parsed_args.delta:
        demisto.debug(f'Got the following delta keys {str(list(parsed_args.delta.keys()))}')

    ticket_type = client.ticket_type
    ticket_id = parsed_args.remote_incident_id
    if parsed_args.incident_changed:
        demisto.debug(f'Incident changed: {parsed_args.incident_changed}')
        # Closing sc_type ticket. This ticket type can be closed only when changing the ticket state.
        if (ticket_type == 'sc_task' or ticket_type == 'sc_req_item')\
                and parsed_args.inc_status == IncidentStatus.DONE and params.get('close_ticket'):
            parsed_args.data['state'] = '3'
        # Closing incident ticket.
        if ticket_type == 'incident' and parsed_args.inc_status == IncidentStatus.DONE and params.get('close_ticket'):
            parsed_args.data['state'] = '7'

        fields = get_ticket_fields(parsed_args.data, ticket_type=ticket_type)
        if not params.get('close_ticket'):
            fields = {key: val for key, val in fields.items() if key != 'closed_at' and key != 'resolved_at'}

        demisto.debug(f'Sending update request to server {ticket_type}, {ticket_id}, {fields}')
        result = client.update(ticket_type, ticket_id, fields)

        demisto.info(f'Ticket Update result {result}')

    entries = parsed_args.entries
    if entries:
        demisto.debug(f'New entries {entries}')

        for entry in entries:
            demisto.debug(f'Sending entry {entry.get("id")}, type: {entry.get("type")}')
            # Mirroring files as entries
            if entry.get('type') == 3:
                path_res = demisto.getFilePath(entry.get('id'))
                full_file_name = path_res.get('name')
                file_name, file_extension = os.path.splitext(full_file_name)
                if not file_extension:
                    file_extension = ''
                client.upload_file(ticket_id, entry.get('id'), file_name + '_mirrored_from_xsoar' + file_extension,
                                   ticket_type)
            else:
                # Mirroring comment and work notes as entries
                tags = entry.get('tags', [])
                key = ''
                if params.get('work_notes_tag') in tags:
                    key = 'work_notes'
                elif params.get('comment_tag') in tags:
                    key = 'comments'
                user = entry.get('user', 'dbot')
                text = f"({user}): {str(entry.get('contents', ''))}\n\n Mirrored from Cortex XSOAR"
                client.add_comment(ticket_id, ticket_type, key, text)

    return ticket_id


def get_mapping_fields_command(client: Client) -> GetMappingFieldsResponse:
    """
    Returns the list of fields for an incident type.
    Args:
        client: XSOAR client to use

    Returns: Dictionary with keys as field names

    """

    incident_type_scheme = SchemeTypeMapping(type_name=client.ticket_type)
    demisto.debug(f'Collecting incident mapping for incident type - "{client.ticket_type}"')

    for field in SNOW_ARGS:
        incident_type_scheme.add_field(field)

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def get_modified_remote_data_command(
        client: Client,
        args: Dict[str, str],
        update_timestamp_field: str = 'sys_updated_on',
        mirror_limit: str = '100',
) -> GetModifiedRemoteDataResponse:
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'}).strftime('%Y-%m-%d %H:%M:%S')

    demisto.debug(f'Running get-modified-remote-data command. Last update is: {last_update}')

    result = client.query(
        table_name=client.ticket_type,
        sys_param_limit=mirror_limit,
        sys_param_offset=str(client.sys_param_offset),
        sys_param_query=f'{update_timestamp_field}>{last_update}',
        sysparm_fields='sys_id',
    )

    modified_records_ids = []

    if result and (modified_records := result.get('result')):
        modified_records_ids = [record.get('sys_id') for record in modified_records if 'sys_id' in record]

    return GetModifiedRemoteDataResponse(modified_records_ids)


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    command = demisto.command()
    LOG(f'Executing command {command}')

    params = demisto.params()
    verify = not params.get('insecure', False)
    use_oauth = params.get('use_oauth', False)
    oauth_params = {}

    if use_oauth:  # if the `Use OAuth` checkbox was checked, client id & secret should be in the credentials fields
        username = ''
        password = ''
        client_id = params.get('credentials', {}).get('identifier')
        client_secret = params.get('credentials', {}).get('password')
        oauth_params = {
            'credentials': {
                'identifier': username,
                'password': password
            },
            'client_id': client_id,
            'client_secret': client_secret,
            'url': params.get('url'),
            'headers': {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            'verify': verify,
            'proxy': params.get('proxy'),
            'use_oauth': use_oauth
        }
    else:  # use basic authentication
        username = params.get('credentials', {}).get('identifier')
        password = params.get('credentials', {}).get('password')

    version = params.get('api_version')
    if version:
        api = f'/api/now/{version}/'
        sc_api = f'/api/sn_sc/{version}/'
    else:
        api = '/api/now/'
        sc_api = '/api/sn_sc/'
    server_url = params.get('url')
    sc_server_url = f'{get_server_url(server_url)}{sc_api}'
    server_url = f'{get_server_url(server_url)}{api}'

    fetch_time = params.get('fetch_time', '10 minutes').strip()
    sysparm_query = params.get('sysparm_query')
    sysparm_limit = int(params.get('fetch_limit', 10))
    timestamp_field = params.get('timestamp_field', 'opened_at')
    ticket_type = params.get('ticket_type', 'incident')
    incident_name = params.get('incident_name', 'number') or 'number'
    get_attachments = params.get('get_attachments', False)
    update_timestamp_field = params.get('update_timestamp_field', 'sys_updated_on') or 'sys_updated_on'
    mirror_limit = params.get('mirror_limit', '100') or '100'

    raise_exception = False
    try:
        client = Client(server_url=server_url, sc_server_url=sc_server_url, username=username, password=password,
                        verify=verify, fetch_time=fetch_time, sysparm_query=sysparm_query, sysparm_limit=sysparm_limit,
                        timestamp_field=timestamp_field, ticket_type=ticket_type, get_attachments=get_attachments,
                        incident_name=incident_name, oauth_params=oauth_params, version=version)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any], bool]]] = {
            'test-module': test_module,
            'servicenow-oauth-test': oauth_test_module,
            'servicenow-oauth-login': login_command,
            'servicenow-update-ticket': update_ticket_command,
            'servicenow-create-ticket': create_ticket_command,
            'servicenow-delete-ticket': delete_ticket_command,
            'servicenow-query-tickets': query_tickets_command,
            'servicenow-add-link': add_link_command,
            'servicenow-add-comment': add_comment_command,
            'servicenow-upload-file': upload_file_command,
            'servicenow-add-tag': add_tag_command,
            'servicenow-get-ticket-notes': get_ticket_notes_command,
            'servicenow-get-record': get_record_command,
            'servicenow-update-record': update_record_command,
            'servicenow-create-record': create_record_command,
            'servicenow-delete-record': delete_record_command,
            'servicenow-query-table': query_table_command,
            'servicenow-list-table-fields': list_table_fields_command,
            'servicenow-query-computers': query_computers_command,
            'servicenow-query-groups': query_groups_command,
            'servicenow-query-users': query_users_command,
            'servicenow-get-table-name': get_table_name_command,
            'servicenow-query-items': query_items_command,
            'servicenow-get-item-details': get_item_details_command,
            'servicenow-create-item-order': create_order_item_command,
            'servicenow-document-route-to-queue': document_route_to_table,
        }
        args = demisto.args()
        if command == 'fetch-incidents':
            raise_exception = True
            incidents = fetch_incidents(client)
            demisto.incidents(incidents)
        elif command == 'servicenow-get-ticket':
            demisto.results(get_ticket_command(client, args))
        elif command == 'get-remote-data':
            return_results(get_remote_data_command(client, demisto.args(), demisto.params()))
        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client, demisto.args(), demisto.params()))
        elif demisto.command() == 'get-mapping-fields':
            return_results(get_mapping_fields_command(client))
        elif demisto.command() == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client, args, update_timestamp_field, mirror_limit))
        elif command in commands:
            md_, ec_, raw_response, ignore_auto_extract = commands[command](client, args)
            return_outputs(md_, ec_, raw_response, ignore_auto_extract=ignore_auto_extract)
        else:
            raise_exception = True
            raise NotImplementedError(f'{COMMAND_NOT_IMPLEMENTED_MSG}: {demisto.command()}')

    except Exception as err:
        LOG(err)
        LOG.print_log()
        if not raise_exception:
            return_error(f'Unexpected error: {str(err)}', error=traceback.format_exc())
        else:
            raise


from ServiceNowApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
