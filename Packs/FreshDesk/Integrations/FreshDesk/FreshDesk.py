import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''


import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()
# Remove proxy if not set to true in params
handle_proxy(proxy_param_name='proxy')
''' GLOBALS/PARAMS '''

PARAMS = demisto.params()
CREDS = PARAMS.get('credentials')
USERNAME = CREDS.get('identifier') if CREDS else None
PASSWORD = CREDS.get('password') if CREDS else None
TOKEN = PARAMS.get('token_creds', {}).get('password') or PARAMS.get('token')

if not (USERNAME and PASSWORD) and not TOKEN:
    err_msg = 'You must provide either your Freshdesk account API key or the ' \
              'username and password you use to sign into your Freshdesk account ' \
              'when instantiating an instance of the Freshdesk integration.'
    return_error(err_msg)

AUTH = (TOKEN, 'X') if TOKEN else (USERNAME, PASSWORD)

# How much time before the first fetch to retrieve incidents
FETCH_TIME = PARAMS.get('fetch_time', '24 hours')
# Remove trailing slash to prevent wrong URL path to service
SERVER = PARAMS['url'].removesuffix('/')
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
# Service base URL
BASE_URL = SERVER + '/api/v2/'

# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
# Headers to be used when making a request to POST a multi-part encoded file
MULTIPART_HEADERS = {'Accept': 'application/json'}

# Amount of results returned per fetch (default 50)
MAX_INCIDENTS = int(PARAMS.get('maxFetch', 50))

# Default amount of results returned per-page/per-api-call when the
# fd-search-tickets command's results that match the command's specified
# filter criteria exceeds 30
PER_PAGE = 30

# The API response ticket attributes that will be included
# in most command's context outputs
DEFAULT_TICKET_CONTEXT_FIELDS = [
    'priority', 'due_by', 'subject', 'status',
    'requester_id', 'tags', 'group_id', 'source', 'created_at',
    'responder_id', 'fr_due_by', 'id'
]


''' HELPER FUNCTIONS '''


def get_number_of_incidents_to_fetch():
    # FreshDesk API supports maximum of 100 tickets per page so if user asked for more, pagination is needed.
    return 100 if MAX_INCIDENTS >= 100 else MAX_INCIDENTS


def reformat_canned_response_context(context):
    """
    Reformat context for canned-response related commands (from having used string_to_context_key)
    to desired output format.

    parameter: (dict) context
        The context to reformat

    returns:
        The reformatted context
    """
    for key, val in list(context.items()):
        if 'Id' in key:
            new_key = key.replace('Id', 'ID')
            context[new_key] = val
            del context[key]
        elif 'Html' in key:
            new_key = key.replace('Html', 'HTML')
            context[new_key] = val
            del context[key]
    return context


def reformat_conversation_context(context):
    """
    Reformat context for conversation related commands (from having used string_to_context_key)
    to desired output format.

    parameter: (dict) context
        The context to reformat

    returns:
        The reformatted context
    """
    to_emails = context.get('ToEmails')
    body = context.get('Body')
    attachments = context.get('Attachments')
    if to_emails:
        context['ToEmail'] = to_emails
        del context['ToEmails']
    if body:
        context['BodyHTML'] = body
        del context['Body']
    if attachments:
        del context['Attachments']
    return context


def format_contact_context(contact):
    """
    Format context for contact related commands.

    parameter: (dict) contact
        The API response from executing a contact related command whose attributes need
        to be parsed into context

    returns:
        The formatted context
    """
    dont_include = ['other_companies', 'other_emails', 'custom_fields', 'avatar']
    # Parse response into context
    context = {}
    for key, val in contact.items():
        if key not in dont_include and val:
            new_key = string_to_context_key(key)
            if 'Id' in new_key:
                new_key = new_key.replace('Id', 'ID')
            elif new_key == 'Tags':
                new_key = 'Tag'
            context[new_key] = val
    return context


def reformat_ticket_context(context):
    """
    Reformat context outputs (from having used string_to_context_key) to desired output format.

    parameter: (dict) context
        The context to reformat

    returns:
        The reformatted context
    """
    standard_context_outputs = [
        'Priority', 'DueBy', 'Subject', 'Status', 'RequesterID',
        'Tag', 'GroupID', 'Source', 'CreatedAt', 'ResponderID',
        'FrDueBy', 'ID', 'UpdatedAt', 'Attachment', 'AdditionalFields',
        'UserID', 'BodyText', 'Category', 'Private', 'Incoming'
    ]

    for key, val in list(context.items()):
        if key == 'Tags':
            new_key = key[:-1]
            context[new_key] = val
            del context[key]
        elif key == 'CustomFields':
            new_key = key[:-1]
            context[new_key] = val
            del context[key]
        elif key == 'FwdEmails':
            new_key = key[:-1]
            context[new_key] = val
            del context[key]
        elif key == 'Description':
            new_key = 'DescriptionHTML'
            context[new_key] = val
            del context[key]
        elif 'Id' in key:
            new_key = key.replace('Id', 'ID')
            context[new_key] = val
            del context[key]
        elif 'Cc' in key:
            new_key = key.removesuffix('s').replace('Cc', 'CC')
            context[new_key] = val
            del context[key]

    # If 'Attachments' are still in context get rid of them - should be 'Attachment'
    attachments = context.get('Attachments')
    if attachments:
        del context['Attachments']

    new_context = {}
    new_context['AdditionalFields'] = context.get('AdditionalFields') if context.get('AdditionalFields') else {}
    additional_fields = {}
    for key, val in list(context.items()):
        if key not in standard_context_outputs:
            if not ((isinstance(val, dict | list)) and len(val) == 0):
                additional_fields[key] = val
        else:
            new_context[key] = val
    new_context['AdditionalFields'] = dict(new_context.get('AdditionalFields', {}), **additional_fields)
    return new_context


def handle_search_tickets_pagination(args, response, limit=-1):
    """
    Retrieve all resulting tickets even over the default 30 returned by a single API call.

    When the search_tickets_command results in more tickets than the default per page count (30) returned from
    making an API call, then this function retrieves the remaining tickets by iterating and making API calls
    per additional page of results.

    parameter: (dict) args
        search_tickets_command arguments

    parameter: (dict) response
        The initial json response from making an API call in the search_tickets function

    parameter: (int) limit
        Stops the pagination as soon as the number of tickets exceeds the limit (default -1 for no limit)

    returns:
        All Ticket Objects
    """
    # If user entered custom_query arg, the resulting tickets are in the 'results' attribute of the response
    if args.get('custom_query'):
        # Max page count allowed by API when using custom query
        max_pages = 10
        # Deal with pagination if necessary
        tickets = response.get('results')
        total_tickets = response.get('total')
        total_tickets -= PER_PAGE
        page = 1
        while total_tickets > 0 and page <= max_pages:
            page += 1
            args['page'] = page
            tickets_page = search_tickets(args)
            tickets.extend(tickets_page.get('results'))
            total_tickets -= PER_PAGE
    else:
        # Max page count allowed by API when using normal filters
        max_pages = 300
        tickets = response
        page = 1
        next_page = tickets
        while next_page and page <= max_pages:
            # Stop pagination if limit is defined and we exceeded it
            if 0 < limit <= len(tickets):
                break
            page += 1
            args['page'] = page
            next_page = search_tickets(args)
            if next_page:
                tickets.extend(next_page)
    return tickets


def attachments_into_context(api_response, context):
    """
    Get the attachments field from the api_response argument if present and parse it into the context.

    parameter: (dict) api_response
        The json response returned by the calling function's associated 'requests' function in which calls
        to the API are made.

    parameter: (dict) context
        The context that will be modified and returned to the war room

    returns:
        The modified context, and the modified context with the attachments in readable format for the
        human readable output
    """
    attachment_keys_to_include = [
        'attachment_url', 'content_type', 'id', 'name', 'size'
    ]

    context_readable = dict(**context)
    # Parse attachments into context
    attachments = api_response.get('attachments')
    if attachments:
        attachments_context = []
        attachments_context_readable = []
        for attachment in attachments:
            attachment_context = {}
            for key, val in attachment.items():
                if key in attachment_keys_to_include:
                    if key == 'attachment_url':
                        key = 'AttachmentURL'
                    elif key == 'id':
                        key = 'ID'
                    else:
                        key = string_to_context_key(key)
                    attachment_context[key] = val
            attachment_formatted = formatCell(attachment_context).split('\n')
            attachment_formatted = ', '.join(attachment_formatted)
            attachments_context_readable.append(attachment_formatted)

            attachments_context.append(attachment_context)
        context['Attachment'] = attachments_context
        context_readable['Attachment'] = attachments_context_readable
    return context, context_readable


def additional_fields_to_context(context, already_in_context, additional_fields, additional_values):
    """
    Parses fields not presented as part of the command's standard arguments into the context.

    For commands where the user can enter additional fields and their associated values beyond what
    is offered by the standard arguments (but are still supported by the API endpoint). If the additional
    fields are not part of the standard context output for that command, then those fields and values
    from the API call are parsed and subcategorized under the 'AdditionalFields' context output.

    parameter: (dict) context
        The context that will be modified and returned to the war room

    parameter: (list) already_in_context
        List of fields which are ordinarily/already parsed into the context

    parameter: (list) additional_fields
        List of the fields beyond the command's standard arguments that the user entered as part
        of the call to the API endpoint

    parameter: (list) additional_values
        List of values corresponding to the additional_fields argument

    returns:
        The modified context
    """
    # Parse additional fields into context
    if additional_fields and additional_values:
        added_context = {}
        for field, value in zip(additional_fields, additional_values):
            if field not in already_in_context and field != 'attachments':
                key = string_to_context_key(field)
                added_context[key] = value
        context['AdditionalFields'] = added_context
    return context


def additional_fields_to_args(args, additional_fields_arg_name):
    """
    Parses the additional_fields command argument for the individual fields and values and
    reassigns them to the args dictionary.

    parameter: (dict) args
        The command's arguments

    parameter: (string) additional_fields_arg_name
        The name of the command argument that contains the additional fields and values

    returns:
        The args dictionary that has been updated with the additional fields and values,
        the list of additional fields, and the list of additional values.
    """
    additional_fields = args.get(additional_fields_arg_name)
    if additional_fields:
        fields, values = [], []
        fields_and_vals = additional_fields.split(';')
        # For the case there is only one additional field + value
        if len(fields_and_vals) == 1:
            fields_and_vals = list(fields_and_vals)
        for field_and_val in fields_and_vals:
            field_and_val = field_and_val.split('=')
            # If the length doesn't equal 2, means there were either no equal signs or more than one
            if len(field_and_val) != 2:
                err_msg = 'It appears you entered either too many or too few' \
                          ' equal signs in the \'additional_fields\' argument.'
                return_error(err_msg)
            field = field_and_val[0].strip()
            val = field_and_val[1]

            # If the value contains commas, then it is a list
            if ',' in val:
                val = argToList(val)
            args[field] = val
            fields.append(field)
            values.append(val)
        del args[additional_fields_arg_name]
        return args, fields, values
    return args, None, None


def ticket_to_incident(ticket):
    """
    Create incident from ticket object.

    parameter: (object) ticket
        Ticket object

    returns:
        Incident Object
    """
    incident = {}
    # Incident Title
    subject = ticket.get('subject', '').encode('ascii', 'replace').decode("utf-8")
    incident['name'] = f'Freshdesk Ticket: "{subject}"'
    # Incident update time - the ticket's update time - The API does not support filtering tickets by creation time
    # but only by update time. The update time will be the creation time of the incidents and the incident id check will
    # prevent duplications of incidents.
    incident['occurred'] = ticket.get('updated_at')
    # The raw response from the service, providing full info regarding the item
    incident['rawJSON'] = json.dumps(ticket)
    return incident


def get_additional_fields(args):
    """
    Determine which fields need to be added to context based off arguments given in the search_tickets_command.

    parameter: (dict) args
        The search_tickets_command arguments

    returns:
        List of fields to be added to the context outputs
    """
    additional_fields = []  # fields that should be added to output context
    filter = args.get('filter')
    if filter:
        if filter == 'deleted':
            additional_fields.append('deleted')
        elif filter == 'spam':
            additional_fields.append('spam')
    requester = args.get('requester')
    if requester and '@' in requester:
        additional_fields.append('email')
    company_id = args.get('company_id')
    if company_id:
        additional_fields.append('company_id')
    if args.get('include_description') and args.get('include_description').lower() == 'yes':
        additional_fields.extend(['description', 'description_text'])
    return additional_fields


def entries_to_files(entry_ids):
    """
    Format file details (retrieved using the files' entry IDs) to API expectations to include files in API call.

    parameter: (list) entry_ids
        List of entry ID strings for files uploaded to the warroom

    returns:
        List of attachment field, value tuples formatted according to API expectations
    """
    attachments = []
    for entry_id in entry_ids:
        execute_results = demisto.getFilePath(entry_id)
        file_path = execute_results['path']
        file_name = execute_results['name']
        attachments.append(('attachments[]', (file_name, open(file_path, 'rb'))))

    return attachments


def handle_array_input(args):
    """
    Format any command argument that is supposed to be an array from a string to a list.

    parameter: (dict) args
        The command arguments dictionary

    returns:
        The arguments dict with field values transformed from strings to lists where necessary
    """
    array_inputs = [
        'tags', 'attachments', 'cc_emails', 'bcc_emails', 'to_emails',
        'update_fields', 'update_values', 'notify_emails'
    ]
    attchs_present = args.get('attachments')
    if attchs_present:
        for arr_input in array_inputs:
            if arr_input in args:
                if arr_input != 'attachments':
                    args[arr_input + '[]'] = argToList(args.get(arr_input))
                    del args[arr_input]
                else:
                    args[arr_input] = argToList(args.get(arr_input))
    else:
        for arr_input in array_inputs:
            if arr_input in args:
                args[arr_input] = argToList(args.get(arr_input))
    return args


def validate_priority_input(args):
    """
    Check entered value for command argument 'priority' and format to API expectations.

    parameter: (dict) args
        The command arguments dictionary

    returns:
        The arguments dict with the value for 'priority' field reformatted if necessary
    """
    # Parse and ensure valid command argument
    priority = args.get('priority', None)

    # If priority wasn't given by the user as a cmd arg
    # then no need to alter it to API expectations
    if not priority:
        return args

    priorities = ['low', 'medium', 'high', 'urgent']

    # Check if the user entered status as words - aka the
    # options listed above in 'statuses'
    err_msg = 'priority should be one of these values: 1, 2, 3, 4, {}'.format(', '.join(priorities))
    if len(priority) > 1:
        if priority.lower() in priorities:
            # Add 1 since API status numbers for tickets start at 1
            # Cast to string so clean_arguments helper function doesn't throw any errors
            args['priority'] = str(priorities.index(priority.lower()) + 1)
        else:
            return_error(err_msg)
    # Otherwise make sure the user entered valid status number
    elif not (0 < int(priority) < 5):
        return_error(err_msg)
    return args


def validate_status_input(args):
    """
    Check entered value for command argument 'status' and format to API expectations.

    parameter: (dict) args
        The command arguments dictionary

    returns:
        The arguments dict with the value for 'status' field reformatted if necessary
    """
    # Parse and ensure valid command argument
    status = args.get('status', None)

    # If status wasn't given by the user as a cmd arg
    # then no need to alter it to API expectations
    if not status:
        return args

    statuses = [
        'open', 'pending', 'resolved', 'closed',
        'waiting on customer', 'waiting on third party'
    ]

    # Check if the user entered status as words - aka the
    # options listed above in 'statuses'
    err_msg = 'status should be one of these values: 2, 3, 4, 5, 6, 7, {}'.format(', '.join(statuses))
    if len(status) > 1:
        if status.lower() in statuses:
            # Add 2 since API status numbers for tickets start at 2
            # Cast to string so clean_arguments helper function doesn't throw any errors
            args['status'] = str(statuses.index(status.lower()) + 2)
        else:
            return_error(err_msg)
    # Otherwise make sure the user entered valid status number
    elif not (1 < int(status) < 8):
        return_error(err_msg)
    return args


def handle_number_input(args):
    """
    Format any command argument that is supposed to be a number from a string to an int.

    parameter: (dict) args
        The command arguments dictionary

    returns:
        The arguments dict with field values transformed from strings to numbers where necessary
    """
    # Command args that should be numbers
    number_args = [
        'requester_id', 'status', 'priority', 'responder_id',
        'email_config_id', 'group_id', 'product_id', 'source', 'company_id'
    ]
    # Convert cmd args that are expected to be numbers from strings to numbers
    for num_arg in number_args:
        if num_arg in args:
            args[num_arg] = int(args.get(num_arg))
    return args


def clean_arguments(args):
    """
    Perform all validation and reformatting of command arguments.

    parameter: (dict) args
        The command arguments dictionary

    returns:
        The arguments dict with all field values reformatted where necessary
    """
    args = validate_status_input(args)
    args = validate_priority_input(args)
    args = handle_array_input(args)
    args = handle_number_input(args)
    return args


def determine_identifier(args):
    """
    Determine whether the input for the 'identifier' argument is an
    email or twitter handle and adjust 'args' accordingly.

    parameter: (dict) args
        The command arguments dictionary

    returns:
        The arguments dict with the email or twitter_id field (depending on what the value was)
        assigned the value entered for the 'identifier' argument
    """
    identifier = args.get('identifier')
    if identifier.startswith('@'):
        # Then it's a twitter handle
        args['twitter_id'] = identifier
    elif '@' in identifier:
        # Otherwise assume it's an email address
        args['email'] = identifier
    else:
        err_msg = 'The entered value for the \'identifier\' argument must ' \
                  'be either a Twitter handle or an Email Address.'
        return_error(err_msg)
    # Delete identifier field from args since it doesn't match API expected inputs
    del args['identifier']
    return args


def determine_responder(args):
    """
    Determine whether the input for the 'responder' argument is a group or an agent and adjust 'args' accordingly.

    parameter: (dict) args
        The command arguments dictionary

    returns:
        The arguments dict with the group_id or responder_id field (depending on what the value was)
        assigned the value entered for the 'responder' argument
    """
    responder = args.get('responder', None)
    if responder:
        args = determine_group(args, 'responder')
        args = determine_agent(args, 'responder')
    return args


def determine_agent(args, key_name):
    """
    Determine if the value points to an agent by checking against all agent names, emails, and IDs, and adjust
    'args' accordingly.

    parameter: (string) key_name
        The name of the command argument

    parameter: (dict) args
        The command arguments dictionary

    returns:
        The arguments dict with responder_id field assigned the appropriate value if the value passed
        for the command argument represented by 'key_name' is associated with an Agent's details
    """
    assigned_agent = args.get(key_name, None)
    if assigned_agent:
        agent_emails, agent_names, agent_ids = [], [], []
        # Get names, emails and ids of agents
        agents = list_agents()
        for agent in agents:
            agent_ids.append(agent.get('id'))
            contact_info = agent.get('contact')
            if contact_info:
                agent_names.append(contact_info.get('name', '').lower())
                agent_emails.append(contact_info.get('email', '').lower())
        # Check if responder value is a contact ID
        if assigned_agent in agent_ids:
            args['responder_id'] = assigned_agent
            # Delete assigned_agent field from args since it doesn't match API expected inputs
            del args[key_name]
        elif assigned_agent.lower() in agent_names:
            agent_name_idx = agent_names.index(assigned_agent.lower())
            args['responder_id'] = agent_ids[agent_name_idx]
            del args[key_name]
        elif assigned_agent.lower() in agent_emails:
            agent_email_idx = agent_emails.index(assigned_agent.lower())
            args['responder_id'] = agent_ids[agent_email_idx]
            del args[key_name]

    return args


def determine_group(args, key_name):
    """
    Determine if the value points to a group by checking against all group names and IDs, and adjust
    'args' accordingly.

    parameter: (string) key_name
        The name of the command argument

    parameter: (dict) args
        The command arguments dictionary

    returns:
        The arguments dict with group_id field assigned the appropriate value if the value passed
        for the command argument represented by 'key_name' is associated with a Group's details
    """
    assigned_group = args.get(key_name, None)
    if assigned_group:
        group_names, group_ids = [], []
        # Get names and ids of groups
        groups = list_groups()
        for group in groups:
            group_ids.append(group.get('id'))
            group_names.append(group.get('name', '').lower())
        # Check if responder value is a group ID
        if assigned_group in group_ids:
            args['group_id'] = assigned_group
            del args[key_name]
        # Or the name of a group
        elif assigned_group.lower() in group_names:
            group_name_idx = group_names.index(assigned_group.lower())
            args['group_id'] = group_ids[group_name_idx]
            del args[key_name]
    return args


def http_request(method, url_suffix, params=None, data=None, files=None, headers=HEADERS):
    """
    A wrapper for requests lib to send our requests and handle requests and responses better.

    parameter: (string) method
        A string denoting the http request method to use.
        Can be 'GET', 'POST, 'PUT', 'DELETE', etc.

    parameter: (string) url_suffix
        The API endpoint that determines which data we are trying to access/change in our
        call to the API

    parameter: (dict) params
        The key/value pairs to be encoded as part of the URL's query string

    parameter: (dict) data
        The key/value pairs to be form-encoded

    parameter: (list) files
        The multipart-encoded files to upload

    parameter: (dict) headers
        The headers to use with the request

    returns:
        JSON Response Object
    """
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=headers,
        auth=AUTH,  # type: ignore[arg-type]
        files=files
    )
    # Handle error responses gracefully
    if res.status_code not in {200, 201, 202, 204}:
        LOG(res.json())
        LOG(res.text)
        LOG.print_log()
        err_msg = f'Error in API call to Freshdesk Integration [{res.status_code}] - {res.reason}'
        err = json.loads(res.content)
        if err.get('errors'):
            for error in err.get('errors'):
                err_msg += '\n' + json.dumps(error, indent=2)
        else:
            for key, value in res.json().items():
                err_msg += f'\n{key}: {value}'
        return_error(err_msg)
    # Handle response with no content
    elif res.status_code == 204:
        return res

    return res.json()


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Will try to make a request to the API endpoint for listing all tickets.
    """
    http_request('GET', 'tickets')


def fetch_incidents():
    per_page = get_number_of_incidents_to_fetch()

    # demisto.getLastRun() will returns an obj with the previous run in it.
    last_run = demisto.getLastRun()
    # Get the last fetch time and last id fetched if exist
    last_fetch = last_run.get('last_created_incident_timestamp')
    last_incident_id = last_run.get('last_incident_id', -1)
    # Handle first time fetch, fetch incidents retroactively
    if not last_fetch:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)
    updated_since = timestamp_to_datestring(last_fetch, date_format='%Y-%m-%dT%H:%M:%SZ')
    args = {'updated_since': updated_since, 'order_type': 'asc', 'per_page': per_page}

    response = search_tickets(args)  # page 1
    # handle pagination until user's limit
    tickets = handle_search_tickets_pagination(args, response, limit=MAX_INCIDENTS)
    # convert the ticket/events to demisto incidents
    incidents = []
    for ticket in tickets:
        incident = ticket_to_incident(ticket)
        incident_id = ticket.get('id')
        incident_date = date_to_timestamp(incident.get('occurred'), '%Y-%m-%dT%H:%M:%SZ')
        # Update last run and add incident if the incident is newer than last fetch and was not fetched before
        # The incident IDs are in incremental order.
        if incident_date >= last_fetch and incident_id > last_incident_id:
            last_fetch = incident_date
            incidents.append(incident)
            last_incident_id = incident_id
        if len(incidents) >= MAX_INCIDENTS:
            break

    demisto.setLastRun({'last_created_incident_timestamp': last_fetch, 'last_incident_id': last_incident_id})
    demisto.incidents(incidents)


'''<------ TICKETS ------>'''


def create_ticket(args):
    args = determine_identifier(args)
    args = determine_responder(args)
    args = clean_arguments(args)
    endpoint_url = 'tickets'

    response = None
    if not args.get('attachments'):
        # The service endpoint to request from
        # Send a request using our http_request wrapper
        response = http_request('POST', endpoint_url, data=json.dumps(args))
    else:
        # Get the files from their entry IDs
        attachments = entries_to_files(args.get('attachments'))
        # Format to API expectations
        del args['attachments']
        # Send a request and get raw response
        response = http_request('POST', endpoint_url, data=args, files=attachments, headers=MULTIPART_HEADERS)
    return response


def create_ticket_command():
    """
    Create a new Freshdesk ticket.

    demisto parameter: (string) subject
        Subject of the ticket. The default Value is null.

    demisto parameter: (string) description
        Details of the issue for which you are creating a ticket.

    demisto parameter: (number) priority
        Priority of the ticket. Each number has a corresponding value.
        1 is Low, 2 is Medium, 3 is High, 4 is Urgent.

    demisto parameter: (number) status
        Status of the ticket. Each number has a corresponding value.
        2 is Open, 3 is Pending, 4 is Resolved, 5 is Closed, 6 is Waiting
        on Customer, 7 is Waiting on Third Party.

    demisto parameter: (string) identifier
        This can be an email address or a twitter handle

    demisto parameter: (list) responder
        ID or name of the group or agent to whom you wish to assign this ticket.
        To find potential assignees, try executing the fd-list-groups command.

    demisto parameter: (list) attachments
        Entry IDs of files to attach to the ticket.
        The total size of these attachments cannot exceed 15MB.

    demisto parameter: (list) additional_fields
        Additional ticket fields you wish to set the value of

    returns:
        Ticket Object
    """
    # Get command arguments from user
    args = demisto.args()

    # Handle additional_fields command arguments
    args, additional_fields, additional_values = additional_fields_to_args(args, 'additional_fields')

    # Make request and get raw response
    ticket = create_ticket(args)
    # Parse response into context
    include_in_context = DEFAULT_TICKET_CONTEXT_FIELDS[:]

    context = {string_to_context_key(key): val for key, val in ticket.items() if val}
    context = additional_fields_to_context(context, include_in_context, additional_fields, additional_values)
    context, context_readable = attachments_into_context(ticket, context)
    context = reformat_ticket_context(context)
    context_readable = reformat_ticket_context(context_readable)
    title = 'Newly Created Ticket #{}'.format(context.get('ID'))
    human_readable = tableToMarkdown(title, context_readable, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ticket,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Ticket(val.ID && val.ID === obj.ID)': context
        }
    })


def update_ticket(args):
    # Get ticket number
    ticket_number = args.get('id')
    # Remove ticket number from args
    del args['id']

    args = determine_agent(args, 'assigned_agent')
    args = determine_group(args, 'assigned_group')

    args = clean_arguments(args)

    # The service endpoint to request from
    endpoint_url = f'tickets/{ticket_number}'

    response = None
    if not args.get('attachments'):
        # Send a request using our http_request wrapper
        response = http_request('PUT', endpoint_url, data=json.dumps(args))
    else:
        # Get the files from their entry IDs
        attachments = entries_to_files(args.get('attachments'))
        # Format to API expectations
        del args['attachments']
        # Send a request and get raw response
        response = http_request('PUT', endpoint_url, data=args, files=attachments, headers=MULTIPART_HEADERS)
    return response


def update_ticket_command():
    """
    Update the ticket specified by a ticket ID number.

    demisto parameter: (string) subject
        Update the ticket's subject field

    demisto parameter: (number,string) status
        Update the ticket's status. Possible values are 2,3,4,5,6,7 or
        'Open' , 'Pending', 'Resolved', 'Closed', 'Waiting on Customer',
        'Waiting on Third Party'

    demisto parameter: (number,string) priority
        Update the ticket's priority. Possible values are 1,2,3,4 or
        'Low', 'Medium', 'High', 'Urgent'

    demisto parameter: (string) description
        The HTML content of the ticket

    demisto parameter: (number) id
        ID number of the ticket to update

    demisto parameter: assigned_agent
        Update which agent is assigned to respond to this ticket.
        Values can be either the agent's ID number, name, or email.

    demisto parameter: assigned_group
        Update which group is assigned to respond to this ticket.
        Values can be either the group's ID number or name.

    demisto parameter: (list) additional_fields
        Fields not included in the default command arguments that
        you wish to enter the value for

    returns:
        Ticket specified by the ticket ID number with its updated values
    """
    args = demisto.args()
    args, additional_fields, additional_fields_values = additional_fields_to_args(args, 'additional_fields')

    # Make request and get raw response
    ticket = update_ticket(args)

    # Parse response into context
    include_in_context = DEFAULT_TICKET_CONTEXT_FIELDS[:]
    include_in_context.append('updated_at')
    # Parse default context fields
    context = {string_to_context_key(key): val for key, val in ticket.items() if val}
    # Parse additional fields into context
    context = additional_fields_to_context(context, include_in_context, additional_fields, additional_fields_values)
    # Parse attachments into context
    context, context_readable = attachments_into_context(ticket, context)
    context = reformat_ticket_context(context)
    context_readable = reformat_ticket_context(context_readable)
    title = 'Ticket #{} Updated'.format(context.get('ID'))
    human_readable = tableToMarkdown(title, context_readable, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ticket,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Ticket(val.ID && val.ID === obj.ID)': context
        }
    })


def get_ticket(args):
    ticket_number = args.get('id')
    endpoint_url = f'tickets/{ticket_number}'
    url_params = {}

    # Check if embedding additional info in API response was specified in cmd args
    include = ''
    if args.get('include_stats') and args.get('include_stats').lower() == 'true':
        include += 'stats'
    if args.get('include_requester') and args.get('include_requester').lower() == 'true':
        include += 'requester' if include == '' else ', requester'
    if include != '':
        url_params['include'] = include

    response = http_request('GET', endpoint_url, params=url_params)
    return response


def get_ticket_command():
    """
    View a Ticket.

    demisto parameter: (number) id
        ID number of the ticket to fetch

    demisto parameter: (string) include_requester
        If set to 'yes' then the ticket requester's id, email, mobile, name, and phone
        will be included in the ticket's output.

    demisto parameter: (string) include_stats
        If set to 'yes' then the ticket's closed_at, resolved_at and first_responded_at times will be included.

    returns:
        Ticket Object
    """
    # Get command arguments from user
    args = demisto.args()
    # Make request and get raw response
    ticket = get_ticket(args)

    nonstd_context_fields = ['requester', 'stats']

    # Parse response into context
    context = {
        string_to_context_key(key): val
        for key, val in ticket.items()
        if key not in nonstd_context_fields and val is not None
    }

    # Parse attachments into context
    context, context_readable = attachments_into_context(ticket, context)

    context['AdditionalFields'] = {}
    requester = ticket.get('requester')
    if requester:
        requester_context = {string_to_context_key(key): val for key, val in requester.items() if val}
        context['AdditionalFields']['Requestor'] = requester_context
    stats = ticket.get('stats')
    if stats:
        stats_context = {string_to_context_key(key): val for key, val in stats.items() if val}
        context['AdditionalFields']['Stats'] = stats_context

    if not ticket.get('deleted'):
        context['AdditionalFields']['Deleted'] = False

    context = reformat_ticket_context(context)
    context_readable = reformat_ticket_context(context_readable)
    title = 'Viewing Ticket #{}'.format(ticket.get('id'))
    human_readable = tableToMarkdown(title, context_readable, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ticket,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Ticket(val.ID && val.ID === obj.ID)': context
        }
    })


def delete_ticket(ticket_id):
    endpoint_url = f'tickets/{ticket_id}'
    response = http_request('DELETE', endpoint_url)
    return response


def delete_ticket_command():
    """
    Soft-Delete the ticket specified by the 'id' command argument.

    demisto parameter: (number) id
        ID of the ticket to delete

    returns:
        Success Message
    """
    ticket_id = demisto.args().get('id')
    # Make request
    delete_ticket(ticket_id)
    ticket_context = {
        'ID': int(ticket_id),
        'AdditionalFields': {'Deleted': True}
    }
    message = f'Soft-Deleted Ticket #{ticket_id}'
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ticket_context,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': message,
        'EntryContext': {
            'Freshdesk.Ticket(val.ID && val.ID === obj.ID)': ticket_context
        }
    })


def search_tickets(args):
    endpoint_url = 'tickets'
    url_params = {}

    # Filter By
    filter = args.get('filter')
    if filter:
        url_params['filter'] = filter
    requester = args.get('requester')
    if requester:
        if '@' in requester:
            url_params['email'] = requester
        else:
            url_params['requester_id'] = requester
    updated_since = args.get('updated_since')
    if updated_since:
        url_params['updated_since'] = updated_since
    per_page = args.get('per_page')
    if per_page:
        url_params['per_page'] = per_page

    # Sort By
    order_by = args.get('order_by')
    if order_by:
        url_params['order_by'] = order_by
    order_type = args.get('order_type')
    if order_type:
        url_params['order_type'] = order_type

    # Embeddings (include additional information)
    include = ''
    if args.get('include_stats') and args.get('include_stats').lower() == 'true':
        include += 'stats'
    if args.get('include_requester') and args.get('include_requester').lower() == 'true':
        include += 'requester' if include == '' else ', requester'
    if args.get('include_description') and args.get('include_description').lower() == 'true':
        include += 'description' if include == '' else ', description'
    if include != '':
        url_params['include'] = include

    # Custom Query
    custom_query = args.get('custom_query')
    if custom_query and url_params:
        err_msg = 'You cannot use the custom_query argument in conjunction with the other command arguments. You can ' \
                  'either use the other arguments that allow you to choose options for filtering, sorting, ' \
                  'and including information for tickets, or to use the custom_query alone to create a custom filter ' \
                  'that determines which tickets are listed.'
        return_error(err_msg)
    elif custom_query:
        endpoint_url = 'search/tickets'
        url_params['query'] = '"' + custom_query + '"'

    page = args.get('page')
    if page:
        url_params['page'] = page

    # Make request and get raw response
    response = http_request('GET', endpoint_url, params=url_params)
    return response


def search_tickets_command():
    """
    List all tickets that match the filter criteria you specify.

    demisto parameter: (string) filter
        Predefined filters

    demisto parameter: requester
        Filter by either the ticket requester's email or ID

    demisto parameter: (datetime) updated_since
        By default, only tickets that have been created within the past 30 days will be returned.
        For older tickets, use this filter. Example value for this field would be '2015-01-19T02:00:00Z'

    demisto parameter: (string) order_by
        Reference field for ordering the list of tickets. The default sort order is created_at.

    demisto parameter: (string) order_type
        Whether to order the resulting tickets in ascending or descending order.
        The default is descending. Value can be either 'asc' or 'desc'.

    demisto parameter: (string) include_stats
        If set to 'yes' then the ticket's closed_at, resolved_at and first_responded_at times will be included.

    demisto parameter: (string) include_requester
        If set to 'yes' then the ticket requester's id, email, mobile, name, and phone
        will be included in the ticket's output for each ticket.

    demisto parameter: (string) include_description
        If set to 'yes' then the ticket's description and description_text will be included the tickets' outputs.

    demisto parameter: (string) custom_query
        Filter tickets using a custom query.
        Format  -  "(ticket_field:integer OR ticket_field:'string') AND ticket_field:boolean"
        Example -  "(type:'Question' OR type:'Problem') AND (due_by:>'2017-10-01' AND due_by:<'2017-10-07')"
        Note that the custom_query argument cannot be used in conjunction with this command's other arguments.

    returns:
        Ticket Objects
    """
    args = demisto.args()
    additional_fields = get_additional_fields(args)
    response = search_tickets(args)   # page 1

    tickets = handle_search_tickets_pagination(args, response)

    context_outputs = DEFAULT_TICKET_CONTEXT_FIELDS[:]
    context_outputs.append('updated_at')

    # Parse response into context
    contexts = []
    readable_contexts = []
    for ticket in tickets:
        # Parse ticket into the standard outputs
        context = {string_to_context_key(key): val for key, val in ticket.items() if key in context_outputs}

        # Parse ticket attachments into context
        context, context_readable = attachments_into_context(ticket, context)

        # Parse ticket for the additionally requested fields
        context['AdditionalFields'] = {
            string_to_context_key(key): val for key, val in ticket.items() if key in additional_fields
        }
        requester = ticket.get('requester')
        if requester:
            requester_context = {string_to_context_key(key): val for key, val in requester.items() if val}
            context['AdditionalFields']['Requestor'] = requester_context
        stats = ticket.get('stats')
        if stats:
            stats_context = {string_to_context_key(key): val for key, val in stats.items() if val}
            context['AdditionalFields']['Stats'] = stats_context

        context_readable = reformat_ticket_context(context_readable)
        readable_contexts.append(context_readable)
        context = reformat_ticket_context(context)
        contexts.append(context)

    table_headers = [
        'ID', 'Priority', 'Status', 'Subject', 'DueBy', 'FrDueBy', 'RequesterID', 'GroupID',
        'Source', 'CreatedAt', 'UpdatedAt', 'Tag', 'AdditionalFields', 'Attachment'
    ]
    title = 'Viewing All Requested Tickets'
    human_readable = tableToMarkdown(title, readable_contexts, headers=table_headers, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': tickets,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Ticket(val.ID && val.ID === obj.ID)': contexts
        }
    })


'''<------ CONVERSATIONS ------>'''


def ticket_reply(args):
    ticket_id = args.get('ticket_id')
    del args['ticket_id']
    args = handle_array_input(args)
    endpoint_url = f'tickets/{ticket_id}/reply'

    response = None
    if not args.get('attachments'):
        # The service endpoint to request from
        # Send a request using our http_request wrapper
        response = http_request('POST', endpoint_url, data=json.dumps(args))
    else:
        # Get the files from their entry IDs
        attachments = entries_to_files(args.get('attachments'))
        # Format to API expectations
        del args['attachments']
        # Send a request and get raw response
        response = http_request('POST', endpoint_url, data=args, files=attachments, headers=MULTIPART_HEADERS)
    return response


def ticket_reply_command():
    """
    Reply to a specified ticket.

    demisto parameter: (number) ticket_id
        ID of the ticket you wish to respond to

    demisto parameter: (string) body
        Content of the reply in HTML format

    demisto parameter: (string) from_email
        The email address from which the reply is sent. By default the global support email will be used.

    demisto parameter: (number) user_id
        ID of the agent who is adding the note

    demisto parameter: (list) cc_emails
        Array of email address strings added in the 'cc' field of the outgoing ticket email.

    demisto parameter: (list) bcc_emails
        Array of email address strings added in the 'bcc' field of the outgoing ticket email.

    demisto parameter: (list) attachments
        Entry IDs of files to attach to the reply. The total size of these attachments cannot exceed 15MB.

    returns:
        Ticket Reply Object
    """
    args = demisto.args()
    # Make request and get raw response
    reply = ticket_reply(args)
    # Parse response into context
    context = {string_to_context_key(key): val for key, val in reply.items() if val}
    context = reformat_conversation_context(context)
    # Parse attachments into context
    context, context_readable = attachments_into_context(reply, context)
    context = reformat_ticket_context(context)
    context_readable = reformat_ticket_context(context_readable)
    complete_context = {
        'ID': int(reply.get('ticket_id')),
        'Conversation': context
    }
    title = 'Reply to Ticket #{}'.format(reply.get('ticket_id'))
    human_readable = tableToMarkdown(title, context_readable, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': reply,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Ticket(val.ID && val.ID === obj.ID)': complete_context
        }
    })


def create_ticket_note(args):
    ticket_id = args.get('ticket_id')
    del args['ticket_id']
    args = handle_array_input(args)
    # Set defaults for 'private' and 'incoming' fields if not set by user
    args['private'] = args.get('private', 'true')
    args['incoming'] = args.get('incoming', 'false')
    endpoint_url = f'tickets/{ticket_id}/notes'

    response = None
    if not args.get('attachments'):
        # Format boolean args to API expectations
        dumped_args = json.dumps(args).replace('"false"', 'false').replace('"true\"', 'true')
        # The service endpoint to request from
        # Send a request using our http_request wrapper
        response = http_request('POST', endpoint_url, data=dumped_args)
    else:
        # Get the files from their entry IDs
        attachments = entries_to_files(args.get('attachments'))
        # Format to API expectations
        del args['attachments']
        # Send a request and get raw response
        response = http_request('POST', endpoint_url, data=args, files=attachments, headers=MULTIPART_HEADERS)
    return response


def create_ticket_note_command():
    """
    Create a note for a specified ticket.

    Notes by default are private (AKA not visible to non-agents) unless you
    set the 'private' command argument to False.

    demisto parameter: (number) ticket_id
        ID of the ticket you wish to make a note for

    demisto parameter: (string) body
        Content of the note in HTML format

    demisto parameter: (boolean) private
        Set to false if the note is not private

    demisto parameter: (number) user_id
        ID of the agent who is adding the note

    demisto parameter: (list) notify_emails
        Array of email addresses of agents/users who need to be notified about this note

    demisto parameter: (boolean) incoming
        Set to true if a particular note should appear as being created from outside (i.e., not through web portal).

    demisto parameter: (list) attachments
        Entry IDs of files to attach to the note. The total size of these attachments cannot exceed 15MB.

    returns:
        Note Object
    """
    # Get command arguments
    args = demisto.args()
    # Make request and get raw response
    note = create_ticket_note(args)
    # Parse response into context
    context = {string_to_context_key(key): val for key, val in note.items() if val}
    context = reformat_conversation_context(context)
    # Parse attachments into context
    context, context_readable = attachments_into_context(note, context)
    context = reformat_ticket_context(context)
    context_readable = reformat_ticket_context(context_readable)
    complete_context = {
        'ID': int(note.get('ticket_id')),
        'Conversation': context
    }
    title = 'Note for Ticket #{}'.format(note.get('ticket_id'))
    human_readable = tableToMarkdown(title, context_readable, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': note,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Ticket(val.ID && val.ID === obj.ID)': complete_context
        }
    })


def get_ticket_conversations(ticket_id):
    endpoint_url = f'tickets/{ticket_id}/conversations'
    response = http_request('GET', endpoint_url)
    return response


def get_ticket_conversations_command():
    """
    Lists all replies and notes for a specified ticket.

    demisto parameter: (number) ticket_id
        ID of the ticket for which you would like to list all of its conversations

    returns:
        Conversation Objects
    """
    # Get id number of ticket as cmd arg for which you want to see all the conversations
    ticket_id = demisto.args().get('ticket_id')
    # Make request and get raw response
    conversations = get_ticket_conversations(ticket_id)
    # Parse response into context
    contexts = []
    readable_contexts = []
    for conversation in conversations:
        context = {string_to_context_key(key): val for key, val in conversation.items() if val}
        context = reformat_conversation_context(context)
        # Parse attachments into context
        context, context_readable = attachments_into_context(conversation, context)
        context = reformat_ticket_context(context)
        context_readable = reformat_ticket_context(context_readable)
        contexts.append(context)
        readable_contexts.append(context_readable)
    complete_context = {
        'ID': int(ticket_id),
        'Conversation': contexts
    }
    title = f'Conversations of Ticket #{ticket_id}'
    human_readable = tableToMarkdown(title, readable_contexts, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': conversations,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Ticket(val.ID && val.ID === obj.ID)': complete_context
        }
    })


'''<------ CONTACTS ------>'''


def list_contacts(filters):
    # Alter to match API expected inputs
    updated_since = filters.get('updated_since', None)
    if updated_since:
        del filters['updated_since']
        filters['_updated_since'] = updated_since

    endpoint_url = 'contacts'
    response = http_request('GET', endpoint_url, params=filters)
    return response


def list_contacts_command():
    """
    List all contacts.

    Lists all contacts matching the specified filters. If no filters are provided
    then all unblocked and undeleted contacts will be returned.

    demisto parameter: (number) mobile
        mobile number to filter the contacts by

    demisto parameter: (number) phone
        phone number to filter contacts by

    demisto parameter: (string) state
        The state of contacts by which you want to filter the contacts. Values
        are 'verified', 'unverified', 'blocked', or 'deleted'.

    demisto parameter: (datetime) updated_since
        return contacts that have been updated after the timestamp given as this argument value

    returns:
        Contact Objects
    """
    # Get command arguments from user
    filters = demisto.args()
    # Make request and get raw response
    contacts = list_contacts(filters)
    # Parse response into context
    contexts = []
    for contact in contacts:
        # Parse individual contact response in context
        context = format_contact_context(contact)
        contexts.append(context)
    filters_as_strings = ', '.join([f'{key}: {val}' for key, val in filters.items()])
    title = f'Contacts Filtered by {filters_as_strings}' if filters else 'All Contacts'
    human_readable = tableToMarkdown(title, contexts, removeNull=False)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contacts,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Contact(val.ID && val.ID === obj.ID)': contexts
        }
    })


def get_contact(args):
    contact_id = 0
    if not args:
        err_msg = 'You must provide a value for either the mobile, email or id command argument fields.'
        return_error(err_msg)
    elif args.get('id') is not None:
        contact_id = args.get('id')
    elif args.get('email') is not None:
        try:
            filters = {'email': args.get('email')}
            # Get id field of first result of contacts with that email (There should only be one)
            contact_id = list_contacts(filters)[0].get('id')
        # If there is an IndexError, it means no results were returned for the given filter
        except IndexError:
            err_msg = 'Couldn\'t find a contact with that email address.'\
                      ' Double check that you wrote the email address correctly'\
                      ' and/or that you have a FreshDesk contact with that exact'\
                      ' email address.'
            return_error(err_msg)
        except Exception as e:
            return_error(e)
    else:
        try:
            filters = {'mobile': args.get('mobile')}
            # Get id field of first result of contacts with that mobile number
            contact_id = list_contacts(filters)[0].get('id')
        # If there is an IndexError, it means no results were returned for the given filter
        except IndexError:
            err_msg = 'Couldn\'t find a contact with that mobile number.'\
                      ' Double check that you wrote it correctly and/or that '\
                      'you have a FreshDesk contact with that exact mobile number.'
            return_error(err_msg)
        except Exception as e:
            return_error(e)

    endpoint_url = f'contacts/{contact_id}'
    response = http_request('GET', endpoint_url)
    return response


def get_contact_command():
    """
    View the details of the contact specified by the ID number.

    demisto parameter: (number) id
        ID of the contact you wish to view the details of

    demisto parameter: (number) mobile
        Mobile number of the contact you wish to view the details of

    demisto parameter: (string) email
        Email address of the contact you wish to view the details of

    returns:
        Contact Object
    """
    # Get command arguments from user
    args = demisto.args()
    # Make request and get raw response
    contact = get_contact(args)

    context = format_contact_context(contact)
    title = 'Viewing Contact #{}'.format(contact.get('id'))
    human_readable = tableToMarkdown(title, context, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contact,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Contact(val.ID && val.ID === obj.ID)': context
        }
    })


'''<------ CANNED RESPONSES ------>'''


def list_canned_response_folders():
    endpoint_url = 'canned_response_folders'
    response = http_request('GET', endpoint_url)
    return response


def list_canned_response_folders_command():
    """
    List all Canned Response Folders (Only users with Admin Privileges).

    returns:
        Folder Objects
    """
    # Make request and get raw response
    cr_folders = list_canned_response_folders()
    # Parse response into context
    contexts = []
    for folder in cr_folders:
        # Parse individual contact response in context
        context = {string_to_context_key(key): val for key, val in folder.items() if val}
        context = reformat_canned_response_context(context)
        contexts.append(context)
    title = 'All Canned Response Folders'
    human_readable = tableToMarkdown(title, contexts, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': cr_folders,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.CRFolder(val.ID && val.ID === obj.ID)': contexts
        }
    })


def get_canned_response_folder(id):
    endpoint_url = f'canned_response_folders/{id}/responses'
    response = http_request('GET', endpoint_url)
    return response


def get_canned_response_folder_command():
    """
    View the details of all the Canned Responses in a Folder.

    demisto parameter: (number) id
        ID of the Folder containing the Canned Responses you wish to view the details of

    returns:
        Canned Response Objects with more details, aka all of a Canned Response Object's attributes
    """
    # Get id of the containing canned response folder as cmd argument
    cr_folder_id = demisto.args().get('id')
    # Make request and get raw response
    canned_responses = get_canned_response_folder(cr_folder_id)
    # Parse the responses into context
    contexts = []
    readable_contexts = []
    for cr in canned_responses:
        context = {string_to_context_key(key): val for key, val in cr.items() if val}
        context = reformat_canned_response_context(context)
        context, context_readable = attachments_into_context(cr, context)
        contexts.append(context)
        readable_contexts.append(context_readable)
    title = f'Details of Canned Responses in CR Folder #{cr_folder_id}'
    human_readable = tableToMarkdown(title, readable_contexts, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': canned_responses,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.CRFolder(val.ID && val.ID === obj.ID).CR(val.ID && val.ID === obj.ID)': contexts
        }
    })


'''<------ GROUPS ------>'''


def list_groups():
    endpoint_url = 'groups'
    response = http_request('GET', endpoint_url)
    return response


def list_groups_command():
    """
    List all groups.

    returns:
        Group Objects
    """
    # Make request and get raw response
    groups = list_groups()
    # Parse response into context
    contexts = []
    for group in groups:
        # Parse individual group response in context
        context = {}
        for key, val in list(group.items()):
            if val:
                if key == 'agent_ids':
                    key = 'agent_id'
                new_key = string_to_context_key(key)
                if 'Id' in new_key:
                    new_key = new_key.replace('Id', 'ID')
                context[new_key] = val
        contexts.append(context)
    title = 'All Groups'
    human_readable = tableToMarkdown(title, contexts, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': groups,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Group(val.ID && val.ID === obj.ID)': contexts
        }
    })


'''<------ AGENTS ------>'''


def list_agents(filters={}):
    endpoint_url = 'agents'
    response = http_request('GET', endpoint_url, params=filters)
    return response


def list_agents_command():
    """
    List agents that match the criteria of the filters entered as command arguments.

    demisto parameter: (number) mobile
        Mobile phone number to filter agents by

    demisto parameter: (number) phone
        Telephone number to filter agents by

    demisto parameter: (string) state
        Filter agents by whether they are 'fulltime' or 'occasional'

    returns:
        Agent Objects
    """
    # Get filter as cmd arg
    args = demisto.args()
    # Make request and get raw response
    agents = list_agents(args)
    # Parse response into context
    contexts = []
    for agent in agents:
        # Parse the individual agent into context
        context = {}
        for key, val in list(agent.items()):
            if val:
                if key == 'group_ids':
                    key = 'group_id'
                elif key == 'role_ids':
                    key = 'role_id'
                new_key = string_to_context_key(key)
                if 'Id' in new_key:
                    new_key = new_key.replace('Id', 'ID')
                context[new_key] = val
        context['Contact'] = {string_to_context_key(key): val for key, val in agent.get('contact').items() if val}
        contexts.append(context)
    title = 'All Agents'
    human_readable = tableToMarkdown(title, contexts, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': agents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Freshdesk.Agent(val.ID && val.ID === obj.ID)': contexts
        }
    })


''' COMMANDS MANAGER / SWITCH PANEL '''


# Commands Switch Panel
commands = {
    'fd-create-ticket': create_ticket_command,
    'fd-update-ticket': update_ticket_command,
    'fd-get-ticket': get_ticket_command,
    'fd-get-contact': get_contact_command,
    'fd-list-contacts': list_contacts_command,
    'fd-list-canned-response-folders': list_canned_response_folders_command,
    'fd-get-canned-response-folder': get_canned_response_folder_command,
    'fd-list-groups': list_groups_command,
    'fd-ticket-reply': ticket_reply_command,
    'fd-create-ticket-note': create_ticket_note_command,
    'fd-get-ticket-conversations': get_ticket_conversations_command,
    'fd-list-agents': list_agents_command,
    'fd-delete-ticket': delete_ticket_command,
    'fd-search-tickets': search_tickets_command,
}

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
    elif demisto.command() in commands:
        # Execute that command
        commands[demisto.command()]()

# Log exceptions
except Exception as e:
    return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}", e)
