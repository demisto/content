from CommonServerPython import *

''' IMPORTS '''
import requests
import json
import re
import urllib

''' GLOBAL VARS '''
SERVER = None
BASE_URL = None
USERNAME = None
PASSWORD = None
USE_SSL = None
FETCH_PRIORITY = 0
FETCH_STATUS = None
FETCH_QUEUE = None
CURLY_BRACKETS_REGEX = r'\{(.*?)\}'  # Extracts string in curly brackets, e.g. '{string}' -> 'string'
apostrophe = "'"
SESSION = requests.session()
SESSION.verify = USE_SSL
REFERER = None
HEADERS = {'Referer': REFERER} if REFERER else {}  # type: dict

''' HELPER FUNCTIONS '''


def ticket_to_incident(ticket):
    incident = {
        'name': 'RTIR Ticket ' + str(ticket['ID']),
        'rawJSON': json.dumps(ticket),
    }
    attachments, attachments_content = get_ticket_attachments(ticket['ID'])
    if attachments:
        incident_attachments = []
        for i in range(len(attachments)):
            incident_attachments.append({
                'path': attachments_content[i]['FileID'],
                'name': attachments[i]['Name']
            })

        incident['attachment'] = incident_attachments  # type: ignore
    return incident


def ticket_string_to_id(ticket_string):
    '''
    Translates 'ticket/1' to the integer 1
    '''
    slash_index = ticket_string.index('/')
    ticket_id = int(ticket_string[slash_index + 1:])
    return ticket_id


def http_request(method, suffix_url, data=None, files=None, query=None):
    # Returns the http request

    url = BASE_URL + suffix_url
    params = {'user': USERNAME, 'pass': PASSWORD}
    if query:
        params.update(query)

    response = SESSION.request(method, url, data=data, params=params, files=files, headers=HEADERS)  # type: ignore

    # handle request failure
    if response.status_code not in {200}:
        message = parse_error_response(response)
        return_error('Error in API call with status code {}\n{}'.format(response.status_code, message))

    return response


def parse_error_response(response):
    try:
        res = response.json()
        msg = res.get('message')
        if res.get('details') and res.get('details')[0].get('message'):
            msg = msg + "\n" + json.dumps(res.get('details')[0])
    except Exception:
        return response.text
    return msg


def login():
    data = {
        'user': USERNAME,
        'pass': PASSWORD
    }
    res = SESSION.post(SERVER, data=data)  # type: ignore
    response_text = res.text.encode('utf-8')
    are_credentials_wrong = 'Your username or password is incorrect' in response_text
    if are_credentials_wrong:
        return_error("Error: login failed. please check your credentials.")


def logout():
    suffix_url = 'logout'
    http_request('POST', suffix_url)


def parse_ticket_data(raw_query):
    raw_tickets = search_ticket_request(raw_query)
    headers = ['ID', 'Subject', 'Status', 'Priority', 'Created', 'Queue', 'Creator', 'Owner', 'InitialPriority',
               'FinalPriority']
    search_context = []
    data = raw_tickets.content.split('\n')
    data = data[2:]
    for line in data:
        split_line = line.split(': ')
        search_ticket = get_ticket_request(split_line[0]).content
        search_ticket = search_ticket.split('\n')
        search_ticket = search_ticket[2:]
        id_ticket = search_ticket[0].upper()
        search_ticket[0] = id_ticket

        current_ticket_search = build_ticket(search_ticket)

        for key in search_ticket:  # Adding ticket custom fields to outputs
            if key.startswith('CF.'):
                split_key = key.split(':')
                if split_key[0]:
                    custom_field_regex = re.findall(CURLY_BRACKETS_REGEX, key)[0].replace(' ',
                                                                                          '')  # Regex and removing white spaces
                    current_ticket_search[custom_field_regex] = split_key[1]
                    headers.append(custom_field_regex)

        if current_ticket_search:
            search_context.append(current_ticket_search)

    return search_context


''' FUNCTIONS '''


def create_ticket_request(encoded):
    suffix_url = 'ticket/new'
    ticket_id = http_request('POST', suffix_url, data=encoded)

    return ticket_id


def create_ticket_attachments_request(encoded, files_data):
    suffix_url = 'ticket/new'
    ticket_id = http_request('POST', suffix_url, files=files_data)

    return ticket_id


def create_ticket():
    args = dict(demisto.args())
    args = {arg: value.encode('utf-8') for arg, value in args.items() if isinstance(value, unicode)}

    queue = args.get('queue')
    data = 'id: ticket/new\nQueue: {}\n'.format(queue)

    subject = args.get('subject')
    if subject:
        data += "Subject: {}\n".format(subject)

    requestor = args.get('requestor')
    if requestor:
        data += "Requestor: {}\n".format(requestor)

    cc = args.get('cc', '')
    if cc:
        data += "Cc: {}\n".format(cc)

    admin_cc = args.get('admin-cc', '')
    if admin_cc:
        data += "AdminCc: {}\n".format(admin_cc)

    owner = args.get('owner')
    if owner:
        data += "Owner: {}\n".format(owner)

    status = args.get('status')
    if status:
        data += "Status: {}\n".format(status)

    priority = args.get('priority')
    if priority:
        data += "Priority: {}\n".format(priority)

    initial_priority = args.get('initial-priority')
    if initial_priority:
        data += "Initial-priority: {}\n".format(initial_priority)

    final_priority = args.get('final-priority')
    if final_priority:
        data += "FinalPriority: {}\n".format(final_priority)

    text = args.get('text')
    if text:
        data += "Text: {}\n".format(text)

    customfields = args.get('customfields')
    if customfields:
        cf_list = customfields.split(',')
        for cf in cf_list:
            equal_index = cf.index('=')
            key = 'CF-{}: '.format(cf[:equal_index])
            value = cf[equal_index + 1:]
            data = data + key + value + '\n'

    attachments = args.get('attachment')
    if attachments:
        files_data = {}
        if isinstance(attachments, list):  # Given as list
            attachments_list = attachments
        else:  # Given as string
            attachments_list = attachments.split(',')
        for i, file_pair in enumerate(attachments_list):
            file = demisto.getFilePath(file_pair)
            file_name = file['name']
            files_data['attachment_{:d}'.format(i + 1)] = (file_name, open(file['path'], 'rb'))
            data += 'Attachment: {}'.format(file_name)

    encoded = "content=" + urllib.quote_plus(data)
    if attachments:
        files_data.update({'content': (None, data)})  # type: ignore
        raw_ticket_res = create_ticket_attachments_request(encoded, files_data)
    else:
        raw_ticket_res = create_ticket_request(encoded)
    ticket_id = re.findall('\d+', raw_ticket_res.content)[-1]
    if ticket_id == -1:
        return_error('Ticket creation failed')

    ticket_context = ({
        'ID': ticket_id,
        'Subject': subject,
        'Creator': requestor,
        'InitialPriority': initial_priority,
        'Priority': priority,
        'FinalPriority': final_priority,
        'Owner': owner
    })
    ec = {
        'RTIR.Ticket(val.ID && val.ID === obj.ID)': ticket_context
    }
    hr = 'Ticket {} was created successfully.'.format(ticket_id)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': raw_ticket_res.content,
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    })


def get_ticket_request(ticket_id):
    suffix_url = 'ticket/{}/show'.format(ticket_id)
    raw_ticket = http_request('GET', suffix_url)

    return raw_ticket


def fix_query_suffix(query):
    new_query = query
    if new_query.endswith('+AND+'):
        new_query = new_query[:-5]
    elif new_query.endswith('+OR+'):
        new_query = new_query[:-4]
    return new_query


def build_search_query():
    raw_query = ''
    args = dict(demisto.args())
    args = {arg: value.encode('utf-8') for arg, value in args.items() if isinstance(value, unicode)}
    ticket_id = args.get('ticket-id')
    if ticket_id:
        raw_query += 'id={}{}{}+AND+'.format(apostrophe, ticket_id, apostrophe)

    subject = args.get('subject')
    if subject:
        raw_query += 'Subject={}{}{}+AND+'.format(apostrophe, subject, apostrophe)

    status = args.get('status')
    if status:
        raw_query += 'Status={}{}{}+AND+'.format(apostrophe, status, apostrophe)

    creator = args.get('creator')
    if creator:
        raw_query += 'Creator={}{}{}+AND+'.format(apostrophe, creator, apostrophe)

    priority_equal_to = args.get('priority-equal-to')
    if priority_equal_to:
        raw_query += 'Priority={}{}{}+AND+'.format(apostrophe, priority_equal_to, apostrophe)

    priority_greater_than = args.get('priority-greater-than')
    if priority_greater_than:
        raw_query += 'Priority>{}{}{}+AND+'.format(apostrophe, priority_greater_than, apostrophe)

    created_after = args.get('created-after')
    if created_after:
        raw_query += 'Created>{}{}{}+AND+'.format(apostrophe, created_after, apostrophe)

    created_on = args.get('created-on')
    if created_on:
        raw_query += 'Created={}{}{}+AND+'.format(apostrophe, created_on, apostrophe)

    created_before = args.get('created-before')
    if created_before:
        raw_query += 'Created<{}{}{}+AND+'.format(apostrophe, created_before, apostrophe)

    owner = args.get('owner')
    if owner:
        raw_query += 'Created={}{}{}+AND+'.format(apostrophe, owner, apostrophe)

    due = args.get('due')
    if due:
        raw_query += 'Due={}{}{}+AND+'.format(apostrophe, due, apostrophe)

    queue = args.get('queue')
    if queue:
        raw_query += 'Queue={}{}{}+AND+'.format(apostrophe, queue, apostrophe)
    raw_query = fix_query_suffix(raw_query)
    return raw_query


def build_ticket(rtir_search_ticket):
    current_ticket_search = {}
    for entity in rtir_search_ticket:
        if ': ' in entity:
            header, content = entity.split(': ', 1)
            if 'ID' == header:
                content = ticket_string_to_id(content)
            if header in {'ID', 'Subject', 'Status', 'Priority', 'Created', 'Queue', 'Creator', 'Owner',
                          'InitialPriority', 'FinalPriority'}:
                current_ticket_search[header] = content
    return current_ticket_search


def search_ticket():
    raw_query = build_search_query()

    raw_tickets = search_ticket_request(raw_query)
    headers = ['ID', 'Subject', 'Status', 'Priority', 'Created', 'Queue', 'Creator', 'Owner', 'InitialPriority',
               'FinalPriority']
    search_context = []
    data = raw_tickets.content.split('\n')
    data = data[2:]
    results_limit = int(demisto.args().get('results_limit', 0))
    data = data if (results_limit == 0) else data[:results_limit]
    for line in data:
        split_line = line.split(': ')
        empty_line_response = ['NO OBJECTS SPECIFIED.', '']
        is_line_non_empty = split_line[0] != ''
        if is_line_non_empty:
            search_ticket = get_ticket_request(split_line[0]).content
            search_ticket = search_ticket.split('\n')
            search_ticket = search_ticket[2:]
            id_ticket = search_ticket[0].upper()
            search_ticket[0] = id_ticket
        else:
            search_ticket = empty_line_response

        current_ticket_search = build_ticket(search_ticket)

        for key in search_ticket:  # Adding ticket custom fields to outputs
            if key.startswith('CF.'):
                split_key = key.split(':')
                if split_key[0]:
                    custom_field_regex = re.findall(CURLY_BRACKETS_REGEX, key)[0].replace(' ',
                                                                                          '')  # Regex and removing white spaces
                    current_ticket_search[custom_field_regex] = split_key[1]
                    headers.append(custom_field_regex)

        if current_ticket_search:
            search_context.append(current_ticket_search)
    if search_context:
        ec = {
            'RTIR.Ticket(val.ID && val.ID === obj.ID)': search_context
        }
        title = 'RTIR ticket search results'

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': search_context,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, search_context, headers, removeNull=True),
            'EntryContext': ec
        })
    else:
        demisto.results('No results found.')


def search_ticket_request(raw_query):
    suffix_url = 'search/ticket'
    raw_tickets = http_request('GET', suffix_url, query={'query': raw_query})

    return raw_tickets


def close_ticket_request(ticket_id, encoded):
    suffix_url = 'ticket/{}/edit'.format(ticket_id)
    closed_ticket = http_request('POST', suffix_url, data=encoded)

    return closed_ticket


def close_ticket():
    ticket_id = demisto.args().get('ticket-id')
    content = '\nStatus: resolved'
    encoded = "content=" + urllib.quote_plus(content)
    closed_ticket = close_ticket_request(ticket_id, encoded)
    if '200 Ok' in closed_ticket.content:
        ec = {
            'RTIR.Ticket(val.ID && val.ID === obj.ID)': {
                'ID': int(ticket_id),
                'State': 'resolved'
            }
        }
        hr = 'Ticket {} was resolved successfully.'.format(ticket_id)
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': hr,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        })
    else:
        return_error('Failed to resolve ticket')


def edit_ticket_request(ticket_id, encoded):
    suffix_url = 'ticket/{}/edit'.format(ticket_id)
    edited_ticket = http_request('POST', suffix_url, data=encoded)

    return edited_ticket


def edit_ticket():
    arguments_given = False
    ticket_id = demisto.args().get('ticket-id')
    content = 'ID: ' + ticket_id
    kwargs = {}
    subject = demisto.args().get('subject')
    if subject:
        content += '\nSubject: ' + subject
        arguments_given = True
        kwargs['Subject'] = subject

    owner = demisto.args().get('owner')
    if owner:
        content += '\nOwner: ' + owner
        arguments_given = True
        kwargs['Owner'] = owner

    status = demisto.args().get('status')
    if status:
        content += '\nStatus: ' + status
        arguments_given = True
        kwargs['Status'] = status

    priority = demisto.args().get('priority')
    if priority:
        content += '\nPriority: ' + priority
        arguments_given = True
        kwargs['Priority'] = int(priority)

    final_priority = demisto.args().get('final-priority')
    if final_priority:
        content += '\nFinalPriority: ' + final_priority
        arguments_given = True
        kwargs['FinalPriority'] = int(final_priority)

    due = demisto.args().get('due')
    if due:
        content += '\nDue: ' + due
        arguments_given = True
        kwargs['Due'] = due

    customfields = demisto.args().get('customfields')
    if customfields:
        cf_list = customfields.split(',')
        for cf in cf_list:
            equal_index = cf.index('=')
            key = 'CF-{}: '.format(cf[:equal_index])
            value = cf[equal_index + 1:]
            content = content + key + value + '\n'

    if arguments_given:
        encoded = "content=" + urllib.quote_plus(content.encode('utf-8'))
        edited_ticket = edit_ticket_request(ticket_id, encoded)
        if "200 Ok" in edited_ticket.content:
            ticket_context = ({
                'ID': ticket_id,
                'Subject': subject,
                'State': status,
                'Priority': priority,
                'FinalPriority': final_priority,
                'Owner': owner
            })
            ec = {
                'RTIR.Ticket(val.ID && val.ID === obj.ID)': ticket_context
            }

            hr = 'Ticket {} was edited successfully.'.format(ticket_id)
            demisto.results({
                'Type': entryTypes['note'],
                'Contents': hr,
                'ContentsFormat': formats['json'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': hr,
                'EntryContext': ec
            })
        else:
            return_error('Failed to edit ticket')
    else:
        return_error('No arguments were given to edit the ticket.')


def get_ticket_attachments(ticket_id):
    suffix_url = 'ticket/{}/attachments'.format(ticket_id)
    raw_attachments = http_request('GET', suffix_url).text

    attachments = []
    attachments_content = []
    attachments_list = parse_attachments_list(raw_attachments)
    for attachment_id, attachment_name, attachment_type, attachment_size in attachments_list:
        attachments.append({
            'ID': attachment_id,
            'Name': attachment_name,
            'Type': attachment_type,
            'Size': attachment_size
        })

        suffix_url = 'ticket/{}/attachments/{}'.format(ticket_id, attachment_id)
        raw_attachment_content = http_request('GET', suffix_url).content
        attachment_content = parse_attachment_content(attachment_id, raw_attachment_content)
        attachments_content.append(fileResult(attachment_name, attachment_content))
    return attachments, attachments_content


def parse_attachments_list(raw_attachments):
    """
    Parses attachments details from raw attachments response.
    Example input:
        RT/4.4.2 200 Ok

        id: ticket/6325/attachments
        Attachments: 504: mimecast-get-remediation-incident.log (text/plain / 3.5k)
        505: mimecast-get-remediation-incident2.log (text/plain / 3.6k)

    Example output:
        [('504', 'mimecast-get-remediation-incident.log', 'text/plain', '3.5k'),
         ('505', 'mimecast-get-remediation-incident2.log', 'text/plain', '3.6k')]
    Args:
        raw_attachments: The raw attachments response
    Returns:
        A list of tuples containing the id, name, format and size of each attachment
    """
    attachments_regex = re.compile(r'(\d+): (.+) \((.+) \/ (.+)\)')
    attachments_list = attachments_regex.findall(raw_attachments)
    return attachments_list


def parse_attachment_content(attachment_id, raw_attachment_content):
    # type: (str, str) -> str
    """
    Parses raw attachment response into the attachment content
    Example input:
        From: root@localhost
        Subject: <ticket subject>
        X-RT-Interface: REST
        Content-Type: text/plain
        Content-Disposition: form-data;
        name="attachment_1";
        filename="mimecast-get-remediation-incident.log";
        filename="mimecast-get-remediation-incident.log"
        Content-Transfer-Encoding: binary
        Content-Length: <length of the content>

        Content: <the actual attachment content...>
    Example output:
        <the actual attachment content...>
    Args:
        attachment_id: The ID of the attachment
        raw_attachment_content: The raw attachment content, should be like the example input

    Returns:
        The actual content
    """
    attachment_content_pattern = re.compile(r'Content: (.*)', flags=re.DOTALL)
    attachment_content = attachment_content_pattern.findall(raw_attachment_content)
    if not attachment_content:
        return_error('Could not parse attachment content for attachment id {}'.format(attachment_id))
    return attachment_content[0]


def get_ticket_attachments_command():
    ticket_id = demisto.args().get('ticket-id')
    attachments, attachments_content = get_ticket_attachments(ticket_id)
    if attachments:
        ec = {
            'RTIR.Ticket(val.ID && val.ID === obj.ID)': {
                'ID': int(ticket_id),
                'Attachment': attachments
            }
        }
        title = 'RTIR ticket {} attachments'.format(ticket_id)
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': attachments,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, attachments, removeNull=True),
            'EntryContext': ec
        })
        demisto.results(attachments_content)
    else:
        demisto.results('No attachments found.')


def get_ticket_history_by_id(ticket_id, history_id):
    """Accepts ticket ID and history ID as input and returns a dictionary of ticket history entry properties"""

    suffix_url = 'ticket/{}/history/id/{}'.format(ticket_id, history_id)
    raw_history = http_request('GET', suffix_url)
    return parse_history_response(raw_history.content)


def parse_history_response(raw_history):
    # type: (str) -> dict
    """
    Parses raw history string into dict
    Example input:
        RT/4.4.2 200 Ok

        # 24/24 (id/80/total)

        id: 80
        Ticket: 5
        TimeTaken: 0
        Type: Create
        Field:
        OldValue:
        NewValue: some new value
        Data:
        Description: Ticket created by root
        Content: Some
        Multi line
        Content
        Creator: root
        Created: 2018-07-09 11:25:59
        Attachments:
    Example output:
        {'ID': '80',
         'Ticket': '5',
         'TimeTaken': '0',
         'Type': 'Create',
         'Field': '',
         'OldValue': '',
         'NewValue': 'some new value',
         'Data': '',
         'Description': 'Ticket created by root',
         'Content': 'Some\nMulti line\nContent',
         'Creator': 'root',
         'Created': '2018-07-09 11:25:59',
         'Attachments': ''}

    Args:
        raw_history: The raw ticket history string response

    Returns:
        A pasred dict with keys and values
    """
    keys = re.findall(r'^([a-z|A-Z]+):', raw_history, flags=re.MULTILINE)
    values = re.split(r'\n[a-z|A-Z]+:', raw_history)[1:]
    if len(keys) != len(values):
        return {}
    current_history_context = {key.upper() if key == 'id' else key: value.strip() for key, value in zip(keys, values)}
    return current_history_context


def get_ticket_history(ticket_id):
    suffix_url = 'ticket/{}/history'.format(ticket_id)
    raw_history = http_request('GET', suffix_url)
    history_context = []
    headers = ['ID', 'Created', 'Creator', 'Description', 'Content']
    data = raw_history.text.split('\n')
    data = data[4:]
    for line in data:
        history_id = line.split(': ')[0]
        if not history_id:
            continue
        history_response = get_ticket_history_by_id(ticket_id, history_id)
        history_context.append(history_response)
    return history_context, headers


def get_ticket_history_command():
    ticket_id = demisto.args().get('ticket-id')
    history_context, headers = get_ticket_history(ticket_id)
    if history_context:
        ec = {
            'RTIR.Ticket(val.ID && val.ID === obj.ID)': {
                'ID': int(ticket_id),
                'History': history_context
            }
        }
        title = 'RTIR ticket {} history'.format(ticket_id)
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': history_context,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, history_context, headers, removeNull=True),
            'EntryContext': ec
        })
    else:
        demisto.results('No results found.')


def get_ticket():
    ticket_id = demisto.args().get('ticket-id')
    raw_ticket = get_ticket_request(ticket_id)
    if not raw_ticket or 'Ticket {} does not exist'.format(ticket_id) in raw_ticket.text:
        return_error('Failed to get ticket, possibly does not exist.')
    ticket_context = []
    data = raw_ticket.content.split('\n')
    data = data[2:]
    current_ticket = {}
    for line in data:
        split_line = line.split(': ')
        if len(split_line) == 2:
            current_ticket[split_line[0]] = split_line[1]
    ticket = {
        'ID': ticket_string_to_id(current_ticket['id']),
        'Subject': current_ticket.get('Subject'),
        'State': current_ticket.get('Status'),
        'Creator': current_ticket.get('Creator'),
        'Created': current_ticket.get('Created'),
        'Priority': current_ticket.get('Priority'),
        'InitialPriority': current_ticket.get('InitialPriority'),
        'FinalPriority': current_ticket.get('FinalPriority'),
        'Queue': current_ticket.get('Queue'),
        'Owner': current_ticket.get('Owner')
    }

    for key in data:  # Adding ticket custom fields to outputs
        if key.startswith('CF.'):
            split_key = key.split(':')
            if split_key[0]:
                custom_field_regex = re.findall(CURLY_BRACKETS_REGEX, key)[0].replace(' ',
                                                                                      '')  # Regex and removing white spaces
                ticket[custom_field_regex] = split_key[1]

    suffix_url = 'ticket/{}/links/show'.format(ticket_id)
    raw_links = http_request('GET', suffix_url)
    links = parse_ticket_links(raw_links.text)
    ticket['LinkedTo'] = links

    ticket_context.append(ticket)
    ec = {
        'RTIR.Ticket(val.ID && val.ID === obj.ID)': ticket
    }
    title = 'RTIR ticket {}'.format(ticket_id)
    headers = ['ID', 'Subject', 'Status', 'Priority', 'Created', 'Queue', 'Creator', 'Owner', 'InitialPriority',
               'FinalPriority', 'LinkedTo']
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': ticket_context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, ticket, headers, removeNull=True),
        'EntryContext': ec
    })


def parse_ticket_links(raw_links):
    # type: (str) -> list
    """
    Parses the link IDs from the ticket link response
    An example to an expected 'raw_links' is:
    "RT/4.4.4 200 Ok

    id: ticket/68315/links

    Members: some-url.com/ticket/65461,
             some-url.com/ticket/65462,
             some-url.com/ticket/65463"

    For 'raw_links' as descripbed above- the output will be [{'ID': '65461'}, {'ID': '65462'}, {'ID': '65463'}]
    Args:
        raw_links: The raw links string response

    Returns:
        A list of parsed IDs
    """
    links = [{'ID': link} for link in re.findall(r'/ticket/(\d+)', raw_links)] if raw_links else []
    return links


def add_comment_request(ticket_id, encoded):
    suffix_url = 'ticket/{}/comment'.format(ticket_id)
    added_comment = http_request('POST', suffix_url, data=encoded)

    return added_comment


def add_comment_attachment(ticket_id, encoded, files_data):
    suffix_url = 'ticket/{}/comment'.format(ticket_id)
    comment = http_request('POST', suffix_url, files=files_data)

    return comment.content


def add_comment():
    ticket_id = demisto.args().get('ticket-id')
    text = demisto.args().get('text')
    content = 'Action: comment\n'
    if text:
        content += '\nText: ' + text.encode('utf-8')
    attachments = demisto.args().get('attachment')
    if attachments:
        files_data = {}
        if isinstance(attachments, list):
            attachments_list = attachments
        else:  # Given as string
            attachments_list = attachments.split(',')
        for i, file_pair in enumerate(attachments_list):
            file = demisto.getFilePath(file_pair)
            file_name = file['name']
            files_data['attachment_{:d}'.format(i + 1)] = (file_name, open(file['path'], 'rb'))
            content += 'Attachment: {}\n'.format(file_name)

    encoded = "content=" + urllib.quote_plus(content)
    if attachments:
        files_data.update({'content': (None, content)})  # type: ignore
        comment = add_comment_attachment(ticket_id, encoded, files_data)
        return_outputs('Added comment to ticket {} successfully.'.format(ticket_id), {}, comment)
    else:
        added_comment = add_comment_request(ticket_id, encoded)
        if '200' in added_comment.content:
            demisto.results('Added comment to ticket {} successfully.'.format(ticket_id))
        else:
            return_error('Failed to add comment')


def add_reply_request(ticket_id, encoded):
    suffix_url = 'ticket/{}/comment'.format(ticket_id)
    added_reply = http_request('POST', suffix_url, data=encoded)

    return added_reply


def add_reply():
    ticket_id = demisto.args().get('ticket-id')
    content = 'Action: comment\n'
    text = demisto.args().get('text')
    if text:
        content += '\nText: ' + text.encode('utf-8')
    cc = demisto.args().get('cc')
    if cc:
        content += '\nCc: ' + cc
    try:
        encoded = "content=" + urllib.quote_plus(content)
        added_reply = add_reply_request(ticket_id, encoded)
        if '200' in added_reply.content:
            demisto.results('Replied successfully to ticket {}.'.format(ticket_id))
        else:
            return_error('Failed to reply')
    except Exception as e:
        demisto.error(str(e))
        return_error('Failed to reply')


def get_ticket_id(ticket):
    return int(ticket['ID'])


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_ticket_id = last_run['ticket_id'] if (last_run and last_run['ticket_id']) else 0
    raw_query = 'id>{}+AND+Priority>{}+AND+Queue={}{}{}'.format(last_ticket_id, FETCH_PRIORITY, apostrophe, FETCH_QUEUE,
                                                                apostrophe)
    if FETCH_STATUS:
        status_list = FETCH_STATUS.split(',')
        status_query = '+AND+('
        for status in status_list:
            status_query += 'Status={}{}{}+OR+'.format(apostrophe, status, apostrophe)
        status_query = fix_query_suffix(status_query)
        raw_query += status_query + ')'
    tickets = parse_ticket_data(raw_query)
    tickets.sort(key=get_ticket_id)
    fetch_batch_limit = int(demisto.params().get('fetch_limit', 0))
    tickets = tickets if (fetch_batch_limit == 0) else tickets[:fetch_batch_limit]
    incidents = []
    max_ticket_id = last_ticket_id
    for ticket in tickets:
        ticket_id = ticket['ID']
        history_context, _ = get_ticket_history(ticket_id)
        ticket['History'] = history_context
        incidents.append(ticket_to_incident(ticket))
        max_ticket_id = max(max_ticket_id, ticket_id)
    if tickets:
        demisto.setLastRun({'ticket_id': max_ticket_id})
    demisto.incidents(incidents)


''' EXECUTION CODE '''


def main():
    handle_proxy()

    # disable insecure warnings
    requests.packages.urllib3.disable_warnings()

    ''' GLOBAL VARS '''
    global SERVER, USERNAME, PASSWORD, BASE_URL, USE_SSL, FETCH_PRIORITY, FETCH_STATUS, FETCH_QUEUE, HEADERS, REFERER
    SERVER = demisto.params().get('server', '')[:-1] if demisto.params().get('server', '').endswith(
        '/') else demisto.params().get('server', '')
    USERNAME = demisto.params()['credentials']['identifier']
    PASSWORD = demisto.params()['credentials']['password']
    BASE_URL = urljoin(SERVER, '/REST/1.0/')
    USE_SSL = not demisto.params().get('unsecure', False)
    FETCH_PRIORITY = int(demisto.params()['fetch_priority']) - 1
    FETCH_STATUS = demisto.params()['fetch_status']
    FETCH_QUEUE = demisto.params()['fetch_queue']
    REFERER = demisto.params().get('referer')
    HEADERS = {'Referer': REFERER} if REFERER else {}

    LOG('command is %s' % (demisto.command(),))
    try:
        if demisto.command() == 'test-module':
            login()
            logout()
            demisto.results('ok')

        if demisto.command() in {'fetch-incidents'}:
            fetch_incidents()

        elif demisto.command() == 'rtir-create-ticket':
            create_ticket()

        elif demisto.command() == 'rtir-search-ticket':
            search_ticket()

        elif demisto.command() == 'rtir-resolve-ticket':
            close_ticket()

        elif demisto.command() == 'rtir-edit-ticket':
            edit_ticket()

        elif demisto.command() == 'rtir-ticket-history':
            get_ticket_history_command()

        elif demisto.command() == 'rtir-ticket-attachments':
            get_ticket_attachments_command()

        elif demisto.command() == 'rtir-get-ticket':
            get_ticket()

        elif demisto.command() == 'rtir-add-comment':
            add_comment()

        elif demisto.command() == 'rtir-add-reply':
            add_reply()

    except Exception as e:
        LOG(e.message)
        LOG.print_log()
        raise


if __name__ in ('__builtin__', 'builtins'):
    main()
