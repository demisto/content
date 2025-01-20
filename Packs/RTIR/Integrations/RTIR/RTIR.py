from CommonServerPython import *

''' IMPORTS '''
import tempfile
import requests
import json
import re
import urllib


''' GLOBAL VARS '''
SERVER = None
BASE_URL = ''
USERNAME = None
PASSWORD = None
TOKEN = ''
CERTIFICATE = None
PRIVATE_KEY = None
USE_SSL = None
FETCH_PRIORITY = 0
FETCH_STATUS = ''
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


class TempFile:
    def __init__(self, data):
        _, self.path = tempfile.mkstemp()
        with open(self.path, 'w') as temp_file:
            temp_file.write(data)

    def __del__(self):
        os.remove(self.path)


def http_request(method, suffix_url, data=None, files=None, query=None):
    # Returns the http request

    url = urljoin(BASE_URL, suffix_url)
    params = {'user': USERNAME, 'pass': PASSWORD} if not TOKEN else {}
    if query:
        params.update(query)

    cert = TempFile(CERTIFICATE) if CERTIFICATE else None
    key = TempFile(PRIVATE_KEY) if PRIVATE_KEY else None
    cert_key_pair = (cert.path, key.path) if cert and key else None  # type: ignore[attr-defined]

    response = SESSION.request(method, url, data=data, params=params, files=files,
                               headers=HEADERS, cert=cert_key_pair)

    # handle request failure
    if response.status_code not in {200}:
        message = parse_error_response(response)
        raise DemistoException(f'Error in API call with status code {response.status_code}\n{message}')

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


def parse_ticket_data(raw_query):
    raw_tickets = search_ticket_request(raw_query)
    headers = ['ID', 'Subject', 'Status', 'Priority', 'Created', 'Queue', 'Creator', 'Owner', 'InitialPriority',
               'FinalPriority']
    search_context = []
    data = raw_tickets.text.split('\n')
    data = data[2:]
    for line in data:
        split_line = line.split(': ')
        search_ticket = get_ticket_request(split_line[0]).text
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


def test_module():
    res = http_request('GET', '')
    if '401 Credentials required' in res.text:
        raise DemistoException("Error: Test failed. please check your credentials.")
    elif "200 Ok" in res.text:
        return_results('ok')


def create_ticket_request(encoded):
    suffix_url = 'ticket/new'
    ticket_id = http_request('POST', suffix_url, data=encoded)
    return ticket_id


def edit_links(ticket_id, member_of, members, depends_on, depended_on_by, refers_to, referred_to_by):

    content = ""
    if member_of:
        content = f"MemberOf: {member_of}\n"
    if members:
        content += f"Members: {members}\n"
    if depends_on:
        content += f"DependsOn: {depends_on}\n"
    if depended_on_by:
        content += f"DependedOnBy: {depended_on_by}\n"
    if refers_to:
        content += f"RefersTo: {refers_to}\n"
    if referred_to_by:
        content += f"ReferredToBy: {referred_to_by}\n"

    data = f"content={urllib.parse.quote_plus(content)}"

    suffix_url = f'ticket/{ticket_id}/links'
    return http_request('POST', suffix_url, data=data)


def create_ticket_attachments_request(encoded, files_data):
    suffix_url = 'ticket/new'
    ticket_id = http_request('POST', suffix_url, files=files_data)

    return ticket_id


def create_ticket():
    args = dict(demisto.args())
    args = {arg: value for arg, value in args.items() if isinstance(value, str)}
    queue = args.get('queue')
    data = f'id: ticket/new\nQueue: {queue}\n'

    subject = args.get('subject')
    if subject:
        data += f"Subject: {subject}\n"

    requestor = args.get('requestor')
    if requestor:
        data += f"Requestor: {requestor}\n"

    cc = args.get('cc', '')
    if cc:
        data += f"Cc: {cc}\n"

    admin_cc = args.get('admin-cc', '')
    if admin_cc:
        data += f"AdminCc: {admin_cc}\n"

    owner = args.get('owner')
    if owner:
        data += f"Owner: {owner}\n"

    status = args.get('status')
    if status:
        data += f"Status: {status}\n"

    priority = args.get('priority')
    if priority:
        data += f"Priority: {priority}\n"

    initial_priority = args.get('initial-priority')
    if initial_priority:
        data += f"Initial-priority: {initial_priority}\n"

    final_priority = args.get('final-priority')
    if final_priority:
        data += f"FinalPriority: {final_priority}\n"

    text = args.get('text')
    if text:
        data += f"Text: {text}\n"

    customfields = args.get('customfields')
    if customfields:
        cf_list = customfields.split(',')
        for cf in cf_list:
            equal_index = cf.index('=')
            key = f'CF-{cf[:equal_index]}: '
            value = cf[equal_index + 1:]
            data = data + key + value + '\n'

    attachments = args.get('attachment', '')
    files_data = {}
    if attachments:

        if isinstance(attachments, list):  # Given as list
            attachments_list = attachments
        else:  # Given as string
            attachments_list = attachments.split(',')
        for i, file_pair in enumerate(attachments_list):
            file = demisto.getFilePath(file_pair)
            file_name = file['name']
            files_data[f'attachment_{i + 1:d}'] = (file_name, open(file['path'], 'rb'))
            data += f'Attachment: {file_name}'

    encoded = "content=" + urllib.parse.quote_plus(data)
    if attachments:
        files_data.update({'content': (None, data)})  # type: ignore
        raw_ticket_res = create_ticket_attachments_request(encoded, files_data)
    else:
        raw_ticket_res = create_ticket_request(encoded)
    ticket_id = re.findall('\d+', raw_ticket_res.text)[-1]
    demisto.debug(f"got ticket with id: {ticket_id}")
    if ticket_id == -1:
        raise DemistoException('Ticket creation failed')

    member_of = args.get('member-of')
    members = args.get('members')
    depends_on = args.get('depends-on')
    depended_on_by = args.get('depended-on-by')
    refers_to = args.get('refers-to')
    referred_to_by = args.get('referred-to-by')

    if members or member_of or depends_on or depended_on_by or refers_to or referred_to_by:
        edit_links(ticket_id, member_of, members, depends_on, depended_on_by, refers_to, referred_to_by)

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
    hr = f'Ticket {ticket_id} was created successfully.'
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': raw_ticket_res.text,
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    })


def get_ticket_request(ticket_id):
    suffix_url = f'ticket/{ticket_id}/show'
    return http_request('GET', suffix_url)


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
    args = {arg: value for arg, value in args.items() if isinstance(value, str)}
    ticket_id = args.get('ticket-id')
    if ticket_id:
        raw_query += f'id={apostrophe}{ticket_id}{apostrophe}+AND+'

    subject = args.get('subject')
    if subject:
        raw_query += f'Subject={apostrophe}{subject}{apostrophe}+AND+'

    status = args.get('status')
    if status:
        raw_query += f'Status={apostrophe}{status}{apostrophe}+AND+'

    creator = args.get('creator')
    if creator:
        raw_query += f'Creator={apostrophe}{creator}{apostrophe}+AND+'

    priority_equal_to = args.get('priority-equal-to')
    if priority_equal_to:
        raw_query += f'Priority={apostrophe}{priority_equal_to}{apostrophe}+AND+'

    priority_greater_than = args.get('priority-greater-than')
    if priority_greater_than:
        raw_query += f'Priority>{apostrophe}{priority_greater_than}{apostrophe}+AND+'

    created_after = args.get('created-after')
    if created_after:
        raw_query += f'Created>{apostrophe}{created_after}{apostrophe}+AND+'

    created_on = args.get('created-on')
    if created_on:
        raw_query += f'Created={apostrophe}{created_on}{apostrophe}+AND+'

    created_before = args.get('created-before')
    if created_before:
        raw_query += f'Created<{apostrophe}{created_before}{apostrophe}+AND+'

    owner = args.get('owner')
    if owner:
        raw_query += f'Created={apostrophe}{owner}{apostrophe}+AND+'

    due = args.get('due')
    if due:
        raw_query += f'Due={apostrophe}{due}{apostrophe}+AND+'

    queue = args.get('queue')
    if queue:
        raw_query += f'Queue={apostrophe}{queue}{apostrophe}+AND+'
    raw_query = fix_query_suffix(raw_query)
    return raw_query


def build_ticket(rtir_search_ticket):
    current_ticket_search = {}
    for entity in rtir_search_ticket:
        if ': ' in entity:
            header, content = entity.split(': ', 1)
            if header == 'ID':
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
    data = raw_tickets.text.split('\n')
    data = data[2:]
    results_limit = int(demisto.args().get('results_limit', 0))
    data = data if (results_limit == 0) else data[:results_limit]
    for line in data:
        split_line = line.split(': ')
        empty_line_response = ['NO OBJECTS SPECIFIED.', '']
        is_line_non_empty = split_line[0] != ''
        if is_line_non_empty:
            search_ticket = get_ticket_request(split_line[0]).text
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
    suffix_url = f'ticket/{ticket_id}/edit'
    closed_ticket = http_request('POST', suffix_url, data=encoded)

    return closed_ticket


def close_ticket():
    ticket_id = demisto.args().get('ticket-id')
    content = '\nStatus: resolved'
    encoded = "content=" + urllib.parse.quote_plus(content)
    closed_ticket = close_ticket_request(ticket_id, encoded)
    if '200 Ok' in closed_ticket.text:
        ec = {
            'RTIR.Ticket(val.ID && val.ID === obj.ID)': {
                'ID': int(ticket_id),
                'State': 'resolved'
            }
        }
        hr = f'Ticket {ticket_id} was resolved successfully.'
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': hr,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        })
    else:
        raise DemistoException('Failed to resolve ticket')


def edit_ticket_request(ticket_id, encoded):
    suffix_url = f'ticket/{ticket_id}/edit'
    return http_request('POST', suffix_url, data=encoded)


def edit_ticket():
    args = demisto.args()
    arguments_given = False
    ticket_id = args.get('ticket-id')
    content = 'ID: ' + ticket_id
    kwargs = {}
    subject = args.get('subject')
    if subject:
        content += '\nSubject: ' + subject
        arguments_given = True
        kwargs['Subject'] = subject

    owner = args.get('owner')
    if owner:
        content += '\nOwner: ' + owner
        arguments_given = True
        kwargs['Owner'] = owner

    status = args.get('status')
    if status:
        content += '\nStatus: ' + status
        arguments_given = True
        kwargs['Status'] = status

    priority = args.get('priority')
    if priority:
        content += '\nPriority: ' + priority
        arguments_given = True
        kwargs['Priority'] = int(priority)

    final_priority = args.get('final-priority')
    if final_priority:
        content += '\nFinalPriority: ' + final_priority
        arguments_given = True
        kwargs['FinalPriority'] = int(final_priority)

    due = args.get('due')
    if due:
        content += '\nDue: ' + due
        arguments_given = True
        kwargs['Due'] = due

    customfields = args.get('customfields')
    if customfields:
        arguments_given = True
        cf_list = customfields.split(',')
        for cf in cf_list:
            equal_index = cf.index('=')
            key = f'CF-{cf[:equal_index]}: '
            value = cf[equal_index + 1:]
            content += '\n' + key + value

    edit_succeeded = False
    member_of = args.get('member-of')
    members = args.get('members')
    depends_on = args.get('depends-on')
    depended_on_by = args.get('depended-on-by')
    refers_to = args.get('refers-to')
    referred_to_by = args.get('referred-to-by')

    if members or member_of or depends_on or depended_on_by or refers_to or referred_to_by:
        links = edit_links(ticket_id, member_of, members, depends_on, depended_on_by, refers_to, referred_to_by)
        if "200 Ok" in links.text:
            edit_succeeded = True

    if arguments_given:
        edited_ticket = edit_ticket_request(ticket_id, f"content={urllib.parse.quote_plus(content)}")
        if "200 Ok" in edited_ticket.text:
            edit_succeeded = True

    elif not members and not member_of:
        raise DemistoException('No arguments were given to edit the ticket.')

    if edit_succeeded:
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

        hr = f'Ticket {ticket_id} was edited successfully.'
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': hr,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        })
    else:
        raise DemistoException('Failed to edit ticket')


def get_ticket_attachments(ticket_id):
    suffix_url = f'ticket/{ticket_id}/attachments'
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

        suffix_url = f'ticket/{ticket_id}/attachments/{attachment_id}'
        raw_attachment_content = http_request('GET', suffix_url).text
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
        raise DemistoException(f'Could not parse attachment content for attachment id {attachment_id}')
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
        title = f'RTIR ticket {ticket_id} attachments'
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

    suffix_url = f'ticket/{ticket_id}/history/id/{history_id}'
    raw_history = http_request('GET', suffix_url)
    return parse_history_response(raw_history.text)


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
    suffix_url = f'ticket/{ticket_id}/history'
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
        title = f'RTIR ticket {ticket_id} history'
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
    if not raw_ticket or f'Ticket {ticket_id} does not exist' in raw_ticket.text:
        raise DemistoException('Failed to get ticket, possibly does not exist.')
    ticket_context = []
    data_list = raw_ticket.text
    data = data_list.split('\n')
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

    suffix_url = f'ticket/{ticket_id}/links/show'
    raw_links = http_request('GET', suffix_url)
    links = parse_ticket_links(raw_links.text)
    ticket['LinkedTo'] = links

    ticket_context.append(ticket)
    ec = {
        'RTIR.Ticket(val.ID && val.ID === obj.ID)': ticket
    }
    title = f'RTIR ticket {ticket_id}'
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
    suffix_url = f'ticket/{ticket_id}/comment'
    added_comment = http_request('POST', suffix_url, data=encoded)

    return added_comment


def add_comment_attachment(ticket_id, encoded, files_data):
    suffix_url = f'ticket/{ticket_id}/comment'
    comment = http_request('POST', suffix_url, files=files_data)

    return comment.text


def add_comment():
    ticket_id = demisto.args().get('ticket-id')
    content = 'Action: comment\n'
    if text := demisto.args().get('text'):
        content += f'\nText: {text}'
    attachments = demisto.args().get('attachment', '')
    files_data = {}
    if attachments:

        if isinstance(attachments, list):
            attachments_list = attachments
        else:  # Given as string
            attachments_list = attachments.split(',')
        for i, file_pair in enumerate(attachments_list):
            file = demisto.getFilePath(file_pair)
            file_name = file['name']
            files_data[f'attachment_{i + 1:d}'] = (file_name, open(file['path'], 'rb'))
            content += f'Attachment: {file_name}\n'

    encoded = f"content={urllib.parse.quote_plus(content)}"
    if attachments:
        files_data.update({'content': (None, content)})  # type: ignore
        comment = add_comment_attachment(ticket_id, encoded, files_data)
        return_outputs(f'Added comment to ticket {ticket_id} successfully.', {}, comment)
    else:
        added_comment = add_comment_request(ticket_id, encoded)
        if '200' in added_comment.text:
            demisto.results(f'Added comment to ticket {ticket_id} successfully.')
        else:
            raise DemistoException('Failed to add comment')


def add_reply_request(ticket_id, encoded):
    suffix_url = f'ticket/{ticket_id}/comment'
    added_reply = http_request('POST', suffix_url, data=encoded)

    return added_reply


def add_reply():
    ticket_id = demisto.args().get('ticket-id')
    content = 'Action: comment\n'
    if (text := demisto.args().get('text')):
        content += f'\nText: {text}'
    if (cc := demisto.args().get('cc')):
        content += f'\nCc: {cc}'
    try:
        encoded = "content=" + urllib.parse.quote_plus(content)
        added_reply = add_reply_request(ticket_id, encoded)
        if '200' in added_reply.text:
            demisto.results(f'Replied successfully to ticket {ticket_id}.')
        else:
            raise DemistoException('Failed to reply')
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException('Failed to reply')


def get_ticket_id(ticket):
    return int(ticket['ID'])


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_ticket_id = last_run['ticket_id'] if (last_run and last_run['ticket_id']) else 0
    raw_query = f'id>{last_ticket_id}+AND+Priority>{FETCH_PRIORITY}+AND+Queue={apostrophe}{FETCH_QUEUE}{apostrophe}'
    if FETCH_STATUS:
        status_list = FETCH_STATUS.split(',')
        status_query = '+AND+('
        for status in status_list:
            status_query += f'Status={apostrophe}{status}{apostrophe}+OR+'
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

    params = demisto.params()
    command = demisto.command()

    try:
        ''' GLOBAL VARS '''
        global SERVER, USERNAME, PASSWORD, BASE_URL, USE_SSL, FETCH_PRIORITY, FETCH_STATUS, FETCH_QUEUE, HEADERS, REFERER, \
            TOKEN, CERTIFICATE, PRIVATE_KEY
        SERVER = params.get('server', '')[:-1] if params.get('server', '').endswith(
            '/') else params.get('server', '')
        USERNAME = params.get('credentials', {}).get('identifier', '')
        PASSWORD = params.get('credentials', {}).get('password', '')
        TOKEN = params.get('token', {}).get('password', '')
        if not (USERNAME and PASSWORD) and not TOKEN:
            raise DemistoException("Username and password or Token must be provided.")
        CERTIFICATE = replace_spaces_in_credential(params.get('certificate', {}).get('identifier'))
        PRIVATE_KEY = replace_spaces_in_credential(params.get('certificate', {}).get('password'))
        BASE_URL = urljoin(SERVER, '/REST/1.0/')
        USE_SSL = not params.get('unsecure', False)
        FETCH_PRIORITY = int(params.get('fetch_priority', "0")) - 1
        FETCH_STATUS = params.get('fetch_status')
        FETCH_QUEUE = params.get('fetch_queue')
        REFERER = params.get('referer')
        HEADERS = {"Authorization": f"token {TOKEN}"} if TOKEN else {}
        HEADERS |= {'Referer': REFERER} if REFERER else {}

        demisto.debug(f'Command being called is {command}')
        if command == 'test-module':
            test_module()

        if command in {'fetch-incidents'}:
            fetch_incidents()

        elif command == 'rtir-create-ticket':
            create_ticket()

        elif command == 'rtir-search-ticket':
            search_ticket()

        elif command == 'rtir-resolve-ticket':
            close_ticket()

        elif command == 'rtir-edit-ticket':
            edit_ticket()

        elif command == 'rtir-ticket-history':
            get_ticket_history_command()

        elif command == 'rtir-ticket-attachments':
            get_ticket_attachments_command()

        elif command == 'rtir-get-ticket':
            get_ticket()

        elif command == 'rtir-add-comment':
            add_comment()

        elif command == 'rtir-add-reply':
            add_reply()

    except Exception as e:
        return_error(
            f'Failed to execute {command} command. Error: {str(e)}'
        )


if __name__ in ('__builtin__', 'builtins', "__main__"):
    main()
