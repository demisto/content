from CommonServerPython import *

''' IMPORTS '''
import requests
import os
import json
import re
import urllib

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
SERVER = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
BASE_URL = SERVER + '/REST/1.0/'
USE_SSL = not demisto.params().get('unsecure', False)
FETCH_PRIORITY = int(demisto.params()['fetch_priority']) - 1
FETCH_STATUS = demisto.params()['fetch_status']
FETCH_QUEUE = demisto.params()['fetch_queue']
CURLY_BRACKETS_REGEX = r'\{(.*?)\}'  # Extracts string in curly brackets, e.g. '{string}' -> 'string'
apostrophe = "'"
SESSION = requests.session()
REFERER = demisto.params().get('referer')
HEADERS = {'Referer': REFERER} if REFERER else {}

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
    SESSION.post(SERVER, data=data)  # type: ignore


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

        current_ticket_search = {}
        for entity in search_ticket:
            if ': ' in entity:
                header, content = entity.split(': ', 1)
                if 'ID' in header:
                    content = ticket_string_to_id(content)
                if header in {'ID', 'Subject', 'Status', 'Priority', 'Created', 'Queue', 'Creator', 'Owner',
                              'InitialPriority', 'FinalPriority'}:
                    current_ticket_search[header] = content

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
    queue = demisto.args().get('queue')
    data = 'id: ticket/new\nQueue: {}\n'.format(queue)

    subject = demisto.args().get('subject')
    if subject:
        data += "Subject: {}\n".format(subject)

    requestor = demisto.args().get('requestor')
    if requestor:
        data += "Requestor: {}\n".format(requestor)

    cc = demisto.args().get('cc', '')
    if cc:
        data += "Cc: {}\n".format(cc)

    admin_cc = demisto.args().get('admin-cc', '')
    if admin_cc:
        data += "AdminCc: {}\n".format(admin_cc)

    owner = demisto.args().get('owner')
    if owner:
        data += "Owner: {}\n".format(owner)

    status = demisto.args().get('status')
    if status:
        data += "Status: {}\n".format(status)

    priority = demisto.args().get('priority')
    if priority:
        data += "Priority: {}\n".format(priority)

    initial_priority = demisto.args().get('initial-priority')
    if initial_priority:
        data += "Initial-priority: {}\n".format(initial_priority)

    final_priority = demisto.args().get('final-priority')
    if final_priority:
        data += "FinalPriority: {}\n".format(final_priority)

    text = demisto.args().get('text')
    if text:
        data += "Text: {}\n".format(unicode(text).encode('utf-8'))

    customfields = demisto.args().get('customfields')
    if customfields:
        cf_list = customfields.split(',')
        for cf in cf_list:
            equal_index = cf.index('=')
            key = 'CF-{}: '.format(cf[:equal_index])
            value = cf[equal_index + 1:]
            data = data + key + value + '\n'

    attachments = demisto.args().get('attachment')
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


def search_ticket():
    raw_query = ''
    ticket_id = demisto.args().get('ticket-id')

    if ticket_id:
        raw_query += 'id={}{}{}+AND+'.format(apostrophe, ticket_id, apostrophe)

    subject = demisto.args().get('subject')
    if subject:
        raw_query += 'Subject={}{}{}+AND+'.format(apostrophe, subject, apostrophe)

    status = demisto.args().get('status')
    if status:
        raw_query += 'Status={}{}{}+AND+'.format(apostrophe, status, apostrophe)

    creator = demisto.args().get('creator')
    if creator:
        raw_query += 'Creator={}{}{}+AND+'.format(apostrophe, creator, apostrophe)

    priority_equal_to = demisto.args().get('priority-equal-to')
    if priority_equal_to:
        raw_query += 'Priority={}{}{}+AND+'.format(apostrophe, priority_equal_to, apostrophe)

    priority_greater_than = demisto.args().get('priority-greater-than')
    if priority_greater_than:
        raw_query += 'Priority>{}{}{}+AND+'.format(apostrophe, priority_greater_than, apostrophe)

    created_after = demisto.args().get('created-after')
    if created_after:
        raw_query += 'Created>{}{}{}+AND+'.format(apostrophe, created_after, apostrophe)

    created_on = demisto.args().get('created-on')
    if created_on:
        raw_query += 'Created={}{}{}+AND+'.format(apostrophe, created_on, apostrophe)

    created_before = demisto.args().get('created-before')
    if created_before:
        raw_query += 'Created<{}{}{}+AND+'.format(apostrophe, created_before, apostrophe)

    owner = demisto.args().get('owner')
    if owner:
        raw_query += 'Created={}{}{}+AND+'.format(apostrophe, owner, apostrophe)

    due = demisto.args().get('due')
    if due:
        raw_query += 'Due={}{}{}+AND+'.format(apostrophe, due, apostrophe)

    queue = demisto.args().get('queue')
    if queue:
        raw_query += 'Queue={}{}{}+AND+'.format(apostrophe, queue, apostrophe)
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

        current_ticket_search = {}
        for entity in search_ticket:
            if ': ' in entity:
                header, content = entity.split(': ', 1)
                if 'ID' in header:
                    content = ticket_string_to_id(content)
                if header in {'ID', 'Subject', 'Status', 'Priority', 'Created', 'Queue', 'Creator', 'Owner',
                              'InitialPriority', 'FinalPriority'}:
                    current_ticket_search[header] = content

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
        encoded = "content=" + urllib.quote_plus(content)
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
    raw_attachments = http_request('GET', suffix_url).content

    attachments = []
    attachments_content = []
    split_raw_attachment = raw_attachments.split('\n')
    for i in xrange(len(split_raw_attachment)):
        if 'Attachments' in split_raw_attachment[i]:
            attachment_lines = split_raw_attachment[i:]
            for line in attachment_lines:
                if line and 'Unnamed' not in line:
                    split_line = line.split(': ')
                    if 'Attachments' in split_line:
                        starting_index = 1
                    else:
                        starting_index = 0
                    attachment_id = split_line[starting_index]
                    attachment_id = attachment_id.strip()
                    attachment_name = split_line[starting_index + 1]
                    attachment_type = attachment_name.replace('(', '').replace(')', '')
                    split_line_type = attachment_type.split(' ')
                    attachment_name = split_line_type[0]
                    attachment_type = split_line_type[1]
                    attachment_size = split_line_type[3]

                    attachments.append({
                        'ID': attachment_id,
                        'Name': attachment_name,
                        'Type': attachment_type,
                        'Size': attachment_size
                    })

                    suffix_url = 'ticket/{}/attachments/{}'.format(ticket_id, attachment_id)
                    attachment_content = http_request('GET', suffix_url).content
                    attachments_content.append(fileResult(attachment_name, attachment_content))
    return attachments, attachments_content


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

    return raw_history


def get_ticket_history(ticket_id):
    suffix_url = 'ticket/{}/history'.format(ticket_id)
    raw_history = http_request('GET', suffix_url)
    history_context = []
    headers = ['ID', 'Created', 'Creator', 'Description']
    data = raw_history.text.split('\n')
    data = data[4:]
    for line in data:
        split_line = line.split(': ')
        current_raw_ticket_history = get_ticket_history_by_id(ticket_id, split_line[0]).content
        current_raw_ticket_history = current_raw_ticket_history.split('\n')
        current_raw_ticket_history = current_raw_ticket_history[4:]
        id_ticket = current_raw_ticket_history[0].upper()
        current_raw_ticket_history[0] = id_ticket
        current_history_context = {}
        for entity in current_raw_ticket_history:
            if ': ' in entity:
                header, content = entity.split(': ', 1)
                if header in {'ID', 'Content', 'Created', 'Creator', 'Description', 'NewValue'}:
                    current_history_context[header] = content
        if current_history_context:
            history_context.append(current_history_context)
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
    if not raw_ticket:
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

        if ticket:
            ticket_context.append(ticket)

    suffix_url = 'ticket/{}/links/show'.format(ticket_id)
    raw_links = http_request('GET', suffix_url)
    if raw_links:
        links = []
        for raw_link in raw_links:
            link_id = raw_link.rsplit('/', 3)[-2]
            links.append({
                'ID': link_id
            })
        ticket['LinkedTo'] = links
    ec = {
        'RTIR.Ticket(val.ID && val.ID === obj.ID)': ticket
    }
    title = 'RTIR ticket {}'.format(ticket_id)
    headers = ['ID', 'Subject', 'Status', 'Priority', 'Created', 'Queue', 'Creator', 'Owner', 'InitialPriority',
               'FinalPriority']
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': ticket_context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, ticket, headers, removeNull=True),
        'EntryContext': ec
    })


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
    except Exception, e:
        demisto.error(str(e))
        return_error('Failed to reply')


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
        raw_query += status_query + ')'
    tickets = parse_ticket_data(raw_query)
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

LOG('command is %s' % (demisto.command(),))
try:
    login()
    if demisto.command() == 'test-module':
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

except Exception, e:
    LOG(e.message)
    LOG.print_log()
    raise

finally:
    logout()
