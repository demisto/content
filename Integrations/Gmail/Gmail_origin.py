import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import re
import json
import base64
from datetime import datetime, timedelta
import httplib2
import urlparse
from distutils.util import strtobool
import sys
from HTMLParser import HTMLParser, HTMLParseError
from htmlentitydefs import name2codepoint

from apiclient import discovery
from oauth2client import service_account


''' GLOBAL VARS '''
ADMIN_EMAIL = None
PRIVATE_KEY_CONTENT = None
GAPPS_ID = None
SCOPES = ['https://www.googleapis.com/auth/admin.directory.user.readonly']
PROXY = demisto.params().get('proxy')
DISABLE_SSL = demisto.params().get('insecure', False)


''' HELPER FUNCTIONS '''


class TextExtractHtmlParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self._texts = []  # type: list
        self._ignore = False

    def handle_starttag(self, tag, attrs):
        if tag in ('p', 'br') and not self._ignore:
            self._texts.append('\n')
        elif tag in ('script', 'style'):
            self._ignore = True

    def handle_startendtag(self, tag, attrs):
        if tag in ('br', 'tr') and not self._ignore:
            self._texts.append('\n')

    def handle_endtag(self, tag):
        if tag in ('p', 'tr'):
            self._texts.append('\n')
        elif tag in ('script', 'style'):
            self._ignore = False

    def handle_data(self, data):
        if data and not self._ignore:
            stripped = data.strip()
            if stripped:
                self._texts.append(re.sub(r'\s+', ' ', stripped))

    def handle_entityref(self, name):
        if not self._ignore and name in name2codepoint:
            self._texts.append(unichr(name2codepoint[name]))

    def handle_charref(self, name):
        if not self._ignore:
            if name.startswith('x'):
                c = unichr(int(name[1:], 16))
            else:
                c = unichr(int(name))
            self._texts.append(c)

    def get_text(self):
        return "".join(self._texts)


def html_to_text(html):
    parser = TextExtractHtmlParser()
    try:
        parser.feed(html)
        parser.close()
    except HTMLParseError:
        pass
    return parser.get_text()


def get_http_client_with_proxy():
    proxies = handle_proxy()
    if not proxies or not proxies['https']:
        raise Exception('https proxy value is empty. Check Demisto server configuration')
    https_proxy = proxies['https']
    if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
        https_proxy = 'https://' + https_proxy
    parsed_proxy = urlparse.urlparse(https_proxy)
    proxy_info = httplib2.ProxyInfo(
        proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # disable-secrets-detection
        proxy_host=parsed_proxy.hostname,
        proxy_port=parsed_proxy.port,
        proxy_user=parsed_proxy.username,
        proxy_pass=parsed_proxy.password)
    return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=DISABLE_SSL)


def get_credentials(additional_scopes=None, delegated_user=None):
    """Gets valid user credentials from storage.

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.

    Returns:
        Credentials, the obtained credential.
    """
    if not delegated_user or delegated_user == 'me':
        delegated_user = ADMIN_EMAIL
    scopes = SCOPES
    if additional_scopes is not None:
        scopes += additional_scopes

    cred = service_account.ServiceAccountCredentials.from_json_keyfile_dict(json.loads(PRIVATE_KEY_CONTENT),  # type: ignore
                                                                            scopes=scopes)

    return cred.create_delegated(delegated_user)


def get_service(serviceName, version, additional_scopes=None, delegated_user=None):
    credentials = get_credentials(additional_scopes=additional_scopes, delegated_user=delegated_user)
    if PROXY or DISABLE_SSL:
        http_client = credentials.authorize(get_http_client_with_proxy())
        return discovery.build(serviceName, version, http=http_client)
    return discovery.build(serviceName, version, credentials=credentials)


def parse_mail_parts(parts):
    body = u''
    html = u''
    attachments = []  # type: list
    for part in parts:
        if 'multipart' in part['mimeType']:
            part_body, part_html, part_attachments = parse_mail_parts(
                part['parts'])
            body += part_body
            html += part_html
            attachments.extend(part_attachments)
        elif len(part['filename']) == 0:
            text = unicode(base64.urlsafe_b64decode(
                part['body'].get('data', '').encode('ascii')), 'utf-8')
            if 'text/html' in part['mimeType']:
                html += text
            else:
                body += text

        else:
            attachments.append({
                'ID': part['body']['attachmentId'],
                'Name': part['filename']
            })

    return body, html, attachments


def get_email_context(email_data, mailbox):
    context_headers = email_data.get('payload', {}).get('headers', [])
    context_headers = [{'Name': v['name'], 'Value':v['value']}
                       for v in context_headers]
    headers = dict([(h['Name'].lower(), h['Value']) for h in context_headers])
    body = demisto.get(email_data, 'payload.body.data')
    body = body.encode('ascii') if body is not None else ''
    parsed_body = base64.urlsafe_b64decode(body)

    context = {
        'Type': 'Gmail',
        'Mailbox': ADMIN_EMAIL if mailbox == 'me' else mailbox,
        'ID': email_data['id'],
        'ThreadId': email_data['threadId'],
        'Labels': ', '.join(email_data['labelIds']),
        'Headers': context_headers,
        'Attachments': email_data.get('payload', {}).get('filename', ''),
        # only for format 'raw'
        'RawData': email_data.get('raw'),
        # only for format 'full' and 'metadata'
        'Format': headers.get('content-type', '').split(';')[0],
        'Subject': headers.get('subject'),
        'From': headers.get('from'),
        'To': headers.get('to'),
        # only for format 'full'
        'Body': unicode(parsed_body, 'utf-8'),

        # only for incident
        'Cc': headers.get('cc', []),
        'Bcc': headers.get('bcc', []),
        'Date': headers.get('date', ''),
        'Html': None,
    }

    if 'text/html' in context['Format']:  # type: ignore
        context['Html'] = context['Body']
        context['Body'] = html_to_text(context['Body'])

    if 'multipart' in context['Format']:  # type: ignore
        context['Body'], context['Html'], context['Attachments'] = parse_mail_parts(
            email_data.get('payload', {}).get('parts', []))
        context['Attachment Names'] = ', '.join(
            [attachment['Name'] for attachment in context['Attachments']])  # type: ignore

    return context, headers


TIME_REGEX = re.compile(r'^([\w,\d: ]*) (([+-]{1})(\d{2}):?(\d{2}))?[\s\w\(\)]*$')


def parse_time(t):
    # there is only one time refernce is the string
    base_time, _, sign, hours, minutes = TIME_REGEX.findall(t)[0]

    if all([sign, hours, minutes]):
        seconds = int(sign + hours) * 3600 + int(sign + minutes) * 60
        parsed_time = datetime.strptime(
            base_time, '%a, %d %b %Y %H:%M:%S') + timedelta(seconds=seconds)
        return parsed_time.isoformat() + 'Z'
    else:
        return datetime.strptime(base_time, '%a, %d %b %Y %H:%M:%S').isoformat() + 'Z'


def create_incident_labels(parsed_msg, headers):
    labels = [
        {'type': 'Email/ID', 'value': parsed_msg['ID']},
        {'type': 'Email/subject', 'value': parsed_msg['Subject']},
        {'type': 'Email/text', 'value': parsed_msg['Body']},
        {'type': 'Email/from', 'value': parsed_msg['From']},
        {'type': 'Email/html', 'value': parsed_msg['Html']},
    ]
    labels.extend([{'type': 'Email/to', 'value': to}
                   for to in headers.get('To', '').split(',')])
    labels.extend([{'type': 'Email/cc', 'value': cc}
                   for cc in headers.get('Cc', '').split(',')])
    labels.extend([{'type': 'Email/bcc', 'value': bcc}
                   for bcc in headers.get('Bcc', '').split(',')])
    for key, val in headers.items():
        labels.append({'type': 'Email/Header/' + key, 'value': val})

    return labels


def emails_to_entry(title, raw_emails, format_data, mailbox):
    emails = []
    for email_data in raw_emails:
        context, _ = get_email_context(email_data, mailbox)
        emails.append(context)

    headers = {
        'minimal': ['Mailbox', 'ID', 'Labels', 'Attachment Names', ],
        'raw': ['MailBox', 'ID', 'Labels', 'Attachment Names', 'RawData'],
        'metadata': ['MailBox', 'ID', 'Subject', 'From', 'To', 'Labels', 'Attachment Names', 'Format'],
        'full': ['Mailbox', 'ID', 'Subject', 'From', 'To', 'Labels', 'Attachment Names', 'Format', 'Body'],
    }

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': emails,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, emails, headers[format_data]),
        'EntryContext': {'Gmail(val.ID && val.ID == obj.ID)': emails}
    }


def mail_to_incident(msg, service, user_key):
    parsed_msg, headers = get_email_context(msg, user_key)

    file_names = []
    command_args = {
        'messageId': parsed_msg['ID'],
        'userId': user_key,
    }

    for attachment in parsed_msg['Attachments']:
        command_args['id'] = attachment['ID']
        result = service.users().messages().attachments().get(**command_args).execute()
        file_data = base64.urlsafe_b64decode(result['data'].encode('ascii'))

        # save the attachment
        file_result = fileResult(attachment['Name'], file_data)

        # check for error
        if file_result['Type'] == entryTypes['error']:
            demisto.error(file_result['Contents'])
            raise Exception(file_result['Contents'])

        file_names.append({
            'path': file_result['FileID'],
            'name': attachment['Name'],
        })

    return {
        'type': 'Gmail',
        'name': parsed_msg['Subject'],
        'details': parsed_msg['Body'],
        'labels': create_incident_labels(parsed_msg, headers),
        'occurred': parse_time(parsed_msg['Date']),
        'attachment': file_names,
        'rawJSON': json.dumps(parsed_msg),
    }


def users_to_entry(title, response):
    context = []
    for user_data in response:
        context.append({
            'Type': 'Google',
            'ID': user_data.get('id'),
            'UserName': (user_data.get('name').get('givenName')
                         if user_data.get('name') and 'givenName' in user_data.get('name') else None),
            'DisplayName': (user_data.get('name').get('fullName')
                            if user_data.get('name') and 'fullName' in user_data.get('name') else None),
            'Email': {'Address': user_data.get('primaryEmail')},
            'Gmail': {'Address': user_data.get('primaryEmail')},
            'Group': user_data.get('kind'),
            'CustomerId': user_data.get('customerId'),
        })
    headers = ['Type', 'ID', 'UserName',
               'DisplayName', 'Email', 'Group', 'CustomerId']

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, context, headers),
        'EntryContext': {'Account(val.ID && val.Type && val.ID == obj.ID && val.Type == obj.Type)': context}
    }


def roles_to_entry(title, response):
    context = []
    for role_data in response:
        context.append({
            'ID': role_data['roleId'],
            'AssignedTo': role_data['assignedTo'],
            'RoleAssignmentId': role_data['roleAssignmentId'],
            'ScopeType': role_data['scopeType'],
            'Kind': role_data['kind'],
            'OrgUnitId': role_data.get('orgUnitId', ''),
        })
    headers = ['ID', 'AssignedTo', 'RoleAssignmentId',
               'ScopeType', 'Kind', 'OrgUnitId']

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, context, headers),
        'EntryContext': {'Gmail.Role(val.ID && val.ID == obj.ID)': context}
    }


def tokens_to_entry(title, response):
    context = []
    for token_data in response:
        context.append({
            'DisplayText': token_data.get('displayText'),
            'ClientId': token_data.get('clientId'),
            'Kind': token_data.get('kind'),
            'Scopes': token_data.get('scopes', []),
            'UserKey': token_data.get('userKey'),
        })

    headers = ['DisplayText', 'ClientId', 'Kind', 'Scopes', 'UserKey']

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, context, headers),
        'EntryContext': {'Tokens(val.ClientId && val.ClientId == obj.ClientId)': context}
    }


def filters_to_entry(title, mailbox, response):
    context = []
    for filter_data in response:
        context.append({
            'ID': filter_data.get('id'),
            'Mailbox': mailbox,
            'Criteria': filter_data.get('criteria'),
            'Action': filter_data.get('action'),
        })

    headers = ['ID', 'Criteria', 'Action', ]

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, context, headers),
        'EntryContext': {'GmailFilter(val.ID && val.ID == obj.ID)': context}
    }


''' FUNCTIONS '''


def list_users_command():
    args = demisto.args()
    domain = args.get('domain', ADMIN_EMAIL.split('@')[1])  # type: ignore
    customer = args.get('customer')
    event = args.get('event')
    view_type = args.get('view-type-public-domain', 'admin_view')
    query = args.get('query')
    sort_order = args.get('sort-order')
    max_results = args.get('max-results', 100)
    show_deleted = bool(strtobool(args.get('show-deleted', 'false')))
    projection = args.get('projection', 'basic')
    custom_field_mask = args.get(
        'custom_field_mask') if projection == 'custom' else None

    users = list_users(domain, customer, event, query, sort_order, view_type,
                       show_deleted, max_results, projection, custom_field_mask)
    return users_to_entry('Users:', users)


def list_users(domain, customer=None, event=None, query=None, sort_order=None, view_type='admin_view',
               show_deleted=False, max_results=100, projection='basic', custom_field_mask=None):
    command_args = {
        'domain': domain,
        'customer': customer,
        'event': event,
        'viewType': view_type,
        'query': query,
        'sortOrder': sort_order,
        'projection': projection,
        'showDeleted': show_deleted,
        'maxResults': max_results,
    }
    if projection == 'custom':
        command_args['customFieldMask'] = custom_field_mask

    service = get_service('admin', 'directory_v1')
    result = service.users().list(**command_args).execute()

    return result['users']


def get_user_command():
    args = demisto.args()
    user_key = args.get('user-id')
    view_type = args.get('view-type-public-domain')
    projection = args.get('projection')
    customer_field_mask = args.get('customer-field-mask')

    result = get_user(user_key, view_type, projection, customer_field_mask)
    return users_to_entry('User %s:' % (user_key, ), [result])


def get_user(user_key, view_type, projection, customer_field_mask=None):
    command_args = {
        'userKey': user_key if user_key != 'me' else ADMIN_EMAIL,
        'projection': projection,
        'viewType': view_type,
    }
    if projection == 'custom':
        command_args['customFieldMask'] = customer_field_mask

    service = get_service('admin', 'directory_v1')
    result = service.users().get(**command_args).execute()

    return result


def create_user_command():
    args = demisto.args()
    primary_email = args['email']
    first_name = args['first-name']
    family_name = args['family-name']
    password = args.get('password', '')

    if len(password) > 100 or len(password) < 8:
        raise ValueError('password must be over between 8 and 100 characters')

    result = create_user(primary_email, first_name, family_name, password)
    return users_to_entry('New User:', [result])


def create_user(primary_email, first_name, family_name, password):
    command_args = {
        'primaryEmail': primary_email,
        'name': {
            'givenName': first_name,
            'familyName': family_name,
            'fullName': '%s %s' % (first_name, family_name, ),
        },
        'password': password
    }

    service = get_service(
        'admin',
        'directory_v1',
        ['https://www.googleapis.com/auth/admin.directory.user'])
    result = service.users().insert(body=command_args).execute()

    return result


def delete_user_command():
    args = demisto.args()
    user_key = args.get('user-id')

    return delete_user(user_key)


def delete_user(user_key):
    command_args = {
        'userKey': user_key,
    }

    service = get_service(
        'admin',
        'directory_v1',
        ['https://www.googleapis.com/auth/admin.directory.user'])
    service.users().delete(**command_args).execute()

    return 'User %s have been deleted.' % (command_args['userKey'], )


def get_user_role_command():
    args = demisto.args()
    user_key = args['user-id']
    user_key = ADMIN_EMAIL if user_key == 'me' else user_key

    if GAPPS_ID is None:
        raise ValueError('Must provide Immutable GoogleApps Id')

    roles = get_user_role(user_key, GAPPS_ID)
    return roles_to_entry('User Roles of %s:' % (user_key, ), roles)


def get_user_role(user_key, customer):
    command_args = {
        'customer': customer,
        'maxResults': 100,
    }

    service = get_service(
        'admin',
        'directory_v1',
        ['https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly',
         'https://www.googleapis.com/auth/admin.directory.rolemanagement'])
    result = service.roleAssignments().list(**command_args).execute()

    user_data = service.users().get(userKey=user_key).execute()

    return [role for role in result['items'] if role['assignedTo'] == user_data['id']]


def revoke_user_roles_command():
    args = demisto.args()

    user_key = args.get('user-id')
    role_assignment_id = args['role-assignment-id']

    revoke_user_roles(user_key, role_assignment_id)
    return 'Role has been deleted.'


def revoke_user_roles(user_id, role_assignment_id):
    command_args = {
        'customer': GAPPS_ID,
        'roleAssignmentId': role_assignment_id,
    }

    if GAPPS_ID is None:
        raise ValueError('Must provide Immutable GoogleApps Id')

    service = get_service(
        'admin',
        'directory_v1',
        ['https://www.googleapis.com/auth/admin.directory.rolemanagement'])
    return service.roleAssignments().delete(**command_args).execute()


def get_user_tokens_command():
    args = demisto.args()
    user_id = args.get('user-id')
    user_id = ADMIN_EMAIL if user_id == 'me' else user_id

    tokens = get_user_tokens(user_id)

    return tokens_to_entry('Tokens:', tokens)


def get_user_tokens(user_id):
    command_args = {
        'userKey': user_id,
    }

    service = get_service(
        'admin',
        'directory_v1',
        ['https://www.googleapis.com/auth/admin.directory.user.security'])
    result = service.tokens().list(**command_args).execute()

    return result.get('items', [])


def search_all_mailboxes():
    command_args = {
        'maxResults': 100,
        'domain': ADMIN_EMAIL.split('@')[1],  # type: ignore
    }

    service = get_service('admin', 'directory_v1')
    result = service.users().list(**command_args).execute()

    entries = [search_command(user['primaryEmail'])
               for user in result['users']]
    return entries


def search_command(mailbox=None):
    args = demisto.args()

    user_id = args.get('user-id') if mailbox is None else mailbox
    mailbox = ADMIN_EMAIL if user_id == 'me' else user_id
    subject = args.get('subject', '')
    _from = args.get('from', '')
    to = args.get('to', '')
    before = args.get('before', '')
    after = args.get('after', '')
    filename = args.get('filename', '')
    _in = args.get('in', '')

    query = args.get('query', '')
    fields = args.get('fields')  # TODO
    label_ids = [lbl for lbl in args.get('labels-ids', '').split(',') if lbl != '']
    max_results = int(args.get('max-results', 100))
    page_token = args.get('page-token')
    include_spam_trash = args.get('include-spam-trash', False)
    has_attachments = args.get('has-attachments')
    has_attachments = None if has_attachments is None else bool(
        strtobool(has_attachments))

    if max_results > 500:
        raise ValueError(
            'maxResults must be lower than 500, got %s' % (max_results, ))

    mails, q = search(user_id, subject, _from, to, before, after, filename, _in, query,
                      fields, label_ids, max_results, page_token, include_spam_trash, has_attachments)

    return emails_to_entry('Search in %s:\nquery: "%s"' % (mailbox, q, ), mails, 'full', mailbox)


def search(user_id, subject='', _from='', to='', before='', after='', filename='', _in='', query='',
           fields=None, label_ids=None, max_results=100, page_token=None, include_spam_trash=False,
           has_attachments=None):
    query_values = {
        'subject': subject,
        'from': _from,
        'to': to,
        'before': before,
        'after': after,
        'filename': filename,
        'in': _in,
        'has': 'attachment' if has_attachments else ''
    }
    q = ' '.join('%s:%s ' % (name, value, )
                 for name, value in query_values.iteritems() if value != '')
    q = ('%s %s' % (q, query, )).strip()

    command_args = {
        'userId': user_id,
        'q': q,
        'maxResults': max_results,
        'fields': fields,
        'labelIds': label_ids,
        'pageToken': page_token,
        'includeSpamTrash': include_spam_trash,
    }
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly'],
        command_args['userId'])
    result = service.users().messages().list(**command_args).execute()

    return [get_mail(user_id, mail['id'], 'full') for mail in result.get('messages', [])], q


def get_mail_command():
    args = demisto.args()
    user_id = args.get('user-id', ADMIN_EMAIL)
    _id = args.get('message-id')
    _format = args.get('format')

    mail = get_mail(user_id, _id, _format)
    return emails_to_entry('Email:', [mail], _format, user_id)


def get_mail(user_id, _id, _format):
    command_args = {
        'userId': user_id,
        'id': _id,
        'format': _format,
    }

    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly'],
        delegated_user=command_args['userId'])
    result = service.users().messages().get(**command_args).execute()

    return result


def get_attachments_command():
    args = demisto.args()
    user_id = args.get('user-id')
    _id = args.get('message-id')

    attachments = get_attachments(user_id, _id)

    return [fileResult(name, data) for name, data in attachments]


def get_attachments(user_id, _id):
    mail_args = {
        'userId': user_id,
        'id': _id,
        'format': 'full',
    }
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly'],
        delegated_user=mail_args['userId'])
    result = service.users().messages().get(**mail_args).execute()
    result = get_email_context(result, user_id)[0]

    command_args = {
        'userId': user_id,
        'messageId': _id,
    }
    files = []
    for attachment in result['Attachments']:
        command_args['id'] = attachment['ID']
        result = service.users().messages().attachments().get(**command_args).execute()
        file_data = base64.urlsafe_b64decode(result['data'].encode('ascii'))
        files.append((attachment['Name'], file_data))

    return files


def move_mail_command():
    args = demisto.args()
    user_id = args.get('user-id')
    _id = args.get('message-id')
    add_labels = [lbl for lbl in args.get('add-labels', '').split(',') if lbl != '']
    remove_labels = [lbl for lbl in args.get(
        'remove-labels', '').split(',') if lbl != '']

    mail = move_mail(user_id, _id, add_labels, remove_labels)
    return emails_to_entry('Email:', [mail], 'full', user_id)


def move_mail(user_id, _id, add_labels, remove_labels):
    command_args = {
        'userId': user_id,
        'id': _id,
        'body': {
            'addLabelIds': add_labels,
            'removeLabelIds': remove_labels,
        }

    }
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.modify'],
        delegated_user=user_id)
    result = service.users().messages().modify(**command_args).execute()

    return result


def move_mail_to_mailbox_command():
    args = demisto.args()
    src_user_id = args.get('src-user-id')
    message_id = args.get('message-id')
    dst_user_id = args.get('dst-user-id')

    new_mail_id = move_mail_to_mailbox(src_user_id, message_id, dst_user_id)

    mail = get_mail(dst_user_id, new_mail_id, 'full')
    return emails_to_entry('Email:', [mail], 'full', dst_user_id)


def move_mail_to_mailbox(src_mailbox, message_id, dst_mailbox):
    # get the original mail
    mail = get_mail(src_mailbox, message_id, 'raw')

    # import the mail to the destination mailbox
    command_args = {
        'userId': dst_mailbox,
        'body': {
            'raw': mail['raw'],
        }
    }
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.modify'],
        delegated_user=dst_mailbox)
    result = service.users().messages().import_(**command_args).execute()

    # delete the original mail
    delete_mail(src_mailbox, message_id, True)

    return result['id']


def delete_mail_command():
    args = demisto.args()

    user_id = args['user-id']
    _id = args['message-id']
    permanent = bool(strtobool(args.get('permanent', 'false')))

    return delete_mail(user_id, _id, permanent)


def delete_mail(user_id, _id, permanent):
    command_args = {
        'userId': user_id,
        'id': _id,
    }

    service = get_service(
        'gmail',
        'v1',
        ['https://mail.google.com',
         'https://www.googleapis.com/auth/gmail.modify'],
        delegated_user=command_args['userId'])
    if permanent:
        service.users().messages().delete(**command_args).execute()
        return 'Email has been successfully deleted.'
    else:
        service.users().messages().trash(**command_args).execute()
        return 'Email has been successfully moved to trash.'


def get_thread_command():
    args = demisto.args()

    user_id = args.get('user-id', ADMIN_EMAIL)
    _id = args.get('thread-id')
    _format = args.get('format')

    messages = get_thread(user_id, _id, _format)

    return emails_to_entry('Emails of Thread:', messages, _format, user_id)


def get_thread(user_id, _id, _format):
    command_args = {
        'userId': user_id,
        'id': _id,
        'format': _format
    }

    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly'],
        delegated_user=user_id)
    result = service.users().threads().get(**command_args).execute()

    return result['messages']


def add_delete_filter_command():
    args = demisto.args()

    user_id = args.get('user-id', ADMIN_EMAIL)
    user_id = user_id if user_id.lower() != 'me' else ADMIN_EMAIL
    _from = args.get('email-address')

    _filter = add_filter(user_id, _from=_from, add_labels=['TRASH', ])

    return filters_to_entry('New filter:', user_id, [_filter])


def add_filter_command():
    args = demisto.args()

    user_id = args.get('user-id', ADMIN_EMAIL)
    user_id = user_id if user_id.lower() != 'me' else ADMIN_EMAIL
    _from = args.get('from')
    to = args.get('to')
    subject = args.get('subject')
    query = args.get('query')
    has_attachments = args.get('has-attachments')
    size = args.get('size')
    size_comparison = args.get('size-comparison')
    forward = args.get('forward')
    add_labels = args.get('add-labels', '').split(',')
    add_labels = add_labels if any(add_labels) else None
    remove_labels = args.get('remove-labels', '').split(',')
    remove_labels = remove_labels if any(remove_labels) else None

    _filter = add_filter(user_id,
                         _from=_from,
                         to=to,
                         subject=subject,
                         query=query,
                         has_attachments=has_attachments,
                         size=size,
                         size_comparison=size_comparison,
                         forward=forward,
                         add_labels=add_labels,
                         remove_labels=remove_labels,
                         )

    return filters_to_entry('New filter:', user_id, [_filter])


def add_filter(user_id, _from=None, to=None, subject=None, query=None, has_attachments=None, size=None,
               size_comparison=None, forward=None, add_labels=None, remove_labels=None):
    command_args = {
        'userId': user_id,
        'body': {
            'criteria': {},
            'action': {},
        }
    }

    if _from is not None:
        command_args['body']['criteria']['from'] = _from
    if to is not None:
        command_args['body']['criteria']['to'] = to
    if subject is not None:
        command_args['body']['criteria']['subject'] = subject
    if query is not None:
        command_args['body']['criteria']['query'] = query
    if has_attachments is not None:
        command_args['body']['criteria']['hasAttachment'] = has_attachments
    if size is not None:
        command_args['body']['criteria']['size'] = size
    if size_comparison is not None:
        command_args['body']['criteria']['size_comparison'] = size_comparison
    if add_labels is not None:
        command_args['body']['action']['addLabelIds'] = add_labels
    if remove_labels is not None:
        command_args['body']['action']['removeLabelIds'] = remove_labels
    if forward is not None:
        command_args['body']['action']['forward'] = forward

    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.settings.basic'],
        delegated_user=user_id)
    result = service.users().settings().filters().create(**command_args).execute()

    return result


def list_filters_command():
    args = demisto.args()

    user_id = args.get('user-id', ADMIN_EMAIL)
    user_id = user_id if user_id.lower() != 'me' else ADMIN_EMAIL
    address = args.get('address')
    limit = int(args.get('limit', 100))

    filters = list_filters(
        user_id,
        address=address,
        limit=limit)

    return filters_to_entry('filters:', user_id, filters)


def list_filters(user_id, address=None, limit=100):
    command_args = {
        'userId': user_id,
    }
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.settings.basic'],
        delegated_user=user_id)
    result = service.users().settings().filters().list(**command_args).execute()
    filters = result.get('filter', [])
    if address is not None:
        filters = [f for f in filters if address in {f['criteria'].get('from'), f['criteria'].get('to')}]

    return filters[:limit]


def remove_filter_command():
    args = demisto.args()

    user_id = args.get('user-id', ADMIN_EMAIL)
    ids = args.get('filter_ids', '')
    if isinstance(ids, STRING_TYPES):  # alternativly it could be an array
        ids = ids.split(',')

    for _id in ids:
        remove_filter(user_id, _id)

    return 'filters were removed successfully.'


def remove_filter(user_id, _id):
    command_args = {
        'userId': user_id,
        'id': _id
    }

    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.settings.basic'],
        delegated_user=user_id)
    result = service.users().settings().filters().delete(**command_args).execute()

    return result


def fetch_incidents():
    params = demisto.params()
    user_key = params.get('queryUserKey')
    user_key = user_key if user_key else ADMIN_EMAIL
    query = '' if params['query'] is None else params['query']
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch = datetime.now() - timedelta(days=1)
    else:
        last_fetch = datetime.strptime(
            last_fetch, '%Y-%m-%dT%H:%M:%SZ')
    current_fetch = last_fetch

    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly'],
        user_key)

    query += last_fetch.strftime(' after:%Y/%m/%d')
    LOG('GMAIL: fetch parameters:\nuser: %s\nquery=%s\nfetch time: %s' %
        (user_key, query, last_fetch, ))

    result = service.users().messages().list(
        userId=user_key, maxResults=100, q=query).execute()

    incidents = []
    # so far, so good
    LOG('GMAIL: possible new incidents are %s' % (result, ))
    for msg in result.get('messages', []):
        msg_result = service.users().messages().get(
            id=msg['id'], userId=user_key).execute()
        incident = mail_to_incident(msg_result, service, user_key)
        temp_date = datetime.strptime(
            incident['occurred'], '%Y-%m-%dT%H:%M:%SZ')
        LOG("look here!!!§§§§§§ ___ORIGINAL___ internal date: " + str(temp_date) + " ### last fetch: " + str(last_fetch))
        LOG.print_log()
        # update last run
        if temp_date > last_fetch:
            last_fetch = temp_date + timedelta(seconds=1)

        # avoid duplication due to weak time query
        if temp_date > current_fetch:
            incidents.append(incident)
    demisto.info('extract {} incidents'.format(len(incidents)))
    demisto.setLastRun({'time': last_fetch.isoformat().split('.')[0] + 'Z'})
    return incidents


def main():
    global ADMIN_EMAIL, PRIVATE_KEY_CONTENT, GAPPS_ID
    ADMIN_EMAIL = demisto.params()['adminEmail'].get('identifier', '')
    PRIVATE_KEY_CONTENT = demisto.params()['adminEmail'].get('password', '{}')
    GAPPS_ID = demisto.params().get('gappsID')
    ''' EXECUTION CODE '''
    COMMANDS = {
        'gmail-list-users': list_users_command,
        'gmail-get-user': get_user_command,
        'gmail-create-user': create_user_command,
        'gmail-delete-user': delete_user_command,
        'gmail-get-user-roles': get_user_role_command,
        'gmail-revoke-user-role': revoke_user_roles_command,
        'gmail-get-tokens-for-user': get_user_tokens_command,
        'gmail-search-all-mailboxes': search_all_mailboxes,
        'gmail-search': search_command,
        'gmail-get-mail': get_mail_command,
        'gmail-get-attachments': get_attachments_command,
        'gmail-move-mail': move_mail_command,
        'gmail-move-mail-to-mailbox': move_mail_to_mailbox_command,
        'gmail-delete-mail': delete_mail_command,
        'gmail-get-thread': get_thread_command,
        'gmail-add-filter': add_filter_command,
        'gmail-add-delete-filter': add_delete_filter_command,
        'gmail-list-filters': list_filters_command,
        'gmail-remove-filter': remove_filter_command,
    }
    command = demisto.command()
    LOG('GMAIL: command is %s' % (command, ))
    try:
        if command == 'test-module':
            list_users(ADMIN_EMAIL.split('@')[1])
            demisto.results('ok')
            sys.exit(0)

        if command == 'fetch-incidents':
            demisto.incidents(fetch_incidents())
            sys.exit(0)

        cmd_func = COMMANDS.get(command)
        if cmd_func is None:
            raise NotImplementedError(
                'Command "{}" is not implemented.'.format(command))
        else:
            demisto.results(cmd_func())  # type: ignore
    except Exception as e:
        import traceback
        if command == 'fetch-incidents':
            LOG(traceback.format_exc())
            LOG.print_log()
            raise
        else:
            return_error('GMAIL: {}'.format(str(e)), traceback.format_exc())


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

