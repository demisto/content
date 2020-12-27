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
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
import mimetypes
import random
import string
from apiclient import discovery
from oauth2client import service_account
import itertools as it

''' GLOBAL VARS '''
ADMIN_EMAIL = None
PRIVATE_KEY_CONTENT = None
GAPPS_ID = None
SCOPES = ['https://www.googleapis.com/auth/admin.directory.user.readonly']
PROXY = demisto.params().get('proxy')
DISABLE_SSL = demisto.params().get('insecure', False)
FETCH_TIME = demisto.params().get('fetch_time', '1 days')

SEND_AS_SMTP_FIELDS = ['host', 'port', 'username', 'password', 'securitymode']
DATE_FORMAT = '%Y-%m-%d'  # sample - 2020-08-23

''' HELPER FUNCTIONS '''


class TextExtractHtmlParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self._texts = []  # type: list
        self._ignore = False

    def handle_starttag(self, tag, attrs):  # noqa: F841
        if tag in ('p', 'br') and not self._ignore:  # ignore
            self._texts.append('\n')
        elif tag in ('script', 'style'):
            self._ignore = True

    def handle_startendtag(self, tag, attrs):  # noqa: F841
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


# disable-secrets-detection-start
def get_http_client_with_proxy():
    proxy_info = None
    proxies = handle_proxy()
    if PROXY:
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


# disable-secrets-detection-end


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

    cred = service_account.ServiceAccountCredentials. \
        from_json_keyfile_dict(json.loads(PRIVATE_KEY_CONTENT), scopes=scopes)  # type: ignore

    return cred.create_delegated(delegated_user)


def get_service(serviceName, version, additional_scopes=None, delegated_user=None):
    credentials = get_credentials(additional_scopes=additional_scopes, delegated_user=delegated_user)
    http_client = credentials.authorize(get_http_client_with_proxy())
    return discovery.build(serviceName, version, http=http_client)
    # return discovery.build(serviceName, version, credentials=credentials)


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
            if part['body'].get('attachmentId') is not None:
                attachments.append({
                    'ID': part['body']['attachmentId'],
                    'Name': part['filename']
                })

    return body, html, attachments


def parse_privileges(raw_privileges):
    privileges = []
    for p in raw_privileges:
        privilege = assign_params(**{'ServiceID': p.get('serviceId'), 'Name': p.get('privilegeName')})
        if privilege:
            privileges.append(privilege)
    return privileges


def localization_extract(time_from_mail):
    if time_from_mail is None or len(time_from_mail) < 5:
        return '-0000', 0

    utc = time_from_mail[-5:]
    if utc[0] != '-' and utc[0] != '+':
        return '-0000', 0

    for ch in utc[1:]:
        if not ch.isdigit():
            return '-0000', 0

    delta_in_seconds = int(utc[0] + utc[1:3]) * 3600 + int(utc[0] + utc[3:]) * 60
    return utc, delta_in_seconds


def create_base_time(internal_date_timestamp, header_date):
    """
    Args:
        internal_date_timestamp: The timestamp from the Gmail API response.
        header_date: The date string from the email payload.

    Returns: A date string in the senders local time in the format of "Mon, 26 Aug 2019 14:40:04 +0300"

    """
    # intenalDate timestamp has 13 digits, but epoch-timestamp counts the seconds since Jan 1st 1970
    # (which is currently less than 13 digits) thus a need to cut the timestamp down to size.
    timestamp_len = len(str(int(time.time())))
    if len(str(internal_date_timestamp)) > timestamp_len:
        internal_date_timestamp = int(str(internal_date_timestamp)[:timestamp_len])

    utc, delta_in_seconds = localization_extract(header_date)
    base_time = datetime.utcfromtimestamp(internal_date_timestamp) + timedelta(seconds=delta_in_seconds)
    base_time = str(base_time.strftime('%a, %d %b %Y %H:%M:%S')) + " " + utc
    return base_time


def get_email_context(email_data, mailbox):
    context_headers = email_data.get('payload', {}).get('headers', [])
    context_headers = [{'Name': v['name'], 'Value': v['value']}
                       for v in context_headers]
    headers = dict([(h['Name'].lower(), h['Value']) for h in context_headers])
    body = demisto.get(email_data, 'payload.body.data')
    body = body.encode('ascii') if body is not None else ''
    parsed_body = base64.urlsafe_b64decode(body)
    if email_data.get('internalDate') is not None:
        base_time = create_base_time(email_data.get('internalDate'), str(headers.get('date', '')))

    else:
        # in case no internalDate field exists will revert to extracting the date from the email payload itself
        # Note: this should not happen in any command other than other than gmail-move-mail which doesn't return the
        # email payload nor internalDate
        demisto.info(
            "No InternalDate timestamp found - getting Date from mail payload - msg ID:" + str(email_data['id']))
        base_time = str(headers.get('date', ''))

    context_gmail = {
        'Type': 'Gmail',
        'Mailbox': ADMIN_EMAIL if mailbox == 'me' else mailbox,
        'ID': email_data.get('id'),
        'ThreadId': email_data.get('threadId'),
        'Labels': ', '.join(email_data.get('labelIds', [])),
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
        'Date': base_time,
        'Html': None,
    }

    context_email = {
        'ID': email_data.get('id'),
        'Headers': context_headers,
        'Attachments': {'entryID': email_data.get('payload', {}).get('filename', '')},
        # only for format 'raw'
        'RawData': email_data.get('raw'),
        # only for format 'full' and 'metadata'
        'Format': headers.get('content-type', '').split(';')[0],
        'Subject': headers.get('subject'),
        'From': headers.get('from'),
        'To': headers.get('to'),
        # only for format 'full'
        'Body/Text': unicode(parsed_body, 'utf-8'),

        'CC': headers.get('cc', []),
        'BCC': headers.get('bcc', []),
        'Date': base_time,
        'Body/HTML': None,
    }

    if 'text/html' in context_gmail['Format']:  # type: ignore
        context_gmail['Html'] = context_gmail['Body']
        context_gmail['Body'] = html_to_text(context_gmail['Body'])
        context_email['Body/HTML'] = context_gmail['Html']
        context_email['Body/Text'] = context_gmail['Body']

    if 'multipart' in context_gmail['Format']:  # type: ignore
        context_gmail['Body'], context_gmail['Html'], context_gmail['Attachments'] = parse_mail_parts(
            email_data.get('payload', {}).get('parts', []))
        context_gmail['Attachment Names'] = ', '.join(
            [attachment['Name'] for attachment in context_gmail['Attachments']])  # type: ignore
        context_email['Body/Text'], context_email['Body/HTML'], context_email['Attachments'] = parse_mail_parts(
            email_data.get('payload', {}).get('parts', []))
        context_email['Attachment Names'] = ', '.join(
            [attachment['Name'] for attachment in context_email['Attachments']])  # type: ignore

    return context_gmail, headers, context_email


TIME_REGEX = re.compile(r'^([\w,\d: ]*) (([+-]{1})(\d{2}):?(\d{2}))?[\s\w\(\)]*$')  # NOSONAR


def move_to_gmt(t):
    # there is only one time refernce is the string
    base_time, _, sign, hours, minutes = TIME_REGEX.findall(t)[0]
    if all([sign, hours, minutes]):
        seconds = -1 * (int(sign + hours) * 3600 + int(sign + minutes) * 60)
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
    gmail_emails = []
    emails = []
    for email_data in raw_emails:
        context_gmail, _, context_email = get_email_context(email_data, mailbox)
        gmail_emails.append(context_gmail)
        emails.append(context_email)

    headers = {
        'minimal': ['Mailbox', 'ID', 'Labels', 'Attachment Names', ],
        'raw': ['MailBox', 'ID', 'Labels', 'Attachment Names', 'RawData'],
        'metadata': ['MailBox', 'ID', 'Subject', 'From', 'To', 'Labels', 'Attachment Names', 'Format'],
        'full': ['Mailbox', 'ID', 'Subject', 'From', 'To', 'Labels', 'Attachment Names', 'Format', 'Body'],
    }

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': raw_emails,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, gmail_emails, headers[format_data], removeNull=True),
        'EntryContext': {
            'Gmail(val.ID && val.ID == obj.ID)': gmail_emails,
            'Email(val.ID && val.ID == obj.ID)': emails
        }
    }


def mail_to_incident(msg, service, user_key):
    parsed_msg, headers, _ = get_email_context(msg, user_key)

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
    # date in the incident itself is set to GMT time, the correction to local time is done in Demisto
    gmt_time = move_to_gmt(parsed_msg['Date'])

    incident = {
        'type': 'Gmail',
        'name': parsed_msg['Subject'],
        'details': parsed_msg['Body'],
        'labels': create_incident_labels(parsed_msg, headers),
        'occurred': gmt_time,
        'attachment': file_names,
        'rawJSON': json.dumps(parsed_msg),
    }
    return incident


def organization_format(org_list):
    if org_list:
        return ','.join(str(org.get('name')) for org in org_list if org.get('name'))
    else:
        return None


def users_to_entry(title, response, next_page_token=None):
    context = []

    for user_data in response:
        username = dict_safe_get(user_data, ['name', 'givenName'])
        display = dict_safe_get(user_data, ['name', 'fullName'])
        context.append({
            'Type': 'Google',
            'ID': user_data.get('id'),
            'UserName': username,
            'Username': username,  # adding to fit the new context standard
            'DisplayName': display,
            'Email': {'Address': user_data.get('primaryEmail')},
            'Gmail': {'Address': user_data.get('primaryEmail')},
            'Group': user_data.get('kind'),
            'Groups': user_data.get('kind'),  # adding to fit the new context standard
            'CustomerId': user_data.get('customerId'),
            'Domain': user_data.get('primaryEmail').split('@')[1],
            'VisibleInDirectory': user_data.get('includeInGlobalAddressList'),

        })
    headers = ['Type', 'ID', 'Username',
               'DisplayName', 'Groups', 'CustomerId', 'Domain', 'OrganizationUnit', 'Email', 'VisibleInDirectory']

    human_readable = tableToMarkdown(title, context, headers, removeNull=True)

    if next_page_token:
        human_readable += "\nTo get further results, rerun the command with this page-token:\n" + next_page_token

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {'Account(val.ID && val.Type && val.ID == obj.ID && val.Type == obj.Type)': context}
    }


def autoreply_to_entry(title, response, user_id):
    autoreply_context = []
    for autoreply_data in response:
        autoreply_context.append({
            'EnableAutoReply': autoreply_data.get('enableAutoReply'),
            'ResponseBody': autoreply_data.get('responseBodyPlainText'),
            'ResponseSubject': autoreply_data.get('responseSubject'),
            'RestrictToContact': autoreply_data.get('restrictToContacts'),
            'RestrictToDomain': autoreply_data.get('restrictToDomain'),
            'StartTime': autoreply_data.get('startTime'),
            'EndTime': autoreply_data.get('endTime'),
            'ResponseBodyHtml': autoreply_data.get('responseBodyHtml')
        })
    headers = ['EnableAutoReply', 'ResponseBody', 'ResponseBodyHtml',
               'ResponseSubject', 'RestrictToContact', 'RestrictToDomain',
               'EnableAutoReply', 'StartTime', 'EndTime']

    account_context = {
        "Address": user_id,
        "AutoReply": autoreply_context
    }

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': autoreply_context,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, autoreply_context, headers, removeNull=True),
        'EntryContext': {
            'Account.Gmail(val.Address == obj.Address)': account_context
        }
    }


def sent_mail_to_entry(title, response, to, emailfrom, cc, bcc, body, subject):
    gmail_context = []
    for mail_results_data in response:
        gmail_context.append({
            'Type': "Gmail",
            'ID': mail_results_data.get('id'),
            'Labels': mail_results_data.get('labelIds', []),
            'ThreadId': mail_results_data.get('threadId'),
            'To': ','.join(to),
            'From': emailfrom,
            'Cc': ','.join(cc) if len(cc) > 0 else None,
            'Bcc': ','.join(bcc) if len(bcc) > 0 else None,
            'Subject': subject,
            'Body': body,
            'Mailbox': ','.join(to)
        })

    headers = ['Type', 'ID', 'To', 'From', 'Cc', 'Bcc', 'Subject', 'Body', 'Labels',
               'ThreadId']

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, gmail_context, headers, removeNull=True),
        'EntryContext': {
            'Gmail.SentMail(val.ID && val.Type && val.ID == obj.ID && val.Type == obj.Type)': gmail_context}
    }


def user_roles_to_entry(title, response):
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
    headers = ['ID', 'RoleAssignmentId',
               'ScopeType', 'Kind', 'OrgUnitId']

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, context, headers, removeNull=True),
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
        'HumanReadable': tableToMarkdown(title, context, headers, removeNull=True),
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
        'HumanReadable': tableToMarkdown(title, context, headers, removeNull=True),
        'EntryContext': {'GmailFilter(val.ID && val.ID == obj.ID)': context,
                         'Gmail.Filter(val.ID && val.ID == obj.ID)': context}
    }


def role_to_entry(title, role):
    context = {
        'ETag': role.get('etag').strip('"'),
        'IsSuperAdminRole': bool(role.get('isSuperAdminRole')) if role.get('isSuperAdminRole') else False,
        'IsSystemRole': bool(role.get('isSystemRole')) if role.get('isSystemRole') else False,
        'Kind': role.get('kind'),
        'Description': role.get('roleDescription'),
        'ID': role.get('roleId'),
        'Name': role.get('roleName'),
        'Privilege': parse_privileges(role.get('rolePrivileges', []))
    }

    headers = ['ETag', 'IsSuperAdminRole', 'IsSystemRole', 'Kind', 'Description',
               'ID', 'Name']
    details_hr = tableToMarkdown(title, context, headers, removeNull=True)

    privileges = context.get('Privilege', [])
    privileges_headers = ['ServiceID', 'Name']
    privileges_title = 'Role {} privileges:'.format(context.get('ID'))
    privileges_hr = tableToMarkdown(privileges_title, privileges, privileges_headers, removeNull=True)

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': details_hr + privileges_hr,
        'EntryContext': {'Gmail.Role(val.ID && val.ID == obj.ID)': context}
    }


def dict_keys_snake_to_camelcase(dictionary):
    """
    Converts all dictionary keys from snake case (dict_key) to lower camel case(dictKey).
    :param dictionary: Dictionary which may contain keys in snake_case
    :return: Dictionary with snake_case keys converted to lowerCamelCase
    """
    underscore_pattern = re.compile(r'_([a-z])')
    return {underscore_pattern.sub(lambda i: i.group(1).upper(), key.lower()): value for (key, value) in
            dictionary.items()}


def get_millis_from_date(date, arg_name):
    """
    Convert a date string into epoch milliseconds or return epoch milliseconds as int.

    :param date: Date string in expected format.
    :param arg_name: field_name for setting proper error message.
    :return: Epoch milliseconds.
    """
    try:
        return date_to_timestamp(date, DATE_FORMAT)
    except ValueError:
        try:
            return int(date)
        except ValueError:
            raise ValueError('{} argument is not in expected format.'.format(arg_name))


''' FUNCTIONS '''


def list_users_command():
    args = demisto.args()
    domain = args.get('domain', ADMIN_EMAIL.split('@')[1])  # type: ignore
    customer = args.get('customer')
    view_type = args.get('view-type-public-domain', 'admin_view')
    query = args.get('query')
    sort_order = args.get('sort-order')
    max_results = args.get('max-results', 100)
    show_deleted = bool(strtobool(args.get('show-deleted', 'false')))
    projection = args.get('projection', 'basic')
    custom_field_mask = args.get(
        'custom_field_mask') if projection == 'custom' else None
    page_token = args.get('page-token')

    users, next_page_token = list_users(domain, customer, query, sort_order, view_type,
                                        show_deleted, max_results, projection, custom_field_mask, page_token)
    return users_to_entry('Users:', users, next_page_token)


def list_users(domain, customer=None, query=None, sort_order=None, view_type='admin_view',
               show_deleted=False, max_results=100, projection='basic', custom_field_mask=None, page_token=None):
    command_args = {
        'domain': domain,
        'customer': customer,
        'viewType': view_type,
        'query': query,
        'sortOrder': sort_order,
        'projection': projection,
        'showDeleted': show_deleted,
        'maxResults': max_results,
        'pageToken': page_token
    }
    if projection == 'custom':
        command_args['customFieldMask'] = custom_field_mask

    service = get_service('admin', 'directory_v1')
    result = service.users().list(**command_args).execute()

    return result['users'], result.get('nextPageToken')


def get_user_command():
    args = demisto.args()
    user_key = args.get('user-id')
    view_type = args.get('view-type-public-domain')
    projection = args.get('projection')
    customer_field_mask = args.get('customer-field-mask')

    result = get_user(user_key, view_type, projection, customer_field_mask)
    return users_to_entry('User {}:'.format(user_key), [result])


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


def hide_user_command():
    args = demisto.args()
    user_key = args.get('user-id')
    hide_value = args.get('visible-globally')
    result = hide_user(user_key, hide_value)

    return users_to_entry('User {}:'.format(user_key, ), [result])


def hide_user(user_key, hide_value):
    command_args = {
        'userKey': user_key if user_key != 'me' else ADMIN_EMAIL,
        'body': {
            'includeInGlobalAddressList': hide_value,
        }}

    service = get_service('admin', 'directory_v1',
                          additional_scopes=['https://www.googleapis.com/auth/admin.directory.user'])
    result = service.users().update(**command_args).execute()

    return result


def set_user_password_command():
    args = demisto.args()
    user_key = args.get('user-id')
    password = args.get('password')
    result = set_user_password(user_key, password)
    return result


def set_user_password(user_key, password):
    command_args = {
        'userKey': user_key if user_key != 'me' else ADMIN_EMAIL,
        'body': {
            'password': password,
        }}

    service = get_service('admin', 'directory_v1',
                          additional_scopes=['https://www.googleapis.com/auth/admin.directory.user'])
    service.users().update(**command_args).execute()

    return 'User {} password has been set.'.format(command_args['userKey'])


def get_autoreply_command():
    args = demisto.args()
    user_id = args.get('user-id', ADMIN_EMAIL)

    autoreply_message = get_autoreply(user_id)

    return autoreply_to_entry('User {}:'.format(user_id), [autoreply_message], user_id)


def get_autoreply(user_id):
    command_args = {
        'userId': user_id
    }

    service = get_service('gmail', 'v1',
                          additional_scopes=['https://mail.google.com', 'https://www.googleapis.com/auth/gmail.modify',
                                             'https://www.googleapis.com/auth/gmail.readonly',
                                             'https://www.googleapis.com/auth/gmail.settings.basic'],
                          delegated_user=user_id)
    result = service.users().settings().getVacation(**command_args).execute()

    return result


def set_autoreply_command():
    args = demisto.args()

    user_id = args.get('user-id')
    enable_autoreply = args.get('enable-autoReply')
    response_subject = args.get('response-subject')
    response_body_entry_id = args.get('response-body-entry-id')
    file_content = ''
    if response_body_entry_id and not args.get('response-body'):
        file_entry = demisto.getFilePath(response_body_entry_id)
        with open(file_entry['path'], 'r') as f:
            file_content = str(f.read())
    response_body_plain_text = file_content if file_content else args.get('response-body')
    response_body_type = args.get('response-body-type')
    domain_only = args.get('domain-only')
    contacts_only = args.get('contacts-only')
    start_time = get_millis_from_date(args.get('start-time'), 'start-time') if args.get('start-time') else None
    end_time = get_millis_from_date(args.get('end-time'), 'end-time') if args.get('end-time') else None

    autoreply_message = set_autoreply(user_id, enable_autoreply, response_subject, response_body_plain_text,
                                      domain_only, contacts_only, start_time, end_time, response_body_type)

    return autoreply_to_entry('User {}:'.format(user_id), [autoreply_message], user_id)


def set_autoreply(user_id, enable_autoreply, response_subject, response_body_plain_text, domain_only, contacts_only,
                  start_time, end_time, response_body_type='text'):
    command_args = remove_empty_elements({
        'userId': user_id if user_id != 'me' else ADMIN_EMAIL,
        'body': {
            'enableAutoReply': enable_autoreply,
            'responseSubject': response_subject,
            'responseBodyPlainText': response_body_plain_text,
            'restrictToContacts': contacts_only,
            'restrictToDomain': domain_only,
            'startTime': start_time,
            'endTime': end_time
        }})
    if response_body_type.lower() == 'html':
        command_args['body']['responseBodyHtml'] = response_body_plain_text

    service = get_service('gmail', 'v1', additional_scopes=['https://www.googleapis.com/auth/gmail.settings.basic'],
                          delegated_user=user_id)
    result = service.users().settings().updateVacation(**command_args).execute()
    return result


def remove_delegate_user_mailbox_command():
    args = demisto.args()
    user_id = args.get('user-id')
    delegate_email = args.get('removed-mail')
    return delegate_user_mailbox(user_id, delegate_email, False)


def delegate_user_mailbox_command():
    args = demisto.args()
    user_id = args.get('user-id')
    delegate_email = args.get('delegate-email')
    return delegate_user_mailbox(user_id, delegate_email, True)


def delegate_user_mailbox(user_id, delegate_email, delegate_token):
    service = get_service('gmail', 'v1', additional_scopes=['https://www.googleapis.com/auth/gmail.settings.sharing'],
                          delegated_user=user_id)
    if delegate_token:  # guardrails-disable-line
        command_args = {
            'userId': user_id if user_id != 'me' else ADMIN_EMAIL,
            'body': {
                'delegateEmail': delegate_email,
            }
        }

        service.users().settings().delegates().create(**command_args).execute()
        return 'Email {} has been delegated'.format(delegate_email)

    else:
        command_args = {
            'userId': user_id if user_id != 'me' else ADMIN_EMAIL,
            'delegateEmail': delegate_email
        }

        service.users().settings().delegates().delete(**command_args).execute()
        return 'Email {} has been removed from delegation'.format(delegate_email)


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
            'fullName': '%s %s' % (first_name, family_name,),
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

    return 'User {} have been deleted.'.format(command_args['userKey'])


def get_user_role_command():
    args = demisto.args()
    user_key = args['user-id']
    user_key = ADMIN_EMAIL if user_key == 'me' else user_key

    if GAPPS_ID is None:
        raise ValueError('Must provide Immutable GoogleApps Id')

    roles = get_user_role(user_key, GAPPS_ID)
    return user_roles_to_entry('User Roles of %s:' % (user_key,), roles)


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


def get_role(role_identity, customer):
    command_args = {
        'customer': customer,
        'roleId': role_identity
    }

    service = get_service(
        'admin',
        'directory_v1',
        ['https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly',
         'https://www.googleapis.com/auth/admin.directory.rolemanagement'])

    return service.roles().get(**command_args).execute()


def get_role_command():
    args = demisto.args()
    role_id = args['role-id']
    customer = args['customer-id'] if args.get('customer-id') else GAPPS_ID

    if not customer:
        raise ValueError('Must provide Immutable GoogleApps Id')

    role = get_role(role_id, customer)
    return role_to_entry('Role {} details:'.format(role_id), role)


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
    next_page_token = None
    service = get_service('admin', 'directory_v1')
    while True:
        command_args = {
            'maxResults': 100,
            'domain': ADMIN_EMAIL.split('@')[1],  # type: ignore
            'pageToken': next_page_token
        }

        result = service.users().list(**command_args).execute()
        next_page_token = result.get('nextPageToken')

        entries = [search_command(user['primaryEmail']) for user in result['users']]

        # if these are the final result push - return them
        if next_page_token is None:
            entries.append("Search completed")
            return entries

        # return midway results
        demisto.results(entries)


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
            'maxResults must be lower than 500, got %s' % (max_results,))

    mails, q = search(user_id, subject, _from, to, before, after, filename, _in, query,
                      fields, label_ids, max_results, page_token, include_spam_trash, has_attachments)

    res = emails_to_entry('Search in {}:\nquery: "{}"'.format(mailbox, q), mails, 'full', mailbox)
    return res


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
    q = ' '.join('%s:%s ' % (name, value,)
                 for name, value in query_values.iteritems() if value != '')
    q = ('%s %s' % (q, query,)).strip()

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


'''MAIL SENDER FUNCTIONS'''


def randomword(length):
    """
    Generate a random string of given length
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))  # NOSONAR


def header(s):
    if not s:
        return None

    s_no_newlines = ' '.join(s.splitlines())
    return Header(s_no_newlines, 'utf-8')


def template_params(paramsStr):
    """
    Translate the template params if they exist from the context
    """
    actualParams = {}
    if paramsStr:
        try:
            params = json.loads(paramsStr)

        except ValueError as e:
            return_error('Unable to parse templateParams: {}'.format(str(e)))
        # Build a simple key/value

        for p in params:
            if params[p].get('value'):
                actualParams[p] = params[p]['value']

            elif params[p].get('key'):
                actualParams[p] = demisto.dt(demisto.context(), params[p]['key'])

        return actualParams

    else:
        return None


def transient_attachments(transientFile, transientFileContent, transientFileCID):
    if transientFile is None or len(transientFile) == 0:
        return []

    if transientFileContent is None:
        transientFileContent = []

    if transientFileCID is None:
        transientFileCID = []

    attachments = []
    for file_name, file_data, file_cid in it.izip_longest(transientFile, transientFileContent, transientFileCID):
        if file_name is None:
            break

        content_type, encoding = mimetypes.guess_type(file_name)
        if content_type is None or encoding is not None:
            content_type = 'application/octet-stream'

        main_type, sub_type = content_type.split('/', 1)

        attachments.append({
            'name': file_name,
            'maintype': main_type,
            'subtype': sub_type,
            'data': file_data,
            'cid': file_cid
        })

    return attachments


def handle_html(htmlBody):
    """
    Extract all data-url content from within the html and return as separate attachments.
    Due to security implications, we support only images here
    We might not have Beautiful Soup so just do regex search
    """
    attachments = []
    cleanBody = ''
    lastIndex = 0
    for i, m in enumerate(
            re.finditer(r'<img.+?src=\"(data:(image\/.+?);base64,([a-zA-Z0-9+/=\r\n]+?))\"', htmlBody,  # NOSONAR
                        re.I)):
        maintype, subtype = m.group(2).split('/', 1)
        att = {
            'maintype': maintype,
            'subtype': subtype,
            'data': base64.b64decode(m.group(3)),
            'name': 'image%d.%s' % (i, subtype)
        }
        att['cid'] = '%s@%s.%s' % (att['name'], randomword(8), randomword(8))
        attachments.append(att)
        cleanBody += htmlBody[lastIndex:m.start(1)] + 'cid:' + att['cid']
        lastIndex = m.end() - 1

    cleanBody += htmlBody[lastIndex:]
    return cleanBody, attachments


def collect_inline_attachments(attach_cids):
    """
    collects all attachments which are inline - only used in html bodied emails
    """
    inline_attachment = []
    if attach_cids is not None and len(attach_cids) > 0:
        for cid in attach_cids:
            file = demisto.getFilePath(cid)
            file_path = file['path']

            content_type, encoding = mimetypes.guess_type(file_path)
            if content_type is None or encoding is not None:
                content_type = 'application/octet-stream'
            main_type, sub_type = content_type.split('/', 1)

            fp = open(file_path, 'rb')
            data = fp.read()
            fp.close()

            inline_attachment.append({
                'ID': cid,
                'name': file['name'],
                'maintype': main_type,
                'subtype': sub_type,
                'data': data,
                'cid': cid
            })

        return inline_attachment


def collect_manual_attachments():
    attachments = []
    for attachment in demisto.getArg('manualAttachObj') or []:
        res = demisto.getFilePath(os.path.basename(attachment['RealFileName']))

        path = res['path']
        content_type, encoding = mimetypes.guess_type(path)
        if content_type is None or encoding is not None:
            content_type = 'application/octet-stream'
        maintype, subtype = content_type.split('/', 1)

        if maintype == 'text':
            with open(path) as fp:
                data = fp.read()
        else:
            with open(path, 'rb') as fp:
                data = fp.read()
        attachments.append({
            'name': attachment['FileName'],
            'maintype': maintype,
            'subtype': subtype,
            'data': data,
            'cid': None
        })

    return attachments


def collect_attachments(entry_ids, file_names):
    """
    Creates a dictionary containing all the info about all attachments
    """
    attachments = []
    entry_number = 0
    if entry_ids is not None and len(entry_ids) > 0:
        for entry_id in entry_ids:
            file = demisto.getFilePath(entry_id)
            file_path = file['path']
            if file_names is not None and len(file_names) > entry_number and file_names[entry_number] is not None:
                file_name = file_names[entry_number]

            else:
                file_name = file['name']

            content_type, encoding = mimetypes.guess_type(file_path)
            if content_type is None or encoding is not None:
                content_type = 'application/octet-stream'

            main_type, sub_type = content_type.split('/', 1)

            fp = open(file_path, 'rb')
            data = fp.read()
            fp.close()
            attachments.append({
                'ID': entry_id,
                'name': file_name,
                'maintype': main_type,
                'subtype': sub_type,
                'data': data,
                'cid': None
            })
            entry_number += 1
    return attachments


def attachment_handler(message, attachments):
    """
    Adds the attachments to the email message
    """
    for att in attachments:
        if att['maintype'] == 'text':
            msg_txt = MIMEText(att['data'], att['subtype'], 'utf-8')
            if att['cid'] is not None:
                msg_txt.add_header('Content-Disposition', 'inline', filename=att['name'])
                msg_txt.add_header('Content-ID', '<' + att['name'] + '>')

            else:
                msg_txt.add_header('Content-Disposition', 'attachment', filename=att['name'])
            message.attach(msg_txt)

        elif att['maintype'] == 'image':
            msg_img = MIMEImage(att['data'], att['subtype'])
            if att['cid'] is not None:
                msg_img.add_header('Content-Disposition', 'inline', filename=att['name'])
                msg_img.add_header('Content-ID', '<' + att['name'] + '>')

            else:
                msg_img.add_header('Content-Disposition', 'attachment', filename=att['name'])
            message.attach(msg_img)

        elif att['maintype'] == 'audio':
            msg_aud = MIMEAudio(att['data'], att['subtype'])
            if att['cid'] is not None:
                msg_aud.add_header('Content-Disposition', 'inline', filename=att['name'])
                msg_aud.add_header('Content-ID', '<' + att['name'] + '>')

            else:
                msg_aud.add_header('Content-Disposition', 'attachment', filename=att['name'])
            message.attach(msg_aud)

        else:
            msg_base = MIMEBase(att['maintype'], att['subtype'])
            msg_base.set_payload(att['data'])
            if att['cid'] is not None:
                msg_base.add_header('Content-Disposition', 'inline', filename=att['name'])
                msg_base.add_header('Content-ID', '<' + att['name'] + '>')

            else:
                msg_base.add_header('Content-Disposition', 'attachment', filename=att['name'])
            message.attach(msg_base)


def send_mail(emailto, emailfrom, subject, body, entry_ids, cc, bcc, htmlBody, replyTo, file_names, attach_cid,
              transientFile, transientFileContent, transientFileCID, manualAttachObj, additional_headers,
              templateParams, inReplyTo=None, references=None):
    if templateParams:
        templateParams = template_params(templateParams)
        if body:
            body = body.format(**templateParams)
        if htmlBody:
            htmlBody = htmlBody.format(**templateParams)

    attach_body_to = None
    if htmlBody and not any([entry_ids, file_names, attach_cid, manualAttachObj, body]):
        # if there is only htmlbody and no attachments to the mail , we would like to send it without attaching the body
        message = MIMEText(htmlBody, 'html')  # type: ignore
    elif body and not any([entry_ids, file_names, attach_cid, manualAttachObj, htmlBody]):
        # if there is only body and no attachments to the mail , we would like to send it without attaching every part
        message = MIMEText(body, 'plain', 'utf-8')  # type: ignore
    elif htmlBody and body and any([entry_ids, file_names, attach_cid, manualAttachObj]):
        # if all these exist - htmlBody, body and one of the attachment's items, the message object will be:
        # a MimeMultipart object of type 'mixed' which contains
        # a MIMEMultipart object of type `alternative` which contains
        # the 2 MIMEText objects for each body part and the relevant Mime<type> object for the attachments.
        message = MIMEMultipart('mixed')  # type: ignore
        alt = MIMEMultipart('alternative')
        message.attach(alt)
        attach_body_to = alt
    else:
        message = MIMEMultipart('alternative') if body and htmlBody else MIMEMultipart()  # type: ignore

    if not attach_body_to:
        attach_body_to = message  # type: ignore

    message['to'] = header(','.join(emailto))
    message['cc'] = header(','.join(cc))
    message['bcc'] = header(','.join(bcc))
    message['from'] = header(emailfrom)
    message['subject'] = header(subject)
    message['reply-to'] = header(replyTo)

    # The following headers are being used for the reply-mail command.
    if inReplyTo:
        message['In-Reply-To'] = header(' '.join(inReplyTo))
    if references:
        message['References'] = header(' '.join(references))

    # if there are any attachments to the mail or both body and htmlBody were given
    if entry_ids or file_names or attach_cid or manualAttachObj or (body and htmlBody):
        msg = MIMEText(body, 'plain', 'utf-8')
        attach_body_to.attach(msg)  # type: ignore
        htmlAttachments = []  # type: list
        inlineAttachments = []  # type: list

        if htmlBody:
            htmlBody, htmlAttachments = handle_html(htmlBody)
            msg = MIMEText(htmlBody, 'html', 'utf-8')
            attach_body_to.attach(msg)  # type: ignore
            if attach_cid:
                inlineAttachments = collect_inline_attachments(attach_cid)

        else:
            # if not html body, cannot attach cids in message
            transientFileCID = None

        attachments = collect_attachments(entry_ids, file_names)
        manual_attachments = collect_manual_attachments()
        transientAttachments = transient_attachments(transientFile, transientFileContent, transientFileCID)

        attachments = attachments + htmlAttachments + transientAttachments + inlineAttachments + manual_attachments
        attachment_handler(message, attachments)

    if additional_headers:
        for h in additional_headers:
            header_name, header_value = h.split('=')
            message[header_name] = header(header_value)

    encoded_message = base64.urlsafe_b64encode(message.as_string())
    command_args = {
        'userId': emailfrom,
        'body': {
            'raw': encoded_message,
        }
    }
    service = get_service('gmail', 'v1', additional_scopes=['https://www.googleapis.com/auth/gmail.compose',
                                                            'https://www.googleapis.com/auth/gmail.send'],
                          delegated_user=emailfrom)
    result = service.users().messages().send(**command_args).execute()
    return result


def send_mail_command():
    args = demisto.args()
    emailto = argToList(args.get('to'))
    emailfrom = args.get('from')
    body = args.get('body')
    subject = args.get('subject')
    entry_ids = argToList(args.get('attachIDs'))
    cc = argToList(args.get('cc'))
    bcc = argToList(args.get('bcc'))
    htmlBody = args.get('htmlBody')
    replyTo = args.get('replyTo')
    file_names = argToList(args.get('attachNames'))
    attchCID = argToList(args.get('attachCIDs'))
    transientFile = argToList(args.get('transientFile'))
    transientFileContent = argToList(args.get('transientFileContent'))
    transientFileCID = argToList(args.get('transientFileCID'))
    manualAttachObj = argToList(args.get('manualAttachObj'))  # when send-mail called from within XSOAR (like reports)
    additional_headers = argToList(args.get('additionalHeader'))
    template_param = args.get('templateParams')

    if emailfrom is None:
        emailfrom = ADMIN_EMAIL

    result = send_mail(emailto, emailfrom, subject, body, entry_ids, cc, bcc, htmlBody,
                       replyTo, file_names, attchCID, transientFile, transientFileContent,
                       transientFileCID, manualAttachObj, additional_headers, template_param)
    return sent_mail_to_entry('Email sent:', [result], emailto, emailfrom, cc, bcc, body, subject)


def reply_mail_command():
    args = demisto.args()
    emailto = argToList(args.get('to'))
    emailfrom = args.get('from')
    inReplyTo = argToList(args.get('inReplyTo'))
    references = argToList(args.get('references'))
    body = args.get('body')
    subject = 'Re: ' + args.get('subject')
    entry_ids = argToList(args.get('attachIDs'))
    cc = argToList(args.get('cc'))
    bcc = argToList(args.get('bcc'))
    htmlBody = args.get('htmlBody')
    replyTo = args.get('replyTo')
    file_names = argToList(args.get('attachNames'))
    attchCID = argToList(args.get('attachCIDs'))
    transientFile = argToList(args.get('transientFile'))
    transientFileContent = argToList(args.get('transientFileContent'))
    transientFileCID = argToList(args.get('transientFileCID'))
    manualAttachObj = argToList(args.get('manualAttachObj'))  # when send-mail called from within XSOAR (like reports)
    additional_headers = argToList(args.get('additionalHeader'))
    template_param = args.get('templateParams')

    if emailfrom is None:
        emailfrom = ADMIN_EMAIL

    result = send_mail(emailto, emailfrom, subject, body, entry_ids, cc, bcc, htmlBody,
                       replyTo, file_names, attchCID, transientFile, transientFileContent,
                       transientFileCID, manualAttachObj, additional_headers, template_param, inReplyTo, references)
    return sent_mail_to_entry('Email sent:', [result], emailto, emailfrom, cc, bcc, body, subject)


def forwarding_address_add_command():
    """
    Creates a forwarding address.
    """

    args = demisto.args()
    forwarding_email = args.get('forwarding_email', '')
    user_id = args.get('user_id', '')
    request_body = {'forwardingEmail': forwarding_email}
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.settings.sharing'],
        delegated_user=user_id)
    result = service.users().settings().forwardingAddresses().create(userId=user_id, body=request_body).execute()
    readable_output = "Added forwarding address {0} for {1} with status {2}.".format(forwarding_email, user_id,
                                                                                     result.get('verificationStatus',
                                                                                                ''))
    context = dict(result)
    context['userId'] = user_id
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': {
            'Gmail.ForwardingAddress((val.forwardingEmail && val.forwardingEmail '
            '== obj.forwardingEmail) && (val.userId && val.userId == obj.userId))': context,
        }
    }


def send_as_add_command():
    """
    Creates a custom "from" send-as alias. If an SMTP MSA is specified, Gmail will attempt to connect to the SMTP
    service to validate the configuration before creating the alias. If ownership verification is required for the
    alias, a message will be sent to the email address and the resource's verification status will be set to pending;
    otherwise, the resource will be created with verification status set to accepted. If a signature is provided,
    Gmail will sanitize the HTML before saving it with the alias.

    This method is only available to service account clients that have been delegated domain-wide authority.
    """
    args = demisto.args()
    user_id = args.pop('user_id', '')

    smtp_msa_object = {key.replace('smtp_', ''): value for (key, value) in args.items() if
                       key.startswith('smtp_')}

    args = {key: value for (key, value) in args.items() if not key.startswith('smtp_')}

    send_as_settings = dict_keys_snake_to_camelcase(args)

    if smtp_msa_object:
        if any(field not in smtp_msa_object.keys() for field in SEND_AS_SMTP_FIELDS):
            raise ValueError('SMTP configuration missing. Please provide all the SMTP field values.')
        smtp_msa_object['securityMode'] = smtp_msa_object.pop('securitymode', '')
        send_as_settings['smtpMsa'] = smtp_msa_object

    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.settings.sharing'],
        delegated_user=user_id)
    result = service.users().settings().sendAs().create(userId='me', body=send_as_settings).execute()
    context = result.copy()
    context['userId'] = user_id

    for (key, value) in context.pop('smtpMsa', {}).items():
        context['smtpMsa' + (key[0].upper() + key[1:])] = value

    hr_fields = ['sendAsEmail', 'displayName', 'replyToAddress', 'isPrimary', 'treatAsAlias']

    readable_output = tableToMarkdown(
        'A custom "{}" send-as alias created for "{}".'.format(result.get('sendAsEmail', ''), user_id),
        context, headerTransform=pascalToSpace, removeNull=True,
        headers=hr_fields)

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': {
            'Gmail.SendAs((val.sendAsEmail && val.sendAsEmail '
            '== obj.sendAsEmail) && (val.userId && val.userId == obj.userId))': context,
        }
    }


'''FETCH INCIDENTS'''


def fetch_incidents():
    params = demisto.params()
    user_key = params.get('queryUserKey')
    user_key = user_key if user_key else ADMIN_EMAIL
    query = '' if params['query'] is None else params['query']
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('gmt_time')
    # handle first time fetch - gets current GMT time -1 day
    if last_fetch is None:
        last_fetch, _ = parse_date_range(date_range=FETCH_TIME, utc=True, to_timestamp=False)
        last_fetch = str(last_fetch.isoformat()).split('.')[0] + 'Z'

    last_fetch = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ')
    current_fetch = last_fetch
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly'],
        user_key)

    query += last_fetch.strftime(' after:%Y/%m/%d')
    LOG('GMAIL: fetch parameters:\nuser: %s\nquery=%s\nfetch time: %s' %
        (user_key, query, last_fetch,))

    result = service.users().messages().list(
        userId=user_key, maxResults=100, q=query).execute()

    incidents = []
    # so far, so good
    LOG('GMAIL: possible new incidents are %s' % (result,))
    for msg in result.get('messages', []):
        msg_result = service.users().messages().get(
            id=msg['id'], userId=user_key).execute()
        incident = mail_to_incident(msg_result, service, user_key)
        temp_date = datetime.strptime(
            incident['occurred'], '%Y-%m-%dT%H:%M:%SZ')
        # update last run
        if temp_date > last_fetch:
            last_fetch = temp_date + timedelta(seconds=1)

        # avoid duplication due to weak time query
        if temp_date > current_fetch:
            incidents.append(incident)

    demisto.info('extract {} incidents'.format(len(incidents)))
    demisto.setLastRun({'gmt_time': last_fetch.isoformat().split('.')[0] + 'Z'})
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
        'gmail-hide-user-in-directory': hide_user_command,
        'gmail-set-password': set_user_password_command,
        'gmail-get-autoreply': get_autoreply_command,
        'gmail-set-autoreply': set_autoreply_command,
        'gmail-delegate-user-mailbox': delegate_user_mailbox_command,
        'gmail-remove-delegated-mailbox': remove_delegate_user_mailbox_command,
        'send-mail': send_mail_command,
        'reply-mail': reply_mail_command,
        'gmail-get-role': get_role_command,
        'gmail-forwarding-address-add': forwarding_address_add_command,
        'gmail-send-as-add': send_as_add_command,
    }
    command = demisto.command()
    LOG('GMAIL: command is %s' % (command,))
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
if __name__ in ("__builtin__", "builtins"):
    main()
