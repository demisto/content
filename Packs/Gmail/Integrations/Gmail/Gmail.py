import uuid
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import base64
import concurrent.futures
import itertools as it
import json
import mimetypes
import random
import re
import string
import sys
import copy
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime, format_datetime
from distutils.util import strtobool
from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html.entities import name2codepoint
from html.parser import HTMLParser
from typing import *
from urllib.parse import urlparse

import google_auth_httplib2
import httplib2
from apiclient import discovery
from google.oauth2 import service_account
from googleapiclient.errors import HttpError

''' GLOBAL VARS '''

ADMIN_EMAIL = ''  # set from params later on
PRIVATE_KEY_CONTENT = None
GAPPS_ID = None
SCOPES = ['https://www.googleapis.com/auth/admin.directory.user.readonly']
PROXY = demisto.params().get('proxy')
DISABLE_SSL = demisto.params().get('insecure', False)
FETCH_TIME = demisto.params().get('fetch_time', '1 days')
LEGACY_NAME = argToBoolean(demisto.params().get('legacy_name', False))

SEND_AS_SMTP_FIELDS = ['host', 'port', 'username', 'password', 'securitymode']
DATE_FORMAT = '%Y-%m-%d'  # sample - 2020-08-23

BATCH_DIVIDER = 5
MAX_USERS = 2500
MAX_WITHOUT_POLLING = 500

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
                self._texts.append(re.sub(r'\s+', ' ', stripped))  # pylint: disable=E1101

    def handle_entityref(self, name):
        if not self._ignore and name in name2codepoint:
            self._texts.append(chr(name2codepoint[name]))

    def handle_charref(self, name):
        if not self._ignore:
            if name.startswith('x'):
                c = chr(int(name[1:], 16))
            else:
                c = chr(int(name))
            self._texts.append(c)

    def get_text(self):
        return "".join(self._texts)


def html_to_text(html):
    parser = TextExtractHtmlParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as e:
        demisto.error(f'The following error occurred while parsing the HTML: {e}')
        pass
    return parser.get_text()


# disable-secrets-detection-start
def get_http_client_with_proxy(proxies):
    proxy_info = None
    if PROXY:
        if not proxies or not proxies['https']:
            raise Exception('https proxy value is empty. Check Demisto server configuration')
        https_proxy = proxies['https']
        if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
            https_proxy = 'https://' + https_proxy
        parsed_proxy = urlparse(https_proxy)
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

    json_acct_info = json.loads(PRIVATE_KEY_CONTENT)  # type: ignore
    credentials = service_account.Credentials.from_service_account_info(json_acct_info)
    scoped_credentials = credentials.with_scopes(scopes)
    delegated_credentials = scoped_credentials.with_subject(delegated_user)
    return delegated_credentials


def get_service(serviceName, version, additional_scopes=None, delegated_user=None):
    credentials = get_credentials(additional_scopes=additional_scopes, delegated_user=delegated_user)
    proxies = handle_proxy()
    if PROXY or DISABLE_SSL:
        http_client = google_auth_httplib2.AuthorizedHttp(credentials, http=get_http_client_with_proxy(proxies))
        return discovery.build(serviceName, version, cache_discovery=False, http=http_client)
    return discovery.build(serviceName, version, cache_discovery=False, credentials=credentials)


def parse_mail_parts(parts):
    body = ''
    html = ''
    attachments = []  # type: list
    for part in parts:
        if 'multipart' in part['mimeType'] and part.get('parts'):
            part_body, part_html, part_attachments = parse_mail_parts(
                part['parts'])
            body += part_body
            html += part_html
            attachments.extend(part_attachments)
        elif len(part['filename']) == 0:
            text = str(base64.urlsafe_b64decode(
                part['body'].get('data', '').encode('ascii')), 'utf-8')
            if 'text/html' in part['mimeType']:
                html += text
            else:
                body += text

        else:
            if part['body'].get('attachmentId') is not None:
                attachmentName = part['filename']
                content_id = ""
                is_inline = False
                for header in part.get('headers', []):
                    if header.get('name') == 'Content-ID':
                        content_id = header.get('value').strip("<>")
                    if header.get('name') == 'Content-Disposition':
                        is_inline = 'inline' in header.get('value').strip('<>')
                if is_inline and content_id and content_id != "None" and not LEGACY_NAME:
                    attachmentName = f"{content_id}-attachmentName-{attachmentName}"
                attachments.append({
                    'ID': part['body']['attachmentId'],
                    'Name': attachmentName,
                })

    return body, html, attachments


def format_fields_argument(fields: list[str]) -> list[str] | None:
    """
    Checks if the filter fields are valid, if so returns the valid fields,
    otherwise returns `None`, when given an empty list returns `None`.
    """
    all_valid_fields = (
        "Type",
        "Mailbox",
        "ThreadId",
        "Labels",
        "Headers",
        "Attachments",
        "RawData",
        "Format",
        "Subject",
        "From",
        "To",
        "Body",
        "Cc",
        "Bcc",
        "Date",
        "Html",
        "Attachment Names",
    )
    lower_filter_fields = {field.lower() for field in fields}
    if valid_fields := [field for field in all_valid_fields if field.lower() in lower_filter_fields]:
        valid_fields.append('ID')
        return valid_fields
    return None


def filter_by_fields(full_mail: dict[str, Any], filter_fields: list[str]) -> dict:
    return {field: full_mail.get(field) for field in filter_fields}


def parse_privileges(raw_privileges):
    privileges = []
    for p in raw_privileges:
        privilege = assign_params(ServiceID=p.get('serviceId'), Name=p.get('privilegeName'))
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


def get_occurred_date(email_data: dict) -> Tuple[datetime, bool]:
    """Get the occurred date of an email. The date gmail uses is actually the X-Received or the top Received
    dates in the header. If fails finding these dates will fall back to internal date.
    Args:
        email_data (dict): email to extract from
    Returns:
        Tuple[datetime, bool]: occurred datetime, can be used for incrementing search date
    """
    headers = demisto.get(email_data, 'payload.headers')
    output = None
    if not headers or not isinstance(headers, list):
        demisto.error(f"couldn't get headers for msg (shouldn't happen): {email_data}")
    else:
        # use x-received or recvived. We want to use x-received first and fallback to received.
        for name in ['x-received', 'received', ]:
            header = next(filter(lambda ht: ht.get('name', '').lower() == name, headers), None)
            if header:
                val = header.get('value')
                if val:
                    res = get_date_from_email_header(val)
                    if res:
                        output = datetime.fromtimestamp(res.timestamp(), tz=timezone.utc)
                        demisto.debug(f"The timing from header: {name} value: {val} the result: {res}, the UTC time is {output}")
                        break
    internalDate = email_data.get('internalDate')
    demisto.info(f"trying internalDate: {internalDate}")
    if internalDate and internalDate != '0':
        # intenalDate timestamp has 13 digits, but epoch-timestamp counts the seconds since Jan 1st 1970
        # (which is currently less than 13 digits) thus a need to cut the timestamp down to size.
        timestamp_len = len(str(int(time.time())))
        if len(str(internalDate)) >= timestamp_len:
            internalDate = (str(internalDate)[:timestamp_len])
            internalDate_dt = datetime.fromtimestamp(int(internalDate), tz=timezone.utc)
            demisto.debug(f"{internalDate=} {internalDate_dt=}")
            if output and internalDate_dt:
                # check which time is earlier, return it
                output = internalDate_dt if internalDate_dt < output else output
            elif internalDate_dt and not output:
                output = internalDate_dt
    if output:
        demisto.debug(f"The final occurred time is {output}")
        return output, True
    # we didn't get a date from anywhere
    demisto.info("Failed finding date from internal or headers. Using 'datetime.now()'")
    return datetime.now(tz=timezone.utc), False


def get_date_from_email_header(header: str) -> Optional[datetime]:
    """Parse an email header such as Date or Received. The format is either just the date
    or name value pairs followed by ; and the date specification. For example:
    by 2002:a17:90a:77cb:0:0:0:0 with SMTP id e11csp4670216pjs;        Mon, 21 Dec 2020 12:11:57 -0800 (PST)
    Args:
        header (str): header value to parse
    Returns:
        Optional[datetime]: parsed datetime
    """
    if not header:
        return None
    try:
        date_part = header.split(';')[-1].strip()
        res = parsedate_to_datetime(date_part)
        if res.tzinfo is None:
            # some headers may contain a non TZ date so we assume utc
            res = res.replace(tzinfo=timezone.utc)
        return res
    except Exception as ex:
        demisto.debug(f'Failed parsing date from header value: [{header}]. Err: {ex}. Will ignore and continue.')
    return None


def get_email_context(email_data, mailbox):
    occurred, occurred_is_valid = get_occurred_date(email_data)
    context_headers = email_data.get('payload', {}).get('headers', [])
    context_headers = [{'Name': v['name'], 'Value': v['value']}
                       for v in context_headers]
    headers = {h['Name'].lower(): h['Value'] for h in context_headers}
    body = demisto.get(email_data, 'payload.body.data')
    body = body.encode('ascii') if body is not None else ''
    parsed_body = base64.urlsafe_b64decode(body)
    demisto.debug(f"get_email_context {body=} {parsed_body=}")

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
        'Body': str(parsed_body, 'utf-8'),

        # only for incident
        'Cc': headers.get('cc', []),
        'Bcc': headers.get('bcc', []),
        'Date': format_datetime(occurred),
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
        'Body/Text': str(parsed_body, 'utf-8'),

        'CC': headers.get('cc', []),
        'BCC': headers.get('bcc', []),
        'Date': format_datetime(occurred),
        'Body/HTML': None,
    }

    if 'text/html' in context_gmail['Format']:  # type: ignore
        context_gmail['Html'] = context_gmail['Body']
        context_gmail['Body'] = html_to_text(context_gmail['Body'])
        context_email['Body/HTML'] = context_gmail['Html']
        context_email['Body/Text'] = context_gmail['Body']
        demisto.debug(f"In text/html {context_gmail['Body']=}")

    if 'multipart' in context_gmail['Format']:  # type: ignore
        context_gmail['Body'], context_gmail['Html'], context_gmail['Attachments'] = parse_mail_parts(
            email_data.get('payload', {}).get('parts', []))
        demisto.debug(f"In multipart {context_gmail['Body']=}")
        context_gmail['Attachment Names'] = ', '.join(
            [attachment['Name'] for attachment in context_gmail['Attachments']])  # type: ignore
        context_email['Body/Text'], context_email['Body/HTML'], context_email['Attachments'] = parse_mail_parts(
            email_data.get('payload', {}).get('parts', []))
        context_email['Attachment Names'] = ', '.join(
            [attachment['Name'] for attachment in context_email['Attachments']])  # type: ignore

    return context_gmail, headers, context_email, occurred, occurred_is_valid


TIME_REGEX = re.compile(r'^([\w,\d: ]*) (([+-]{1})(\d{2}):?(\d{2}))?[\s\w\(\)]*$')  # pylint: disable=E1101


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
    for key, val in list(headers.items()):
        labels.append({'type': 'Email/Header/' + key, 'value': val})

    return labels


def mailboxes_to_entry(mailboxes: list[dict]) -> list[CommandResults]:
    query = f"Query: {mailboxes[0].get('q') if mailboxes else ''}"
    found_accounts = []
    errored_accounts = []  # accounts not searched, due to an error accessing them

    for user in mailboxes:
        mailbox = user.get('Mailbox')
        if (error := user.get('Error')):
            errored_accounts.append({"Mailbox": mailbox, "Error": error})
        elif mailbox:
            found_accounts.append(mailbox)
        else:
            demisto.debug(f"unexpected value: neither user['Mailbox'] nor user['Error']: {user=}")

    command_results = [CommandResults(
        outputs_prefix='Gmail.Mailboxes',
        readable_output=tableToMarkdown(
            query,
            [{'Mailbox': mailbox} for mailbox in found_accounts],
            headers=['Mailbox'],
            removeNull=True),
        outputs=found_accounts
    )]

    if errored_accounts:
        command_results.append(CommandResults(
            outputs_prefix='Gmail.UnsearchedAcounts',
            outputs=errored_accounts,
        ))
    return command_results


def emails_to_entry(title, raw_emails, format_data, mailbox, fields: list[str] | None = None):
    gmail_emails = []
    emails = []
    for email_data in raw_emails:
        context_gmail, _, context_email, occurred, occurred_is_valid = get_email_context(email_data, mailbox)
        if fields:
            context_gmail = filter_by_fields(context_gmail, fields)
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


def get_date_isoformat_server(dt: datetime) -> str:
    """Get the  datetime str in the format a server can parse. UTC based with Z at the end
    Args:
        dt (datetime): datetime
    Returns:
        str: string representation
    """
    return datetime.fromtimestamp(dt.timestamp()).isoformat(timespec='seconds') + 'Z'


def mail_to_incident(msg, service, user_key):
    parsed_msg, headers, _, occurred, occurred_is_valid = get_email_context(msg, user_key)
    occurred_str = get_date_isoformat_server(occurred)
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

    incident = {
        'type': 'Gmail',
        'name': parsed_msg['Subject'],
        'details': parsed_msg['Body'],
        'labels': create_incident_labels(parsed_msg, headers),
        'occurred': occurred_str,
        'attachment': file_names,
        'rawJSON': json.dumps(parsed_msg),
    }
    return incident, occurred, occurred_is_valid


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

    return CommandResults(
        outputs=context,
        raw_response=response,
        readable_output=human_readable,
        outputs_prefix='Account',
        outputs_key_field=['ID', 'Type']
    )


def labels_to_entry(title, response, user_key):
    context = []

    for label in response:
        context.append({
            'UserID': user_key,
            'Name': label.get('name'),
            'ID': label.get('id'),
            "Type": label.get('type'),
            "MessageListVisibility": label.get('messageListVisibility'),
            "LabelListVisibility": label.get('labelListVisibility')
        })
    headers = ['Name', 'ID', 'Type', 'MessageListVisibility', 'LabelListVisibility']
    human_readable = tableToMarkdown(title, context, headers, removeNull=True)

    return CommandResults(
        outputs=context,
        raw_response=response,
        readable_output=human_readable,
        outputs_prefix='GmailLabel',
        outputs_key_field=['ID', 'Name', 'UserID']
    )


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
    return CommandResults(
        raw_response=autoreply_context,
        outputs=account_context,
        readable_output=tableToMarkdown(title, autoreply_context, headers, removeNull=True),
        outputs_prefix='Account.Gmail',
        outputs_key_field='Address'
    )


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

    return CommandResults(
        raw_response=response,
        outputs=gmail_context,
        readable_output=tableToMarkdown(title, gmail_context, headers, removeNull=True),
        outputs_prefix='Gmail.SentMail',
        outputs_key_field=['ID', 'Type']
    )


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
    human_readable = tableToMarkdown(title, context, headers, removeNull=True)
    return CommandResults(
        raw_response=context,
        outputs=context,
        readable_output=human_readable,
        outputs_prefix='Gmail.Role',
        outputs_key_field='ID'
    )


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

    return CommandResults(
        raw_response=context,
        outputs=context,
        readable_output=tableToMarkdown(title, context, headers, removeNull=True),
        outputs_prefix='Tokens',
        outputs_key_field='ClientId'
    )


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
    privileges_title = f"Role {context.get('ID')} privileges:"
    privileges_hr = tableToMarkdown(privileges_title, privileges, privileges_headers, removeNull=True)

    return CommandResults(
        raw_response=context,
        outputs=context,
        readable_output=details_hr + privileges_hr,
        outputs_prefix='Gmail.Role',
        outputs_key_field='ID'
    )


def dict_keys_snake_to_camelcase(dictionary):
    """
    Converts all dictionary keys from snake case (dict_key) to lower camel case(dictKey).
    :param dictionary: Dictionary which may contain keys in snake_case
    :return: Dictionary with snake_case keys converted to lowerCamelCase
    """
    underscore_pattern = re.compile(r'_([a-z])')  # pylint: disable=E1101
    return {underscore_pattern.sub(lambda i: i.group(1).upper(), key.lower()): value for (key, value) in
            list(dictionary.items())}


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
            raise ValueError(f'{arg_name} argument is not in expected format.')


def cutting_for_batches(list_accounts: list) -> List[list]:

    accounts: list = []
    rest_accounts: list = []

    batch_size = int(len(list_accounts) / BATCH_DIVIDER)
    if rest := len(list_accounts) % BATCH_DIVIDER:
        rest_accounts = list_accounts[-rest:]
        list_accounts = list_accounts[:-rest]

    accounts.extend(batch(list_accounts, batch_size))

    # When the number of accounts is not exactly divisible by BATCH_DIVIDER,
    # We add the remaining accounts to the first batch to avoid running another polling command.
    if rest_accounts:
        accounts[0].extend(rest_accounts)

    return accounts


def scheduled_commands_for_more_users(accounts: list, next_page_token: str) -> List[CommandResults]:

    accounts_batches = cutting_for_batches(accounts)

    command_results: list[CommandResults] = []
    args = copy.deepcopy(demisto.args())
    for batch in accounts_batches:

        args.update({'list_accounts': batch})
        command_results.append(
            CommandResults(
                readable_output='Searching mailboxes, please wait...',
                scheduled_command=ScheduledCommand(
                    command='gmail-search-all-mailboxes',
                    next_run_in_seconds=10,
                    args=copy.deepcopy(args),
                    timeout_in_seconds=600
                )
            )
        )
        args.pop('list_accounts', None)
    if next_page_token:
        command_results.append(
            CommandResults(
                outputs_key_field='PageToken',
                outputs={'PageToken': {'NextPageToken': next_page_token}}
            )
        )

    return command_results


def get_mailboxes(max_results: int, users_next_page_token: str = None):
    '''
    Used to fetch the list of accounts for the search-all-mailboxes command
    '''
    accounts: list[str] = []
    accounts_counter = 0
    users_next_page_token = users_next_page_token
    service = get_service('admin', 'directory_v1')

    while True:
        command_args = {
            'maxResults': min(max_results, 100),
            'domain': ADMIN_EMAIL.split('@')[1],
            'pageToken': users_next_page_token
        }

        result = service.users().list(**command_args).execute()
        accounts_counter += len(result['users'])
        accounts.extend([account['primaryEmail'] for account in result['users']])
        users_next_page_token = result.get('nextPageToken')

        if accounts_counter >= max_results:
            accounts = accounts[:max_results]
            break
        if users_next_page_token is None:
            break

    return accounts, users_next_page_token


def information_search_process(length_accounts: int, search_from: int | None, search_to: int | None) -> CommandResults:

    if search_from is None or search_to is None:
        readable_output = f'Searching the first {length_accounts} accounts'
        search_from = 0
        search_to = length_accounts
    else:
        search_from = search_to + 1
        search_to = search_to + length_accounts
        readable_output = f'Searching accounts {search_from} to {search_to}'

    return CommandResults(
        readable_output=readable_output,
        outputs={'SearchFromAccountIndex': search_from, 'SearchToAccountIndex': search_to},
    )


''' FUNCTIONS '''


def list_users_command() -> CommandResults:
    args = demisto.args()
    domain = args.get('domain', ADMIN_EMAIL.split('@')[1])
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


def list_labels_command():
    args = demisto.args()
    user_key = args.get('user-id')
    labels = list_labels(user_key)
    return labels_to_entry(f'Labels for UserID {user_key}:', labels, user_key)


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


def get_user_command() -> CommandResults:
    args = demisto.args()
    user_key = args.get('user-id')
    view_type = args.get('view-type-public-domain')
    projection = args.get('projection')
    customer_field_mask = args.get('customer-field-mask')

    result = get_user(user_key, view_type, projection, customer_field_mask)
    return users_to_entry(f'User {user_key}:', [result])


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


def hide_user_command() -> CommandResults:
    args = demisto.args()
    user_key = args.get('user-id')
    hide_value = args.get('visible-globally')
    result = hide_user(user_key, hide_value)

    return users_to_entry(f'User {user_key}:', [result])


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

    return f'User {command_args["userKey"]} password has been set.'


def get_autoreply_command():
    args = demisto.args()
    user_id = args.get('user-id', ADMIN_EMAIL)

    autoreply_message = get_autoreply(user_id)

    return autoreply_to_entry(f'User {user_id}:', [autoreply_message], user_id)


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
        with open(file_entry['path']) as f:
            file_content = str(f.read())
    response_body_plain_text = file_content if file_content else args.get('response-body')
    response_body_type = args.get('response-body-type')
    domain_only = args.get('domain-only')
    contacts_only = args.get('contacts-only')
    start_time = get_millis_from_date(args.get('start-time'), 'start-time') if args.get('start-time') else None
    end_time = get_millis_from_date(args.get('end-time'), 'end-time') if args.get('end-time') else None

    autoreply_message = set_autoreply(user_id, enable_autoreply, response_subject, response_body_plain_text,
                                      domain_only, contacts_only, start_time, end_time, response_body_type)

    return autoreply_to_entry(f'User {user_id}:', [autoreply_message], user_id)


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
        return f'Email {delegate_email} has been delegated'

    else:
        command_args = {
            'userId': user_id if user_id != 'me' else ADMIN_EMAIL,
            'delegateEmail': delegate_email
        }

        service.users().settings().delegates().delete(**command_args).execute()
        return f'Email {delegate_email} has been removed from delegation'


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
            'fullName': f'{first_name} {family_name}',
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

    return f'User {command_args["userKey"]} have been deleted.'


def list_labels(user_key):
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly'],
        delegated_user=user_key)
    results = service.users().labels().list(userId=user_key).execute()
    labels = results.get('labels', [])
    return labels


def get_user_role_command():
    args = demisto.args()
    user_key = args['user-id']
    user_key = ADMIN_EMAIL if user_key == 'me' else user_key

    if GAPPS_ID is None:
        raise ValueError('Must provide Immutable GoogleApps Id')

    roles = get_user_role(user_key, GAPPS_ID)
    return user_roles_to_entry(f'User Roles of {user_key}:', roles)


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
    return role_to_entry(f'Role {role_id} details:', role)


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


def search_in_mailboxes(accounts: list[str], only_return_account_names: bool) -> None:
    '''
    Searching for email messages within accounts based on a query,
    Results are returned only if messages matching the query are found.
    Returns only the names of the accounts where the messages were found
    if the only_return_account_names argument is true,
    Otherwise, returns all the information about the message, including its content.
    '''
    futures: list = []
    entries: list = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for user in accounts:
            futures.append(executor.submit(search_command, mailbox=user,
                                           only_return_account_names=only_return_account_names))
        for account in concurrent.futures.as_completed(futures):
            if found := account.result():
                entries.append(found)

        if entries:
            if only_return_account_names:
                entries = [mailboxes_to_entry(entries)]
            return_results(entries)


def search_all_mailboxes():

    args = demisto.args()
    only_return_account_names = argToBoolean(args.get('show-only-mailboxes', 'true'))
    list_accounts = argToList(args.get('list_accounts', ''))
    next_page_token = args.get('page-token', '')

    if list_accounts:
        support_multithreading()
        search_in_mailboxes(list_accounts, only_return_account_names)
    else:
        # check if there is next_page_token and remove it from the args (To avoid using this argument in search command)
        if next_page_token:
            demisto.args().pop('page-token', None)

        # Get the accounts that will be searched, maximum accounts is set by MAX_USERS.
        all_accounts, next_page_token = get_mailboxes(MAX_USERS, next_page_token)

        # When the number of accounts is more than MAX_WITHOUT_POLLING the searching will make with polling commands.
        if len(all_accounts) > MAX_WITHOUT_POLLING:
            command_results: List[CommandResults] = scheduled_commands_for_more_users(all_accounts, next_page_token)
            if next_page_token:
                command_results.append(
                    information_search_process(
                        len(all_accounts),
                        arg_to_number(args.get('search_from')),
                        arg_to_number(args.get('search_to'))
                    )
                )
            return_results(command_results)

        # In case that the number of accounts less than MAX_WITHOUT_POLLING the searching run as usual.
        elif all_accounts:
            if args.get('search_from'):
                return_results(information_search_process(
                    len(all_accounts),
                    arg_to_number(args.get('search_from')),
                    arg_to_number(args.get('search_to'))
                ))
            args['list_accounts'] = all_accounts
            search_all_mailboxes()


def search_command(mailbox: str = None, only_return_account_names: bool = False) -> dict[str, Any] | None:
    """
    Searches for Gmail records of a specified Google user.
    """
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
    fields = format_fields_argument(argToList(args.get('fields')))
    label_ids = [lbl for lbl in args.get('labels-ids', '').split(',') if lbl != '']
    max_results = int(args.get('max-results', 100))
    page_token = args.get('page-token')
    include_spam_trash = args.get('include-spam-trash', False)
    has_attachments = args.get('has-attachments')
    has_attachments = None if has_attachments is None else bool(
        strtobool(has_attachments))

    if max_results > 500:
        raise ValueError(
            f'maxResults must be lower than 500, got {max_results}')
    try:
        mails, q = search(user_id, subject, _from, to,
                          before, after, filename, _in, query,
                          fields, label_ids, max_results, page_token,
                          include_spam_trash, has_attachments, only_return_account_names,
                          )
    except HttpError as err:
        if only_return_account_names and err.status_code == 429:
            return {'Mailbox': mailbox, 'Error': {'message': str(err.error_details), 'status_code': err.status_code}}
        raise

    # In case the user wants only account list without content.
    if only_return_account_names:
        if mails:
            return {'Mailbox': mailbox, 'q': q}
        return None
    if mails:
        res = emails_to_entry(f'Search in {mailbox}:\nquery: "{q}"', mails, 'full', mailbox, fields)
        return res
    return None


def search(user_id, subject='', _from='', to='', before='', after='', filename='', _in='', query='',
           fields=None, label_ids=None, max_results=100, page_token=None, include_spam_trash=False,
           has_attachments=None, only_return_account_names=None):
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
    q = ' '.join(f'{name}:{value} '
                 for name, value in list(query_values.items()) if value != '')
    q = (f'{q} {query}').strip()

    command_args = {
        'userId': user_id,
        'q': q,
        'maxResults': max_results,
        'labelIds': label_ids,
        'pageToken': page_token,
        'includeSpamTrash': include_spam_trash,
    }
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly'],
        command_args['userId'])

    try:
        result = service.users().messages().list(**command_args).execute()
    except Exception as e:
        if "Mail service not enabled" in str(e):
            result = {}
        else:
            raise

    # In case the user wants only account list without content.
    if only_return_account_names and result.get('sizeEstimate', 0) > 0:
        return True, q

    entries = [get_mail(user_id=user_id,
                        _id=mail['id'],
                        _format='full',
                        service=service) for mail in result.get('messages', [])]

    return entries, q


def get_mail_command():
    args = demisto.args()
    user_id = args.get('user-id', ADMIN_EMAIL)
    _id = args.get('message-id')
    _format = args.get('format')
    should_run_get_attachments = argToBoolean(args.get('include-attachments', 'false'))

    mail = get_mail(user_id, _id, _format)
    email_entry = emails_to_entry('Email:', [mail], _format, user_id)
    results = [email_entry]
    if should_run_get_attachments:
        get_attachments_command_results = get_attachments_command()
        results.append(get_attachments_command_results)  # type: ignore
    return results


def get_mail(user_id, _id, _format, service=None):
    command_args = {
        'userId': user_id,
        'id': _id,
        'format': _format,
    }
    if not service:
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
    for attachment in result.get('Attachments', []):
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
    if isinstance(ids, STRING_OBJ_TYPES):  # alternativly it could be an array
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
    return Header(s_no_newlines)


def template_params(paramsStr):
    """
    Translate the template params if they exist from the context
    """
    actualParams = {}
    if paramsStr:
        try:
            params = json.loads(paramsStr)

        except ValueError as e:
            return_error(f'Unable to parse templateParams: {str(e)}')
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
    for file_name, file_data, file_cid in it.zip_longest(transientFile, transientFileContent, transientFileCID):
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
        re.finditer(  # pylint: disable=E1101
            r'<img.+?src=\"(data:(image\/.+?);base64,([a-zA-Z0-9+/=\r\n]+?))\"',
            htmlBody,
            re.I | re.S  # pylint: disable=E1101
        )
    ):
        maintype, subtype = m.group(2).split('/', 1)
        name = f"image{i}.{subtype}"
        cid = (f'{name}@{str(uuid.uuid4())[:8]}_{str(uuid.uuid4())[:8]}')
        attachment = {
            'maintype': maintype,
            'subtype': subtype,
            'data': b64_decode(m.group(3)),
            'name': name,
            'cid': cid,
            'ID': cid
        }
        attachments.append(attachment)
        cleanBody += htmlBody[lastIndex:m.start(1)] + 'cid:' + attachment['cid']
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
    return None


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
                data = fp.read()  # type: ignore [assignment]

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

            content_type, encoding = mimetypes.guess_type(file_name)
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
                msg_txt.add_header('Content-ID', '<' + att['cid'] + '>')

            else:
                msg_txt.add_header('Content-Disposition', 'attachment', filename=att['name'])
            message.attach(msg_txt)

        elif att['maintype'] == 'image':
            msg_img = MIMEImage(att['data'], att['subtype'])
            if att['cid'] is not None:
                msg_img.add_header('Content-Disposition', 'inline', filename=att['name'])
                msg_img.add_header('Content-ID', '<' + att['cid'] + '>')
                if att.get('ID'):
                    msg_img.add_header('X-Attachment-Id', att['ID'])

            else:
                msg_img.add_header('Content-Disposition', 'attachment', filename=att['name'])
            message.attach(msg_img)

        elif att['maintype'] == 'audio':
            msg_aud = MIMEAudio(att['data'], att['subtype'])
            if att['cid'] is not None:
                msg_aud.add_header('Content-Disposition', 'inline', filename=att['name'])
                msg_aud.add_header('Content-ID', '<' + att['cid'] + '>')

            else:
                msg_aud.add_header('Content-Disposition', 'attachment', filename=att['name'])
            message.attach(msg_aud)

        elif att['maintype'] == 'application':
            msg_app = MIMEApplication(att['data'], att['subtype'])
            if att['cid'] is not None:
                msg_app.add_header('Content-Disposition', 'inline', filename=att['name'])
                msg_app.add_header('Content-ID', '<' + att['cid'] + '>')
            else:
                msg_app.add_header('Content-Disposition', 'attachment', filename=att['name'])
            message.attach(msg_app)

        else:
            msg_base = MIMEBase(att['maintype'], att['subtype'])
            msg_base.set_payload(att['data'])
            if att['cid'] is not None:
                msg_base.add_header('Content-Disposition', 'inline', filename=att['name'])
                msg_base.add_header('Content-ID', '<' + att['cid'] + '>')

            else:
                msg_base.add_header('Content-Disposition', 'attachment', filename=att['name'])
            message.attach(msg_base)


def send_mail(emailto, emailfrom, subject, body, entry_ids, cc, bcc, htmlBody, replyTo, file_names,
              attach_cid, transientFile, transientFileContent, transientFileCID, manualAttachObj, additional_headers,
              templateParams, sender_display_name, inReplyTo=None, references=None, force_handle_htmlBody=False):
    if templateParams:
        templateParams = template_params(templateParams)
        if body:
            body = body.format(**templateParams)
        if htmlBody:
            htmlBody = htmlBody.format(**templateParams)

    attach_body_to = None
    if htmlBody and not any([entry_ids, file_names, attach_cid, manualAttachObj, body, force_handle_htmlBody]):
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
        message = MIMEMultipart()  # type: ignore

    if not attach_body_to:
        attach_body_to = message  # type: ignore

    message['to'] = header(','.join(emailto))
    message['cc'] = header(','.join(cc))
    message['bcc'] = header(','.join(bcc))
    message['subject'] = header(subject)
    message['reply-to'] = header(replyTo)
    if sender_display_name:
        message['from'] = header(sender_display_name + f' <{emailfrom}>')
    else:
        message['from'] = header(emailfrom)

    # The following headers are being used for the reply-mail command.
    if inReplyTo:
        message['In-Reply-To'] = header(' '.join(inReplyTo))
    if references:
        message['References'] = header(' '.join(references))

    # if there are any attachments to the mail or both body and htmlBody were given
    if entry_ids or file_names or attach_cid or manualAttachObj or (body and htmlBody) or force_handle_htmlBody:
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
            msg = MIMEText(body, 'plain', 'utf-8')
            attach_body_to.attach(msg)  # type: ignore

        attachments = collect_attachments(entry_ids, file_names)
        manual_attachments = collect_manual_attachments()
        transientAttachments = transient_attachments(transientFile, transientFileContent, transientFileCID)

        attachments = attachments + htmlAttachments + transientAttachments + inlineAttachments + manual_attachments
        attachment_handler(message, attachments)

    if additional_headers:
        for h in additional_headers:
            header_name, header_value = h.split('=')
            message[header_name] = header(header_value)

    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
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
    return mail_command(args)


def mail_command(args, subject_prefix='', in_reply_to=None, references=None):
    email_to = argToList(args.get('to'))
    email_from = args.get('from', ADMIN_EMAIL)
    body = args.get('body')
    subject = f"{subject_prefix}{args.get('subject')}"
    entry_ids = argToList(args.get('attachIDs'))
    cc = argToList(args.get('cc'))
    bcc = argToList(args.get('bcc'))
    html_body = args.get('htmlBody')
    force_handle_htmlBody = argToBoolean(args.get('force_handle_htmlBody', False))
    reply_to = args.get('replyTo')
    attach_names = argToList(args.get('attachNames'))
    attach_cids = argToList(args.get('attachCIDs'))
    transient_file = argToList(args.get('transientFile'))
    transient_file_content = argToList(args.get('transientFileContent'))
    transient_file_cid = argToList(args.get('transientFileCID'))
    manual_attach_obj = argToList(args.get('manualAttachObj'))  # when send-mail called from within XSOAR (like reports)
    additional_headers = argToList(args.get('additionalHeader'))
    template_param = args.get('templateParams')
    render_body = argToBoolean(args.get('renderBody', False))
    body_type = args.get('bodyType', 'Text').lower()
    sender_display_name = args.get('senderDisplayName')

    result = send_mail(email_to, email_from, subject, body, entry_ids, cc, bcc, html_body, reply_to,
                       attach_names, attach_cids, transient_file, transient_file_content, transient_file_cid, manual_attach_obj,
                       additional_headers, template_param, sender_display_name, in_reply_to, references, force_handle_htmlBody)
    rendering_body = html_body if body_type == "html" else body

    send_mail_result = sent_mail_to_entry('Email sent:', [result], email_to, email_from, cc, bcc, rendering_body,
                                          subject)
    if render_body:
        html_result = CommandResults(
            entry_type=EntryType.NOTE,
            content_format=EntryFormat.HTML,
            raw_response=html_body,
        )
        return [send_mail_result, html_result]
    return send_mail_result


def reply_mail_command():
    args = demisto.args()
    in_reply_to = argToList(args.get('inReplyTo'))
    references = argToList(args.get('references'))

    return mail_command(args, 'Re: ', in_reply_to, references)


def forwarding_address_add(user_id: str, forwarding_email: str) -> tuple[dict, bool, Optional[dict]]:
    """ Creates forwarding address.
        Args:
            user_id: str - The user's email address or the user id.
            forwarding_email: str - The forwarding address to be retrieved.
        Returns:
            result: dict - Response body from the API.
            exception: bool - Indicates whether there is an error.
            exception_details: dict - The details of the exception.
    """
    result = {}
    exception_details = {}
    exception = False
    request_body = {'forwardingEmail': forwarding_email}
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.settings.sharing'],
        delegated_user=user_id)
    try:
        result = service.users().settings().forwardingAddresses().create(userId=user_id, body=request_body).execute()
        result['userId'] = user_id
    except HttpError as e:
        exception = True
        exception_details = {'forwardingEmail': forwarding_email, 'errorMessage': e.reason, 'userId': user_id}
    return result, exception, exception_details


def forwarding_address_add_command() -> list[CommandResults]:
    """ Creates forwarding address.
        Args:
            user_id: str - The user's email address or the user id.
            forwarding_email: str - The forwarding address to be retrieved.
        Returns:
            A list of CommandResults.
    """
    args = demisto.args()
    forwarding_email_list = argToList(args.get('forwarding_email'))
    user_id = args.get('user_id', '')
    headers = {
        'success': ['forwardingEmail', 'userId', 'verificationStatus'],
        'failure': ['forwardingEmail', 'errorMessage']
    }
    outputs_list_success = []
    outputs_list_failure = []
    results = []
    for forwarding_email in forwarding_email_list:
        result_forwarding_add, is_exception, error_details = forwarding_address_add(user_id, forwarding_email)
        if is_exception:
            outputs_list_failure.append(error_details)
            demisto.debug(error_details)
        else:
            outputs_list_success.append(result_forwarding_add)

    if outputs_list_success:
        results.append(CommandResults(raw_response=outputs_list_success,
                                      outputs=outputs_list_success,
                                      readable_output=tableToMarkdown(f'Forwarding addresses results for "{user_id}":',
                                                                      outputs_list_success, headers['success'], removeNull=True),
                                      outputs_prefix='Gmail.ForwardingAddress',
                                      outputs_key_field=['forwardingEmail', 'userId']))
    if outputs_list_failure:
        results.append(CommandResults(raw_response=outputs_list_failure,
                                      readable_output=tableToMarkdown(f'Forwarding addresses errors for "{user_id}":',
                                                                      outputs_list_failure, headers['failure'], removeNull=True),
                                      outputs_prefix='Gmail.ForwardingAddress',
                                      outputs_key_field=['forwardingEmail', 'userId']))
    return results


def forwarding_address_update(user_id: str, disposition: str, forwarding_email: str) -> tuple[dict, bool, Optional[dict]]:
    """ Update forwarding address with disposition.
        Args:
            user_id: str - The user's email address or the user id.
            forwarding_email: str - The forwarding address to be retrieved.
            disposition: str - The state that a message should be left in after it has been forwarded.
        Returns:
            result: dict - Response body from the API.
            exception: bool - Indicates whether there is an error.
            exception_details: dict - The details of the exception.
    """
    exception = False
    result = {}
    exception_details = {}
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.settings.sharing'],
        delegated_user=user_id)
    request_body = {'emailAddress': forwarding_email,
                    'enabled': True,
                    'disposition': disposition
                    }
    try:
        result = service.users().settings().updateAutoForwarding(userId=user_id, body=request_body).execute()
        result['userId'] = user_id
    except HttpError as e:
        exception = True
        exception_details = {'forwardingEmail': forwarding_email, 'errorMessage': e.reason, 'userId': user_id}

    return result, exception, exception_details


def forwarding_address_update_command() -> list[CommandResults]:
    """ Update forwarding address with disposition.
        Args:
            user_id: str - The user's email address or the user id.
            forwarding_email: list[str] - a forwarding addresses list to be retrieved.
            disposition: str - The state that a message should be left in after it has been forwarded.
        Returns:
           A list of CommandResults.
    """
    args = demisto.args()
    forwarding_email_list = argToList(args.get('forwarding_email'))
    user_id = args.get('user_id')
    disposition = args.get('disposition')
    headers = {
        'success': ['forwardingEmail', 'userId', 'disposition', 'enabled'],
        'failure': ['forwardingEmail', 'errorMessage']
    }
    outputs_list_success = []
    outputs_list_failure = []
    results = []
    for forwarding_email in forwarding_email_list:
        result_forwarding_update, is_exception, error_details = forwarding_address_update(user_id, disposition, forwarding_email)
        if is_exception:
            outputs_list_failure.append(error_details)
            demisto.debug(error_details)
        else:
            result_forwarding_update['forwardingEmail'] = result_forwarding_update.pop('emailAddress')
            result_forwarding_update['userId'] = user_id
            outputs_list_success.append(result_forwarding_update)

    if outputs_list_success:
        results.append(CommandResults(raw_response=outputs_list_success,
                                      outputs=outputs_list_success,
                                      readable_output=tableToMarkdown(f'Forwarding addresses update results for "{user_id}":',
                                                                      outputs_list_success, headers['success'], removeNull=True),
                                      outputs_prefix='Gmail.ForwardingAddress',
                                      outputs_key_field=['forwardingEmail', 'userId']))
    if outputs_list_failure:
        results.append(CommandResults(raw_response=outputs_list_failure,
                                      readable_output=tableToMarkdown(f'Forwarding addresses update errors for "{user_id}":',
                                                                      outputs_list_failure, headers['failure'], removeNull=True),
                                      outputs_prefix='Gmail.ForwardingAddress',
                                      outputs_key_field=['userId', 'forwardingEmail']))

    return results


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

    smtp_msa_object = {key.replace('smtp_', ''): value for (key, value) in list(args.items()) if
                       key.startswith('smtp_')}

    args = {key: value for (key, value) in list(args.items()) if not key.startswith('smtp_')}

    send_as_settings = dict_keys_snake_to_camelcase(args)

    if smtp_msa_object:
        if any(field not in list(smtp_msa_object.keys()) for field in SEND_AS_SMTP_FIELDS):
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

    for (key, value) in list(context.pop('smtpMsa', {}).items()):
        context['smtpMsa' + (key[0].upper() + key[1:])] = value

    hr_fields = ['sendAsEmail', 'displayName', 'replyToAddress', 'isPrimary', 'treatAsAlias']

    readable_output = tableToMarkdown(
        f'A custom "{result.get("sendAsEmail", "")}" send-as alias created for "{user_id}".',
        context, headerTransform=pascalToSpace, removeNull=True,
        headers=hr_fields)

    return CommandResults(
        outputs=context,
        raw_response=result,
        readable_output=readable_output,
        outputs_prefix='Gmail.SendAs',
        outputs_key_field=['sendAsEmail', 'userId']
    )


def parse_date_isoformat_server(dt: str) -> datetime:
    """Get the datetime by parsing the format passed to the server. UTC basded with Z at the end
    Args:
        dt (str): datetime as string
    Returns:
        datetime: datetime representation
    """
    return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def forwarding_address_get(user_id: str, forwarding_email: str) -> dict:
    """ Gets an Existing forwarding address.
        Args:
            user_id: str - The user email address or the user id.
            forwarding_email: str - The forwarding address to be retrieved.
        Returns:
            A Dict object - Response body from the API.
    """
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly',
         'https://www.googleapis.com/auth/gmail.modify',
         'https://mail.google.com/',
         'https://www.googleapis.com/auth/gmail.settings.basic'],
        delegated_user=user_id)
    result = service.users().settings().forwardingAddresses().get(userId=user_id, forwardingEmail=forwarding_email).execute()
    return result


def forwarding_address_get_command() -> CommandResults:
    """ Gets an Existing forwarding address.
        Args:
            user_id: str - The user's email address or the user id.
            forwarding_email: str - The forwarding address to be retrieved.
        Returns:
            A CommandResults object.
    """
    args = demisto.args()
    forwarding_email = args.get('forwarding_email')
    headers = ['forwardingEmail', 'verificationStatus']
    user_id = args.get('user_id')
    result = forwarding_address_get(user_id, forwarding_email)
    result['userId'] = user_id

    return CommandResults(
        raw_response=result,
        outputs=result,
        readable_output=tableToMarkdown(f'Get forwarding address for: "{user_id}"', result, headers, removeNull=True),
        outputs_prefix='Gmail.ForwardingAddress',
        outputs_key_field=['forwardingEmail', 'userId']
    )


def forwarding_address_remove(user_id: str, forwarding_email: str) -> dict:
    """ Removes a forwarding address.
        Args:
            user_id: str - The user's email address or the user id.
            forwarding_email: str - The forwarding address to be retrieved.
        Returns:
            A Dict object - Response body from the API (empty when successful).
    """
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.settings.sharing'],
        delegated_user=user_id)
    result = service.users().settings().forwardingAddresses().delete(userId=user_id, forwardingEmail=forwarding_email).execute()
    return result


def forwarding_address_remove_command() -> CommandResults:
    """ Removes a forwarding address.
        Args:
            user_id: str - The user's email address or the user id.
            forwarding_email: str - The forwarding address to be retrieved.
        Returns:
            A CommandResults object.
    """
    args = demisto.args()
    forwarding_email = args.get('forwarding_email')
    user_id = args.get('user_id')
    forwarding_address_remove(user_id, forwarding_email)
    return CommandResults(
        readable_output=f'Forwarding address "{forwarding_email}" for "{user_id}" was deleted successfully .'
    )


def forwarding_address_list(user_id: str) -> dict:
    """ Gets a list of forwarding addresses.
        Args:
            user_id: str - The user's email address or the user id.
        Returns:
            A Dict object - Response body from the API.
    """
    result = {}
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.settings.basic',
         'https://mail.google.com/',
         'https://www.googleapis.com/auth/gmail.modify',
         'https://www.googleapis.com/auth/gmail.readonly'],
        delegated_user=user_id)
    result = service.users().settings().forwardingAddresses().list(userId=user_id).execute()
    return result


def forwarding_address_list_command() -> CommandResults:
    """ Gets a list of forwarding addresses.
        Args:
            user_id: str - The user's email address or the user id.
            limit: str - The Limit of the results list. Default is 50.
        Returns:
            A CommandResults object.
    """
    args = demisto.args()
    user_id = args.get('user_id')
    limit = int(args.get('limit', '50'))
    result = forwarding_address_list(user_id)
    context = result.get('forwardingAddresses')
    context = context[:limit] if context else []
    for msg in context:
        msg['userId'] = user_id
    headers = ['forwardingEmail', 'verificationStatus']
    return CommandResults(
        raw_response=result,
        outputs=context,
        readable_output=tableToMarkdown(f'Forwarding addresses list for: "{user_id}"', context, headers, removeNull=True),
        outputs_prefix='Gmail.ForwardingAddress',
        outputs_key_field=['forwardingEmail', 'userId']
    )


'''FETCH INCIDENTS'''


def fetch_incidents():
    params = demisto.params()
    user_key = params.get('queryUserKey')
    user_key = user_key if user_key else ADMIN_EMAIL
    max_fetch = int(params.get('fetch_limit') or 50)
    query = '' if params['query'] is None else params['query']
    last_run = demisto.getLastRun()
    demisto.debug(f'last run: {last_run}')
    last_fetch = last_run.get('gmt_time')
    next_last_fetch = last_run.get('next_gmt_time')
    page_token = last_run.get('page_token') or None
    ignore_ids: List[str] = last_run.get('ignore_ids') or []
    ignore_list_used = last_run.get('ignore_list_used') or False  # can we reset the ignore list if we haven't used it
    # handle first time fetch - gets current GMT time -1 day
    if not last_fetch:
        last_fetch = dateparser.parse(date_string=FETCH_TIME, settings={'TIMEZONE': 'UTC'})
        last_fetch = str(last_fetch.isoformat(timespec='seconds')) + 'Z'
    # use replace(tzinfo) to  make the datetime aware of the timezone as all other dates we use are aware
    last_fetch = parse_date_isoformat_server(last_fetch)
    if next_last_fetch:
        next_last_fetch = parse_date_isoformat_server(next_last_fetch)
    else:
        next_last_fetch = last_fetch + timedelta(seconds=1)
    service = get_service(
        'gmail',
        'v1',
        ['https://www.googleapis.com/auth/gmail.readonly'],
        user_key)

    # use seconds for the filter (note that it is inclusive)
    # see: https://developers.google.com/gmail/api/guides/filtering
    query += f' after:{int(last_fetch.timestamp())}'
    max_results = max_fetch
    if max_fetch > 200:
        max_results = 200
    demisto.debug(f'GMAIL: fetch parameters: user: {user_key} query={query} fetch time: {last_fetch} \
    page_token: {page_token} max results: {max_results}')
    result = service.users().messages().list(
        userId=user_key, maxResults=max_results, pageToken=page_token, q=query).execute()

    incidents = []
    # so far, so good
    demisto.debug(f'GMAIL: possible new incidents are {result}')
    for msg in result.get('messages', []):
        msg_id = msg['id']
        if msg_id in ignore_ids:
            demisto.info(f'Ignoring msg id: {msg_id} as it is in the ignore list')
            ignore_list_used = True
            continue
        msg_result = service.users().messages().get(
            id=msg_id, userId=user_key).execute()
        incident, occurred, is_valid_date = mail_to_incident(msg_result, service, user_key)
        if not is_valid_date:  # if  we can't trust the date store the msg id in the ignore list
            demisto.info(f'appending to ignore list msg id: {msg_id}. name: {incident.get("name")}')
            ignore_list_used = True
            ignore_ids.append(msg_id)
        # update last run only if we trust the occurred timestamp
        if is_valid_date and occurred >= next_last_fetch:
            next_last_fetch = occurred + timedelta(seconds=1)

        # avoid duplication due to weak time query
        if (not is_valid_date) or (occurred >= last_fetch):
            incidents.append(incident)
        else:
            demisto.info(
                f'skipped incident with lower date: {occurred} than fetch: {last_fetch} name: {incident.get("name")}')

    demisto.info(f'extract {len(incidents)} incidents')
    next_page_token = result.get('nextPageToken', '')
    if next_page_token:
        # we still have more results
        demisto.info(f'keeping current last fetch: {last_fetch} as result has additional pages to fetch.'
                     f' token: {next_page_token}. Ignoring incremented last_fatch: {next_last_fetch}')
    else:
        demisto.debug(f'will use new last fetch date (no next page token): {next_last_fetch}')
        # if we are not in a tokenized search and we didn't use the ignore ids we can reset it
        if (not page_token) and (not ignore_list_used) and (len(ignore_ids) > 0):
            demisto.info(f'reseting igonre list of len: {len(ignore_ids)}')
            ignore_ids = []
        last_fetch = next_last_fetch
    demisto.setLastRun({
        'gmt_time': get_date_isoformat_server(last_fetch),
        'next_gmt_time': get_date_isoformat_server(next_last_fetch),
        'page_token': next_page_token,
        'ignore_ids': ignore_ids,
        'ignore_list_used': ignore_list_used,
    })
    return incidents


def main():  # pragma: no cover
    global ADMIN_EMAIL, PRIVATE_KEY_CONTENT, GAPPS_ID
    ADMIN_EMAIL = demisto.params()['adminEmail'].get('identifier', '')
    if '@' not in ADMIN_EMAIL:
        raise ValueError(f"Admin email {ADMIN_EMAIL} must be in an email format")
    PRIVATE_KEY_CONTENT = demisto.params()['adminEmail'].get('password', '{}')
    GAPPS_ID = demisto.params().get('gappsID')
    ''' EXECUTION CODE '''
    COMMANDS = {
        'gmail-list-users': list_users_command,
        'gmail-list-labels': list_labels_command,
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
        'gmail-send-as-add': send_as_add_command,
        'gmail-forwarding-address-get': forwarding_address_get_command,
        'gmail-forwarding-address-remove': forwarding_address_remove_command,
        'gmail-forwarding-address-list': forwarding_address_list_command,
        'gmail-forwarding-address-update': forwarding_address_update_command,
        'gmail-forwarding-address-add': forwarding_address_add_command,
    }
    command = demisto.command()
    demisto.debug(f'GMAIL: command is {command},')
    try:
        if command == 'test-module':
            list_users(ADMIN_EMAIL.split('@')[1])
            return_results('ok')
            sys.exit(0)

        if command == 'fetch-incidents':
            demisto.incidents(fetch_incidents())
            sys.exit(0)
        cmd_func = COMMANDS.get(command)
        if cmd_func is None:
            raise NotImplementedError(
                f'Command "{command}" is not implemented.')

        else:
            if command == 'gmail-search-all-mailboxes':
                cmd_func()  # type: ignore[operator]
            else:
                return_results(cmd_func())  # type: ignore
    except Exception as e:
        import traceback
        if command == 'fetch-incidents':
            demisto.error(traceback.format_exc())
            demisto.error(f'GMAIL: {str(e)}')
            raise

        else:
            return_error(f'GMAIL: {str(e)}', traceback.format_exc())


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
