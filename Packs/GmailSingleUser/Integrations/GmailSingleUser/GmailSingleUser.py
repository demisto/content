import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import re
import json
import base64
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime, format_datetime
import httplib2
import sys
from html.parser import HTMLParser
from html.entities import name2codepoint
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.header import Header
import mimetypes
import random
import string
from apiclient import discovery
from oauth2client.client import AccessTokenCredentials
from googleapiclient.discovery_cache.base import Cache
import itertools as it
import urllib.parse
from typing import List, Optional, Tuple
import secrets
import hashlib

''' GLOBAL VARS '''
params = demisto.params()
EMAIL = params.get('email', '')
PROXIES = handle_proxy()
DISABLE_SSL = params.get('insecure', False)
FETCH_TIME = params.get('fetch_time', '1 days')
MAX_FETCH = int(params.get('fetch_limit') or 50)
AUTH_CODE = params.get('code')

CLIENT_ID = params.get('client_id') or "391797357217-pa6jda1554dbmlt3hbji2bivphl0j616.apps.googleusercontent.com"
TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"
TOKEN_FORM_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    'Accept': 'application/json',
}


''' HELPER FUNCTIONS '''


# See: https://github.com/googleapis/google-api-python-client/issues/325#issuecomment-274349841
class MemoryCache(Cache):
    _CACHE: dict = {}

    def get(self, url):
        return MemoryCache._CACHE.get(url)

    def set(self, url, content):
        MemoryCache._CACHE[url] = content


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


class Client:

    def html_to_text(self, html):
        parser = TextExtractHtmlParser()
        try:
            parser.feed(html)
            parser.close()
        except html.parser.HTMLParseError:
            pass
        return parser.get_text()

    def get_http_client_with_proxy(self):
        https_proxy = PROXIES.get('https')
        proxy_info = None
        if https_proxy:
            if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
                https_proxy = 'https://' + https_proxy
            parsed_proxy = urllib.parse.urlparse(https_proxy)
            proxy_info = httplib2.ProxyInfo(  # disable-secrets-detection
                proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # disable-secrets-detection
                proxy_host=parsed_proxy.hostname,
                proxy_port=parsed_proxy.port,
                proxy_user=parsed_proxy.username,
                proxy_pass=parsed_proxy.password)
        return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=DISABLE_SSL)

    def get_service(self, serviceName, version):
        token = self.get_access_token()
        credentials = AccessTokenCredentials(token, 'Demisto Gmail integration')
        if PROXIES or DISABLE_SSL:
            http_client = credentials.authorize(self.get_http_client_with_proxy())
            return discovery.build(serviceName, version, http=http_client, cache=MemoryCache())
        return discovery.build(serviceName, version, credentials=credentials, cache=MemoryCache())

    def get_refresh_token(self, integration_context):
        # use cached refresh_token only if auth code hasn't changed. If it has we will try to obtain a new
        # refresh token
        if integration_context.get('refresh_token') and integration_context.get('code') == AUTH_CODE:
            return integration_context.get('refresh_token')
        if not AUTH_CODE:
            raise ValueError("Auth code not set. Make sure to follow the auth flow. Start by running !gmail-auth-link.")
        refresh_prefix = "refresh_token:"
        if AUTH_CODE.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return AUTH_CODE[len(refresh_prefix):]
        demisto.info(f"Going to obtain refresh token from google's oauth service. For client id: {CLIENT_ID}")
        verifier = integration_context.get('verifier')
        if not verifier:
            raise ValueError("Missing verifier. Make sure to follow the auth flow. Start by running !gmail-auth-link.")
        h = self.get_http_client_with_proxy()
        body = {
            'client_id': CLIENT_ID,
            'code_verifier': verifier,
            'grant_type': 'authorization_code',
            'code': AUTH_CODE,
            'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',  # disable-secrets-detection
        }
        resp, content = h.request(TOKEN_URL, "POST", urllib.parse.urlencode(body), TOKEN_FORM_HEADERS)
        if resp.status not in {200, 201}:
            raise ValueError('Error obtaining refresh token. Make sure to follow auth flow. {} {} {}'.format(
                             resp.status, resp.reason, content))
        resp_json = json.loads(content)
        if not resp_json.get('refresh_token'):
            raise ValueError('Error obtaining refresh token. Missing refresh token in response: {}'.format(content))
        return resp_json.get('refresh_token')

    def get_access_token(self):
        integration_context = demisto.getIntegrationContext() or {}
        access_token = integration_context.get('access_token')
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until and integration_context.get('code') == AUTH_CODE:
            if self.epoch_seconds() < valid_until:
                return access_token
        refresh_token = self.get_refresh_token(integration_context)
        body = {
            'refresh_token': refresh_token,
            'client_id': CLIENT_ID,
            'grant_type': 'refresh_token',
        }
        h = self.get_http_client_with_proxy()
        resp, content = h.request(TOKEN_URL, "POST", urllib.parse.urlencode(body), TOKEN_FORM_HEADERS)

        if resp.status not in {200, 201}:
            msg = 'Error obtaining access token. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    resp.status, resp.reason, content))

                msg += ' Server message: {}'.format(content)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)

        parsed_response = json.loads(content)
        access_token = parsed_response.get('access_token')
        expires_in = parsed_response.get('expires_in', 3595)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        integration_context['access_token'] = access_token
        integration_context['valid_until'] = time_now + expires_in
        integration_context['refresh_token'] = refresh_token
        integration_context['code'] = AUTH_CODE
        demisto.setIntegrationContext(integration_context)
        return access_token

    def parse_mail_parts(self, parts):
        body = u''
        html = u''
        attachments = []  # type: list
        for part in parts:
            if 'multipart' in part['mimeType']:
                part_body, part_html, part_attachments = self.parse_mail_parts(
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
                    attachments.append({
                        'ID': part['body']['attachmentId'],
                        'Name': part['filename']
                    })

        return body, html, attachments

    @staticmethod
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

    @staticmethod
    def get_occurred_date(email_data: dict) -> Tuple[datetime, bool]:
        """Get the occurred date of an email. The date gmail uses is actually the X-Received or the top Received
        dates in the header. If fails finding these dates will fall back to internal date.

        Args:
            email_data (dict): email to extract from

        Returns:
            Tuple[datetime, bool]: occurred datetime, can be used for incrementing search date
        """
        headers = demisto.get(email_data, 'payload.headers')
        if not headers or not isinstance(headers, list):
            demisto.error(f"couldn't get headers for msg (shouldn't happen): {email_data}")
        else:
            # use x-received or recvived. We want to use x-received first and fallback to received.
            for name in ['x-received', 'received', ]:
                header = next(filter(lambda ht: ht.get('name', '').lower() == name, headers), None)
                if header:
                    val = header.get('value')
                    if val:
                        res = Client.get_date_from_email_header(val)
                        if res:
                            demisto.debug(f"Using occurred date: {res} from header: {name} value: {val}")
                            return res, True
        internalDate = email_data.get('internalDate')
        demisto.info(f"couldn't extract occurred date from headers trying internalDate: {internalDate}")
        if internalDate and internalDate != '0':
            # intenalDate timestamp has 13 digits, but epoch-timestamp counts the seconds since Jan 1st 1970
            # (which is currently less than 13 digits) thus a need to cut the timestamp down to size.
            timestamp_len = len(str(int(time.time())))
            if len(str(internalDate)) > timestamp_len:
                internalDate = (str(internalDate)[:timestamp_len])
            return datetime.fromtimestamp(int(internalDate), tz=timezone.utc), True
        # we didn't get a date from anywhere
        demisto.info("Failed finding date from internal or headers. Using 'datetime.now()'")
        return datetime.now(tz=timezone.utc), False

    def get_email_context(self, email_data, mailbox) -> Tuple[dict, dict, dict, datetime, bool]:
        """Get the email context from email data

        Args:
            email_data (dics): the email data received from the gmail api
            mailbox (str): mail box name

        Returns:
            (context_gmail, headers, context_email, received_date, is_valid_recieved): note that if received date is not
                resolved properly is_valid_recieved will be false

        """
        occurred, occurred_is_valid = Client.get_occurred_date(email_data)
        context_headers = email_data.get('payload', {}).get('headers', [])
        context_headers = [{'Name': v['name'], 'Value':v['value']}
                           for v in context_headers]
        headers = dict([(h['Name'].lower(), h['Value']) for h in context_headers])
        body = demisto.get(email_data, 'payload.body.data')
        body = body.encode('ascii') if body is not None else ''
        parsed_body = base64.urlsafe_b64decode(body)
        base_time = headers.get('date', '')
        if not base_time or not Client.get_date_from_email_header(base_time):
            # we have an invalid date. use the occurred in rfc 2822
            demisto.debug(f'Using Date base time from occurred: {occurred} instead of date header: [{base_time}]')
            base_time = format_datetime(occurred)
        context_gmail = {
            'Type': 'Gmail',
            'Mailbox': EMAIL if mailbox == 'me' else mailbox,
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
            'Body/Text': str(parsed_body, 'utf-8'),

            'CC': headers.get('cc', []),
            'BCC': headers.get('bcc', []),
            'Date': base_time,
            'Body/HTML': None,
        }

        if 'text/html' in context_gmail['Format']:  # type: ignore
            context_gmail['Html'] = context_gmail['Body']
            context_gmail['Body'] = self.html_to_text(context_gmail['Body'])
            context_email['Body/HTML'] = context_gmail['Html']
            context_email['Body/Text'] = context_gmail['Body']

        if 'multipart' in context_gmail['Format']:  # type: ignore
            context_gmail['Body'], context_gmail['Html'], context_gmail['Attachments'] = self.parse_mail_parts(
                email_data.get('payload', {}).get('parts', []))
            context_gmail['Attachment Names'] = ', '.join(
                [attachment['Name'] for attachment in context_gmail['Attachments']])  # type: ignore
            context_email['Body/Text'], context_email['Body/HTML'], context_email['Attachments'] = self.parse_mail_parts(
                email_data.get('payload', {}).get('parts', []))
            context_email['Attachment Names'] = ', '.join(
                [attachment['Name'] for attachment in context_email['Attachments']])  # type: ignore

        return context_gmail, headers, context_email, occurred, occurred_is_valid

    def create_incident_labels(self, parsed_msg, headers):
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

    @staticmethod
    def get_date_isoformat_server(dt: datetime) -> str:
        """Get the  datetime str in the format a server can parse. UTC based with Z at the end

        Args:
            dt (datetime): datetime

        Returns:
            str: string representation
        """
        return datetime.fromtimestamp(dt.timestamp()).isoformat(timespec='seconds') + 'Z'

    @staticmethod
    def parse_date_isoformat_server(dt: str) -> datetime:
        """Get the datetime by parsing the format passed to the server. UTC basded with Z at the end

        Args:
            dt (str): datetime as string

        Returns:
            datetime: datetime representation
        """
        return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)

    def mail_to_incident(self, msg, service, user_key) -> Tuple[dict, datetime, bool]:
        """Parse an email message

        Args:
            msg
            service
            user_key

        Raises:
            Exception: when problem getting attachements

        Returns:
            Tuple[dict, datetime, bool]: incident object, occurred datetime, boolean indicating if date is valid or not
        """
        parsed_msg, headers, _, occurred, occurred_is_valid = self.get_email_context(msg, user_key)
        # conver occurred to gmt and then isoformat + Z
        occurred_str = Client.get_date_isoformat_server(occurred)
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

        incident = {
            'type': 'Gmail',
            'name': parsed_msg['Subject'],
            'details': parsed_msg['Body'],
            'labels': self.create_incident_labels(parsed_msg, headers),
            'occurred': occurred_str,
            'attachment': file_names,
            'rawJSON': json.dumps(parsed_msg),
        }
        return incident, occurred, occurred_is_valid

    def sent_mail_to_entry(self, title, response, to, emailfrom, cc, bcc, bodyHtml, body, subject):
        gmail_context = []
        for mail_results_data in response:
            gmail_context.append({
                'Type': "Gmail",
                'ID': mail_results_data.get('id'),
                'Labels': mail_results_data.get('labelIds', []),
                'ThreadId': mail_results_data.get('threadId'),
                'To': to,
                'From': emailfrom,
                'Cc': cc,
                'Bcc': bcc,
                'Subject': subject,
                'Body': body,
                'Mailbox': to,
                'BodyHTML': bodyHtml
            })

        headers = ['Type', 'ID', 'To', 'From', 'Cc', 'Bcc', 'Subject', 'Body', 'Labels',
                   'ThreadId']

        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': response,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, gmail_context, headers, removeNull=True),
            'EntryContext': {'Gmail.SentMail(val.ID && val.Type && val.ID == obj.ID && val.Type == obj.Type)': gmail_context}
        }

    def epoch_seconds(self, d=None):
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = datetime.utcnow()
        return int((d - datetime.utcfromtimestamp(0)).total_seconds())

    def search(self, user_id, subject='', _from='', to='', before='', after='', filename='', _in='', query='',
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
                     for name, value in query_values.items() if value != '')
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
        service = self.get_service('gmail', 'v1')
        result = service.users().messages().list(**command_args).execute()

        return [self.get_mail(user_id, mail['id'], 'full') for mail in result.get('messages', [])], q

    def get_mail(self, user_id, _id, _format):
        command_args = {
            'userId': user_id,
            'id': _id,
            'format': _format,
        }

        service = self.get_service('gmail', 'v1')
        result = service.users().messages().get(**command_args).execute()

        return result

    '''MAIL SENDER FUNCTIONS'''

    def randomword(self, length):
        """
        Generate a random string of given length
        """
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(length))

    def header(self, s):
        if not s:
            return None

        s_no_newlines = ' '.join(s.splitlines())
        return Header(s_no_newlines, 'utf-8')

    def template_params(self, paramsStr):
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

    def transient_attachments(self, transientFile, transientFileContent, transientFileCID):
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

    def handle_html(self, htmlBody):
        """
        Extract all data-url content from within the html and return as separate attachments.
        Due to security implications, we support only images here
        We might not have Beautiful Soup so just do regex search
        """
        attachments = []
        cleanBody = ''
        lastIndex = 0
        for i, m in enumerate(
                re.finditer(r'<img.+?src=\"(data:(image\/.+?);base64,([a-zA-Z0-9+/=\r\n]+?))\"', htmlBody, re.I)):
            maintype, subtype = m.group(2).split('/', 1)
            att = {
                'maintype': maintype,
                'subtype': subtype,
                'data': base64.b64decode(m.group(3)),
                'name': 'image%d.%s' % (i, subtype)
            }
            att['cid'] = '%s@%s.%s' % (att['name'], self.randomword(8), self.randomword(8))
            attachments.append(att)
            cleanBody += htmlBody[lastIndex:m.start(1)] + 'cid:' + att['cid']
            lastIndex = m.end() - 1

        cleanBody += htmlBody[lastIndex:]
        return cleanBody, attachments

    def collect_inline_attachments(self, attach_cids):
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

    def collect_manual_attachments(self):
        attachments = []
        for attachment in demisto.getArg('manualAttachObj') or []:
            res = demisto.getFilePath(os.path.basename(attachment['RealFileName']))

            path = res.get('path', '')
            content_type, encoding = mimetypes.guess_type(path)
            if content_type is None or encoding is not None:
                content_type = 'application/octet-stream'
            maintype, subtype = content_type.split('/', 1)

            if maintype == 'text':
                with open(path) as fp:
                    data = fp.read()
            else:
                with open(path, 'rb') as fp:  # type: ignore
                    data = fp.read()
            attachments.append({
                'name': attachment['FileName'],
                'maintype': maintype,
                'subtype': subtype,
                'data': data,
                'cid': None
            })

        return attachments

    def collect_attachments(self, entry_ids, file_names):
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

    def attachment_handler(self, message, attachments):
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

            elif att['maintype'] == 'application':
                msg_app = MIMEApplication(att['data'], att['subtype'])
                if att['cid'] is not None:
                    msg_app.add_header('Content-Disposition', 'inline', filename=att['name'])
                    msg_app.add_header('Content-ID', '<' + att['name'] + '>')
                else:
                    msg_app.add_header('Content-Disposition', 'attachment', filename=att['name'])
                message.attach(msg_app)

            else:
                msg_base = MIMEBase(att['maintype'], att['subtype'])
                msg_base.set_payload(att['data'])
                if att['cid'] is not None:
                    msg_base.add_header('Content-Disposition', 'inline', filename=att['name'])
                    msg_base.add_header('Content-ID', '<' + att['name'] + '>')

                else:
                    msg_base.add_header('Content-Disposition', 'attachment', filename=att['name'])
                message.attach(msg_base)

    def send_mail(self, emailto, emailfrom, cc, bcc, subject, body, htmlBody, entry_ids, replyTo, file_names,
                  attach_cid, manualAttachObj,
                  transientFile, transientFileContent, transientFileCID, additional_headers, templateParams):

        templateParams = self.template_params(templateParams)
        if templateParams is not None:
            if body is not None:
                body = body.format(**templateParams)

            if htmlBody is not None:
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

        message['to'] = emailto
        message['cc'] = cc
        message['bcc'] = bcc
        message['from'] = emailfrom
        message['subject'] = subject
        message['reply-to'] = replyTo

        # # The following headers are being used for the reply-mail command.
        # if inReplyTo:
        #     message['In-Reply-To'] = header(' '.join(inReplyTo))
        # if references:
        #     message['References'] = header(' '.join(references))

        # if there are any attachments to the mail or both body and htmlBody were given
        if entry_ids or file_names or attach_cid or manualAttachObj or (body and htmlBody):
            msg = MIMEText(body, 'plain', 'utf-8')
            attach_body_to.attach(msg)  # type: ignore
            htmlAttachments = []  # type: list
            inlineAttachments = []  # type: list

            if htmlBody:
                # htmlBody, htmlAttachments = handle_html(htmlBody)
                htmlBody, htmlAttachments = self.handle_html(htmlBody)
                msg = MIMEText(htmlBody, 'html', 'utf-8')
                attach_body_to.attach(msg)  # type: ignore
                if attach_cid:
                    inlineAttachments = self.collect_inline_attachments(attach_cid)

            else:
                # if not html body, cannot attach cids in message
                transientFileCID = None

            attachments = self.collect_attachments(entry_ids, file_names)
            manual_attachments = self.collect_manual_attachments()
            transientAttachments = self.transient_attachments(transientFile, transientFileContent, transientFileCID)

            attachments = attachments + htmlAttachments + transientAttachments + inlineAttachments + manual_attachments
            self.attachment_handler(message, attachments)

        if additional_headers is not None and len(additional_headers) > 0:
            for h in additional_headers:
                header_name, header_value = h.split('=', 1)
                message[header_name] = self.header(header_value)
        encoded_message = base64.urlsafe_b64encode(message.as_bytes())
        command_args = {'raw': encoded_message.decode()}

        service = self.get_service('gmail', 'v1')
        result = (service.users().messages().send(userId=emailfrom, body=command_args).execute())
        return result

    def generate_auth_link(self) -> Tuple[str, str]:
        """Generate an auth2 link.

        Returns:
            Tuple[str, str] -- Return the link and the challenge used for generating the link.
        """
        verifier = secrets.token_hex(64)
        sha = hashlib.sha256()
        sha.update(bytes(verifier, 'us-ascii'))
        challenge = str(base64.urlsafe_b64encode(sha.digest()), 'us-ascii').rstrip('=')
        link = f"https://accounts.google.com/o/oauth2/v2/auth?scope=https://www.googleapis.com/auth/gmail.compose%20https://www.googleapis.com/auth/gmail.send%20https://www.googleapis.com/auth/gmail.readonly&response_type=code&redirect_uri=urn:ietf:wg:oauth:2.0:oob&client_id={CLIENT_ID}&code_challenge={challenge}&code_challenge_method=S256"  # noqa: E501
        integration_context = demisto.getIntegrationContext() or {}
        integration_context['verifier'] = verifier
        demisto.setIntegrationContext(integration_context)
        return link, challenge


def test_module(client):
    demisto.results('Test is not supported. Please use the following command: !gmail-auth-test.')


def send_mail_command(client):
    args = demisto.args()
    emailto = args.get('to')
    body = args.get('body')
    subject = args.get('subject')
    entry_ids = argToList(args.get('attachIDs'))
    cc = args.get('cc')
    bcc = args.get('bcc')
    htmlBody = args.get('htmlBody')
    replyTo = args.get('replyTo')
    file_names = argToList(args.get('attachNames'))
    attchCID = argToList(args.get('attachCIDs'))
    manualAttachObj = argToList(args.get('manualAttachObj'))  # when send-mail called from within XSOAR (like reports)
    transientFile = argToList(args.get('transientFile'))
    transientFileContent = argToList(args.get('transientFileContent'))
    transientFileCID = argToList(args.get('transientFileCID'))
    additional_headers = argToList(args.get('additionalHeader'))
    template_param = args.get('templateParams')

    result = client.send_mail(emailto, EMAIL, cc, bcc, subject, body, htmlBody, entry_ids,
                              replyTo, file_names, attchCID, manualAttachObj, transientFile, transientFileContent,
                              transientFileCID, additional_headers, template_param)
    return client.sent_mail_to_entry('Email sent:', [result], emailto, EMAIL, cc, bcc, htmlBody, body, subject)


'''FETCH INCIDENTS'''


def fetch_incidents(client: Client):
    user_key = 'me'
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
        last_fetch, _ = parse_date_range(date_range=FETCH_TIME, utc=True, to_timestamp=False)
        last_fetch = str(last_fetch.isoformat(timespec='seconds')) + 'Z'
    # use replace(tzinfo) to  make the datetime aware of the timezone as all other dates we use are aware
    last_fetch = client.parse_date_isoformat_server(last_fetch)
    if next_last_fetch:
        next_last_fetch = client.parse_date_isoformat_server(next_last_fetch)
    else:
        next_last_fetch = last_fetch + timedelta(seconds=1)
    service = client.get_service('gmail', 'v1')

    # use seconds for the filter (note that it is inclusive)
    # see: https://developers.google.com/gmail/api/guides/filtering
    query += f' after:{int(last_fetch.timestamp())}'
    max_results = MAX_FETCH
    if MAX_FETCH > 200:
        max_results = 200
    LOG(f'GMAIL: fetch parameters: user: {user_key} query={query}'
        f' fetch time: {last_fetch} page_token: {page_token} max results: {max_results}')
    result = service.users().messages().list(
        userId=user_key, maxResults=max_results, pageToken=page_token, q=query).execute()

    incidents = []
    # so far, so good
    LOG('GMAIL: possible new incidents are %s' % (result, ))
    for msg in result.get('messages', []):
        msg_id = msg['id']
        if msg_id in ignore_ids:
            demisto.info(f'Ignoring msg id: {msg_id} as it is in the ignore list')
            ignore_list_used = True
            continue
        msg_result = service.users().messages().get(
            id=msg_id, userId=user_key).execute()
        incident, occurred, is_valid_date = client.mail_to_incident(msg_result, service, user_key)
        if not is_valid_date:  # if  we can't trust the date store the msg id in the ignore list
            demisto.info(f'appending to ignore list msg id: {msg_id}. name: {incident.get("name")}')
            ignore_list_used = True
            ignore_ids.append(msg_id)
        # update last run only if we trust the occurred timestamp
        if is_valid_date and occurred > next_last_fetch:
            next_last_fetch = occurred + timedelta(seconds=1)

        # avoid duplication due to weak time query
        if (not is_valid_date) or (occurred >= last_fetch):
            incidents.append(incident)
        else:
            demisto.info(f'skipped incident with lower date: {occurred} than fetch: {last_fetch} name: {incident.get("name")}')

    demisto.info('extract {} incidents'.format(len(incidents)))
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
        'gmt_time': client.get_date_isoformat_server(last_fetch),
        'next_gmt_time': client.get_date_isoformat_server(next_last_fetch),
        'page_token': next_page_token,
        'ignore_ids': ignore_ids,
        'ignore_list_used': ignore_list_used,
    })
    return incidents


def auth_link_command(client: Client):
    link, challange = client.generate_auth_link()
    markdown = f"""
## Gmail Auth Link
Please follow the following **[link]({link})**.

After Completing the authentication process, copy the received code
to the **Auth Code** configuration parameter of the integration instance.
Save the integration instance and then run *!gmail-auth-test* to test that
the authentication is properly set.
    """
    return {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': markdown,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': markdown,
    }


def auth_test_command(client):
    client.search('me', '', '', '', '', '', '', '', '',
                  '', [], 10, '', False, False)
    return "Authentication test completed successfully."


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    global EMAIL

    command = demisto.command()
    client = Client()
    demisto.info(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        'send-mail': send_mail_command,
        'fetch-incidents': fetch_incidents,
        'gmail-auth-link': auth_link_command,
        'gmail-auth-test': auth_test_command,
    }

    try:
        if command == 'fetch-incidents':
            demisto.incidents(fetch_incidents(client))
            sys.exit(0)
        if command in commands:
            demisto.results(commands[command](client))
        # Log exceptions
    except Exception as e:
        import traceback
        return_error('GMAIL: {}'.format(str(e)), traceback.format_exc())


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
