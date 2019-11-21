import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import re
import json
import base64
from datetime import datetime, timedelta
import httplib2
import sys
from html.parser import HTMLParser
from html.entities import name2codepoint
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
from oauth2client.client import AccessTokenCredentials
import itertools as it
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import urllib.parse

''' GLOBAL VARS '''
params = demisto.params()
EMAIL = params.get('email', '')
PROXY = params.get('proxy')
DISABLE_SSL = params.get('insecure', False)
FETCH_TIME = params.get('fetch_time', '1 days')
OPROXY_URL = 'https://us-central1-oproxy-dev.cloudfunctions.net'  # disable-secrets-detection
TOKEN_RETRIEVAL_URL = f'{OPROXY_URL}/google-oauth2_ProvideGoogleTokenFunction'  # disable-secrets-detection
ENC_KEY = params.get('enc_key')
REFRESH_TOKEN = params.get('token')
REG_ID = params.get('registration_id')
TIME_REGEX = re.compile(r'^([\w,\d: ]*) (([+-]{1})(\d{2}):?(\d{2}))?[\s\w\(\)]*$')


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
        proxies = handle_proxy()
        https_proxy = proxies['https']
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
        if PROXY or DISABLE_SSL:
            http_client = credentials.authorize(self.get_http_client_with_proxy())
            return discovery.build(serviceName, version, http=http_client)
        return discovery.build(serviceName, version, credentials=credentials)

    def get_access_token(self):
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        body = json.dumps({'app_name': 'google',
                          'registration_id': REG_ID,
                           'encrypted_token': self.get_encrypted(REFRESH_TOKEN, ENC_KEY)})

        h = httplib2.Http(disable_ssl_certificate_validation=not DISABLE_SSL)
        dbot_response, content = h.request(TOKEN_RETRIEVAL_URL, "POST", body, {'Accept': 'application/json'})

        if dbot_response.status not in {200, 201}:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    dbot_response.status, dbot_response.reason, content))

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

        demisto.setIntegrationContext({
            'access_token': access_token,
            'valid_until': time_now + expires_in
        })

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

    def localization_extract(self, time_from_mail):
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

    def create_base_time(self, internal_date_timestamp, header_date):
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

        utc, delta_in_seconds = self.localization_extract(header_date)
        base_time = datetime.utcfromtimestamp(internal_date_timestamp) + \
            timedelta(seconds=delta_in_seconds)
        base_time = str(base_time.strftime('%a, %d %b %Y %H:%M:%S')) + " " + utc
        return base_time

    def get_email_context(self, email_data, mailbox):
        context_headers = email_data.get('payload', {}).get('headers', [])
        context_headers = [{'Name': v['name'], 'Value':v['value']}
                           for v in context_headers]
        headers = dict([(h['Name'].lower(), h['Value']) for h in context_headers])
        body = demisto.get(email_data, 'payload.body.data')
        body = body.encode('ascii') if body is not None else ''
        parsed_body = base64.urlsafe_b64decode(body)
        if email_data.get('internalDate') is not None:
            base_time = self.create_base_time(email_data.get('internalDate'), str(headers.get('date', '')))

        else:
            # in case no internalDate field exists will revert to extracting the date from the email payload itself
            # Note: this should not happen in any command other than other than gmail-move-mail which doesn't return the
            # email payload nor internalDate
            demisto.info("No InternalDate timestamp found - getting Date from mail payload - msg ID:" + str(email_data['id']))
            base_time = str(headers.get('date', ''))

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

        return context_gmail, headers, context_email

    def move_to_gmt(self, t):
        # there is only one time refernce is the string
        base_time, _, sign, hours, minutes = TIME_REGEX.findall(t)[0]
        if all([sign, hours, minutes]):
            seconds = -1 * (int(sign + hours) * 3600 + int(sign + minutes) * 60)
            parsed_time = datetime.strptime(
                base_time, '%a, %d %b %Y %H:%M:%S') + timedelta(seconds=seconds)
            return parsed_time.isoformat() + 'Z'
        else:
            return datetime.strptime(base_time, '%a, %d %b %Y %H:%M:%S').isoformat() + 'Z'

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

    def mail_to_incident(self, msg, service, user_key):
        parsed_msg, headers, _ = self.get_email_context(msg, user_key)

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
        gmt_time = self.move_to_gmt(parsed_msg['Date'])

        incident = {
            'type': 'Gmail',
            'name': parsed_msg['Subject'],
            'details': parsed_msg['Body'],
            'labels': self.create_incident_labels(parsed_msg, headers),
            'occurred': gmt_time,
            'attachment': file_names,
            'rawJSON': json.dumps(parsed_msg),
        }
        return incident

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
                'Mailbox': to
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

    def get_encrypted(self, content, key):
        """

        Args:
            content (str): content to encrypt. For a request to Demistobot for a new access token, content should be
                the tenant id
            key (str): encryption key from Demistobot

        Returns:
            encrypted timestamp:content
        """
        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """

            Args:
                enc_key (str):
                string (str):

            Returns:
                bytes:
            """
            # String to bytes
            enc_key = base64.b64decode(enc_key)
            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)
        now = self.epoch_seconds()
        encrypted = encrypt(str(now) + ':' + content, key).decode('utf-8')
        return encrypted

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

            else:
                msg_base = MIMEBase(att['maintype'], att['subtype'])
                msg_base.set_payload(att['data'])
                if att['cid'] is not None:
                    msg_base.add_header('Content-Disposition', 'inline', filename=att['name'])
                    msg_base.add_header('Content-ID', '<' + att['name'] + '>')

                else:
                    msg_base.add_header('Content-Disposition', 'attachment', filename=att['name'])
                message.attach(msg_base)

    def send_mail(self, emailto, emailfrom, subject, body, entry_ids, cc, bcc, htmlBody, replyTo, file_names, attach_cid,
                  transientFile, transientFileContent, transientFileCID, additional_headers, templateParams):
        message = MIMEMultipart()
        message['to'] = emailto
        message['cc'] = cc
        message['bcc'] = bcc
        message['from'] = emailfrom
        message['subject'] = subject
        message['reply-to'] = replyTo

        templateParams = self.template_params(templateParams)
        if templateParams is not None:
            if body is not None:
                body = body.format(**templateParams)

            if htmlBody is not None:
                htmlBody = htmlBody.format(**templateParams)

        if additional_headers is not None and len(additional_headers) > 0:
            for h in additional_headers:
                header_name_and_value = h.split('=')
                message[header_name_and_value[0]] = self.header(header_name_and_value[1])

        msg = MIMEText(body, 'plain', 'utf-8')
        message.attach(msg)
        htmlAttachments = []  # type: list
        inlineAttachments = []  # type: list

        if htmlBody is not None:
            htmlBody, htmlAttachments = self.handle_html(htmlBody)
            msg = MIMEText(htmlBody, 'html', 'utf-8')
            message.attach(msg)
            if attach_cid is not None and len(attach_cid) > 0:
                inlineAttachments = self.collect_inline_attachments(attach_cid)

        else:
            # if not html body, cannot attach cids in message
            transientFileCID = None
        attachments = self.collect_attachments(entry_ids, file_names)
        manual_attachments = self.collect_manual_attachments()
        transientAttachments = self.transient_attachments(transientFile, transientFileContent, transientFileCID)

        attachments = attachments + htmlAttachments + transientAttachments + inlineAttachments + manual_attachments
        self.attachment_handler(message, attachments)

        encoded_message = base64.urlsafe_b64encode(message.as_bytes())
        command_args = {'raw': encoded_message.decode()}

        service = self.get_service('gmail', 'v1')
        result = (service.users().messages().send(userId=emailfrom, body=command_args).execute())
        return result


def test_module(client):
    client.search('me', '', '', '', '', '', '', '', '',
                  '', [], 10, '', False, False)
    demisto.results('ok')


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
    transientFile = argToList(args.get('transientFile'))
    transientFileContent = argToList(args.get('transientFileContent'))
    transientFileCID = argToList(args.get('transientFileCID'))
    additional_headers = argToList(args.get('additionalHeader'))
    template_param = args.get('templateParams')

    result = client.send_mail(emailto, EMAIL, subject, body, entry_ids, cc, bcc, htmlBody,
                              replyTo, file_names, attchCID, transientFile, transientFileContent,
                              transientFileCID, additional_headers, template_param)
    return client.sent_mail_to_entry('Email sent:', [result], emailto, EMAIL, cc, bcc, htmlBody, body, subject)


'''FETCH INCIDENTS'''


def fetch_incidents(client):
    user_key = 'me'
    query = ''
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('gmt_time')
    # handle first time fetch - gets current GMT time -1 day
    if last_fetch is None:
        last_fetch, _ = parse_date_range(date_range=FETCH_TIME, utc=True, to_timestamp=False)
        last_fetch = str(last_fetch.isoformat()).split('.')[0] + 'Z'

    last_fetch = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ')
    current_fetch = last_fetch
    service = client.get_service('gmail', 'v1')

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
        incident = client.mail_to_incident(msg_result, service, user_key)
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


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    global EMAIL

    command = demisto.command()
    client = Client()
    demisto.info(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        f'send-mail': send_mail_command,
        f'fetch-incidents': fetch_incidents,
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
        if command == 'fetch-incidents':
            LOG(traceback.format_exc())
            LOG.print_log()
            raise

        else:
            return_error('GMAIL: {}'.format(str(e)), traceback.format_exc())


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
