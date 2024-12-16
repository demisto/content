import demistomock as demisto

from CommonServerPython import *
from CommonServerUserPython import *

import poplib
import base64
import quopri
from email.parser import Parser
from html.entities import name2codepoint
from html.parser import HTMLParser

''' GLOBALS/PARAMS '''
SERVER = demisto.params().get('server', '')
EMAIL = demisto.params().get('email', '')

PORT = int(demisto.params().get('port', '995'))
SSL = demisto.params().get('ssl')
FETCH_TIME = demisto.params().get('fetch_time', '7 days')

# pop3 server connection object.
pop3_server_conn = None  # type: ignore

TIME_REGEX = re.compile(r'^([\w,\d: ]*) (([+-]{1})(\d{2}):?(\d{2}))?[\s\w\(\)]*$')
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def connect_pop3_server():
    global pop3_server_conn

    if pop3_server_conn is None:
        if SSL:
            pop3_server_conn = poplib.POP3_SSL(SERVER, PORT)  # type: ignore
        else:
            pop3_server_conn = poplib.POP3(SERVER, PORT)  # type: ignore
        password = demisto.params().get('credentials_password', {}).get('password') or demisto.params().get('password')
        if not password:
            raise DemistoException('Password must be provided')

        pop3_server_conn.getwelcome()  # type: ignore
        pop3_server_conn.user(EMAIL)  # type: ignore
        pop3_server_conn.pass_(password)  # type: ignore


def close_pop3_server_connection():
    global pop3_server_conn
    if pop3_server_conn is not None:
        pop3_server_conn.quit()
        pop3_server_conn = None


def get_user_emails():
    _, mails_list, _ = pop3_server_conn.list()  # type: ignore

    mails = []

    for mail in mails_list:
        try:
            index = int(mail.split(b' ')[0])
            (resp_message, lines, octets) = pop3_server_conn.retr(index)  # type: ignore
            msg_content = str(b'\r\n'.join(lines), errors='ignore')
            msg = Parser().parsestr(msg_content)
            msg['index'] = index  # type: ignore[assignment]
            mails.append(msg)
        except Exception:
            demisto.error("Failed to get email with index " + str(index) + 'from the server.')
            raise

    return mails


def get_attachment_name(headers):
    name = headers.get('content-description', '')

    if re.match(r'^.+\..{3,5}$', name):
        return name

    content_disposition = headers.get('content-disposition', '')

    if content_disposition:
        m = re.search('filename="(.*?)"', content_disposition)
        if m:
            name = m.group(1)

    if re.match('^.+\..{3,5}$', name):
        return name

    extension = re.match(r'.*[\\/]([\d\w]{2,4}).*', headers.get('content-type', 'txt')).group(1)  # type: ignore

    return name + '.' + extension


def parse_base64(text):
    if re.match("^=?.*?=$", text):
        res = re.search('=\?.*?\?[A-Z]{1}\?(.*?)\?=', text, re.IGNORECASE)
        if res:
            res = res.group(1)  # type: ignore
            return base64.b64decode(res)  # type: ignore
    return text


class TextExtractHtmlParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self._texts = []  # type: list
        self._ignore = False

    def handle_starttag(self, tag, _):
        if tag in ('p', 'br') and not self._ignore:
            self._texts.append('\n')
        elif tag in ('script', 'style'):
            self._ignore = True

    def handle_startendtag(self, tag, _):
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


def html_to_text(html):
    parser = TextExtractHtmlParser()
    parser.feed(html)
    parser.close()
    return parser.get_text()


def get_email_context(email_data):
    context_headers = email_data._headers
    context_headers = [{'Name': v[0], 'Value': v[1]}
                       for v in context_headers]
    headers = {h['Name'].lower(): h['Value'] for h in context_headers}

    context = {
        'Mailbox': EMAIL,
        'ID': email_data.get('Message-ID', 'None'),
        'Labels': ', '.join(email_data.get('labelIds', '')),
        'Headers': context_headers,
        'Format': headers.get('content-type', '').split(';')[0],
        'Subject': parse_base64(headers.get('subject')),
        'Body': email_data._payload,
        'From': headers.get('from'),
        'To': headers.get('to'),
        'Cc': headers.get('cc', []),
        'Bcc': headers.get('bcc', []),
        'Date': headers.get('date', ''),
        'Html': None,
    }

    if 'text/html' in context['Format']:
        context['Html'] = context['Body']
        context['Body'] = html_to_text(context['Body'])

    if 'multipart' in context['Format']:
        context['Body'], context['Html'], context['Attachments'] = parse_mail_parts(email_data._payload)
        context['Attachment Names'] = ', '.join(
            [attachment['Name'] for attachment in context['Attachments']])

    raw = dict(email_data)
    raw['Body'] = context['Body']
    raw = {key.lower(): value for key, value in raw.items()}
    context['RawData'] = raw
    return context, headers


def parse_mail_parts(parts):
    body = ""
    html = ""

    attachments = []  # type: ignore
    for part in parts:
        context_headers = part._headers
        context_headers = [{'Name': v[0], 'Value': v[1]}
                           for v in context_headers]
        headers = {h['Name'].lower(): h['Value'] for h in context_headers}

        content_type = headers.get('content-type', 'text/plain')

        is_attachment = headers.get('content-disposition', '').startswith('attachment') or headers.get(
            'x-attachment-id') or "image" in content_type

        if 'multipart' in content_type or isinstance(part._payload, list):
            part_body, part_html, part_attachments = parse_mail_parts(part._payload)
            body += part_body
            html += part_html
            attachments.extend(part_attachments)
        elif not is_attachment:
            if headers.get('content-transfer-encoding') == 'base64':
                text = base64.b64decode(part._payload).decode('utf-8', 'replace')
            elif headers.get('content-transfer-encoding') == 'quoted-printable':
                str_utf8 = part._payload.encode().decode('cp1252')
                str_utf8 = str_utf8.encode('utf-8')
                decoded_string = quopri.decodestring(str_utf8)
                text = str(decoded_string, errors='ignore')
            else:
                str_utf8 = part._payload.encode().decode('cp1252')
                str_utf8 = str_utf8.encode('utf-8')
                text = quopri.decodestring(str_utf8)  # type: ignore

            if not isinstance(text, str):
                text = text.decode('unicode-escape')

            if 'text/html' in content_type:
                html += text
            else:
                body += text

        if is_attachment:
            payload = part._payload
            if isinstance(payload, list):
                # indicating that the attachment is eml file.
                message_object = payload[0]
                payload = message_object.as_string()
            attachments.append({
                'ID': headers.get('x-attachment-id', 'None'),
                'Name': get_attachment_name(headers),
                'Data': payload
            })

    return body, html, attachments


def parse_time(t):
    base_time, _, _, _, _ = TIME_REGEX.findall(t)[0]
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
        labels.append({'type': 'Email/Header/' + key, 'value': str(val)})

    return labels


@logger
def mail_to_incident(msg):
    parsed_msg, headers = get_email_context(msg)

    file_names = []
    for attachment in parsed_msg.get('Attachments', []):
        file_data = attachment['Data']
        if not attachment.get('Name', '').endswith('.eml'):
            file_data = base64.urlsafe_b64decode(file_data.encode('ascii'))

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

    raw_data = parsed_msg['RawData']
    raw_data.update({'attachments': file_names})

    return {
        'name': parsed_msg['Subject'],
        'details': parsed_msg['Body'],
        'labels': create_incident_labels(parsed_msg, headers),
        'occurred': parse_time(parsed_msg['Date']),
        'attachment': file_names,
        'rawJSON': json.dumps(raw_data)
    }


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, date_format=DATE_FORMAT)

    last_fetch = datetime.strptime(last_fetch, DATE_FORMAT)
    current_fetch = last_fetch

    incidents = []
    messages = get_user_emails()

    for msg in messages:
        try:
            incident = mail_to_incident(msg)
        except Exception:
            demisto.error("failed to create incident from email, index = {}, subject = {}, date = {}".format(
                msg['index'], msg['subject'], msg['date']))
            raise

        temp_date = datetime.strptime(
            incident['occurred'], DATE_FORMAT)

        # update last run
        if temp_date > last_fetch:
            last_fetch = temp_date + timedelta(seconds=1)

        # avoid duplication due to weak time query
        if temp_date > current_fetch:
            incidents.append(incident)

    demisto.setLastRun({'time': last_fetch.isoformat().split('.')[0] + 'Z'})

    return demisto.incidents(incidents)


def test_module():
    resp_message, _, _ = pop3_server_conn.list()  # type: ignore
    if b"OK" in resp_message:
        demisto.results('ok')


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    try:
        handle_proxy()
        connect_pop3_server()
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
        if demisto.command() == 'fetch-incidents':
            fetch_incidents()
            sys.exit(0)
    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        raise
    finally:
        close_pop3_server_connection()


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
