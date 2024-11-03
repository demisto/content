import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import contextlib
from typing import NoReturn

from email.message import Message
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from smtplib import SMTP, SMTP_SSL
from smtplib import SMTPRecipientsRefused
import base64
import json
import mimetypes
from email import encoders
import re
import random
import string
import smtplib
import traceback
import sys
from itertools import zip_longest

SERVER: Optional[smtplib.SMTP] = None
UTF_8 = 'utf-8'


def randomword(length):
    """
    Generate a random string of given length
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


def return_error_mail_sender(data) -> NoReturn:  # type: ignore
    """
    Return error as result and exit
    """
    if SERVER:
        # quite may throw if the connection was closed already
        with contextlib.suppress(Exception):
            SERVER.quit()
    return_error(data)


def guess_type(filename):
    """
    Return the maintype and subtype guessed based on the extension
    """
    content_type, encoding = mimetypes.guess_type(filename)
    if content_type is None or encoding is not None:
        # No guess could be made, or the file is encoded (compressed), so
        # use a generic bag-of-bits type.
        content_type = 'application/octet-stream'
    return content_type.split('/', 1)


def handle_file(msg, filename, maintype, subtype, cid, data):
    """
    Add the attachment to the message and add the relevant header
    """
    if maintype in ('text', 'message'):
        # UTF-8 is a pretty safe bet
        att = MIMEText(data, subtype, UTF_8)  # type: MIMEBase
    elif maintype == 'image':
        att = MIMEImage(data, subtype)
    elif maintype == 'audio':
        att = MIMEAudio(data, subtype)
    else:
        att = MIMEBase(maintype, subtype)
        att.set_payload(data)
        # Encode the payload using Base64
        encoders.encode_base64(att)
    # Set the filename parameter
    if cid:
        att.add_header('Content-Disposition', 'inline', filename=filename)
        att.add_header('Content-ID', '<' + cid + '>')
    else:
        att.add_header('Content-Disposition', 'attachment', filename=filename)
    msg.attach(att)


def handle_html(html_body):
    """
    Extract all data-url content from within the html and return as separate attachments.
    Due to security implications, we support only images here
    We might not have Beautiful Soup so just do regex search
    """
    attachments = []
    clean_body = ''
    last_index = 0
    for i, m in enumerate(
            re.finditer(r'<img.+?src=\"(data:(image/.+?);base64,([a-zA-Z0-9+/=\r\n]+?))\"', html_body, re.I)):
        maintype, subtype = m.group(2).split('/', 1)
        name = 'image%d.%s' % (i, subtype)
        att = {
            'maintype': maintype,
            'subtype': subtype,
            'data': base64.b64decode(m.group(3)),
            'name': name,
            'cid': '%r@%r.%r' % (name, randomword(8), randomword(8))
        }
        attachments.append(att)
        clean_body += html_body[last_index:m.start(1)] + 'cid:' + att['cid']
        last_index = m.end() - 1
    clean_body += html_body[last_index:]
    return clean_body, attachments


def collect_manual_attachments():
    attachments = []
    manual_attach_obj: List[Dict[Any, Any]] = demisto.getArg('manualAttachObj') or []
    for attachment in manual_attach_obj:
        res = demisto.getFilePath(os.path.basename(attachment['RealFileName']))

        path = res['path']
        maintype, subtype = guess_type(attachment['FileName'])
        data: str | bytes  # Because of mypy errors.
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
            'cid': ''
        })

    return attachments


def collect_attachments():
    """
    Collect all attachments into a list with all data
    """
    attachments = []
    attach_ids = argToList(demisto.getArg('attachIDs'))
    attach_names = argToList(demisto.getArg('attachNames'))
    attach_cids = argToList(demisto.getArg('attachCIDs'))
    for i, aid in enumerate(attach_ids):
        try:
            file_res = demisto.getFilePath(aid)

            path = file_res['path']
            if len(attach_names) > i and attach_names[i]:
                filename = attach_names[i]
            else:
                filename = file_res['name']
            if len(attach_cids) > i and attach_cids[i]:
                cid = attach_cids[i]
            else:
                cid = ''
            maintype, subtype = guess_type(filename)
            data: str | bytes  # Because of mypy errors.
            if maintype == 'text':
                with open(path) as fp:
                    data = fp.read()
            else:
                with open(path, 'rb') as fp:
                    data = fp.read()
            attachments.append({
                'name': filename,
                'maintype': maintype,
                'subtype': subtype,
                'data': data,
                'cid': cid
            })
        except Exception as exc:
            demisto.error(f"Invalid entry {aid} with exception: {exc}")
            return_error_mail_sender('Entry %s is not valid or is not a file entry' % aid)

    # handle transient files
    args = demisto.args()
    f_names = args.get('transientFile', [])
    f_names = f_names if isinstance(f_names, (list, tuple)) else f_names.split(',')
    f_contents = args.get('transientFileContent', [])
    f_contents = f_contents if isinstance(f_contents, (list, tuple)) else f_contents.split(',')
    f_cids = args.get('transientFileCID', [])
    f_cids = f_cids if isinstance(f_cids, (list, tuple)) else f_cids.split(',')

    for name, data, cid in zip_longest(f_names, f_contents, f_cids):
        if name is None or data is None:
            break
        maintype, subtype = guess_type(name)
        attachments.append({
            'name': name,
            'maintype': maintype,
            'subtype': subtype,
            'data': data,
            'cid': cid
        })

    return attachments


def parse_params(params):
    actual_params = {}
    # Build a simple key/value
    for p in params:
        if params[p].get('value'):
            actual_params[p] = params[p]['value']
        elif params[p].get('key'):
            actual_params[p] = demisto.dt(demisto.context(), params[p]['key'])
    return actual_params


def parse_template_params():
    """
    Translate the template params if they exist from the context
    """
    params_str = demisto.getArg('templateParams')
    if params_str:
        if isinstance(params_str, dict):
            return parse_params(params_str)
        else:
            try:
                return parse_params(json.loads(params_str))
            except (ValueError, TypeError) as e:
                return_error_mail_sender('Unable to parse templateParams: %s' % (str(e)))


def header(s):
    if not s:
        return None
    s_no_newlines = ' '.join(s.splitlines())
    return Header(s_no_newlines)


def create_msg():
    """
    Will get args from demisto object
    Return: a string representation of the message, to, cc, bcc
    """
    # Collect all parameters
    to = argToList(demisto.getArg('to'))
    cc = argToList(demisto.getArg('cc'))
    bcc = argToList(demisto.getArg('bcc'))
    additional_header = argToList(demisto.getArg('additionalHeader'))
    subject = demisto.getArg('subject') or ''
    body = demisto.getArg('body') or ''
    html_body = demisto.getArg('htmlBody') or ''
    reply_to = demisto.getArg('replyTo')
    template_params = parse_template_params()
    if template_params:
        body = body.format(**template_params)
        html_body = html_body.format(**template_params)

    # Basic validation - we allow pretty much everything, but you have to have at least a recipient
    # We allow messages without subject and also without body
    if not to and not cc and not bcc:
        return_error_mail_sender('You must have at least one recipient')

    attachments = collect_attachments()
    attachments.extend(collect_manual_attachments())

    # Let's see what type of message we are talking about
    if not html_body:
        # This is a simple text message - we cannot have CIDs here
        if len(attachments) > 0:
            # This is multipart - default is mixed
            msg: Message = MIMEMultipart()
            msg.preamble = 'The message is only available on a MIME-aware mail reader.\n'
            msg.attach(MIMEText(body, 'plain', UTF_8))
            for att in attachments:
                handle_file(msg, att['name'], att['maintype'], att['subtype'], None, att['data'])
        else:
            # Just text, how boring
            msg = MIMEText(body, 'plain', UTF_8)
    else:
        html_body, html_attachments = handle_html(html_body)
        attachments += html_attachments
        if len(attachments) > 0:
            msg = MIMEMultipart()
            msg.preamble = 'The message is only available on a MIME-aware mail reader.\n'
            if body:
                alt = MIMEMultipart('alternative')
                alt.attach(MIMEText(body, 'plain', UTF_8))
                alt.attach(MIMEText(html_body, 'html', UTF_8))
                msg.attach(alt)
            else:
                msg.attach(MIMEText(html_body, 'html', UTF_8))
            for att in attachments:
                handle_file(msg, att['name'], att['maintype'], att['subtype'], att['cid'], att['data'])
        else:
            if body:
                msg = MIMEMultipart('alternative')
                msg.preamble = 'The message is only available on a MIME-aware mail reader.\n'
                msg.attach(MIMEText(body, 'plain', UTF_8))
                msg.attach(MIMEText(html_body, 'html', UTF_8))
            else:
                msg = MIMEText(html_body, 'html', UTF_8)

    # Add the relevant headers to the most outer message
    msg['Subject'] = header(subject)
    msg['From'] = header(demisto.getParam('from'))
    if reply_to:
        msg['Reply-To'] = header(reply_to)
    if to:
        msg['To'] = header(','.join(to))
    if cc:
        msg['CC'] = header(','.join(cc))
    if additional_header:
        for h in additional_header:
            header_name_and_value = h.split('=', 1)
            msg[header_name_and_value[0]] = header(header_name_and_value[1])
    # Notice we should not add BCC header since Python2 does not filter it
    return body, html_body, msg.as_string(), to, cc, bcc


def get_user_pass():
    credentials: Dict[str, Any] = demisto.getParam('credentials')  # noqa
    if credentials:
        return (str(credentials.get('identifier', '')),
                str(credentials.get('password', '')))
    return None, None


def swap_stderr(new_stderr):
    """
    swap value of stderr if given, return old value.
    smtplib uses `sys.stderr` directly in newer versions, so use that instead

    """
    if hasattr(smtplib, 'stderr'):
        module = smtplib
    else:
        module = sys  # type: ignore
    old_stderr = module.stderr
    if new_stderr:
        module.stderr = new_stderr
    return old_stderr


def main():
    # Following methods raise exceptions so no need to check for return codes
    # But we do need to catch them
    global SERVER
    from_email = demisto.getParam('from')
    fqdn = demisto.params().get('fqdn')
    fqdn = (fqdn and fqdn.strip()) or None
    tls = demisto.getParam('tls')
    stderr_org = None
    try:
        if demisto.command() == 'test-module':
            stderr_org = swap_stderr(LOG)
            smtplib.SMTP.debuglevel = 1

        # TODO - support for non-valid certs
        if tls == 'SSL/TLS':
            SERVER = SMTP_SSL(demisto.getParam('host'), int(demisto.params().get('port', 0)), local_hostname=fqdn)
        else:
            SERVER = SMTP(demisto.getParam('host'),     # type: ignore[assignment]
                          int(demisto.params().get('port', 0)), local_hostname=fqdn)

        SERVER.ehlo()  # type: ignore
        # For BC purposes where TLS was a checkbox (no value only true or false) if TLS=True or TLS='STARTTLS' we enter
        # this condition, otherwise it means TLS is not configured (TLS=False) or is set to 'SSL/TLS' or 'None'.
        if tls is True or tls == 'STARTTLS' or str(tls).lower() == 'true':
            SERVER.starttls()  # type: ignore
        user, password = get_user_pass()
        if user:
            SERVER.login(user, password)  # type: ignore[union-attr]
    except Exception as e:
        # also reset at the bottom finally
        swap_stderr(stderr_org)  # type: ignore[union-attr]
        smtplib.SMTP.debuglevel = 0
        demisto.error(f'Failed test: {e}\nStack trace: {traceback.format_exc()}')
        return_error_mail_sender(e)
        return  # so mypy knows that we don't continue after this
    # -- COMMANDS --
    try:
        if demisto.command() == 'test-module':
            msg = MIMEText('This is a test mail from Demisto\nRegards\nDBot')
            msg['Subject'] = 'Test mail from Demisto'
            msg['From'] = from_email
            msg['To'] = from_email
            SERVER.sendmail(from_email, [from_email], msg.as_string())  # type: ignore[union-attr]
            SERVER.quit()  # type: ignore[union-attr]
            demisto.results('ok')
        elif demisto.command() == 'send-mail':
            raw_message = demisto.getArg('raw_message')
            if raw_message:
                to = argToList(demisto.getArg('to'))
                cc = argToList(demisto.getArg('cc'))
                bcc = argToList(demisto.getArg('bcc'))
                str_msg = raw_message
                html_body = raw_message
            else:
                (_, html_body, str_msg, to, cc, bcc) = create_msg()

            SERVER.sendmail(from_email, to + cc + bcc, str_msg)  # type: ignore[union-attr]
            SERVER.quit()
            render_body = argToBoolean(demisto.getArg('renderBody') or False)
            results = [CommandResults(entry_type=EntryType.NOTE, raw_response='Mail sent successfully')]
            if render_body:
                results.append(CommandResults(
                    entry_type=EntryType.NOTE,
                    content_format=EntryFormat.HTML,
                    raw_response=html_body,
                ))

            return_results(results)
        else:
            return_error_mail_sender('Command not recognized')
    except SMTPRecipientsRefused as e:
        error_msg = ''.join(f'{val}\n' for key, val in e.recipients.items())
        return_error_mail_sender(f"Encountered error: {error_msg}")
    except Exception as e:
        return_error_mail_sender(e)
    finally:
        swap_stderr(stderr_org)  # type: ignore[union-attr]
        smtplib.SMTP.debuglevel = 0


# python2 uses __builtin__ python3 uses builtins
if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
