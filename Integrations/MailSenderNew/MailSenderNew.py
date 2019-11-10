import demistomock as demisto
from CommonServerPython import *
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from email.header import Header
from smtplib import SMTP
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

SERVER = None
UTF_8 = 'utf-8'


def randomword(length):
    """
    Generate a random string of given length
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def return_error_mail_sender(data):
    """
    Return error as result and exit
    """
    if SERVER:
        try:
            SERVER.quit()  # quite may throw if the connection was closed already
        except Exception:
            pass
    return_error(data)


def guess_type(filename):
    """
    Return the maintype and subtype guessed based on the extension
    """
    ctype, encoding = mimetypes.guess_type(filename)
    if ctype is None or encoding is not None:
        # No guess could be made, or the file is encoded (compressed), so
        # use a generic bag-of-bits type.
        ctype = 'application/octet-stream'
    return ctype.split('/', 1)


def handle_file(msg, filename, maintype, subtype, cid, data):
    """
    Add the attachment to the message and add the relevant header
    """
    if maintype == 'text':
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


def handle_html(htmlBody):
    """
    Extract all data-url content from within the html and return as separate attachments.
    Due to security implications, we support only images here
    We might not have Beautiful Soup so just do regex search
    """
    attachments = []
    cleanBody = ''
    lastIndex = 0
    for i, m in enumerate(re.finditer(r'<img.+?src=\"(data:(image\/.+?);base64,([a-zA-Z0-9+/=\r\n]+?))\"', htmlBody, re.I)):
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


def collect_manual_attachments():
    attachments = []
    for attachment in demisto.getArg('manualAttachObj') or []:
        res = demisto.getFilePath(os.path.basename(attachment['RealFileName']))

        path = res['path']
        maintype, subtype = guess_type(attachment['FileName'])
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
    attachIDs = argToList(demisto.getArg('attachIDs'))
    attachNames = argToList(demisto.getArg('attachNames'))
    attachCIDs = argToList(demisto.getArg('attachCIDs'))
    for i, aid in enumerate(attachIDs):
        try:
            fileRes = demisto.getFilePath(aid)

            path = fileRes['path']
            if len(attachNames) > i and attachNames[i]:
                filename = attachNames[i]
            else:
                filename = fileRes['name']
            if len(attachCIDs) > i and attachCIDs[i]:
                cid = attachCIDs[i]
            else:
                cid = ''
            maintype, subtype = guess_type(filename)
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
        except Exception as ex:
            demisto.error("Invalid entry {} with exception: {}".format(aid, ex))
            return_error_mail_sender('Entry %s is not valid or is not a file entry' % (aid))

    # handle transient files
    args = demisto.args()
    f_names = args.get('transientFile', [])
    f_names = f_names if isinstance(f_names, (list, tuple)) else f_names.split(',')
    f_contents = args.get('transientFileContent', [])
    f_contents = f_contents if isinstance(f_contents, (list, tuple)) else f_contents.split(',')
    f_cids = args.get('transientFileCID', [])
    f_cids = f_cids if isinstance(f_cids, (list, tuple)) else f_cids.split(',')

    for name, data, cid in map(None, f_names, f_contents, f_cids):
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


def template_params():
    """
    Translate the template params if they exist from the context
    """
    actualParams = {}
    paramsStr = demisto.getArg('templateParams')
    if paramsStr:
        try:
            params = json.loads(paramsStr)
        except ValueError as e:
            return_error_mail_sender('Unable to parse templateParams: %s' % (str(e)))
        # Build a simple key/value
        for p in params:
            if params[p].get('value'):
                actualParams[p] = params[p]['value']
            elif params[p].get('key'):
                actualParams[p] = demisto.dt(demisto.context(), params[p]['key'])
    return actualParams


def header(s):
    if not s:
        return None
    s_no_newlines = ' '.join(s.splitlines())
    return Header(s_no_newlines, UTF_8)


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
    htmlBody = demisto.getArg('htmlBody') or ''
    replyTo = demisto.getArg('replyTo')
    templateParams = template_params()
    if templateParams:
        body = body.format(**templateParams)
        htmlBody = htmlBody.format(**templateParams)

    # Basic validation - we allow pretty much everything but you have to have at least a recipient
    # We allow messages without subject and also without body
    if not to and not cc and not bcc:
        return_error_mail_sender('You must have at least one recipient')

    attachments = collect_attachments()
    attachments.extend(collect_manual_attachments())

    # Let's see what type of message we are talking about
    if not htmlBody:
        # This is a simple text message - we cannot have CIDs here
        if len(attachments) > 0:
            # This is multipart - default is mixed
            msg = MIMEMultipart()  # type: Message
            msg.preamble = 'The message is only available on a MIME-aware mail reader.\n'
            msg.attach(MIMEText(body, 'plain', UTF_8))
            for att in attachments:
                handle_file(msg, att['name'], att['maintype'], att['subtype'], None, att['data'])
        else:
            # Just text, how boring
            msg = MIMEText(body, 'plain', UTF_8)
    else:
        htmlBody, htmlAttachments = handle_html(htmlBody)
        attachments += htmlAttachments
        if len(attachments) > 0:
            msg = MIMEMultipart()
            msg.preamble = 'The message is only available on a MIME-aware mail reader.\n'
            if body:
                alt = MIMEMultipart('alternative')
                alt.attach(MIMEText(body, 'plain', UTF_8))
                alt.attach(MIMEText(htmlBody, 'html', UTF_8))
                msg.attach(alt)
            else:
                msg.attach(MIMEText(htmlBody, 'html', UTF_8))
            for att in attachments:
                handle_file(msg, att['name'], att['maintype'], att['subtype'], att['cid'], att['data'])
        else:
            if body:
                msg = MIMEMultipart('alternative')
                msg.preamble = 'The message is only available on a MIME-aware mail reader.\n'
                msg.attach(MIMEText(body, 'plain', UTF_8))
                msg.attach(MIMEText(htmlBody, 'html', UTF_8))
            else:
                msg = MIMEText(htmlBody, 'html', UTF_8)

    # Add the relevant headers to the most outer message
    msg['Subject'] = header(subject)
    msg['From'] = header(demisto.getParam('from'))
    if replyTo:
        msg['Reply-To'] = header(replyTo)
    if to:
        msg['To'] = header(','.join(to))
    if cc:
        msg['CC'] = header(','.join(cc))
    if additional_header:
        for h in additional_header:
            header_name_and_value = h.split('=', 1)
            msg[header_name_and_value[0]] = header(header_name_and_value[1])
    # Notice we should not add BCC header since Python2 does not filter it
    return msg.as_string(), to, cc, bcc


def get_user_pass():
    if demisto.getParam('credentials'):
        return (str(demisto.getParam('credentials').get('identifier', '')),
                str(demisto.getParam('credentials').get('password', '')))
    return (None, None)


def main():
    # Following methods raise exceptions so no need to check for return codes
    # But we do need to catch them
    global SERVER
    FROM = demisto.getParam('from')
    FQDN = demisto.params().get('fqdn')
    FQDN = (FQDN and FQDN.strip()) or None
    stderr_org = smtplib.stderr  # type: ignore
    try:
        if demisto.command() == 'test-module':
            smtplib.stderr = LOG  # type: ignore
            smtplib.SMTP.debuglevel = 1
        SERVER = SMTP(demisto.getParam('host'), int(demisto.params().get('port', 0)), local_hostname=FQDN)
        SERVER.ehlo()
        # TODO - support for non-valid certs
        if demisto.getParam('tls'):
            SERVER.starttls()
        user, password = get_user_pass()
        if user:
            SERVER.login(user, password)
    except Exception as e:
        # also reset at the bottom finally
        smtplib.stderr = stderr_org  # type: ignore
        smtplib.SMTP.debuglevel = 0
        demisto.error('Failed test: {}\nStack trace: {}'.format(e, traceback.format_exc()))
        return_error_mail_sender(e)
        return  # so mypy knows that we don't continue after this
    # -- COMMANDS --
    try:
        if demisto.command() == 'test-module':
            msg = MIMEText('This is a test mail from Demisto\nRegards\nDBot')  # type: Message
            msg['Subject'] = 'Test mail from Demisto'
            msg['From'] = FROM
            msg['To'] = FROM
            SERVER.sendmail(FROM, [FROM], msg.as_string())
            SERVER.quit()
            demisto.results('ok')
        elif demisto.command() == 'send-mail':
            raw_message = demisto.getArg('raw_message')
            if raw_message:
                to = argToList(demisto.getArg('to'))
                cc = argToList(demisto.getArg('cc'))
                bcc = argToList(demisto.getArg('bcc'))
                str_msg = raw_message
            else:
                (str_msg, to, cc, bcc) = create_msg()

            SERVER.sendmail(FROM, to + cc + bcc, str_msg)  # type: ignore
            SERVER.quit()  # type: ignore
            demisto.results('Mail sent successfully')
        else:
            return_error_mail_sender('Command not recognized')
    except SMTPRecipientsRefused as e:
        error_msg = ''.join('{}\n'.format(val) for key, val in e.recipients.iteritems())
        return_error_mail_sender("Encountered error: {}".format(error_msg))
    except Exception as e:
        return_error_mail_sender(e)
    finally:
        smtplib.stderr = stderr_org  # type: ignore
        smtplib.SMTP.debuglevel = 0


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
