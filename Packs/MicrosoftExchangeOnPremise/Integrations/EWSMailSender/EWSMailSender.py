import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from io import StringIO
import logging
import warnings
import traceback

import getpass


# workaround for bug in exchangelib: https://github.com/ecederstrand/exchangelib/issues/448
class FixGetPass(object):
    def __init__(self):
        self.getpass_getuser_org = getpass.getuser

        def getuser_no_fail():
            # getuser() fails on some systems. Provide a sane default.
            user = 'ews'
            try:
                if self.getpass_getuser_org:
                    user = self.getpass_getuser_org()
            except KeyError:
                pass
            return user
        getpass.getuser = getuser_no_fail

    def __del__(self):
        if self.getpass_getuser_org and getpass:
            getpass.getuser = self.getpass_getuser_org


_fix_getpass = FixGetPass()

warnings.filterwarnings("ignore")


import exchangelib  # noqa: E402
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter  # noqa: E402
from exchangelib.version import EXCHANGE_2007, EXCHANGE_2010, EXCHANGE_2010_SP2, EXCHANGE_2013, \
    EXCHANGE_2016  # noqa: E402
from exchangelib import HTMLBody, Message, FileAttachment, Account, IMPERSONATION, Credentials, Configuration, NTLM, \
    BASIC, DIGEST, Version, DELEGATE  # noqa: E402
from exchangelib.errors import ErrorItemNotFound, UnauthorizedError  # noqa: E402

IS_TEST_MODULE = False

# load arguments
USE_PROXY = demisto.params().get('proxy', False)
NON_SECURE = demisto.params().get('insecure', False)
AUTH_METHOD_STR = demisto.params().get('authType', 'Basic').lower()
EWS_SERVER = demisto.params().get('ewsServer', 'https://outlook.office365.com/EWS/Exchange.asmx/')
VERSION_STR = demisto.params().get('defaultServerVersion', '2013')
FOLDER_NAME = demisto.params().get('folder', 'Inbox')
ACCESS_TYPE = IMPERSONATION if demisto.params().get('impersonation', False) else DELEGATE

# initialized in main()
USERNAME = ""
PASSWORD = ""
ACCOUNT_EMAIL = ""

VERSIONS = {
    '2007': EXCHANGE_2007,
    '2010': EXCHANGE_2010,
    '2010_SP2': EXCHANGE_2010_SP2,
    '2013': EXCHANGE_2013,
    '2016': EXCHANGE_2016
}


config = None  # type: ignore
# LOGGING
log_stream = None
log_handler = None


def start_logging():
    logging.raiseExceptions = False
    global log_stream
    global log_handler
    if log_stream is None:
        log_stream = StringIO()
        log_handler = logging.StreamHandler(stream=log_stream)
        log_handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
        logger = logging.getLogger()
        logger.addHandler(log_handler)
        logger.setLevel(logging.DEBUG)


# NOTE: Same method used in EWSv2
# If you are modifying this probably also need to modify in the other file
def exchangelib_cleanup():      # pragma: no cover
    key_protocols = exchangelib.protocol.CachingProtocol._protocol_cache.items()
    try:
        exchangelib.close_connections()
    except Exception as ex:
        demisto.error("Error was found in exchangelib cleanup, ignoring: {}".format(ex))
    for key, protocol in key_protocols:
        try:
            if "thread_pool" in protocol.__dict__:
                demisto.debug('terminating thread pool key{} id: {}'.format(key, id(protocol.thread_pool)))
                protocol.thread_pool.terminate()
                del protocol.__dict__["thread_pool"]
            else:
                demisto.info(
                    'Thread pool not found (ignoring terminate) in protcol dict: {}'.format(dir(protocol.__dict__)))
        except Exception as ex:
            demisto.error("Error with thread_pool.terminate, ignoring: {}".format(ex))


def get_account(account_email):
    for i in range(1, 4):
        response = Account(
            primary_smtp_address=account_email, autodiscover=False, config=config, access_type=ACCESS_TYPE,
        )
        try:
            response.root  # Check if you have access to root directory
            return response
        except UnauthorizedError:
            demisto.debug("Got unauthorized error, This is attempt number {}".format(i))
            continue
    return response


def send_email_to_mailbox(
    account: Account,
    to: List[str],
    subject: str,
    body: str,
    bcc: List[str],
    cc: List[str],
    reply_to: List[str],
    html_body: Optional[str] = None,
    attachments: Optional[List[str]] = None,
    raw_message: Optional[str] = None,
    from_address: Optional[str] = None
):      # pragma: no cover
    """
    Send an email to a mailbox.

    Args:
        account (Account): account from which to send an email.
        to (list[str]): a list of emails to send an email.
        subject (str): subject of the mail.
        body (str): body of the email.
        reply_to (list[str]): list of emails of which to reply to from the sent email.
        bcc (list[str]): list of email addresses for the 'bcc' field.
        cc (list[str]): list of email addresses for the 'cc' field.
        html_body (str): HTML formatted content (body) of the email to be sent. This argument
            overrides the "body" argument.
        attachments (list[str]): list of names of attachments to send.
        raw_message (str): Raw email message from MimeContent type.
        from_address (str): the email address from which to reply.
    """
    if not attachments:
        attachments = []
    message_body = HTMLBody(html_body) if html_body else body
    m = Message(
        account=account,
        mime_content=raw_message.encode('UTF-8') if raw_message else None,
        folder=account.sent,
        cc_recipients=cc,
        bcc_recipients=bcc,
        subject=subject,
        body=message_body,
        to_recipients=to,
        reply_to=reply_to,
        author=from_address
    )
    if account.protocol.version.build <= EXCHANGE_2010_SP2:
        m.save()
        for attachment in attachments:
            m.attach(attachment)
        m.send()
    else:
        for attachment in attachments:
            m.attach(attachment)
        m.send_and_save()
    return m


def send_email_reply_to_mailbox(account, inReplyTo, to, body, subject=None, bcc=None, cc=None, html_body=None,
                                attachments=[]):      # pragma: no cover
    item_to_reply_to = account.inbox.get(id=inReplyTo)
    if isinstance(item_to_reply_to, ErrorItemNotFound):
        raise Exception(item_to_reply_to)

    subject = subject or item_to_reply_to.subject
    message_body = HTMLBody(html_body) if html_body else body
    reply = item_to_reply_to.create_reply(subject='Re: ' + subject, body=message_body, to_recipients=to, cc_recipients=cc,
                                          bcc_recipients=bcc)
    reply = reply.save(account.drafts)
    m = account.inbox.get(id=reply.id)

    for attachment in attachments:
        m.attach(attachment)
    m.send()

    return m


def get_auth_method(auth_method):      # pragma: no cover
    auth_method = auth_method.lower()
    if auth_method == 'ntlm':
        return NTLM
    elif auth_method == 'basic':
        return BASIC
    elif auth_method == 'digest':
        return DIGEST
    raise Exception("%s auth method is not supported. Choose one of %s" % (auth_method, 'ntlm\\basic\\digest'))


def get_version(version_str):
    if version_str not in VERSIONS:
        raise Exception("%s is unsupported version: %s. Choose one of" % (version_str, "\\".join(VERSIONS.keys())))
    return Version(VERSIONS[version_str])


def collect_manual_attachments(manualAttachObj):      # pragma: no cover
    attachments = []
    for attachment in manualAttachObj:
        res = demisto.getFilePath(os.path.basename(attachment['RealFileName']))

        file_path = res["path"]
        with open(file_path, 'rb') as f:
            attachments.append(FileAttachment(content=f.read(), name=attachment['FileName']))

    return attachments


def get_none_empty_addresses(addresses_ls):
    return [adress for adress in addresses_ls if adress]


def send_email(to, subject, body="", bcc=None, cc=None, replyTo=None, htmlBody=None,
               attachIDs="", attachCIDs="", attachNames="", from_mailbox=None, manualAttachObj=None,
               raw_message=None, from_address=None):
    account = get_account(from_mailbox or ACCOUNT_EMAIL)
    bcc: List[str] = get_none_empty_addresses(argToList(bcc))
    cc: List[str] = get_none_empty_addresses(argToList(cc))
    to: List[str] = get_none_empty_addresses(argToList(to))
    reply_to: List[str] = argToList(replyTo)
    manualAttachObj = manualAttachObj if manualAttachObj is not None else []
    subject = subject[:252] + '...' if len(subject) > 255 else subject

    attachments, attachments_names = process_attachments(attachCIDs, attachIDs, attachNames, manualAttachObj)

    send_email_to_mailbox(
        account=account, to=to, subject=subject, body=body, bcc=bcc, cc=cc, reply_to=reply_to,
        html_body=htmlBody, attachments=attachments, raw_message=raw_message, from_address=from_address
    )
    result_object = {
        'from': account.primary_smtp_address,
        'to': to,
        'subject': subject,
        'attachments': attachments_names
    }

    return {
        'Type': entryTypes['note'],
        'Contents': result_object,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sent email', result_object),
    }


def process_attachments(attachCIDs="", attachIDs="", attachNames="", manualAttachObj=None):      # pragma: no cover
    if manualAttachObj is None:
        manualAttachObj = []
    file_entries_for_attachments = []  # type: list
    attachments_names = []  # type: list

    if attachIDs:
        file_entries_for_attachments = attachIDs if isinstance(attachIDs, list) else attachIDs.split(",")
        if attachNames:
            attachments_names = attachNames if isinstance(attachNames, list) else attachNames.split(",")
        else:
            for att_id in file_entries_for_attachments:
                att_name = demisto.getFilePath(att_id)['name']
                if isinstance(att_name, list):
                    att_name = att_name[0]
                attachments_names.append(att_name)
        if len(file_entries_for_attachments) != len(attachments_names):
            raise Exception("attachIDs and attachNames lists should be the same length")

    attachments = collect_manual_attachments(manualAttachObj)

    if attachCIDs:
        file_entries_for_attachments_inline = attachCIDs if isinstance(attachCIDs, list) else attachCIDs.split(",")
        for att_id_inline in file_entries_for_attachments_inline:
            try:
                file_info = demisto.getFilePath(att_id_inline)
            except Exception as ex:
                demisto.info("EWS error from getFilePath: {}".format(ex))
                raise Exception("entry %s does not contain a file" % att_id_inline)
            att_name_inline = file_info["name"]
            with open(file_info["path"], 'rb') as f:
                attachments.append(FileAttachment(content=f.read(), name=att_name_inline, is_inline=True,
                                                  content_id=att_name_inline))

    for i in range(0, len(file_entries_for_attachments)):
        entry_id = file_entries_for_attachments[i]
        attachment_name = attachments_names[i]
        try:
            res = demisto.getFilePath(entry_id)
        except Exception as ex:
            raise Exception("entry {} does not contain a file: {}".format(entry_id, str(ex)))
        file_path = res["path"]
        with open(file_path, 'rb') as f:
            attachments.append(FileAttachment(content=f.read(), name=attachment_name))
    return attachments, attachments_names


def reply_email(to, inReplyTo, body="", subject="", bcc=None, cc=None, htmlBody=None, attachIDs="", attachCIDs="",
                attachNames="", from_mailbox=None, manualAttachObj=None):     # pragma: no cover
    account = get_account(from_mailbox or ACCOUNT_EMAIL)
    bcc = bcc.split(",") if bcc else None
    cc = cc.split(",") if cc else None
    to = to.split(",") if to else None
    manualAttachObj = manualAttachObj if manualAttachObj is not None else []
    subject = subject[:252] + '...' if len(subject) > 255 else subject

    attachments, attachments_names = process_attachments(attachCIDs, attachIDs, attachNames, manualAttachObj)

    send_email_reply_to_mailbox(account, inReplyTo, to, body, subject, bcc, cc, htmlBody, attachments)
    result_object = {
        'from': account.primary_smtp_address,
        'to': to,
        'subject': subject,
        'attachments': attachments_names
    }

    return {
        'Type': entryTypes['note'],
        'Contents': result_object,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sent email', result_object),
    }


def prepare():
    if NON_SECURE:
        BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter

    if not USE_PROXY:
        def remove_from_dict(d, key):
            if key in d:
                del d[key]

        import os

        remove_from_dict(os.environ, 'HTTP_PROXY')
        remove_from_dict(os.environ, 'http_proxy')
        remove_from_dict(os.environ, 'HTTPS_PROXY')
        remove_from_dict(os.environ, 'https_proxy')

        os.environ['NO_PROXY'] = EWS_SERVER

    version = get_version(VERSION_STR)
    credentials = Credentials(username=USERNAME, password=PASSWORD)
    config_args = {
        'credentials': credentials,
        'auth_type': get_auth_method(AUTH_METHOD_STR),
        'version': version
    }
    if 'http' in EWS_SERVER.lower():
        config_args['service_endpoint'] = EWS_SERVER
    else:
        config_args['server'] = EWS_SERVER
    config = Configuration(**config_args)
    return config


def prepare_args(d):     # pragma: no cover
    if "from" in d:
        d['from_address'] = d.pop('from')
    return dict((k.replace("-", "_"), v) for k, v in d.items())


def test_module():     # pragma: no cover
    global IS_TEST_MODULE
    IS_TEST_MODULE = True
    BaseProtocol.TIMEOUT = 20
    get_account(ACCOUNT_EMAIL).root
    demisto.results('ok')


def main():     # pragma: no cover
    global USERNAME, PASSWORD, ACCOUNT_EMAIL, log_stream, config
    USERNAME = demisto.params()['credentials']['identifier']
    PASSWORD = demisto.params()['credentials']['password']
    ACCOUNT_EMAIL = demisto.params().get('mailbox', None)
    if not ACCOUNT_EMAIL:
        if "@" in USERNAME:
            ACCOUNT_EMAIL = USERNAME
    if ACCOUNT_EMAIL is None:
        raise Exception("Provide a valid email address in the mailbox field")

    try:
        start_logging()
        config = prepare()
        args = prepare_args(demisto.args())
        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'send-mail':
            demisto.results(send_email(**args))
        elif demisto.command() == 'reply-mail':
            demisto.results(reply_email(**args))
    except Exception as e:
        import time

        time.sleep(2)
        debug_log = "=== DEBUG LOG ===\n" + (log_stream.getvalue() if log_stream else "")
        error_message = ""
        if "Status code: 401" in debug_log:
            error_message = ("Got unauthorized from the server. "
                             "Check credentials are correct and authentication"
                             " method are supported. ")

            error_message += ("You can try using 'domain\\username' as username for authentication. "
                              if AUTH_METHOD_STR.lower() == 'ntlm' else '')
        if "Status code: 503" in debug_log:
            error_message = "Got timeout from the server. " \
                            "Probably the server is not reachable with the current settings. " \
                            "Check proxy parameter. If you are using server URL - change to server IP address. "
        error_message = error_message + "\n" + str(e)
        stacktrace = traceback.format_exc()
        if stacktrace:
            debug_log += "\nFull stacktrace:\n" + stacktrace

        demisto.error(
            "EWS Mail Sender failed {}. Error: {}. Debug: {}".format(demisto.command(), error_message, debug_log))
        if IS_TEST_MODULE:
            demisto.results(error_message)
        else:
            return_error(error_message + '\n' + debug_log)
    finally:
        exchangelib_cleanup()
        if log_stream:
            try:
                logging.getLogger().removeHandler(log_handler)  # type: ignore
                log_stream.close()
                log_stream = None
            except Exception as ex:
                demisto.error("EWS Mail Sender: unexpected exception when trying to remove log handler: {}".format(ex))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins" or __name__ == "__main__":
    main()
