import email
import hashlib
import subprocess
import warnings
from multiprocessing import Process

import dateparser  # type: ignore
import exchangelib
from CommonServerPython import *
from io import StringIO
from exchangelib import (BASIC, DELEGATE, DIGEST, IMPERSONATION, NTLM, Account,
                         Build, Configuration, Credentials, EWSDateTime,
                         EWSTimeZone, FileAttachment, Folder, HTMLBody,
                         ItemAttachment, Version)
from exchangelib.errors import (AutoDiscoverFailed, ErrorFolderNotFound,
                                ErrorInvalidIdMalformed,
                                ErrorInvalidPropertyRequest,
                                ErrorIrresolvableConflict, ErrorItemNotFound,
                                ErrorMailboxMoveInProgress,
                                ErrorMailboxStoreUnavailable,
                                ErrorNameResolutionNoResults, RateLimitError,
                                ResponseMessageError, TransportError)
from exchangelib.items import Contact, Item, Message
from exchangelib.protocol import BaseProtocol, Protocol
from exchangelib.services import EWSService
from exchangelib.services.common import EWSAccountService
from exchangelib.util import add_xml_child, create_element
from exchangelib.version import (EXCHANGE_2007, EXCHANGE_2010,
                                 EXCHANGE_2010_SP2, EXCHANGE_2013,
                                 EXCHANGE_2016, EXCHANGE_2019)
from future import utils as future_utils
from requests.exceptions import ConnectionError
from exchangelib.version import VERSIONS as EXC_VERSIONS


# Exchange2 2019 patch - server dosen't connect with 2019 but with other versions creating an error mismatch (see CIAC-3086),
# overriding this function to remove minor version test and remove error throw.
# opened bug for exchanglib here https://github.com/ecederstrand/exchangelib/issues/1210
def our_fullname(self):  # pragma: no cover
    for build, api_version, full_name in EXC_VERSIONS:
        # removed 'or self.build.minor_version != build.minor_version'
        if self.build and self.build.major_version != build.major_version:
            continue
        if self.api_version == api_version:
            return full_name
    return None


Version.fullname = our_fullname


class exchangelibSSLAdapter(SSLAdapter):
    def cert_verify(self, conn, url, verify, cert):
        # We're overriding a method, so we have to keep the signature, although verify is unused
        del verify
        super().cert_verify(conn=conn, url=url, verify=False, cert=cert)


# Ignore warnings print to stdout
warnings.filterwarnings("ignore")

MNS, TNS = exchangelib.util.MNS, exchangelib.util.TNS

# consts
VERSIONS = {
    '2007': EXCHANGE_2007,
    '2010': EXCHANGE_2010,
    '2010_SP2': EXCHANGE_2010_SP2,
    '2013': EXCHANGE_2013,
    '2016': EXCHANGE_2016,
    '2019': EXCHANGE_2019
}

ATTACHMENT_ID = "attachmentId"
ATTACHMENT_ORIGINAL_ITEM_ID = 'originalItemId'
NEW_ITEM_ID = 'newItemId'
MESSAGE_ID = "messageId"
ITEM_ID = "itemId"
ACTION = "action"
MAILBOX = "mailbox"
MAILBOX_ID = "mailboxId"
FOLDER_ID = "id"

MOVED_TO_MAILBOX = "movedToMailbox"
MOVED_TO_FOLDER = "movedToFolder"

FILE_ATTACHMENT_TYPE = 'FileAttachment'
ITEM_ATTACHMENT_TYPE = 'ItemAttachment'
ATTACHMENT_TYPE = 'attachmentType'

TOIS_PATH = '/root/Top of Information Store/'

ENTRY_CONTEXT = "EntryContext"
CONTEXT_UPDATE_EWS_ITEM = "EWS.Items(val.{0} == obj.{0} || (val.{1} && obj.{1} && val.{1} == obj.{1}))".format(ITEM_ID,
                                                                                                               MESSAGE_ID)
CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT = f"EWS.Items(val.{ITEM_ID} == obj.{ATTACHMENT_ORIGINAL_ITEM_ID})"
CONTEXT_UPDATE_ITEM_ATTACHMENT = ".ItemAttachments(val.{0} == obj.{0})".format(ATTACHMENT_ID)
CONTEXT_UPDATE_FILE_ATTACHMENT = ".FileAttachments(val.{0} == obj.{0})".format(ATTACHMENT_ID)
CONTEXT_UPDATE_FOLDER = "EWS.Folders(val.{0} == obj.{0})".format(FOLDER_ID)

LAST_RUN_TIME = "lastRunTime"
LAST_RUN_IDS = "ids"
LAST_RUN_FOLDER = "folderName"
ERROR_COUNTER = "errorCounter"

ITEMS_RESULTS_HEADERS = ['sender', 'subject', 'hasAttachments', 'datetimeReceived', 'receivedBy', 'author',
                         'toRecipients', 'textBody', ]

# Load integratoin params from demisto
NON_SECURE = demisto.params().get('insecure', True)
AUTH_METHOD_STR = demisto.params().get('authType', '')
AUTH_METHOD_STR = AUTH_METHOD_STR.lower() if AUTH_METHOD_STR else ''
VERSION_STR = demisto.params().get('defaultServerVersion', None)
MANUAL_USERNAME = demisto.params().get('domainAndUserman', '')
FOLDER_NAME = demisto.params().get('folder', 'Inbox')
IS_PUBLIC_FOLDER = demisto.params().get('isPublicFolder', False)
ACCESS_TYPE = IMPERSONATION if demisto.params().get('impersonation', False) else DELEGATE
FETCH_ALL_HISTORY = demisto.params().get('fetchAllHistory', False)
IS_TEST_MODULE = False
BaseProtocol.TIMEOUT = int(demisto.params().get('requestTimeout', 120))
AUTO_DISCOVERY = False
SERVER_BUILD = ""
MARK_AS_READ = demisto.params().get('markAsRead', False)
MAX_FETCH = min(50, int(demisto.params().get('maxFetch', 50)))
FETCH_TIME = demisto.params().get('fetch_time') or '10 minutes'

LAST_RUN_IDS_QUEUE_SIZE = 500

START_COMPLIANCE = """
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,

[Parameter(Mandatory=$True)]
[string]$query
)

$WarningPreference = "silentlyContinue"
# Create Credential object
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)

# Generate a unique search name
$searchName = [guid]::NewGuid().ToString() -replace '[-]'
$searchName = "DemistoSearch" + $searchName

# open remote PS session to Office 365 Security & Compliance Center
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $UserCredential `
-Authentication Basic -AllowRedirection

if (!$session)
{
   "Failed to create remote PS session"
   return
}

Import-PSSession $session -CommandName *Compliance* -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null

$compliance = New-ComplianceSearch -Name $searchName -ExchangeLocation All -ContentMatchQuery $query -Confirm:$false

Start-ComplianceSearch -Identity $searchName

$complianceSearchName = "Action status: " + $searchName

$complianceSearchName | ConvertTo-Json

# Close the session
Remove-PSSession $session
"""
GET_COMPLIANCE = """[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,


[Parameter(Mandatory=$True)]
[string]$searchName
)

$WarningPreference = "silentlyContinue"
# Create Credential object
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)


# open remote PS session to Office 365 Security & Compliance Center
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $UserCredential `
-Authentication Basic -AllowRedirection

if (!$session)
{
   "Failed to create remote PS session"
   return
}


Import-PSSession $session -CommandName Get-ComplianceSearch -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null


$searchStatus = Get-ComplianceSearch $searchName
#"Search status: " + $searchStatus.Status
$searchStatus.Status
if ($searchStatus.Status -eq "Completed")
{
   $searchStatus.SuccessResults | ConvertTo-Json
}

# Close the session
Remove-PSSession $session
"""
PURGE_COMPLIANCE = """
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,

[Parameter(Mandatory=$True)]
[string]$searchName
)

$WarningPreference = "silentlyContinue"
# Create Credential object
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)

# open remote PS session to Office 365 Security & Compliance Center
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $UserCredential `
-Authentication Basic -AllowRedirection
if (!$session)
{
   "Failed to create remote PS session"
   return
}


Import-PSSession $session -CommandName *Compliance* -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null

# Delete mails based on an existing search criteria
$newActionResult = New-ComplianceSearchAction -SearchName $searchName -Purge -PurgeType SoftDelete -Confirm:$false
if (!$newActionResult)
{
   # Happens when there are no results from the search
   "No action was created"
}

# Close the session
Remove-PSSession $session
return
"""
PURGE_STATUS_COMPLIANCE = """
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,

[Parameter(Mandatory=$True)]
[string]$searchName
)

$WarningPreference = "silentlyContinue"
# Create Credential object
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)

# open remote PS session to Office 365 Security & Compliance Center
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $UserCredential `
-Authentication Basic -AllowRedirection

if (!$session)
{
   "Failed to create remote PS session"
   return
}


Import-PSSession $session -CommandName *Compliance* -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null

$actionName = $searchName + "_Purge"
$actionStatus = Get-ComplianceSearchAction $actionName
""
$actionStatus.Status

# Close the session
Remove-PSSession $session
"""
REMOVE_COMPLIANCE = """
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,

[Parameter(Mandatory=$True)]
[string]$searchName
)

$WarningPreference = "silentlyContinue"
# Create Credential object
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)


# open remote PS session to Office 365 Security & Compliance Center

$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $UserCredential `
-Authentication Basic -AllowRedirection

if (!$session)
{
   "Failed to create remote PS session"
   return
}


Import-PSSession $session -CommandName *Compliance* -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null

# Remove the search
Remove-ComplianceSearch $searchName -Confirm:$false

# Close the session
Remove-PSSession $session
"""

# initialized in main()
EWS_SERVER = ''
USERNAME = ''
ACCOUNT_EMAIL = ''
PASSWORD = ''
config = None
credentials = None


# NOTE: Same method used in EWSMailSender
# If you are modifying this probably also need to modify in the other file
def exchangelib_cleanup():  # pragma: no cover
    try:
        exchangelib.close_connections()
    except Exception as ex:
        demisto.error(f"Error was found in exchangelib cleanup, ignoring: {ex}")


# Prep Functions
def get_auth_method(auth_method):  # pragma: no cover
    auth_method = auth_method.lower()
    if auth_method == 'ntlm':
        return NTLM
    elif auth_method == 'basic':
        return BASIC
    elif auth_method == 'digest':
        return DIGEST
    raise Exception("{} auth method is not supported. Choose one of {}".format(auth_method, 'ntlm\\basic\\digest'))


def get_build(version_str):  # pragma: no cover
    if version_str not in VERSIONS:
        raise Exception("{} is unsupported version: {}. Choose one of".format(version_str, "\\".join(list(VERSIONS.keys()))))
    return VERSIONS[version_str]


def get_build_autodiscover(context_dict):  # pragma: no cover
    build_params = context_dict["build"].split(".")
    build_params = [int(i) for i in build_params]
    return Build(*build_params)


def get_endpoint_autodiscover(context_dict):  # pragma: no cover
    return context_dict["service_endpoint"]


def get_version(version_str):
    if version_str not in VERSIONS:
        raise Exception("{} is unsupported version: {}. Choose one of".format(version_str, "\\".join(list(VERSIONS.keys()))))
    return Version(VERSIONS[version_str])


def create_context_dict(account):  # pragma: no cover
    return {
        "auth_type": account.protocol.auth_type,
        "service_endpoint": account.protocol.service_endpoint,
        "build": str(account.protocol.version.build),
        "api_version": account.protocol.version.api_version
    }


def prepare_context(credentials):  # pragma: no cover
    context_dict = demisto.getIntegrationContext()
    global SERVER_BUILD, EWS_SERVER
    if not context_dict:
        try:
            account = Account(
                primary_smtp_address=ACCOUNT_EMAIL, autodiscover=True,
                access_type=ACCESS_TYPE, credentials=credentials,
            )
            EWS_SERVER = account.protocol.service_endpoint
            SERVER_BUILD = account.protocol.version.build
            demisto.setIntegrationContext(create_context_dict(account))
        except AutoDiscoverFailed:
            return_error("Auto discovery failed. Check credentials or configure manually")
        except Exception as e:
            return_error(str(e))
    else:
        SERVER_BUILD = get_build_autodiscover(context_dict)
        EWS_SERVER = get_endpoint_autodiscover(context_dict)


def prepare():  # pragma: no cover
    if NON_SECURE:
        BaseProtocol.HTTP_ADAPTER_CLS = exchangelibSSLAdapter
    else:
        BaseProtocol.HTTP_ADAPTER_CLS = requests.adapters.HTTPAdapter

    global AUTO_DISCOVERY, VERSION_STR, AUTH_METHOD_STR, USERNAME
    AUTO_DISCOVERY = not EWS_SERVER
    if AUTO_DISCOVERY:
        credentials = Credentials(username=USERNAME, password=PASSWORD)
        prepare_context(credentials)
        return None, credentials
    else:
        if 'outlook.office365.com' in EWS_SERVER.lower():
            if not AUTH_METHOD_STR:
                AUTH_METHOD_STR = 'Basic'
            VERSION_STR = '2016'
        else:
            if MANUAL_USERNAME:
                USERNAME = MANUAL_USERNAME
            if not AUTH_METHOD_STR:
                AUTH_METHOD_STR = 'ntlm'
            if not VERSION_STR:
                return_error('Exchange Server Version is required for on-premise Exchange Servers.')

        version = get_version(VERSION_STR)
        credentials = Credentials(username=USERNAME, password=PASSWORD)
        config_args = {
            'credentials': credentials,
            'auth_type': get_auth_method(AUTH_METHOD_STR),
            'version': version
        }
        if not EWS_SERVER:
            return_error("Exchange Server Hostname or IP Address is required for manual configuration.")
        elif 'http' in EWS_SERVER.lower():
            config_args['service_endpoint'] = EWS_SERVER
        else:
            config_args['server'] = EWS_SERVER

        return Configuration(**config_args), None


def construct_config_args(context_dict, credentials):  # pragma: no cover
    auth_type = context_dict["auth_type"]
    api_version = context_dict["api_version"]
    service_endpoint = context_dict["service_endpoint"]
    version = Version(get_build_autodiscover(context_dict), api_version)

    config_args = {
        'credentials': credentials,
        'auth_type': auth_type,
        'version': version,
        'service_endpoint': service_endpoint
    }
    return config_args


def get_account_autodiscover(account_email, access_type=ACCESS_TYPE):  # pragma: no cover
    account = None
    original_exc = None  # type: ignore
    context_dict = demisto.getIntegrationContext()

    if context_dict:
        try:
            config_args = construct_config_args(context_dict, credentials)
            account = Account(
                primary_smtp_address=account_email, autodiscover=False, config=Configuration(**config_args),
                access_type=access_type,
            )
            account.root.effective_rights.read  # pylint: disable=E1101
            return account
        except Exception as e:
            # fixing flake8 correction where original_exc is assigned but unused
            original_exc = e
            pass

    try:
        account = Account(
            primary_smtp_address=ACCOUNT_EMAIL, autodiscover=True, credentials=credentials, access_type=access_type,
        )
    except AutoDiscoverFailed:
        return_error("Auto discovery failed. Check credentials or configure manually")

    autodiscover_result = create_context_dict(account)
    if autodiscover_result == context_dict and original_exc:
        raise original_exc  # pylint: disable=E0702

    if account_email == ACCOUNT_EMAIL:
        demisto.setIntegrationContext(create_context_dict(account))
    return account


def get_account(account_email, access_type=ACCESS_TYPE):  # pragma: no cover
    if not AUTO_DISCOVERY:
        return Account(
            primary_smtp_address=account_email, autodiscover=False, config=config, access_type=access_type,
        )
    return get_account_autodiscover(account_email, access_type)


# LOGGING
log_stream = None
log_handler = None


def start_logging():
    global log_stream
    global log_handler
    logging.raiseExceptions = False
    if log_stream is None:
        log_stream = StringIO()
        log_handler = logging.StreamHandler(stream=log_stream)
        log_handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
        logger = logging.getLogger()
        logger.addHandler(log_handler)
        logger.setLevel(logging.DEBUG)


# Exchange 2010 Fixes
def fix_2010():  # pragma: no cover
    version = SERVER_BUILD if SERVER_BUILD else get_build(VERSION_STR)
    if version <= EXCHANGE_2010_SP2:
        for m in (
                Item, Message, exchangelib.items.CalendarItem, exchangelib.items.Contact,
                exchangelib.items.DistributionList,
                exchangelib.items.PostItem, exchangelib.items.Task, exchangelib.items.MeetingRequest,
                exchangelib.items.MeetingResponse, exchangelib.items.MeetingCancellation):
            for i, f in enumerate(m.FIELDS):
                if f.name == 'text_body':
                    m.FIELDS.pop(i)
                    break
        for m in (exchangelib.Folder, exchangelib.folders.Inbox):
            for i, f in enumerate(m.FIELDS):
                if f.name == 'unread_count':
                    m.FIELDS.pop(i)
                    break

        def repr1(self):
            return self.__class__.__name__ + repr((self.root, self.name, self.total_count, self.child_folder_count,
                                                   self.folder_class, self.id, self.changekey))

        def repr2(self):
            return self.__class__.__name__ + repr(
                (self.root, self.name, self.total_count, self.child_folder_count, self.folder_class, self.changekey))

        def repr3(self):
            return self.__class__.__name__ + repr((self.account, '[self]', self.name, self.total_count,
                                                   self.child_folder_count, self.folder_class, self.changekey))

        exchangelib.Folder.__repr__ = repr1
        exchangelib.folders.Inbox.__repr__ = exchangelib.folders.JunkEmail.__repr__ = repr2
        exchangelib.folders.Root.__repr__ = repr3

    start_logging()


def str_to_unicode(obj):  # pragma: no cover
    if isinstance(obj, dict):
        obj = {k: str_to_unicode(v) for k, v in list(obj.items())}
    elif isinstance(obj, list):
        obj = [str_to_unicode(k) for k in obj]
    elif isinstance(obj, str):
        obj = obj.encode("utf-8")
    return obj


def filter_dict_null(d):  # pragma: no cover
    if isinstance(d, dict):
        return {k: v for k, v in list(d.items()) if v is not None}
    return d


def is_empty_object(obj):
    size = 0
    if isinstance(obj, map):
        size = obj.__sizeof__()
    else:
        size = len(obj)
    return size == 0


def get_attachment_name(attachment_name):  # pragma: no cover
    if attachment_name is None or attachment_name == "":
        return 'demisto_untitled_attachment'
    return attachment_name


def get_entry_for_object(title, context_key, obj, headers=None):  # pragma: no cover
    if is_empty_object(obj):
        return "There is no output results"
    obj = filter_dict_null(obj)
    if isinstance(obj, list):
        obj = [filter_dict_null(k) for k in obj]
    if headers and isinstance(obj, dict):
        headers = list(set(headers).intersection(set(obj.keys())))

    return {
        'Type': entryTypes['note'],
        'Contents': obj,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, obj, headers),
        ENTRY_CONTEXT: {
            context_key: obj
        }
    }


def get_items_from_mailbox(account, item_ids):  # pragma: no cover
    if type(item_ids) is not list:
        item_ids = [item_ids]
    items = [Item(id=x) for x in item_ids]
    result = list(account.fetch(ids=items))
    result = [x for x in result if not (isinstance(x, ErrorInvalidIdMalformed | ErrorItemNotFound))]
    if len(result) != len(item_ids):
        raise Exception("One or more items were not found/malformed. Check the input item ids")
    return result


def get_item_from_mailbox(account, item_id):  # pragma: no cover
    result = get_items_from_mailbox(account, [item_id])
    if len(result) == 0:
        raise Exception("ItemId %s not found" % str(item_id))
    return result[0]


def is_default_folder(folder_path, is_public):  # pragma: no cover

    if is_public is not None:
        return is_public

    if folder_path == FOLDER_NAME:
        return IS_PUBLIC_FOLDER

    return False


def get_folder_by_path(account, path, is_public=False):  # pragma: no cover
    # handle exchange folder id
    if len(path) == 120:
        folders_map = account.root._folders_map
        if path in folders_map:
            return account.root._folders_map[path]

    if is_public:
        folder_result = account.public_folders_root
    elif path == 'AllItems':
        folder_result = account.root
    else:
        folder_result = account.inbox.parent  # Top of Information Store
    path = path.replace("/", "\\")
    path = path.split('\\')
    for sub_folder_name in path:
        folder_filter_by_name = [x for x in folder_result.children if x.name.lower() == sub_folder_name.lower()]
        if len(folder_filter_by_name) == 0:
            raise Exception("No such folder %s" % path)
        folder_result = folder_filter_by_name[0]

    return folder_result


class MarkAsJunk(EWSAccountService):
    SERVICE_NAME = 'MarkAsJunk'

    def call(self, item_id, move_item):  # pragma: no cover
        elements = list(self._get_elements(payload=self.get_payload(item_id=item_id, move_item=move_item)))
        for element in elements:
            if isinstance(element, ResponseMessageError):
                return element.message
        return "Success"

    def get_payload(self, item_id, move_item):  # pragma: no cover
        junk = create_element('m:%s' % self.SERVICE_NAME,
                              {"IsJunk": "true",
                               "MoveItem": ("true" if move_item else "false")})

        items_list = create_element('m:ItemIds')
        item_element = create_element("t:ItemId", {"Id": item_id})
        items_list.append(item_element)
        junk.append(items_list)

        return junk


def send_email_to_mailbox(account, to, subject, body, bcc, cc, reply_to, html_body=None, attachments=None,
                          raw_message=None, from_address=None):  # pragma: no cover
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


def send_email_reply_to_mailbox(account, in_reply_to, to, body, subject=None, bcc=None, cc=None, html_body=None,
                                attachments=None, from_mailbox=None):  # pragma: no cover
    if attachments is None:
        attachments = []
    item_to_reply_to = account.inbox.get(id=in_reply_to)
    if isinstance(item_to_reply_to, ErrorItemNotFound):
        raise Exception(item_to_reply_to)

    subject = subject or item_to_reply_to.subject
    message_body = HTMLBody(html_body) if html_body else body
    reply = item_to_reply_to.create_reply(subject='Re: ' + subject, body=message_body, to_recipients=to, cc_recipients=cc,
                                          bcc_recipients=bcc, author=from_mailbox)
    reply = reply.save(account.drafts)
    m = account.inbox.get(id=reply.id)

    for attachment in attachments:
        m.attach(attachment)
    m.send()

    return m


class GetSearchableMailboxes(EWSService):
    SERVICE_NAME = 'GetSearchableMailboxes'
    element_container_name = '{%s}SearchableMailboxes' % MNS

    @staticmethod
    def parse_element(element):
        return {
            MAILBOX: element.find("{%s}PrimarySmtpAddress" % TNS).text if element.find(
                "{%s}PrimarySmtpAddress" % TNS) is not None else None,
            MAILBOX_ID: element.find("{%s}ReferenceId" % TNS).text if element.find(
                "{%s}ReferenceId" % TNS) is not None else None,
            'displayName': element.find("{%s}DisplayName" % TNS).text if element.find(
                "{%s}DisplayName" % TNS) is not None else None,
            'isExternal': element.find("{%s}IsExternalMailbox" % TNS).text if element.find(
                "{%s}IsExternalMailbox" % TNS) is not None else None,
            'externalEmailAddress': element.find("{%s}ExternalEmailAddress" % TNS).text if element.find(
                "{%s}ExternalEmailAddress" % TNS) is not None else None
        }

    def call(self):
        if self.protocol.version.build < EXCHANGE_2013:
            raise NotImplementedError('%s is only supported for Exchange 2013 servers and later' % self.SERVICE_NAME)
        elements = self._get_elements(payload=self.get_payload())
        return [self.parse_element(e) for e in elements]

    def get_payload(self):
        element = create_element(
            'm:%s' % self.SERVICE_NAME,
        )
        return element


class SearchMailboxes(EWSService):
    SERVICE_NAME = 'SearchMailboxes'
    element_container_name = f'{{{MNS}}}SearchMailboxesResult/{{{TNS}}}Items'

    @staticmethod
    def parse_element(element):  # pragma: no cover
        to_recipients = element.find('{%s}ToRecipients' % TNS)
        if to_recipients:
            to_recipients = [x.text if x is not None else None for x in to_recipients]

        result = {
            ITEM_ID: element.find('{%s}Id' % TNS).attrib['Id'] if element.find('{%s}Id' % TNS) is not None else None,
            MAILBOX: element.find(f'{{{TNS}}}Mailbox/{{{TNS}}}PrimarySmtpAddress').text if element.find(
                f'{{{TNS}}}Mailbox/{{{TNS}}}PrimarySmtpAddress') is not None else None,
            'subject': element.find("{%s}Subject" % TNS).text if element.find(
                "{%s}Subject" % TNS) is not None else None,
            'toRecipients': to_recipients,
            'sender': element.find("{%s}Sender" % TNS).text if element.find("{%s}Sender" % TNS) is not None else None,
            'hasAttachments': element.find("{%s}HasAttachment" % TNS).text if element.find(
                "{%s}HasAttachment" % TNS) is not None else None,
            'datetimeSent': element.find("{%s}SentTime" % TNS).text if element.find(
                "{%s}SentTime" % TNS) is not None else None,
            'datetimeReceived': element.find("{%s}ReceivedTime" % TNS).text if element.find(
                "{%s}ReceivedTime" % TNS) is not None else None
        }

        return result

    def call(self, query, mailboxes):  # pragma: no cover
        if self.protocol.version.build < EXCHANGE_2013:
            raise NotImplementedError('%s is only supported for Exchange 2013 servers and later' % self.SERVICE_NAME)
        elements = list(self._get_elements(payload=self.get_payload(query, mailboxes)))
        return [self.parse_element(x) for x in elements]

    def get_payload(self, query, mailboxes):  # pragma: no cover
        def get_mailbox_search_scope(mailbox_id):
            mailbox_search_scope = create_element("t:MailboxSearchScope")
            add_xml_child(mailbox_search_scope, "t:Mailbox", mailbox_id)
            add_xml_child(mailbox_search_scope, "t:SearchScope", "All")
            return mailbox_search_scope

        mailbox_query_element = create_element("t:MailboxQuery")
        add_xml_child(mailbox_query_element, "t:Query", query)
        mailboxes_scopes = []
        for mailbox in mailboxes:
            mailboxes_scopes.append(get_mailbox_search_scope(mailbox))
        add_xml_child(mailbox_query_element, "t:MailboxSearchScopes", mailboxes_scopes)

        element = create_element('m:%s' % self.SERVICE_NAME)
        add_xml_child(element, "m:SearchQueries", mailbox_query_element)
        add_xml_child(element, "m:ResultType", "PreviewOnly")

        return element


class ExpandGroup(EWSService):
    SERVICE_NAME = 'ExpandDL'
    element_container_name = '{%s}DLExpansion' % MNS

    @staticmethod
    def parse_element(element):  # pragma: no cover
        return {
            MAILBOX: element.find("{%s}EmailAddress" % TNS).text if element.find(
                "{%s}EmailAddress" % TNS) is not None else None,
            'displayName': element.find("{%s}Name" % TNS).text if element.find("{%s}Name" % TNS) is not None else None,
            'mailboxType': element.find("{%s}MailboxType" % TNS).text if element.find(
                "{%s}MailboxType" % TNS) is not None else None
        }

    def call(self, email_address, recursive_expansion=False):  # pragma: no cover
        if self.protocol.version.build < EXCHANGE_2010:
            raise NotImplementedError('%s is only supported for Exchange 2010 servers and later' % self.SERVICE_NAME)
        try:
            if recursive_expansion == 'True':
                group_members = {}  # type: dict
                self.expand_group_recursive(email_address, group_members)
                return list(group_members.values())
            else:
                return self.expand_group(email_address)
        except ErrorNameResolutionNoResults:
            demisto.results("No results were found.")
            sys.exit()

    def get_payload(self, email_address):  # pragma: no cover
        element = create_element('m:%s' % self.SERVICE_NAME, )
        mailbox_element = create_element('m:Mailbox')
        add_xml_child(mailbox_element, 't:EmailAddress', email_address)
        element.append(mailbox_element)
        return element

    def expand_group(self, email_address):  # pragma: no cover
        elements = self._get_elements(payload=self.get_payload(email_address))
        return [self.parse_element(x) for x in elements]

    def expand_group_recursive(self, email_address, non_dl_emails, dl_emails=set()):  # pragma: no cover
        if email_address in non_dl_emails or email_address in dl_emails:
            return
        dl_emails.add(email_address)

        for member in self.expand_group(email_address):
            if member['mailboxType'] == 'PublicDL' or member['mailboxType'] == 'PrivateDL':
                self.expand_group_recursive(member['mailbox'], non_dl_emails, dl_emails)
            else:
                if member['mailbox'] not in non_dl_emails:
                    non_dl_emails[member['mailbox']] = member


def get_expanded_group(protocol, email_address, recursive_expansion=False):
    group_members = ExpandGroup(protocol=protocol).call(email_address, recursive_expansion)
    group_details = {
        "name": email_address,
        "members": group_members
    }
    entry_for_object = get_entry_for_object("Expanded group", 'EWS.ExpandGroup', group_details)
    entry_for_object['HumanReadable'] = tableToMarkdown('Group Members', group_members)
    return entry_for_object


def get_searchable_mailboxes(protocol):
    searchable_mailboxes = GetSearchableMailboxes(protocol=protocol).call()
    return get_entry_for_object("Searchable mailboxes", 'EWS.Mailboxes', searchable_mailboxes)


def search_mailboxes(protocol, filter, limit=100, mailbox_search_scope=None, email_addresses=None):  # pragma: no cover
    mailbox_ids = []
    limit = int(limit)
    if mailbox_search_scope is not None and email_addresses is not None:
        raise Exception("Use one of the arguments - mailbox-search-scope or email-addresses, not both")
    if email_addresses:
        email_addresses = email_addresses.split(",")
        all_mailboxes = get_searchable_mailboxes(protocol)[ENTRY_CONTEXT]['EWS.Mailboxes']
        for email_address in email_addresses:
            for mailbox in all_mailboxes:
                if MAILBOX in mailbox and email_address.lower() == mailbox[MAILBOX].lower():
                    mailbox_ids.append(mailbox[MAILBOX_ID])
        if len(mailbox_ids) == 0:
            raise Exception("No searchable mailboxes were found for the provided email addresses.")
    elif mailbox_search_scope:
        mailbox_ids = mailbox_search_scope if type(mailbox_search_scope) is list else [mailbox_search_scope]
    else:
        entry = get_searchable_mailboxes(protocol)
        mailboxes = [x for x in entry[ENTRY_CONTEXT]['EWS.Mailboxes'] if MAILBOX_ID in list(x.keys())]
        mailbox_ids = [x[MAILBOX_ID] for x in mailboxes]  # type: ignore

    try:
        search_results = SearchMailboxes(protocol=protocol).call(filter, mailbox_ids)
        search_results = search_results[:limit]
    except TransportError as e:
        if "ItemCount>0<" in str(e):
            return "No results for search query: " + filter
        else:
            raise e

    return get_entry_for_object("Search mailboxes results",
                                CONTEXT_UPDATE_EWS_ITEM,
                                search_results)


def get_last_run():
    last_run = demisto.getLastRun()
    if not last_run or last_run.get(LAST_RUN_FOLDER) != FOLDER_NAME:
        last_run = {
            LAST_RUN_TIME: None,
            LAST_RUN_FOLDER: FOLDER_NAME,
            LAST_RUN_IDS: []
        }
    if LAST_RUN_TIME in last_run and last_run[LAST_RUN_TIME] is not None:
        last_run[LAST_RUN_TIME] = EWSDateTime.from_string(last_run[LAST_RUN_TIME])

    # In case we have existing last_run data
    if last_run.get(LAST_RUN_IDS) is None:
        last_run[LAST_RUN_IDS] = []

    return last_run


def fetch_last_emails(account, folder_name='Inbox', since_datetime=None, exclude_ids=None):
    qs = get_folder_by_path(account, folder_name, is_public=IS_PUBLIC_FOLDER)
    demisto.debug(f'since_datetime: {since_datetime}')
    if since_datetime:
        qs = qs.filter(datetime_received__gte=since_datetime)
    else:
        if not FETCH_ALL_HISTORY:
            tz = EWSTimeZone('UTC')
            first_fetch_datetime = dateparser.parse(FETCH_TIME)
            if not first_fetch_datetime:
                raise DemistoException('Failed to parse first last run time')
            first_fetch_ews_datetime = first_fetch_datetime.astimezone(tz)
            qs = qs.filter(datetime_received__gte=first_fetch_ews_datetime)
    qs = qs.filter().only(*[x.name for x in Message.FIELDS])
    qs = qs.filter().order_by('datetime_received')
    result = []
    exclude_ids = exclude_ids if exclude_ids else set()
    demisto.debug(f'Exclude ID list: {exclude_ids}')

    for item in qs:
        demisto.debug('Looking on subject={}, message_id={}, created={}, received={}'.format(
            item.subject, item.message_id, item.datetime_created, item.datetime_received))
        try:
            if isinstance(item, Message) and item.message_id not in exclude_ids:
                result.append(item)
                demisto.debug(f'Appending {item.subject}, {item.message_id}.')
                if len(result) >= MAX_FETCH:
                    break
        except ValueError as exc:
            future_utils.raise_from(ValueError(
                'Got an error when pulling incidents. You might be using the wrong exchange version.'
            ), exc)
            raise exc
    demisto.debug(f'EWS V2 - Got total of {len(result)} from ews query. ')
    return result


def keys_to_camel_case(value):
    def str_to_camel_case(snake_str):
        # Add condtion as Email object arrived in list and raised error
        if not isinstance(snake_str, str):
            return snake_str
        components = snake_str.split('_')
        return components[0] + "".join(x.title() for x in components[1:])

    if value is None:
        return None
    if isinstance(value, list | set):
        return [keys_to_camel_case(v) for v in value]
    if isinstance(value, dict):
        return {keys_to_camel_case(k): keys_to_camel_case(v) if isinstance(v, list | dict) else v
                for (k, v) in list(value.items())}

    return str_to_camel_case(value)


def email_ec(item):
    return {
        'CC': None if not item.cc_recipients else [mailbox.email_address for mailbox in item.cc_recipients],
        'BCC': None if not item.bcc_recipients else [mailbox.email_address for mailbox in item.bcc_recipients],
        'To': None if not item.to_recipients else [mailbox.email_address for mailbox in item.to_recipients],
        'From': item.author.email_address,
        'Subject': item.subject,
        'Text': item.text_body,
        'HTML': item.body,
        'HeadersMap': {} if not item.headers else {header.name: header.value for header in item.headers},
    }


def parse_object_as_dict_with_serialized_items(object):
    raw_dict = {}
    if object is not None:
        for field in object.FIELDS:
            try:
                v = getattr(object, field.name, None)
                if v is not None:
                    json.dumps(v)
                    raw_dict[field.name] = v
            except (TypeError, OverflowError):
                demisto.debug(f'Data in field {field.name} is not serilizable, skipped field')
                continue
    return raw_dict


def parse_item_as_dict(item, email_address, camel_case=False, compact_fields=False):  # pragma: no cover
    def parse_object_as_dict(object):
        raw_dict = {}
        if object is not None:
            for field in object.FIELDS:
                raw_dict[field.name] = getattr(object, field.name, None)
        return raw_dict

    def parse_attachment_as_raw_json(attachment):
        raw_dict = parse_object_as_dict(attachment)
        if raw_dict['attachment_id']:
            raw_dict['attachment_id'] = parse_object_as_dict(raw_dict['attachment_id'])
        if raw_dict['last_modified_time']:
            raw_dict['last_modified_time'] = raw_dict['last_modified_time'].ewsformat()
        return raw_dict

    def parse_folder_as_json(folder):  # pragma: no cover
        raw_dict = parse_object_as_dict(folder)
        if 'parent_folder_id' in raw_dict:
            raw_dict['parent_folder_id'] = parse_folder_as_json(raw_dict['parent_folder_id'])
        if 'effective_rights' in raw_dict:
            raw_dict['effective_rights'] = parse_object_as_dict(raw_dict['effective_rights'])
        return raw_dict

    raw_dict = parse_object_as_dict_with_serialized_items(item)

    if getattr(item, 'attachments', None):
        raw_dict['attachments'] = [parse_attachment_as_dict(item.id, x) for x in item.attachments]

    for time_field in ['datetime_sent', 'datetime_created', 'datetime_received', 'last_modified_time',
                       'reminder_due_by']:
        value = getattr(item, time_field, None)
        if value:
            raw_dict[time_field] = value.ewsformat()

    for dict_field in ['effective_rights', 'parent_folder_id', 'conversation_id', 'author',
                       'extern_id', 'received_by', 'received_representing', 'reply_to', 'sender', 'folder']:
        value = getattr(item, dict_field, None)
        if value:
            if type(value) is list:
                raw_dict[dict_field] = [parse_object_as_dict(x) for x in value]
            else:
                raw_dict[dict_field] = parse_object_as_dict(value)

    for list_dict_field in ['headers', 'cc_recipients', 'to_recipients']:
        value = getattr(item, list_dict_field, None)
        if value:
            raw_dict[list_dict_field] = [parse_object_as_dict(x) for x in value]

    for list_str_field in ["categories"]:
        value = getattr(item, list_str_field, None)
        if value:
            raw_dict[list_str_field] = value

    if getattr(item, 'folder', None):
        raw_dict['folder'] = parse_folder_as_json(item.folder)
        folder_path = item.folder.absolute[len(TOIS_PATH):] if item.folder.absolute.startswith(
            TOIS_PATH) else item.folder.absolute
        raw_dict['folder_path'] = folder_path

    raw_dict['item_id'] = getattr(item, 'id', None)
    raw_dict['id'] = getattr(item, 'id', None)

    if compact_fields:
        new_dict = {}
        fields_list = ['datetime_created', 'datetime_received', 'datetime_sent', 'sender',
                       'has_attachments', 'importance', 'message_id', 'last_modified_time',
                       'size', 'subject', 'text_body', 'headers', 'body', 'folder_path', 'is_read', 'categories']

        fields_list.append('item_id')

        for field in fields_list:
            if field in raw_dict:
                new_dict[field] = raw_dict.get(field)
        for field in ['received_by', 'author', 'sender']:
            if field in raw_dict:
                new_dict[field] = raw_dict.get(field, {}).get('email_address')
        for field in ['to_recipients']:
            if field in raw_dict:
                new_dict[field] = [x.get('email_address') for x in raw_dict[field]]
        attachments = raw_dict.get('attachments')
        if attachments and len(attachments) > 0:
            file_attachments = [x for x in attachments if x[ATTACHMENT_TYPE] == FILE_ATTACHMENT_TYPE]
            if len(file_attachments) > 0:
                new_dict['FileAttachments'] = file_attachments
            item_attachments = [x for x in attachments if x[ATTACHMENT_TYPE] == ITEM_ATTACHMENT_TYPE]
            if len(item_attachments) > 0:
                new_dict['ItemAttachments'] = item_attachments
        raw_dict = new_dict

    if camel_case:
        raw_dict = keys_to_camel_case(raw_dict)

    if email_address:
        raw_dict[MAILBOX] = email_address
    return raw_dict


def parse_incident_from_item(item, is_fetch):  # pragma: no cover
    incident = {}
    labels = []

    try:
        try:
            incident['details'] = item.text_body or item.body
        except AttributeError:
            incident['details'] = item.body

        incident['name'] = item.subject
        labels.append({'type': 'Email/subject', 'value': item.subject})
        incident['occurred'] = item.datetime_created.ewsformat()

        # handle recipients
        if item.to_recipients:
            for recipient in item.to_recipients:
                labels.append({'type': 'Email', 'value': recipient.email_address})

        # handle cc
        if item.cc_recipients:
            for recipient in item.cc_recipients:
                labels.append({'type': 'Email/cc', 'value': recipient.email_address})
        # handle email from
        if item.sender:
            labels.append({'type': 'Email/from', 'value': item.sender.email_address})

        # email format
        email_format = ''
        try:
            if item.text_body:
                labels.append({'type': 'Email/text', 'value': item.text_body})
                email_format = 'text'
        except AttributeError:
            pass
        if item.body:
            labels.append({'type': 'Email/html', 'value': item.body})
            email_format = 'HTML'
        labels.append({'type': 'Email/format', 'value': email_format})

        # handle attachments
        if item.attachments:
            incident['attachment'] = []
            for attachment in item.attachments:
                if attachment is not None:
                    attachment.parent_item = item
                    file_result = None
                    label_attachment_type = None
                    label_attachment_id_type = None
                    if isinstance(attachment, FileAttachment):
                        try:
                            if attachment.content:
                                # file attachment
                                label_attachment_type = 'attachments'
                                label_attachment_id_type = 'attachmentId'

                                # save the attachment
                                file_name = get_attachment_name(attachment.name)
                                file_result = fileResult(file_name, attachment.content)

                                # check for error
                                if file_result['Type'] == entryTypes['error']:
                                    demisto.error(file_result['Contents'])
                                    raise Exception(file_result['Contents'])

                                # save attachment to incident
                                incident['attachment'].append({
                                    'path': file_result['FileID'],
                                    'name': get_attachment_name(attachment.name)
                                })
                        except TypeError as e:
                            if str(e) != "must be string or buffer, not None":
                                raise
                            continue
                    else:
                        # other item attachment
                        label_attachment_type = 'attachmentItems'
                        label_attachment_id_type = 'attachmentItemsId'

                        # save the attachment
                        if hasattr(attachment, 'item') and attachment.item.mime_content:
                            # Some items arrive with bytes attachemnt
                            if isinstance(attachment.item.mime_content, bytes):
                                attached_email = email.message_from_bytes(attachment.item.mime_content)
                            else:
                                attached_email = email.message_from_string(attachment.item.mime_content)
                            if attachment.item.headers:
                                attached_email_headers = []
                                for h, v in list(attached_email.items()):
                                    if not isinstance(v, str):
                                        try:
                                            v = str(v)
                                        except:  # noqa: E722
                                            demisto.debug(f'cannot parse the header "{h}"')
                                            continue

                                    v = ' '.join(map(str.strip, v.split('\r\n')))
                                    attached_email_headers.append((h, v))

                                for header in attachment.item.headers:
                                    if (header.name, header.value) not in attached_email_headers \
                                       and header.name != 'Content-Type':
                                        attached_email.add_header(header.name, header.value)

                            file_result = fileResult(get_attachment_name(attachment.name) + ".eml",
                                                     attached_email.as_string())

                        if file_result:
                            # check for error
                            if file_result['Type'] == entryTypes['error']:
                                demisto.error(file_result['Contents'])
                                raise Exception(file_result['Contents'])

                            # save attachment to incident
                            incident['attachment'].append({
                                'path': file_result['FileID'],
                                'name': get_attachment_name(attachment.name) + ".eml"
                            })

                        else:
                            incident['attachment'].append({
                                'name': get_attachment_name(attachment.name) + ".eml"
                            })

                    labels.append({'type': label_attachment_type, 'value': get_attachment_name(attachment.name)})
                    labels.append({'type': label_attachment_id_type, 'value': attachment.attachment_id.id})

        # handle headers
        if item.headers:
            headers = []
            for header in item.headers:
                labels.append({'type': f'Email/Header/{header.name}', 'value': str(header.value)})
                headers.append(f"{header.name}: {header.value}")
            labels.append({'type': 'Email/headers', 'value': "\r\n".join(headers)})

        # handle item id
        if item.message_id:
            labels.append({'type': 'Email/MessageId', 'value': str(item.message_id)})
            # fetch history
            incident['dbotMirrorId'] = str(item.message_id)

        if item.id:
            labels.append({'type': 'Email/ID', 'value': item.id})
            labels.append({'type': 'Email/itemId', 'value': item.id})

        # handle conversion id
        if item.conversation_id:
            labels.append({'type': 'Email/ConversionID', 'value': item.conversation_id.id})

        if MARK_AS_READ and is_fetch:
            item.is_read = True
            try:
                item.save()
            except ErrorIrresolvableConflict:
                time.sleep(0.5)
                item.save()
            except ValueError as e:
                if item.subject and len(item.subject) > 255:
                    demisto.debug("Length of message subject is greater than 255, item.save could not handle it, "
                                  "cutting the subject.")
                    sub_subject = "Length of subject greater than 255 characters. " \
                                  "Partial subject: {}".format(item.subject[:180])
                    item.subject = sub_subject
                    item.save()
                else:
                    raise e

        incident['labels'] = labels
        incident['rawJSON'] = json.dumps(parse_item_as_dict(item, None), ensure_ascii=False)

    except Exception as e:
        if 'Message is not decoded yet' in str(e):
            demisto.debug('EWS v2 - Skipped a protected message')
            return None
        else:
            raise e

    return incident


def fetch_emails_as_incidents(account_email, folder_name):
    last_run = get_last_run()
    excluded_ids = set(last_run.get(LAST_RUN_IDS, []))

    try:
        account = get_account(account_email)
        last_emails = fetch_last_emails(account, folder_name, last_run.get(LAST_RUN_TIME), last_run.get(LAST_RUN_IDS))

        incidents = []
        incident = {}  # type: Dict[Any, Any]
        current_fetch_ids = set()
        last_incident_run_time = None

        for item in last_emails:
            if item.message_id:
                current_fetch_ids.add(item.message_id)
                incident = parse_incident_from_item(item, True)
                demisto.debug(f'Parsed incident: {item.message_id}')
                if incident:
                    incidents.append(incident)
                    last_incident_run_time = item.datetime_received
                    demisto.debug(f'Appended incident: {item.message_id}')

                if len(incidents) >= MAX_FETCH:
                    break

        demisto.debug(f'EWS V2 - ending fetch - got {len(incidents)} incidents.')
        last_fetch_time = last_run.get(LAST_RUN_TIME)
        last_incident_run_time = last_incident_run_time if last_incident_run_time else last_fetch_time

        # making sure both last fetch time and the time of last incident are the same type for comparing.
        if isinstance(last_incident_run_time, EWSDateTime):
            last_incident_run_time = last_incident_run_time.ewsformat()

        if isinstance(last_fetch_time, EWSDateTime):
            last_fetch_time = last_fetch_time.ewsformat()

        debug_msg = '#### last_incident_time: {}({}). last_fetch_time: {}({}) ####'
        demisto.debug(debug_msg.format(last_incident_run_time, type(last_incident_run_time),
                                       last_fetch_time, type(last_fetch_time)))

        # If the fetch query is not fully fetched (we didn't have any time progress) - then we keep the
        # id's from current fetch until progress is made. This is for when max_fetch < incidents_from_query.
        if not last_incident_run_time or not last_fetch_time or last_incident_run_time > last_fetch_time:
            ids = current_fetch_ids
        else:
            ids = current_fetch_ids | excluded_ids
        new_last_run = {
            LAST_RUN_TIME: last_incident_run_time,
            LAST_RUN_FOLDER: folder_name,
            LAST_RUN_IDS: list(ids),
            ERROR_COUNTER: 0,
        }

        demisto.setLastRun(new_last_run)
        return incidents

    except RateLimitError:
        if LAST_RUN_TIME in last_run:
            last_run[LAST_RUN_TIME] = last_run[LAST_RUN_TIME].ewsformat()
        if ERROR_COUNTER not in last_run:
            last_run[ERROR_COUNTER] = 0
        last_run[ERROR_COUNTER] += 1
        demisto.setLastRun(last_run)
        if last_run[ERROR_COUNTER] > 2:
            raise
        return []


def get_entry_for_file_attachment(item_id, attachment):  # pragma: no cover
    entry = fileResult(get_attachment_name(attachment.name), attachment.content)
    ec = {
        CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT + CONTEXT_UPDATE_FILE_ATTACHMENT: parse_attachment_as_dict(item_id,
                                                                                                          attachment)
    }
    entry[ENTRY_CONTEXT] = filter_dict_null(ec)
    return entry


def parse_attachment_as_dict(item_id, attachment):  # pragma: no cover
    try:
        # if this is a file attachment or a non-empty email attachment
        if isinstance(attachment, FileAttachment) or hasattr(attachment, 'item'):
            attachment_content = attachment.content if isinstance(attachment, FileAttachment) \
                else attachment.item.mime_content

            return {
                ATTACHMENT_ORIGINAL_ITEM_ID: item_id,
                ATTACHMENT_ID: attachment.attachment_id.id,
                'attachmentName': get_attachment_name(attachment.name),
                'attachmentSHA256': hashlib.sha256(attachment_content).hexdigest() if attachment_content else None,
                'attachmentContentType': attachment.content_type,
                'attachmentContentId': attachment.content_id,
                'attachmentContentLocation': attachment.content_location,
                'attachmentSize': attachment.size,
                'attachmentLastModifiedTime': attachment.last_modified_time.ewsformat(),
                'attachmentIsInline': attachment.is_inline,
                ATTACHMENT_TYPE: FILE_ATTACHMENT_TYPE if isinstance(attachment, FileAttachment)
                else ITEM_ATTACHMENT_TYPE
            }

        # If this is an empty email attachment
        else:
            return {
                ATTACHMENT_ORIGINAL_ITEM_ID: item_id,
                ATTACHMENT_ID: attachment.attachment_id.id,
                'attachmentName': get_attachment_name(attachment.name),
                'attachmentSize': attachment.size,
                'attachmentLastModifiedTime': attachment.last_modified_time.ewsformat(),
                'attachmentIsInline': attachment.is_inline,
                ATTACHMENT_TYPE: FILE_ATTACHMENT_TYPE if isinstance(attachment, FileAttachment)
                else ITEM_ATTACHMENT_TYPE
            }

    except TypeError as e:
        if str(e) != "must be string or buffer, not None":
            raise
        return {
            ATTACHMENT_ORIGINAL_ITEM_ID: item_id,
            ATTACHMENT_ID: attachment.attachment_id.id,
            'attachmentName': get_attachment_name(attachment.name),
            'attachmentSHA256': None,
            'attachmentContentType': attachment.content_type,
            'attachmentContentId': attachment.content_id,
            'attachmentContentLocation': attachment.content_location,
            'attachmentSize': attachment.size,
            'attachmentLastModifiedTime': attachment.last_modified_time.ewsformat(),
            'attachmentIsInline': attachment.is_inline,
            ATTACHMENT_TYPE: FILE_ATTACHMENT_TYPE if isinstance(attachment, FileAttachment) else ITEM_ATTACHMENT_TYPE
        }


def get_entry_for_item_attachment(item_id, attachment, target_email):  # pragma: no cover
    item = attachment.item
    dict_result = parse_attachment_as_dict(item_id, attachment)
    dict_result.update(parse_item_as_dict(item, target_email, camel_case=True, compact_fields=True))
    title = f'EWS get attachment got item for "{target_email}", "{get_attachment_name(attachment.name)}"'

    return get_entry_for_object(title, CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT + CONTEXT_UPDATE_ITEM_ATTACHMENT,
                                dict_result)


def get_attachments_for_item(item_id, account, attachment_ids=None):  # pragma: no cover
    item = get_item_from_mailbox(account, item_id)
    attachments = []
    if attachment_ids and not isinstance(attachment_ids, list):
        attachment_ids = attachment_ids.split(",")
    if item:
        if item.attachments:
            for attachment in item.attachments:
                if attachment is not None:
                    attachment.parent_item = item
                    if attachment_ids and attachment.attachment_id.id not in attachment_ids:
                        continue
                    attachments.append(attachment)

    else:
        raise Exception('Message item not found: ' + item_id)

    if attachment_ids and len(attachments) < len(attachment_ids):
        raise Exception('Some attachment id did not found for message:' + str(attachment_ids))

    return attachments


def delete_attachments_for_message(item_id, target_mailbox=None, attachment_ids=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    attachments = get_attachments_for_item(item_id, account, attachment_ids)
    deleted_file_attachments = []
    deleted_item_attachments = []  # type: ignore
    for attachment in attachments:
        attachment_deleted_action = {
            ATTACHMENT_ID: attachment.attachment_id.id,
            ACTION: 'deleted'
        }
        if isinstance(attachment, FileAttachment):
            deleted_file_attachments.append(attachment_deleted_action)
        else:
            deleted_item_attachments.append(attachment_deleted_action)
        attachment.detach()

    entries = []
    if len(deleted_file_attachments) > 0:
        entry = get_entry_for_object("Deleted file attachments",
                                     "EWS.Items" + CONTEXT_UPDATE_FILE_ATTACHMENT,
                                     deleted_file_attachments)
        entries.append(entry)
    if len(deleted_item_attachments) > 0:
        entry = get_entry_for_object("Deleted item attachments",
                                     "EWS.Items" + CONTEXT_UPDATE_ITEM_ATTACHMENT,
                                     deleted_item_attachments)
        entries.append(entry)

    return entries


def fetch_attachments_for_message(item_id, target_mailbox=None, attachment_ids=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    attachments = get_attachments_for_item(item_id, account, attachment_ids)
    entries = []
    for attachment in attachments:
        if isinstance(attachment, FileAttachment):
            try:
                if attachment.content:
                    entries.append(get_entry_for_file_attachment(item_id, attachment))
            except TypeError as e:
                if str(e) != "must be string or buffer, not None":
                    raise
        else:
            entries.append(get_entry_for_item_attachment(item_id, attachment, account.primary_smtp_address))
            if attachment.item.mime_content:
                entries.append(fileResult(get_attachment_name(attachment.name) + ".eml", attachment.item.mime_content))

    return entries


def move_item_between_mailboxes(item_id, destination_mailbox, destination_folder_path, source_mailbox=None,
                                is_public=None):  # pragma: no cover
    source_account = get_account(source_mailbox or ACCOUNT_EMAIL)
    destination_account = get_account(destination_mailbox or ACCOUNT_EMAIL)
    is_public = is_default_folder(destination_folder_path, is_public)
    destination_folder = get_folder_by_path(destination_account, destination_folder_path, is_public)
    item = get_item_from_mailbox(source_account, item_id)

    exported_items = source_account.export([item])
    destination_account.upload([(destination_folder, exported_items[0])])
    source_account.bulk_delete([item])

    move_result = {
        MOVED_TO_MAILBOX: destination_mailbox,
        MOVED_TO_FOLDER: destination_folder_path,
    }

    return {
        'Type': entryTypes['note'],
        'Contents': "Item was moved successfully.",
        'ContentsFormat': formats['text'],
        ENTRY_CONTEXT: {
            f"EWS.Items(val.itemId === '{item_id}')": move_result
        }
    }


def move_item(item_id, target_folder_path, target_mailbox=None, is_public=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    is_public = is_default_folder(target_folder_path, is_public)
    target_folder = get_folder_by_path(account, target_folder_path, is_public)
    item = get_item_from_mailbox(account, item_id)
    if isinstance(item, ErrorInvalidIdMalformed):
        raise Exception("Item not found")
    item.move(target_folder)
    move_result = {
        NEW_ITEM_ID: item.id,
        ITEM_ID: item_id,
        MESSAGE_ID: item.message_id,
        ACTION: 'moved'
    }

    return get_entry_for_object('Moved items',
                                CONTEXT_UPDATE_EWS_ITEM,
                                move_result)


def delete_items(item_ids, delete_type, target_mailbox=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    deleted_items = []
    if type(item_ids) != list:
        item_ids = item_ids.split(",")
    items = get_items_from_mailbox(account, item_ids)
    delete_type = delete_type.lower()

    for item in items:
        item_id = item.id
        if delete_type == 'trash':
            item.move_to_trash()
        elif delete_type == 'soft':
            item.soft_delete()
        elif delete_type == 'hard':
            item.delete()
        else:
            raise Exception('invalid delete type: %s. Use "trash" \\ "soft" \\ "hard"' % delete_type)
        deleted_items.append({
            ITEM_ID: item_id,
            MESSAGE_ID: item.message_id,
            ACTION: '%s-deleted' % delete_type
        })

    return get_entry_for_object('Deleted items (%s delete type)' % delete_type,
                                CONTEXT_UPDATE_EWS_ITEM,
                                deleted_items)


def prepare_args(d):  # pragma: no cover
    d = {k.replace("-", "_"): v for k, v in list(d.items())}
    if 'is_public' in d:
        d['is_public'] = d['is_public'] == 'True'
    return d


def get_limited_number_of_messages_from_qs(qs, limit):  # pragma: no cover
    count = 0
    results = []
    for item in qs:
        if count == limit:
            break
        if isinstance(item, Message):
            count += 1
            results.append(item)
    return results


def search_items_in_mailbox(query=None, message_id=None, folder_path='', limit=100, target_mailbox=None,
                            is_public=None, selected_fields='all'):  # pragma: no cover
    if not query and not message_id:
        return_error("Missing required argument. Provide query or message-id")

    if message_id and message_id[0] != '<' and message_id[-1] != '>':
        message_id = f'<{message_id}>'

    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    limit = int(limit)
    if folder_path.lower() == 'inbox':
        folders = [account.inbox]
    elif folder_path:
        is_public = is_default_folder(folder_path, is_public)
        folders = [get_folder_by_path(account, folder_path, is_public)]
    else:
        folders = account.inbox.parent.walk()  # pylint: disable=E1101

    items = []  # type: ignore
    selected_all_fields = (selected_fields == 'all')

    if selected_all_fields:
        restricted_fields = {x.name for x in Message.FIELDS}  # type: ignore
    else:
        restricted_fields = set(argToList(selected_fields))  # type: ignore
        restricted_fields.update(['id', 'message_id'])  # type: ignore

    for folder in folders:
        if Message not in folder.supported_item_models:
            continue
        if query:
            items_qs = folder.filter(query).only(*restricted_fields)
        else:
            items_qs = folder.filter(message_id=message_id).only(*restricted_fields)
        items += get_limited_number_of_messages_from_qs(items_qs, limit)
        if len(items) >= limit:
            break

    items = items[:limit]
    searched_items_result = [parse_item_as_dict(item, account.primary_smtp_address, camel_case=True,
                                                compact_fields=selected_all_fields) for item in items]

    if not selected_all_fields:
        # we show id as 'itemId' for BC
        restricted_fields.remove('id')
        restricted_fields.add('itemId')
        searched_items_result = [
            {k: v for (k, v) in i.items()
             if k in keys_to_camel_case(restricted_fields)} for i in searched_items_result]

    return get_entry_for_object('Searched items',
                                CONTEXT_UPDATE_EWS_ITEM,
                                searched_items_result,
                                headers=ITEMS_RESULTS_HEADERS if selected_all_fields else None)


def get_out_of_office_state(target_mailbox=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    oof = account.oof_settings
    oof_dict = {
        'state': oof.state,  # pylint: disable=E1101
        'externalAudience': getattr(oof, 'external_audience', None),
        'start': oof.start.ewsformat() if oof.start else None,  # pylint: disable=E1101
        'end': oof.end.ewsformat() if oof.end else None,  # pylint: disable=E1101
        'internalReply': getattr(oof, 'internal_replay', None),
        'externalReply': getattr(oof, 'external_replay', None),
        MAILBOX: account.primary_smtp_address
    }
    return get_entry_for_object("Out of office state for %s" % account.primary_smtp_address,
                                f'Account.Email(val.Address == obj.{MAILBOX}).OutOfOffice',
                                oof_dict)


def recover_soft_delete_item(message_ids, target_folder_path="Inbox", target_mailbox=None, is_public=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    is_public = is_default_folder(target_folder_path, is_public)
    target_folder = get_folder_by_path(account, target_folder_path, is_public)
    recovered_messages = []
    if type(message_ids) != list:
        message_ids = message_ids.split(",")
    items_to_recover = account.recoverable_items_deletions.filter(  # pylint: disable=E1101
        message_id__in=message_ids).all()  # pylint: disable=E1101
    if items_to_recover.count() != len(message_ids):
        raise Exception("Some message ids are missing in recoverable items directory")
    for item in items_to_recover:
        item.move(target_folder)
        recovered_messages.append({
            ITEM_ID: item.id,
            MESSAGE_ID: item.message_id,
            ACTION: 'recovered'
        })
    return get_entry_for_object("Recovered messages",
                                CONTEXT_UPDATE_EWS_ITEM,
                                recovered_messages)


def get_contacts(limit, target_mailbox=None):  # pragma: no cover
    def parse_physical_address(address):
        result = {}
        for attr in ['city', 'country', 'label', 'state', 'street', 'zipcode']:
            result[attr] = getattr(address, attr, None)
        return result

    def parse_phone_number(phone_number):
        result = {}
        for attr in ['label', 'phone_number']:
            result[attr] = getattr(phone_number, attr, None)
        return result

    def is_jsonable(x):
        try:
            json.dumps(x)
            return True
        except Exception:
            return False

    def parse_contact(contact):
        contact_dict = parse_object_as_dict_with_serialized_items(contact)
        for k in contact_dict:
            v = contact_dict[k]
            if isinstance(v, EWSDateTime):
                contact_dict[k] = v.ewsformat()  # pylint: disable=E4702

        contact_dict['id'] = contact.id
        if isinstance(contact, Contact) and contact.physical_addresses:
            contact_dict['physical_addresses'] = list(map(parse_physical_address, contact.physical_addresses))
        if isinstance(contact, Contact) and contact.phone_numbers:
            contact_dict['phone_numbers'] = list(map(parse_phone_number, contact.phone_numbers))
        if isinstance(contact, Contact) and contact.email_addresses and len(contact.email_addresses) > 0:
            contact_dict['emailAddresses'] = [x.email for x in contact.email_addresses]
        contact_dict = keys_to_camel_case(contact_dict)
        contact_dict = {k: v for k, v in contact_dict.items() if (v and is_jsonable(v))}
        contact_dict['originMailbox'] = target_mailbox
        return contact_dict

    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    contacts = []

    for contact in account.contacts.all()[:int(limit)]:  # pylint: disable=E1101
        contacts.append(parse_contact(contact))
    return get_entry_for_object(f'Email contacts for {target_mailbox or ACCOUNT_EMAIL}',
                                'Account.Email(val.Address == obj.originMailbox).EwsContacts',
                                contacts)


def create_folder(new_folder_name, folder_path, target_mailbox=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    full_path = f"{folder_path}\\{new_folder_name}"
    try:
        if get_folder_by_path(account, full_path):
            return "Folder %s already exists" % full_path
    except Exception:
        pass
    parent_folder = get_folder_by_path(account, folder_path)
    f = Folder(parent=parent_folder, name=new_folder_name)
    f.save()
    get_folder_by_path(account, full_path)
    return "Folder %s created successfully" % full_path


def find_folders(target_mailbox=None, is_public=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    root = account.root
    if is_public:
        root = account.public_folders_root
    folders = []
    for f in root.walk():  # pylint: disable=E1101
        folder = folder_to_context_entry(f)
        folders.append(folder)
    folders_tree = root.tree()  # pylint: disable=E1101

    return {
        'Type': entryTypes['note'],
        'Contents': folders,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': folders_tree,
        ENTRY_CONTEXT: {
            'EWS.Folders(val.id == obj.id)': folders
        }
    }


def mark_item_as_junk(item_id, move_items, target_mailbox=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    move_items = (move_items.lower() == "yes")
    ews_result = MarkAsJunk(account=account).call(item_id=item_id, move_item=move_items)
    mark_as_junk_result = {
        ITEM_ID: item_id,
    }
    if ews_result == "Success":
        mark_as_junk_result[ACTION] = 'marked-as-junk'
    else:
        raise Exception("Failed mark-item-as-junk with error: " + ews_result)

    return get_entry_for_object('Mark item as junk',
                                CONTEXT_UPDATE_EWS_ITEM,
                                mark_as_junk_result)


def get_items_from_folder(folder_path, limit=100, target_mailbox=None, is_public=None,
                          get_internal_item='no'):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    limit = int(limit)
    get_internal_item = (get_internal_item == 'yes')
    is_public = is_default_folder(folder_path, is_public)
    folder = get_folder_by_path(account, folder_path, is_public)
    qs = folder.filter().order_by('-datetime_created')[:limit]
    items = get_limited_number_of_messages_from_qs(qs, limit)
    items_result = []

    for item in items:
        item_attachment = parse_item_as_dict(item, account.primary_smtp_address, camel_case=True,
                                             compact_fields=True)

        for attachment in item.attachments:
            if attachment is not None:
                attachment.parent_item = item
                if get_internal_item and isinstance(attachment, ItemAttachment) and isinstance(attachment.item,
                                                                                               Message):
                    # if found item attachment - switch item to the attchment
                    item_attachment = parse_item_as_dict(attachment.item, account.primary_smtp_address, camel_case=True,
                                                         compact_fields=True)
                    break

        items_result.append(item_attachment)
    hm_headers = ['sender', 'subject', 'hasAttachments', 'datetimeReceived',
                  'receivedBy', 'author', 'toRecipients', 'itemId']
    return get_entry_for_object('Items in folder ' + folder_path,
                                CONTEXT_UPDATE_EWS_ITEM,
                                items_result,
                                headers=hm_headers)


def get_items(item_ids, target_mailbox=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    if type(item_ids) != list:
        item_ids = item_ids.split(",")

    items = get_items_from_mailbox(account, item_ids)
    items = [x for x in items if isinstance(x, Message)]
    items_as_incidents = [parse_incident_from_item(x, False) for x in items]
    items_to_context = [parse_item_as_dict(x, account.primary_smtp_address, True, True) for x in items]

    return {
        'Type': entryTypes['note'],
        'Contents': items_as_incidents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Get items', items_to_context, ITEMS_RESULTS_HEADERS),
        ENTRY_CONTEXT: {
            CONTEXT_UPDATE_EWS_ITEM: items_to_context,
            'Email': [email_ec(item) for item in items],
        }
    }


def get_folder(folder_path, target_mailbox=None, is_public=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    is_public = is_default_folder(folder_path, is_public)
    folder = folder_to_context_entry(get_folder_by_path(account, folder_path, is_public))
    return get_entry_for_object(f"Folder {folder_path}", CONTEXT_UPDATE_FOLDER, folder)


def folder_to_context_entry(f):
    f_entry = {
        'name': f.name,
        'totalCount': f.total_count,
        'id': f.id,
        'childrenFolderCount': f.child_folder_count,
        'changeKey': f.changekey
    }

    if 'unread_count' in [x.name for x in Folder.FIELDS]:
        f_entry['unreadCount'] = f.unread_count
    return f_entry


def check_cs_prereqs():  # pragma: no cover
    if 'outlook.office365.com' not in EWS_SERVER:
        raise Exception("This command is only supported for Office 365")


def get_cs_error(stderr):
    return {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": stderr
    } if stderr else None


def get_cs_status(search_name, status):
    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Search {search_name} status: {status}',
        'EntryContext': {
            'EWS.ComplianceSearch(val.Name === obj.Name)': {'Name': search_name, 'Status': status}
        }
    }


def start_compliance_search(query):  # pragma: no cover
    check_cs_prereqs()
    try:
        with open("startcompliancesearch2.ps1", "w+") as f:
            f.write(START_COMPLIANCE)

        output = subprocess.Popen(["pwsh", "startcompliancesearch2.ps1", USERNAME, query],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8')

        stdout, stderr = output.communicate(input=PASSWORD)

    finally:
        os.remove("startcompliancesearch2.ps1")

    if stderr:
        return get_cs_error(stderr)

    prefix = '"Action status: '
    pref_ind = stdout.find(prefix)
    sub_start = pref_ind + len(prefix)
    sub_end = sub_start + 45
    search_name = stdout[sub_start:sub_end]

    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Search started: {search_name!r}',
        'EntryContext': {
            'EWS.ComplianceSearch': {'Name': search_name, 'Status': 'Starting'}
        }
    }


def get_compliance_search(search_name, show_only_recipients):  # pragma: no cover
    check_cs_prereqs()
    try:
        with open("getcompliancesearch2.ps1", "w+") as f:
            f.write(GET_COMPLIANCE)

        output = subprocess.Popen(["pwsh", "getcompliancesearch2.ps1", USERNAME, search_name],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8')
        stdout, stderr = output.communicate(input=PASSWORD)

    finally:
        os.remove("getcompliancesearch2.ps1")

    if stderr:
        return get_cs_error(stderr)

    # Get search status
    stdout = stdout[len(PASSWORD):]
    stdout = stdout.split('\n', 1)  # type: ignore

    results = [get_cs_status(search_name, stdout[0])]

    # Parse search results from script output if the search has completed. Output to warroom as table.
    if stdout[0] == 'Completed':
        if stdout[1] and stdout[1] != '{}':
            res = [r[:-1].split(', ') if r[-1] == ',' else r.split(', ') for r in stdout[1][2:-3].split(r'\r\n')]
            res = [dict(s.split(': ') for s in x) for x in res]
            entry = {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['text'],
                'Contents': stdout,
                'ReadableContentsFormat': formats['markdown'],
            }
            if show_only_recipients == 'True':
                res = [x for x in res if int(x['Item count']) > 0]

                entry['EntryContext'] = {
                    'EWS.ComplianceSearch(val.Name == obj.Name)': {
                        'Name': search_name,
                        'Results': res
                    }
                }

            entry['HumanReadable'] = tableToMarkdown('Office 365 Compliance search results', res,
                                                     ['Location', 'Item count', 'Total size'])
        else:
            entry = {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['text'],
                'Contents': stdout,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': "The compliance search didn't return any results."
            }

        results.append(entry)
    return results


def purge_compliance_search(search_name):  # pragma: no cover
    check_cs_prereqs()
    try:
        with open("purgecompliancesearch2.ps1", "w+") as f:
            f.write(PURGE_COMPLIANCE)

        output = subprocess.Popen(["pwsh", "purgecompliancesearch2.ps1", USERNAME, search_name],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8')
        _, stderr = output.communicate(input=PASSWORD)

    finally:
        os.remove("purgecompliancesearch2.ps1")

    if stderr:
        return get_cs_error(stderr)

    return get_cs_status(search_name, 'Purging')


def check_purge_compliance_search(search_name):  # pragma: no cover
    check_cs_prereqs()
    try:
        with open("purgestatuscompliancesearch2.ps1", "w+") as f:
            f.write(PURGE_STATUS_COMPLIANCE)

        output = subprocess.Popen(["pwsh", "purgestatuscompliancesearch2.ps1", USERNAME, search_name],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8')
        stdout, stderr = output.communicate(input=PASSWORD)

        stdout = stdout[len(PASSWORD):]

    finally:
        os.remove("purgestatuscompliancesearch2.ps1")

    if stderr:
        return get_cs_error(stderr)

    return get_cs_status(search_name, 'Purged' if stdout.split('\n')[-2] == 'Completed' else 'Purging')


def remove_compliance_search(search_name):  # pragma: no cover
    check_cs_prereqs()
    try:
        with open("removecompliance2.ps1", "w+") as f:
            f.write(REMOVE_COMPLIANCE)

        output = subprocess.Popen(
            ["pwsh", "removecompliance2.ps1", USERNAME, search_name],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf8')
        stdout, stderr = output.communicate(input=PASSWORD)

    finally:
        os.remove("removecompliance2.ps1")

    if stderr:
        return get_cs_error(stderr)

    return get_cs_status(search_name, 'Removed')


def get_autodiscovery_config():  # pragma: no cover
    config_dict = demisto.getIntegrationContext()
    return {
        'Type': entryTypes['note'],
        'Contents': config_dict,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Auto-Discovery Exchange Configuration', config_dict)
    }


def mark_item_as_read(item_ids, operation='read', target_mailbox=None):  # pragma: no cover
    marked_items = []
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    item_ids = argToList(item_ids)
    items = get_items_from_mailbox(account, item_ids)
    items = [x for x in items if isinstance(x, Message)]

    for item in items:
        item.is_read = (operation == 'read')
        item.save()

        marked_items.append({
            ITEM_ID: item.id,
            MESSAGE_ID: item.message_id,
            ACTION: f'marked-as-{operation}'
        })

    return get_entry_for_object(f'Marked items ({operation} marked operation)',
                                CONTEXT_UPDATE_EWS_ITEM,
                                marked_items)


def get_item_as_eml(item_id, target_mailbox=None):  # pragma: no cover
    account = get_account(target_mailbox or ACCOUNT_EMAIL)
    item = get_item_from_mailbox(account, item_id)

    if item.mime_content:
        # came across an item with bytes attachemnt which failed in the source code, added this to keep functionality
        if isinstance(item.mime_content, bytes):
            email_content = email.message_from_bytes(item.mime_content)
        else:
            email_content = email.message_from_string(item.mime_content)
        if item.headers:
            attached_email_headers = []
            for h, v in list(email_content.items()):
                if not isinstance(v, str):
                    try:
                        v = str(v)
                    except:  # noqa: E722
                        demisto.debug(f'cannot parse the header "{h}"')

                v = ' '.join(map(str.strip, v.split('\r\n')))
                attached_email_headers.append((h, v))
            for header in item.headers:
                if (header.name, header.value) not in attached_email_headers and header.name != 'Content-Type':
                    email_content.add_header(header.name, header.value)

        eml_name = item.subject if item.subject else 'demisto_untitled_eml'
        file_result = fileResult(eml_name + ".eml", email_content.as_string())
        file_result = file_result if file_result else "Failed uploading eml file to war room"

        return file_result
    return None


def collect_manual_attachments(manual_attach_obj):  # pragma: no cover
    attachments = []
    for attachment in manual_attach_obj:
        res = demisto.getFilePath(os.path.basename(attachment['RealFileName']))

        file_path = res["path"]
        with open(file_path, 'rb') as f:
            attachments.append(FileAttachment(content=f.read(), name=attachment['FileName']))

    return attachments


def process_attachments(attach_cids="", attach_ids="", attach_names="", manual_attach_obj=None):  # pragma: no cover
    if manual_attach_obj is None:
        manual_attach_obj = []
    file_entries_for_attachments = []  # type: list
    attachments_names = []  # type: list

    if attach_ids:
        file_entries_for_attachments = attach_ids if isinstance(attach_ids, list) else attach_ids.split(",")
        if attach_names:
            attachments_names = attach_names if isinstance(attach_names, list) else attach_names.split(",")
        else:
            for att_id in file_entries_for_attachments:
                att_name = demisto.getFilePath(att_id)['name']
                if isinstance(att_name, list):
                    att_name = att_name[0]
                attachments_names.append(att_name)
        if len(file_entries_for_attachments) != len(attachments_names):
            raise Exception("attachIDs and attachNames lists should be the same length")

    attachments = collect_manual_attachments(manual_attach_obj)

    if attach_cids:
        file_entries_for_attachments_inline = attach_cids if isinstance(attach_cids, list) else attach_cids.split(",")
        for att_id_inline in file_entries_for_attachments_inline:
            try:
                file_info = demisto.getFilePath(att_id_inline)
            except Exception as ex:
                demisto.info(f"EWS error from getFilePath: {ex}")
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
            raise Exception(f"entry {entry_id} does not contain a file: {str(ex)}")
        file_path = res["path"]
        with open(file_path, 'rb') as f:
            attachments.append(FileAttachment(content=f.read(), name=attachment_name))
    return attachments, attachments_names


def get_none_empty_addresses(addresses_ls):
    return [adress for adress in addresses_ls if adress]


def send_email(args):
    account = get_account(ACCOUNT_EMAIL)
    bcc = get_none_empty_addresses(argToList(args.get('bcc')))
    cc = get_none_empty_addresses(argToList(args.get('cc')))
    to = get_none_empty_addresses(argToList(args.get('to')))
    replyTo = get_none_empty_addresses(argToList(args.get('replyTo')))
    render_body = argToBoolean(args.get('renderBody') or False)
    subject = args.get('subject')
    subject = subject[:252] + '...' if len(subject) > 255 else subject

    attachments, attachments_names = process_attachments(args.get('attachCIDs', ''), args.get('attachIDs', ''),
                                                         args.get('attachNames', ''), args.get('manualAttachObj') or [])

    send_email_to_mailbox(
        account=account, to=to, subject=subject, body=args.get('body'), bcc=bcc, cc=cc, reply_to=replyTo,
        html_body=args.get('htmlBody'), attachments=attachments, raw_message=args.get('raw_message'),
        from_address=args.get('from')
    )
    result_object = {
        'from': args.get('from') or account.primary_smtp_address,
        'to': to,
        'subject': subject,
        'attachments': attachments_names
    }

    results = [{
        'Type': entryTypes['note'],
        'Contents': result_object,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sent email', result_object),
    }]
    if render_body:
        results.append({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['html'],
            'Contents': args.get('htmlBody')
        })

    return results


def reply_email(args):  # pragma: no cover
    account = get_account(ACCOUNT_EMAIL)
    bcc = args.get('bcc').split(",") if args.get('bcc') else None
    cc = args.get('cc').split(",") if args.get('cc') else None
    to = args.get('to').split(",") if args.get('to') else None
    subject = args.get('subject')
    subject = subject[:252] + '...' if subject and len(subject) > 255 else subject

    attachments, attachments_names = process_attachments(args.get('attachCIDs', ''), args.get('attachIDs', ''),
                                                         args.get('attachNames', ''), args.get('manualAttachObj') or [])

    send_email_reply_to_mailbox(account, args.get('inReplyTo'), to, args.get('body'), subject, bcc, cc, args.get('htmlBody'),
                                attachments, args.get('from'))
    result_object = {
        'from': args.get('from') or account.primary_smtp_address,
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


def test_module():  # pragma: no cover
    try:
        global IS_TEST_MODULE
        IS_TEST_MODULE = True
        account = get_account(ACCOUNT_EMAIL)
        folder = get_folder_by_path(account, FOLDER_NAME, IS_PUBLIC_FOLDER)
        if not folder.effective_rights.read:  # pylint: disable=E1101
            raise Exception("Success to authenticate, but user has no permissions to read from the mailbox. "
                            "Need to delegate the user permissions to the mailbox - "
                            "please read integration documentation and follow the instructions")
        folder.test_access()
    except ErrorFolderNotFound as e:
        if "Top of Information Store" in str(e):
            raise Exception(
                "Success to authenticate, but user probably has no permissions to read from the specific folder."
                "Check user permissions. You can try !ews-find-folders command to "
                "get all the folders structure that the user has permissions to")

    demisto.results('ok')


def get_protocol():  # pragma: no cover
    if AUTO_DISCOVERY:
        protocol = get_account_autodiscover(ACCOUNT_EMAIL).protocol
    else:
        protocol = Protocol(config=config)  # type: ignore
    return protocol


def encode_and_submit_results(obj):
    demisto.results(obj)


def sub_main():  # pragma: no cover
    global EWS_SERVER, USERNAME, ACCOUNT_EMAIL, PASSWORD
    global config, credentials
    EWS_SERVER = demisto.params()['ewsServer']
    USERNAME = demisto.params()['credentials']['identifier']
    ACCOUNT_EMAIL = demisto.params()['defaultTargetMailbox']
    PASSWORD = demisto.params()['credentials']['password']
    config, credentials = prepare()
    args = prepare_args(demisto.args())

    fix_2010()
    try:
        protocol = get_protocol()
        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'fetch-incidents':
            incidents = fetch_emails_as_incidents(ACCOUNT_EMAIL, FOLDER_NAME)
            demisto.incidents(incidents)
        elif demisto.command() == 'ews-get-attachment':
            encode_and_submit_results(fetch_attachments_for_message(**args))
        elif demisto.command() == 'ews-delete-attachment':
            encode_and_submit_results(delete_attachments_for_message(**args))
        elif demisto.command() == 'ews-get-searchable-mailboxes':
            encode_and_submit_results(get_searchable_mailboxes(protocol))
        elif demisto.command() == 'ews-search-mailboxes':
            encode_and_submit_results(search_mailboxes(protocol, **args))
        elif demisto.command() == 'ews-move-item-between-mailboxes':
            encode_and_submit_results(move_item_between_mailboxes(**args))
        elif demisto.command() == 'ews-move-item':
            encode_and_submit_results(move_item(**args))
        elif demisto.command() == 'ews-delete-items':
            encode_and_submit_results(delete_items(**args))
        elif demisto.command() == 'ews-search-mailbox':
            encode_and_submit_results(search_items_in_mailbox(**args))
        elif demisto.command() == 'ews-get-contacts':
            encode_and_submit_results(get_contacts(**args))
        elif demisto.command() == 'ews-get-out-of-office':
            encode_and_submit_results(get_out_of_office_state(**args))
        elif demisto.command() == 'ews-recover-messages':
            encode_and_submit_results(recover_soft_delete_item(**args))
        elif demisto.command() == 'ews-create-folder':
            encode_and_submit_results(create_folder(**args))
        elif demisto.command() == 'ews-mark-item-as-junk':
            encode_and_submit_results(mark_item_as_junk(**args))
        elif demisto.command() == 'ews-find-folders':
            encode_and_submit_results(find_folders(**args))
        elif demisto.command() == 'ews-get-items-from-folder':
            encode_and_submit_results(get_items_from_folder(**args))
        elif demisto.command() == 'ews-get-items':
            encode_and_submit_results(get_items(**args))
        elif demisto.command() == 'ews-get-folder':
            encode_and_submit_results(get_folder(**args))
        elif demisto.command() == 'ews-o365-start-compliance-search':
            encode_and_submit_results(start_compliance_search(**args))
        elif demisto.command() == 'ews-o365-get-compliance-search':
            encode_and_submit_results(get_compliance_search(**args))
        elif demisto.command() == 'ews-o365-purge-compliance-search-results':
            encode_and_submit_results(purge_compliance_search(**args))
        elif demisto.command() == 'ews-o365-get-compliance-search-purge-status':
            encode_and_submit_results(check_purge_compliance_search(**args))
        elif demisto.command() == 'ews-o365-remove-compliance-search':
            encode_and_submit_results(remove_compliance_search(**args))
        elif demisto.command() == 'ews-get-autodiscovery-config':
            encode_and_submit_results(get_autodiscovery_config())
        elif demisto.command() == 'ews-expand-group':
            encode_and_submit_results(get_expanded_group(protocol, **args))
        elif demisto.command() == 'ews-mark-items-as-read':
            encode_and_submit_results(mark_item_as_read(**args))
        elif demisto.command() == 'ews-get-items-as-eml':
            encode_and_submit_results(get_item_as_eml(**args))
        elif demisto.command() == 'send-mail':
            encode_and_submit_results(send_email(args))
        elif demisto.command() == 'reply-mail':
            encode_and_submit_results(reply_email(args))

    except Exception as e:
        import time

        time.sleep(2)
        start_logging()
        debug_log = log_stream.getvalue()  # type: ignore
        error_message_simple = ""
        error_message = ""

        # Office365 regular maintenance case
        if (isinstance(e, ErrorMailboxMoveInProgress | ErrorMailboxStoreUnavailable)) and 'outlook.office365.com' in EWS_SERVER:
            log_message = "Office365 is undergoing load balancing operations. " \
                          "As a result, the service is temporarily unavailable."
            if demisto.command() == 'fetch-incidents':
                demisto.info(log_message)
                demisto.incidents([])
                sys.exit(0)
            if IS_TEST_MODULE:
                demisto.results(log_message + " Please retry the instance configuration test.")
                sys.exit(0)
            error_message_simple = log_message + " Please retry your request."

        if isinstance(e, ConnectionError):
            error_message_simple = "Could not connect to the server.\n" \
                                   "Verify that the Hostname or IP address is correct.\n\n" \
                                   "Additional information: {}".format(str(e))
        if isinstance(e, ErrorInvalidPropertyRequest):
            error_message_simple = "Verify that the Exchange version is correct."
        else:
            from exchangelib.errors import MalformedResponseError

            if IS_TEST_MODULE and isinstance(e, MalformedResponseError):
                error_message_simple = "Got invalid response from the server.\n" \
                                       "Verify that the Hostname or IP address is is correct."

        # Legacy error handling
        if "Status code: 401" in debug_log:
            error_message_simple = "Got unauthorized from the server. " \
                                   "Check credentials are correct and authentication method are supported. "

            error_message_simple += "You can try using 'domain\\username' as username for authentication. " \
                if AUTH_METHOD_STR.lower() == 'ntlm' else ''

        if "SSL: CERTIFICATE_VERIFY_FAILED" in debug_log:
            # same status code (503) but different error.
            error_message_simple = "Certificate verification failed - This error may happen if the server " \
                                   "certificate cannot be validated or as a result of a proxy that is doing SSL/TLS " \
                                   "termination. It is possible to bypass certificate validation by checking " \
                                   "'Trust any certificate' in the instance settings."

        elif "Status code: 503" in debug_log:
            error_message_simple = "Got timeout from the server. " \
                                   "Probably the server is not reachable with the current settings. " \
                                   "Check proxy parameter. If you are using server URL - change to server IP address. "

        if not error_message_simple:
            error_message = error_message_simple = str(e)
        else:
            error_message = error_message_simple + "\n" + str(e)

        stacktrace = traceback.format_exc()
        if stacktrace:
            error_message += "\nFull stacktrace:\n" + stacktrace

        if debug_log:
            error_message += "\nFull debug log:\n" + debug_log

        if demisto.command() == 'fetch-incidents':
            raise Exception(str(e) + traceback.format_exc())
        if demisto.command() == 'ews-search-mailbox' and isinstance(e, ValueError):
            return_error(message="Selected invalid field, please specify valid field name.", error=e)
        if IS_TEST_MODULE:
            demisto.results(error_message_simple)
        else:
            demisto.results(
                {"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": error_message_simple})
        demisto.error(f"{e.__class__.__name__}: {error_message}")
    finally:
        exchangelib_cleanup()
        if log_stream:
            try:
                logging.getLogger().removeHandler(log_handler)  # type: ignore
                log_stream.close()
            except Exception as ex:
                demisto.error(f"EWS: unexpected exception when trying to remove log handler: {ex}")


def process_main():
    """setup stdin to fd=0 so we can read from the server"""
    sys.stdin = os.fdopen(0, "r")
    sub_main()


def main():  # pragma: no cover
    try:
        handle_proxy()
        # When running big queries, like 'ews-search-mailbox' the memory might not freed by the garbage
        # collector. `separate_process` flag will run the integration on a separate process that will prevent
        # memory leakage.
        separate_process = demisto.params().get("separate_process", False)
        demisto.debug(f"Running as separate_process: {separate_process}")
        if separate_process:
            try:
                p = Process(target=process_main)
                p.start()
                p.join()
            except Exception as ex:
                demisto.error(f"Failed starting Process: {ex}")
        else:
            sub_main()
    except Exception as exc:
        return_error(f"Found error in EWSv2: {exc}",
                     error=f'Error: {exc}\nTraceback: {traceback.format_exc()}')


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
