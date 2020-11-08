import random
import string
from typing import Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import sys
import traceback
import json
import os
import hashlib
from datetime import timedelta
from io import StringIO
import logging
import warnings
import email
from requests.exceptions import ConnectionError
from collections import deque

from multiprocessing import Process
import exchangelib
from exchangelib.errors import (
    ErrorItemNotFound,
    ResponseMessageError,
    RateLimitError,
    ErrorInvalidIdMalformed,
    ErrorFolderNotFound,
    ErrorMailboxStoreUnavailable,
    ErrorMailboxMoveInProgress,
    ErrorNameResolutionNoResults,
    MalformedResponseError,
)
from exchangelib.items import Item, Message, Contact
from exchangelib.services.common import EWSService, EWSAccountService
from exchangelib.util import create_element, add_xml_child, MNS, TNS
from exchangelib import (
    IMPERSONATION,
    Account,
    EWSDateTime,
    EWSTimeZone,
    Configuration,
    FileAttachment,
    Version,
    Folder,
    HTMLBody,
    Body,
    ItemAttachment,
    OAUTH2,
    OAuth2AuthorizationCodeCredentials,
    Identity,
    ExtendedProperty
)
from oauthlib.oauth2 import OAuth2Token
from exchangelib.version import EXCHANGE_O365
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter

# Ignore warnings print to stdout
warnings.filterwarnings("ignore")

""" Constants """

APP_NAME = "ms-ews-o365"
FOLDER_ID_LEN = 120
MAX_INCIDENTS_PER_FETCH = 50

# move results
MOVED_TO_MAILBOX = "movedToMailbox"
MOVED_TO_FOLDER = "movedToFolder"

# item types
FILE_ATTACHMENT_TYPE = "FileAttachment"
ITEM_ATTACHMENT_TYPE = "ItemAttachment"
ATTACHMENT_TYPE = "attachmentType"

TOIS_PATH = "/root/Top of Information Store/"

# context keys
ATTACHMENT_ID = "attachmentId"
ATTACHMENT_ORIGINAL_ITEM_ID = "originalItemId"
NEW_ITEM_ID = "newItemId"
MESSAGE_ID = "messageId"
ITEM_ID = "itemId"
ACTION = "action"
MAILBOX = "mailbox"
MAILBOX_ID = "mailboxId"
FOLDER_ID = "id"

# context paths
CONTEXT_UPDATE_EWS_ITEM = "EWS.Items(val.{0} === obj.{0} || (val.{1} && obj.{1} && val.{1} === obj.{1}))".format(
    ITEM_ID, MESSAGE_ID
)
CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT = "EWS.Items(val.{0} == obj.{1})".format(
    ITEM_ID, ATTACHMENT_ORIGINAL_ITEM_ID
)
CONTEXT_UPDATE_ITEM_ATTACHMENT = ".ItemAttachments(val.{0} == obj.{0})".format(
    ATTACHMENT_ID
)
CONTEXT_UPDATE_FILE_ATTACHMENT = ".FileAttachments(val.{0} == obj.{0})".format(
    ATTACHMENT_ID
)
CONTEXT_UPDATE_FOLDER = "EWS.Folders(val.{0} == obj.{0})".format(FOLDER_ID)

# fetch params
LAST_RUN_TIME = "lastRunTime"
LAST_RUN_IDS = "ids"
LAST_RUN_FOLDER = "folderName"
ERROR_COUNTER = "errorCounter"

# headers
ITEMS_RESULTS_HEADERS = [
    "sender",
    "subject",
    "hasAttachments",
    "datetimeReceived",
    "receivedBy",
    "author",
    "toRecipients",
    "textBody",
]

UTF_8 = 'utf-8'

""" Classes """


class ProxyAdapter(requests.adapters.HTTPAdapter):
    """
    Proxy Adapter used to add PROXY to requests
    """

    def send(self, *args, **kwargs):
        kwargs['proxies'] = handle_proxy()
        return super().send(*args, **kwargs)


class InsecureProxyAdapter(NoVerifyHTTPAdapter):
    """
    Insecure Proxy Adapter used to add PROXY and INSECURE to requests
    NoVerifyHTTPAdapter is a built-in insecure HTTPAdapter class
    """

    def send(self, *args, **kwargs):
        kwargs['proxies'] = handle_proxy()
        return super().send(*args, **kwargs)


class EWSClient:
    def __init__(
            self,
            default_target_mailbox,
            client_id,
            client_secret,
            tenant_id,
            folder="Inbox",
            is_public_folder=False,
            request_timeout="120",
            max_fetch=MAX_INCIDENTS_PER_FETCH,
            self_deployed=True,
            insecure=True,
            proxy=False,
            **kwargs,
    ):
        """
        Client used to communicate with EWS
        :param default_target_mailbox: Email address from which to fetch incidents
        :param client_id: Application client ID
        :param client_secret: Application client secret
        :param folder: Name of the folder from which to fetch incidents
        :param is_public_folder: Public Folder flag
        :param request_timeout: Timeout (in seconds) for HTTP requests to Exchange Server
        :param max_fetch: Max incidents per fetch
        :param insecure: Trust any certificate (not secure)
        """
        BaseProtocol.TIMEOUT = int(request_timeout)
        self.ews_server = "https://outlook.office365.com/EWS/Exchange.asmx/"
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id,
            auth_id=client_id,
            enc_key=client_secret,
            app_name=APP_NAME,
            base_url=self.ews_server,
            verify=not insecure,
            proxy=proxy,
            self_deployed=self_deployed,
            scope="https://outlook.office.com/.default",
        )
        self.folder_name = folder
        self.is_public_folder = is_public_folder
        self.access_type = kwargs.get('access_type') or IMPERSONATION
        self.max_fetch = min(MAX_INCIDENTS_PER_FETCH, int(max_fetch))
        self.last_run_ids_queue_size = 500
        self.client_id = client_id
        self.client_secret = client_secret
        self.account_email = default_target_mailbox
        self.config = self.__prepare(insecure)
        self.protocol = BaseProtocol(self.config)

    def __prepare(self, insecure):
        """
        Prepares the client PROTOCOL, CREDENTIALS and CONFIGURATION
        :param insecure: Trust any certificate (not secure)
        :return: OAuth 2 Configuration
        """
        BaseProtocol.HTTP_ADAPTER_CLS = InsecureProxyAdapter if insecure else ProxyAdapter
        access_token = self.ms_client.get_access_token()
        oauth2_token = OAuth2Token({"access_token": access_token})
        self.credentials = credentials = OAuth2AuthorizationCodeCredentials(
            client_id=self.client_id,
            client_secret=self.client_secret,
            access_token=oauth2_token,
        )
        # need to add identity for protocol OAuth header
        self.credentials.identity = Identity(upn=self.account_email)
        config_args = {
            "credentials": credentials,
            "auth_type": OAUTH2,
            "version": Version(EXCHANGE_O365),
            "service_endpoint": "https://outlook.office365.com/EWS/Exchange.asmx",
        }

        return Configuration(**config_args)

    def get_account(self, target_mailbox=None):
        """
        Request an account from EWS
        :param (Optional) target_mailbox: Mailbox associated with the requested account
        :return: exchangelib Account
        """
        if not target_mailbox:
            target_mailbox = self.account_email
        return Account(
            primary_smtp_address=target_mailbox,
            autodiscover=False,
            config=self.config,
            access_type=self.access_type,
        )

    def get_items_from_mailbox(self, account, item_ids):
        """
        Request specific items from a mailbox associated with an account
        :param account: EWS account or target_mailbox associated with that account
        :param item_ids: item_ids of the requested items
        :return: list of exchangelib Items
        """
        # allow user to pass target_mailbox as account
        if isinstance(account, str):
            account = self.get_account(account)
        else:
            account = self.get_account(self.account_email)
        if type(item_ids) is not list:
            item_ids = [item_ids]
        items = [Item(id=x) for x in item_ids]
        result = list(account.fetch(ids=items))
        result = [x for x in result if not isinstance(x, ErrorItemNotFound)]
        if len(result) != len(item_ids):
            raise Exception(
                "One or more items were not found. Check the input item ids"
            )
        return result

    def get_item_from_mailbox(self, account, item_id):
        """
        Request a single item from a mailbox associated with an account
        :param account: EWS account or target_mailbox associated with that account
        :param item_id: item_id of the requested item
        :return: exchangelib Item
        """
        result = self.get_items_from_mailbox(account, [item_id])
        if len(result) == 0:
            raise Exception(f"ItemId {str(item_id)} not found")
        return result[0]

    def get_attachments_for_item(self, item_id, account, attachment_ids=None):
        """
        Request attachments for an item
        :param item_id: item_id of the item to retrieve attachments from
        :param account: EWS account or target_mailbox associated with that account
        :param (Optional) attachment_ids: attachment_ids: attachment_ids to retrieve
        :return: list of exchangelib Item.attachments
        """
        item = self.get_item_from_mailbox(account, item_id)
        attachments = []
        attachment_ids = argToList(attachment_ids)
        if item:
            if item.attachments:
                for attachment in item.attachments:
                    if (
                            attachment_ids
                            and attachment.attachment_id.id not in attachment_ids
                    ):
                        continue
                    attachments.append(attachment)

        else:
            raise Exception("Message item not found: " + item_id)

        if attachment_ids and len(attachments) < len(attachment_ids):
            raise Exception(
                "Some attachment id did not found for message:" + str(attachment_ids)
            )

        return attachments

    def is_default_folder(self, folder_path, is_public=None):
        """
        Is the given folder_path public
        :param folder_path: folder path to check if is public
        :param is_public: (Optional) if provided, will return this value
        :return: Boolean
        """
        if is_public is not None:
            return is_public

        if folder_path == self.folder_name:
            return self.is_public_folder

        return False

    def get_folder_by_path(self, path, account=None, is_public=False):
        """
        Retrieve folder by path
        :param path: path of the folder
        :param account: account associated with the requested path
        :param is_public: is the requested folder public
        :return: exchangelib Folder
        """
        if account is None:
            account = self.get_account()
        # handle exchange folder id
        if len(path) == FOLDER_ID_LEN:
            folders_map = account.root._folders_map
            if path in folders_map:
                return account.root._folders_map[path]
        if is_public:
            folder_result = account.public_folders_root
        elif path == "AllItems":
            folder_result = account.root
        else:
            folder_result = account.inbox.parent  # Top of Information Store
        path = path.replace("/", "\\")
        path = path.split("\\")
        for sub_folder_name in path:
            folder_filter_by_name = [
                x
                for x in folder_result.children
                if x.name.lower() == sub_folder_name.lower()
            ]
            if len(folder_filter_by_name) == 0:
                raise Exception(f"No such folder {path}")
            folder_result = folder_filter_by_name[0]

        return folder_result

    def send_email(self, message: Message):
        account = self.get_account()
        message.account = account
        message.send_and_save()


class MarkAsJunk(EWSAccountService):
    """
    EWSAccountService class used for marking items as junk
    """
    SERVICE_NAME = "MarkAsJunk"

    def call(self, item_id, move_item):
        elements = list(
            self._get_elements(
                payload=self.get_payload(item_id=item_id, move_item=move_item)
            )
        )
        for element in elements:
            if isinstance(element, ResponseMessageError):
                return str(element)
        return "Success"

    def get_payload(self, item_id, move_item):
        junk = create_element(
            f"m:{self.SERVICE_NAME}",
            {"IsJunk": "true", "MoveItem": "true" if move_item else "false"},
        )

        items_list = create_element("m:ItemIds")
        item_element = create_element("t:ItemId", {"Id": item_id})
        items_list.append(item_element)
        junk.append(items_list)

        return junk


class GetSearchableMailboxes(EWSService):
    """
    EWSAccountService class used for getting Searchable Mailboxes
    """
    SERVICE_NAME = "GetSearchableMailboxes"
    element_container_name = f"{{{MNS}}}SearchableMailboxes"

    @staticmethod
    def parse_element(element):
        return {
            MAILBOX: element.find(f"{{{TNS}}}PrimarySmtpAddress").text
            if element.find(f"{{{TNS}}}PrimarySmtpAddress") is not None
            else None,
            MAILBOX_ID: element.find(f"{{{TNS}}}ReferenceId").text
            if element.find(f"{{{TNS}}}ReferenceId") is not None
            else None,
            "displayName": element.find(f"{{{TNS}}}DisplayName").text
            if element.find(f"{{{TNS}}}DisplayName") is not None
            else None,
            "isExternal": element.find(f"{{{TNS}}}IsExternalMailbox").text
            if element.find(f"{{{TNS}}}IsExternalMailbox") is not None
            else None,
            "externalEmailAddress": element.find(f"{{{TNS}}}ExternalEmailAddress").text
            if element.find(f"{{{TNS}}}ExternalEmailAddress") is not None
            else None,
        }

    def call(self):
        elements = self._get_elements(payload=self.get_payload())
        return [
            self.parse_element(x)
            for x in elements
            if x.find(f"{{{TNS}}}ReferenceId").text
        ]

    def get_payload(self):
        element = create_element(f"m:{self.SERVICE_NAME}")
        return element


class ExpandGroup(EWSService):
    """
    EWSAccountService class used for expanding groups
    """
    SERVICE_NAME = "ExpandDL"
    element_container_name = f"{{{MNS}}}DLExpansion"

    @staticmethod
    def parse_element(element):
        return {
            MAILBOX: element.find(f"{{{TNS}}}EmailAddress").text
            if element.find(f"{{{TNS}}}EmailAddress") is not None
            else None,
            "displayName": element.find(f"{{{TNS}}}Name").text
            if element.find(f"{{{TNS}}}Name") is not None
            else None,
            "mailboxType": element.find(f"{{{TNS}}}MailboxType").text
            if element.find(f"{{{TNS}}}MailboxType") is not None
            else None,
        }

    def call(self, email_address, recursive_expansion=False):
        try:
            if recursive_expansion == "True":
                group_members: Dict = {}
                self.expand_group_recursive(email_address, group_members)
                return list(group_members.values())
            else:
                return self.expand_group(email_address)
        except ErrorNameResolutionNoResults:
            demisto.results("No results were found.")
            sys.exit()

    def get_payload(self, email_address):
        element = create_element(f"m:{self.SERVICE_NAME}")
        mailbox_element = create_element("m:Mailbox")
        add_xml_child(mailbox_element, "t:EmailAddress", email_address)
        element.append(mailbox_element)
        return element

    def expand_group(self, email_address):
        """
        Expand given group
        :param email_address: email address of the group to expand
        :return: list dict with parsed expanded group data
        """
        elements = self._get_elements(payload=self.get_payload(email_address))
        return [self.parse_element(x) for x in elements]

    def expand_group_recursive(self, email_address, non_dl_emails, dl_emails=None):
        """
        Expand group recursively
        :param email_address: email address of the group to expand
        :param non_dl_emails: non distribution only emails
        :param dl_emails: (Optional) distribution only emails
        :return: Set of dl emails and non dl emails (returned via reference)
        """
        if dl_emails is None:
            dl_emails = set()
        if email_address in non_dl_emails or email_address in dl_emails:
            return None
        dl_emails.add(email_address)

        for member in self.expand_group(email_address):
            if (
                    member["mailboxType"] == "PublicDL"
                    or member["mailboxType"] == "PrivateDL"
            ):
                self.expand_group_recursive(member.get("mailbox"), non_dl_emails, dl_emails)
            else:
                if member["mailbox"] not in non_dl_emails:
                    non_dl_emails[member["mailbox"]] = member


# If you are modifying this probably also need to modify in other files
def exchangelib_cleanup():
    key_protocols = list(exchangelib.protocol.CachingProtocol._protocol_cache.items())
    try:
        exchangelib.close_connections()
    except Exception as ex:
        demisto.error("Error was found in exchangelib cleanup, ignoring: {}".format(ex))
    for key, protocol in key_protocols:
        try:
            if "thread_pool" in protocol.__dict__:
                demisto.debug(
                    "terminating thread pool key{} id: {}".format(
                        key, id(protocol.thread_pool)
                    )
                )
                protocol.thread_pool.terminate()
                del protocol.__dict__["thread_pool"]
            else:
                demisto.info(
                    "Thread pool not found (ignoring terminate) in protcol dict: {}".format(
                        dir(protocol.__dict__)
                    )
                )
        except Exception as ex:
            demisto.error("Error with thread_pool.terminate, ignoring: {}".format(ex))


""" LOGGING """

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


""" Helper Functions """


def get_attachment_name(attachment_name):
    """
    Retrieve attachment name or error string if none is provided
    :param attachment_name: attachment name to retrieve
    :return: string
    """
    if attachment_name is None or attachment_name == "":
        return "demisto_untitled_attachment"
    return attachment_name


def get_entry_for_object(title, context_key, obj, headers=None):
    """
    Create an entry for a given object
    :param title: Title of the human readable
    :param context_key: Context key used for entry context
    :param obj: Object to create entry for
    :param headers: (Optional) headers used in the tableToMarkDown
    :return: Entry object to be used with demisto.results()
    """
    if len(obj) == 0:
        return "There is no output results"
    if headers and isinstance(obj, dict):
        headers = list(set(headers).intersection(set(obj.keys())))

    return {
        "Type": entryTypes["note"],
        "Contents": obj,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown(title, obj, headers),
        "EntryContext": {context_key: obj},
    }


def prepare_args(args):
    """
    Prepare arguments to be used as the API expects it
    :param args: demisto args
    :return: transformed args
    """
    args = dict((k.replace("-", "_"), v) for k, v in list(args.items()))
    if "is_public" in args:
        args["is_public"] = args["is_public"] == "True"
    return args


def get_limited_number_of_messages_from_qs(qs, limit):
    """
    Retrieve a limited number of messages from query search
    :param qs: query search to execute
    :param limit: limit on number of items to retrieve from search
    :return: list of exchangelib.Message
    """
    count = 0
    results = []
    for item in qs:
        if count == limit:
            break
        if isinstance(item, Message):
            count += 1
            results.append(item)
    return results


def keys_to_camel_case(value):
    """
    Transform keys from snake to camel case (does nothing if no snakes are found)
    :param value: value to transform
    :return: transformed value
    """

    def str_to_camel_case(snake_str):
        components = snake_str.split("_")
        return components[0] + "".join(x.title() for x in components[1:])

    if value is None:
        return None
    if isinstance(value, (list, set)):
        return list(map(keys_to_camel_case, value))
    if isinstance(value, dict):
        return dict(
            (
                keys_to_camel_case(k),
                keys_to_camel_case(v) if isinstance(v, (list, dict)) else v,
            )
            for (k, v) in list(value.items())
        )

    return str_to_camel_case(value)


def get_last_run(client: EWSClient, last_run=None):
    """
    Retrieve the last run time
    :param client: EWS Client
    :param last_run: (Optional) last run object
    :return: last run dict
    """
    if not last_run or last_run.get(LAST_RUN_FOLDER) != client.folder_name:
        last_run = {
            LAST_RUN_TIME: None,
            LAST_RUN_FOLDER: client.folder_name,
            LAST_RUN_IDS: [],
        }
    if LAST_RUN_TIME in last_run and last_run[LAST_RUN_TIME] is not None:
        last_run[LAST_RUN_TIME] = EWSDateTime.from_string(last_run[LAST_RUN_TIME])

    # In case we have existing last_run data
    if last_run.get(LAST_RUN_IDS) is None:
        last_run[LAST_RUN_IDS] = []

    return last_run


def email_ec(item):
    """
    Create entry context for an email
    :param item: exchangelib.Item
    :return: entry context dict
    """
    return {
        "CC": None
        if not item.cc_recipients
        else [mailbox.email_address for mailbox in item.cc_recipients],
        "BCC": None
        if not item.bcc_recipients
        else [mailbox.email_address for mailbox in item.bcc_recipients],
        "To": None
        if not item.to_recipients
        else [mailbox.email_address for mailbox in item.to_recipients],
        "From": item.author.email_address,
        "Subject": item.subject,
        "Text": item.text_body,
        "HTML": item.body,
        "HeadersMap": {header.name: header.value for header in item.headers},
    }


def parse_item_as_dict(item, email_address=None, camel_case=False, compact_fields=False):
    """
    Parses an exchangelib item as a dict
    :param item: exchangelib.Item to parse
    :param (Optional) email_address: string mailbox
    :param (Optional) camel_case: Is camel case
    :param (Optional) compact_fields: Is compact fields
    :return: Item as a dict
    """

    def parse_object_as_dict(obj):
        raw_dict = {}
        if obj is not None:
            for field in obj.FIELDS:
                raw_dict[field.name] = getattr(obj, field.name, None)
        return raw_dict

    def parse_folder_as_json(folder):
        raw_dict = parse_object_as_dict(folder)
        if "parent_folder_id" in raw_dict:
            raw_dict["parent_folder_id"] = parse_folder_as_json(
                raw_dict["parent_folder_id"]
            )
        if "effective_rights" in raw_dict:
            raw_dict["effective_rights"] = parse_object_as_dict(
                raw_dict["effective_rights"]
            )
        return raw_dict

    raw_dict = {}
    for field, value in item._field_vals():
        if type(value) in [str, str, int, float, bool, Body, HTMLBody, None]:
            raw_dict[field] = value
    raw_dict["id"] = item.id
    if getattr(item, "attachments", None):
        raw_dict["attachments"] = [
            parse_attachment_as_dict(item.id, x) for x in item.attachments
        ]

    for time_field in [
        "datetime_sent",
        "datetime_created",
        "datetime_received",
        "last_modified_time",
        "reminder_due_by",
    ]:
        value = getattr(item, time_field, None)
        if value:
            raw_dict[time_field] = value.ewsformat()

    for dict_field in [
        "effective_rights",
        "parent_folder_id",
        "conversation_id",
        "author",
        "extern_id",
        "received_by",
        "received_representing",
        "reply_to",
        "sender",
        "folder",
    ]:
        value = getattr(item, dict_field, None)
        if value:
            if isinstance(value, list):
                raw_dict[dict_field] = []
                for single_val in value:
                    raw_dict[dict_field].append(parse_object_as_dict(single_val))
            else:
                raw_dict[dict_field] = parse_object_as_dict(value)

    for list_dict_field in ["headers", "cc_recipients", "to_recipients"]:
        value = getattr(item, list_dict_field, None)
        if value:
            raw_dict[list_dict_field] = [parse_object_as_dict(x) for x in value]

    if getattr(item, "folder", None):
        raw_dict["folder"] = parse_folder_as_json(item.folder)
        folder_path = (
            item.folder.absolute[len(TOIS_PATH):]
            if item.folder.absolute.startswith(TOIS_PATH)
            else item.folder.absolute
        )
        raw_dict["folder_path"] = folder_path

    if compact_fields:
        new_dict = {}
        # noinspection PyListCreation
        fields_list = [
            "datetime_created",
            "datetime_received",
            "datetime_sent",
            "sender",
            "has_attachments",
            "importance",
            "message_id",
            "last_modified_time",
            "size",
            "subject",
            "text_body",
            "headers",
            "body",
            "folder_path",
            "is_read",
        ]

        if "id" in raw_dict:
            new_dict["itemId"] = raw_dict["id"]
            fields_list.append("itemId")

        for field in fields_list:
            if field in raw_dict:
                new_dict[field] = raw_dict.get(field)
        for field in ["received_by", "author", "sender"]:
            if field in raw_dict:
                new_dict[field] = raw_dict.get(field, {}).get("email_address")
        for field in ["to_recipients"]:
            if field in raw_dict:
                new_dict[field] = [x.get("email_address") for x in raw_dict[field]]
        attachments = raw_dict.get("attachments")
        if attachments and len(attachments) > 0:
            file_attachments = [
                x for x in attachments if x[ATTACHMENT_TYPE] == FILE_ATTACHMENT_TYPE
            ]
            if len(file_attachments) > 0:
                new_dict["FileAttachments"] = file_attachments
            item_attachments = [
                x for x in attachments if x[ATTACHMENT_TYPE] == ITEM_ATTACHMENT_TYPE
            ]
            if len(item_attachments) > 0:
                new_dict["ItemAttachments"] = item_attachments

        raw_dict = new_dict

    if camel_case:
        raw_dict = keys_to_camel_case(raw_dict)

    if email_address:
        raw_dict[MAILBOX] = email_address
    return raw_dict


def get_entry_for_file_attachment(item_id, attachment):
    """
    Creates a file entry for an attachment
    :param item_id: item_id of the attachment
    :param attachment: attachment dict
    :return: file entry dict for attachment
    """
    entry = fileResult(get_attachment_name(attachment.name), attachment.content)
    entry["EntryContext"] = {
        CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT
        + CONTEXT_UPDATE_FILE_ATTACHMENT: parse_attachment_as_dict(item_id, attachment)
    }
    return entry


def parse_attachment_as_dict(item_id, attachment):
    """
    Creates a note entry for an attachment
    :param item_id: item_id of the attachment
    :param attachment: attachment dict
    :return: note entry dict for attachment
    """
    try:
        attachment_content = (
            attachment.content
            if isinstance(attachment, FileAttachment)
            else attachment.item.mime_content
        )
        return {
            ATTACHMENT_ORIGINAL_ITEM_ID: item_id,
            ATTACHMENT_ID: attachment.attachment_id.id,
            "attachmentName": get_attachment_name(attachment.name),
            "attachmentSHA256": hashlib.sha256(attachment_content).hexdigest()
            if attachment_content
            else None,
            "attachmentContentType": attachment.content_type,
            "attachmentContentId": attachment.content_id,
            "attachmentContentLocation": attachment.content_location,
            "attachmentSize": attachment.size,
            "attachmentLastModifiedTime": attachment.last_modified_time.ewsformat(),
            "attachmentIsInline": attachment.is_inline,
            ATTACHMENT_TYPE: FILE_ATTACHMENT_TYPE
            if isinstance(attachment, FileAttachment)
            else ITEM_ATTACHMENT_TYPE,
        }
    except TypeError as e:
        if str(e) != "must be string or buffer, not None":
            raise
        return {
            ATTACHMENT_ORIGINAL_ITEM_ID: item_id,
            ATTACHMENT_ID: attachment.attachment_id.id,
            "attachmentName": get_attachment_name(attachment.name),
            "attachmentSHA256": None,
            "attachmentContentType": attachment.content_type,
            "attachmentContentId": attachment.content_id,
            "attachmentContentLocation": attachment.content_location,
            "attachmentSize": attachment.size,
            "attachmentLastModifiedTime": attachment.last_modified_time.ewsformat(),
            "attachmentIsInline": attachment.is_inline,
            ATTACHMENT_TYPE: FILE_ATTACHMENT_TYPE
            if isinstance(attachment, FileAttachment)
            else ITEM_ATTACHMENT_TYPE,
        }


def get_entry_for_item_attachment(item_id, attachment, target_email):
    """
    Creates a note entry for an item attachment
    :param item_id: Item id
    :param attachment: exchangelib attachment
    :param target_email: target email
    :return: note entry dict for item attachment
    """
    item = attachment.item
    dict_result = parse_attachment_as_dict(item_id, attachment)
    dict_result.update(
        parse_item_as_dict(item, target_email, camel_case=True, compact_fields=True)
    )
    title = f'EWS get attachment got item for "{target_email}", "{get_attachment_name(attachment.name)}"'

    return get_entry_for_object(
        title,
        CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT + CONTEXT_UPDATE_ITEM_ATTACHMENT,
        dict_result,
    )


""" Command Functions """


def get_expanded_group(client: EWSClient, email_address, recursive_expansion=False):
    """
    Retrieve expanded group command
    :param client: EWS Client
    :param email_address: Email address of the group to expand
    :param (Optional) recursive_expansion: Whether to enable recursive expansion. Default is "False".
    :return: Expanded groups output tuple
    """
    group_members = ExpandGroup(protocol=client.protocol).call(
        email_address, recursive_expansion
    )
    group_details = {"name": email_address, "members": group_members}
    output = {"EWS.ExpandGroup": group_details}
    readable_output = tableToMarkdown("Group Members", group_members)
    return readable_output, output, group_details


def get_searchable_mailboxes(client: EWSClient):
    """
    Retrieve searchable mailboxes command
    :param client: EWS Client
    :return: Searchable mailboxes output tuple
    """
    searchable_mailboxes = GetSearchableMailboxes(protocol=client.protocol).call()
    readable_output = tableToMarkdown(
        "Searchable mailboxes", searchable_mailboxes, headers=["displayName", "mailbox"]
    )
    output = {"EWS.Mailboxes": searchable_mailboxes}
    return readable_output, output, searchable_mailboxes


def delete_attachments_for_message(
        client: EWSClient, item_id, target_mailbox=None, attachment_ids=None
):
    """
    Deletes attachments for a given message
    :param client: EWS Client
    :param item_id: item id
    :param (Optional) target_mailbox: target mailbox
    :param (Optional) attachment_ids: attachment ids to delete
    :return: entries that were delted
    """
    attachments = client.get_attachments_for_item(
        item_id, target_mailbox, attachment_ids
    )
    deleted_file_attachments = []
    deleted_item_attachments = []  # type: ignore
    for attachment in attachments:
        attachment_deleted_action = {
            ATTACHMENT_ID: attachment.attachment_id.id,
            ACTION: "deleted",
        }
        if isinstance(attachment, FileAttachment):
            deleted_file_attachments.append(attachment_deleted_action)
        else:
            deleted_item_attachments.append(attachment_deleted_action)
        attachment.detach()

    entries = []
    if len(deleted_file_attachments) > 0:
        entry = get_entry_for_object(
            "Deleted file attachments",
            "EWS.Items" + CONTEXT_UPDATE_FILE_ATTACHMENT,
            deleted_file_attachments,
        )
        entries.append(entry)
    if len(deleted_item_attachments) > 0:
        entry = get_entry_for_object(
            "Deleted item attachments",
            "EWS.Items" + CONTEXT_UPDATE_ITEM_ATTACHMENT,
            deleted_item_attachments,
        )
        entries.append(entry)

    return entries


def fetch_attachments_for_message(
        client: EWSClient, item_id, target_mailbox=None, attachment_ids=None
):
    """
    Fetches attachments for a message
    :param client: EWS Client
    :param item_id: item id
    :param (Optional) target_mailbox: target mailbox
    :param (Optional) attachment_ids: attachment ids
    :return: list of parsed entries
    """
    account = client.get_account(target_mailbox)
    attachments = client.get_attachments_for_item(item_id, account, attachment_ids)
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
            entries.append(
                get_entry_for_item_attachment(
                    item_id, attachment, account.primary_smtp_address
                )
            )
            if attachment.item.mime_content:
                entries.append(
                    fileResult(
                        get_attachment_name(attachment.name) + ".eml",
                        attachment.item.mime_content,
                    )
                )

    return entries


def move_item_between_mailboxes(
        client: EWSClient,
        item_id,
        destination_mailbox,
        destination_folder_path,
        source_mailbox=None,
        is_public=None,
):
    """
    Moves item between mailboxes
    :param client: EWS Client
    :param item_id: item id
    :param destination_mailbox: destination mailbox
    :param destination_folder_path: destination folder path
    :param (Optional) source_mailbox: source mailbox
    :param (Optional) is_public: is the destination folder public
    :return: Output tuple
    """
    source_account = client.get_account(source_mailbox)
    destination_account = client.get_account(destination_mailbox)
    is_public = client.is_default_folder(destination_folder_path, is_public)
    destination_folder = client.get_folder_by_path(
        destination_folder_path, destination_account, is_public
    )
    item = client.get_item_from_mailbox(source_account, item_id)

    exported_items = source_account.export([item])
    destination_account.upload([(destination_folder, exported_items[0])])
    source_account.bulk_delete([item])

    move_result = {
        MOVED_TO_MAILBOX: destination_mailbox,
        MOVED_TO_FOLDER: destination_folder_path,
    }
    readable_output = "Item was moved successfully."
    output = {f"EWS.Items(val.itemId === '{item_id}')": move_result}
    return readable_output, output, move_result


def move_item(
        client: EWSClient, item_id, target_folder_path, target_mailbox=None, is_public=None
):
    """
    Moves an item within the same mailbox
    :param client: EWS Client
    :param item_id: item id
    :param target_folder_path: target folder path
    :param (Optional) target_mailbox: mailbox containing the item
    :param (Optional) is_public: is the destination folder public
    :return: Output tuple
    """
    account = client.get_account(target_mailbox)
    is_public = client.is_default_folder(target_folder_path, is_public)
    target_folder = client.get_folder_by_path(target_folder_path, is_public=is_public)
    item = client.get_item_from_mailbox(account, item_id)
    if isinstance(item, ErrorInvalidIdMalformed):
        raise Exception("Item not found")
    item.move(target_folder)
    move_result = {
        NEW_ITEM_ID: item.id,
        ITEM_ID: item_id,
        MESSAGE_ID: item.message_id,
        ACTION: "moved",
    }
    readable_output = tableToMarkdown("Moved items", move_result)
    output = {CONTEXT_UPDATE_EWS_ITEM: move_result}
    return readable_output, output, move_result


def delete_items(client: EWSClient, item_ids, delete_type, target_mailbox=None):
    """
    Delete items in a mailbox
    :param client: EWS Client
    :param item_ids: items ids to delete
    :param delete_type: delte type soft/hard
    :param (Optional) target_mailbox: mailbox containinf the items
    :return: Output tuple
    """
    deleted_items = []
    item_ids = argToList(item_ids)
    items = client.get_items_from_mailbox(target_mailbox, item_ids)
    delete_type = delete_type.lower()

    for item in items:
        item_id = item.id
        if delete_type == "trash":
            item.move_to_trash()
        elif delete_type == "soft":
            item.soft_delete()
        elif delete_type == "hard":
            item.delete()
        else:
            raise Exception(
                f'invalid delete type: {delete_type}. Use "trash" \\ "soft" \\ "hard"'
            )
        deleted_items.append(
            {
                ITEM_ID: item_id,
                MESSAGE_ID: item.message_id,
                ACTION: f"{delete_type}-deleted",
            }
        )

    readable_output = tableToMarkdown(
        f"Deleted items ({delete_type} delete type)", deleted_items
    )
    output = {CONTEXT_UPDATE_EWS_ITEM: deleted_items}
    return readable_output, output, deleted_items


def search_items_in_mailbox(
        client: EWSClient,
        query=None,
        message_id=None,
        folder_path="",
        limit=100,
        target_mailbox=None,
        is_public=None,
        selected_fields="all",
):
    """
    Search items in mailbox
    :param client: EWS Client
    :param (Optional) query: query to execute
    :param (Optional) message_id: message ids to search
    :param (Optional) folder_path: folder path to search
    :param (Optional) limit: max amount of items to fetch
    :param (Optional) target_mailbox: mailbox containing the items
    :param (Optional) is_public: is the targeted folder public
    :param (Optional) selected_fields: Selected fields
    :return: Output tuple
    """
    if not query and not message_id:
        return_error("Missing required argument. Provide query or message-id")

    if message_id and message_id[0] != "<" and message_id[-1] != ">":
        message_id = "<{}>".format(message_id)

    account = client.get_account(target_mailbox)
    limit = int(limit)
    if folder_path.lower() == "inbox":
        folders = [account.inbox]
    elif folder_path:
        is_public = client.is_default_folder(folder_path, is_public)
        folders = [client.get_folder_by_path(folder_path, account, is_public)]
    else:
        folders = account.inbox.parent.walk()  # pylint: disable=E1101

    items = []  # type: ignore
    selected_all_fields = selected_fields == "all"

    if selected_all_fields:
        restricted_fields = list([x.name for x in Message.FIELDS])  # type: ignore
    else:
        restricted_fields = set(argToList(selected_fields))  # type: ignore
        restricted_fields.update(["id", "message_id"])  # type: ignore

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
    searched_items_result = [
        parse_item_as_dict(
            item,
            account.primary_smtp_address,
            camel_case=True,
            compact_fields=selected_all_fields,
        )
        for item in items
    ]

    if not selected_all_fields:
        searched_items_result = [
            {k: v for (k, v) in i.items() if k in keys_to_camel_case(restricted_fields)}
            for i in searched_items_result
        ]

        for item in searched_items_result:
            item["itemId"] = item.pop("id", "")

    readable_output = tableToMarkdown(
        "Searched items",
        searched_items_result,
        headers=ITEMS_RESULTS_HEADERS if selected_all_fields else None,
    )
    output = {CONTEXT_UPDATE_EWS_ITEM: searched_items_result}
    return readable_output, output, searched_items_result


def get_out_of_office_state(client: EWSClient, target_mailbox=None):
    """
    Retrieve get out of office state of the targeted mailbox
    :param client: EWS Client
    :param (Optional) target_mailbox: target mailbox
    :return: Output tuple
    """
    account = client.get_account(target_mailbox)
    oof = account.oof_settings
    oof_dict = {
        "state": oof.state,  # pylint: disable=E1101
        "externalAudience": getattr(oof, "external_audience", None),
        "start": oof.start.ewsformat() if oof.start else None,  # pylint: disable=E1101
        "end": oof.end.ewsformat() if oof.end else None,  # pylint: disable=E1101
        "internalReply": getattr(oof, "internal_replay", None),
        "externalReply": getattr(oof, "external_replay", None),
        MAILBOX: account.primary_smtp_address,
    }
    readable_output = tableToMarkdown(
        f"Out of office state for {account.primary_smtp_address}", oof_dict
    )
    output = {f"Account.Email(val.Address == obj.{MAILBOX}).OutOfOffice": oof_dict}
    return readable_output, output, oof_dict


def recover_soft_delete_item(
        client: EWSClient,
        message_ids,
        target_folder_path="Inbox",
        target_mailbox=None,
        is_public=None,
):
    """
    Recovers soft deleted items
    :param client: EWS Client
    :param message_ids: Message ids to recover
    :param (Optional) target_folder_path: target folder path
    :param (Optional) target_mailbox: target mailbox
    :param (Optional) is_public: is the target folder public
    :return:
    """
    account = client.get_account(target_mailbox)
    is_public = client.is_default_folder(target_folder_path, is_public)
    target_folder = client.get_folder_by_path(target_folder_path, account, is_public)
    recovered_messages = []
    message_ids = argToList(message_ids)

    items_to_recover = account.recoverable_items_deletions.filter(  # pylint: disable=E1101
        message_id__in=message_ids
    ).all()  # pylint: disable=E1101

    recovered_items = set()
    for item in items_to_recover:
        recovered_items.add(item)
    if len(recovered_items) != len(message_ids):
        missing_items = set(message_ids).difference(recovered_items)
        raise Exception(
            f"Some message ids are missing in recoverable items directory: {missing_items}"
        )

    for item in recovered_items:
        item.move(target_folder)
        recovered_messages.append(
            {ITEM_ID: item.id, MESSAGE_ID: item.message_id, ACTION: "recovered"}
        )

    readable_output = tableToMarkdown("Recovered messages", recovered_messages)
    output = {CONTEXT_UPDATE_EWS_ITEM: recovered_messages}
    return readable_output, output, recovered_messages


def get_contacts(client: EWSClient, limit, target_mailbox=None):
    """
    Retrieve contacts of the target mailbox or client mailbox
    :param client: EWS Client
    :param limit: max amount of contacts to retrieve
    :param (Optional) target_mailbox: Target mailbox
    :return:
    """

    def parse_physical_address(address):
        result = {}
        for attr in ["city", "country", "label", "state", "street", "zipcode"]:
            result[attr] = getattr(address, attr, None)
        return result

    def parse_phone_number(phone_number):
        result = {}
        for attr in ["label", "phone_number"]:
            result[attr] = getattr(phone_number, attr, None)
        return result

    def parse_contact(contact):
        contact_dict = dict(
            (k, v if not isinstance(v, EWSDateTime) else v.ewsformat())
            for k, v in list(contact._field_vals())
            if isinstance(v, str) or isinstance(v, EWSDateTime)
        )
        if isinstance(contact, Contact) and contact.physical_addresses:
            contact_dict["physical_addresses"] = list(
                map(parse_physical_address, contact.physical_addresses)
            )
        if isinstance(contact, Contact) and contact.phone_numbers:
            contact_dict["phone_numbers"] = list(
                map(parse_phone_number, contact.phone_numbers)
            )
        if (
                isinstance(contact, Contact)
                and contact.email_addresses
                and len(contact.email_addresses) > 0
        ):
            contact_dict["emailAddresses"] = [x.email for x in contact.email_addresses]
        contact_dict = keys_to_camel_case(contact_dict)
        contact_dict = dict((k, v) for k, v in list(contact_dict.items()) if v)
        contact_dict.pop("mimeContent", None)
        contact_dict["originMailbox"] = target_mailbox
        return contact_dict

    account = client.get_account(target_mailbox)
    contacts = []

    for contact in account.contacts.all()[: int(limit)]:  # pylint: disable=E1101
        contacts.append(parse_contact(contact))
    readable_output = tableToMarkdown(f"Email contacts for {target_mailbox}", contacts)
    output = {"Account.Email(val.Address == obj.originMailbox).EwsContacts": contacts}
    return readable_output, output, contacts


def create_folder(client: EWSClient, new_folder_name, folder_path, target_mailbox=None):
    """
    Creates a folder in the target mailbox or the client mailbox
    :param client: EWS Client
    :param new_folder_name: new folder name
    :param folder_path: path of the new folder
    :param (Optional) target_mailbox: target mailbox
    :return: Output tuple
    """
    account = client.get_account(target_mailbox)
    full_path = os.path.join(folder_path, new_folder_name)
    try:
        if client.get_folder_by_path(full_path, account):
            return f"Folder {full_path} already exists",
    except Exception:
        pass
    parent_folder = client.get_folder_by_path(folder_path, account)
    f = Folder(parent=parent_folder, name=new_folder_name)
    f.save()
    client.get_folder_by_path(full_path, account)
    return f"Folder {full_path} created successfully",


def find_folders(client: EWSClient, target_mailbox=None):
    """
    Finds folders in the mailbox
    :param client: EWS Client
    :param (Optional) target_mailbox: target mailbox
    :return: Output tuple
    """
    account = client.get_account(target_mailbox)
    root = account.root
    if client.is_public_folder:
        root = account.public_folders_root
    folders = []
    for f in root.walk():  # pylint: disable=E1101
        folder = folder_to_context_entry(f)
        folders.append(folder)
    folders_tree = root.tree()  # pylint: disable=E1101
    readable_output = folders_tree
    output = {"EWS.Folders(val.id == obj.id)": folders}
    return readable_output, output, folders


def mark_item_as_junk(client: EWSClient, item_id, move_items, target_mailbox=None):
    """
    Marks item as junk in the target mailbox or client mailbox
    :param client: EWS Client
    :param item_id: item ids to mark as junk
    :param move_items: "yes" or "no" - to move or not to move to trash
    :param (Optional) target_mailbox: target mailbox
    :return:
    """
    account = client.get_account(target_mailbox)
    move_items = move_items.lower() == "yes"
    ews_result = MarkAsJunk(account=account).call(item_id=item_id, move_item=move_items)
    mark_as_junk_result = {
        ITEM_ID: item_id,
    }
    if ews_result == "Success":
        mark_as_junk_result[ACTION] = "marked-as-junk"
    else:
        raise Exception("Failed mark-item-as-junk with error: " + ews_result)

    readable_output = tableToMarkdown("Mark item as junk", mark_as_junk_result)
    output = {CONTEXT_UPDATE_EWS_ITEM: mark_as_junk_result}
    return readable_output, output, mark_as_junk_result


def get_items_from_folder(
        client: EWSClient,
        folder_path,
        limit=100,
        target_mailbox=None,
        is_public=None,
        get_internal_item="no",
):
    """
    Retrieve items from folder path
    :param client: EWS Client
    :param folder_path: folder path
    :param (Optional) limit: max amount of items to retrieve
    :param (Optional) target_mailbox: target mailbox
    :param (Optional) is_public: is the folder public
    :param (Optional) get_internal_item: should also retrieve internal items ("no" by default)
    :return: Output tuple
    """
    account = client.get_account(target_mailbox)
    limit = int(limit)
    get_internal_item = get_internal_item == "yes"
    is_public = client.is_default_folder(folder_path, is_public)
    folder = client.get_folder_by_path(folder_path, account, is_public)
    qs = folder.filter().order_by("-datetime_created")[:limit]
    items = get_limited_number_of_messages_from_qs(qs, limit)
    items_result = []

    for item in items:
        item_attachment = parse_item_as_dict(
            item, account.primary_smtp_address, camel_case=True, compact_fields=True
        )
        for attachment in item.attachments:
            if (
                    get_internal_item
                    and isinstance(attachment, ItemAttachment)
                    and isinstance(attachment.item, Message)
            ):
                # if found item attachment - switch item to the attchment
                item_attachment = parse_item_as_dict(
                    attachment.item,
                    account.primary_smtp_address,
                    camel_case=True,
                    compact_fields=True,
                )
                break
        items_result.append(item_attachment)

    hm_headers = [
        "sender",
        "subject",
        "hasAttachments",
        "datetimeReceived",
        "receivedBy",
        "author",
        "toRecipients",
        "id",
    ]
    readable_output = tableToMarkdown(
        "Items in folder " + folder_path, items_result, headers=hm_headers
    )
    output = {CONTEXT_UPDATE_EWS_ITEM: items_result}
    return readable_output, output, items_result


def get_items(client: EWSClient, item_ids, target_mailbox=None):
    """
    Get items from target mailbox or client mailbox
    :param client: EWS Client
    :param item_ids: item ids to retrieve
    :param (Optional) target_mailbox: target mailbox to retrieve items from
    :return:
    """
    item_ids = argToList(item_ids)
    account = client.get_account(target_mailbox)
    items = client.get_items_from_mailbox(account, item_ids)
    items = [x for x in items if isinstance(x, Message)]
    items_as_incidents = [parse_incident_from_item(x) for x in items]
    items_to_context = [
        parse_item_as_dict(x, account.primary_smtp_address, True, True) for x in items
    ]
    readable_output = tableToMarkdown(
        "Get items", items_to_context, ITEMS_RESULTS_HEADERS
    )
    output = {
        CONTEXT_UPDATE_EWS_ITEM: items_to_context,
        "Email": [email_ec(item) for item in items],
    }
    return readable_output, output, items_as_incidents


def get_folder(client: EWSClient, folder_path, target_mailbox=None, is_public=None):
    """
    Retrieve a folder from the target mailbox or client mailbox
    :param client: EWS Client
    :param folder_path: folder path to retrieve
    :param (Optional) target_mailbox: target mailbox
    :param (Optional) is_public: is the folder public
    :return:
    """
    account = client.get_account(target_mailbox)
    is_public = client.is_default_folder(folder_path, is_public)
    folder = folder_to_context_entry(
        client.get_folder_by_path(folder_path, account=account, is_public=is_public)
    )
    readable_output = tableToMarkdown(f"Folder {folder_path}", folder)
    output = {CONTEXT_UPDATE_FOLDER: folder}
    return readable_output, output, folder


def folder_to_context_entry(f):
    """
    Create a context entry from a folder response
    :param f: folder response
    :return: dict context entry
    """
    try:
        f_entry = {
            "name": f.name,
            "totalCount": f.total_count,
            "id": f.id,
            "childrenFolderCount": f.child_folder_count,
            "changeKey": f.changekey,
        }

        if "unread_count" in [x.name for x in Folder.FIELDS]:
            f_entry["unreadCount"] = f.unread_count
        return f_entry
    except AttributeError:
        if isinstance(f, dict):
            return {
                "name": f.get("name"),
                "totalCount": f.get("total_count"),
                "id": f.get("id"),
                "childrenFolderCount": f.get("child_folder_count"),
                "changeKey": f.get("changekey"),
                "unreadCount": f.get("unread_count"),
            }


def mark_item_as_read(
        client: EWSClient, item_ids, operation="read", target_mailbox=None
):
    """
    Marks item as read
    :param client: EWS Client
    :param item_ids: items ids to mark as read
    :param (Optional) operation: operation to execute
    :param (Optional) target_mailbox: target mailbox
    :return: Output tuple
    """
    marked_items = []
    item_ids = argToList(item_ids)
    items = client.get_items_from_mailbox(target_mailbox, item_ids)
    items = [x for x in items if isinstance(x, Message)]

    for item in items:
        item.is_read = operation == "read"
        item.save()

        marked_items.append(
            {
                ITEM_ID: item.id,
                MESSAGE_ID: item.message_id,
                ACTION: "marked-as-{}".format(operation),
            }
        )

    readable_output = tableToMarkdown(
        f"Marked items ({operation} marked operation)", marked_items
    )
    output = {CONTEXT_UPDATE_EWS_ITEM: marked_items}
    return readable_output, output, marked_items


def random_word_generator(length):
    """Generate a random string of given length
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


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
            re.finditer(r'<img.+?src=\"(data:(image\/.+?);base64,([a-zA-Z0-9+/=\r\n]+?))\"', html_body, re.I)):
        attachment = {
            'data': base64.b64decode(m.group(3)),
            'name': f'image{i}'
        }
        attachment['cid'] = f'{attachment["name"]}@{random_word_generator(8)}.{random_word_generator(8)}'

        attachments.append(attachment)
        clean_body += html_body[last_index:m.start(1)] + 'cid:' + attachment['cid']
        last_index = m.end() - 1

    clean_body += html_body[last_index:]
    return clean_body, attachments


def collect_manual_attachments(manualAttachObj):
    """Collect all manual attachments' data

    Args:
        manualAttachObj (str): String representation of the manually attached files list.

    Returns:
        List[Dict]. List of the files data.
    """
    manually_attached_objects = argToList(manualAttachObj)

    attachments = []
    for attachment in manually_attached_objects:
        file_res = demisto.getFilePath(os.path.basename(attachment['RealFileName']))

        path = file_res['path']

        with open(path, 'rb') as fp:
            data = fp.read()

        attachments.append({
            'name': attachment['FileName'],
            'data': data,
            'cid': ''
        })

    return attachments


def collect_attachments(attachments_ids, attachments_cids, attachments_names):
    """Collect all attachments' data

    Args:
        attachments_ids (str): String representation of the files ids list.
        attachments_cids (str): String representation of the files content ids list.
        attachments_names (str): String representation of the files names list.

    Returns:
        List[Dict]. List of the files data.
    """
    attachments = []

    files_ids = argToList(attachments_ids)
    files_cids = argToList(attachments_cids)
    files_names = argToList(attachments_names)

    for index, file_id in enumerate(files_ids):
        try:
            file_res = demisto.getFilePath(file_id)
            path = file_res['path']

            if len(files_names) > index and files_names[index]:
                filename = files_names[index]
            else:
                filename = file_res['name']

            if len(files_cids) > index and files_cids[index]:
                cid = files_cids[index]
            else:
                cid = ''

            with open(path, 'rb') as fp:
                data = fp.read()

            attachments.append({
                'name': filename,
                'data': data,
                'cid': cid
            })

        except Exception as e:
            demisto.error(f'Invalid entry {file_id} with exception: {e}')
            return_error(f'Entry {file_id} is not valid or is not a file entry')

    return attachments


def handle_transient_files(transient_files, transient_files_contents, transient_files_cids):
    """Creates the transient attachments data

    Args:
        transient_files (str): String representation of the transient files names list.
        transient_files_contents (str): String representation of the transient files content list.
        transient_files_cids (str): String representation of the transient files content ids list.

    Returns:
        List[Dict]. List of the transient files data.
    """
    transient_attachments = []

    files_names = argToList(transient_files)
    files_contents = argToList(transient_files_contents)
    files_cids = argToList(transient_files_cids)

    for index in range(len(files_names)):
        file_name = files_names[index]

        if index >= len(files_contents):
            break

        file_content = bytes(files_contents[index], UTF_8)

        if index >= len(files_cids):
            file_cid = ''
        else:
            file_cid = files_cids[index]

        transient_attachments.append({
            'name': file_name,
            'data': file_content,
            'cid': file_cid
        })

    return transient_attachments


def handle_template_params(template_params):
    """Translates the template params if they exist from the context

    Args:
        template_params (str): JSON string that represent the variables names to be replaced and the desired value.
                                Value can be either real value or context key to fetch the value from.

    Returns:
        Dict. `variable_name: value_to_use` of the templated parameters.
    """
    actual_params = {}

    if template_params:
        try:
            params = json.loads(template_params)

            for p in params:
                if params[p].get('value'):
                    actual_params[p] = params[p]['value']
                elif params[p].get('key'):
                    actual_params[p] = demisto.dt(demisto.context(), params[p]['key'])
        except ValueError as e:
            return_error('Unable to parse template_params: %s' % (str(e)))

    return actual_params


def create_message_object(to, cc, bcc, subject, body, additional_headers):
    """Creates the message object according to the existence of additional custom headers.
    """
    if additional_headers:
        return Message(
            to_recipients=to,
            cc_recipients=cc,
            bcc_recipients=bcc,
            subject=subject,
            body=body,
            **additional_headers
        )

    return Message(
        to_recipients=to,
        cc_recipients=cc,
        bcc_recipients=bcc,
        subject=subject,
        body=body
    )


def create_message(to, subject='', body='', bcc=None, cc=None, html_body=None, attachments=None,
                   additional_headers=None):
    """Creates the Message object that will be sent.

    Args:
        to (list): Main recipients.
        cc (list): CC recipients.
        bcc (list): BCC recipients.
        subject (str): Email's subject.
        body (str): Email's simple text body.
        html_body (str): Email's html body.
        attachments (list): Files to be attached to the mail, both inline and as files.
        additional_headers (Dict): Custom headers to be added to the message.

    Returns:
        Message. Message object ready to be sent.
    """
    if not html_body:
        # This is a simple text message - we cannot have CIDs here
        message = create_message_object(to, cc, bcc, subject, body, additional_headers)

        for attachment in attachments:
            if not attachment.get('cid'):
                new_attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'))
                message.attach(new_attachment)

    else:
        html_body, html_attachments = handle_html(html_body)
        attachments += html_attachments

        message = create_message_object(to, cc, bcc, subject, HTMLBody(html_body), additional_headers)

        for attachment in attachments:
            if not attachment.get('cid'):
                new_attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'))
            else:
                new_attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'),
                                                is_inline=True, content_id=attachment.get('cid'))

            message.attach(new_attachment)

    return message


def add_additional_headers(additional_headers):
    """Adds custom headers to the Message object

    Args:
        additional_headers (str): Headers list as string. Example: headerName1=headerValue1,headerName2=headerValue2

    Returns:
        Dict. Headers dictionary in the form of: `header_name: header value`
    """
    headers = dict()

    for header in argToList(additional_headers):
        header_name, header_value = header.split('=', 1)

        class TempClass(ExtendedProperty):
            distinguished_property_set_id = 'InternetHeaders'
            property_name = header_name
            property_type = 'String'

        try:
            Message.register(header_name, TempClass)
            headers[header_name] = header_value
        except ValueError as e:
            demisto.debug('EWSO365 - Header ' + header_name + ' could not be registered. ' + str(e))

    return headers


def send_email(client: EWSClient, to, subject='', body="", bcc=None, cc=None, htmlBody=None,
               attachIDs="", attachCIDs="", attachNames="", manualAttachObj=None,
               transientFile=None, transientFileContent=None, transientFileCID=None, templateParams=None,
               additionalHeader=None, raw_message=None):
    to = argToList(to)
    cc = argToList(cc)
    bcc = argToList(bcc)

    # Basic validation - we allow pretty much everything but you have to have at least a recipient
    # We allow messages without subject and also without body
    if not to and not cc and not bcc:
        return_error('You must have at least one recipient')

    if raw_message:
        message = Message(
            to_recipients=to,
            cc_recipients=cc,
            bcc_recipients=bcc,
            body=raw_message
        )

    else:
        if additionalHeader:
            additionalHeader = add_additional_headers(additionalHeader)

        # collect all types of attachments
        attachments = collect_attachments(attachIDs, attachCIDs, attachNames)
        attachments.extend(collect_manual_attachments(manualAttachObj))
        attachments.extend(handle_transient_files(transientFile, transientFileContent, transientFileCID))

        # update body and html_body with the templated params, if exists
        template_params = handle_template_params(templateParams)
        if template_params:
            body = body.format(**template_params)
            htmlBody = htmlBody.format(**template_params)

        message = create_message(to, subject, body, bcc, cc, htmlBody, attachments, additionalHeader)

    client.send_email(message)

    return 'Mail sent successfully', {}, {}


def get_item_as_eml(client: EWSClient, item_id, target_mailbox=None):
    """
    Retrieve item as an eml
    :param client: EWS Client
    :param item_id: Item id to retrieve
    :param (Optional) target_mailbox: target mailbox
    :return: Output tuple
    """
    account = client.get_account(target_mailbox)
    item = client.get_item_from_mailbox(account, item_id)

    if item.mime_content:
        mime_content = item.mime_content
        if isinstance(mime_content, bytes):
            email_content = email.message_from_bytes(mime_content)
        else:
            email_content = email.message_from_string(mime_content)
        if item.headers:
            attached_email_headers = [
                (h, " ".join(map(str.strip, v.split("\r\n"))))
                for (h, v) in list(email_content.items())
            ]
            for header in item.headers:
                if (
                        header.name,
                        header.value,
                ) not in attached_email_headers and header.name != "Content-Type":
                    email_content.add_header(header.name, header.value)

        eml_name = item.subject if item.subject else "demisto_untitled_eml"
        file_result = fileResult(eml_name + ".eml", email_content.as_string())
        file_result = (
            file_result if file_result else "Failed uploading eml file to war room"
        )

        return file_result


def parse_incident_from_item(item):
    """
    Parses an incident from an item
    :param item: item to parse
    :return: Parsed item
    """
    incident = {}
    labels = []

    try:
        incident["details"] = item.text_body or item.body
    except AttributeError:
        incident["details"] = item.body
    incident["name"] = item.subject
    labels.append({"type": "Email/subject", "value": item.subject})
    incident["occurred"] = item.datetime_created.ewsformat()

    # handle recipients
    if item.to_recipients:
        for recipient in item.to_recipients:
            labels.append({"type": "Email", "value": recipient.email_address})

    # handle cc
    if item.cc_recipients:
        for recipient in item.cc_recipients:
            labels.append({"type": "Email/cc", "value": recipient.email_address})
    # handle email from
    if item.sender:
        labels.append({"type": "Email/from", "value": item.sender.email_address})

    # email format
    email_format = ""
    try:
        if item.text_body:
            labels.append({"type": "Email/text", "value": item.text_body})
            email_format = "text"
    except AttributeError:
        pass
    if item.body:
        labels.append({"type": "Email/html", "value": item.body})
        email_format = "HTML"
    labels.append({"type": "Email/format", "value": email_format})

    # handle attachments
    if item.attachments:
        incident["attachment"] = []
        for attachment in item.attachments:
            file_result = None
            label_attachment_type = None
            label_attachment_id_type = None
            if isinstance(attachment, FileAttachment):
                try:
                    if attachment.content:
                        # file attachment
                        label_attachment_type = "attachments"
                        label_attachment_id_type = "attachmentId"

                        # save the attachment
                        file_name = get_attachment_name(attachment.name)
                        file_result = fileResult(file_name, attachment.content)

                        # check for error
                        if file_result["Type"] == entryTypes["error"]:
                            demisto.error(file_result["Contents"])
                            raise Exception(file_result["Contents"])

                        # save attachment to incident
                        incident["attachment"].append(
                            {
                                "path": file_result["FileID"],
                                "name": get_attachment_name(attachment.name),
                            }
                        )
                except TypeError as e:
                    if str(e) != "must be string or buffer, not None":
                        raise
                    continue
            else:
                # other item attachment
                label_attachment_type = "attachmentItems"
                label_attachment_id_type = "attachmentItemsId"

                # save the attachment
                if attachment.item.mime_content:
                    mime_content = attachment.item.mime_content
                    attached_email = email.message_from_bytes(mime_content) if isinstance(mime_content, bytes) \
                        else email.message_from_string(mime_content)
                    if attachment.item.headers:
                        attached_email_headers = [
                            (h, " ".join(map(str.strip, v.split("\r\n"))))
                            for (h, v) in list(attached_email.items())
                        ]
                        for header in attachment.item.headers:
                            if (
                                    (header.name, header.value)
                                    not in attached_email_headers
                                    and header.name != "Content-Type"
                            ):
                                attached_email.add_header(header.name, header.value)

                    file_result = fileResult(
                        get_attachment_name(attachment.name) + ".eml",
                        attached_email.as_string(),
                    )

                if file_result:
                    # check for error
                    if file_result["Type"] == entryTypes["error"]:
                        demisto.error(file_result["Contents"])
                        raise Exception(file_result["Contents"])

                    # save attachment to incident
                    incident["attachment"].append(
                        {
                            "path": file_result["FileID"],
                            "name": get_attachment_name(attachment.name) + ".eml",
                        }
                    )

            labels.append(
                {
                    "type": label_attachment_type,
                    "value": get_attachment_name(attachment.name),
                }
            )
            labels.append(
                {"type": label_attachment_id_type, "value": attachment.attachment_id.id}
            )

    # handle headers
    if item.headers:
        headers = []
        for header in item.headers:
            labels.append(
                {
                    "type": "Email/Header/{}".format(header.name),
                    "value": str(header.value),
                }
            )
            headers.append("{}: {}".format(header.name, header.value))
        labels.append({"type": "Email/headers", "value": "\r\n".join(headers)})

    # handle item id
    if item.message_id:
        labels.append({"type": "Email/MessageId", "value": str(item.message_id)})

    if item.id:
        labels.append({"type": "Email/ID", "value": item.id})
        labels.append({"type": "Email/itemId", "value": item.id})

    # handle conversion id
    if item.conversation_id:
        labels.append({"type": "Email/ConversionID", "value": item.conversation_id.id})

    incident["labels"] = labels
    incident["rawJSON"] = json.dumps(parse_item_as_dict(item, None), ensure_ascii=False)

    return incident


def fetch_emails_as_incidents(client: EWSClient, last_run):
    """
    Fetch incidents
    :param client: EWS Client
    :param last_run: last run dict
    :return:
    """
    last_run = get_last_run(client, last_run)

    try:
        last_emails = fetch_last_emails(
            client,
            client.folder_name,
            last_run.get(LAST_RUN_TIME),
            last_run.get(LAST_RUN_IDS),
        )

        ids = deque(
            last_run.get(LAST_RUN_IDS, []), maxlen=client.last_run_ids_queue_size
        )
        incidents = []
        incident: Dict[str, str] = {}
        for item in last_emails:
            if item.message_id:
                ids.append(item.message_id)
                incident = parse_incident_from_item(item)
                incidents.append(incident)

                if len(incidents) >= client.max_fetch:
                    break

        last_run_time = incident.get("occurred", last_run.get(LAST_RUN_TIME))
        if isinstance(last_run_time, EWSDateTime):
            last_run_time = last_run_time.ewsformat()

        new_last_run = {
            LAST_RUN_TIME: last_run_time,
            LAST_RUN_FOLDER: client.folder_name,
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


def fetch_last_emails(
        client: EWSClient, folder_name="Inbox", since_datetime=None, exclude_ids=None
):
    """
    Fetches last emails
    :param client: EWS client
    :param (Optional) folder_name: folder name to pull from
    :param (Optional) since_datetime: items will be searched after this datetime
    :param (Optional) exclude_ids: exclude ids from fetch
    :return: list of exchangelib.Items
    """
    qs = client.get_folder_by_path(folder_name, is_public=client.is_public_folder)
    if since_datetime:
        qs = qs.filter(datetime_received__gte=since_datetime)
    else:
        last_10_min = EWSDateTime.now(tz=EWSTimeZone.timezone("UTC")) - timedelta(
            minutes=10
        )
        qs = qs.filter(last_modified_time__gte=last_10_min)
    qs = qs.filter().only(*[x.name for x in Message.FIELDS])
    qs = qs.filter().order_by("datetime_received")

    result = qs.all()
    result = [x for x in result if isinstance(x, Message)]
    if exclude_ids and len(exclude_ids) > 0:
        exclude_ids = set(exclude_ids)
        result = [x for x in result if x.message_id not in exclude_ids]
    return result


def test_module(client: EWSClient, max_fetch):
    """
    test-module
    * Max incidents per fetch <= MAX_INCIDENTS_PER_FETCH
    * Account can be retrieved
    * Account has read rights
    * Test access to fetch folder
    :param client: EWS Client
    :param max_fetch: Max fetches per incident
    :return: "ok"
    """
    try:
        if int(max_fetch) > MAX_INCIDENTS_PER_FETCH:
            return_error(f'Error - Max incidents per fetch cannot be greater than {MAX_INCIDENTS_PER_FETCH}. '
                         f'You provided: {max_fetch}')
        account = client.get_account()
        if not account.root.effective_rights.read:  # pylint: disable=E1101
            raise Exception(
                "Success to authenticate, but user has no permissions to read from the mailbox. "
                "Need to delegate the user permissions to the mailbox - "
                "please read integration documentation and follow the instructions"
            )
        client.get_folder_by_path(
            client.folder_name, account, client.is_public_folder
        ).test_access()
    except ErrorFolderNotFound as e:
        if "Top of Information Store" in str(e):
            raise Exception(
                "Success to authenticate, but user probably has no permissions to read from the specific folder."
                "Check user permissions. You can try !ews-find-folders command to "
                "get all the folders structure that the user has permissions to"
            )

    return "ok"


def sub_main():
    is_test_module = False
    params = demisto.params()
    args = prepare_args(demisto.args())
    params['default_target_mailbox'] = args.get('target_mailbox', params['default_target_mailbox'])
    client = EWSClient(**params)
    start_logging()
    try:
        command = demisto.command()
        # commands that return a single note result
        normal_commands = {
            "ews-get-searchable-mailboxes": get_searchable_mailboxes,
            "ews-move-item-between-mailboxes": move_item_between_mailboxes,
            "ews-move-item": move_item,
            "ews-delete-items": delete_items,
            "ews-search-mailbox": search_items_in_mailbox,
            "ews-get-contacts": get_contacts,
            "ews-get-out-of-office": get_out_of_office_state,
            "ews-recover-messages": recover_soft_delete_item,
            "ews-create-folder": create_folder,
            "ews-mark-item-as-junk": mark_item_as_junk,
            "ews-find-folders": find_folders,
            "ews-get-items-from-folder": get_items_from_folder,
            "ews-get-items": get_items,
            "ews-get-folder": get_folder,
            "ews-expand-group": get_expanded_group,
            "ews-mark-items-as-read": mark_item_as_read,
            "send-mail": send_email,
        }

        # commands that may return multiple results or non-note result
        special_output_commands = {
            "ews-get-attachment": fetch_attachments_for_message,
            "ews-delete-attachment": delete_attachments_for_message,
            "ews-get-items-as-eml": get_item_as_eml,
        }
        # system commands:
        if command == "test-module":
            is_test_module = True
            demisto.results(test_module(client, params.get('max_fetch')))
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            incidents = fetch_emails_as_incidents(client, last_run)
            demisto.incidents(incidents)

        # special outputs commands
        elif command in special_output_commands:
            demisto.results(special_output_commands[command](client, **args))  # type: ignore[operator]

        # normal commands
        else:
            output = normal_commands[command](client, **args)  # type: ignore[operator]
            return_outputs(*output)

    except Exception as e:
        start_logging()
        debug_log = log_stream.getvalue()  # type: ignore[union-attr]
        error_message_simple = ""

        # Office365 regular maintenance case
        if isinstance(e, ErrorMailboxStoreUnavailable) or isinstance(
                e, ErrorMailboxMoveInProgress
        ):
            log_message = (
                "Office365 is undergoing load balancing operations. "
                "As a result, the service is temporarily unavailable."
            )
            if demisto.command() == "fetch-incidents":
                demisto.info(log_message)
                demisto.incidents([])
                sys.exit(0)
            if is_test_module:
                demisto.results(
                    log_message + " Please retry the instance configuration test."
                )
                sys.exit(0)
            error_message_simple = log_message + " Please retry your request."

        if isinstance(e, ConnectionError):
            error_message_simple = (
                "Could not connect to the server.\n"
                f"Additional information: {str(e)}"
            )
        else:
            if is_test_module and isinstance(e, MalformedResponseError):
                error_message_simple = (
                    "Got invalid response from the server.\n"
                )

        # Legacy error handling
        if "Status code: 401" in debug_log:
            error_message_simple = (
                "Got unauthorized from the server. "
            )

        if "Status code: 503" in debug_log:
            error_message_simple = (
                "Got timeout from the server. "
                "Probably the server is not reachable with the current settings. "
            )

        if not error_message_simple:
            error_message = error_message_simple = str(e)
        else:
            error_message = error_message_simple + "\n" + str(e)

        stacktrace = traceback.format_exc()
        if stacktrace:
            error_message += "\nFull stacktrace:\n" + stacktrace

        if debug_log:
            error_message += "\nFull debug log:\n" + debug_log

        if demisto.command() == "fetch-incidents":
            raise
        if demisto.command() == "ews-search-mailbox" and isinstance(e, ValueError):
            return_error(
                message="Selected invalid field, please specify valid field name.",
                error=e,
            )
        if is_test_module:
            demisto.results(error_message_simple)
        else:
            demisto.results(
                {
                    "Type": entryTypes["error"],
                    "ContentsFormat": formats["text"],
                    "Contents": error_message_simple,
                }
            )
        demisto.error(f"{e.__class__.__name__}: {error_message}")
    finally:
        exchangelib_cleanup()
        if log_stream:
            try:
                logging.getLogger().removeHandler(log_handler)  # type: ignore
                log_stream.close()
            except Exception as ex:
                demisto.error(
                    "EWS: unexpected exception when trying to remove log handler: {}".format(
                        ex
                    )
                )


def process_main():
    """setup stdin to fd=0 so we can read from the server"""
    sys.stdin = os.fdopen(0, "r")
    sub_main()


def main():
    # When running big queries, like 'ews-search-mailbox' the memory might not freed by the garbage
    # collector. `separate_process` flag will run the integration on a separate process that will prevent
    # memory leakage.
    separate_process = demisto.params().get("separate_process", False)
    demisto.debug("Running as separate_process: {}".format(separate_process))
    if separate_process:
        try:
            p = Process(target=process_main)
            p.start()
            p.join()
        except Exception as ex:
            demisto.error("Failed starting Process: {}".format(ex))
    else:
        sub_main()


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
