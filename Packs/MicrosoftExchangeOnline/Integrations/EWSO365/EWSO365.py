import email
import hashlib
import json
import logging
import os
import subprocess
import sys
import traceback
import warnings
from email import _header_value_parser as parser
from email.policy import SMTP, SMTPUTF8
from io import StringIO
from multiprocessing import Process
from xml.sax import SAXParseException

import chardet
import dateparser
import exchangelib
from exchangelib import (
    DELEGATE,
    OAUTH2,
    Body,
    EWSDateTime,
    EWSTimeZone,
    ExtendedProperty,
    FileAttachment,
    Folder,
    HTMLBody,
    ItemAttachment,
)
from exchangelib.errors import (
    ErrorFolderNotFound,
    ErrorInvalidIdMalformed,
    ErrorMailboxMoveInProgress,
    ErrorMailboxStoreUnavailable,
    ErrorNameResolutionNoResults,
    MalformedResponseError,
    RateLimitError,
    ResponseMessageError,
)
from exchangelib.items import Contact, Message
from exchangelib.services.common import EWSAccountService, EWSService
from exchangelib.util import MNS, TNS, add_xml_child, create_element
from requests.exceptions import ConnectionError

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from EWSApiModule import *

# Ignore warnings print to stdout
warnings.filterwarnings("ignore")

""" Constants """
INTEGRATION_NAME = get_integration_name()
APP_NAME = "ms-ews-o365"
FOLDER_ID_LEN = 120
MAX_INCIDENTS_PER_FETCH = 200
FETCH_TIME = demisto.params().get('fetch_time') or '10 minutes'

# move results
MOVED_TO_MAILBOX = "movedToMailbox"
MOVED_TO_FOLDER = "movedToFolder"

# item types
FILE_ATTACHMENT_TYPE = "FileAttachment"
ITEM_ATTACHMENT_TYPE = "ItemAttachment"
ATTACHMENT_TYPE = "attachmentType"

TOIS_PATH = "/root/Top of Information Store/"

# context keys
ATTACHMENT_ORIGINAL_ITEM_ID = "originalItemId"
NEW_ITEM_ID = "newItemId"
MESSAGE_ID = "messageId"
ITEM_ID = "itemId"
MAILBOX = "mailbox"
MAILBOX_ID = "mailboxId"
FOLDER_ID = "id"
TARGET_MAILBOX = 'receivedBy'

# context paths
CONTEXT_UPDATE_EWS_ITEM = f"EWS.Items((val.{ITEM_ID} === obj.{ITEM_ID} || " \
    f"(val.{MESSAGE_ID} && obj.{MESSAGE_ID} && val.{MESSAGE_ID} === obj.{MESSAGE_ID}))" \
    f" && val.{TARGET_MAILBOX} === obj.{TARGET_MAILBOX})"

CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT = f"EWS.Items(val.{ITEM_ID} == obj.{ATTACHMENT_ORIGINAL_ITEM_ID})"
CONTEXT_UPDATE_FOLDER = f"EWS.Folders(val.{FOLDER_ID} == obj.{FOLDER_ID})"

# fetch params
LAST_RUN_TIME = "lastRunTime"
LAST_RUN_IDS = "ids"
LAST_RUN_FOLDER = "folderName"
ERROR_COUNTER = "errorCounter"

# Types of filter
MODIFIED_FILTER = "modified-time"
RECEIVED_FILTER = "received-time"

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

# attachment name param
LEGACY_NAME = argToBoolean(demisto.params().get('legacy_name', False))
UTF_8 = 'utf-8'

# If you are modifying this probably also need to modify in other files
def exchangelib_cleanup():  # pragma: no cover
    key_protocols = list(exchangelib.protocol.CachingProtocol._protocol_cache.items())
    try:
        exchangelib.close_connections()
    except Exception as ex:
        demisto.error(f"Error was found in exchangelib cleanup, ignoring: {ex}")
    for key, (protocol, _) in key_protocols:
        try:
            if "thread_pool" in protocol.__dict__:
                demisto.debug(
                    f"terminating thread pool key{key} id: {id(protocol.thread_pool)}"
                )
                protocol.thread_pool.terminate()
                del protocol.__dict__["thread_pool"]
            else:
                demisto.info(
                    f"Thread pool not found (ignoring terminate) in protocol dict: {dir(protocol.__dict__)}"
                )
        except Exception as ex:
            demisto.error(f"Error with thread_pool.terminate, ignoring: {ex}")


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


def get_client_from_params(params: dict) -> EWSClient:
    """
    Parse the integration params and create an EWS client object
    Args:
        params (dict): dict received from demisto.params()

    Returns:
        EWSClient: EWS client object to interact with the exchange API
    """
    client_id = params.get('_client_id') or params.get('client_id', '')
    client_secret = (params.get('credentials') or {}).get('password') or params.get('client_secret', '')
    tenant_id = params.get('_tenant_id') or params.get('tenant_id', '')
    if not client_secret:
        raise Exception('Key / Application Secret must be provided.')
    elif not client_id:
        raise Exception('ID / Application ID must be provided.')
    elif not tenant_id:
        raise Exception('Token / Tenant ID must be provided.')

    access_type = params.get('access_type', DELEGATE) or DELEGATE
    access_type = (access_type[0] if isinstance(access_type, list) else access_type).lower()
    default_target_mailbox = params.get('default_target_mailbox', '')
    max_fetch = min(int(params.get('max_fetch', MAX_INCIDENTS_PER_FETCH)), MAX_INCIDENTS_PER_FETCH)
    azure_cloud = get_azure_cloud(params, INTEGRATION_NAME)
    ews_server = f'{azure_cloud.endpoints.exchange_online}/EWS/Exchange.asmx/'
    folder = params.get('folder', 'Inbox')
    is_public_folder = argToBoolean(params.get('is_public_folder', False))
    request_timeout = int(params.get('request_timeout', 120))
    mark_as_read = params.get('mark_as_read', False)
    incident_filter = IncidentFilter(params.get('incidentFilter', IncidentFilter.RECEIVED_FILTER))
    self_deployed = argToBoolean(params.get('self_deployed', False))
    insecure = argToBoolean(params.get('insecure', False))
    proxy = params.get('proxy', False)

    return EWSClient(
        client_id=client_id,
        client_secret=client_secret,
        access_type=access_type,
        default_target_mailbox=default_target_mailbox,
        max_fetch=max_fetch,
        ews_server=ews_server,
        auth_type=OAUTH2,
        version='O365',
        folder=folder,
        is_public_folder=is_public_folder,
        request_timeout=request_timeout,
        mark_as_read=mark_as_read,
        incident_filter=incident_filter,
        azure_cloud=azure_cloud,
        tenant_id=tenant_id,
        self_deployed=self_deployed,
        log_memory=is_debug_mode(),
        app_name=APP_NAME,
        insecure=insecure,
        proxy=proxy,
    )


def get_attachment_name(attachment_name, eml_extension=False, content_id="", is_inline=False):
    """
    Retrieve attachment name or error string if none is provided
    :param attachment_name: attachment name to retrieve
    :param eml_extension: Indicates whether the eml extension should be added
    :return: string
    """
    if is_inline and content_id and content_id != "None" and not LEGACY_NAME:
        if attachment_name is None or attachment_name == "":
            return (f"{content_id}-attachmentName-demisto_untitled_attachment.eml"
                    if eml_extension
                    else f"{content_id}-attachmentName-demisto_untitled_attachment")
        elif eml_extension and not attachment_name.endswith(".eml"):
            return f'{content_id}-attachmentName-{attachment_name}.eml'
        return f'{content_id}-attachmentName-{attachment_name}'
    if attachment_name is None or attachment_name == "":
        return "demisto_untitled_attachment.eml" if eml_extension else "demisto_untitled_attachment"
    elif eml_extension and not attachment_name.endswith(".eml"):
        return f'{attachment_name}.eml'
    return attachment_name


def prepare_args(args):
    """
    Prepare arguments to be used as the API expects it
    :param args: demisto args
    :return: transformed args
    """
    args = {k.replace("-", "_"): v for k, v in list(args.items())}
    if "is_public" in args:
        args["is_public"] = args["is_public"] == "True"
    if "from" in args:
        args['from_address'] = args.pop('from')
    return args


def get_limited_number_of_messages_from_qs(qs, limit):  # pragma: no cover
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


def keys_to_camel_case(value):  # pragma: no cover
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
    if isinstance(value, list | set):
        return list(map(keys_to_camel_case, value))
    if isinstance(value, dict):
        return {
            keys_to_camel_case(k): keys_to_camel_case(v) if isinstance(v, list | dict) else v
            for (k, v) in list(value.items())
        }

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
        "CC": None if not item.cc_recipients else
        [mailbox.email_address for mailbox in item.cc_recipients],
        "BCC": None
        if not item.bcc_recipients else
        [mailbox.email_address for mailbox in item.bcc_recipients],
        "To": None if not item.to_recipients else
        [mailbox.email_address for mailbox in item.to_recipients],
        "From": item.author.email_address,
        "Subject": item.subject,
        "Text": item.text_body,
        "HTML": item.body,
        "HeadersMap": None if not item.headers else
        {header.name: header.value for header in item.headers},
    }


def parse_item_as_dict(item, email_address=None, camel_case=False, compact_fields=False):  # pragma: no cover
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

    def parse_folder_as_json(folder):  # pragma: no cover
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
    demisto.debug(f"checking for attachments in email with id {item.id}")
    log_memory()
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

    for list_str_field in ["categories"]:
        value = getattr(item, list_str_field, None)
        if value:
            raw_dict[list_str_field] = value

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
            "categories"
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
    entry = fileResult(get_attachment_name(attachment_name=attachment.name, content_id=attachment.content_id,
                       is_inline=attachment.is_inline), attachment.content)
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
        if isinstance(attachment_content, str):  # Strings must be encoded before hashing
            attachment_content = attachment_content.encode()
        return {
            ATTACHMENT_ORIGINAL_ITEM_ID: item_id,
            ATTACHMENT_ID: attachment.attachment_id.id,
            "attachmentName": get_attachment_name(attachment_name=attachment.name,
                                                  content_id=attachment.content_id,
                                                  is_inline=attachment.is_inline),
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
            "attachmentName": get_attachment_name(attachment_name=attachment.name,
                                                  content_id=attachment.content_id,
                                                  is_inline=attachment.is_inline),
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


def get_entry_for_item_attachment(item_id, attachment, target_email):  # pragma: no cover
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
    title = (f'EWS get attachment got item for "{target_email}", '
             f'"{get_attachment_name(attachment_name=attachment.name, content_id=attachment.content_id, is_inline=attachment.is_inline)}"')  # noqa: E501

    return get_entry_for_object(
        title,
        CONTEXT_UPDATE_EWS_ITEM_FOR_ATTACHMENT + CONTEXT_UPDATE_ITEM_ATTACHMENT,
        dict_result,
    )


""" Command Functions """


def fetch_attachments_for_message(
    client: EWSClient, item_id, target_mailbox=None, attachment_ids=None, identifiers_filter=""
):  # pragma: no cover
    """
    Fetches attachments for a message
    :param client: EWS Client
    :param item_id: item id
    :param (Optional) target_mailbox: target mailbox
    :param (Optional) attachment_ids: attachment ids
    :param (Optional) identifiers_filter: attachment ids or content ids to create a fileResult
    :return: list of parsed entries
    """
    identifiers_filter = argToList(identifiers_filter)
    attachment_ids = argToList(attachment_ids)
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
                        get_attachment_name(attachment_name=attachment.name, eml_extension=True,
                                            content_id=attachment.content_id,
                                            is_inline=attachment.is_inline),
                        attachment.item.mime_content,
                    )
                )

    return entries


def search_items_in_mailbox(
    client: EWSClient,
    query=None,
    message_id=None,
    folder_path="",
    limit=100,
    target_mailbox=None,
    is_public=None,
    selected_fields="all",
):  # pragma: no cover
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
        message_id = f"<{message_id}>"

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
        restricted_fields = [x.name for x in Message.FIELDS]
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


def get_contacts(client: EWSClient, limit, target_mailbox=None):  # pragma: no cover
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
        contact_dict = {
            k: v if not isinstance(v, EWSDateTime) else v.ewsformat()
            for k, v in list(contact._field_vals())
            if isinstance(v, str | EWSDateTime)
        }
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
        contact_dict = {k: v for k, v in list(contact_dict.items()) if v}
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


def get_items_from_folder(
    client: EWSClient,
    folder_path,
    limit=100,
    target_mailbox=None,
    is_public=None,
    get_internal_item="no",
):  # pragma: no cover
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
        "itemId",
    ]
    readable_output = tableToMarkdown(
        "Items in folder " + folder_path, items_result, headers=hm_headers
    )
    output = {CONTEXT_UPDATE_EWS_ITEM: items_result}
    return readable_output, output, items_result


def get_items(client: EWSClient, item_ids, target_mailbox=None):  # pragma: no cover
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


def collect_manual_attachments(manualAttachObj):  # pragma: no cover
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


def collect_attachments(attachments_ids, attachments_cids, attachments_names):  # pragma: no cover
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

            filename = files_names[index] if len(files_names) > index and files_names[index] else file_res["name"]

            cid = files_cids[index] if len(files_cids) > index and files_cids[index] else ""

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

        file_cid = "" if index >= len(files_cids) else files_cids[index]

        transient_attachments.append({
            'name': file_name,
            'data': file_content,
            'cid': file_cid
        })

    return transient_attachments


def handle_template_params(template_params):  # pragma: no cover
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
            return_error(f'Unable to parse template_params: {str(e)}')

    return actual_params


def create_message_object(to, cc, bcc, subject, body, additional_headers, from_address, reply_to, importance):
    """Creates the message object according to the existence of additional custom headers.
    """
    if additional_headers:
        return Message(
            to_recipients=to,
            author=from_address,
            cc_recipients=cc,
            bcc_recipients=bcc,
            subject=subject,
            reply_to=reply_to,
            body=body,
            importance=importance,
            **additional_headers
        )

    return Message(
        to_recipients=to,
        author=from_address,
        cc_recipients=cc,
        bcc_recipients=bcc,
        subject=subject,
        reply_to=reply_to,
        body=body,
        importance=importance
    )


def create_message(
    to, handle_inline_image: bool = True, subject='', body='', bcc=None, cc=None, html_body=None,
    attachments=[], additional_headers=None, from_address=None, reply_to=None, importance=None,
):  # pragma: no cover
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
        from_address (str): The email address from which to reply.
        reply_to (list): Email addresses that need to be used to reply to the message.
        handle_inline_image (bool): Whether to handle inline images in the HTML body.
    Returns:
        Message. Message object ready to be sent.
    """
    demisto.debug(f"create_message: Received {len(attachments)} attachments, {handle_inline_image=}")
    if not html_body:
        # This is a simple text message - we cannot have CIDs here
        message = create_message_object(to, cc, bcc, subject, body, additional_headers, from_address, reply_to, importance)

        for attachment in attachments:
            if not attachment.get('cid'):
                new_attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'))
                message.attach(new_attachment)

    else:
        html_attachments: list = []
        if handle_inline_image:
            html_body, html_attachments = handle_html(html_body)
            attachments += html_attachments
            demisto.debug(f"create_message: Processed HTML body with {len(attachments)} attachments")
        message = create_message_object(to, cc, bcc, subject, HTMLBody(html_body), additional_headers, from_address,
                                        reply_to, importance)

        for attachment in attachments:
            if not isinstance(attachment, FileAttachment):
                if not attachment.get('cid'):
                    attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'))
                else:
                    attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'),
                                                is_inline=True, content_id=attachment.get('cid'))

            message.attach(attachment)

    return message


def add_additional_headers(additional_headers):
    """Adds custom headers to the Message object

    Args:
        additional_headers (str): Headers list as string. Example: headerName1=headerValue1,headerName2=headerValue2

    Returns:
        Dict. Headers dictionary in the form of: `header_name: header value`
    """
    headers = {}

    for header in argToList(additional_headers):
        header_name, header_value = header.split('=', 1)

        class TempClass(ExtendedProperty):
            distinguished_property_set_id = 'InternetHeaders'
            property_name = header_name
            property_type = 'String'

        try:
            Message.register(header_name, TempClass)
            headers[header_name] = header_value
        except ValueError:
            Message.deregister(header_name)
            try:
                Message.register(header_name, TempClass)
                headers[header_name] = header_value
            except ValueError as e:
                demisto.debug('EWSO365 - Header ' + header_name + ' could not be registered. ' + str(e))

    return headers


def send_email(client: EWSClient, to=None, subject='', body="", bcc=None, cc=None, htmlBody=None,
               attachIDs="", attachCIDs="", attachNames="", manualAttachObj=None,
               transientFile=None, transientFileContent=None, transientFileCID=None, templateParams=None,
               additionalHeader=None, raw_message=None, from_address=None, replyTo=None, importance=None,
               renderBody=False, handle_inline_image=True):  # pragma: no cover
    to = argToList(to)
    cc = argToList(cc)
    bcc = argToList(bcc)
    reply_to = argToList(replyTo)
    render_body = argToBoolean(renderBody)
    handle_inline_image = argToBoolean(handle_inline_image)

    # Basic validation - we allow pretty much everything but you have to have at least a recipient
    # We allow messages without subject and also without body
    if not to and not cc and not bcc:
        return_error('You must have at least one recipient')

    if raw_message:
        message = Message(
            to_recipients=to,
            cc_recipients=cc,
            bcc_recipients=bcc,
            body=raw_message,
            author=from_address,
            reply_to=reply_to,
            importance=importance
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
            if htmlBody:
                htmlBody = htmlBody.format(**template_params)

        message = create_message(
            to,
            handle_inline_image,
            subject,
            body,
            bcc,
            cc,
            htmlBody,
            attachments,
            additionalHeader,
            from_address,
            reply_to,
            importance
        )

    client.send_email(message)

    results = [CommandResults(entry_type=EntryType.NOTE, raw_response='Mail sent successfully')]
    if render_body:
        results.append(CommandResults(
            entry_type=EntryType.NOTE,
            content_format=EntryFormat.HTML,
            raw_response=htmlBody,
        ))

    return results


def reply_mail(client: EWSClient, to, inReplyTo, subject='', body="", bcc=None, cc=None, htmlBody=None,
               attachIDs="", attachCIDs="", attachNames="", manualAttachObj=None):  # pragma: no cover
    to = argToList(to)
    cc = argToList(cc)
    bcc = argToList(bcc)

    # collect all types of attachments
    attachments = collect_attachments(attachIDs, attachCIDs, attachNames)
    attachments.extend(collect_manual_attachments(manualAttachObj))
    client.reply_email(inReplyTo, to, body, subject, bcc, cc, htmlBody, attachments)


def get_item_as_eml(client: EWSClient, item_id, target_mailbox=None):  # pragma: no cover
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
        email_content = cast_mime_item_to_message(item)
        if item.headers:
            # compare header keys case-insensitive
            attached_email_headers = [
                (h.lower(), " ".join(map(str.strip, v.split("\r\n"))))
                for (h, v) in list(email_content.items())
            ]
            for header in item.headers:
                if (
                    header.name.lower(),
                    header.value,
                ) not in attached_email_headers and header.name.lower() != "content-type":
                    try:
                        email_content.add_header(header.name, header.value)
                    except ValueError as err:
                        if "There may be at most" not in str(err):
                            raise err

        eml_name = item.subject if item.subject else "demisto_untitled_eml"
        email_data = decode_email_data(email_content)
        file_result = fileResult(eml_name + ".eml", email_data)
        file_result = (
            file_result if file_result else "Failed uploading eml file to war room"
        )

        return file_result
    return None


def handle_attached_email_with_incorrect_message_id(attached_email: Message):
    """This function handles a malformed Message-ID value which can be returned in the header of certain email objects.
    This issue happens due to a current bug in "email" library and further explained in XSUP-32074.
    Public issue link: https://github.com/python/cpython/issues/105802

    The function will run on every attached email if exists, check its Message-ID header value and fix it if possible.
    Args:
        attached_email (Message): attached email object.

    Returns:
        Message: attached email object.
    """
    message_id_value = ""
    for i in range(len(attached_email._headers)):
        if attached_email._headers[i][0].lower() == "message-id":
            message_id = attached_email._headers[i][1]
            message_header = attached_email._headers[i][0]
            demisto.debug(f'Handling Message-ID header, {message_id=}.')
            try:
                message_id_value = handle_incorrect_message_id(message_id)
                if message_id_value != message_id:
                    # If the Message-ID header was fixed in the context of this function
                    # the header will be replaced in _headers list
                    attached_email._headers.pop(i)
                    attached_email._headers.append((message_header, message_id_value))

            except Exception as e:
                # The function is designed to handle a specific format error for the Message-ID header
                # as explained in the docstring.
                # That being said, we do expect the header to be in a known format.
                # If this function encounters a header format which is not in the known format and can't be fixed,
                # the header will be ignored completely to prevent crashing the fetch command.
                demisto.debug(f"Invalid {message_id=}, Error: {e}")
                break
            break
    return attached_email


def handle_attached_email_with_incorrect_from_header(attached_email: Message):
    """This function handles a malformed From value which can be returned in the header of certain email objects.
    This issue happens due to a current bug in "email" library.
    Public issue link: https://github.com/python/cpython/issues/114906

    The function will run on every attached email if exists, check its From header value and fix it if possible.
    Args:
        attached_email (Message): attached email object.

    Returns:
        Message: attached email object.
    """
    for i, (header_name, header_value) in enumerate(attached_email._headers):
        if header_name.lower() == "from":
            demisto.debug(f'Handling From header, value={header_value}.')
            try:
                new_value = parser.get_address_list(header_value)[0].value
                new_value = new_value.replace("\n", " ").replace("\r", " ").strip()
                if header_value != new_value:
                    # Update the 'From' header with the corrected value
                    attached_email._headers[i] = (header_name, new_value)
                    demisto.debug(f'From header fixed, new value: {new_value}')

            except Exception as e:
                demisto.debug(f"Error processing From header: {e}")
            break
    return attached_email


def handle_incorrect_message_id(message_id: str) -> str:
    """
    Use regex to identify and correct one of the following invalid message_id formats:
    1. '<[message_id]>' --> '<message_id>'
    2. '\r\n\t<[message_id]>' --> '\r\n\t<message_id>'
    If no necessary changes identified the original 'message_id' argument value is returned.
    """
    if re.search(r"\<\[.*\]\>", message_id):
        # find and replace "<[" with "<" and "]>" with ">"
        fixed_message_id = re.sub(r'<\[(.*?)\]>', r'<\1>', message_id)
        demisto.debug('Fixed message id {message_id} to {fixed_message_id}')
        return fixed_message_id
    return message_id


def decode_email_data(email_obj: Message):
    attached_email_bytes = email_obj.as_bytes()
    chardet_detection = chardet.detect(attached_email_bytes)
    encoding = chardet_detection.get('encoding', 'utf-8') or 'utf-8'
    try:
        # Trying to decode using the detected encoding
        data = attached_email_bytes.decode(encoding)
    except UnicodeDecodeError:
        # In case the detected encoding fails apply the default encoding
        demisto.info(f'Could not decode attached email using detected encoding: {encoding}, retrying '
                     f'using utf-8.\nAttached email details: '
                     f'\nMessage-ID = {email_obj.get("Message-ID")}'
                     f'\nDate = {email_obj.get("Date")}'
                     f'\nSubject = {email_obj.get("Subject")}'
                     f'\nFrom = {email_obj.get("From")}'
                     f'\nTo = {email_obj.get("To")}')
        try:
            data = attached_email_bytes.decode('utf-8')
        except UnicodeDecodeError:
            demisto.info('Could not decode attached email using utf-8. returned the content without decoding')
            data = attached_email_bytes  # type: ignore

    return data


def cast_mime_item_to_message(item):
    mime_content = item.mime_content
    email_policy = SMTP if mime_content.isascii() else SMTPUTF8

    if isinstance(mime_content, str) and not mime_content.isascii():
        mime_content = mime_content.encode()

    if isinstance(mime_content, bytes):
        message = email.message_from_bytes(mime_content, policy=email_policy)  # type: ignore[arg-type]
    else:
        message = email.message_from_string(mime_content, policy=email_policy)  # type: ignore[arg-type]

    return message


def parse_incident_from_item(item):  # pragma: no cover
    """
    Parses an incident from an item
    :param item: item to parse
    :return: Parsed item
    """
    incident = {}
    labels = []
    demisto.debug(f"starting to parse the email with id {item.id} into an incident")
    log_memory()
    try:
        incident["details"] = item.text_body or item.body
    except AttributeError:
        incident["details"] = item.body
    incident["name"] = item.subject
    labels.append({"type": "Email/subject", "value": item.subject})
    incident["occurred"] = item.datetime_received.ewsformat()

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
        labels.append({"type": "Email/from/name", "value": item.sender.name})

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
        demisto.debug(f"parsing {len(item.attachments)} attachments for item with id {item.id}")
        attachment_counter = 0
        for attachment in item.attachments:
            attachment_counter += 1
            demisto.debug(f'retrieving attachment number {attachment_counter} of email with id {item.id}')
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
                        file_name = get_attachment_name(attachment_name=attachment.name,
                                                        content_id=attachment.content_id,
                                                        is_inline=attachment.is_inline)
                        demisto.debug(f"saving content number {attachment_counter}, "
                                      f"of size {sys.getsizeof(attachment.content)}, of email with id {item.id}")
                        file_result = fileResult(file_name, attachment.content)

                        # check for error
                        if file_result["Type"] == entryTypes["error"]:
                            demisto.error(file_result["Contents"])
                            raise Exception(file_result["Contents"])

                        # save attachment to incident
                        incident["attachment"].append(
                            {
                                "path": file_result["FileID"],
                                "name": get_attachment_name(attachment_name=attachment.name,
                                                            content_id=attachment.content_id,
                                                            is_inline=attachment.is_inline),
                                "description": FileAttachmentType.ATTACHED if not attachment.is_inline else "",
                            }
                        )
                except TypeError as e:
                    if str(e) != "must be string or buffer, not None":
                        raise
                    continue
                except SAXParseException as e:
                    # TODO: When a fix is released, we will need to bump the library version.
                    #  https://github.com/ecederstrand/exchangelib/issues/1200
                    demisto.debug(f'An XML error occurred while loading an attachments content.'
                                  f'\nMessage ID is {item.id}'
                                  f'\nError: {e.getMessage()}')
                    continue
            else:
                # other item attachment
                label_attachment_type = "attachmentItems"
                label_attachment_id_type = "attachmentItemsId"

                # save the attachment
                if attachment.item.mime_content:
                    attached_email = cast_mime_item_to_message(attachment.item)
                    if attachment.item.headers:
                        # compare header keys case-insensitive
                        attached_email_headers = []
                        attached_email = handle_attached_email_with_incorrect_message_id(attached_email)
                        attached_email = handle_attached_email_with_incorrect_from_header(attached_email)
                        for h, v in attached_email.items():
                            if not isinstance(v, str):
                                try:
                                    v = str(v)
                                except:  # noqa: E722
                                    demisto.debug(f'cannot parse the header "{h}"')
                                    continue

                            v = ' '.join(map(str.strip, v.split('\r\n')))
                            attached_email_headers.append((h.lower(), v))
                        demisto.debug(f'{attached_email_headers=}')
                        for header in attachment.item.headers:
                            if (
                                (header.name.lower(), header.value)
                                not in attached_email_headers
                                and header.name.lower() != "content-type"
                            ):
                                try:
                                    if header.name.lower() == "message-id":
                                        """ Handle a case where a Message-ID header was NOT already in attached_email,
                                        and instead is coming from attachment.item.headers.
                                        Meaning it wasn't handled in handle_attached_email_with_incorrect_message_id function
                                        and instead it is handled here using handle_incorrect_message_id function."""
                                        correct_message_id = handle_incorrect_message_id(header.value)
                                        if (header.name.lower(), correct_message_id) not in attached_email_headers:
                                            attached_email.add_header(header.name, correct_message_id)
                                    else:
                                        attached_email.add_header(header.name, header.value)
                                except ValueError as err:
                                    if "There may be at most" not in str(err):
                                        raise err

                    data = decode_email_data(attached_email)
                    file_result = fileResult(get_attachment_name(attachment_name=attachment.name,
                                             eml_extension=True, content_id=attachment.content_id,
                                             is_inline=attachment.is_inline), data)

                if file_result:
                    # check for error
                    if file_result["Type"] == entryTypes["error"]:
                        demisto.error(file_result["Contents"])
                        raise Exception(file_result["Contents"])

                    # save attachment to incident
                    incident["attachment"].append(
                        {
                            "path": file_result["FileID"],
                            "name": get_attachment_name(attachment_name=attachment.name,
                                                        eml_extension=True,
                                                        content_id=attachment.content_id,
                                                        is_inline=attachment.is_inline),
                        }
                    )

            labels.append(
                {
                    "type": label_attachment_type,
                    "value": get_attachment_name(attachment_name=attachment.name,
                                                 content_id=attachment.content_id,
                                                 is_inline=attachment.is_inline),
                }
            )
            labels.append(
                {"type": label_attachment_id_type, "value": attachment.attachment_id.id}
            )
        demisto.debug(f'finished parsing attachment {attachment_counter} of email with id {item.id}')

    # handle headers
    if item.headers:
        headers = []
        for header in item.headers:
            labels.append(
                {
                    "type": f"Email/Header/{header.name}",
                    "value": str(header.value),
                }
            )
            headers.append(f"{header.name}: {header.value}")
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
    demisto.debug(f"Starting to generate rawJSON for incident, from email with id {item.id}")
    log_memory()
    incident["rawJSON"] = json.dumps(parse_item_as_dict(item, None), ensure_ascii=False)
    log_memory()
    demisto.debug(f"Finished generating rawJSON from email with id {item.id}")

    return incident


def fetch_emails_as_incidents(client: EWSClient, last_run, incident_filter, skip_unparsable_emails: bool = False):
    """
    Fetch incidents
    :param client: EWS Client
    :param last_run: last run dict
    :return:
    """
    log_memory()
    last_run = get_last_run(client, last_run)
    demisto.debug(f"get_last_run: {last_run=}")
    excluded_ids = set(last_run.get(LAST_RUN_IDS, []))
    try:
        last_emails = fetch_last_emails(
            client,
            client.folder_name,
            last_run.get(LAST_RUN_TIME),
            excluded_ids,
            incident_filter,
        )

        incidents = []
        incident: dict[str, str] = {}
        emails_ids = []  # Used for mark emails as read
        demisto.debug(f'{APP_NAME} - Started fetch with {len(last_emails)} at {last_run.get(LAST_RUN_TIME)}')
        current_fetch_ids = set()

        last_fetch_time = last_run.get(LAST_RUN_TIME)

        last_modification_time = last_fetch_time
        if isinstance(last_modification_time, EWSDateTime):
            last_modification_time = last_modification_time.ewsformat()

        for item in last_emails:
            try:
                if item.message_id:
                    current_fetch_ids.add(item.message_id)
                    incident = parse_incident_from_item(item)
                    incidents.append(incident)

                    if incident_filter == MODIFIED_FILTER:
                        item_modified_time = item.last_modified_time.ewsformat()
                        if last_modification_time is None or last_modification_time < item_modified_time:
                            last_modification_time = item_modified_time

                    if item.id:
                        emails_ids.append(item.id)

                    if len(incidents) >= client.max_fetch:
                        break
            except Exception as e:
                if not skip_unparsable_emails:  # default is to raise and exception and fail the command
                    raise

                # when the skip param is `True`, we log the exceptions and move on instead of failing the whole fetch
                error_msg = (
                    "Encountered email parsing issue while fetching. "
                    f"Skipping item with message id: {item.message_id or '<error parsing message_id>'}"
                )
                demisto.debug(f"{error_msg}, Error: {str(e)} {traceback.format_exc()}")
                demisto.updateModuleHealth(error_msg, is_error=False)

        demisto.debug(f'{APP_NAME} - ending fetch - got {len(incidents)} incidents.')

        if incident_filter == MODIFIED_FILTER:
            last_incident_run_time = last_modification_time
        else:  # default case - using 'received' time
            last_incident_run_time = incident.get("occurred", last_fetch_time)

        # making sure both last fetch time and the time of most recent incident are the same type for comparing.
        if isinstance(last_incident_run_time, EWSDateTime):
            last_incident_run_time = last_incident_run_time.ewsformat()

        if isinstance(last_fetch_time, EWSDateTime):
            last_fetch_time = last_fetch_time.ewsformat()

        demisto.debug(
            f'#### last_incident_time: {last_incident_run_time}({type(last_incident_run_time)}).'
            f'last_fetch_time: {last_fetch_time}({type(last_fetch_time)}) ####')

        # If the fetch query is not fully fetched (we didn't have any time progress) - then we keep the
        # id's from current fetch until progress is made. This is for when max_fetch < incidents_from_query.
        if not last_incident_run_time or not last_fetch_time or last_incident_run_time > last_fetch_time:
            ids = current_fetch_ids
        else:
            ids = current_fetch_ids | excluded_ids

        new_last_run = {
            LAST_RUN_TIME: last_incident_run_time,
            LAST_RUN_FOLDER: client.folder_name,
            LAST_RUN_IDS: list(ids),
            ERROR_COUNTER: 0,
        }

        demisto.debug(f'Set last run to: {new_last_run=}')
        demisto.setLastRun(new_last_run)

        if client.mark_as_read:
            mark_item_as_read(client, emails_ids)

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
    client: EWSClient, folder_name="Inbox", since_datetime=None, exclude_ids=None, incident_filter=RECEIVED_FILTER
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
    demisto.debug(f"Finished getting the folder named {folder_name} by path")
    log_memory()
    if since_datetime:
        if incident_filter == MODIFIED_FILTER:
            qs = qs.filter(last_modified_time__gte=since_datetime)
        else:  # default to "received" time
            qs = qs.filter(datetime_received__gte=since_datetime)
    else:
        tz = EWSTimeZone('UTC')
        first_fetch_datetime = dateparser.parse(FETCH_TIME)
        assert first_fetch_datetime is not None
        first_fetch_ews_datetime = EWSDateTime.from_datetime(first_fetch_datetime.replace(tzinfo=tz))
        qs = qs.filter(last_modified_time__gte=first_fetch_ews_datetime)
        demisto.debug(f"{first_fetch_ews_datetime=}")
    qs = qs.filter().only(*[x.name for x in Message.FIELDS if x.name.lower() != 'mime_content'])
    qs = qs.filter().order_by("datetime_received")
    result = []
    exclude_ids = exclude_ids if exclude_ids else set()
    demisto.debug(f'{APP_NAME} - Exclude ID list: {exclude_ids}')
    qs.chunk_size = min(client.max_fetch, 100)
    qs.page_size = min(client.max_fetch, 100)
    demisto.debug("Before iterating on queryset")
    demisto.debug(f'Size of the queryset object in fetch-incidents: {sys.getsizeof(qs)}')
    for item in qs:
        demisto.debug("next iteration of the queryset in fetch-incidents")
        if isinstance(item, Message) and item.message_id not in exclude_ids:
            result.append(item)
            if len(result) >= client.max_fetch:
                break
        else:
            demisto.debug(f'message_id {item.message_id} was excluded. IsMessage: {isinstance(item, Message)}')
    demisto.debug(f'{APP_NAME} - Got total of {len(result)} from ews query.')
    log_memory()
    return result


def test_module(client: EWSClient, max_fetch):  # pragma: no cover
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


def sub_main():  # pragma: no cover
    is_test_module = False
    params = demisto.params()
    args = prepare_args(demisto.args())
    # client's default_target_mailbox is the authorization source for the instance
    params['default_target_mailbox'] = args.get('target_mailbox',
                                                args.get('source_mailbox', params.get('default_target_mailbox', '')))
    if params.get('upn_mailbox') and not (args.get('target_mailbox')):
        params['default_target_mailbox'] = params.get('upn_mailbox', '')

    if params.get('access_type') == 'Impersonation':
        demisto.info(
            'Note: The access type Impersonation you are using is deprecated. For more information, '
            'please refer to the integration description.')
    try:
        client = get_client_from_params(params)
        start_logging()
        # replace sensitive access_token value in logs
        if not isinstance(client.credentials, CustomDomainOAuth2Credentials):  # Should not fail
            raise DemistoException('Failed to initialize EWS Client properly, check credentials')

        add_sensitive_log_strs(client.credentials.access_token.get('access_token', ''))
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
        }

        # commands that may return multiple results or non-note result
        special_output_commands = {
            "ews-get-attachment": fetch_attachments_for_message,
            "ews-delete-attachment": delete_attachments_for_message,
            "ews-get-items-as-eml": get_item_as_eml,
            "reply-mail": reply_mail,
        }
        # system commands:
        if command == "test-module":
            is_test_module = True
            demisto.results(test_module(client, params.get('max_fetch')))
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            incident_filter = params.get('incidentFilter', RECEIVED_FILTER)
            if incident_filter not in [RECEIVED_FILTER, MODIFIED_FILTER]:  # Ensure it's one of the allowed filter values
                incident_filter = RECEIVED_FILTER  # or if not, force it to the default, RECEIVED_FILTER
            demisto.debug(f"{incident_filter=}")
            skip_unparsable_emails: bool = argToBoolean(params.get("skip_unparsable_emails", False))
            incidents = fetch_emails_as_incidents(client, last_run, incident_filter, skip_unparsable_emails)
            demisto.debug(f"Saving incidents with size {sys.getsizeof(incidents)}")
            demisto.incidents(incidents)

        elif command == "send-mail":
            commands_res = send_email(client, **args)
            return_results(commands_res)

        # special outputs commands
        elif command in special_output_commands:
            demisto.results(special_output_commands[command](client, **args))  # type: ignore[operator]

        elif command == "ews-auth-reset":
            return_results(reset_auth())

        # normal commands
        else:
            output = normal_commands[command](client, **args)  # type: ignore[operator]
            if isinstance(output, tuple): # Legacy, some commands return a tuple for return outputs
                return_outputs(*output)
            else:
                return_results(output)

    except Exception as e:
        demisto.error(f'got exception {e}')
        start_logging()
        debug_log = log_stream.getvalue()  # type: ignore[union-attr]
        error_message_simple = ""

        # Office365 regular maintenance case
        if isinstance(e, ErrorMailboxStoreUnavailable | ErrorMailboxMoveInProgress):
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
                    f"EWS: unexpected exception when trying to remove log handler: {ex}"
                )


def process_main():
    """setup stdin to fd=0 so we can read from the server"""
    sys.stdin = os.fdopen(0, "r")
    sub_main()


def main():  # pragma: no cover
    # When running big queries, like 'ews-search-mailbox' the memory might not be freed by the garbage
    # collector. `separate_process` flag will run the integration on a separate process that will prevent
    # memory leakage.
    separate_process = demisto.params().get("separate_process", False)
    demisto.debug(f"Running as separate_process: {separate_process}")
    if separate_process:
        try:
            p = Process(target=process_main)
            p.start()
            p.join()
            demisto.debug("subprocess finished")
        except Exception as ex:
            demisto.error(f"Failed starting Process: {ex}")
    else:
        sub_main()


def log_memory():
    if is_debug_mode():
        demisto.debug(f'memstat\n{str(subprocess.check_output(["ps", "-opid,comm,rss,vsz"]))}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
