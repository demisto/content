import hashlib
import os
import re
import time
import traceback
import uuid
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import demistomock as demisto
from CommonServerPython import *

""" CONSTANTS """

UTC_TZ = timezone.utc  # noqa: UP017  (datetime.UTC is unavailable in the Python 3.10 used by mypy)

OPERATION_SEARCH = "Search Only"
OPERATION_DELETE = "Search & Delete"
OPERATIONS = [OPERATION_SEARCH, OPERATION_DELETE]

SCOPE_SPECIFIC = "Specific"
SCOPE_ALL = "All"
SCOPES = [SCOPE_SPECIFIC, SCOPE_ALL]

DELETE_SOFT = "Soft"
DELETE_HARD = "Hard"
DELETE_TYPES = [DELETE_SOFT, DELETE_HARD]

DEFAULT_TIME_FRAME = "1 hour"

# Brands (the `brand` value reported by `demisto.getModules()`).
GMAIL_BRAND = "Gmail"
MSGRAPH_MAIL_BRAND = "MicrosoftGraphMail"
MSGRAPH_SECURITY_BRAND = "Microsoft Graph"
EWS_BRAND = "EWS v2"
# Used only to enumerate the mailboxes of the tenant when the scope is "All" and the vendor has no listing command.
MSGRAPH_USER_BRAND = "Microsoft Graph User"

SUPPORTED_BRANDS = [GMAIL_BRAND, MSGRAPH_MAIL_BRAND, MSGRAPH_SECURITY_BRAND, EWS_BRAND]
BRAND_ALIASES = {
    **{brand.lower(): brand for brand in SUPPORTED_BRANDS},
    "microsoft graph security": MSGRAPH_SECURITY_BRAND,
    "microsoftgraphsecurity": MSGRAPH_SECURITY_BRAND,
    "microsoft graph mail": MSGRAPH_MAIL_BRAND,
    "o365 outlook mail (using graph api)": MSGRAPH_MAIL_BRAND,
    "ews": EWS_BRAND,
    "ewsv2": EWS_BRAND,
}

# Tunables (all of them are bounded so the script can never loop forever).
MAX_PAGES = 1000  # Safety bound for every pagination loop.
GMAIL_MAILBOX_CHUNK_SIZE = 100  # Mailboxes passed to a single `gmail-search-all-mailboxes` call.
GMAIL_MAX_RESULTS = 500  # Gmail API maximum page size.
GMAIL_USERS_PAGE_SIZE = 500
MSGRAPH_MAIL_PAGE_SIZE = 50
MSGRAPH_MAIL_PAGES_TO_PULL = 20
EWS_SEARCH_LIMIT = 1000
EWS_MAILBOX_CHUNK_SIZE = 50  # Mailboxes passed to a single `ews-search-mailboxes` call.
EWS_ITEMS_CHUNK_SIZE = 50  # Item IDs passed to a single `ews-get-items` / `ews-delete-items` call.
MSGRAPH_SECURITY_CASE_NAME = "XSOAR Search And Delete Email"
MSGRAPH_SECURITY_POLL_INTERVAL_SECONDS = 20
MSGRAPH_SECURITY_POLL_MAX_ATTEMPTS = 90

VERIFY_UNSUPPORTED_WARNING = (
    "Deletion verification (verify_deletion) is not supported for Microsoft Graph Security. "
    "The deletion will be performed without verification for this integration."
)
GMAIL_NEXT_PAGE_TOKEN_PATTERN = re.compile(r"page-token:\s*(\S+)")

""" DATA MODELS """


class InputError(ValueError):
    """Raised when the arguments provided by the user are invalid."""


class CommandError(Exception):
    """Raised when an integration command returns an error entry."""


@dataclass
class Attachment:
    name: str
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass
class SearchParams:
    operation: str
    mailbox_scope: str
    mailboxes: list[str]
    brands: list[str]
    start_time: datetime
    delete_type: str = DELETE_SOFT
    internet_message_ids: list[str] = field(default_factory=list)
    object_id: str = ""
    subject: str = ""
    sender_address: str = ""
    retrieve_files: bool = False
    verbose: bool = False
    verify_deletion: bool = False


@dataclass
class EmailRecord:
    """A vendor-agnostic representation of a found email (or of a failure of a brand)."""

    brand: str
    mailbox: str = ""
    object_id: str = ""
    subject: str = ""
    sender: str = ""
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    html: str = ""
    timestamp: str = ""
    internet_message_id: str = ""
    has_attachments: bool | None = None
    attachments: dict[str, str] = field(default_factory=dict)
    files: list[Attachment] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)  # Exposed in AdditionalFields only when verbose.
    found: bool = True  # False for placeholder records that describe a failure.
    count: int = 1  # Number of emails represented by the record (aggregated vendors report more than one).
    success: bool = True
    reason: str = ""
    deleted: bool = False
    verified: bool | None = None


@dataclass(frozen=True)
class BrandHandler:
    """Functions implementing the operations of a single brand. Missing operations are simply unsupported."""

    brand: str
    search: Callable[[SearchParams, list[str]], list[EmailRecord]] | None = None
    get_by_id: Callable[[SearchParams], list[EmailRecord]] | None = None
    delete: Callable[[SearchParams, list[EmailRecord]], None] | None = None
    get_attachments: Callable[[EmailRecord], list[Attachment]] | None = None
    verify: Callable[[SearchParams, list[EmailRecord]], set[str]] | None = None
    list_mailboxes: Callable[[SearchParams], list[str]] | None = None
    # Vendors whose search can't be separated from the deletion (Microsoft Graph Security).
    combined: Callable[[SearchParams, list[str], bool], list[EmailRecord]] | None = None


""" GENERIC HELPERS """


def dedupe(values: Iterable[str]) -> list[str]:
    """Removes empty values and duplicates while preserving the order."""
    return list(dict.fromkeys(value for value in values if value))


def chunked(items: list, size: int) -> Iterator[list]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def to_str_list(value: Any) -> list[str]:
    """Normalizes address-like values (string, dict with an address or a list of those) to a list of strings."""
    if not value:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, dict):
        address = value.get("Address") or value.get("address") or value.get("emailAddress")
        return to_str_list(address) if address else []
    if isinstance(value, list | tuple | set):
        result: list[str] = []
        for item in value:
            result.extend(to_str_list(item))
        return result
    return [str(value)]


def find_header(headers: Any, name: str) -> str:
    """Finds the value of a header in a list of {name, value} dicts (or in a dict)."""
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == name:
                return str(value)
    elif isinstance(headers, list):
        for header in headers:
            if isinstance(header, dict) and str(header.get("Name") or header.get("name") or "").lower() == name:
                return str(header.get("Value") or header.get("value") or "")
    return ""


def strip_angle_brackets(message_id: str) -> str:
    return message_id.strip().removeprefix("<").removesuffix(">")


def ensure_angle_brackets(message_id: str) -> str:
    return f"<{strip_angle_brackets(message_id)}>"


def escape_quotes(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def to_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def execute(command: str, args: dict[str, Any], brand: str) -> list[dict[str, Any]]:
    """Runs an integration command on the given brand. Raises CommandError if the command returned an error."""
    demisto.debug(f"Running {command} using brand {brand}")
    entries = demisto.executeCommand(command, {**args, "using-brand": brand}) or []
    if is_error(entries):
        raise CommandError(f"{command} failed: {get_error(entries)}")
    return entries


def get_context(entries: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    """Collects the dict items stored under `key` (with or without a DT suffix) in the entries' contexts."""
    items: list[dict[str, Any]] = []
    for entry in entries:
        for context_key, value in (entry.get("EntryContext") or {}).items():
            if context_key == key or context_key.startswith(f"{key}("):
                items.extend(item for item in (value if isinstance(value, list) else [value]) if isinstance(item, dict))
    return items


def files_from_entries(entries: list[dict[str, Any]]) -> list[Attachment]:
    """Reads the content of the file entries returned by an integration command."""
    attachments: list[Attachment] = []
    for entry in entries:
        if entry.get("Type") != EntryType.FILE:
            continue
        file_info = demisto.getFilePath(entry.get("ID"))
        with open(file_info["path"], "rb") as file_handle:
            attachments.append(
                Attachment(name=file_info.get("name") or entry.get("File") or "attachment", data=file_handle.read())
            )
    return attachments


def paginate(fetch_page: Callable[[str], tuple[list, str]], max_pages: int = MAX_PAGES) -> list:
    """Calls fetch_page(token) until it returns no next token (bounded by max_pages and by token repetition)."""
    items: list = []
    token = ""
    seen_tokens: set[str] = set()
    for _ in range(max_pages):
        page, token = fetch_page(token)
        items.extend(page)
        if not token or token in seen_tokens:
            return items
        seen_tokens.add(token)
    demisto.debug(f"Pagination stopped after reaching the maximum of {max_pages} pages.")
    return items


def received_since(timestamp: str, start_time: datetime) -> bool:
    """Whether an email timestamp is not older than start_time. Unparsable timestamps are kept."""
    if not timestamp:
        return True
    try:
        parsed = arg_to_datetime(timestamp)
    except ValueError:
        return True
    if parsed is None:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC_TZ)
    return parsed >= start_time


def error_record(brand: str, reason: str, mailbox: str = "") -> EmailRecord:
    return EmailRecord(brand=brand, mailbox=mailbox, found=False, count=0, success=False, reason=reason)


def mark_deleted(record: EmailRecord) -> None:
    record.deleted = True
    record.success = True
    record.reason = ""


def mark_failed(record: EmailRecord, reason: str) -> None:
    record.deleted = False
    record.success = False
    record.reason = reason


def delete_each(records: list[EmailRecord], delete_one: Callable[[EmailRecord], None]) -> None:
    for record in records:
        try:
            delete_one(record)
            mark_deleted(record)
        except CommandError as error:
            mark_failed(record, str(error))


def dedupe_records(records: list[EmailRecord]) -> list[EmailRecord]:
    unique: dict[tuple, EmailRecord] = {}
    for index, record in enumerate(records):
        key = (record.brand, record.mailbox.lower(), record.object_id) if record.object_id else (record.brand, index)
        unique.setdefault(key, record)
    return list(unique.values())


def group_by_mailbox(records: list[EmailRecord]) -> dict[str, list[EmailRecord]]:
    groups: dict[str, list[EmailRecord]] = {}
    for record in records:
        groups.setdefault(record.mailbox, []).append(record)
    return groups


def verify_by_lookup(records: list[EmailRecord], lookup: Callable[[EmailRecord], bool]) -> set[str]:
    """Returns the IDs of records that still exist. A lookup error means the item no longer exists."""
    present: set[str] = set()
    for record in records:
        try:
            exists = lookup(record)
        except CommandError:
            exists = False
        if exists:
            present.add(record.object_id)
    return present


""" INPUT PARSING AND VALIDATION """


def parse_time_frame(time_frame: str) -> datetime:
    """Converts a relative ('3 hours', '7 days') or absolute time frame to the start datetime (UTC)."""
    try:
        start_time = arg_to_datetime(time_frame, arg_name="time_frame", required=True)
    except ValueError as error:
        raise InputError(f"Invalid time_frame '{time_frame}'. Use a value such as '1 hour', '3 hours' or '7 days'.") from error
    if start_time is None:
        raise InputError(f"Invalid time_frame '{time_frame}'.")
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=UTC_TZ)
    if start_time > datetime.now(UTC_TZ):
        raise InputError(f"The time_frame '{time_frame}' must describe a period in the past (for example '7 days').")
    return start_time


def normalize_choice(value: Any, choices: list[str], name: str, required: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        if required:
            raise InputError(f"The '{name}' argument is required. Valid values: {', '.join(choices)}.")
        return ""
    for choice in choices:
        if choice.lower() == text.lower():
            return choice
    raise InputError(f"Invalid value '{text}' for '{name}'. Valid values: {', '.join(choices)}.")


def resolve_brands(requested: list[str], enabled_brands: set[str]) -> list[str]:
    """Returns the brands to use: the requested ones (must be supported and enabled) or all the enabled supported ones."""
    if requested:
        brands: list[str] = []
        for name in requested:
            canonical = BRAND_ALIASES.get(name.strip().lower())
            if not canonical:
                raise InputError(f"Unsupported brand '{name}'. Supported brands: {', '.join(SUPPORTED_BRANDS)}.")
            brands.append(canonical)
        brands = dedupe(brands)
        not_enabled = [brand for brand in brands if brand not in enabled_brands]
        if not_enabled:
            raise InputError(f"The following integrations have no active instance: {', '.join(not_enabled)}.")
        return brands
    brands = [brand for brand in SUPPORTED_BRANDS if brand in enabled_brands]
    if not brands:
        raise InputError(f"No active instance was found for the supported integrations: {', '.join(SUPPORTED_BRANDS)}.")
    return brands


def get_enabled_brands() -> set[str]:
    return {module.get("brand") for module in demisto.getModules().values() if module.get("state") == "active"}


def validate_object_id_args(object_id: str, mailboxes: list[str], requested_brands: list[str], scope: str) -> None:
    if not mailboxes or not requested_brands:
        raise InputError("When 'object_id' is specified, both 'target_mailbox' and 'brands' must be specified.")
    if len(mailboxes) > 1 or len(requested_brands) > 1 or scope == SCOPE_ALL:
        raise InputError(
            "When 'object_id' is specified, exactly one 'target_mailbox' and one brand must be given "
            f"(mailbox_scope must be '{SCOPE_SPECIFIC}')."
        )
    if BRAND_ALIASES.get(requested_brands[0].strip().lower()) == MSGRAPH_SECURITY_BRAND:
        raise InputError("'object_id' is not supported for Microsoft Graph Security.")


def parse_args(args: dict[str, Any], enabled_brands: set[str]) -> SearchParams:
    """Validates the script arguments and converts them to SearchParams. Raises InputError on invalid input."""
    operation = normalize_choice(args.get("operation"), OPERATIONS, "operation", required=True)
    scope = normalize_choice(args.get("mailbox_scope") or SCOPE_SPECIFIC, SCOPES, "mailbox_scope")
    delete_type = normalize_choice(args.get("delete_type") or DELETE_SOFT, DELETE_TYPES, "delete_type")
    internet_message_ids = dedupe(argToList(args.get("internet_message_id")))
    object_id = str(args.get("object_id") or "").strip()
    subject = str(args.get("subject") or "").strip()
    sender_address = str(args.get("sender_address") or "").strip()
    mailboxes = dedupe(argToList(args.get("target_mailbox")))
    requested_brands = argToList(args.get("brands"))

    if not (internet_message_ids or object_id or subject or sender_address):
        raise InputError("At least one of 'internet_message_id', 'object_id', 'subject' or 'sender_address' must be specified.")
    if object_id:
        validate_object_id_args(object_id, mailboxes, requested_brands, scope)
    elif scope == SCOPE_SPECIFIC and not mailboxes:
        raise InputError(f"'target_mailbox' is required when 'mailbox_scope' is '{SCOPE_SPECIFIC}'.")
    if scope == SCOPE_ALL:
        mailboxes = []  # The target mailboxes are ignored when all the mailboxes are searched.

    return SearchParams(
        operation=operation,
        mailbox_scope=scope,
        mailboxes=mailboxes,
        brands=resolve_brands(requested_brands, enabled_brands),
        start_time=parse_time_frame(args.get("time_frame") or DEFAULT_TIME_FRAME),
        delete_type=delete_type,
        internet_message_ids=internet_message_ids,
        object_id=object_id,
        subject=subject,
        sender_address=sender_address,
        retrieve_files=argToBoolean(args.get("retrieve_files") or False),
        verbose=argToBoolean(args.get("verbose") or False),
        verify_deletion=argToBoolean(args.get("verify_deletion") or False),
    )


""" GMAIL """


def build_gmail_query(params: SearchParams) -> str:
    """Internet message IDs are preferred over the subject / sender."""
    if params.internet_message_ids:
        terms = [f"rfc822msgid:{strip_angle_brackets(message_id)}" for message_id in params.internet_message_ids]
        parts = [terms[0] if len(terms) == 1 else f"({' OR '.join(terms)})"]
    else:
        parts = []
        if params.subject:
            parts.append(f'subject:"{escape_quotes(params.subject)}"')
        if params.sender_address:
            parts.append(f"from:{params.sender_address}")
    parts.append(f"after:{int(params.start_time.timestamp())}")
    return " ".join(parts)


def gmail_mail_to_record(mail: dict[str, Any], default_mailbox: str) -> EmailRecord:
    attachments = mail.get("Attachments") or []
    return EmailRecord(
        brand=GMAIL_BRAND,
        mailbox=mail.get("Mailbox") or default_mailbox,
        object_id=str(mail.get("ID") or ""),
        subject=mail.get("Subject") or "",
        sender=", ".join(to_str_list(mail.get("From"))),
        to=to_str_list(mail.get("To")),
        cc=to_str_list(mail.get("Cc")),
        bcc=to_str_list(mail.get("Bcc")),
        html=mail.get("Html") or "",
        timestamp=mail.get("Date") or "",
        internet_message_id=find_header(mail.get("Headers"), "message-id"),
        has_attachments=bool(attachments),
        details={
            "Body": mail.get("Body"),
            "Headers": mail.get("Headers"),
            "Labels": mail.get("Labels"),
            "ThreadId": mail.get("ThreadId"),
            "AttachmentNames": [attachment.get("Name") for attachment in attachments if isinstance(attachment, dict)],
        },
    )


def search_gmail_mailbox(mailbox: str, query: str, include_trash: bool) -> list[EmailRecord]:
    """Searches a single mailbox using `gmail-search`, following the page tokens."""

    def fetch_page(token: str) -> tuple[list, str]:
        command_args: dict[str, Any] = {
            "user-id": mailbox,
            "query": query,
            "max-results": GMAIL_MAX_RESULTS,
            "include-spam-trash": str(include_trash),
        }
        if token:
            command_args["page-token"] = token
        entries = execute("gmail-search", command_args, GMAIL_BRAND)
        tokens = get_context(entries, "GmailEmails")
        return get_context(entries, "Gmail"), str(tokens[0].get("NextPageToken") or "") if tokens else ""

    return [gmail_mail_to_record(mail, mailbox) for mail in paginate(fetch_page)]


def search_gmail_mailboxes_individually(mailboxes: list[str], query: str, include_trash: bool) -> list[EmailRecord]:
    records: list[EmailRecord] = []
    for mailbox in mailboxes:
        try:
            records.extend(search_gmail_mailbox(mailbox, query, include_trash))
        except CommandError as error:
            demisto.debug(f"Gmail search failed for mailbox {mailbox}: {error}")
            records.append(error_record(GMAIL_BRAND, str(error), mailbox))
    return records


def search_gmail_chunk(mailboxes: list[str], query: str, include_trash: bool) -> list[EmailRecord]:
    """Searches a chunk of mailboxes with one command. If the command fails, falls back to a per-mailbox search."""
    command_args = {
        "query": query,
        "list_accounts": ",".join(mailboxes),
        "max-results": GMAIL_MAX_RESULTS,
        "show-only-mailboxes": "false",
        "include-spam-trash": str(include_trash),
    }
    try:
        entries = execute("gmail-search-all-mailboxes", command_args, GMAIL_BRAND)
    except CommandError as error:
        demisto.debug(f"Gmail chunk search failed, searching mailboxes one by one: {error}")
        return search_gmail_mailboxes_individually(mailboxes, query, include_trash)

    records: list[EmailRecord] = []
    for entry in entries:
        mails = get_context([entry], "Gmail")
        next_page = get_context([entry], "GmailEmails")
        if next_page and next_page[0].get("NextPageToken") and mails:
            # The mailbox has more results than a single page: collect all of its pages.
            records.extend(search_gmail_mailboxes_individually([mails[0].get("Mailbox") or ""], query, include_trash))
        else:
            records.extend(gmail_mail_to_record(mail, "") for mail in mails)
    return records


def search_gmail(params: SearchParams, mailboxes: list[str], include_trash: bool = True) -> list[EmailRecord]:
    # Sequential on purpose: the integration already searches the mailboxes of a chunk in parallel.
    query = build_gmail_query(params)
    records: list[EmailRecord] = []
    for chunk in chunked(mailboxes, GMAIL_MAILBOX_CHUNK_SIZE):
        records.extend(search_gmail_chunk(chunk, query, include_trash))
    return dedupe_records(records)


def get_gmail_by_id(params: SearchParams) -> list[EmailRecord]:
    mailbox = params.mailboxes[0]
    entries = execute("gmail-get-mail", {"user-id": mailbox, "message-id": params.object_id, "format": "full"}, GMAIL_BRAND)
    return [gmail_mail_to_record(mail, mailbox) for mail in get_context(entries, "Gmail")]


def delete_gmail(params: SearchParams, records: list[EmailRecord]) -> None:
    permanent = str(params.delete_type == DELETE_HARD)

    def delete_one(record: EmailRecord) -> None:
        execute(
            "gmail-delete-mail", {"user-id": record.mailbox, "message-id": record.object_id, "permanent": permanent}, GMAIL_BRAND
        )

    delete_each(records, delete_one)


def get_gmail_attachments(record: EmailRecord) -> list[Attachment]:
    entries = execute("gmail-get-attachments", {"user-id": record.mailbox, "message-id": record.object_id}, GMAIL_BRAND)
    return files_from_entries(entries)


def verify_gmail(params: SearchParams, records: list[EmailRecord]) -> set[str]:
    """Searches again (without spam/trash) - soft-deleted emails are in the trash and hard-deleted ones are gone."""
    mailboxes = dedupe(record.mailbox for record in records)
    remaining = search_gmail(params, mailboxes, include_trash=False)
    return {record.object_id for record in remaining if record.found}


def list_gmail_mailboxes(params: SearchParams) -> list[str]:
    def fetch_page(token: str) -> tuple[list, str]:
        command_args: dict[str, Any] = {"max-results": GMAIL_USERS_PAGE_SIZE}
        if token:
            command_args["page-token"] = token
        entries = execute("gmail-list-users", command_args, GMAIL_BRAND)
        addresses = [
            (account.get("Gmail") or account.get("Email") or {}).get("Address") for account in get_context(entries, "Account")
        ]
        readable = "\n".join(str(entry.get("HumanReadable") or "") for entry in entries)
        match = GMAIL_NEXT_PAGE_TOKEN_PATTERN.search(readable)
        return addresses, match.group(1) if match else ""

    return dedupe(paginate(fetch_page))


""" MICROSOFT GRAPH MAIL """


def build_msgraph_mail_odata(params: SearchParams) -> str:
    """The time frame is applied locally on the received time to avoid Graph's 'InefficientFilter' limitation."""
    if params.internet_message_ids:
        clauses = [
            " or ".join(
                f"internetMessageId eq '{ensure_angle_brackets(message_id).replace(chr(39), chr(39) * 2)}'"
                for message_id in params.internet_message_ids
            )
        ]
    else:
        clauses = []
        if params.sender_address:
            clauses.append(f"from/emailAddress/address eq '{params.sender_address.replace(chr(39), chr(39) * 2)}'")
        if params.subject:
            clauses.append(f"contains(subject,'{params.subject.replace(chr(39), chr(39) * 2)}')")
    return f"$filter={' and '.join(clauses)}"


def msgraph_mail_to_record(mail: dict[str, Any], default_mailbox: str) -> EmailRecord:
    return EmailRecord(
        brand=MSGRAPH_MAIL_BRAND,
        mailbox=mail.get("UserID") or default_mailbox,
        object_id=str(mail.get("ID") or ""),
        subject=mail.get("Subject") or "",
        sender=", ".join(to_str_list(mail.get("From") or mail.get("Sender"))),
        to=to_str_list(mail.get("Recipients")),
        cc=to_str_list(mail.get("CCRecipients")),
        bcc=to_str_list(mail.get("BCCRecipients")),
        html=mail.get("Body") or "",
        timestamp=mail.get("ReceivedTime") or mail.get("SendTime") or "",
        internet_message_id=mail.get("InternetMessageID") or "",
        has_attachments=mail.get("HasAttachments"),
        details={
            "ConversationID": mail.get("ConversationID"),
            "Categories": mail.get("Categories"),
            "IsDraft": mail.get("IsDraft"),
            "ReplyTo": mail.get("ReplyTo"),
        },
    )


def search_msgraph_mail(params: SearchParams, mailboxes: list[str]) -> list[EmailRecord]:
    # The command has no mailbox list argument, so the mailboxes are searched one by one.
    odata = build_msgraph_mail_odata(params)
    records: list[EmailRecord] = []
    for mailbox in mailboxes:
        command_args = {
            "user_id": mailbox,
            "odata": odata,
            "page_size": MSGRAPH_MAIL_PAGE_SIZE,
            "pages_to_pull": MSGRAPH_MAIL_PAGES_TO_PULL,
        }
        try:
            entries = execute("msgraph-mail-list-emails", command_args, MSGRAPH_MAIL_BRAND)
        except CommandError as error:
            demisto.debug(f"Microsoft Graph Mail search failed for mailbox {mailbox}: {error}")
            records.append(error_record(MSGRAPH_MAIL_BRAND, str(error), mailbox))
            continue
        items = get_context(entries, "MSGraphMail")
        if any(item.get("NextPage") for item in items):
            demisto.debug(f"Mailbox {mailbox} has more than {MSGRAPH_MAIL_PAGES_TO_PULL} pages of results.")
        records.extend(
            msgraph_mail_to_record(item, mailbox)
            for item in items
            if item.get("ID") and received_since(item.get("ReceivedTime") or "", params.start_time)
        )
    return dedupe_records(records)


def get_msgraph_mail_by_id(params: SearchParams) -> list[EmailRecord]:
    mailbox = params.mailboxes[0]
    entries = execute(
        "msgraph-mail-get-email", {"user_id": mailbox, "message_id": params.object_id, "get_body": "true"}, MSGRAPH_MAIL_BRAND
    )
    return [msgraph_mail_to_record(item, mailbox) for item in get_context(entries, "MSGraphMail") if item.get("ID")]


def delete_msgraph_mail(params: SearchParams, records: list[EmailRecord]) -> None:
    """Microsoft Graph moves the email to the Deleted Items folder; there is no command for a hard delete."""

    def delete_one(record: EmailRecord) -> None:
        execute("msgraph-mail-delete-email", {"user_id": record.mailbox, "message_id": record.object_id}, MSGRAPH_MAIL_BRAND)
        if params.delete_type == DELETE_HARD:
            record.details["Note"] = "Hard delete is not supported by Microsoft Graph Mail; the email was moved to Deleted Items."

    delete_each(records, delete_one)


def get_msgraph_mail_attachments(record: EmailRecord) -> list[Attachment]:
    entries = execute(
        "msgraph-mail-get-attachment", {"user_id": record.mailbox, "message_id": record.object_id}, MSGRAPH_MAIL_BRAND
    )
    return files_from_entries(entries)


def verify_msgraph_mail(params: SearchParams, records: list[EmailRecord]) -> set[str]:
    """Moving an email to Deleted Items changes its ID, so the original ID must no longer be found."""

    def lookup(record: EmailRecord) -> bool:
        execute("msgraph-mail-get-email", {"user_id": record.mailbox, "message_id": record.object_id}, MSGRAPH_MAIL_BRAND)
        return True

    return verify_by_lookup(records, lookup)


def list_msgraph_mailboxes(params: SearchParams) -> list[str]:
    """Lists the tenant users using the Microsoft Graph User integration."""

    def fetch_page(token: str) -> tuple[list, str]:
        command_args: dict[str, Any] = {"properties": "id,mail,userPrincipalName"}
        if token:
            command_args["next_page"] = token
        users = get_context(execute("msgraph-user-list", command_args, MSGRAPH_USER_BRAND), "MSGraphUser")
        next_page = next((str(user["NextPage"]) for user in users if user.get("NextPage")), "")
        return [user.get("Mail") or user.get("UserPrincipalName") for user in users if not user.get("NextPage")], next_page

    return dedupe(paginate(fetch_page))


""" EWS """


def build_ews_query(params: SearchParams) -> str:
    parts = []
    if params.subject:
        parts.append(f'Subject:"{escape_quotes(params.subject)}"')
    if params.sender_address:
        parts.append(f'From:"{escape_quotes(params.sender_address)}"')
    parts.append(f"Received:>={params.start_time.strftime('%Y-%m-%d')}")
    return " AND ".join(parts)


def ews_item_to_record(item: dict[str, Any], default_mailbox: str) -> EmailRecord:
    attachment_names = [
        attachment.get("attachmentName")
        for attachment in (item.get("FileAttachments") or []) + (item.get("ItemAttachments") or [])
        if isinstance(attachment, dict)
    ]
    return EmailRecord(
        brand=EWS_BRAND,
        mailbox=item.get("mailbox") or default_mailbox,
        object_id=str(item.get("itemId") or ""),
        subject=item.get("subject") or "",
        sender=", ".join(to_str_list(item.get("sender"))),
        to=to_str_list(item.get("toRecipients")),
        html=item.get("body") or "",
        timestamp=item.get("datetimeReceived") or "",
        internet_message_id=item.get("messageId") or "",
        has_attachments=item.get("hasAttachments"),
        details={
            "Body": item.get("textBody"),
            "Headers": item.get("headers"),
            "IsRead": item.get("isRead"),
            "Size": item.get("size"),
            "AttachmentNames": attachment_names,
        },
    )


def search_ews_by_message_ids(params: SearchParams, mailboxes: list[str]) -> list[EmailRecord]:
    records: list[EmailRecord] = []
    for mailbox in mailboxes:
        for message_id in params.internet_message_ids:
            command_args = {"target-mailbox": mailbox, "message-id": message_id, "limit": EWS_SEARCH_LIMIT}
            try:
                entries = execute("ews-search-mailbox", command_args, EWS_BRAND)
            except CommandError as error:
                demisto.debug(f"EWS search failed for mailbox {mailbox}: {error}")
                records.append(error_record(EWS_BRAND, str(error), mailbox))
                continue
            records.extend(ews_item_to_record(item, mailbox) for item in get_context(entries, "EWS.Items") if item.get("itemId"))
    return records


def search_ews_by_query(params: SearchParams, mailboxes: list[str]) -> list[EmailRecord]:
    """Uses the eDiscovery search, which is also able to search all the mailboxes (empty chunk = no mailbox restriction)."""
    query = build_ews_query(params)
    records: list[EmailRecord] = []
    for chunk in list(chunked(mailboxes, EWS_MAILBOX_CHUNK_SIZE)) or [[]]:
        command_args: dict[str, Any] = {"filter": query, "limit": EWS_SEARCH_LIMIT}
        if chunk:
            command_args["email_addresses"] = ",".join(chunk)
        try:
            entries = execute("ews-search-mailboxes", command_args, EWS_BRAND)
        except CommandError as error:
            records.append(error_record(EWS_BRAND, str(error), ",".join(chunk)))
            continue
        records.extend(ews_item_to_record(item, "") for item in get_context(entries, "EWS.Items") if item.get("itemId"))
    return records


def enrich_ews_records(records: list[EmailRecord]) -> list[EmailRecord]:
    """The multi-mailbox search returns partial data; fetches the full items of the records that lack a body."""
    missing = [record for record in records if record.found and not record.html]
    for mailbox, group in group_by_mailbox(missing).items():
        by_id = {record.object_id: record for record in group}
        for chunk in chunked(list(by_id), EWS_ITEMS_CHUNK_SIZE):
            try:
                entries = execute("ews-get-items", {"item-ids": ",".join(chunk), "target-mailbox": mailbox}, EWS_BRAND)
            except CommandError as error:
                demisto.debug(f"Failed enriching EWS items of {mailbox}: {error}")
                continue
            for item in get_context(entries, "EWS.Items"):
                full = ews_item_to_record(item, mailbox)
                target = by_id.get(full.object_id)
                if not target:
                    continue
                for attribute in ("html", "subject", "sender", "timestamp", "internet_message_id"):
                    if getattr(full, attribute) and not getattr(target, attribute):
                        setattr(target, attribute, getattr(full, attribute))
                if target.has_attachments is None:
                    target.has_attachments = full.has_attachments
                target.details.update({key: value for key, value in full.details.items() if value is not None})
    return records


def search_ews(params: SearchParams, mailboxes: list[str]) -> list[EmailRecord]:
    records = (
        search_ews_by_message_ids(params, mailboxes) if params.internet_message_ids else search_ews_by_query(params, mailboxes)
    )
    records = [record for record in records if not record.found or received_since(record.timestamp, params.start_time)]
    return enrich_ews_records(dedupe_records(records))


def get_ews_by_id(params: SearchParams) -> list[EmailRecord]:
    mailbox = params.mailboxes[0]
    entries = execute("ews-get-items", {"item-ids": params.object_id, "target-mailbox": mailbox}, EWS_BRAND)
    return [ews_item_to_record(item, mailbox) for item in get_context(entries, "EWS.Items") if item.get("itemId")]


def delete_ews(params: SearchParams, records: list[EmailRecord]) -> None:
    delete_type = "hard" if params.delete_type == DELETE_HARD else "soft"
    for mailbox, group in group_by_mailbox(records).items():
        for chunk in chunked(group, EWS_ITEMS_CHUNK_SIZE):
            command_args = {
                "item-ids": ",".join(record.object_id for record in chunk),
                "delete-type": delete_type,
                "target-mailbox": mailbox,
            }
            try:
                entries = execute("ews-delete-items", command_args, EWS_BRAND)
            except CommandError as error:
                for record in chunk:
                    mark_failed(record, str(error))
                continue
            reported = {item.get("itemId") for item in get_context(entries, "EWS.Items")}
            for record in chunk:
                if not reported or record.object_id in reported:
                    mark_deleted(record)
                else:
                    mark_failed(record, "The item was not reported as deleted by EWS.")


def get_ews_attachments(record: EmailRecord) -> list[Attachment]:
    entries = execute("ews-get-attachment", {"item-id": record.object_id, "target-mailbox": record.mailbox}, EWS_BRAND)
    return files_from_entries(entries)


def verify_ews(params: SearchParams, records: list[EmailRecord]) -> set[str]:
    def lookup(record: EmailRecord) -> bool:
        entries = execute("ews-get-items", {"item-ids": record.object_id, "target-mailbox": record.mailbox}, EWS_BRAND)
        return any(item.get("itemId") for item in get_context(entries, "EWS.Items"))

    return verify_by_lookup(records, lookup)


def list_ews_mailboxes(params: SearchParams) -> list[str]:
    """Only needed for message ID searches; the query search natively covers all the mailboxes."""
    if not params.internet_message_ids:
        return []
    entries = execute("ews-get-searchable-mailboxes", {}, EWS_BRAND)
    return dedupe(item.get("mailbox") or "" for item in get_context(entries, "EWS.Mailboxes"))


""" MICROSOFT GRAPH SECURITY (eDiscovery) """


def build_kql_query(params: SearchParams, mailboxes: list[str]) -> str:
    clauses = ["kind:email"]
    if params.internet_message_ids:
        terms = [f'InternetMessageId:"{ensure_angle_brackets(message_id)}"' for message_id in params.internet_message_ids]
        clauses.append(f"({' OR '.join(terms)})")
    else:
        if params.subject:
            clauses.append(f'subject:"{escape_quotes(params.subject)}"')
        if params.sender_address:
            clauses.append(f'from:"{escape_quotes(params.sender_address)}"')
    clauses.append(f"received>={params.start_time.strftime('%Y-%m-%d')}")
    if mailboxes:
        clauses.append(f"({' OR '.join(f'participants:{mailbox}' for mailbox in mailboxes)})")
    return " AND ".join(clauses)


def get_or_create_security_case() -> str:
    entries = execute("msg-list-ediscovery-cases", {"all_results": "true"}, MSGRAPH_SECURITY_BRAND)
    for case in get_context(entries, "MsGraph.eDiscoveryCase"):
        if case.get("DisplayName") == MSGRAPH_SECURITY_CASE_NAME and case.get("CaseId"):
            return str(case["CaseId"])
    entries = execute(
        "msg-create-ediscovery-case",
        {"display_name": MSGRAPH_SECURITY_CASE_NAME, "description": "Case used by the Search & Delete Email script."},
        MSGRAPH_SECURITY_BRAND,
    )
    cases = get_context(entries, "MsGraph.eDiscoveryCase")
    case_id = cases[0].get("CaseId") if cases else ""
    if not case_id:
        raise CommandError("Failed to create the Microsoft Graph Security eDiscovery case.")
    return str(case_id)


def create_security_search(case_id: str, kql_query: str) -> str:
    """Step 1: creates the eDiscovery search."""
    entries = execute(
        "msg-create-ediscovery-search",
        {
            "case_id": case_id,
            "display_name": f"XSOAR-SearchAndDeleteEmail-{uuid.uuid4().hex[:12]}",
            "description": "Created by the Search & Delete Email script.",
            "content_query": kql_query,
            "data_source_scopes": "allTenantMailboxes",
        },
        MSGRAPH_SECURITY_BRAND,
    )
    searches = get_context(entries, "MsGraph.eDiscoverySearch")
    search_id = searches[0].get("SearchId") if searches else ""
    if not search_id:
        raise CommandError("Failed to create the Microsoft Graph Security eDiscovery search.")
    return str(search_id)


def run_estimate_and_wait(case_id: str, search_id: str) -> dict[str, Any]:
    """Steps 2+3: executes the search (estimate statistics), polls until it completes and returns its results."""
    ids = {"case_id": case_id, "search_id": search_id}
    execute("msg-run-estimate-statistics", ids, MSGRAPH_SECURITY_BRAND)
    for attempt in range(MSGRAPH_SECURITY_POLL_MAX_ATTEMPTS):
        entries = execute("msg-get-last-estimate-statistics-operation", ids, MSGRAPH_SECURITY_BRAND)
        statistics = get_context(entries, "MsGraph.eDiscovery.EstimateStatistics")
        status = str(statistics[0].get("status") or statistics[0].get("Status") or "").lower() if statistics else ""
        if status in ("succeeded", "completed", "partiallysucceeded"):
            return statistics[0]
        if status in ("failed", "submissionfailed"):
            raise CommandError(f"The eDiscovery estimate operation ended with status '{status}'.")
        demisto.debug(f"eDiscovery estimate still running (attempt {attempt + 1}/{MSGRAPH_SECURITY_POLL_MAX_ATTEMPTS}).")
        time.sleep(MSGRAPH_SECURITY_POLL_INTERVAL_SECONDS)
    raise CommandError("Timed out waiting for the Microsoft Graph Security eDiscovery search to complete.")


def build_security_record(params: SearchParams, statistics: dict[str, Any], case_id: str, search_id: str) -> EmailRecord:
    """The eDiscovery estimate has no per-email data, so the matching emails are reported as one aggregated record."""
    total = to_int(statistics.get("totalItemCount", statistics.get("TotalItemsCount")))
    return EmailRecord(
        brand=MSGRAPH_SECURITY_BRAND,
        mailbox=",".join(params.mailboxes),
        subject=params.subject,
        sender=params.sender_address,
        found=total > 0,
        count=total,
        details={
            "TotalItems": total,
            "MailboxCount": to_int(statistics.get("mailboxCount", statistics.get("MailboxCount"))),
            "CaseID": case_id,
            "SearchID": search_id,
        },
    )


def purge_security_search(params: SearchParams, case_id: str, search_id: str, record: EmailRecord) -> None:
    purge_type = "permanentlyDelete" if params.delete_type == DELETE_HARD else "recoverable"
    try:
        entries = execute(
            "msg-purge-ediscovery-data",
            {"case_id": case_id, "search_id": search_id, "purge_type": purge_type, "purge_areas": "mailboxes"},
            MSGRAPH_SECURITY_BRAND,
        )
    except CommandError as error:
        mark_failed(record, str(error))
        return
    purge = get_context(entries, "MsGraph.eDiscoveryCase.Purge")
    status = str(purge[0].get("Status") or "") if purge else ""
    record.details.update({"PurgeStatus": status, "PurgeOperationID": purge[0].get("OperationID") if purge else None})
    if "fail" in status.lower():
        mark_failed(record, f"The purge operation ended with status '{status}'.")
    else:
        mark_deleted(record)


def cleanup_security_search(case_id: str, search_id: str) -> None:
    """Deletes the search created by the script. A cleanup failure is logged but never masks the main result."""
    try:
        execute("msg-delete-ediscovery-search", {"case_id": case_id, "search_id": search_id}, MSGRAPH_SECURITY_BRAND)
    except Exception as error:
        demisto.error(f"Failed to delete eDiscovery search {search_id} of case {case_id}: {error}")


def run_msgraph_security(params: SearchParams, mailboxes: list[str], delete: bool) -> list[EmailRecord]:
    """create search -> execute (poll) -> retrieve results -> [purge]; the search is always deleted at the end."""
    case_id = get_or_create_security_case()
    search_id = ""
    try:
        search_id = create_security_search(case_id, build_kql_query(params, mailboxes))
        record = build_security_record(params, run_estimate_and_wait(case_id, search_id), case_id, search_id)
        if not record.found:
            return []
        if delete:
            purge_security_search(params, case_id, search_id, record)
        return [record]
    finally:
        if search_id:
            cleanup_security_search(case_id, search_id)


""" ORCHESTRATION """

HANDLERS: dict[str, BrandHandler] = {
    GMAIL_BRAND: BrandHandler(
        brand=GMAIL_BRAND,
        search=search_gmail,
        get_by_id=get_gmail_by_id,
        delete=delete_gmail,
        get_attachments=get_gmail_attachments,
        verify=verify_gmail,
        list_mailboxes=list_gmail_mailboxes,
    ),
    MSGRAPH_MAIL_BRAND: BrandHandler(
        brand=MSGRAPH_MAIL_BRAND,
        search=search_msgraph_mail,
        get_by_id=get_msgraph_mail_by_id,
        delete=delete_msgraph_mail,
        get_attachments=get_msgraph_mail_attachments,
        verify=verify_msgraph_mail,
        list_mailboxes=list_msgraph_mailboxes,
    ),
    MSGRAPH_SECURITY_BRAND: BrandHandler(brand=MSGRAPH_SECURITY_BRAND, combined=run_msgraph_security),
    EWS_BRAND: BrandHandler(
        brand=EWS_BRAND,
        search=search_ews,
        get_by_id=get_ews_by_id,
        delete=delete_ews,
        get_attachments=get_ews_attachments,
        verify=verify_ews,
        list_mailboxes=list_ews_mailboxes,
    ),
}


def resolve_mailboxes(handler: BrandHandler, params: SearchParams) -> list[str]:
    if params.mailbox_scope == SCOPE_SPECIFIC:
        return params.mailboxes
    return handler.list_mailboxes(params) if handler.list_mailboxes else []


def fetch_attachments(handler: BrandHandler, record: EmailRecord) -> None:
    """Retrieves the attachments of a record. A failure is recorded in the details and doesn't fail the record."""
    if record.has_attachments is False or not handler.get_attachments:
        return
    try:
        record.files = handler.get_attachments(record)
    except Exception as error:
        demisto.debug(f"Failed retrieving attachments of {record.object_id}: {error}")
        record.details["AttachmentsError"] = str(error)
        return
    record.attachments = {attachment.name: attachment.sha256 for attachment in record.files}


def delete_and_verify(handler: BrandHandler, params: SearchParams, records: list[EmailRecord]) -> None:
    if not handler.delete:
        raise CommandError(f"Deleting emails is not supported for {handler.brand}.")
    handler.delete(params, records)
    deleted = [record for record in records if record.deleted]
    if not params.verify_deletion or not handler.verify or not deleted:
        return
    try:
        still_present = handler.verify(params, deleted)
    except Exception as error:
        for record in deleted:
            mark_failed(record, f"The deletion could not be verified: {error}")
        return
    for record in deleted:
        if record.object_id in still_present:
            mark_failed(record, "The email still exists after the deletion (verification failed).")
        else:
            record.verified = True


def process_brand(handler: BrandHandler, params: SearchParams) -> list[EmailRecord]:
    delete = params.operation == OPERATION_DELETE
    mailboxes = resolve_mailboxes(handler, params)
    if handler.combined:
        return handler.combined(params, mailboxes, delete)
    if params.object_id and handler.get_by_id:
        records = handler.get_by_id(params)
    elif handler.search:
        records = handler.search(params, mailboxes)
    else:
        raise CommandError(f"Searching emails is not supported for {handler.brand}.")
    found = [record for record in records if record.found]
    if params.retrieve_files:
        for record in found:  # The attachments must be retrieved before the email is deleted.
            fetch_attachments(handler, record)
    if delete and found:
        delete_and_verify(handler, params, found)
    return records


def run_brand(handler: BrandHandler, params: SearchParams) -> list[EmailRecord]:
    """Runs a brand and isolates its failures, so one failing integration doesn't stop the others."""
    try:
        return process_brand(handler, params)
    except Exception as error:
        demisto.debug(f"{handler.brand} failed: {traceback.format_exc()}")
        return [error_record(handler.brand, str(error))]


def run_all_brands(params: SearchParams) -> list[EmailRecord]:
    records: list[EmailRecord] = []
    for brand in params.brands:
        records.extend(run_brand(HANDLERS[brand], params))
    return records


""" OUTPUT """


def build_email_data(record: EmailRecord, params: SearchParams) -> dict[str, Any]:
    additional: dict[str, Any] = {
        "ObjectID": record.object_id,
        "InternetMessageID": record.internet_message_id,
        "HasAttachments": record.has_attachments,
        "Deleted": record.deleted,
    }
    if record.verified is not None:
        additional["Verified"] = record.verified
    if params.verbose:
        additional.update({key: value for key, value in record.details.items() if value not in (None, "", [], {})})
    return {
        "Mailbox": [mailbox for mailbox in record.mailbox.split(",") if mailbox],
        "Subject": record.subject,
        "From": record.sender,
        "To": record.to,
        "CC": record.cc,
        "BCC": record.bcc,
        "HTML": record.html,
        "Timestamp": record.timestamp,
        "Attachments": record.attachments,
        "Success": record.success,
        "Reason": record.reason,
        "Operation": params.operation,
        "Brand": record.brand,
        "AdditionalFields": {key: value for key, value in additional.items() if value is not None},
    }


def compute_totals(records: list[EmailRecord]) -> dict[str, int]:
    return {
        "TotalFound": sum(record.count for record in records if record.found),
        "TotalDeleted": sum(record.count for record in records if record.deleted),
        "TotalFailed": sum(max(record.count, 1) for record in records if not record.success),
    }


def build_readable_output(email_data: list[dict[str, Any]], totals: dict[str, int], params: SearchParams) -> str:
    rows = [
        {
            "Brand": email["Brand"],
            "Mailbox": ", ".join(email["Mailbox"]),
            "Subject": email["Subject"],
            "From": email["From"],
            "To": ", ".join(email["To"]),
            "Timestamp": email["Timestamp"],
            "Operation": email["Operation"],
            "Success": email["Success"],
            "Reason": email["Reason"],
        }
        for email in email_data
    ]
    table = tableToMarkdown(
        f"Search & Delete Email - {params.operation}",
        rows,
        headers=["Brand", "Mailbox", "Subject", "From", "To", "Timestamp", "Operation", "Success", "Reason"],
        removeNull=True,
    )
    summary = (
        f"**Total found:** {totals['TotalFound']} | "
        f"**Total deleted:** {totals['TotalDeleted']} | "
        f"**Total failed:** {totals['TotalFailed']}"
    )
    return f"{table}\n{summary}" if rows else f"No emails were found.\n\n{summary}"


def build_command_results(records: list[EmailRecord], params: SearchParams) -> list[Any]:
    """Builds the context/human readable entry, followed by a file entry per retrieved attachment."""
    email_data = [build_email_data(record, params) for record in records]
    totals = compute_totals(records)
    files = [attachment for record in records for attachment in record.files]
    outputs: dict[str, Any] = {"EmailData": email_data, **totals}
    if files:
        outputs["File(val.SHA256 && val.SHA256 == obj.SHA256)"] = [
            {
                "Name": file.name,
                "SHA256": file.sha256,
                "Size": len(file.data),
                "Extension": os.path.splitext(file.name)[1].lstrip("."),
            }
            for file in files
        ]
    all_failed = bool(records) and not any(record.found for record in records)
    readable_output = build_readable_output(email_data, totals, params)
    if all_failed:
        readable_output = f"The operation failed for all the integrations ({', '.join(params.brands)}).\n\n{readable_output}"
    results: list[Any] = [
        CommandResults(
            readable_output=readable_output,
            outputs=outputs,
            raw_response=outputs,
            entry_type=EntryType.ERROR if all_failed else EntryType.NOTE,
        )
    ]
    results.extend(fileResult(file.name, file.data) for file in files)
    return results


""" MAIN """


def main():  # pragma: no cover
    try:
        params = parse_args(demisto.args(), get_enabled_brands())
    except InputError as error:
        return_error(str(error))
        return
    try:
        if params.verify_deletion and MSGRAPH_SECURITY_BRAND in params.brands:
            return_results(CommandResults(readable_output=VERIFY_UNSUPPORTED_WARNING, entry_type=EntryType.WARNING))
        return_results(build_command_results(run_all_brands(params), params))
    except Exception as error:
        demisto.error(traceback.format_exc())
        failures = [error_record(brand, str(error)) for brand in params.brands]
        return_results(build_command_results(failures, params))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
