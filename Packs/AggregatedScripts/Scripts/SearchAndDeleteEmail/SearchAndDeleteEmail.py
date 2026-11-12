"""
Search & Delete Email - a unified command over several mail integrations.

Searches for emails (and optionally deletes them) using the supported mail integrations and normalizes the results of
all vendors into the unified ``EmailData`` context path. See the README for the arguments and outputs.

Execution
---------
The script runs once, synchronously: it resolves the enabled instances of the requested vendors and, for each instance
in turn, runs the "search -> (retrieve files) -> delete" flow, then returns all the results in a single entry. The
``timeout`` argument is the overall time budget of the run: it is checked before each instance (and before each email),
and whatever was not started in time is reported as failed instead.

Supported vendors and their capabilities
----------------------------------------
+---------------------------+-------------------------+------------------+------------------------------------------+
| Vendor (brand)            | Specific mailbox(es)    | All mailboxes    | Delete types                             |
+---------------------------+-------------------------+------------------+------------------------------------------+
| Gmail                     | Yes (gmail-search)      | Yes (gmail-      | Soft (move to trash), Hard (permanent)   |
|                           |                         | search-all-      |                                          |
|                           |                         | mailboxes)       |                                          |
| Microsoft Graph Mail      | Yes (per mailbox)       | NO               | Soft only (moved to "Deleted Items")     |
| EWS on-prem (EWS v2)      | Yes (email_addresses)   | Yes              | Soft, Hard                               |
+---------------------------+-------------------------+------------------+------------------------------------------+
"""

import re
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from typing import Any
from urllib.parse import quote

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

OPERATION_SEARCH_ONLY = "Search Only"
OPERATION_SEARCH_AND_DELETE = "Search & Delete"
DELETE_SOFT = "soft"
DELETE_HARD = "hard"
SCOPE_SPECIFIC = "Specific"
SCOPE_ALL = "All"
DEFAULT_TIME_FRAME = "1 hour"

SCRIPT_NAME = "SearchAndDeleteEmail"
DEFAULT_TIMEOUT_SECONDS = 1800  # The overall time budget of the run.
# The run executes synchronously under the script's YAML timeout (35 minutes): a larger budget could get the run killed
# by the platform (and its results lost).
MAX_TIMEOUT_SECONDS = 1800
VENDOR_TIMEOUT_REASON = (
    "Timed out: the {timeout} seconds timeout budget was exhausted before this integration ran. "
    "Increase the timeout argument or narrow the search."
)
EMAIL_TIMEOUT_REASON = "Timed out: the timeout budget was exhausted before this email was processed."
EMAIL_TIMEOUT_NOTE = (
    "The timeout budget was exhausted during the run, the remaining emails were not processed. "
    "Increase the timeout argument or narrow the search."
)
MAX_ROUNDS = 10  # Max number of "search -> delete" rounds when the vendor returns capped result pages.
GMAIL_PAGE_SIZE = 500
GRAPH_MAIL_PAGE_SIZE = 50
GRAPH_MAIL_MAX_PAGES = 64
EWS_LIMIT_STEPS = (100, 500, 1000)
EWS_ENRICH_LIMIT = 50  # Max number of emails for which the full item (body, attachments) is fetched.

# Property name used to search by Internet Message ID in the EWS query language.
EWS_MESSAGE_ID_FIELD = "Message-ID"
# An RFC 5322 msg-id never contains whitespace, quotes, backslashes or parentheses. The IDs may come from attacker
# controlled headers, so anything else is rejected: it could break out of the quoted query terms (query injection).
INTERNET_MESSAGE_ID_PATTERN = re.compile(r'^<?[^\s"<>\\()]+>?$')
# A plain sender address never contains these characters (they could break out of the quoted query terms).
INVALID_SENDER_CHARS = re.compile(r'[\s"\\()]')
# Characters that are kept as is when a literal value is URL-encoded into the Graph Mail $filter (see odata_literal).
ODATA_LITERAL_SAFE_CHARS = "@<>.-_"

# The commands executed during the current run (shown when verbose is true). Reset at the start of every run.
COMMAND_TRACE: list[str] = []


class VendorError(DemistoException):
    """A vendor command returned an error entry."""


class NotFoundError(VendorError):
    """The email requested by ``object_id`` does not exist (raised only by the object_id lookups)."""


# A "not found" error of an object_id lookup: Gmail / Graph return HTTP 404, EWS returns "not found/malformed".
NOT_FOUND_ERROR = re.compile(r"\b404\b|not\s*found|ErrorItemNotFound", re.IGNORECASE)
GMAIL_SPLIT_SEARCH_ERROR = (
    "Gmail split the all-mailboxes search into background sub-searches (more than 500 accounts), "
    "so the results are not available to this script. Use specific mailboxes or another brand."
)
# What gmail-search-all-mailboxes returns instead of emails when it splits the search (more than 500 accounts): one
# entry per batch of accounts with this human readable and a scheduled command (``scheduled_commands_for_more_users``).
GMAIL_SPLIT_SEARCH_TEXT = "Searching mailboxes, please wait"


@dataclass
class SearchParams:
    """Parsed and validated command arguments."""

    internet_message_ids: list[str]
    object_id: str
    operation: str
    delete_type: str
    since: datetime
    subjects: list[str]
    sender_address: str
    retrieve_files: bool
    target_mailboxes: list[str]
    mailbox_scope: str
    brands: list[str]
    verbose: bool
    timeout: int
    # Absolute ``time.time()`` value at which the timeout budget of the run ends (computed once, in parse_args).
    deadline: float = float("inf")

    @property
    def deadline_passed(self) -> bool:
        return time.time() > self.deadline

    @property
    def delete(self) -> bool:
        return self.operation == OPERATION_SEARCH_AND_DELETE

    @property
    def hard_delete(self) -> bool:
        return self.delete_type == DELETE_HARD

    @property
    def all_mailboxes(self) -> bool:
        return self.mailbox_scope == SCOPE_ALL


@dataclass
class VendorResult:
    """Combined outcome of one vendor instance."""

    vendor: str
    brand: str
    instance: str
    emails: list[dict[str, Any]] = field(default_factory=list)
    total_found: int = 0
    total_deleted: int = 0
    total_failed: int = 0
    errors: list[str] = field(default_factory=list)
    file_entries: list[dict[str, Any]] = field(default_factory=list)  # Published at the end of the run (publish_files).
    additional: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return not self.errors and self.total_failed == 0


# ---------------------------------------------------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------------------------------------------------
def normalize_name(value: str) -> str:
    """Lower-cases a brand name and strips everything but letters and digits (``EWS v2`` -> ``ewsv2``)."""
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def strip_brackets(message_id: str) -> str:
    return message_id.strip().lstrip("<").rstrip(">")


def with_brackets(message_id: str) -> str:
    return f"<{strip_brackets(message_id)}>"


def escape_single_quotes(value: str) -> str:
    return value.replace("'", "''")


def quote_phrase(value: str) -> str:
    """
    Prepares a value for a double quoted Gmail / EWS (AQS) phrase term: every ``"`` and ``\\`` is replaced with a space.

    Neither Gmail search nor Exchange AQS documents an escape sequence for a quote inside a quoted phrase, so the value
    could otherwise break out of the quotes (query injection, the values may come from attacker controlled headers).
    The terms are phrase searches, so replacing the characters with a space keeps the meaning of the search.
    """
    return re.sub(r'["\\]', " ", value)


def odata_literal(value: str) -> str:
    """
    A literal value for a single quoted OData string in the Graph Mail ``$filter``.

    The single quotes are doubled (the OData escape) and the value is URL-encoded, since the Graph Mail integration
    pastes the ``odata`` argument into the request URL as is (``MicrosoftGraphMailApiModule.list_mails``): otherwise
    ``+`` would be decoded as a space, ``&`` / ``#`` would cut the query and ``%`` would start an escape sequence.
    """
    return quote(escape_single_quotes(value), safe=ODATA_LITERAL_SAFE_CHARS)


def primary_mailbox(email: dict[str, Any]) -> str:
    """The first mailbox of an email record ("" when it has none)."""
    return email["Mailbox"][0] if email["Mailbox"] else ""


def add_note(result: VendorResult, note: str) -> None:
    """Appends ``note`` to the vendor's ``Note`` (instead of overwriting it), skipping a note that is already there."""
    existing = result.additional.get("Note") or ""
    if note not in existing:
        result.additional["Note"] = f"{existing} {note}" if existing else note


def as_list(value: Any) -> list[str]:
    """Converts a vendor value (None / CSV string / list of strings or address dicts) to a list of strings."""
    if not value:
        return []
    if isinstance(value, str):
        return argToList(value)
    if isinstance(value, dict):
        value = [value]
    result: list[str] = []
    for item in value:
        if isinstance(item, dict):
            address = item.get("Address") or item.get("address") or item.get("emailAddress") or item.get("Name")
            if address:
                result.append(str(address))
        elif item:
            result.append(str(item))
    return result


def parse_time_frame(value: str) -> timedelta:
    """Parses values such as ``7 days`` / ``3 hours`` / ``30 minutes`` / ``2 weeks`` / ``1 month`` to a timedelta."""
    match = re.fullmatch(r"\s*(\d+)\s*(minute|hour|day|week|month)s?\s*", value or "", re.IGNORECASE)
    if not match:
        raise DemistoException(f"Invalid time_frame '{value}'. Use a number and a unit, e.g. '7 days' or '3 hours'.")
    amount, unit = int(match.group(1)), match.group(2).lower()
    if amount <= 0:
        raise DemistoException("time_frame must be greater than zero.")
    seconds_per_unit = {"minute": 60, "hour": 3600, "day": 86400, "week": 604800, "month": 2592000}
    return timedelta(seconds=amount * seconds_per_unit[unit])


def run_command(command: str, args: dict[str, Any], instance: str) -> list[dict[str, Any]]:
    """Runs a vendor command on a specific instance and raises ``VendorError`` if it returned an error entry."""
    command_args = {key: value for key, value in args.items() if value not in (None, "")}
    command_args["using"] = instance
    COMMAND_TRACE.append(f"{command} { ({k: v for k, v in command_args.items() if k != 'using'}) } [using={instance}]")
    demisto.debug(f"Running {command} with {command_args=}")
    results = demisto.executeCommand(command, command_args)
    if is_error(results):
        raise VendorError(f"{command} failed: {get_error(results)}")
    return results or []


def object_id_lookup(command: str, args: dict[str, Any], instance: str) -> list[dict[str, Any]]:
    """``run_command`` for a lookup by ``object_id``: a "not found" error is raised as ``NotFoundError``."""
    try:
        return run_command(command, args, instance)
    except VendorError as exc:
        if NOT_FOUND_ERROR.search(str(exc)):
            raise NotFoundError(str(exc)) from exc
        raise


def context_values(results: list[dict[str, Any]], path: str) -> list[Any]:
    """Collects the context values stored under ``path`` (ignoring the ``(val.x == obj.x)`` DT suffix) in all entries."""
    values: list[Any] = []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        for key, value in (entry.get("EntryContext") or {}).items():
            if key.split("(")[0] == path:
                values.extend(value if isinstance(value, list) else [value])
    return [value for value in values if value]


def find_key(obj: Any, name: str) -> Any:
    """Recursively searches ``obj`` for the first non-empty value stored under the key ``name``."""
    if isinstance(obj, dict):
        if obj.get(name) not in (None, ""):
            return obj[name]
        children: list[Any] = list(obj.values())
    elif isinstance(obj, list):
        children = obj
    else:
        return None
    for child in children:
        found = find_key(child, name)
        if found not in (None, ""):
            return found
    return None


def find_in_results(results: list[dict[str, Any]], name: str) -> Any:
    return find_key([entry.get("EntryContext") for entry in results if isinstance(entry, dict)], name)


def make_email(
    *,
    object_id: str,
    mailbox: str | list[str],
    subject: str = "",
    sender: str = "",
    to: Any = None,
    cc: Any = None,
    bcc: Any = None,
    html: str = "",
    timestamp: str = "",
    internet_message_id: str = "",
    attachments: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Builds the vendor independent email record."""
    return {
        "ObjectID": object_id,
        "InternetMessageID": internet_message_id,
        "Mailbox": as_list(mailbox),
        "Subject": subject or "",
        "From": sender or "",
        "To": as_list(to),
        "CC": as_list(cc),
        "BCC": as_list(bcc),
        "HTMLBody": html or "",
        "Timestamp": timestamp or "",
        "Attachments": attachments or {},
    }


def collect_files(results: list[dict[str, Any]], email: dict[str, Any], result: VendorResult) -> None:
    """
    Stores the file entries returned by a vendor "get attachment" command.

    The entries are re-published at the end of the run (so a file is created in the War Room) and the
    ``name -> SHA256`` mapping is added to the email's ``Attachments``.
    """
    for entry in results:
        if isinstance(entry, dict) and entry.get("Type") == entryTypes["file"]:
            result.file_entries.append(entry)
    for file_info in context_values(results, "File"):
        if isinstance(file_info, dict) and file_info.get("Name"):
            email["Attachments"][file_info["Name"]] = file_info.get("SHA256", "")


def email_key(email: dict[str, Any]) -> tuple[str, str]:
    return ",".join(email["Mailbox"]), email["ObjectID"]


def message_key(email: dict[str, Any]) -> tuple[str, str] | None:
    """``(mailbox key, InternetMessageID)``, or None when the vendor did not return an InternetMessageID."""
    message_id = email.get("InternetMessageID")
    return (",".join(email["Mailbox"]), message_id) if message_id else None


@dataclass
class EmailOps:
    """The vendor specific callables of a vendor instance (built from the params by ``VendorSpec.ops``)."""

    search: Callable[[], tuple[list[dict[str, Any]], bool]]
    delete: Callable[[dict[str, Any]], None]
    get_files: Callable[[dict[str, Any]], list[dict[str, Any]]]


def search_and_delete(params: SearchParams, result: VendorResult, ops: EmailOps) -> None:
    """
    Shared "search -> (retrieve files) -> delete" loop used by all the vendors.

    ``ops.search`` returns ``(emails, saturated)``. ``saturated`` is True when the vendor capped the number of returned
    emails, in which case the search is repeated (after the deletion) until nothing new is returned, so that
    no email is missed. Files are retrieved BEFORE the deletion, since afterwards they can not be fetched.

    A soft delete in Graph Mail / EWS moves the item to "Deleted Items" under a NEW ID, so a later round would see the
    moved copy as a new email (and delete it again, in effect a hard delete). Emails whose ``(mailbox,
    InternetMessageID)`` was already processed in a previous round are therefore skipped as well.

    The timeout budget (``params.deadline``) is checked before every round and every email: once it passed, the run
    stops gracefully, the remaining emails are reported as not processed and a note is added.
    """
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    seen_message_ids: set[tuple[str, str] | None] = set()  # never holds None: emails without an InternetMessageID are not added
    exhausted = False
    try:
        for _ in range(MAX_ROUNDS if params.delete else 1):
            if params.deadline_passed:
                add_note(result, EMAIL_TIMEOUT_NOTE)
                break
            emails, saturated = ops.search()
            exhausted = False
            fresh = [email for email in emails if email_key(email) not in seen and message_key(email) not in seen_message_ids]
            if not fresh:
                break
            for email in fresh:
                seen[email_key(email)] = email
            process_round(params, result, fresh, ops)
            # Updated after the round: two copies of the same message in one mailbox found in the SAME round are both kept.
            seen_message_ids.update(key for key in map(message_key, fresh) if key)
            if not saturated:
                break
            exhausted = True
    finally:
        # Partial results must survive a timeout / error in a later round: report what was already found and deleted.
        result.emails = list(seen.values())
        result.total_found = len(seen)
    if exhausted:
        add_note(
            result,
            "The vendor capped the number of returned emails, more matching emails may exist. "
            "Rerun the command to process the remaining emails.",
        )


def process_round(params: SearchParams, result: VendorResult, emails: list[dict[str, Any]], ops: EmailOps) -> None:
    """Processes the emails of one search round, skipping the ones left when the timeout budget is exhausted."""
    for email in emails:
        if params.deadline_passed:
            skip_email(params, result, email)
        else:
            process_email(params, result, email, ops)


def skip_email(params: SearchParams, result: VendorResult, email: dict[str, Any]) -> None:
    """Records an email that was not processed because the timeout budget was exhausted."""
    add_note(result, EMAIL_TIMEOUT_NOTE)
    if not params.delete:
        return
    email["Deleted"] = False
    email["Reason"] = EMAIL_TIMEOUT_REASON
    result.total_failed += 1


def process_email(params: SearchParams, result: VendorResult, email: dict[str, Any], ops: EmailOps) -> None:
    """Retrieves the files of one email (when requested) and deletes it (when the operation is "Search & Delete")."""
    if params.retrieve_files and email.get("HasAttachments", bool(email["Attachments"])):
        try:
            collect_files(ops.get_files(email), email, result)
        except Exception as exc:  # a failing attachment must not block the deletion of the other emails
            result.errors.append(f"Failed retrieving files of {email['ObjectID']}: {exc}")
    if not params.delete:
        return
    try:
        ops.delete(email)
        email["Deleted"] = True
        result.total_deleted += 1
    except Exception as exc:
        email["Deleted"] = False
        email["Reason"] = str(exc)
        result.total_failed += 1


# ---------------------------------------------------------------------------------------------------------------------
# Gmail (specific mailboxes + all mailboxes)
# ---------------------------------------------------------------------------------------------------------------------
def build_gmail_query(params: SearchParams) -> str:
    """Message ID is preferred over subject / sender when it was provided (the message IDs are validated in parse_args)."""
    clauses: list[str] = []
    if params.internet_message_ids:
        ids = " OR ".join(
            f'rfc822msgid:"{quote_phrase(strip_brackets(message_id))}"' for message_id in params.internet_message_ids
        )
        clauses.append(f"({ids})")
    else:
        if params.subjects:
            clauses.append("(" + " OR ".join(f'subject:"{quote_phrase(subject)}"' for subject in params.subjects) + ")")
        if params.sender_address:
            clauses.append(f'from:"{quote_phrase(params.sender_address)}"')
    clauses.append(f"after:{int(params.since.timestamp())}")
    return " ".join(clauses)


def gmail_to_email(item: dict[str, Any]) -> dict[str, Any]:
    date = next((h.get("Value", "") for h in item.get("Headers") or [] if str(h.get("Name")).lower() == "date"), "")
    attachments = {a["Name"]: "" for a in item.get("Attachments") or [] if isinstance(a, dict) and a.get("Name")}
    email = make_email(
        object_id=item.get("ID", ""),
        mailbox=item.get("Mailbox", ""),
        subject=item.get("Subject", ""),
        sender=item.get("From", ""),
        to=item.get("To"),
        cc=item.get("Cc"),
        bcc=item.get("Bcc"),
        html=item.get("Body", ""),
        timestamp=date,
        attachments=attachments,
    )
    email["HasAttachments"] = bool(attachments)
    return email


def gmail_split_search(results: list[dict[str, Any]]) -> bool:
    """
    Whether gmail-search-all-mailboxes split the search into background scheduled sub-searches (more than 500 accounts,
    ``MAX_WITHOUT_POLLING`` in Gmail.py): it then returns "Searching mailboxes, please wait..." entries without emails.
    """
    for entry in results:
        if not isinstance(entry, dict):
            continue
        texts = (entry.get("HumanReadable"), entry.get("Contents"))
        if any(isinstance(text, str) and GMAIL_SPLIT_SEARCH_TEXT in text for text in texts):
            return True
    return False


def gmail_search(params: SearchParams, instance: str) -> tuple[list[dict[str, Any]], bool]:
    """Searches Gmail and follows every page token so that all matching emails are returned."""
    query = build_gmail_query(params)
    emails: list[dict[str, Any]] = []
    if params.object_id:
        results = object_id_lookup(
            "gmail-get-mail", {"user-id": params.target_mailboxes[0], "message-id": params.object_id}, instance
        )
        return [gmail_to_email(item) for item in context_values(results, "Gmail")], False

    command, mailboxes = (
        ("gmail-search-all-mailboxes", [""]) if params.all_mailboxes else ("gmail-search", params.target_mailboxes)
    )
    for mailbox in mailboxes:
        page_token = ""
        while True:  # Pagination: loop until Gmail does not return another page token.
            args: dict[str, Any] = {"query": query, "max-results": GMAIL_PAGE_SIZE, "page-token": page_token}
            if params.all_mailboxes:
                args["show-only-mailboxes"] = "false"
            else:
                args["user-id"] = mailbox
            results = run_command(command, args, instance)
            if params.all_mailboxes and gmail_split_search(results):
                raise VendorError(GMAIL_SPLIT_SEARCH_ERROR)
            emails.extend(gmail_to_email(item) for item in context_values(results, "Gmail"))
            # NOTE: for "all mailboxes" the page token below belongs to the *accounts* list (more than 2500
            # accounts), which is why it is followed here as well.
            page_token = find_in_results(results, "NextPageToken") or ""
            if not page_token:
                break
    return emails, False


def gmail_ops(params: SearchParams, instance: str, result: VendorResult) -> EmailOps:
    def delete(email: dict[str, Any]) -> None:
        run_command(
            "gmail-delete-mail",
            {"user-id": email["Mailbox"][0], "message-id": email["ObjectID"], "permanent": str(params.hard_delete).lower()},
            instance,
        )

    def get_files(email: dict[str, Any]) -> list[dict[str, Any]]:
        return run_command("gmail-get-attachments", {"user-id": email["Mailbox"][0], "message-id": email["ObjectID"]}, instance)

    return EmailOps(lambda: gmail_search(params, instance), delete, get_files)


# ---------------------------------------------------------------------------------------------------------------------
# Microsoft Graph Mail (specific mailboxes only)
# ---------------------------------------------------------------------------------------------------------------------
def build_graph_mail_filter(params: SearchParams) -> str:
    """
    The ``$filter`` query of msgraph-mail-list-emails. Only the literal values are URL-encoded (``odata_literal``): the
    spaces of the expression itself are encoded by ``requests`` when the URL is sent.
    """
    clauses = [f"receivedDateTime ge {params.since.strftime('%Y-%m-%dT%H:%M:%SZ')}"]
    if params.internet_message_ids:
        ids = " or ".join(f"internetMessageId eq '{odata_literal(with_brackets(i))}'" for i in params.internet_message_ids)
        clauses.append(f"({ids})")
    else:
        if params.subjects:
            subjects = " or ".join(f"contains(subject,'{odata_literal(s)}')" for s in params.subjects)
            clauses.append(f"({subjects})")
        if params.sender_address:
            clauses.append(f"from/emailAddress/address eq '{odata_literal(params.sender_address)}'")
    return "$filter=" + " and ".join(clauses)


def graph_mail_to_email(item: dict[str, Any]) -> dict[str, Any]:
    email = make_email(
        object_id=item.get("ID", ""),
        mailbox=item.get("UserID", ""),
        subject=item.get("Subject", ""),
        sender=(item.get("From") or item.get("Sender") or {}).get("Address", ""),
        to=item.get("Recipients"),
        cc=item.get("CCRecipients"),
        bcc=item.get("BCCRecipients"),
        html=item.get("Body", ""),
        timestamp=item.get("ReceivedTime", ""),
        internet_message_id=item.get("InternetMessageID", ""),
    )
    email["HasAttachments"] = bool(item.get("HasAttachments"))
    return email


def graph_mail_search(params: SearchParams, instance: str) -> tuple[list[dict[str, Any]], bool]:
    emails: list[dict[str, Any]] = []
    saturated = False
    for mailbox in params.target_mailboxes:
        if params.object_id:
            results = object_id_lookup(
                "msgraph-mail-get-email", {"user_id": mailbox, "message_id": params.object_id, "get_body": "true"}, instance
            )
            emails.extend(graph_mail_to_email(item) for item in context_values(results, "MSGraphMail"))
            continue
        pages = 1
        while True:
            # Pagination: the command has no page cursor, so the number of pulled pages is doubled
            # until the amount of returned emails is lower than the requested amount.
            results = run_command(
                "msgraph-mail-list-emails",
                {
                    "user_id": mailbox,
                    "odata": build_graph_mail_filter(params),
                    "page_size": GRAPH_MAIL_PAGE_SIZE,
                    "pages_to_pull": pages,
                },
                instance,
            )
            items = [i for i in context_values(results, "MSGraphMail") if isinstance(i, dict) and i.get("ID")]
            if len(items) < GRAPH_MAIL_PAGE_SIZE * pages:
                break
            if pages >= GRAPH_MAIL_MAX_PAGES:
                saturated = True  # Deleting what was found and searching again will reveal the remaining emails.
                break
            pages *= 2
        emails.extend(graph_mail_to_email(item) for item in items)
    return emails, saturated


def graph_mail_ops(params: SearchParams, instance: str, result: VendorResult) -> EmailOps:
    if params.all_mailboxes:
        raise DemistoException(
            "Microsoft Graph Mail can not search all mailboxes, use Gmail or EWS on-prem or specify the mailboxes."
        )
    if params.delete and params.hard_delete:
        add_note(result, "Microsoft Graph Mail can not hard delete, emails were moved to 'Deleted Items'.")

    def delete(email: dict[str, Any]) -> None:
        run_command("msgraph-mail-delete-email", {"user_id": email["Mailbox"][0], "message_id": email["ObjectID"]}, instance)

    def get_files(email: dict[str, Any]) -> list[dict[str, Any]]:
        return run_command(
            "msgraph-mail-get-attachment", {"user_id": email["Mailbox"][0], "message_id": email["ObjectID"]}, instance
        )

    return EmailOps(lambda: graph_mail_search(params, instance), delete, get_files)


# ---------------------------------------------------------------------------------------------------------------------
# EWS on-prem
# ---------------------------------------------------------------------------------------------------------------------
def build_ews_query(params: SearchParams) -> str:
    """The AQS query of ews-search-mailboxes (the message IDs are validated in parse_args)."""
    clauses: list[str] = []
    if params.internet_message_ids:
        ids = " OR ".join(f'{EWS_MESSAGE_ID_FIELD}:"{quote_phrase(with_brackets(i))}"' for i in params.internet_message_ids)
        clauses.append(f"({ids})")  # Always wrapped, so the clause can never widen the rest of the query.
    else:
        if params.subjects:
            subjects_query = " OR ".join(f'Subject:"{quote_phrase(subject)}"' for subject in params.subjects)
            clauses.append(f"({subjects_query})" if len(params.subjects) > 1 else subjects_query)
        if params.sender_address:
            clauses.append(f'From:"{quote_phrase(params.sender_address)}"')

    clauses.append(f"Received:>={params.since.strftime('%Y-%m-%d')}")
    return " AND ".join(clauses)


def ews_to_email(item: dict[str, Any], mailbox: str = "") -> dict[str, Any]:
    attachments = {a["attachmentName"]: a.get("attachmentSHA256", "") for a in item.get("FileAttachments") or []}
    email = make_email(
        object_id=item.get("itemId", ""),
        mailbox=item.get("mailbox") or mailbox,
        subject=item.get("subject", ""),
        sender=item.get("sender", ""),
        to=item.get("toRecipients"),
        html=item.get("body", ""),
        timestamp=item.get("datetimeReceived", ""),
        internet_message_id=item.get("messageId", ""),
        attachments=attachments,
    )
    email["HasAttachments"] = bool(item.get("hasAttachments"))
    return email


def ews_search(params: SearchParams, instance: str) -> tuple[list[dict[str, Any]], bool]:
    if params.object_id:
        results = object_id_lookup(
            "ews-get-items", {"item-ids": params.object_id, "target-mailbox": params.target_mailboxes[0]}, instance
        )
        return [ews_to_email(item, params.target_mailboxes[0]) for item in context_values(results, "EWS.Items")], False

    emails: list[dict[str, Any]] = []
    for limit in EWS_LIMIT_STEPS:
        # Pagination: the command only supports a limit, so it is raised until fewer results than the limit are returned.
        results = run_command(
            "ews-search-mailboxes",
            {
                "filter": build_ews_query(params),
                "limit": limit,
                "email_addresses": "" if params.all_mailboxes else ",".join(params.target_mailboxes),
            },
            instance,
        )
        emails = [ews_to_email(item) for item in context_values(results, "EWS.Items") if isinstance(item, dict)]
        if len(emails) < limit:
            return emails, False
    return emails, True  # Still capped: the caller deletes what was found and searches again.


def ews_ops(params: SearchParams, instance: str, result: VendorResult) -> EmailOps:
    def search() -> tuple[list[dict[str, Any]], bool]:
        emails, saturated = ews_search(params, instance)
        for email in emails[:EWS_ENRICH_LIMIT]:  # The search results do not contain the body and attachments.
            if email["Mailbox"] and not email["HTMLBody"]:
                try:
                    items = context_values(
                        run_command(
                            "ews-get-items", {"item-ids": email["ObjectID"], "target-mailbox": email["Mailbox"][0]}, instance
                        ),
                        "EWS.Items",
                    )
                    if items:
                        email.update({k: v for k, v in ews_to_email(items[0], email["Mailbox"][0]).items() if v})
                except Exception as exc:
                    demisto.debug(f"Failed enriching EWS item {email['ObjectID']}: {exc}")
        return emails, saturated

    def delete(email: dict[str, Any]) -> None:
        run_command(
            "ews-delete-items",
            {
                "item-ids": email["ObjectID"],
                "delete-type": "hard" if params.hard_delete else "soft",
                "target-mailbox": primary_mailbox(email),
            },
            instance,
        )

    def get_files(email: dict[str, Any]) -> list[dict[str, Any]]:
        return run_command("ews-get-attachment", {"item-id": email["ObjectID"], "target-mailbox": primary_mailbox(email)}, instance)

    return EmailOps(search, delete, get_files)


# ---------------------------------------------------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class VendorSpec:
    display_name: str
    aliases: frozenset[str]  # normalized brand names (see normalize_name)
    ops: Callable[[SearchParams, str, VendorResult], EmailOps]  # builds the vendor callables for (params, instance, result)


# `aliases` must contain the normalized integration `name` (the brand reported by demisto.getModules), the normalized
# integration `display` (what users see) and any other common spelling:
#   Gmail:                    name `Gmail`,                display `Gmail`
#   Microsoft Graph Mail:     name `MicrosoftGraphMail`,   display `O365 Outlook Mail (Using Graph API)`
#   EWS on-prem:              name `EWS v2`,               display `EWS v2`
VENDORS: dict[str, VendorSpec] = {
    "gmail": VendorSpec("Gmail", frozenset({"gmail"}), gmail_ops),
    "msgraph_mail": VendorSpec(
        "Microsoft Graph Mail",
        frozenset({"microsoftgraphmail", "msgraphmail", "o365outlookmailusinggraphapi"}),
        graph_mail_ops,
    ),
    "ews": VendorSpec("EWS on-prem", frozenset({"ewsv2", "ews", "ewsonprem"}), ews_ops),
}


def vendor_keys_for_brand(brand: str) -> set[str]:
    """Returns the keys of the vendors that have `brand` (a name, display name or alias) among their aliases."""
    normalized = normalize_name(brand)
    return {key for key, spec in VENDORS.items() if normalized in spec.aliases}


def resolve_instances(requested_brands: list[str]) -> list[tuple[str, str, str]]:
    """Returns ``(vendor key, brand, instance name)`` for every active instance of the requested (or all) vendors.

    Routing is vendor based: every requested brand is mapped to the vendor(s) that list it as an alias, and an instance is kept
    when the vendor of its (real) brand was requested, regardless of which alias the user used.
    """
    if unknown := sorted(brand for brand in requested_brands if not vendor_keys_for_brand(brand)):
        supported = ", ".join(spec.display_name for spec in VENDORS.values())
        raise DemistoException(f"Unsupported brand(s): {', '.join(unknown)}. Supported brands: {supported}.")
    wanted_vendors = {key for brand in requested_brands for key in vendor_keys_for_brand(brand)}

    instances: list[tuple[str, str, str]] = []
    for instance_name, data in (demisto.getModules() or {}).items():
        if data.get("state") != "active":
            continue
        instance_brand = data.get("brand", "")
        for key in vendor_keys_for_brand(instance_brand):
            if not wanted_vendors or key in wanted_vendors:
                instances.append((key, instance_brand, instance_name))
    return instances


def resolve_target_instances(params: SearchParams) -> list[tuple[str, str, str]]:
    """``resolve_instances`` plus the checks that at least one instance was found (exactly one vendor for object_id)."""
    instances = resolve_instances(params.brands)
    if params.object_id and len({key for key, _, _ in instances}) != 1:
        raise DemistoException("When object_id is specified, exactly one brand (with an enabled instance) must be selected.")
    if not instances:
        raise DemistoException("No enabled instance was found for the requested brands.")
    return instances


# ---------------------------------------------------------------------------------------------------------------------
# Running the vendors
# ---------------------------------------------------------------------------------------------------------------------
def run_vendor(params: SearchParams, key: str, brand: str, instance: str) -> VendorResult:
    """
    Runs the whole "search -> (files) -> delete" flow of one vendor instance.

    Never raises: a failure is stored in the result's errors, together with whatever was collected before it. An
    instance that is reached after the timeout budget was exhausted is not run and is reported as failed.
    """
    spec = VENDORS[key]
    result = VendorResult(vendor=spec.display_name, brand=brand, instance=instance)
    if params.deadline_passed:
        result.errors.append(VENDOR_TIMEOUT_REASON.format(timeout=params.timeout))
        return result
    try:
        search_and_delete(params, result, spec.ops(params, instance, result))
    except Exception as exc:
        if isinstance(exc, NotFoundError):
            result.additional["NotFound"] = True  # The email requested by object_id does not exist (not a hard failure).
        demisto.debug(f"{result.vendor} ({instance}) failed: {exc}\n{traceback.format_exc()}")
        result.errors.append(str(exc))
    return result


def publish_files(result: VendorResult) -> None:
    """Publishes the retrieved files as War Room file entries and clears them from the result."""
    for file_entry in result.file_entries:
        return_results(file_entry)
    result.file_entries = []


# ---------------------------------------------------------------------------------------------------------------------
# Arguments and outputs
# ---------------------------------------------------------------------------------------------------------------------
def parse_timeout(value: Any) -> int:
    """
    Parses the ``timeout`` argument (seconds): empty -> default, otherwise a positive integer up to
    ``MAX_TIMEOUT_SECONDS``.
    """
    try:
        timeout = arg_to_number(value)
    except ValueError:
        timeout = 0
    if timeout is None:
        return DEFAULT_TIMEOUT_SECONDS
    if timeout <= 0:
        raise DemistoException("timeout must be a positive number of seconds.")
    if timeout > MAX_TIMEOUT_SECONDS:
        raise DemistoException(
            f"timeout must be at most {MAX_TIMEOUT_SECONDS} seconds: the whole search and delete runs synchronously "
            "and must finish within the script timeout."
        )
    return timeout


def validate_search_values(message_ids: list[str], sender: str) -> None:
    """Rejects message IDs and a sender address that could break out of the quoted query terms (query injection)."""
    if invalid := [message_id for message_id in message_ids if not INTERNET_MESSAGE_ID_PATTERN.fullmatch(message_id)]:
        raise DemistoException(
            f"Invalid internet_message_id: {', '.join(invalid)}. A message ID must not contain whitespace, quotes, "
            "backslashes, parentheses or inner angle brackets."
        )
    if sender and INVALID_SENDER_CHARS.search(sender):
        raise DemistoException(
            f"Invalid sender_address: {sender}. The address must not contain whitespace, quotes, backslashes or parentheses."
        )


def parse_args(args: dict[str, Any]) -> SearchParams:
    """Parses and validates the arguments. The timeout budget of the run starts here (``SearchParams.deadline``)."""
    operation = args.get("operation") or ""
    if operation not in (OPERATION_SEARCH_ONLY, OPERATION_SEARCH_AND_DELETE):
        raise DemistoException(f"operation must be '{OPERATION_SEARCH_ONLY}' or '{OPERATION_SEARCH_AND_DELETE}'.")
    delete_type = str(args.get("delete_type") or DELETE_SOFT).strip().lower()
    if delete_type not in (DELETE_SOFT, DELETE_HARD):
        raise DemistoException(f"delete_type must be '{DELETE_SOFT}' or '{DELETE_HARD}'.")
    scope = args.get("mailbox_scope") or SCOPE_SPECIFIC
    if scope not in (SCOPE_SPECIFIC, SCOPE_ALL):
        raise DemistoException(f"mailbox_scope must be '{SCOPE_SPECIFIC}' or '{SCOPE_ALL}'.")

    object_id = (args.get("object_id") or "").strip()
    message_ids = argToList(args.get("internet_message_id"))
    subjects = argToList(args.get("subject"))
    sender = (args.get("sender_address") or "").strip()
    target_mailboxes = argToList(args.get("target_mailbox"))
    brands = argToList(args.get("brands"))

    # Safety: an empty filter would match (and delete) every email in the time frame.
    if not (object_id or message_ids or subjects or sender):
        raise DemistoException("At least one of internet_message_id, object_id, subject or sender_address must be specified.")

    validate_search_values(message_ids, sender)

    if object_id:
        if not target_mailboxes or not brands:
            raise DemistoException("When 'object_id' is specified, both 'target_mailbox' and 'brands' must be specified.")
        if len(target_mailboxes) > 1 or len(brands) > 1 or scope == SCOPE_ALL:
            raise DemistoException(
                "When 'object_id' is specified, exactly one 'target_mailbox' and one brand must be given "
                f"(mailbox_scope must be '{SCOPE_SPECIFIC}')."
            )
    elif scope == SCOPE_SPECIFIC and not target_mailboxes:
        raise DemistoException("target_mailbox must be specified when mailbox_scope is 'Specific'.")

    timeout = parse_timeout(args.get("timeout"))
    since = datetime.now(UTC) - parse_time_frame(args.get("time_frame") or DEFAULT_TIME_FRAME)
    return SearchParams(
        internet_message_ids=message_ids,
        object_id=object_id,
        operation=operation,
        delete_type=delete_type,
        since=since,
        subjects=subjects,
        sender_address=sender,
        retrieve_files=argToBoolean(args.get("retrieve_files") or False),
        target_mailboxes=target_mailboxes,
        mailbox_scope=scope,
        brands=brands,
        verbose=argToBoolean(args.get("verbose") or False),
        timeout=timeout,
        deadline=time.time() + timeout,
    )


def compute_totals(results: list[VendorResult]) -> dict[str, int]:
    return {
        "TotalFound": sum(result.total_found for result in results),
        "TotalDeleted": sum(result.total_deleted for result in results),
        "TotalFailed": sum(result.total_failed for result in results),
    }


def build_email_data_entries(params: SearchParams, results: list[VendorResult]) -> list[dict[str, Any]]:
    email_data: list[dict[str, Any]] = []

    for result in results:
        for email in result.emails:
            additional_fields = {"ObjectID": email["ObjectID"], "InternetMessageID": email["InternetMessageID"]}
            if params.verbose:
                additional_fields["Instance"] = result.instance

            email_data.append(
                {
                    "Brand": result.brand or result.vendor,
                    "Mailbox": email["Mailbox"],
                    "Subject": email["Subject"],
                    "From": email["From"],
                    "To": email["To"],
                    "CC": email["CC"],
                    "BCC": email["BCC"],
                    "HTML": email["HTMLBody"],
                    "Timestamp": email["Timestamp"],
                    "Attachments": email["Attachments"],
                    "Success": email.get("Deleted", True),
                    "Reason": email.get("Reason", ""),
                    "Operation": params.operation,
                    "AdditionalFields": additional_fields,
                }
            )

        # Handle a vendor that found nothing or failed (also after partial results, so the errors are not lost)
        if not result.emails or result.errors:
            email_data.append(
                {
                    "Brand": result.brand or result.vendor,
                    "Mailbox": ["All"] if params.all_mailboxes else params.target_mailboxes,
                    "Success": result.success,
                    "Reason": "; ".join(result.errors),
                    "Operation": params.operation,
                    "AdditionalFields": {"Instance": result.instance, **result.additional},
                }
            )

    return email_data


READABLE_HEADERS = ["Brand", "Mailbox", "ID", "Subject", "From", "To", "Timestamp", "Operation", "Success", "Reason"]


def markdown_table(title: str, rows: list[dict[str, Any]], headers: list[str]) -> str:
    """``tableToMarkdown`` that keeps the header row when there are no rows (instead of "No entries.")."""
    if rows:
        return tableToMarkdown(title, rows, headers=headers)
    return f"### {title}\n|{'|'.join(headers)}|\n|{'|'.join(['---'] * len(headers))}|\n"


def build_readable_output(email_data: list[dict[str, Any]], totals: dict[str, int], params: SearchParams) -> str:
    rows = []
    for email in email_data:
        # Skip the per-vendor status records (vendors that found nothing or failed): only email records have an ObjectID.
        if "ObjectID" not in (email.get("AdditionalFields") or {}):
            continue

        rows.append(
            {
                "Brand": email.get("Brand"),
                "Mailbox": ", ".join(email.get("Mailbox", [])),
                "ID": email.get("AdditionalFields", {}).get("ObjectID", ""),
                "Subject": email.get("Subject"),
                "From": email.get("From"),
                "To": ", ".join(email.get("To", [])),
                "Timestamp": email.get("Timestamp"),
                "Operation": email.get("Operation"),
                "Success": email.get("Success"),
                "Reason": email.get("Reason"),
            }
        )

    summary = (
        f"**Total found:** {totals['TotalFound']} | "
        f"**Total deleted:** {totals['TotalDeleted']} | "
        f"**Total failed:** {totals['TotalFailed']}"
    )
    if totals["TotalFound"] == 0:
        return f"No emails were found.\n\n{summary}"
    table = markdown_table(f"Search & Delete Email - {params.operation}", rows, READABLE_HEADERS)
    return f"{table}\n{summary}"


def is_hard_failure(result: VendorResult) -> bool:
    """
    Whether a vendor failed without finding anything. An email that was requested by ``object_id`` and does not exist
    (``additional["NotFound"]``, set only by the object_id lookups) is a successful search with no results.
    """
    return not (result.success or result.total_found > 0 or result.additional.get("NotFound"))


def vendor_notes(results: list[VendorResult]) -> str:
    """The vendor notes (e.g. capped results, no hard delete) as markdown lines, so they are shown also when emails were found."""
    return "\n".join(f"* **{r.brand or r.vendor}**: {r.additional['Note']}" for r in results if r.additional.get("Note"))


def build_command_results(params: SearchParams, results: list[VendorResult]) -> list[CommandResults]:
    email_data = build_email_data_entries(params, results)
    totals = compute_totals(results)

    outputs = {"EmailData": email_data, **totals}
    readable_output = build_readable_output(email_data, totals, params)
    if notes := vendor_notes(results):
        readable_output += f"\n\n**Notes:**\n{notes}"

    if params.verbose and COMMAND_TRACE:
        readable_output += "\n#### Executed commands\n" + "\n".join(f"* `{line}`" for line in COMMAND_TRACE)

    # all_failed is True only if *all* integrations had a hard failure
    all_failed = bool(results) and all(is_hard_failure(r) for r in results)

    if all_failed:
        error_reasons = [f"**{r.brand or r.vendor}**: {'; '.join(r.errors)}" for r in results if r.errors]
        brands = ", ".join(dict.fromkeys(r.brand or r.vendor for r in results))
        error_text = "\n".join(error_reasons)
        readable_output = (
            f"The operation failed for all the integrations ({brands}).\n\n**Reason:**\n{error_text}\n\n---\n{readable_output}"
        )

    entry_type = EntryType.ERROR if all_failed else EntryType.NOTE
    return [CommandResults(readable_output=readable_output, outputs=outputs, raw_response=outputs, entry_type=entry_type)]


# ---------------------------------------------------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------------------------------------------------
class InvalidArgumentsError(DemistoException):
    """The script arguments are invalid (reported with ``return_error``)."""


def failure_results(params: SearchParams, exc: Exception) -> list[CommandResults]:
    demisto.debug(f"Unexpected failure: {exc}\n{traceback.format_exc()}")
    failure = VendorResult(vendor="None", brand="", instance="", errors=[str(exc)])
    return build_command_results(params, [failure])


def search_and_delete_email(args: dict[str, Any]) -> list[CommandResults]:
    """
    Runs the whole search (and delete) synchronously over every resolved vendor instance and returns the final results.

    Invalid arguments raise ``InvalidArgumentsError``; any other failure (e.g. no enabled instance) is returned as an
    error entry by ``failure_results``.
    """
    COMMAND_TRACE.clear()
    try:
        params = parse_args(args)
    except Exception as exc:
        raise InvalidArgumentsError(str(exc)) from exc
    try:
        instances = resolve_target_instances(params)
        results = [run_vendor(params, key, brand, instance) for key, brand, instance in instances]
        for result in results:
            publish_files(result)
        return build_command_results(params, results)
    except Exception as exc:  # Never crash: report the failure in HR and in the context.
        return failure_results(params, exc)


def main() -> None:  # pragma: no cover
    args = demisto.args()
    try:
        return_results(search_and_delete_email(args))
    except InvalidArgumentsError as exc:
        return_error(f"Invalid arguments: {exc}")
    except Exception as exc:
        demisto.debug(traceback.format_exc())
        return_error(f"Failed to run {SCRIPT_NAME}: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
