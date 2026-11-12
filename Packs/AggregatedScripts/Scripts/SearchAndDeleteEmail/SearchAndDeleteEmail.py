"""
Search & Delete Email - a unified command over several mail integrations.

Searches for emails (and optionally deletes them) using the supported mail integrations and normalizes the results of
all vendors into the unified ``EmailData`` context path. See the README for the arguments and outputs.

Polling (the script never sleeps)
---------------------------------
Every run is ONE "tick" of a JSON state machine (carried in the hidden ``state`` argument): it advances every vendor that
is not done by one step and either returns the final results, or returns a ``ScheduledCommand`` that reruns the script in
``POLL_INTERVAL_SECONDS``. The state holds the absolute deadline of the overall ``timeout`` budget, the search window and,
per vendor, the stage and the ``VendorResult``. Vendor stages: ``start`` (search -> files -> delete, synchronously within
one tick) -> ``verify`` (only with ``verify_deletion``: one search per tick, for up to ``VERIFICATION_TIMEOUT_SECONDS``)
-> ``done``.

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

import json
import re
import time
import traceback
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, UTC
from typing import Any

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
DEFAULT_TIMEOUT_SECONDS = 1800  # The overall time budget of the whole run, measured across all ticks.
# The polling interval: the platform minimum is 10 seconds, 20 keeps the load on the vendor APIs low while the deletion
# verification is polled.
POLL_INTERVAL_SECONDS = 20
# Added to the scheduled command timeout, so the platform timeout of a scheduled run never coincides with the next run.
SCHEDULE_MARGIN_SECONDS = 2 * POLL_INTERVAL_SECONDS
POLL_MESSAGE = "Search & Delete Email is in progress, the next step runs automatically."
VERIFICATION_TIMEOUT_SECONDS = 120  # How long to wait for the deleted emails to disappear from the search results.
MAX_STATE_BYTES = 500_000  # The polling state above this size gets its largest HTML bodies truncated.
HTML_BODY_PREFIX_CHARS = 1000
MAX_TRACE_LINES = 200
STATE_VERSION = 1
STATE_ARG = "state"
HIDE_POLLING_OUTPUT_ARG = "hide_polling_output"

STAGE_START = "start"
STAGE_VERIFY = "verify"
STAGE_DONE = "done"
VALID_STAGES = frozenset({STAGE_START, STAGE_VERIFY, STAGE_DONE})
# The one-line progress that is announced in the War Room when a vendor ENTERS a stage (never on idle polls).
STAGE_LABELS = {
    STAGE_VERIFY: "verifying the deletion",
    STAGE_DONE: "done",
}
MAX_ROUNDS = 10  # Max number of "search -> delete" rounds when the vendor returns capped result pages.
GMAIL_PAGE_SIZE = 500
GRAPH_MAIL_PAGE_SIZE = 50
GRAPH_MAIL_MAX_PAGES = 64
EWS_LIMIT_STEPS = (100, 500, 1000)
EWS_ENRICH_LIMIT = 50  # Max number of emails for which the full item (body, attachments) is fetched.

# Property name used to search by Internet Message ID in the EWS query language.
EWS_MESSAGE_ID_FIELD = "Message-ID"

COMMAND_TRACE: list[str] = []

# The overall time budget of the run: ``_DEADLINE`` is an absolute ``time.time()`` (epoch) value taken from the state
# of the current tick (``None`` = no limit).
_DEADLINE: float | None = None
_TIMEOUT_SECONDS: int = DEFAULT_TIMEOUT_SECONDS


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
GMAIL_TRASH_LABEL = "TRASH"


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
    verify_deletion: bool
    target_mailboxes: list[str]
    mailbox_scope: str
    brands: list[str]
    verbose: bool
    timeout: int

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
    """Combined outcome of one vendor instance (JSON-safe: it is serialized with ``asdict`` into the polling state)."""

    vendor: str
    brand: str
    instance: str
    emails: list[dict[str, Any]] = field(default_factory=list)
    total_found: int = 0
    total_deleted: int = 0
    total_failed: int = 0
    errors: list[str] = field(default_factory=list)
    file_entries: list[dict[str, Any]] = field(default_factory=list)  # Published in the tick that retrieved them, never stored.
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


def escape_quoted(value: str) -> str:
    """Escapes a value for a double quoted Gmail / EWS (AQS) query term, so it can not break out of the quotes."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


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


def budget_exhausted() -> bool:
    """Whether the overall time budget was exhausted (never, when there is no deadline)."""
    return _DEADLINE is not None and _DEADLINE - time.time() <= 0


def ensure_time_left() -> None:
    """Raises a ``DemistoException`` when the overall time budget was exhausted."""
    if budget_exhausted():
        raise DemistoException(
            f"Timed out: the {_TIMEOUT_SECONDS} seconds timeout was reached. Increase the timeout argument or narrow the search."
        )


def run_command(command: str, args: dict[str, Any], instance: str) -> list[dict[str, Any]]:
    """
    Runs a vendor command on a specific instance and raises ``VendorError`` if it returned an error entry.

    Raises a ``DemistoException`` when the overall time budget is exhausted.
    """
    ensure_time_left()
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


VERIFICATION_FAILED_REASON = "Deletion could not be verified: the email was still found after the delete command succeeded."


def email_key(email: dict[str, Any]) -> tuple[str, str]:
    return ",".join(email["Mailbox"]), email["ObjectID"]


def message_key(email: dict[str, Any]) -> tuple[str, str] | None:
    """``(mailbox key, InternetMessageID)``, or None when the vendor did not return an InternetMessageID."""
    message_id = email.get("InternetMessageID")
    return (",".join(email["Mailbox"]), message_id) if message_id else None


@dataclass
class EmailOps:
    """The vendor specific callables of a vendor (rebuilt from the params on every tick, never stored in the state)."""

    search: Callable[[], tuple[list[dict[str, Any]], bool]]
    delete: Callable[[dict[str, Any]], None]
    get_files: Callable[[dict[str, Any]], list[dict[str, Any]]]


def mark_verification(result: VendorResult, deleted: list[dict[str, Any]], remaining: set[tuple[str, str]]) -> None:
    """
    * Emails that are still found: ``Deleted=False`` + ``Reason``, moved from ``total_deleted`` to ``total_failed``.
    * The other emails get ``DeletionVerified=True``.
    """
    for email in deleted:
        verified = email_key(email) not in remaining
        email["DeletionVerified"] = verified
        if not verified:
            email["Deleted"] = False
            email["Reason"] = VERIFICATION_FAILED_REASON
            result.total_deleted -= 1
            result.total_failed += 1


def verify_step(verify_started: float, result: VendorResult, search: Callable[[], tuple[list[dict[str, Any]], bool]]) -> str:
    """
    Stage ``verify``: ONE verification search per tick, checking that the successfully deleted emails are really gone.

    The match is done on ``(mailbox, ObjectID)`` of the deleted emails: Gmail's search excludes the trash by default,
    while Graph Mail and EWS assign a new item ID to an item that was moved to "Deleted Items", so a moved copy is not
    returned as a match of the old ID. The vendor keeps being polled (indexes can lag) until none of the deleted IDs is
    returned or ``VERIFICATION_TIMEOUT_SECONDS`` passed: what is still found is then reported as unverified. The overall
    deadline caps the window as well: once it passed, the search command is refused and the emails stay unverified.

    When searching by ``object_id`` the lookup is not a search: Gmail's ``gmail-get-mail`` still returns a trashed
    message (it has the ``TRASH`` label, which counts as deleted here), and Graph Mail / EWS return a "not found" error
    for a deleted ID, which counts as an empty result (``NotFoundError``, raised only by the object_id lookups).

    A failure of the verification search itself does NOT mean the deletion failed: the emails keep ``Deleted=True``,
    ``DeletionVerified`` is left unset and the error is added to ``result.errors``.

    ``verify_started`` is the epoch time at which the vendor entered the ``verify`` stage.
    """
    deleted = [email for email in result.emails if email.get("Deleted") is True]
    pending = {email_key(email) for email in deleted}
    deadline = verify_started + VERIFICATION_TIMEOUT_SECONDS
    try:
        emails, _ = search()
    except NotFoundError:
        emails = []  # The email requested by object_id no longer exists: it was deleted.
    except Exception as exc:
        if budget_exhausted():  # The overall budget ended: same as the end of the window, the emails stay unverified.
            mark_verification(result, deleted, pending)
        else:
            result.errors.append(f"Failed verifying the deletion: {exc}")
        return STAGE_DONE
    remaining = {email_key(email) for email in emails if not email.get("Trashed")} & pending
    if remaining and time.time() < deadline:
        return STAGE_VERIFY
    mark_verification(result, deleted, remaining)
    return STAGE_DONE


def search_and_delete(params: SearchParams, result: VendorResult, ops: EmailOps) -> None:
    """
    Shared "search -> (retrieve files) -> delete" loop used by all the vendors.

    ``ops.search`` returns ``(emails, saturated)``. ``saturated`` is True when the vendor capped the number of returned
    emails, in which case the search is repeated (after the deletion) until nothing new is returned, so that
    no email is missed. Files are retrieved BEFORE the deletion, since afterwards they can not be fetched.

    A soft delete in Graph Mail / EWS moves the item to "Deleted Items" under a NEW ID, so a later round would see the
    moved copy as a new email (and delete it again, in effect a hard delete). Emails whose ``(mailbox,
    InternetMessageID)`` was already processed in a previous round are therefore skipped as well.
    """
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    seen_message_ids: set[tuple[str, str] | None] = set()  # never holds None: emails without an InternetMessageID are not added
    exhausted = False
    try:
        for _ in range(MAX_ROUNDS if params.delete else 1):
            emails, saturated = ops.search()
            exhausted = False
            fresh = [email for email in emails if email_key(email) not in seen and message_key(email) not in seen_message_ids]
            if not fresh:
                break
            for email in fresh:
                seen[email_key(email)] = email
                process_email(params, result, email, ops)
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
    """Message ID is preferred over subject / sender when it was provided."""
    clauses: list[str] = []
    if params.internet_message_ids:
        ids = " OR ".join(
            f'rfc822msgid:"{escape_quoted(strip_brackets(message_id))}"' for message_id in params.internet_message_ids
        )
        clauses.append(f"({ids})")
    else:
        if params.subjects:
            clauses.append("(" + " OR ".join(f'subject:"{escape_quoted(subject)}"' for subject in params.subjects) + ")")
        if params.sender_address:
            clauses.append(f'from:"{escape_quoted(params.sender_address)}"')
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
    # gmail-get-mail (object_id) also returns trashed messages: "Labels" is a list there and a CSV string in the search.
    email["Trashed"] = GMAIL_TRASH_LABEL in as_list(item.get("Labels"))
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
    clauses = [f"receivedDateTime ge {params.since.strftime('%Y-%m-%dT%H:%M:%SZ')}"]
    if params.internet_message_ids:
        ids = " or ".join(f"internetMessageId eq '{escape_single_quotes(with_brackets(i))}'" for i in params.internet_message_ids)
        clauses.append(f"({ids})")
    else:
        if params.subjects:
            subjects = " or ".join(f"contains(subject,'{escape_single_quotes(s)}')" for s in params.subjects)
            clauses.append(f"({subjects})")
        if params.sender_address:
            clauses.append(f"from/emailAddress/address eq '{escape_single_quotes(params.sender_address)}'")
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
    clauses: list[str] = []
    if params.internet_message_ids:
        ids = " OR ".join(f'{EWS_MESSAGE_ID_FIELD}:"{with_brackets(i)}"' for i in params.internet_message_ids)
        clauses.append(f"({ids})" if len(params.internet_message_ids) > 1 else ids)
    else:
        if params.subjects:
            subjects_query = " OR ".join(f'Subject:"{escape_quoted(subject)}"' for subject in params.subjects)
            clauses.append(f"({subjects_query})" if len(params.subjects) > 1 else subjects_query)
        if params.sender_address:
            clauses.append(f'From:"{escape_quoted(params.sender_address)}"')

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


def vendor_step(params: SearchParams, vendor: dict[str, Any], result: VendorResult) -> str:
    """
    Advances a vendor by ONE step and returns its new stage.

    * ``start``: the whole "search -> (files) -> delete" flow, synchronously within one tick. Then ``verify`` (when
      the deletion should be verified and an email was deleted) or ``done``.
    * ``verify``: see ``verify_step``.
    """
    ops = VENDORS[vendor["key"]].ops(params, vendor["instance"], result)
    if vendor["stage"] == STAGE_VERIFY:
        return verify_step(vendor["verify_started"], result, ops.search)
    try:
        search_and_delete(params, result, ops)
    except NotFoundError:
        result.additional["NotFound"] = True  # The email requested by object_id does not exist (not a hard failure).
        raise
    if params.delete and params.verify_deletion and any(email.get("Deleted") is True for email in result.emails):
        vendor["verify_started"] = time.time()
        return STAGE_VERIFY
    return STAGE_DONE


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


# ---------------------------------------------------------------------------------------------------------------------
# The state machine: JSON state, one step of every vendor per tick
# ---------------------------------------------------------------------------------------------------------------------
def new_vendor_state(key: str, brand: str, instance: str) -> dict[str, Any]:
    result = VendorResult(vendor=VENDORS[key].display_name, brand=brand, instance=instance)
    return {
        "key": key,
        "instance": instance,
        "stage": STAGE_START,
        "result": asdict(result),
        "verify_started": None,  # epoch time at which the vendor entered the ``verify`` stage
    }


def new_state(params: SearchParams) -> dict[str, Any]:
    """Builds the state of the first tick: resolves the vendor instances and fixes the absolute deadline and search window."""
    instances = resolve_instances(params.brands)
    if params.object_id and len({key for key, _, _ in instances}) != 1:
        raise DemistoException("When object_id is specified, exactly one brand (with an enabled instance) must be selected.")
    if not instances:
        raise DemistoException("No enabled instance was found for the requested brands.")
    vendors = [new_vendor_state(key, brand, instance) for key, brand, instance in instances]
    return {
        "version": STATE_VERSION,
        "deadline": time.time() + params.timeout,
        "since": params.since.isoformat(),
        "command_trace": [],
        "vendors": vendors,
    }


def validate_state_vendors(vendors: Any) -> None:
    """Rejects a state whose vendors have an unknown key or stage (the state is a script argument and can be forged)."""
    if not isinstance(vendors, list):
        raise DemistoException("The polling state is invalid: 'vendors' must be a list.")
    for vendor in vendors:
        if not isinstance(vendor, dict):
            raise DemistoException("The polling state is invalid: every vendor must be an object.")
        key, stage, verify_started = vendor.get("key"), vendor.get("stage"), vendor.get("verify_started")
        if key not in VENDORS:
            raise DemistoException(f"The polling state is invalid: unknown vendor '{key}'.")
        if stage not in VALID_STAGES:
            raise DemistoException(f"The polling state is invalid: unknown stage '{stage}' of vendor '{key}'.")
        is_number = isinstance(verify_started, int | float) and not isinstance(verify_started, bool)
        if not is_number and (verify_started is not None or stage == STAGE_VERIFY):
            raise DemistoException(f"The polling state is invalid: bad 'verify_started' of vendor '{key}'.")


def load_state(args: dict[str, Any]) -> dict[str, Any] | None:
    """The state passed by the previous tick (``None`` on the first tick)."""
    raw = args.get(STATE_ARG)
    if not raw:
        return None
    state = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        raise DemistoException("The polling state is invalid or was created by an incompatible version of the script.")
    validate_state_vendors(state.get("vendors", []))
    return state


def dump_state(state: dict[str, Any]) -> str:
    return json.dumps(state, separators=(",", ":"))


def results_from_state(state: dict[str, Any]) -> list[VendorResult]:
    return [VendorResult(**vendor["result"]) for vendor in state["vendors"]]


def publish_files(result: VendorResult) -> None:
    """Publishes the retrieved files right away (they are never carried in the state) and clears them from the result."""
    for file_entry in result.file_entries:
        return_results(file_entry)
    result.file_entries = []


def advance_vendor(params: SearchParams, vendor: dict[str, Any]) -> str:
    """Advances one vendor by ONE step. Never raises: errors are stored in the result together with whatever was collected."""
    result = VendorResult(**vendor["result"])
    try:
        if vendor["stage"] == STAGE_START and budget_exhausted():  # Do not start a vendor when there is no time left.
            result.errors.append(f"Timed out before this vendor was run: the {params.timeout} seconds timeout was reached.")
            stage = STAGE_DONE
        else:
            stage = vendor_step(params, vendor, result)
    except Exception as exc:
        demisto.debug(f"{result.vendor} ({vendor['instance']}) failed: {exc}\n{traceback.format_exc()}")
        result.errors.append(str(exc))
        stage = STAGE_DONE
    publish_files(result)
    vendor["result"] = asdict(result)
    vendor["stage"] = stage
    return stage


def set_deadline(deadline: float | None, timeout: int) -> None:
    """Sets the overall time budget of the current tick from the absolute (epoch) deadline stored in the state."""
    global _DEADLINE, _TIMEOUT_SECONDS
    _DEADLINE = deadline
    _TIMEOUT_SECONDS = timeout


def enforce_state_size(state: dict[str, Any]) -> None:
    """Keeps the serialized state below ``MAX_STATE_BYTES`` by truncating the largest email bodies (and marking them)."""
    size = len(dump_state(state))
    if size <= MAX_STATE_BYTES:
        return
    bodies = [
        (len(email.get("HTMLBody") or ""), email)
        for vendor in state["vendors"]
        for email in vendor["result"]["emails"]
        if len(email.get("HTMLBody") or "") > HTML_BODY_PREFIX_CHARS
    ]
    for _, email in sorted(bodies, key=lambda item: item[0], reverse=True):
        before = len(json.dumps(email["HTMLBody"]))
        email["HTMLBody"] = email["HTMLBody"][:HTML_BODY_PREFIX_CHARS]
        email["HTMLBodyTruncated"] = True
        size -= before - len(json.dumps(email["HTMLBody"]))
        if size <= MAX_STATE_BYTES:
            return
    demisto.debug(f"The polling state is still {size} bytes after truncating the HTML bodies.")


def run_tick(params: SearchParams, state: dict[str, Any]) -> tuple[dict[str, Any], bool, list[str]]:
    """
    Advances every vendor that is not done by one step.

    Returns ``(state, done, progress_messages)``: ``done`` is true when every vendor is done, the messages describe the
    vendors whose stage changed in this tick (idle polls produce none).
    """
    set_deadline(state["deadline"], params.timeout)
    COMMAND_TRACE[:] = list(state.get("command_trace") or [])
    messages: list[str] = []
    for vendor in state["vendors"]:
        before = vendor["stage"]
        if before == STAGE_DONE:
            continue
        after = advance_vendor(params, vendor)
        if after != before:
            messages.append(f"{vendor['result']['vendor']}: {STAGE_LABELS.get(after, after)}")
    done = all(vendor["stage"] == STAGE_DONE for vendor in state["vendors"])
    del COMMAND_TRACE[:-MAX_TRACE_LINES]  # only the last lines are kept (and stored in the state)
    state["command_trace"] = list(COMMAND_TRACE) if params.verbose else []
    if not done:
        enforce_state_size(state)
    return state, done, messages


# ---------------------------------------------------------------------------------------------------------------------
# Arguments and outputs
# ---------------------------------------------------------------------------------------------------------------------
def parse_timeout(value: Any) -> int:
    """Parses the ``timeout`` argument (seconds): empty -> default, otherwise it must be a positive integer."""
    try:
        timeout = arg_to_number(value)
    except ValueError:
        timeout = 0
    if timeout is None:
        return DEFAULT_TIMEOUT_SECONDS
    if timeout <= 0:
        raise DemistoException("timeout must be a positive number of seconds.")
    return timeout


def parse_args(args: dict[str, Any], since: datetime | None = None) -> SearchParams:
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
    time_frame = args.get("time_frame") or DEFAULT_TIME_FRAME
    # `since` is fixed on the first tick (and restored from the state on later ticks): the search window must not slide.
    since = since or datetime.now(UTC) - parse_time_frame(time_frame)
    return SearchParams(
        internet_message_ids=message_ids,
        object_id=object_id,
        operation=operation,
        delete_type=delete_type,
        since=since,
        subjects=subjects,
        sender_address=sender,
        retrieve_files=argToBoolean(args.get("retrieve_files") or False),
        verify_deletion=argToBoolean(args.get("verify_deletion") or False),
        target_mailboxes=target_mailboxes,
        mailbox_scope=scope,
        brands=brands,
        verbose=argToBoolean(args.get("verbose") or False),
        timeout=timeout,
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
            if email.get("DeletionVerified") is not None:
                additional_fields["Verified"] = email["DeletionVerified"]
            if email.get("HTMLBodyTruncated"):
                additional_fields["HTMLBodyTruncated"] = True
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
        # Skip the per-vendor status records (vendors that found nothing or failed): they have no email to show.
        if not email.get("Timestamp"):
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
# Polling entry point: every script run is ONE tick of the state machine
# ---------------------------------------------------------------------------------------------------------------------
class InvalidArgumentsError(DemistoException):
    """The script arguments are invalid (reported with ``return_error``)."""


def scheduled_timeout(state: dict[str, Any]) -> int:
    """
    The platform level timeout of the scheduled command: the remaining overall budget plus ``SCHEDULE_MARGIN_SECONDS``.

    The margin keeps the platform timeout away from the next run, so the next tick can still run and report the
    timeout once the budget is exhausted.
    """
    return max(int(state["deadline"] - time.time()), 0) + SCHEDULE_MARGIN_SECONDS


def failure_results(params: SearchParams, exc: Exception) -> list[CommandResults]:
    demisto.debug(f"Unexpected failure: {exc}\n{traceback.format_exc()}")
    failure = VendorResult(vendor="None", brand="", instance="", errors=[str(exc)])
    return build_command_results(params, [failure])


def polling_results(args: dict[str, Any], state: dict[str, Any], messages: list[str]) -> CommandResults:
    """
    The result of an intermediate tick: the progress messages (or the poll message, unless hidden) and the scheduled
    command that reruns the script with the original arguments, the new ``state`` and ``hide_polling_output=True``.
    """
    if messages:
        readable_output = "\n".join(f"* {message}" for message in messages)
    else:  # An empty readable output produces no War Room text (CommandResults treats it like None).
        readable_output = "" if args.get(HIDE_POLLING_OUTPUT_ARG) else POLL_MESSAGE
    next_args = {**args, STATE_ARG: dump_state(state), HIDE_POLLING_OUTPUT_ARG: True}
    scheduled_command = ScheduledCommand(
        command=SCRIPT_NAME,
        next_run_in_seconds=POLL_INTERVAL_SECONDS,
        args=next_args,
        timeout_in_seconds=scheduled_timeout(state),
    )
    return CommandResults(readable_output=readable_output, scheduled_command=scheduled_command)


def search_and_delete_email(args: dict[str, Any]) -> CommandResults | list[CommandResults]:
    """
    Advances the state machine by one step and returns either the final results or a ``CommandResults`` with a
    ``ScheduledCommand`` that runs the next tick in ``POLL_INTERVAL_SECONDS`` (the state is carried in the ``state`` arg).
    """
    ScheduledCommand.raise_error_if_not_supported()
    state = load_state(args)
    try:
        params = parse_args(args, since=datetime.fromisoformat(state["since"]) if state else None)
    except Exception as exc:
        raise InvalidArgumentsError(str(exc)) from exc
    try:
        if state is None:
            state = new_state(params)
        state, done, messages = run_tick(params, state)
        if done:
            return build_command_results(params, results_from_state(state))
        return polling_results(args, state, messages)
    except Exception as exc:  # Never crash and never poll forever: report the failure in HR and in the context.
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
