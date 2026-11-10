import json
import re
import time
import traceback
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, UTC
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Search & Delete Email - aggregated command.

Searches for emails (and optionally deletes them) using one or more of the supported mail integrations and
normalizes the results of all vendors into the unified ``EmailData`` context path.

Polling (the script never sleeps or blocks)
-------------------------------------------
The script uses the built-in XSOAR polling (``polling_function`` + ``PollResult``). Every run is ONE "tick" of a JSON state
machine: it advances every vendor that is not done by one step and either returns the final results, or schedules the next
run in ``POLL_INTERVAL_SECONDS`` and releases the worker. The state (``args_for_next_run["state"]``) holds the absolute
deadline, the per-vendor stage, the per-vendor result (``VendorResult``) and vendor specific data.

* Per-email vendors (Gmail, Microsoft Graph Mail, EWS): ``start`` (search -> files -> delete, synchronously within one tick)
  -> ``verify`` (only with ``verify_deletion``: one search per tick) -> ``done``.
* Microsoft Graph Security: ``create`` -> ``estimate_start`` -> ``estimate_wait``* -> [``purge_start`` -> ``purge_wait``* ->
  ``estimate_start`` ...] -> ``cleanup`` -> ``done``. The ``cleanup`` is always the last stage.

Arguments worth knowing
-----------------------
* ``delete_type``: ``soft`` (default) or ``hard`` - relevant only for "Search & Delete".
* ``verify_deletion``: ``true`` / ``false`` (default) - see "Deletion verification" below.
* ``timeout``: the OVERALL time budget of the whole run in seconds (default ``DEFAULT_TIMEOUT_SECONDS``), measured across
  all ticks with an absolute epoch deadline stored in the state. Once it is exhausted: vendors that were not started yet
  are reported as failed, the results collected so far are still reported, and the Microsoft Graph Security cleanup
  (deleting the search and the case) always runs (it may take up to ``CLEANUP_GRACE_SECONDS`` more: the scheduled command
  timeout of the platform is the remaining budget plus that grace period).

Output
------
Two War Room entries are returned: the first one holds the ``EmailData`` context and a single results table
(``Search & Delete Email results``), the second one (no context) holds the ``Summary`` table with the totals.

Supported vendors and their capabilities
----------------------------------------
+---------------------------+-------------------------+------------------+------------------------------------------+
| Vendor (brand)            | Specific mailbox(es)    | All mailboxes    | Delete types                             |
+---------------------------+-------------------------+------------------+------------------------------------------+
| Gmail                     | Yes (gmail-search)      | Yes (gmail-      | Soft (move to trash), Hard (permanent)   |
|                           |                         | search-all-      |                                          |
|                           |                         | mailboxes)       |                                          |
| Microsoft Graph Mail      | Yes (per mailbox)       | NO               | Soft only (moved to "Deleted Items")     |
| Microsoft Graph Security  | Yes, via KQL scoping    | Yes (all tenant  | Soft (recoverable), Hard                 |
| (eDiscovery purge)        | (see caveat below)      | mailboxes)       | (permanentlyDelete)                      |
| EWS on-prem (EWS v2)      | Yes (email_addresses)   | Yes              | Soft, Hard                               |
+---------------------------+-------------------------+------------------+------------------------------------------+

Vendor notes / limits
---------------------
* Time frame: Gmail accepts epoch granularity, Microsoft Graph Mail accepts full ISO timestamps, while Microsoft
  Graph Security (KQL ``received>=``) and EWS (AQS ``Received:>=``) only honour the *date* part, so the effective
  search window for those vendors can be up to 24 hours wider than requested.
* Microsoft Graph Security: a search has to be created inside an eDiscovery case, executed (estimate statistics),
  purged and finally deleted. A DEDICATED case (``XSOAR Search And Delete Email <timestamp>-<id>``) is created for every
  run and the search AND the case are ALWAYS deleted at the end (also for "Search Only" and also on failure or timeout).
  Mailbox scoping for "Specific" is done through the KQL query (``recipients:``), which means that copies of the same
  email in other recipients' mailboxes may match as well. The API does not return per-email details, so a single aggregate
  record (``AdditionalFields.Aggregate=True``) with the totals is returned and attachments cannot be retrieved.
* Microsoft Graph Security estimate: ``msg-get-last-estimate-statistics-operation`` returns the raw Graph object with
  lower-case keys (``status`` / ``totalItemCount``) as context only when the operation succeeded. Every other status
  (``running``, ``failed``, ``submissionFailed`` ...) comes back ONLY in the human readable text
  (``... (Status: <status>)``) without context, so the status is parsed from that text.
* Microsoft Graph Mail only works on explicitly named mailboxes and cannot hard delete.
* Searching thousands of mailboxes is resource heavy. All long running steps are polled until the overall
  ``timeout`` budget is exhausted and every search is repeated after a deletion round until no more
  results are returned, so emails beyond a single page are not missed.
* The polling state is capped at ``MAX_STATE_BYTES``: when it grows beyond it, the largest ``HTMLBody`` values are
  truncated (and marked with ``AdditionalFields.HTMLBodyTruncated``).

Deletion verification
---------------------
When ``verify_deletion`` is true (relevant only for "Search & Delete", ignored for "Search Only") the script
verifies that the deletion really happened instead of trusting that the vendor delete command did not fail:
* Gmail / Microsoft Graph Mail / EWS: after the deletion the same search is executed again (once per polling tick, for up to
  ``VERIFICATION_TIMEOUT_SECONDS``, since search indexes may lag) and none of the deleted ``(mailbox, ObjectID)`` pairs
  may be returned. Emails that are still found are reported as failed (``Success=false`` and
  ``AdditionalFields.DeletionVerified=false``) and are not counted in ``TotalDeleted``.
* Microsoft Graph Security: the final estimate that is calculated after the last purge is used. Remaining items
  are reported as failed and ``AdditionalFields.DeletionVerified`` of the vendor entry is false.
"""

OPERATION_SEARCH_ONLY = "Search Only"
OPERATION_SEARCH_AND_DELETE = "Search & Delete"
DELETE_SOFT = "soft"
DELETE_HARD = "hard"
SCOPE_SPECIFIC = "Specific"
SCOPE_ALL = "All"
DEFAULT_TIME_FRAME = "1 hour"

SCRIPT_NAME = "SearchAndDeleteEmail"
DEFAULT_TIMEOUT_SECONDS = 1800  # The overall time budget of the whole run, measured across all ticks.
# The polling interval: the platform minimum is 10 seconds, 20 keeps the load on the vendor APIs low while the eDiscovery
# operations (which take minutes) are polled.
POLL_INTERVAL_SECONDS = 20
POLL_MESSAGE = "Search & Delete Email is in progress, the next step runs automatically."
CLEANUP_GRACE_SECONDS = (
    600  # Added to the scheduled command timeout so our own deadline (which triggers the cleanup) fires first.
)
MAX_CLEANUP_ATTEMPTS = 3
VERIFICATION_TIMEOUT_SECONDS = 120  # How long to wait for the deleted emails to disappear from the search results.
MAX_STATE_BYTES = 500_000  # The polling state above this size gets its largest HTML bodies truncated.
HTML_BODY_PREFIX_CHARS = 1000
MAX_TRACE_LINES = 200
STATE_VERSION = 1
STATE_ARG = "state"
SCHEDULED_TIMEOUT_ARG = "scheduled_timeout_in_seconds"  # NOT "timeout": that is the script's own overall budget argument.
NO_INSTANCE_KEY = "none"

STAGE_START = "start"
STAGE_VERIFY = "verify"
STAGE_CREATE = "create"
STAGE_ESTIMATE_START = "estimate_start"
STAGE_ESTIMATE_WAIT = "estimate_wait"
STAGE_PURGE_START = "purge_start"
STAGE_PURGE_WAIT = "purge_wait"
STAGE_CLEANUP = "cleanup"
STAGE_DONE = "done"
# The one-line progress that is announced in the War Room when a vendor ENTERS a stage (never on idle polls).
STAGE_LABELS = {
    STAGE_START: "started",
    STAGE_CREATE: "creating the eDiscovery case and search",
    STAGE_ESTIMATE_START: "starting the estimate",
    STAGE_ESTIMATE_WAIT: "estimate running",
    STAGE_PURGE_START: "starting the purge",
    STAGE_PURGE_WAIT: "purge running",
    STAGE_VERIFY: "verifying the deletion",
    STAGE_CLEANUP: "cleaning up",
    STAGE_DONE: "done",
}
MAX_ROUNDS = 10  # Max number of "search -> delete" rounds when the vendor returns capped result pages.
GMAIL_PAGE_SIZE = 500
GRAPH_MAIL_PAGE_SIZE = 50
GRAPH_MAIL_MAX_PAGES = 64
EWS_LIMIT_STEPS = (100, 500, 1000)
EWS_ENRICH_LIMIT = 50  # Max number of emails for which the full item (body, attachments) is fetched.
GRAPH_SECURITY_CASE_PREFIX = "XSOAR Search And Delete Email"  # The dedicated per-run case (deleted at the end of the run).
GRAPH_SECURITY_SUCCESS_STATUSES = ("succeeded", "completed")
GRAPH_SECURITY_FAILED_STATUSES = ("failed", "partiallysucceeded", "cancelled", "submissionfailed")
# msg-get-last-estimate-statistics-operation returns the raw Graph object (``status`` / ``totalItemCount``), while its YAML
# documents ``Status`` / ``TotalItemsCount``: every spelling is accepted.
ESTIMATE_STATUS_KEYS = ("status", "Status")
ESTIMATE_COUNT_KEYS = ("totalItemCount", "TotalItemCount", "TotalItemsCount")
# Non-success estimate statuses come back without context, only as "... (Status: <status>)" in the human readable.
ESTIMATE_HR_STATUS = re.compile(r"\(Status:\s*(\w+)\)")
ESTIMATE_PENDING_STATUS = "pending"  # ``last_status`` placeholder when no status could be read at all.

# Property names used to search by Internet Message ID in each vendor query language.
GRAPH_SECURITY_MESSAGE_ID_FIELD = "InternetMessageId"
EWS_MESSAGE_ID_FIELD = "Message-ID"

COMMAND_TRACE: list[str] = []

# The overall time budget of the run: ``_DEADLINE`` is an absolute ``time.time()`` (epoch) value taken from the state
# of the current tick (``None`` = no limit).
_DEADLINE: float | None = None
_TIMEOUT_SECONDS: int = DEFAULT_TIMEOUT_SECONDS


class VendorError(DemistoException):
    """A vendor command returned an error entry."""


class UnsupportedError(DemistoException):
    """The requested operation / scope is not supported by the vendor."""


@dataclass
class SearchParams:
    """Parsed and validated command arguments."""

    internet_message_ids: list[str]
    object_id: str
    operation: str
    delete_type: str
    time_frame: str
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
    """Aggregated outcome of one vendor instance (JSON-safe: it is serialized with ``asdict`` into the polling state)."""

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
    aggregate: bool = False  # The vendor returns aggregate counts only (Graph Security): one aggregate record, no emails.

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


def remaining_budget() -> float | None:
    """The seconds left in the overall time budget (``None`` when there is no limit)."""
    return None if _DEADLINE is None else _DEADLINE - time.time()


def budget_exhausted() -> bool:
    remaining = remaining_budget()
    return remaining is not None and remaining <= 0


def ensure_time_left() -> None:
    """Raises a ``DemistoException`` when the overall time budget was exhausted."""
    if budget_exhausted():
        raise DemistoException(
            f"Timed out: the {_TIMEOUT_SECONDS} seconds timeout was reached. Increase the timeout argument or narrow the search."
        )


def run_command(command: str, args: dict[str, Any], instance: str, *, enforce_timeout: bool = True) -> list[dict[str, Any]]:
    """
    Runs a vendor command on a specific instance and raises ``VendorError`` if it returned an error entry.

    Raises a ``DemistoException`` when the overall time budget is exhausted, unless ``enforce_timeout`` is false (which
    is used for cleanup commands that must run in any case).
    """
    if enforce_timeout:
        ensure_time_left()
    command_args = {key: value for key, value in args.items() if value not in (None, "")}
    command_args["using"] = instance
    COMMAND_TRACE.append(f"{command} { ({k: v for k, v in command_args.items() if k != 'using'}) } [using={instance}]")
    demisto.debug(f"Running {command} with {command_args=}")
    results = demisto.executeCommand(command, command_args)
    if is_error(results):
        raise VendorError(f"{command} failed: {get_error(results)}")
    return results or []


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


def find_first(results: list[dict[str, Any]], names: tuple[str, ...]) -> Any:
    """The first non-empty context value stored under any of ``names`` (tried in order) in the command result entries."""
    for name in names:
        value = find_in_results(results, name)
        if value not in (None, ""):
            return value
    return None


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
VERIFY_UNSUPPORTED_WARNING = (
    "Deletion verification (verify_deletion) is not supported for Microsoft Graph Security. "
    "The deletion will be performed without verification for this integration."
)


def email_key(email: dict[str, Any]) -> tuple[str, str]:
    return ",".join(email["Mailbox"]), email["ObjectID"]


@dataclass
class EmailOps:
    """The vendor specific callables of a per-email vendor (rebuilt from the params on every tick, never stored in the state)."""

    search: Callable[[], tuple[list[dict[str, Any]], bool]]
    delete: Callable[[dict[str, Any]], None]
    get_files: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None


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


def verify_step(vendor: dict[str, Any], result: VendorResult, search: Callable[[], tuple[list[dict[str, Any]], bool]]) -> str:
    """
    Stage ``verify``: ONE verification search per tick, checking that the successfully deleted emails are really gone.

    The match is done on ``(mailbox, ObjectID)`` of the deleted emails: Gmail's search excludes the trash by default,
    while Graph Mail and EWS assign a new item ID to an item that was moved to "Deleted Items", so a moved copy is not
    returned as a match of the old ID. The vendor keeps being polled (indexes can lag) until none of the deleted IDs is
    returned or ``VERIFICATION_TIMEOUT_SECONDS`` passed: what is still found is then reported as unverified. The overall
    deadline caps the window as well: once it passed, the search command is refused and the emails stay unverified.

    A failure of the verification search itself does NOT mean the deletion failed: the emails keep ``Deleted=True``,
    ``DeletionVerified`` is left unset and the error is added to ``result.errors``.
    """
    deleted = [email for email in result.emails if email.get("Deleted") is True]
    pending = {email_key(email) for email in deleted}
    deadline = vendor["data"]["verify_started"] + VERIFICATION_TIMEOUT_SECONDS
    try:
        emails, _ = search()
    except Exception as exc:
        if budget_exhausted():  # The overall budget ended: same as the end of the window, the emails stay unverified.
            mark_verification(result, deleted, pending)
        else:
            result.errors.append(f"Failed verifying the deletion: {exc}")
        return STAGE_DONE
    remaining = {email_key(email) for email in emails} & pending
    if remaining and time.time() < deadline:
        return STAGE_VERIFY
    mark_verification(result, deleted, remaining)
    return STAGE_DONE


def per_email_step(ops_factory: Callable[[SearchParams, str, VendorResult], EmailOps]) -> Callable[..., str]:
    """
    Builds the step function of a per-email vendor.

    * ``start``: the whole "search -> (files) -> delete" flow, synchronously within one tick. Then ``verify`` (when
      the deletion should be verified and an email was deleted) or ``done``.
    * ``verify``: see ``verify_step``.
    """

    def step(params: SearchParams, vendor: dict[str, Any], result: VendorResult) -> str:
        ops = ops_factory(params, vendor["instance"], result)
        if vendor["stage"] == STAGE_VERIFY:
            return verify_step(vendor, result, ops.search)
        search_and_delete(params, result, ops.search, ops.delete, ops.get_files)
        if params.delete and params.verify_deletion and any(email.get("Deleted") is True for email in result.emails):
            vendor["data"]["verify_started"] = time.time()
            return STAGE_VERIFY
        return STAGE_DONE

    return step


def search_and_delete(
    params: SearchParams,
    result: VendorResult,
    search: Callable[[], tuple[list[dict[str, Any]], bool]],
    delete: Callable[[dict[str, Any]], None],
    get_files: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
) -> None:
    """
    Shared "search -> (retrieve files) -> delete" loop used by the per-email vendors.

    ``search`` returns ``(emails, saturated)``. ``saturated`` is True when the vendor capped the number of returned
    emails, in which case the search is repeated (after the deletion) until nothing new is returned, so that
    no email is missed. Files are retrieved BEFORE the deletion, since afterwards they can not be fetched.
    """
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    exhausted = False
    try:
        for _ in range(MAX_ROUNDS if params.delete else 1):
            emails, saturated = search()
            exhausted = False
            fresh = [email for email in emails if email_key(email) not in seen]
            if not fresh:
                break
            for email in fresh:
                seen[email_key(email)] = email
                process_email(params, result, email, delete, get_files)
            if not saturated:
                break
            exhausted = True
    finally:
        # Partial results must survive a timeout / error in a later round: report what was already found and deleted.
        result.emails = list(seen.values())
        result.total_found = len(seen)
    if exhausted:
        result.additional["Note"] = (
            "The vendor capped the number of returned emails, more matching emails may exist. "
            "Rerun the command to process the remaining emails."
        )


def process_email(
    params: SearchParams,
    result: VendorResult,
    email: dict[str, Any],
    delete: Callable[[dict[str, Any]], None],
    get_files: Callable[[dict[str, Any]], list[dict[str, Any]]] | None,
) -> None:
    """Retrieves the files of one email (when requested) and deletes it (when the operation is "Search & Delete")."""
    if params.retrieve_files and get_files and email.get("HasAttachments", bool(email["Attachments"])):
        try:
            collect_files(get_files(email), email, result)
        except Exception as exc:  # a failing attachment must not block the deletion of the other emails
            result.errors.append(f"Failed retrieving files of {email['ObjectID']}: {exc}")
    if not params.delete:
        return
    try:
        delete(email)
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
        ids = " OR ".join(f"rfc822msgid:{strip_brackets(message_id)}" for message_id in params.internet_message_ids)
        clauses.append(f"({ids})")
    else:
        if params.subjects:
            clauses.append("(" + " OR ".join(f'subject:"{subject}"' for subject in params.subjects) + ")")
        if params.sender_address:
            clauses.append(f"from:{params.sender_address}")
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


def gmail_search(params: SearchParams, instance: str) -> tuple[list[dict[str, Any]], bool]:
    """Searches Gmail and follows every page token so that all matching emails are returned."""
    query = build_gmail_query(params)
    emails: list[dict[str, Any]] = []
    if params.object_id:
        results = run_command("gmail-get-mail", {"user-id": params.target_mailboxes[0], "message-id": params.object_id}, instance)
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
            emails.extend(gmail_to_email(item) for item in context_values(results, "Gmail"))
            # NOTE: for "all mailboxes" Gmail splits big domains into scheduled (polling) sub-searches; the
            # page token below belongs to the *accounts* list, which is why it is followed here as well.
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
            results = run_command(
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
        raise UnsupportedError(
            "Microsoft Graph Mail can not search all mailboxes, use Microsoft Graph Security or specify the mailboxes."
        )
    if params.delete and params.hard_delete:
        result.additional["Note"] = "Microsoft Graph Mail can not hard delete, emails were moved to 'Deleted Items'."

    def delete(email: dict[str, Any]) -> None:
        run_command("msgraph-mail-delete-email", {"user_id": email["Mailbox"][0], "message_id": email["ObjectID"]}, instance)

    def get_files(email: dict[str, Any]) -> list[dict[str, Any]]:
        return run_command(
            "msgraph-mail-get-attachment", {"user_id": email["Mailbox"][0], "message_id": email["ObjectID"]}, instance
        )

    return EmailOps(lambda: graph_mail_search(params, instance), delete, get_files)


# ---------------------------------------------------------------------------------------------------------------------
# Microsoft Graph Security (eDiscovery: create search -> estimate -> purge -> delete search)
# ---------------------------------------------------------------------------------------------------------------------
def build_graph_security_kql(params: SearchParams) -> str:
    clauses: list[str] = []
    if params.internet_message_ids:
        ids = " OR ".join(f'{GRAPH_SECURITY_MESSAGE_ID_FIELD}:"{with_brackets(i)}"' for i in params.internet_message_ids)
        clauses.append(f"({ids})")
    else:
        if params.subjects:
            clauses.append("(" + " OR ".join(f'subject:"{subject}"' for subject in params.subjects) + ")")
        if params.sender_address:
            clauses.append(f"from:{params.sender_address}")
    if not params.all_mailboxes:
        clauses.append("(" + " OR ".join(f"recipients:{mailbox}" for mailbox in params.target_mailboxes) + ")")
    clauses.append(f"received>={params.since.strftime('%Y-%m-%d')}")
    return " AND ".join(clauses)


def new_graph_security_data() -> dict[str, Any]:
    """The Graph Security part of the state (``vendor["data"]``). The ids are persisted right after the objects are created."""
    return {
        "case_id": "",
        "search_id": "",
        "case_name": "",
        "rounds": 0,  # The number of finished purge rounds.
        "remaining": 0,  # The items that still matched the search in the last estimate.
        "operation_id": "",
        "purge_requested": False,
        "cleanup_attempts": 0,
        "search_deleted": False,
        "case_deleted": False,
        "last_status": "",  # The last estimate status that was seen (diagnostics only; read with .get for older states).
    }


def graph_security_case_name() -> str:
    """A unique name of the dedicated per-run eDiscovery case (it is deleted at the end of the run)."""
    return f"{GRAPH_SECURITY_CASE_PREFIX} {datetime.now(UTC):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:8]}"


def graph_security_create(params: SearchParams, instance: str, data: dict[str, Any], result: VendorResult) -> str:
    """Stage ``create``: creates the dedicated case and the search in it (the ids are persisted immediately)."""
    if params.object_id:
        raise UnsupportedError("Microsoft Graph Security does not support searching by object_id.")
    if params.retrieve_files:
        result.additional["Note"] = "Microsoft Graph Security does not return email content, files were not retrieved."
    data["case_name"] = graph_security_case_name()
    results = run_command("msg-create-ediscovery-case", {"display_name": data["case_name"]}, instance)
    case_id = find_in_results(results, "CaseId")
    if not case_id:
        raise VendorError("Could not determine the ID of the created eDiscovery case.")
    data["case_id"] = case_id
    results = run_command(
        "msg-create-ediscovery-search",
        {
            "case_id": case_id,
            "display_name": data["case_name"],
            "content_query": build_graph_security_kql(params),
            "data_source_scopes": "allTenantMailboxes",
        },
        instance,
    )
    search_id = find_in_results(results, "SearchId")
    if not search_id:
        raise VendorError("Could not determine the ID of the created eDiscovery search.")
    data["search_id"] = search_id
    return STAGE_ESTIMATE_START


def graph_security_estimate_start(params: SearchParams, instance: str, data: dict[str, Any], result: VendorResult) -> str:
    run_command("msg-run-estimate-statistics", {"case_id": data["case_id"], "search_id": data["search_id"]}, instance)
    return STAGE_ESTIMATE_WAIT


def graph_security_finish_loop(params: SearchParams, data: dict[str, Any], result: VendorResult) -> str:
    """Leaves the estimate / purge loop: reports the deletion totals ("Search & Delete") and moves to the cleanup."""
    remaining = data["remaining"]
    if params.delete:
        result.total_deleted = result.total_found - remaining
        result.total_failed = remaining
    if params.delete and params.verify_deletion and result.total_found > 0:
        # The estimate that was calculated after the last purge is the verification (no additional API calls).
        result.additional["DeletionVerified"] = remaining == 0
        if remaining > 0:
            note = (
                f"Deletion could not be verified: {remaining} item(s) still matched the search "
                "after the last purge, they are reported as failed."
            )
            result.additional["Note"] = f"{result.additional['Note']} {note}" if result.additional.get("Note") else note
    return STAGE_CLEANUP


def status_from_human_readable(results: list[dict[str, Any]]) -> str:
    """The lower-cased ``(Status: <status>)`` of the first entry whose ``HumanReadable`` / ``Contents`` text holds one."""
    for entry in results:
        if not isinstance(entry, dict):
            continue
        for text in (entry.get("HumanReadable"), entry.get("Contents")):
            match = ESTIMATE_HR_STATUS.search(text) if isinstance(text, str) else None
            if match:
                return match.group(1).lower()
    return ""


def parse_item_count(count: Any) -> int | None:
    """An ``int`` or a numeric string as ``int`` (``None`` stays ``None``); anything else raises ``VendorError``."""
    if count is None:
        return None
    if isinstance(count, int) and not isinstance(count, bool):
        return count
    if isinstance(count, str) and count.strip().isdigit():
        return int(count)
    raise VendorError(f"Unexpected estimate item count: {count!r}")


def parse_estimate(results: list[dict[str, Any]]) -> tuple[str, int | None]:
    """
    The ``(lower-cased status, total item count)`` of a msg-get-last-estimate-statistics-operation response.

    The status is read from the context and, when there is none (every non-success status), from the human readable.
    A response without any status yields ``("", None)``.
    """
    status = str(find_first(results, ESTIMATE_STATUS_KEYS) or "").lower() or status_from_human_readable(results)
    return status, parse_item_count(find_first(results, ESTIMATE_COUNT_KEYS))


def graph_security_estimate_wait(params: SearchParams, instance: str, data: dict[str, Any], result: VendorResult) -> str:
    """Stage ``estimate_wait``: ONE status check per tick."""
    results = run_command(
        "msg-get-last-estimate-statistics-operation", {"case_id": data["case_id"], "search_id": data["search_id"]}, instance
    )
    status, count = parse_estimate(results)
    data["last_status"] = status or ESTIMATE_PENDING_STATUS
    if status in GRAPH_SECURITY_FAILED_STATUSES:
        raise VendorError(f"The estimate statistics operation ended with status '{status}'.")
    if status not in GRAPH_SECURITY_SUCCESS_STATUSES:
        return STAGE_ESTIMATE_WAIT  # still running: the polling decorator schedules the next tick
    if count is None:  # never report "0 found" just because the output shape changed
        raise VendorError("The estimate statistics operation finished but did not return the number of items.")
    data["remaining"] = count
    if data["rounds"] == 0:  # the first estimate is the number of the emails that were found
        result.total_found = data["remaining"]
    # A single purge removes a limited amount of items per mailbox, so purge and re-estimate until nothing is left.
    if not params.delete or data["remaining"] == 0 or data["rounds"] >= MAX_ROUNDS:
        return graph_security_finish_loop(params, data, result)
    return STAGE_PURGE_START


def graph_security_purge_start(params: SearchParams, instance: str, data: dict[str, Any], result: VendorResult) -> str:
    purge_type = "permanentlyDelete" if params.hard_delete else "recoverable"
    results = run_command(
        "msg-purge-ediscovery-data",
        {"case_id": data["case_id"], "search_id": data["search_id"], "purge_type": purge_type, "purge_areas": "mailboxes"},
        instance,
    )
    operation_id = find_in_results(results, "OperationID")
    if not operation_id:
        raise VendorError("Could not determine the ID of the purge operation.")
    data["operation_id"] = operation_id
    data["purge_requested"] = True
    return STAGE_PURGE_WAIT


def graph_security_purge_wait(params: SearchParams, instance: str, data: dict[str, Any], result: VendorResult) -> str:
    """Stage ``purge_wait``: ONE status check per tick. A finished purge is followed by a new estimate."""
    operation = run_command(
        "msg-list-case-operation", {"case_id": data["case_id"], "operation_id": data["operation_id"]}, instance
    )
    status = str(find_in_results(operation, "Status") or "").lower()
    if status in GRAPH_SECURITY_FAILED_STATUSES:
        raise VendorError(f"The purge operation ended with status '{status}'.")
    if status not in GRAPH_SECURITY_SUCCESS_STATUSES:
        return STAGE_PURGE_WAIT
    data["rounds"] += 1
    return STAGE_ESTIMATE_START


def graph_security_delete(command: str, args: dict[str, Any], instance: str, what: str, errors: list[str]) -> bool:
    try:
        # The cleanup must run even when the overall time budget is exhausted, otherwise the objects would leak.
        run_command(command, args, instance, enforce_timeout=False)
        return True
    except Exception as exc:
        errors.append(f"Failed deleting eDiscovery {what}: {exc}")
        return False


def graph_security_cleanup(params: SearchParams, instance: str, data: dict[str, Any], result: VendorResult) -> str:
    """
    The guaranteed final stage: deletes the search and then the dedicated case (each one only once, even when the other failed).

    A cleanup that did not fully succeed is retried on the next tick up to ``MAX_CLEANUP_ATTEMPTS``; only the errors of
    the last attempt are reported (an error that was fixed by a retry is not a failure).
    """
    errors: list[str] = []
    case_id, search_id = data["case_id"], data["search_id"]
    if search_id and not data["search_deleted"]:
        data["search_deleted"] = graph_security_delete(
            "msg-delete-ediscovery-search",
            {"case_id": case_id, "search_id": search_id},
            instance,
            f"search {search_id}",
            errors,
        )
    if case_id and not data["case_deleted"]:
        # No hold is ever created in the case and its search was deleted above, so closing it is not required.
        data["case_deleted"] = graph_security_delete(
            "msg-delete-ediscovery-case", {"case_id": case_id}, instance, f"case {case_id}", errors
        )
    data["cleanup_attempts"] += 1
    if errors and data["cleanup_attempts"] < MAX_CLEANUP_ATTEMPTS:
        return STAGE_CLEANUP
    result.errors.extend(errors)
    return STAGE_DONE


GRAPH_SECURITY_STAGES: dict[str, Callable[[SearchParams, str, dict[str, Any], VendorResult], str]] = {
    STAGE_CREATE: graph_security_create,
    STAGE_ESTIMATE_START: graph_security_estimate_start,
    STAGE_ESTIMATE_WAIT: graph_security_estimate_wait,
    STAGE_PURGE_START: graph_security_purge_start,
    STAGE_PURGE_WAIT: graph_security_purge_wait,
    STAGE_CLEANUP: graph_security_cleanup,
}


def graph_security_timeout_message(stage: str, data: dict[str, Any]) -> str:
    """The timeout error of the Graph Security vendor: names the stage it was stuck in and the last estimate status seen."""
    last_status = data.get("last_status") or "none"
    return (
        f"Timed out: the {_TIMEOUT_SECONDS} seconds timeout was reached in stage '{stage}' "
        f"(last estimate status: '{last_status}'). Increase the timeout argument or narrow the search."
    )


def graph_security_step(params: SearchParams, vendor: dict[str, Any], result: VendorResult) -> str:
    """
    Advances the Graph Security machine by one stage.

    ``create -> estimate_start -> estimate_wait* -> [purge_start -> purge_wait* -> estimate_start ...] -> cleanup -> done``.
    The overall deadline is checked in every stage but the cleanup; a failing stage raises and ``advance_vendor`` routes
    the vendor to the cleanup (the case, if it was already created, is always deleted).
    """
    stage = vendor["stage"]
    if stage != STAGE_CLEANUP and budget_exhausted():
        raise DemistoException(graph_security_timeout_message(stage, vendor["data"]))
    return GRAPH_SECURITY_STAGES[stage](params, vendor["instance"], vendor["data"], result)


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
            escaped_subjects = [s.replace("\\", "\\\\").replace('"', '\\"') for s in params.subjects]
            subjects_query = " OR ".join(f'Subject:"{subject}"' for subject in escaped_subjects)
            clauses.append(f"({subjects_query})" if len(params.subjects) > 1 else subjects_query)
        if params.sender_address:
            escaped_sender = params.sender_address.replace("\\", "\\\\").replace('"', '\\"')
            clauses.append(f'From:"{escaped_sender}"')

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
        results = run_command(
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
                "target-mailbox": email["Mailbox"][0] if email["Mailbox"] else "",
            },
            instance,
        )

    def get_files(email: dict[str, Any]) -> list[dict[str, Any]]:
        return run_command(
            "ews-get-attachment",
            {"item-id": email["ObjectID"], "target-mailbox": email["Mailbox"][0] if email["Mailbox"] else ""},
            instance,
        )

    return EmailOps(search, delete, get_files)


# ---------------------------------------------------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class VendorSpec:
    display_name: str
    aliases: frozenset[str]  # normalized brand names (see normalize_name)
    step: Callable[[SearchParams, dict[str, Any], VendorResult], str]  # advances the vendor by ONE step, returns the new stage
    initial_stage: str = STAGE_START
    new_data: Callable[[], dict[str, Any]] = dict  # the vendor specific part of the state
    aggregate: bool = False  # the vendor returns aggregate counts only (no per-email details)


# `aliases` must contain the normalized integration `name` (the brand reported by demisto.getModules), the normalized
# integration `display` (what users see) and any other common spelling:
#   Gmail:                    name `Gmail`,                display `Gmail`
#   Microsoft Graph Mail:     name `MicrosoftGraphMail`,   display `O365 Outlook Mail (Using Graph API)`
#   Microsoft Graph Security: name `Microsoft Graph`,      display `Microsoft Graph Security`
#   EWS on-prem:              name `EWS v2`,               display `EWS v2`
VENDORS: dict[str, VendorSpec] = {
    "gmail": VendorSpec("Gmail", frozenset({"gmail"}), per_email_step(gmail_ops)),
    "msgraph_mail": VendorSpec(
        "Microsoft Graph Mail",
        frozenset({"microsoftgraphmail", "msgraphmail", "o365outlookmailusinggraphapi"}),
        per_email_step(graph_mail_ops),
    ),
    "msgraph_security": VendorSpec(
        "Microsoft Graph Security",
        frozenset({"microsoftgraph", "microsoftgraphsecurity", "msgraphsecurity"}),
        graph_security_step,
        initial_stage=STAGE_CREATE,
        new_data=new_graph_security_data,
        aggregate=True,
    ),
    "ews": VendorSpec("EWS on-prem", frozenset({"ewsv2", "ews", "ewsonprem"}), per_email_step(ews_ops)),
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


# ---------------------------------------------------------------------------------------------------------------------
# The state machine: JSON state, one step of every vendor per tick
# ---------------------------------------------------------------------------------------------------------------------
def new_vendor_state(key: str, brand: str, instance: str) -> dict[str, Any]:
    spec = VENDORS[key]
    result = VendorResult(vendor=spec.display_name, brand=brand, instance=instance, aggregate=spec.aggregate)
    return {
        "key": key,
        "brand": brand,
        "instance": instance,
        "stage": spec.initial_stage,
        "result": asdict(result),
        "data": spec.new_data(),
    }


def new_state(params: SearchParams) -> dict[str, Any]:
    """Builds the state of the first tick: resolves the vendor instances and fixes the absolute deadline and search window."""
    instances = resolve_instances(params.brands)
    if params.object_id and len({key for key, _, _ in instances}) != 1:
        raise DemistoException("When object_id is specified, exactly one brand (with an enabled instance) must be selected.")
    vendors: list[dict[str, Any]] = [new_vendor_state(key, brand, instance) for key, brand, instance in instances]
    if not vendors:
        failure = VendorResult(
            vendor="None", brand="", instance="", errors=["No enabled instance was found for the requested brands."]
        )
        vendors.append(
            {"key": NO_INSTANCE_KEY, "brand": "", "instance": "", "stage": STAGE_DONE, "result": asdict(failure), "data": {}}
        )
    return {
        "version": STATE_VERSION,
        "deadline": time.time() + params.timeout,
        "since": params.since.isoformat(),
        "command_trace": [],
        "vendors": vendors,
    }


def load_state(args: dict[str, Any]) -> dict[str, Any] | None:
    """The state passed by the previous tick (``None`` on the first tick)."""
    raw = args.get(STATE_ARG)
    if not raw:
        return None
    state = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        raise DemistoException("The polling state is invalid or was created by an incompatible version of the script.")
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


def failure_stage(vendor: dict[str, Any]) -> str:
    """Where a vendor goes when one of its steps raised: the guaranteed cleanup when something was created, else ``done``."""
    if vendor["stage"] != STAGE_CLEANUP and vendor["data"].get("case_id"):
        return STAGE_CLEANUP
    return STAGE_DONE


def advance_vendor(params: SearchParams, vendor: dict[str, Any]) -> str:
    """Advances one vendor by ONE step. Never raises: errors are stored in the result together with whatever was collected."""
    spec = VENDORS[vendor["key"]]
    result = VendorResult(**vendor["result"])
    try:
        if vendor["stage"] == spec.initial_stage and budget_exhausted():  # Do not start a vendor when there is no time left.
            result.errors.append(f"Timed out before this vendor was run: the {params.timeout} seconds timeout was reached.")
            stage = STAGE_DONE
        else:
            stage = spec.step(params, vendor, result)
    except Exception as exc:
        demisto.debug(f"{result.vendor} ({vendor['instance']}) failed: {exc}\n{traceback.format_exc()}")
        result.errors.append(str(exc))
        stage = failure_stage(vendor)
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
        if "msgraph_security" in vendor_keys_for_brand(brands[0]):
            raise DemistoException("'object_id' is not supported for Microsoft Graph Security.")
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
        time_frame=time_frame,
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
        # Handle vendors that return only aggregate data (e.g., Graph Security)
        if result.aggregate:
            email_data.append(
                {
                    "Brand": result.brand or result.vendor,
                    "Operation": params.operation,
                    "Mailbox": ["All"] if params.all_mailboxes else params.target_mailboxes,
                    "Success": result.success,
                    "Reason": "; ".join(result.errors),
                    "AdditionalFields": {"Aggregate": True, "Instance": result.instance, **result.additional},
                }
            )
            continue

        # Handle individual emails
        for email in result.emails:
            additional_fields = {"ObjectID": email["ObjectID"], "InternetMessageID": email["InternetMessageID"]}
            if email.get("DeletionVerified") is not None:
                additional_fields["Verified"] = email["DeletionVerified"]
            if params.verbose:
                additional_fields["Instance"] = result.instance
                if email.get("HTMLBodyTruncated"):
                    additional_fields["HTMLBodyTruncated"] = True

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

        # Handle a vendor that found nothing or failed
        if not result.emails and not result.aggregate:
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


def build_readable_output(email_data: list[dict[str, Any]], totals: dict[str, int], params: SearchParams) -> str:
    rows = []
    for email in email_data:
        # Filter out empty aggregate rows or vendors that found nothing (for the table display)
        if email.get("AdditionalFields", {}).get("Aggregate") or not email.get("Timestamp"):
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

    table = tableToMarkdown(
        f"Search & Delete Email - {params.operation}",
        rows,
        headers=["Brand", "Mailbox", "ID", "Subject", "From", "To", "Timestamp", "Operation", "Success", "Reason"],
        removeNull=True,
    )

    summary = (
        f"**Total found:** {totals['TotalFound']} | "
        f"**Total deleted:** {totals['TotalDeleted']} | "
        f"**Total failed:** {totals['TotalFailed']}"
    )

    return f"{table}\n{summary}" if rows else f"No emails were found.\n\n{summary}"


def build_command_results(params: SearchParams, results: list[VendorResult]) -> list[CommandResults]:
    email_data = build_email_data_entries(params, results)
    totals = compute_totals(results)

    outputs = {"EmailData": email_data, **totals}
    readable_output = build_readable_output(email_data, totals, params)

    if params.verbose and COMMAND_TRACE:
        readable_output += "\n#### Executed commands\n" + "\n".join(f"* `{line}`" for line in COMMAND_TRACE)

    # Checks if the integration had a hard failure (ignoring 404 "not found" errors)
    def is_hard_failure(r: VendorResult) -> bool:
        if r.success or r.total_found > 0:
            return False
        for err in r.errors:
            err_lower = err.lower()
            if "404" not in err_lower and "not found" not in err_lower:
                return True  # This is a hard failure
        return False  # The error is just a 404, so it is treated as a successful scan with 0 results

    # all_failed will be True only if *all* integrations experienced a hard failure
    all_failed = bool(results) and all(is_hard_failure(r) for r in results)

    if all_failed:
        error_reasons = []
        for r in results:
            if is_hard_failure(r) and r.errors:
                error_reasons.append(f"**{r.brand or r.vendor}**: {'; '.join(r.errors)}")

        error_text = "\n".join(error_reasons)
        readable_output = f"The operation failed for all the integrations ({', '.join(params.brands)}).\n\n**Reason:**\n{error_text}\n\n---\n{readable_output}"

    return [
        CommandResults(
            readable_output=readable_output,
            outputs=outputs,
            raw_response=outputs,
            entry_type=EntryType.ERROR if all_failed else EntryType.NOTE,
        )
    ]


# ---------------------------------------------------------------------------------------------------------------------
# Polling entry point: every script run is ONE tick of the state machine
# ---------------------------------------------------------------------------------------------------------------------
class InvalidArgumentsError(DemistoException):
    """The script arguments are invalid (reported with ``return_error``)."""


def scheduled_timeout(state: dict[str, Any]) -> int:
    """The platform level timeout of the scheduled command: the remaining overall budget plus the cleanup grace period."""
    return max(int(state["deadline"] - time.time()), 0) + CLEANUP_GRACE_SECONDS


def failure_results(params: SearchParams, exc: Exception) -> list[CommandResults]:
    demisto.debug(f"Unexpected failure: {exc}\n{traceback.format_exc()}")
    failure = VendorResult(vendor="None", brand="", instance="", errors=[str(exc)])
    return build_command_results(params, [failure])


@polling_function(
    name=SCRIPT_NAME,
    interval=POLL_INTERVAL_SECONDS,
    timeout=DEFAULT_TIMEOUT_SECONDS + CLEANUP_GRACE_SECONDS,
    poll_message=POLL_MESSAGE,
    requires_polling_arg=False,
)
def search_and_delete_email_tick(args: dict[str, Any]) -> PollResult:
    """
    Advances the state machine by one step and returns either the final results or "run again in ``POLL_INTERVAL_SECONDS``".

    The state is carried in ``args_for_next_run["state"]`` (a JSON string) together with the original script arguments.
    NOTE: the script's own ``timeout`` argument (the overall budget) is never touched by the decorator, which only uses its
    static ``timeout`` for the scheduled command (it is replaced with a dynamic value by ``search_and_delete_email``).
    """
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
            return PollResult(response=build_command_results(params, results_from_state(state)))
        next_args = {**args, STATE_ARG: dump_state(state), SCHEDULED_TIMEOUT_ARG: scheduled_timeout(state)}
    except Exception as exc:  # Never crash and never poll forever: report the failure in HR and in the context.
        return PollResult(response=failure_results(params, exc))
    progress = CommandResults(readable_output="\n".join(f"* {message}" for message in messages)) if messages else None
    return PollResult(response=None, continue_to_poll=True, args_for_next_run=next_args, partial_result=progress)


def search_and_delete_email(args: dict[str, Any]) -> Any:
    """Runs one tick and gives the scheduled command a timeout that is longer than our own deadline (so the cleanup runs)."""
    response = search_and_delete_email_tick(args)
    scheduled = getattr(response, "scheduled_command", None)
    if not isinstance(response, CommandResults) or scheduled is None:
        return response
    config = scheduled.to_results()
    poll_args = config.get("PollingArgs") or {}
    timeout = arg_to_number(poll_args.get(SCHEDULED_TIMEOUT_ARG))
    if timeout:
        response.scheduled_command = ScheduledCommand(
            command=config["PollingCommand"],
            next_run_in_seconds=int(config["NextRun"]),
            args=poll_args,
            timeout_in_seconds=timeout,
        )
    return response


def main() -> None:  # pragma: no cover
    args = demisto.args()
    try:
        if not args.get(STATE_ARG):
            params = parse_args(args)
            if params.verify_deletion and params.delete:
                instances = resolve_instances(params.brands)
                if any(key == "msgraph_security" for key, _, _ in instances):
                    return_results(
                        CommandResults(
                            readable_output=VERIFY_UNSUPPORTED_WARNING,
                            entry_type=EntryType.WARNING,
                        )
                    )

        return_results(search_and_delete_email(args))
    except InvalidArgumentsError as exc:
        return_error(f"Invalid arguments: {exc}")
    except Exception as exc:
        demisto.debug(traceback.format_exc())
        return_error(f"Failed to run {SCRIPT_NAME}: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
