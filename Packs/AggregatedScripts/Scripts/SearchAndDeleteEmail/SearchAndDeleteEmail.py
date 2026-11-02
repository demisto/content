import re
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from typing import Any, TypeVar

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Search & Delete Email - aggregated command.

Searches for emails (and optionally deletes them) using one or more of the supported mail integrations and
normalizes the results of all vendors into the unified ``EmailData`` context path.

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
  purged and finally deleted. The case is reused between executions, the search is ALWAYS deleted at the end
  (also for "Search Only" and also on failure). Mailbox scoping for "Specific" is done through the KQL query
  (``recipients:``), which means that copies of the same email in other recipients' mailboxes may match as well.
  The API does not return per-email details, so only the totals are populated and attachments cannot be retrieved.
* Microsoft Graph Mail only works on explicitly named mailboxes and cannot hard delete.
* Searching thousands of mailboxes is resource heavy. All long running steps are polled with a high default
  timeout (``DEFAULT_TIMEOUT_SECONDS``) and every search is repeated after a deletion round until no more
  results are returned, so emails beyond a single page are not missed.
"""

T = TypeVar("T")

OPERATION_SEARCH_ONLY = "Search Only"
OPERATION_SEARCH_AND_DELETE = "Search & Delete"
DELETE_SOFT = "Soft Delete"
DELETE_HARD = "Hard Delete"
SCOPE_SPECIFIC = "Specific"
SCOPE_ALL = "All"
DEFAULT_TIME_FRAME = "1 hour"

DEFAULT_TIMEOUT_SECONDS = 3600  # Resource heavy searches (e.g. all tenant mailboxes) can take a long time.
POLL_INTERVAL_SECONDS = 10
MAX_ROUNDS = 10  # Max number of "search -> delete" rounds when the vendor returns capped result pages.
GMAIL_PAGE_SIZE = 500
GRAPH_MAIL_PAGE_SIZE = 50
GRAPH_MAIL_MAX_PAGES = 64
EWS_LIMIT_STEPS = (100, 500, 1000)
EWS_ENRICH_LIMIT = 50  # Max number of emails for which the full item (body, attachments) is fetched.
GRAPH_SECURITY_CASE_NAME = "XSOAR Auto Phishing"
GRAPH_SECURITY_SUCCESS_STATUSES = ("succeeded", "completed")
GRAPH_SECURITY_FAILED_STATUSES = ("failed", "partiallysucceeded", "cancelled")

# Property names used to search by Internet Message ID in each vendor query language.
GRAPH_SECURITY_MESSAGE_ID_FIELD = "InternetMessageId"
EWS_MESSAGE_ID_FIELD = "Message-ID"

COMMAND_TRACE: list[str] = []


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
    target_mailboxes: list[str]
    mailbox_scope: str
    brands: list[str]
    verbose: bool

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
    """Aggregated outcome of one vendor instance."""

    vendor: str
    brand: str
    instance: str
    emails: list[dict[str, Any]] = field(default_factory=list)
    total_found: int = 0
    total_deleted: int = 0
    total_failed: int = 0
    errors: list[str] = field(default_factory=list)
    file_entries: list[dict[str, Any]] = field(default_factory=list)
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


def poll(check: Callable[[], T | None], description: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> T:
    """
    Calls ``check`` every ``POLL_INTERVAL_SECONDS`` until it returns a value which is not ``None``.

    Raises a ``DemistoException`` when ``timeout`` seconds passed.
    """
    deadline = time.monotonic() + timeout
    while True:
        value = check()
        if value is not None:
            return value
        if time.monotonic() >= deadline:
            raise DemistoException(f"Timed out after {timeout} seconds while waiting for: {description}.")
        demisto.debug(f"Waiting for {description}...")
        time.sleep(POLL_INTERVAL_SECONDS)


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
    for _ in range(MAX_ROUNDS if params.delete else 1):
        emails, saturated = search()
        exhausted = False
        fresh = [email for email in emails if (",".join(email["Mailbox"]), email["ObjectID"]) not in seen]
        if not fresh:
            break
        for email in fresh:
            seen[(",".join(email["Mailbox"]), email["ObjectID"])] = email
            if params.retrieve_files and get_files and email.get("HasAttachments", bool(email["Attachments"])):
                try:
                    collect_files(get_files(email), email, result)
                except Exception as exc:  # a failing attachment must not block the deletion of the other emails
                    result.errors.append(f"Failed retrieving files of {email['ObjectID']}: {exc}")
            if params.delete:
                try:
                    delete(email)
                    email["Deleted"] = True
                    result.total_deleted += 1
                except Exception as exc:
                    email["Deleted"] = False
                    email["Reason"] = str(exc)
                    result.total_failed += 1
        if not saturated:
            break
        exhausted = True
    if exhausted:
        result.additional["Note"] = (
            "The vendor capped the number of returned emails, more matching emails may exist. "
            "Rerun the command to process the remaining emails."
        )
    result.emails = list(seen.values())
    result.total_found = len(seen)


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


def run_gmail(params: SearchParams, instance: str, result: VendorResult) -> None:
    def delete(email: dict[str, Any]) -> None:
        run_command(
            "gmail-delete-mail",
            {"user-id": email["Mailbox"][0], "message-id": email["ObjectID"], "permanent": str(params.hard_delete).lower()},
            instance,
        )

    def get_files(email: dict[str, Any]) -> list[dict[str, Any]]:
        return run_command("gmail-get-attachments", {"user-id": email["Mailbox"][0], "message-id": email["ObjectID"]}, instance)

    search_and_delete(params, result, lambda: gmail_search(params, instance), delete, get_files)


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


def run_graph_mail(params: SearchParams, instance: str, result: VendorResult) -> None:
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

    search_and_delete(params, result, lambda: graph_mail_search(params, instance), delete, get_files)


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


def graph_security_get_case_id(instance: str) -> str:
    """Reuses the eDiscovery case used by the playbooks (looked up by name) and creates it when missing."""
    results = run_command("msg-list-ediscovery-cases", {"all_results": "true"}, instance)
    for case in context_values(results, "MsGraph.eDiscoveryCase"):
        if isinstance(case, dict) and case.get("DisplayName") == GRAPH_SECURITY_CASE_NAME and case.get("CaseId"):
            return case["CaseId"]
    results = run_command("msg-create-ediscovery-case", {"display_name": GRAPH_SECURITY_CASE_NAME}, instance)
    case_id = find_in_results(results, "CaseId")
    if not case_id:
        raise VendorError("Could not determine the ID of the created eDiscovery case.")
    return case_id


def graph_security_estimate(case_id: str, search_id: str, instance: str) -> int:
    """Runs the estimate statistics operation, polls until it is done and returns the number of matching items."""
    run_command("msg-run-estimate-statistics", {"case_id": case_id, "search_id": search_id}, instance)

    def check() -> int | None:
        results = run_command(
            "msg-get-last-estimate-statistics-operation", {"case_id": case_id, "search_id": search_id}, instance
        )
        status = str(find_in_results(results, "Status") or "").lower()
        if status in GRAPH_SECURITY_FAILED_STATUSES:
            raise VendorError(f"The estimate statistics operation ended with status '{status}'.")
        if status in GRAPH_SECURITY_SUCCESS_STATUSES:
            return int(find_in_results(results, "TotalItemsCount") or 0)
        return None

    return poll(check, "the eDiscovery estimate statistics operation")


def graph_security_purge(params: SearchParams, case_id: str, search_id: str, instance: str) -> None:
    purge_type = "permanentlyDelete" if params.hard_delete else "recoverable"
    results = run_command(
        "msg-purge-ediscovery-data",
        {"case_id": case_id, "search_id": search_id, "purge_type": purge_type, "purge_areas": "mailboxes"},
        instance,
    )
    operation_id = find_in_results(results, "OperationID")
    if not operation_id:
        raise VendorError("Could not determine the ID of the purge operation.")

    def check() -> bool | None:
        operation = run_command("msg-list-case-operation", {"case_id": case_id, "operation_id": operation_id}, instance)
        status = str(find_in_results(operation, "Status") or "").lower()
        if status in GRAPH_SECURITY_FAILED_STATUSES:
            raise VendorError(f"The purge operation ended with status '{status}'.")
        return True if status in GRAPH_SECURITY_SUCCESS_STATUSES else None

    poll(check, "the eDiscovery purge operation")


def run_graph_security(params: SearchParams, instance: str, result: VendorResult) -> None:
    if params.object_id:
        raise UnsupportedError("Microsoft Graph Security does not support searching by object_id.")
    case_id = graph_security_get_case_id(instance)
    search_id = ""
    try:
        results = run_command(
            "msg-create-ediscovery-search",
            {
                "case_id": case_id,
                "display_name": f"XSOAR Search And Delete Email {datetime.now(UTC):%Y%m%d%H%M%S}",
                "content_query": build_graph_security_kql(params),
                "data_source_scopes": "allTenantMailboxes",
            },
            instance,
        )
        search_id = find_in_results(results, "SearchId") or ""
        if not search_id:
            raise VendorError("Could not determine the ID of the created eDiscovery search.")

        result.total_found = remaining = graph_security_estimate(case_id, search_id, instance)
        rounds = 0
        # A single purge removes a limited amount of items per mailbox, so purge and re-estimate until nothing is left.
        while params.delete and remaining > 0 and rounds < MAX_ROUNDS:
            graph_security_purge(params, case_id, search_id, instance)
            remaining = graph_security_estimate(case_id, search_id, instance)
            rounds += 1
        if params.delete:
            result.total_deleted = result.total_found - remaining
            result.total_failed = remaining
        if params.retrieve_files:
            result.additional["Note"] = "Microsoft Graph Security does not return email content, files were not retrieved."
    finally:
        if search_id:  # Cleanup is mandatory for both "Search Only" and "Search & Delete", even on failure.
            try:
                run_command("msg-delete-ediscovery-search", {"case_id": case_id, "search_id": search_id}, instance)
            except Exception as exc:
                result.errors.append(f"Failed deleting eDiscovery search {search_id}: {exc}")


# ---------------------------------------------------------------------------------------------------------------------
# EWS on-prem
# ---------------------------------------------------------------------------------------------------------------------
def build_ews_query(params: SearchParams) -> str:
    clauses: list[str] = []
    if params.internet_message_ids:
        ids = " OR ".join(f'{EWS_MESSAGE_ID_FIELD}:"{with_brackets(i)}"' for i in params.internet_message_ids)
        clauses.append(f"({ids})")
    else:
        if params.subjects:
            clauses.append("(" + " OR ".join(f'Subject:"{subject}"' for subject in params.subjects) + ")")
        if params.sender_address:
            clauses.append(f'From:"{params.sender_address}"')
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


def run_ews(params: SearchParams, instance: str, result: VendorResult) -> None:
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

    search_and_delete(params, result, search, delete, get_files)


# ---------------------------------------------------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class VendorSpec:
    display_name: str
    aliases: frozenset[str]  # normalized brand names (see normalize_name)
    runner: Callable[[SearchParams, str, VendorResult], None]


VENDORS: dict[str, VendorSpec] = {
    "gmail": VendorSpec("Gmail", frozenset({"gmail"}), run_gmail),
    "msgraph_mail": VendorSpec(
        "Microsoft Graph Mail", frozenset({"microsoftgraphmail", "msgraphmail", "o365outlookmailusinggraphapi"}), run_graph_mail
    ),
    "msgraph_security": VendorSpec(
        "Microsoft Graph Security", frozenset({"microsoftgraph", "microsoftgraphsecurity", "msgraphsecurity"}), run_graph_security
    ),
    "ews": VendorSpec("EWS on-prem", frozenset({"ewsv2", "ews", "ewsonprem"}), run_ews),
}


def resolve_instances(requested_brands: list[str]) -> list[tuple[str, str, str]]:
    """Returns ``(vendor key, brand, instance name)`` for every active instance of the requested (or all) brands."""
    wanted = {normalize_name(brand) for brand in requested_brands}
    known = set().union(*(spec.aliases for spec in VENDORS.values()))
    if unknown := sorted(brand for brand in requested_brands if normalize_name(brand) not in known):
        supported = ", ".join(spec.display_name for spec in VENDORS.values())
        raise DemistoException(f"Unsupported brand(s): {', '.join(unknown)}. Supported brands: {supported}.")

    instances: list[tuple[str, str, str]] = []
    for instance_name, data in (demisto.getModules() or {}).items():
        if data.get("state") != "active":
            continue
        brand = normalize_name(data.get("brand", ""))
        for key, spec in VENDORS.items():
            if brand in spec.aliases and (not wanted or brand in wanted):
                instances.append((key, data.get("brand", ""), instance_name))
    return instances


def run_vendor(params: SearchParams, vendor_key: str, brand: str, instance: str) -> VendorResult:
    """Runs one vendor instance. Never raises: errors are stored in the result together with whatever was collected."""
    result = VendorResult(vendor=VENDORS[vendor_key].display_name, brand=brand, instance=instance)
    try:
        VENDORS[vendor_key].runner(params, instance, result)
    except Exception as exc:
        demisto.debug(f"{result.vendor} ({instance}) failed: {exc}\n{traceback.format_exc()}")
        result.errors.append(str(exc))
    return result


def run_all(params: SearchParams) -> list[VendorResult]:
    instances = resolve_instances(params.brands)
    if params.object_id and len({key for key, _, _ in instances}) != 1:
        raise DemistoException("When object_id is specified, exactly one brand (with an enabled instance) must be selected.")
    if not instances:
        failure = VendorResult(vendor="None", brand="", instance="")
        failure.errors.append("No enabled instance was found for the requested brands.")
        return [failure]
    return [run_vendor(params, key, brand, instance) for key, brand, instance in instances]


# ---------------------------------------------------------------------------------------------------------------------
# Arguments and outputs
# ---------------------------------------------------------------------------------------------------------------------
def parse_args(args: dict[str, Any]) -> SearchParams:
    operation = args.get("operation") or ""
    if operation not in (OPERATION_SEARCH_ONLY, OPERATION_SEARCH_AND_DELETE):
        raise DemistoException(f"operation must be '{OPERATION_SEARCH_ONLY}' or '{OPERATION_SEARCH_AND_DELETE}'.")
    delete_type = args.get("delete_type") or DELETE_SOFT
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
    if scope == SCOPE_SPECIFIC and not target_mailboxes:
        raise DemistoException("target_mailbox must be specified when mailbox_scope is 'Specific'.")
    if object_id and (not target_mailboxes or len(brands) != 1 or scope == SCOPE_ALL):
        raise DemistoException(
            "When object_id is specified, a single target_mailbox (scope 'Specific') and a brand are required."
        )

    time_frame = args.get("time_frame") or DEFAULT_TIME_FRAME
    since = datetime.now(UTC) - parse_time_frame(time_frame)
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
        target_mailboxes=target_mailboxes,
        mailbox_scope=scope,
        brands=brands,
        verbose=argToBoolean(args.get("verbose") or False),
    )


def build_context(params: SearchParams, results: list[VendorResult]) -> list[dict[str, Any]]:
    """Builds the unified ``EmailData`` entries: one per email, plus a summary entry per vendor with no emails or errors."""
    entries: list[dict[str, Any]] = []
    for result in results:
        base = {
            "Brand": result.brand or result.vendor,
            "Operation": params.operation,
            "TotalFound": result.total_found,
            "TotalDeleted": result.total_deleted,
            "TotalFailed": result.total_failed,
        }
        for email in result.emails:
            entries.append(
                {
                    **base,
                    "Mailbox": email["Mailbox"],
                    "Subject": email["Subject"],
                    "From": email["From"],
                    "To": email["To"],
                    "CC": email["CC"],
                    "BCC": email["BCC"],
                    "HTMLBody": email["HTMLBody"],
                    "Timestamp": email["Timestamp"],
                    "Attachments": email["Attachments"],
                    "Success": email.get("Deleted", True),
                    "Reason": email.get("Reason", ""),
                    "AdditionalFields": {
                        "ObjectID": email["ObjectID"],
                        "InternetMessageID": email["InternetMessageID"],
                        "Instance": result.instance,
                    },
                }
            )
        if not result.emails or result.errors:
            entries.append(
                {
                    **base,
                    "Mailbox": params.target_mailboxes,
                    "Success": result.success,
                    "Reason": "; ".join(result.errors),
                    "AdditionalFields": {"Instance": result.instance, **result.additional},
                }
            )
    return entries


def build_human_readable(params: SearchParams, results: list[VendorResult]) -> str:
    summary = [
        {
            "Brand": r.brand or r.vendor,
            "Instance": r.instance,
            "Status": "Success" if r.success else "Failed",
            "Found": r.total_found,
            "Deleted": r.total_deleted,
            "Failed": r.total_failed,
            "Reason": "; ".join(r.errors),
        }
        for r in results
    ]
    title = f"Search & Delete Email - {params.operation}"
    if all(result.errors for result in results):
        title += " - ALL VENDORS FAILED"
    hr = tableToMarkdown(title, summary, headers=["Brand", "Instance", "Status", "Found", "Deleted", "Failed", "Reason"])
    emails = [
        {
            "Brand": r.brand,
            "Mailbox": ", ".join(e["Mailbox"]),
            "Subject": e["Subject"],
            "From": e["From"],
            "Timestamp": e["Timestamp"],
            "Deleted": e.get("Deleted", "N/A"),
            "Reason": e.get("Reason", ""),
        }
        for r in results
        for e in r.emails
    ]
    if emails:
        hr += tableToMarkdown("Emails", emails[: None if params.verbose else 50], removeNull=True)
    if params.verbose:
        hr += "\n#### Executed commands\n" + "\n".join(f"* `{line}`" for line in COMMAND_TRACE)
    return hr


def main() -> None:  # pragma: no cover
    try:
        params = parse_args(demisto.args())
    except Exception as exc:
        return_error(f"Invalid arguments: {exc}")
        return
    try:
        results = run_all(params)
        for result in results:
            for entry in result.file_entries:
                return_results(entry)
        return_results(
            CommandResults(
                outputs_prefix="EmailData",
                outputs=build_context(params, results),
                readable_output=build_human_readable(params, results),
            )
        )
    except Exception as exc:  # Never crash: report the failure in HR and in the context.
        demisto.debug(traceback.format_exc())
        failure = VendorResult(vendor="None", brand="", instance="", errors=[str(exc)])
        return_results(
            CommandResults(
                outputs_prefix="EmailData",
                outputs=build_context(params, [failure]),
                readable_output=build_human_readable(params, [failure]),
            )
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
