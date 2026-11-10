import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, UTC
from types import SimpleNamespace
from typing import Any

import demistomock as demisto
import pytest
import SearchAndDeleteEmail as module
from CommonServerPython import entryTypes
from SearchAndDeleteEmail import (
    DELETE_HARD,
    DELETE_SOFT,
    OPERATION_SEARCH_AND_DELETE,
    OPERATION_SEARCH_ONLY,
    SCOPE_ALL,
    SCOPE_SPECIFIC,
    SearchParams,
)


def make_params(**overrides: Any) -> SearchParams:
    values: dict[str, Any] = {
        "internet_message_ids": [],
        "object_id": "",
        "operation": OPERATION_SEARCH_AND_DELETE,
        "delete_type": DELETE_SOFT,
        "time_frame": "1 hour",
        "since": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        "subjects": ["Invoice"],
        "sender_address": "",
        "retrieve_files": False,
        "verify_deletion": False,
        "target_mailboxes": ["a@example.com"],
        "mailbox_scope": SCOPE_SPECIFIC,
        "brands": [],
        "verbose": False,
        "timeout": module.DEFAULT_TIMEOUT_SECONDS,
    }
    values.update(overrides)
    return SearchParams(**values)


def entry(context: dict[str, Any], entry_type: int = 1) -> dict[str, Any]:
    return {"Type": entry_type, "Contents": "", "ContentsFormat": "json", "EntryContext": context}


def error_entry(message: str = "boom") -> dict[str, Any]:
    return {"Type": entryTypes["error"], "Contents": message, "ContentsFormat": "text"}


class FakeCommands:
    """Dispatches ``demisto.executeCommand`` calls to canned responses and records the calls."""

    def __init__(self, responses: dict[str, Any]):
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, command: str, args: dict[str, Any]) -> Any:
        self.calls.append((command, args))
        response = self.responses.get(command, [])
        return response(args) if callable(response) else response

    def called(self, command: str) -> list[dict[str, Any]]:
        return [args for name, args in self.calls if name == command]


START_EPOCH = 1_700_000_000.0


class Clock:
    """A fake ``time.time`` that only moves when a test advances it."""

    def __init__(self) -> None:
        self.now = START_EPOCH

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


CLOCK = Clock()
PUBLISHED: list[Any] = []  # everything the script published with return_results (e.g. the retrieved file entries)


def forbidden_sleep(*args: Any, **kwargs: Any) -> None:
    raise AssertionError("SearchAndDeleteEmail must never sleep or block: time.sleep was called")


@pytest.fixture(autouse=True)
def environment(mocker):
    """Any call to ``time.sleep`` fails the test, the clock is fake and the platform bits of the polling decorator are mocked."""
    mocker.patch("time.sleep", side_effect=forbidden_sleep)
    CLOCK.now = START_EPOCH
    mocker.patch.object(module, "time", SimpleNamespace(time=CLOCK, sleep=forbidden_sleep))
    mocker.patch.object(module.ScheduledCommand, "raise_error_if_not_supported")  # the server version check
    PUBLISHED.clear()
    mocker.patch.object(module, "return_results", side_effect=PUBLISHED.append)
    module.COMMAND_TRACE.clear()
    mocker.patch.object(module, "_DEADLINE", None)  # no time limit unless a tick sets it
    mocker.patch.object(module, "_TIMEOUT_SECONDS", module.DEFAULT_TIMEOUT_SECONDS)


def setup_demisto(mocker, modules: dict[str, str], responses: dict[str, Any]) -> FakeCommands:
    mocker.patch.object(
        demisto, "getModules", return_value={name: {"brand": brand, "state": "active"} for name, brand in modules.items()}
    )
    fake = FakeCommands(responses)
    mocker.patch.object(demisto, "executeCommand", side_effect=fake)
    return fake


@dataclass
class Run:
    """The outcome of driving the state machine to completion."""

    state: dict[str, Any]
    stages: list[list[str]]  # the stage of every vendor before the first tick and after each tick
    messages: list[list[str]]  # the progress messages of each tick

    @property
    def ticks(self) -> int:
        return len(self.messages)

    @property
    def results(self) -> list[module.VendorResult]:
        return module.results_from_state(self.state)

    def visited(self, index: int = 0) -> list[str]:
        """The stages of one vendor in order: the initial one followed by the stage it reached after every tick."""
        return [stages[index] for stages in self.stages]


def drive(params: SearchParams, state: dict[str, Any] | None = None, max_ticks: int = 100, on_tick: Any = None) -> Run:
    """
    Runs the script tick by tick until every vendor is done.

    The state goes through a JSON round trip after every tick (as it does between two scheduled runs), the verbose command
    trace is dropped from the process and restored from the state, and the fake clock moves by the poll interval.
    """
    state = json.loads(json.dumps(state if state is not None else module.new_state(params)))
    stages = [[vendor["stage"] for vendor in state["vendors"]]]
    messages: list[list[str]] = []
    for tick in range(1, max_ticks + 1):
        if tick > 1:
            module.COMMAND_TRACE.clear()  # a new process: the trace is restored from the state
        state, done, tick_messages = module.run_tick(params, state)
        state = json.loads(json.dumps(state))
        stages.append([vendor["stage"] for vendor in state["vendors"]])
        messages.append(tick_messages)
        if on_tick:
            on_tick(tick, state)
        if done:
            return Run(state, stages, messages)
        CLOCK.advance(module.POLL_INTERVAL_SECONDS)
    raise AssertionError(f"The state machine did not finish within {max_ticks} ticks: {stages[-1]}")


def single_vendor_state(params: SearchParams, key: str, brand: str, instance: str) -> dict[str, Any]:
    return {
        "version": module.STATE_VERSION,
        "deadline": CLOCK.now + params.timeout,
        "since": params.since.isoformat(),
        "command_trace": [],
        "vendors": [module.new_vendor_state(key, brand, instance)],
    }


def drive_vendor(params: SearchParams, key: str, brand: str, instance: str, **kwargs: Any) -> Run:
    return drive(params, single_vendor_state(params, key, brand, instance), **kwargs)


def run_vendor(params: SearchParams, key: str, brand: str, instance: str) -> module.VendorResult:
    return drive_vendor(params, key, brand, instance).results[0]


def run_all(params: SearchParams) -> list[module.VendorResult]:
    return drive(params).results


# Helpers to access unified output structures
def get_outputs(params: SearchParams, results: list[module.VendorResult]) -> dict[str, Any]:
    return module.build_command_results(params, results)[0].outputs


def get_email_data(params: SearchParams, results: list[module.VendorResult]) -> list[dict[str, Any]]:
    return get_outputs(params, results)["EmailData"]


def get_hr(params: SearchParams, results: list[module.VendorResult]) -> str:
    return module.build_command_results(params, results)[0].readable_output


# ----------------------------------------------------------------------------------------------------------------------
# Helpers / argument parsing
# ----------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value, expected",
    [
        ("30 minutes", timedelta(minutes=30)),
        ("3 hours", timedelta(hours=3)),
        ("1 hour", timedelta(hours=1)),
        ("7 days", timedelta(days=7)),
        ("2 weeks", timedelta(weeks=2)),
    ],
)
def test_parse_time_frame(value, expected):
    assert module.parse_time_frame(value) == expected


@pytest.mark.parametrize("value", ["", "soon", "-1 days", "0 hours", "7"])
def test_parse_time_frame_invalid(value):
    with pytest.raises(module.DemistoException):
        module.parse_time_frame(value)


def test_parse_args_defaults():
    params = module.parse_args({"operation": OPERATION_SEARCH_ONLY, "subject": "Invoice", "target_mailbox": "a@example.com"})
    assert params.delete_type == DELETE_SOFT
    assert params.mailbox_scope == SCOPE_SPECIFIC
    assert params.time_frame == "1 hour"
    assert not params.retrieve_files
    assert not params.verify_deletion
    assert not params.delete
    assert (datetime.now(UTC) - params.since).total_seconds() == pytest.approx(3600, abs=5)


@pytest.mark.parametrize("value, expected", [("true", True), ("false", False), (None, False), ("", False)])
def test_parse_args_verify_deletion(value, expected):
    args = {"operation": OPERATION_SEARCH_AND_DELETE, "subject": "Invoice", "target_mailbox": "a@example.com"}
    if value is not None:
        args["verify_deletion"] = value
    assert module.parse_args(args).verify_deletion is expected


@pytest.mark.parametrize(
    "args",
    [
        {"operation": "Delete", "subject": "s", "target_mailbox": "a@example.com"},
        {"operation": OPERATION_SEARCH_ONLY, "subject": "s", "target_mailbox": "a@example.com", "delete_type": "Maybe"},
        {"operation": OPERATION_SEARCH_ONLY, "subject": "s", "target_mailbox": "a@example.com", "mailbox_scope": "Some"},
        # An empty filter would match every email in the time frame.
        {"operation": OPERATION_SEARCH_AND_DELETE, "target_mailbox": "a@example.com"},
        {"operation": OPERATION_SEARCH_ONLY, "subject": "s"},
        # object_id requires a mailbox and exactly one brand.
        {"operation": OPERATION_SEARCH_ONLY, "object_id": "1", "target_mailbox": "a@example.com"},
        {"operation": OPERATION_SEARCH_ONLY, "object_id": "1", "brands": "Gmail"},
    ],
)
def test_parse_args_invalid(args):
    with pytest.raises(module.DemistoException):
        module.parse_args(args)


def test_parse_args_all_mailboxes_does_not_require_target_mailbox():
    params = module.parse_args({"operation": OPERATION_SEARCH_ONLY, "subject": "s", "mailbox_scope": SCOPE_ALL})
    assert params.all_mailboxes


def test_module_has_no_blocking_poll_and_nothing_sleeps():
    assert not hasattr(module, "poll")
    assert not hasattr(module, "start_budget")
    with pytest.raises(AssertionError, match="must never sleep"):
        time.sleep(0)


# ----------------------------------------------------------------------------------------------------------------------
# Query builders
# ----------------------------------------------------------------------------------------------------------------------
def test_gmail_query_prefers_message_id():
    query = module.build_gmail_query(make_params(internet_message_ids=["<abc@x>"], subjects=["Invoice"]))
    assert "rfc822msgid:abc@x" in query
    assert "subject" not in query
    assert f"after:{int(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC).timestamp())}" in query


def test_gmail_query_subject_and_sender():
    query = module.build_gmail_query(make_params(sender_address="bad@evil.com"))
    assert 'subject:"Invoice"' in query
    assert "from:bad@evil.com" in query


def test_graph_mail_filter_escapes_quotes():
    assert "contains(subject,'It''s')" in module.build_graph_mail_filter(make_params(subjects=["It's"]))


def test_graph_security_kql_scopes_to_recipients():
    kql = module.build_graph_security_kql(make_params(sender_address="bad@evil.com"))
    assert "recipients:a@example.com" in kql
    assert "from:bad@evil.com" in kql
    assert "received>=2026-01-02" in kql
    assert "recipients:" not in module.build_graph_security_kql(make_params(mailbox_scope=SCOPE_ALL))


def test_ews_query_uses_message_id_with_brackets():
    query = module.build_ews_query(make_params(internet_message_ids=["abc@x"]))
    assert 'Message-ID:"<abc@x>"' in query
    assert "Subject" not in query
    # Shouldn't wrap with parenthesis for a single item
    assert '("Message-ID' not in query


def test_ews_query_escapes_quotes_and_wraps_in_parens_if_multiple():
    query = module.build_ews_query(make_params(subjects=["sub1", 'su"b2']))
    assert '(Subject:"sub1" OR Subject:"su\\"b2")' in query
    
    query_single = module.build_ews_query(make_params(subjects=["sub1"]))
    assert 'Subject:"sub1"' in query_single
    assert '(Subject' not in query_single


# ----------------------------------------------------------------------------------------------------------------------
# Routing
# ----------------------------------------------------------------------------------------------------------------------
def test_resolve_instances_filters_by_brand(mocker):
    setup_demisto(mocker, {"gmail_1": "Gmail", "ews_1": "EWS v2", "other": "Splunk"}, {})
    assert module.resolve_instances([]) == [("gmail", "Gmail", "gmail_1"), ("ews", "EWS v2", "ews_1")]
    assert module.resolve_instances(["EWS v2"]) == [("ews", "EWS v2", "ews_1")]


def test_resolve_instances_unknown_brand(mocker):
    setup_demisto(mocker, {}, {})
    with pytest.raises(module.DemistoException, match="Unsupported brand"):
        module.resolve_instances(["Splunk"])


# Real brand (`name` in the integration yml, as reported by demisto.getModules) and display name of each vendor.
ALL_BRAND_MODULES = {
    "Gmail_instance": "Gmail",
    "MSGraphMail_instance": "MicrosoftGraphMail",
    "MSGraphSecurity_instance": "Microsoft Graph",
    "EWS_instance": "EWS v2",
    "Splunk_instance": "Splunk",
}
VENDOR_BRAND_CASES = [
    # (vendor key, instance name, real brand, requested brands that must all resolve to that vendor)
    ("gmail", "Gmail_instance", "Gmail", ["Gmail", "gmail"]),
    (
        "msgraph_mail",
        "MSGraphMail_instance",
        "MicrosoftGraphMail",
        ["MicrosoftGraphMail", "O365 Outlook Mail (Using Graph API)", "msgraphmail", "MS Graph Mail"],
    ),
    (
        "msgraph_security",
        "MSGraphSecurity_instance",
        "Microsoft Graph",
        ["Microsoft Graph", "Microsoft Graph Security", "msgraphsecurity"],
    ),
    ("ews", "EWS_instance", "EWS v2", ["EWS v2", "EWS", "ews on-prem", "ewsv2"]),
]


def test_resolve_instances_msgraph_mail_by_display_name_matches_instance_brand(mocker):
    """Regression: the display name offered in the `brands` argument must match an instance whose brand is the `name`."""
    mocker.patch.object(
        demisto, "getModules", return_value={"MSGraphMail_instance": {"brand": "MicrosoftGraphMail", "state": "active"}}
    )
    assert module.resolve_instances(["O365 Outlook Mail (Using Graph API)"]) == [
        ("msgraph_mail", "MicrosoftGraphMail", "MSGraphMail_instance")
    ]


@pytest.mark.parametrize(
    "vendor_key, instance_name, real_brand, requested_brand",
    [
        (key, instance, brand, requested)
        for key, instance, brand, requested_list in VENDOR_BRAND_CASES
        for requested in requested_list
    ],
)
def test_resolve_instances_each_vendor_by_name_display_name_and_alias(
    mocker, vendor_key, instance_name, real_brand, requested_brand
):
    setup_demisto(mocker, ALL_BRAND_MODULES, {})
    assert module.resolve_instances([requested_brand]) == [(vendor_key, real_brand, instance_name)]


def test_resolve_instances_two_brands_return_only_those_vendors(mocker):
    setup_demisto(mocker, ALL_BRAND_MODULES, {})
    assert module.resolve_instances(["O365 Outlook Mail (Using Graph API)", "EWS v2"]) == [
        ("msgraph_mail", "MicrosoftGraphMail", "MSGraphMail_instance"),
        ("ews", "EWS v2", "EWS_instance"),
    ]


def test_resolve_instances_empty_brands_return_all_vendors(mocker):
    setup_demisto(mocker, ALL_BRAND_MODULES, {})
    assert module.resolve_instances([]) == [
        ("gmail", "Gmail", "Gmail_instance"),
        ("msgraph_mail", "MicrosoftGraphMail", "MSGraphMail_instance"),
        ("msgraph_security", "Microsoft Graph", "MSGraphSecurity_instance"),
        ("ews", "EWS v2", "EWS_instance"),
    ]


def test_resolve_instances_unsupported_brand_alongside_supported_raises(mocker):
    setup_demisto(mocker, ALL_BRAND_MODULES, {})
    with pytest.raises(module.DemistoException, match="Unsupported brand.*Splunk.*Supported brands: Gmail, Microsoft Graph Mail"):
        module.resolve_instances(["Gmail", "Splunk"])


def test_resolve_instances_ignores_inactive_instances(mocker):
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "MSGraphMail_off": {"brand": "MicrosoftGraphMail", "state": "disabled"},
            "MSGraphMail_on": {"brand": "MicrosoftGraphMail", "state": "active"},
        },
    )
    assert module.resolve_instances(["O365 Outlook Mail (Using Graph API)"]) == [
        ("msgraph_mail", "MicrosoftGraphMail", "MSGraphMail_on")
    ]


def test_new_state_object_id_counts_distinct_vendors_with_multiple_instances(mocker):
    """Two instances of the same vendor still count as one vendor for the object_id guard."""
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "MSGraphMail_1": {"brand": "MicrosoftGraphMail", "state": "active"},
            "MSGraphMail_2": {"brand": "MicrosoftGraphMail", "state": "active"},
        },
    )
    params = make_params(brands=["O365 Outlook Mail (Using Graph API)"], object_id="obj-1")
    state = module.new_state(params)
    assert [(vendor["key"], vendor["instance"]) for vendor in state["vendors"]] == [
        ("msgraph_mail", "MSGraphMail_1"),
        ("msgraph_mail", "MSGraphMail_2"),
    ]


def test_new_state_object_id_requires_exactly_one_vendor(mocker):
    setup_demisto(mocker, ALL_BRAND_MODULES, {})
    with pytest.raises(module.DemistoException, match="exactly one brand"):
        module.new_state(make_params(brands=["Gmail", "EWS v2"], object_id="obj-1"))


# ----------------------------------------------------------------------------------------------------------------------
# Gmail
# ----------------------------------------------------------------------------------------------------------------------
GMAIL_ITEM = {
    "ID": "m1",
    "Mailbox": "a@example.com",
    "Subject": "Invoice",
    "From": "bad@evil.com",
    "To": "a@example.com",
    "Headers": [{"Name": "Date", "Value": "Mon, 2 Jan 2026 03:04:05 +0000"}],
    "Body": "<b>hi</b>",
    "Attachments": [{"ID": "att", "Name": "a.txt"}],
}


def test_gmail_search_and_delete_with_files(mocker):
    fake = setup_demisto(
        mocker,
        {"Gmail": "Gmail"},
        {
            "gmail-search": [entry({"Gmail(val.ID && val.ID == obj.ID)": [GMAIL_ITEM]})],
            "gmail-get-attachments": [
                entry({"File(val.SHA1 == obj.SHA1)": [{"Name": "a.txt", "SHA256": "abc"}]}, entry_type=entryTypes["file"])
            ],
        },
    )
    result = run_vendor(make_params(retrieve_files=True, delete_type=DELETE_HARD), "gmail", "Gmail", "Gmail")
    assert result.success
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)
    assert result.emails[0]["Attachments"] == {"a.txt": "abc"}
    assert len(PUBLISHED) == 1  # the file entry is published in the tick that retrieved it ...
    assert PUBLISHED[0]["Type"] == entryTypes["file"]
    assert result.file_entries == []  # ... and is never carried in the state
    assert fake.called("gmail-delete-mail")[0]["permanent"] == "true"
    # files must be fetched before the email is deleted
    order = [name for name, _ in fake.calls]
    assert order.index("gmail-get-attachments") < order.index("gmail-delete-mail")


def test_gmail_search_only_does_not_delete(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": [entry({"Gmail": [GMAIL_ITEM]})]})
    result = run_vendor(make_params(operation=OPERATION_SEARCH_ONLY), "gmail", "Gmail", "Gmail")
    assert result.total_found == 1
    assert result.total_deleted == 0
    assert not fake.called("gmail-delete-mail")


def test_gmail_all_mailboxes_follows_page_tokens(mocker):
    pages = iter(
        [
            [entry({"Gmail": [GMAIL_ITEM], "PageToken": {"NextPageToken": "t2"}})],
            [entry({"Gmail": [{**GMAIL_ITEM, "ID": "m2"}]})],
        ]
    )
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search-all-mailboxes": lambda args: next(pages)})
    result = run_vendor(make_params(mailbox_scope=SCOPE_ALL, operation=OPERATION_SEARCH_ONLY), "gmail", "Gmail", "Gmail")
    assert result.total_found == 2
    assert [c.get("page-token") for c in fake.called("gmail-search-all-mailboxes")] == [None, "t2"]


def test_delete_failure_is_reported_per_email(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail"},
        {"gmail-search": [entry({"Gmail": [GMAIL_ITEM]})], "gmail-delete-mail": [error_entry("denied")]},
    )
    result = run_vendor(make_params(), "gmail", "Gmail", "Gmail")
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 0, 1)
    assert "denied" in result.emails[0]["Reason"]
    assert not result.success


# ----------------------------------------------------------------------------------------------------------------------
# Microsoft Graph Mail
# ----------------------------------------------------------------------------------------------------------------------
def test_graph_mail_all_mailboxes_is_unsupported(mocker):
    setup_demisto(mocker, {"GraphMail": "O365 Outlook Mail (Using Graph API)"}, {})
    result = run_vendor(make_params(mailbox_scope=SCOPE_ALL), "msgraph_mail", "O365", "GraphMail")
    assert not result.success
    assert "can not search all mailboxes" in result.errors[0]


def test_graph_mail_retrieves_files_and_deletes(mocker):
    item = {"ID": "g1", "UserID": "a@example.com", "Subject": "Invoice", "HasAttachments": True, "ReceivedTime": "t"}
    fake = setup_demisto(
        mocker,
        {"GraphMail": "O365 Outlook Mail (Using Graph API)"},
        {
            "msgraph-mail-list-emails": [entry({"MSGraphMail(val.ID == obj.ID)": [item]})],
            "msgraph-mail-get-attachment": [entry({"File": {"Name": "doc.pdf", "SHA256": "h"}}, entry_type=entryTypes["file"])],
        },
    )
    result = run_vendor(make_params(retrieve_files=True), "msgraph_mail", "O365", "GraphMail")
    assert result.emails[0]["Attachments"] == {"doc.pdf": "h"}
    assert result.total_deleted == 1
    assert fake.called("msgraph-mail-delete-email")[0]["message_id"] == "g1"


# ----------------------------------------------------------------------------------------------------------------------
# Microsoft Graph Security
# ----------------------------------------------------------------------------------------------------------------------
GS = ("msgraph_security", "Microsoft Graph", "MsGraph")
GS_MODULES = {"MsGraph": "Microsoft Graph"}
GS_DELETE_COMMANDS = ("msg-delete-ediscovery-search", "msg-delete-ediscovery-case")


def status_responder(statuses: list[Any], build: Any) -> Any:
    """Answers call N with ``build(statuses[N])`` (the last status is repeated)."""
    calls = {"n": 0}

    def respond(args: dict[str, Any]) -> Any:
        status = statuses[min(calls["n"], len(statuses) - 1)]
        calls["n"] += 1
        return build(status)

    return respond


# The exact context key of msg-get-last-estimate-statistics-operation (outputs_prefix + outputs_key_field="id").
ESTIMATE_CONTEXT_KEY = "MsGraph.eDiscovery.EstimateStatistics(val.id && val.id == obj.id)"


def running_estimate_entry(status: str = "running") -> dict[str, Any]:
    """
    The integration's entry for every non-success status: human readable only, no context.

    Mirrors ``_get_last_estimate_statistics_command``, which lower-cases the Graph status before formatting the text.
    """
    return {
        "Type": entryTypes["note"],
        "Contents": "",
        "ContentsFormat": "markdown",
        "HumanReadable": f"Estimate statistics operation is still running... (Status: {status.lower()})",
    }


def estimate_entry(item: Any) -> list[dict[str, Any]]:
    """
    The real shape of msg-get-last-estimate-statistics-operation.

    ``int`` = a finished estimate with that many items (raw Graph object in the context), a success status ``str``
    (``succeeded`` / ``completed``) = a finished estimate without a count, any other ``str`` (``running``, ``failed``,
    ``submissionFailed`` ...) = the integration's context-free entry with ``(Status: <status>)`` in the human readable.
    """
    if isinstance(item, int):
        return [entry({ESTIMATE_CONTEXT_KEY: {"id": "op", "status": "succeeded", "totalItemCount": item}})]
    if item.lower() in module.GRAPH_SECURITY_SUCCESS_STATUSES:
        return [entry({ESTIMATE_CONTEXT_KEY: {"id": "op", "status": item}})]
    return [running_estimate_entry(item)]


def graph_security_responses(estimates: list[Any], purge_status: Any = "succeeded") -> dict[str, Any]:
    """``estimates``: one item per estimate poll (see ``estimate_entry``); ``purge_status``: a status or a list of statuses."""
    purge_statuses = purge_status if isinstance(purge_status, list) else [purge_status]
    return {
        "msg-create-ediscovery-case": [entry({"MsGraph.eDiscoveryCase": {"CaseId": "case1"}})],
        "msg-create-ediscovery-search": [entry({"MsGraph.eDiscoverySearch": {"SearchId": "search1"}})],
        "msg-run-estimate-statistics": [entry({})],
        "msg-get-last-estimate-statistics-operation": status_responder(estimates, estimate_entry),
        "msg-purge-ediscovery-data": [entry({"MsGraph.eDiscoveryCase.Purge": {"OperationID": "op1", "Status": "running"}})],
        "msg-list-case-operation": status_responder(
            purge_statuses, lambda status: [entry({"MsGraph.eDiscoveryCase.Operation": {"ID": "op1", "Status": status}})]
        ),
        "msg-delete-ediscovery-search": [entry({})],
        "msg-delete-ediscovery-case": [entry({})],
    }


def delete_order(fake: FakeCommands) -> list[str]:
    return [name for name, _ in fake.calls if name in GS_DELETE_COMMANDS]


def assert_cleanup_last(fake: FakeCommands) -> None:
    """The search and then the case were deleted exactly once each, and nothing was executed after them."""
    assert delete_order(fake) == list(GS_DELETE_COMMANDS)
    assert [name for name, _ in fake.calls[-2:]] == list(GS_DELETE_COMMANDS)
    assert fake.called("msg-delete-ediscovery-search") == [{"case_id": "case1", "search_id": "search1", "using": "MsGraph"}]
    assert fake.called("msg-delete-ediscovery-case") == [{"case_id": "case1", "using": "MsGraph"}]


def test_graph_security_search_purge_and_cleanup(mocker):
    fake = setup_demisto(mocker, GS_MODULES, graph_security_responses([3, 0]))
    result = run_vendor(make_params(delete_type=DELETE_HARD), *GS)
    assert result.success
    assert (result.total_found, result.total_deleted, result.total_failed) == (3, 3, 0)
    assert fake.called("msg-purge-ediscovery-data")[0]["purge_type"] == "permanentlyDelete"
    assert_cleanup_last(fake)


def test_graph_security_search_only_stages_and_cleanup_without_purge(mocker):
    """Search Only: the estimate IS polled to completion, its count is reported, then straight to cleanup (no purge)."""
    fake = setup_demisto(mocker, GS_MODULES, graph_security_responses(["running", "running", 3]))
    params = make_params(operation=OPERATION_SEARCH_ONLY)
    run = drive_vendor(params, *GS)
    assert run.visited() == [
        "create",
        "estimate_start",
        "estimate_wait",  # entered after the estimate was started
        "estimate_wait",  # still running
        "estimate_wait",  # still running
        "cleanup",  # the third poll returned the count
        "done",
    ]
    result = run.results[0]
    assert result.aggregate
    assert (result.total_found, result.total_deleted, result.total_failed) == (3, 0, 0)
    assert len(fake.called("msg-run-estimate-statistics")) == 1
    assert len(fake.called("msg-get-last-estimate-statistics-operation")) == 3
    assert not fake.called("msg-purge-ediscovery-data")
    assert not fake.called("msg-list-ediscovery-cases")
    assert_cleanup_last(fake)
    
    outputs = get_outputs(params, run.results)
    assert outputs["TotalFound"] == 3
    assert outputs["EmailData"][0]["AdditionalFields"]["Aggregate"] is True
    
    hr = get_hr(params, run.results)
    assert hr.startswith("|Brand|Mailbox|ID|Subject|From|To|Timestamp|Operation|Success|Reason|")
    # Table should be empty for MS Graph since it's an aggregate result
    assert "Microsoft Graph" not in hr 
    assert "**Total found:** 3" in hr
    
    announced = [m for tick in run.messages for m in tick]
    assert announced.count("Microsoft Graph Security: estimate running") == 1


@pytest.mark.parametrize("purge_status", ["failed", "partiallySucceeded", "submissionFailed"])
def test_graph_security_cleans_up_when_purge_fails(mocker, purge_status):
    fake = setup_demisto(mocker, GS_MODULES, graph_security_responses([3], purge_status=purge_status))
    run = drive_vendor(make_params(), *GS, max_ticks=15)
    result = run.results[0]
    assert not result.success
    assert f"purge operation ended with status '{purge_status.lower()}'" in result.errors[0]
    assert run.visited()[-3:] == ["purge_wait", "cleanup", "done"]
    assert len(fake.called("msg-list-case-operation")) == 1
    assert_cleanup_last(fake)


def test_graph_security_uses_a_dedicated_unique_case_and_never_lists_cases(mocker):
    fake = setup_demisto(mocker, GS_MODULES, graph_security_responses([0]))
    names = []
    for _ in range(2):
        run_vendor(make_params(operation=OPERATION_SEARCH_ONLY), *GS)
        names.append(fake.called("msg-create-ediscovery-case")[-1]["display_name"])
    assert not fake.called("msg-list-ediscovery-cases")
    assert all(name.startswith(module.GRAPH_SECURITY_CASE_PREFIX + " ") for name in names)
    assert module.GRAPH_SECURITY_CASE_PREFIX == "XSOAR Search And Delete Email"
    assert names[0] != names[1]
    assert fake.called("msg-create-ediscovery-search")[0]["case_id"] == "case1"


# ----------------------------------------------------------------------------------------------------------------------
# EWS
# ----------------------------------------------------------------------------------------------------------------------
def test_ews_search_enrich_and_hard_delete(mocker):
    found = {"itemId": "i1", "mailbox": "a@example.com", "subject": "Invoice", "sender": "bad@evil.com"}
    full = {
        **found,
        "body": "<p>x</p>",
        "hasAttachments": True,
        "FileAttachments": [{"attachmentName": "a.txt", "attachmentSHA256": "s"}],
    }
    fake = setup_demisto(
        mocker,
        {"EWS": "EWS v2"},
        {
            "ews-search-mailboxes": [entry({"EWS.Items(val.itemId == obj.itemId)": [found]})],
            "ews-get-items": [entry({"EWS.Items(val.itemId == obj.itemId)": [full]})],
            "ews-get-attachment": [entry({"File": {"Name": "a.txt", "SHA256": "s"}}, entry_type=entryTypes["file"])],
        },
    )
    result = run_vendor(
        make_params(delete_type=DELETE_HARD, retrieve_files=True, sender_address="bad@evil.com"), "ews", "EWS v2", "EWS"
    )
    assert result.success
    assert result.emails[0]["HTMLBody"] == "<p>x</p>"
    assert result.emails[0]["Attachments"] == {"a.txt": "s"}
    assert fake.called("ews-delete-items")[0]["delete-type"] == "hard"
    assert fake.called("ews-search-mailboxes")[0]["email_addresses"] == "a@example.com"


def test_ews_all_mailboxes_sends_no_address_filter(mocker):
    fake = setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-search-mailboxes": []})
    run_vendor(make_params(mailbox_scope=SCOPE_ALL, operation=OPERATION_SEARCH_ONLY), "ews", "EWS v2", "EWS")
    assert "email_addresses" not in fake.called("ews-search-mailboxes")[0]


def test_ews_saturated_search_is_repeated_after_delete(mocker):
    calls = {"n": 0}

    def search_with_state(args):
        calls["n"] += 1
        if calls["n"] <= len(module.EWS_LIMIT_STEPS):  # first round: always capped
            return [entry({"EWS.Items": [{"itemId": f"r1-{i}", "mailbox": "a@example.com"} for i in range(args["limit"])]})]
        return [entry({"EWS.Items": []})]  # second round: nothing left

    setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-search-mailboxes": search_with_state, "ews-get-items": []})
    result = run_vendor(make_params(), "ews", "EWS v2", "EWS")
    assert result.total_found == 1000  # Only one limit step now
    assert result.total_deleted == 1000


# ----------------------------------------------------------------------------------------------------------------------
# Aggregation and error handling
# ----------------------------------------------------------------------------------------------------------------------
def test_run_all_aggregates_partial_failure(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail", "EWS": "EWS v2"},
        {"gmail-search": [entry({"Gmail": [GMAIL_ITEM]})], "ews-search-mailboxes": [error_entry("ews down")]},
    )
    results = run_all(make_params(operation=OPERATION_SEARCH_ONLY))
    assert [r.success for r in results] == [True, False]
    email_data = get_email_data(make_params(operation=OPERATION_SEARCH_ONLY), results)
    assert {c["Brand"] for c in email_data} == {"Gmail", "EWS v2"}
    assert any("ews down" in c["Reason"] for c in email_data)


def test_all_vendors_fail_returns_hr_and_context(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail", "EWS": "EWS v2"},
        {"gmail-search": [error_entry("g down")], "ews-search-mailboxes": [error_entry("e down")]},
    )
    params = make_params(operation=OPERATION_SEARCH_ONLY)
    results = run_all(params)
    assert not any(r.success for r in results)
    
    command_results = module.build_command_results(params, results)[0]
    hr = command_results.readable_output
    assert command_results.entry_type == entryTypes["error"]
    assert "The operation failed for all the integrations" in hr
    assert "**Reason:**" in hr
    assert "g down" in hr
    assert "e down" in hr
    
    outputs = command_results.outputs
    assert outputs["TotalFound"] == 0
    assert len(outputs["EmailData"]) == 2
    assert all(c["Success"] is False for c in outputs["EmailData"])


def test_no_instances_returns_failure_entry(mocker):
    setup_demisto(mocker, {}, {})
    results = run_all(make_params())
    assert "No enabled instance" in results[0].errors[0]
    assert get_email_data(make_params(), results)[0]["Success"] is False


def test_object_id_requires_a_single_vendor(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail", "EWS": "EWS v2"}, {})
    with pytest.raises(module.DemistoException, match="exactly one brand"):
        run_all(make_params(object_id="1", brands=["Gmail", "EWS v2"]))


def test_verbose_lists_executed_commands(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": [entry({"Gmail": [GMAIL_ITEM]})]})
    params = make_params(operation=OPERATION_SEARCH_ONLY, verbose=True)
    hr = get_hr(params, run_all(params))
    assert "#### Executed commands" in hr
    assert "gmail-search" in hr


def test_404_not_found_is_not_a_hard_failure_for_gmail(mocker):
    """If the only error returned includes '404' or 'not found', it shouldn't be EntryType.ERROR"""
    setup_demisto(
        mocker,
        {"Gmail": "Gmail"},
        {"gmail-get-mail": [error_entry('HttpError 404... "Requested entity was not found."')]},
    )
    params = make_params(operation=OPERATION_SEARCH_ONLY, object_id="nonexistent")
    results = run_all(params)
    
    assert not results[0].success
    command_results = module.build_command_results(params, results)[0]
    
    # It should be a NOTE, not an ERROR, since the 404 is ignored by `is_hard_failure`
    assert command_results.entry_type == entryTypes["note"]
    assert "The operation failed for all the integrations" not in command_results.readable_output


# ----------------------------------------------------------------------------------------------------------------------
# Deletion verification
# ----------------------------------------------------------------------------------------------------------------------
GMAIL_FOUND = [entry({"Gmail": [GMAIL_ITEM]})]
GMAIL_EMPTY: list[dict[str, Any]] = []


def sequence(*batches: Any):
    """Returns a command responder that answers call number N with ``batches[N]`` (the last one is repeated)."""
    calls = {"n": 0}

    def respond(args: dict[str, Any]) -> Any:
        batch = batches[min(calls["n"], len(batches) - 1)]
        calls["n"] += 1
        return batch

    return respond


def test_verification_disabled_by_default_runs_no_verification_search(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    params = make_params()
    result = run_vendor(params, "gmail", "Gmail", "Gmail")
    assert len(fake.called("gmail-search")) == 1
    assert "DeletionVerified" not in result.emails[0]
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)
    
    email_data = get_email_data(params, [result])
    assert "Verified" not in email_data[0]["AdditionalFields"]


def test_verification_gmail_verified(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": sequence(GMAIL_FOUND, GMAIL_EMPTY)})
    params = make_params(verify_deletion=True)
    result = run_vendor(params, "gmail", "Gmail", "Gmail")
    assert len(fake.called("gmail-search")) == 2
    assert result.emails[0]["DeletionVerified"] is True
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)
    assert result.success
    
    email_data = get_email_data(params, [result])
    assert email_data[0]["Success"] is True
    assert email_data[0]["AdditionalFields"]["Verified"] is True


def test_verification_gmail_email_still_found_is_reported_as_failed(mocker):
    mocker.patch.object(module, "VERIFICATION_TIMEOUT_SECONDS", 0)  # the first verification attempt is also the last
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    params = make_params(verify_deletion=True)
    result = run_vendor(params, "gmail", "Gmail", "Gmail")
    assert len(fake.called("gmail-search")) == 2
    email = result.emails[0]
    assert email["Deleted"] is False
    assert email["DeletionVerified"] is False
    assert "could not be verified" in email["Reason"]
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 0, 1)
    assert not result.success
    
    email_data = get_email_data(params, [result])[0]
    assert email_data["Success"] is False
    assert "could not be verified" in email_data["Reason"]
    assert email_data["AdditionalFields"]["Verified"] is False
    
    outputs = get_outputs(params, [result])
    assert outputs["TotalDeleted"] == 0
    assert outputs["TotalFailed"] == 1


def test_verification_polls_until_the_email_disappears(mocker):
    fake = setup_demisto(
        mocker, {"Gmail": "Gmail"}, {"gmail-search": sequence(GMAIL_FOUND, GMAIL_FOUND, GMAIL_FOUND, GMAIL_EMPTY)}
    )
    run = drive_vendor(make_params(verify_deletion=True), "gmail", "Gmail", "Gmail")
    result = run.results[0]
    assert len(fake.called("gmail-search")) == 4  # initial search + 3 verification polls (one per tick)
    assert run.visited() == ["start", "verify", "verify", "verify", "done"]
    assert result.emails[0]["DeletionVerified"] is True
    assert (result.total_deleted, result.total_failed) == (1, 0)


def test_verification_search_error_does_not_fail_the_emails(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": sequence(GMAIL_FOUND, [error_entry("search down")])})
    params = make_params(verify_deletion=True)
    result = run_vendor(params, "gmail", "Gmail", "Gmail")
    email = result.emails[0]
    assert email["Deleted"] is True
    assert email.get("DeletionVerified") is None
    assert (result.total_deleted, result.total_failed) == (1, 0)
    assert len(result.errors) == 1
    assert "Failed verifying the deletion" in result.errors[0]
    assert "search down" in result.errors[0]
    
    email_data = get_email_data(params, [result])
    assert "Verified" not in email_data[0]["AdditionalFields"]


def test_verification_is_ignored_for_search_only(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    params = make_params(operation=OPERATION_SEARCH_ONLY, verify_deletion=True)
    result = run_vendor(params, "gmail", "Gmail", "Gmail")
    assert len(fake.called("gmail-search")) == 1
    assert "DeletionVerified" not in result.emails[0]


def test_verification_is_skipped_when_nothing_was_deleted(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND, "gmail-delete-mail": [error_entry("denied")]})
    result = run_vendor(make_params(verify_deletion=True), "gmail", "Gmail", "Gmail")
    assert len(fake.called("gmail-search")) == 1  # emails that failed to delete are not re-verified
    assert "DeletionVerified" not in result.emails[0]
    assert (result.total_deleted, result.total_failed) == (0, 1)


def test_verification_ews_matches_on_object_id_not_on_the_moved_copy(mocker):
    original = {"itemId": "i1", "mailbox": "a@example.com", "subject": "Invoice"}
    moved_copy = {"itemId": "i1-in-deleted-items", "mailbox": "a@example.com", "subject": "Invoice"}
    fake = setup_demisto(
        mocker,
        {"EWS": "EWS v2"},
        {
            "ews-search-mailboxes": sequence(
                [entry({"EWS.Items": [original]})],
                [entry({"EWS.Items": [moved_copy]})],  # a soft deleted item gets a new ID in "Deleted Items"
            ),
            "ews-get-items": [],
        },
    )
    result = run_vendor(make_params(verify_deletion=True), "ews", "EWS v2", "EWS")
    assert len(fake.called("ews-search-mailboxes")) == 2
    assert result.emails[0]["DeletionVerified"] is True
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)


def test_verification_graph_mail_same_id_still_present_is_unverified(mocker):
    mocker.patch.object(module, "VERIFICATION_TIMEOUT_SECONDS", 0)
    item = {"ID": "g1", "UserID": "a@example.com", "Subject": "Invoice", "ReceivedTime": "t"}
    other = {**item, "ID": "g2"}
    setup_demisto(
        mocker,
        {"GraphMail": "O365 Outlook Mail (Using Graph API)"},
        {
            "msgraph-mail-list-emails": sequence(
                [entry({"MSGraphMail": [item, other]})],
                [entry({"MSGraphMail": [item]})],  # g2 is gone, g1 is still returned
            ),
        },
    )
    result = run_vendor(make_params(verify_deletion=True), "msgraph_mail", "O365", "GraphMail")
    verified = {email["ObjectID"]: email["DeletionVerified"] for email in result.emails}
    assert verified == {"g1": False, "g2": True}
    assert (result.total_found, result.total_deleted, result.total_failed) == (2, 1, 1)


def test_verification_graph_security_final_estimate_zero_is_verified(mocker):
    fake = setup_demisto(mocker, {"MsGraph": "Microsoft Graph"}, graph_security_responses([3, 0]))
    params = make_params(verify_deletion=True)
    result = run_vendor(params, "msgraph_security", "Microsoft Graph", "MsGraph")
    assert result.additional["DeletionVerified"] is True
    assert (result.total_found, result.total_deleted, result.total_failed) == (3, 3, 0)
    assert len(fake.called("msg-get-last-estimate-statistics-operation")) == 2  # no additional API calls
    
    email_data = get_email_data(params, [result])
    assert email_data[0]["AdditionalFields"]["Verified"] is True


def test_verification_graph_security_remaining_items_are_unverified(mocker):
    setup_demisto(mocker, {"MsGraph": "Microsoft Graph"}, graph_security_responses([3] + [2] * module.MAX_ROUNDS))
    params = make_params(verify_deletion=True)
    result = run_vendor(params, "msgraph_security", "Microsoft Graph", "MsGraph")
    assert result.additional["DeletionVerified"] is False
    assert "could not be verified" in result.additional["Note"]
    assert (result.total_found, result.total_deleted, result.total_failed) == (3, 1, 2)
    
    email_data = get_email_data(params, [result])
    assert email_data[0]["Success"] is False
    assert email_data[0]["AdditionalFields"]["Verified"] is False


def test_graph_security_without_verification_does_not_set_deletion_verified(mocker):
    setup_demisto(mocker, GS_MODULES, graph_security_responses([3, 0]))
    result = run_vendor(make_params(), "msgraph_security", "Microsoft Graph", "MsGraph")
    assert "DeletionVerified" not in result.additional


# ----------------------------------------------------------------------------------------------------------------------
# Arguments: delete_type / timeout / verify_deletion
# ----------------------------------------------------------------------------------------------------------------------
BASE_ARGS = {"operation": OPERATION_SEARCH_AND_DELETE, "subject": "Invoice", "target_mailbox": "a@example.com"}


@pytest.mark.parametrize(
    "value, expected",
    [
        ("soft", DELETE_SOFT),
        ("hard", DELETE_HARD),
        ("SOFT", DELETE_SOFT),
        (" Hard ", DELETE_HARD),
        (None, DELETE_SOFT),
        ("", DELETE_SOFT),
    ],
)
def test_parse_args_delete_type(value, expected):
    args = dict(BASE_ARGS)
    if value is not None:
        args["delete_type"] = value
    assert module.parse_args(args).delete_type == expected


@pytest.mark.parametrize("value", ["Soft Delete", "Hard Delete", "maybe", "permanent"])
def test_parse_args_delete_type_invalid(value):
    with pytest.raises(module.DemistoException, match="delete_type must be 'soft' or 'hard'."):
        module.parse_args({**BASE_ARGS, "delete_type": value})


def test_delete_type_constants_are_lowercase():
    assert (DELETE_SOFT, DELETE_HARD) == ("soft", "hard")


@pytest.mark.parametrize("value, expected", [(None, 1800), ("", 1800), ("60", 60), (3600, 3600), ("1", 1)])
def test_parse_args_timeout(value, expected):
    args = dict(BASE_ARGS)
    if value is not None:
        args["timeout"] = value
    assert module.parse_args(args).timeout == expected


def test_default_timeout_constant():
    assert module.DEFAULT_TIMEOUT_SECONDS == 1800


@pytest.mark.parametrize("value", ["0", 0, "-5", -5, "abc", "1.5x"])
def test_parse_args_timeout_invalid(value):
    with pytest.raises(module.DemistoException, match="timeout must be a positive number of seconds."):
        module.parse_args({**BASE_ARGS, "timeout": value})


@pytest.mark.parametrize("value, expected", [("true", True), ("false", False), (True, True), (None, False)])
def test_parse_args_verify_deletion_accepts_booleans(value, expected):
    args = dict(BASE_ARGS)
    if value is not None:
        args["verify_deletion"] = value
    assert module.parse_args(args).verify_deletion is expected


# ----------------------------------------------------------------------------------------------------------------------
# Output: command results, readable output, EmailData context
# ----------------------------------------------------------------------------------------------------------------------
GRAPH_MAIL_ITEM = {
    "ID": "AAMk-1",
    "UserID": "avishai@example.com",
    "Subject": "Undeliverable",
    "From": {"Address": "postmaster@example.com"},
    "ReceivedTime": "2026-10-21T11:58:19Z",
    "InternetMessageID": "<imid@example.com>",
}


def vendor_result(vendor: str = "Gmail", brand: str = "Gmail", **kwargs: Any) -> module.VendorResult:
    return module.VendorResult(vendor=vendor, brand=brand, instance=f"{brand}_instance", **kwargs)


def found_email(object_id: str = "m1", **overrides: Any) -> dict[str, Any]:
    email = module.gmail_to_email({**GMAIL_ITEM, "ID": object_id})
    email.update(overrides)
    return email


def test_build_command_results_success():
    result = vendor_result(emails=[found_email()], total_found=1)
    params = make_params(operation=OPERATION_SEARCH_ONLY)
    entries = module.build_command_results(params, [result])
    
    assert len(entries) == 1
    entry = entries[0]
    
    # Check outputs context
    assert "EmailData" in entry.outputs
    assert entry.outputs["TotalFound"] == 1
    assert entry.outputs["TotalDeleted"] == 0
    assert entry.outputs["TotalFailed"] == 0
    
    # Check table structure in readable output
    hr = entry.readable_output
    assert "|Brand|Mailbox|ID|Subject|From|To|Timestamp|Operation|Success|Reason|" in hr
    assert "| Gmail | a@example.com | m1 | Invoice | bad@evil.com | a@example.com | Mon, 2 Jan 2026 03:04:05 +0000 | Search Only | true |  |" in hr
    assert "**Total found:** 1 | **Total deleted:** 0 | **Total failed:** 0" in hr


def test_build_command_results_aggregate_vendor():
    email = module.graph_mail_to_email(GRAPH_MAIL_ITEM)
    result_normal = vendor_result("Microsoft Graph Mail", "MicrosoftGraphMail", emails=[email], total_found=1)
    result_agg = vendor_result("Microsoft Graph Security", "Microsoft Graph", aggregate=True, total_found=3, total_deleted=3)
    
    params = make_params(operation=OPERATION_SEARCH_AND_DELETE)
    entry = module.build_command_results(params, [result_normal, result_agg])[0]
    
    # Aggregated totals
    assert entry.outputs["TotalFound"] == 4
    assert entry.outputs["TotalDeleted"] == 3
    assert entry.outputs["TotalFailed"] == 0
    
    # The aggregate record should be in EmailData context but omitted from the visual table
    email_data = entry.outputs["EmailData"]
    assert len(email_data) == 2
    agg_record = next(item for item in email_data if item["Brand"] == "Microsoft Graph")
    assert agg_record["AdditionalFields"]["Aggregate"] is True
    
    hr = entry.readable_output
    assert "MicrosoftGraphMail" in hr
    assert "Microsoft Graph Security" not in hr  # excluded from visual table
    assert "**Total found:** 4 | **Total deleted:** 3 | **Total failed:** 0" in hr


def test_build_command_results_nothing_found_visuals():
    result = vendor_result()
    params = make_params(operation=OPERATION_SEARCH_ONLY)
    entry = module.build_command_results(params, [result])[0]
    
    # Should skip putting empty vendor in table, falling back to "No emails were found." string
    hr = entry.readable_output
    assert "No emails were found." in hr
    assert "**Total found:** 0" in hr


def test_context_has_object_id_in_additional_fields():
    result = vendor_result(emails=[found_email("m1")], total_found=1)
    entry = get_email_data(make_params(operation=OPERATION_SEARCH_ONLY), [result])[0]
    
    assert "ObjectID" in entry["AdditionalFields"]
    assert entry["AdditionalFields"]["ObjectID"] == "m1"
    assert "InternetMessageID" in entry["AdditionalFields"]


def test_context_vendor_failure_entry_has_no_emails_and_success_false():
    result = vendor_result(errors=["boom"], total_found=0, total_failed=0)
    entry = get_email_data(make_params(), [result])[0]
    assert entry.get("Subject") is None
    assert entry["Success"] is False
    assert entry["Reason"] == "boom"


# ----------------------------------------------------------------------------------------------------------------------
# Overall time budget (timeout): an absolute epoch deadline stored in the state
# ----------------------------------------------------------------------------------------------------------------------
def test_new_state_sets_an_absolute_deadline_and_fixes_the_search_window(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {})
    params = make_params(timeout=90)
    state = module.new_state(params)
    assert state["deadline"] == START_EPOCH + 90
    assert state["since"] == params.since.isoformat()
    assert state["version"] == module.STATE_VERSION
    assert [(v["key"], v["stage"]) for v in state["vendors"]] == [("gmail", "start")]
    assert json.loads(module.dump_state(state)) == state


def test_run_tick_takes_the_deadline_from_the_state(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    params = make_params(operation=OPERATION_SEARCH_ONLY, timeout=90)
    drive(params)
    assert module._DEADLINE == START_EPOCH + 90
    assert module._TIMEOUT_SECONDS == 90


def test_load_state_helpers():
    assert module.load_state({}) is None
    state = {"version": module.STATE_VERSION, "vendors": []}
    assert module.load_state({"state": module.dump_state(state)}) == state
    with pytest.raises(module.DemistoException, match="polling state is invalid"):
        module.load_state({"state": json.dumps({"version": 999})})


def test_run_command_raises_when_budget_is_exhausted(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    mocker.patch.object(module, "_DEADLINE", START_EPOCH + 100)
    mocker.patch.object(module, "_TIMEOUT_SECONDS", 30)
    CLOCK.advance(101)
    with pytest.raises(module.DemistoException, match="Timed out: the 30 seconds timeout was reached"):
        module.run_command("gmail-search", {}, "Gmail")
    assert not fake.calls
    module.run_command("gmail-search", {}, "Gmail", enforce_timeout=False)  # cleanup commands are never blocked
    assert len(fake.calls) == 1


def test_run_command_without_a_budget_never_times_out(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    CLOCK.advance(10**9)
    assert module.run_command("gmail-search", {}, "Gmail")


def test_vendors_are_not_started_when_the_deadline_passed(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail", "EWS": "EWS v2"}, {})
    params = make_params(operation=OPERATION_SEARCH_ONLY, timeout=5)
    state = module.new_state(params)
    CLOCK.advance(10)  # the deadline passed before the first tick
    results = drive(params, state).results
    assert not fake.calls
    assert [r.success for r in results] == [False, False]
    assert all("Timed out before this vendor was run: the 5 seconds timeout was reached." in r.errors[0] for r in results)
    
    hr = get_hr(params, results)
    assert hr.count("Timed out before this vendor was run") == 2
    assert [r.brand for r in results] == ["Gmail", "EWS v2"]


def test_vendor_that_was_not_started_before_the_deadline_is_reported_after_a_slow_vendor(mocker):
    def slow_search(args):
        CLOCK.advance(100)  # Gmail uses up the whole budget
        return GMAIL_FOUND

    fake = setup_demisto(mocker, {"Gmail": "Gmail", "EWS": "EWS v2"}, {"gmail-search": slow_search})
    params = make_params(operation=OPERATION_SEARCH_ONLY, timeout=5)
    gmail, ews = drive(params).results
    assert gmail.success
    assert gmail.total_found == 1
    assert not fake.called("ews-search-mailboxes")
    assert "Timed out before this vendor was run: the 5 seconds timeout was reached." in ews.errors[0]


def test_partial_results_survive_a_failing_second_search_round(mocker):
    """Round 1 finds and deletes an email (and reports a saturated page), round 2 raises: the email is still reported."""
    rounds = iter([([module.gmail_to_email(GMAIL_ITEM)], True)])

    def gmail_search(params, instance):
        try:
            return next(rounds)
        except StopIteration:
            raise module.DemistoException("Timed out: the 30 seconds timeout was reached.") from None

    mocker.patch.object(module, "gmail_search", side_effect=gmail_search)
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {})
    result = run_vendor(make_params(), "gmail", "Gmail", "Gmail")
    assert len(fake.called("gmail-delete-mail")) == 1
    assert result.total_found == 1
    assert [email["ObjectID"] for email in result.emails] == ["m1"]
    assert result.emails[0]["Deleted"] is True
    assert (result.total_deleted, result.total_failed) == (1, 0)
    assert result.errors == ["Timed out: the 30 seconds timeout was reached."]
    
    params = make_params()
    email_data = get_email_data(params, [result])
    # the deleted email + the failure row of the vendor
    assert len(email_data) == 2
    assert email_data[0]["AdditionalFields"]["ObjectID"] == "m1"
    assert email_data[1]["Success"] is False
    assert "Timed out" in email_data[1]["Reason"]


def test_gmail_pagination_timeout_is_reported_as_a_vendor_error(mocker):
    def first_page(args):
        CLOCK.advance(100)  # the budget is gone when the second page is requested
        return [entry({"Gmail": [GMAIL_ITEM], "PageToken": {"NextPageToken": "t2"}})]

    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": first_page})
    result = run_vendor(make_params(operation=OPERATION_SEARCH_ONLY, timeout=30), "gmail", "Gmail", "Gmail")
    assert len(result.errors) == 1
    assert "Timed out: the 30 seconds timeout was reached" in result.errors[0]
    assert not result.success


def test_unexpected_exception_of_a_vendor_is_recorded_and_does_not_stop_the_other_vendor(mocker):
    mocker.patch.object(module, "gmail_search", side_effect=ValueError("kaboom"))
    fake = setup_demisto(mocker, {"Gmail": "Gmail", "MsGraph": "Microsoft Graph"}, graph_security_responses([4]))
    gmail, graph = drive(make_params(operation=OPERATION_SEARCH_ONLY)).results
    assert gmail.errors == ["kaboom"]
    assert graph.total_found == 4
    assert_cleanup_last(fake)


# ----------------------------------------------------------------------------------------------------------------------
# Graph Security: Search & Delete rounds, failures, deadline, cleanup retries
# ----------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("delete_type, purge_type", [(DELETE_SOFT, "recoverable"), (DELETE_HARD, "permanentlyDelete")])
@pytest.mark.parametrize("verify", [True, False])
def test_graph_security_search_and_delete_two_rounds(mocker, delete_type, purge_type, verify):
    fake = setup_demisto(mocker, GS_MODULES, graph_security_responses([5, 2, 0], purge_status=["running", "succeeded"]))
    params = make_params(delete_type=delete_type, verify_deletion=verify)
    run = drive_vendor(params, *GS)
    result = run.results[0]
    assert result.success
    assert (result.total_found, result.total_deleted, result.total_failed) == (5, 5, 0)
    assert run.visited() == [
        "create",
        "estimate_start",
        "estimate_wait",
        "purge_start",
        "purge_wait",
        "purge_wait",
        "estimate_start",
        "estimate_wait",
        "purge_start",
        "purge_wait",
        "estimate_start",
        "estimate_wait",
        "cleanup",
        "done",
    ]
    purges = fake.called("msg-purge-ediscovery-data")
    assert [c["purge_type"] for c in purges] == [purge_type, purge_type]
    assert all(c["purge_areas"] == "mailboxes" for c in purges)
    assert len(fake.called("msg-run-estimate-statistics")) == 3  # the initial estimate + a re-estimate after every purge
    assert len(fake.called("msg-list-case-operation")) == 3
    assert_cleanup_last(fake)
    if verify:
        assert result.additional["DeletionVerified"] is True
    else:
        assert "DeletionVerified" not in result.additional


def test_graph_security_zero_results_is_a_successful_row_with_total_found_zero(mocker):
    fake = setup_demisto(mocker, GS_MODULES, graph_security_responses([0]))
    params = make_params()
    run = drive_vendor(params, *GS)
    result = run.results[0]
    assert result.success
    assert (result.total_found, result.total_deleted, result.total_failed) == (0, 0, 0)
    assert not fake.called("msg-purge-ediscovery-data")
    assert run.visited()[-2:] == ["cleanup", "done"]
    assert_cleanup_last(fake)
    
    outputs = get_outputs(params, run.results)
    assert outputs["TotalFound"] == 0
    assert outputs["EmailData"][0]["Success"] is True


def failing_graph_security(
    mocker, overrides: dict[str, Any], estimates: Any = (3,), purge_status: Any = "succeeded", params=None
):
    responses = graph_security_responses(list(estimates), purge_status)
    responses.update(overrides)
    fake = setup_demisto(mocker, GS_MODULES, responses)
    run = drive_vendor(params or make_params(), *GS)
    return fake, run


@pytest.mark.parametrize("estimate_status", ["failed", "partiallySucceeded", "submissionFailed"])
def test_graph_security_estimate_failed_status_cleans_up(mocker, estimate_status):
    """A failed estimate comes back ONLY in the human readable (no context) and must end the vendor right away."""
    fake, run = failing_graph_security(mocker, {}, estimates=[estimate_status])
    result = run.results[0]
    assert not result.success
    assert f"estimate statistics operation ended with status '{estimate_status.lower()}'" in result.errors[0]
    assert run.visited()[-3:] == ["estimate_wait", "cleanup", "done"]
    assert len(fake.called("msg-get-last-estimate-statistics-operation")) == 1
    assert not fake.called("msg-purge-ediscovery-data")
    assert_cleanup_last(fake)


def test_graph_security_estimate_running_then_failed_stops_long_before_the_timeout(mocker):
    """Regression: a context-free "(Status: failed)" entry used to read as still running until the 1800 s timeout."""
    fake, run = failing_graph_security(mocker, {}, estimates=["running", "failed"])
    result = run.results[0]
    assert run.visited() == ["create", "estimate_start", "estimate_wait", "estimate_wait", "cleanup", "done"]
    assert len(result.errors) == 1
    assert "estimate statistics operation ended with status 'failed'" in result.errors[0]
    assert not any("Timed out" in error for error in result.errors)
    assert CLOCK.now - START_EPOCH <= 10 * module.POLL_INTERVAL_SECONDS < module.DEFAULT_TIMEOUT_SECONDS
    assert run.state["vendors"][0]["data"]["last_status"] == "failed"
    assert_cleanup_last(fake)


def test_graph_security_error_after_the_case_was_created_but_before_the_search_still_deletes_the_case(mocker):
    fake, run = failing_graph_security(mocker, {"msg-create-ediscovery-search": [error_entry("search denied")]})
    result = run.results[0]
    assert "search denied" in result.errors[0]
    assert run.visited() == ["create", "cleanup", "done"]
    assert delete_order(fake) == ["msg-delete-ediscovery-case"]  # there is no search to delete
    assert fake.calls[-1] == ("msg-delete-ediscovery-case", {"case_id": "case1", "using": "MsGraph"})


def test_graph_security_error_midway_cleans_up_search_and_case(mocker):
    fake, run = failing_graph_security(mocker, {"msg-run-estimate-statistics": [error_entry("estimate boom")]})
    result = run.results[0]
    assert "estimate boom" in result.errors[0]
    assert run.visited() == ["create", "estimate_start", "cleanup", "done"]
    assert_cleanup_last(fake)


def test_graph_security_case_creation_failure_has_nothing_to_clean_up(mocker):
    fake, run = failing_graph_security(mocker, {"msg-create-ediscovery-case": [error_entry("no permission")]})
    assert "no permission" in run.results[0].errors[0]
    assert run.visited() == ["create", "done"]
    assert not delete_order(fake)


def test_graph_security_deadline_mid_estimate_still_cleans_up(mocker):
    def running_and_expire(args):
        CLOCK.advance(5000)
        return estimate_entry("running")

    responses = graph_security_responses(["running"])
    responses["msg-get-last-estimate-statistics-operation"] = running_and_expire
    fake = setup_demisto(mocker, GS_MODULES, responses)
    spy = mocker.spy(module, "run_command")
    run = drive_vendor(make_params(), *GS)
    result = run.results[0]
    assert any("Timed out: the 1800 seconds timeout was reached" in error for error in result.errors)
    assert run.visited()[-3:] == ["estimate_wait", "cleanup", "done"]
    assert len(fake.called("msg-get-last-estimate-statistics-operation")) == 1
    assert_cleanup_last(fake)
    cleanup_calls = [call for call in spy.call_args_list if call.args[0] in GS_DELETE_COMMANDS]
    assert len(cleanup_calls) == 2
    assert all(call.kwargs["enforce_timeout"] is False for call in cleanup_calls)


@pytest.mark.parametrize(
    "results, expected",
    [
        ([entry({ESTIMATE_CONTEXT_KEY: {"id": "op", "status": "Succeeded", "totalItemCount": 7}})], ("succeeded", 7)),
        ([entry({"MsGraph.eDiscovery.EstimateStatistics": {"Status": "succeeded", "TotalItemsCount": 4}})], ("succeeded", 4)),
        ([entry({"MsGraph.eDiscovery.EstimateStatistics": {"Status": "completed", "TotalItemCount": "2"}})], ("completed", 2)),
        ([entry({ESTIMATE_CONTEXT_KEY: {"id": "op", "status": "succeeded", "totalItemCount": 0}})], ("succeeded", 0)),
        ([entry({ESTIMATE_CONTEXT_KEY: {"id": "op", "status": "running"}})], ("running", None)),
        ([entry({ESTIMATE_CONTEXT_KEY: {"id": "op", "status": "succeeded", "totalItemCount": "5"}})], ("succeeded", 5)),
        ([running_estimate_entry()], ("running", None)),
        ([running_estimate_entry("failed")], ("failed", None)),
        ([running_estimate_entry("submissionFailed")], ("submissionfailed", None)),
        (
            [{"Type": entryTypes["note"], "HumanReadable": "Estimate ... (Status: PartiallySucceeded)"}],
            ("partiallysucceeded", None),
        ),
        (
            [
                running_estimate_entry("running"),
                entry({ESTIMATE_CONTEXT_KEY: {"id": "op", "status": "succeeded", "totalItemCount": 9}}),
            ],
            ("succeeded", 9),
        ),
        (
            [{"Type": entryTypes["note"], "HumanReadable": "Estimate statistics operation is still running... (Status: )"}],
            ("", None),
        ),
        ([], ("", None)),
    ],
    ids=[
        "raw",
        "documented",
        "total-item-count",
        "zero",
        "running-with-context",
        "count-as-string",
        "hr-running",
        "hr-failed",
        "hr-submission-failed-lower-cased",
        "hr-mixed-case-no-contents-key",
        "context-free-entry-then-context-entry",
        "hr-empty-status",
        "no-entries",
    ],
)
def test_parse_estimate_accepts_raw_and_documented_keys(results, expected):
    assert module.parse_estimate(results) == expected


@pytest.mark.parametrize("bad_count", ["abc", "", "5.5", [5], {"n": 5}])
def test_parse_estimate_rejects_an_unparseable_count(bad_count):
    results = [entry({ESTIMATE_CONTEXT_KEY: {"id": "op", "status": "succeeded", "totalItemCount": bad_count}})]
    if bad_count == "":  # an empty value is "missing" (find_first skips it), not "unparseable"
        assert module.parse_estimate(results) == ("succeeded", None)
        return
    with pytest.raises(module.VendorError, match=re.escape(f"Unexpected estimate item count: {bad_count!r}")):
        module.parse_estimate(results)


def test_graph_security_unparseable_estimate_count_fails_and_cleans_up(mocker):
    overrides = {
        "msg-get-last-estimate-statistics-operation": [
            entry({ESTIMATE_CONTEXT_KEY: {"id": "op", "status": "succeeded", "totalItemCount": "many"}})
        ]
    }
    fake, run = failing_graph_security(mocker, overrides)
    result = run.results[0]
    assert not result.success
    assert "Unexpected estimate item count: 'many'" in result.errors[0]
    assert not fake.called("msg-purge-ediscovery-data")
    assert_cleanup_last(fake)


def test_graph_security_estimate_without_any_status_records_a_neutral_last_status(mocker):
    responses = graph_security_responses([3])
    responses["msg-get-last-estimate-statistics-operation"] = status_responder(
        ["none", 3], lambda item: [entry({})] if item == "none" else estimate_entry(item)
    )
    fake = setup_demisto(mocker, GS_MODULES, responses)
    seen: list[str] = []
    run = drive_vendor(
        make_params(operation=OPERATION_SEARCH_ONLY),
        *GS,
        on_tick=lambda tick, state: seen.append(state["vendors"][0]["data"].get("last_status")),
    )
    assert "pending" in seen
    assert "running" not in seen
    assert run.results[0].total_found == 3
    assert_cleanup_last(fake)


def test_graph_security_regression_raw_estimate_finishes_without_timeout(mocker):
    """Regression: the raw lowercase estimate (status / totalItemCount) used to read as "" forever and hit the 1800 s timeout."""
    fake = setup_demisto(mocker, GS_MODULES, graph_security_responses(["running", 3, 0]))
    run = drive_vendor(make_params(), *GS, max_ticks=15)
    result = run.results[0]
    assert result.errors == []
    assert (result.total_found, result.total_deleted, result.total_failed) == (3, 3, 0)
    assert CLOCK.now - START_EPOCH < module.DEFAULT_TIMEOUT_SECONDS
    assert len(fake.called("msg-purge-ediscovery-data")) == 1
    assert_cleanup_last(fake)


def test_graph_security_estimate_succeeded_without_count_fails_and_cleans_up(mocker):
    fake, run = failing_graph_security(mocker, {}, estimates=["succeeded"])
    result = run.results[0]
    assert not result.success
    assert "did not return the number of items" in result.errors[0]
    assert result.total_found == 0
    assert run.visited()[-3:] == ["estimate_wait", "cleanup", "done"]
    assert not fake.called("msg-purge-ediscovery-data")
    assert_cleanup_last(fake)


def test_graph_security_timeout_message_names_the_stage_and_last_status(mocker):
    calls = {"n": 0}

    def running_then_expire(args):
        calls["n"] += 1
        if calls["n"] == 2:
            CLOCK.advance(5000)
        return estimate_entry("running")

    responses = graph_security_responses(["running"])
    responses["msg-get-last-estimate-statistics-operation"] = running_then_expire
    fake = setup_demisto(mocker, GS_MODULES, responses)
    run = drive_vendor(make_params(), *GS)
    (error,) = run.results[0].errors
    assert "Timed out: the 1800 seconds timeout was reached" in error
    assert "stage 'estimate_wait'" in error
    assert "last estimate status: 'running'" in error
    assert run.state["vendors"][0]["data"]["last_status"] == "running"
    assert run.visited()[-3:] == ["estimate_wait", "cleanup", "done"]
    assert_cleanup_last(fake)


def test_graph_security_old_state_without_last_status_still_loads(mocker):
    fake = setup_demisto(mocker, GS_MODULES, graph_security_responses(["running", 3]))
    params = make_params(operation=OPERATION_SEARCH_ONLY)
    state = single_vendor_state(params, *GS)
    vendor = state["vendors"][0]
    vendor["stage"] = "estimate_wait"
    vendor["data"].update({"case_id": "case1", "search_id": "search1"})
    del vendor["data"]["last_status"]  # a state written before the field existed
    assert module.load_state({"state": json.dumps(state)}) == state
    assert "last estimate status: 'none'" in module.graph_security_timeout_message("estimate_wait", vendor["data"])
    run = drive(params, state)
    result = run.results[0]
    assert result.errors == []
    assert result.total_found == 3
    assert run.state["vendors"][0]["data"]["last_status"] == "succeeded"
    assert_cleanup_last(fake)


def test_graph_security_deadline_mid_purge_still_cleans_up(mocker):
    responses = graph_security_responses([3])
    purge = responses["msg-purge-ediscovery-data"]

    def purge_and_expire(args):
        CLOCK.advance(5000)
        return purge

    responses["msg-purge-ediscovery-data"] = purge_and_expire
    fake = setup_demisto(mocker, GS_MODULES, responses)
    run = drive_vendor(make_params(), *GS)
    result = run.results[0]
    assert any("Timed out: the 1800 seconds timeout was reached" in error for error in result.errors)
    assert run.visited()[-3:] == ["purge_wait", "cleanup", "done"]
    assert not fake.called("msg-list-case-operation")
    assert_cleanup_last(fake)


def test_graph_security_cleanup_retries_the_search_deletion_and_never_deletes_twice(mocker):
    responses = graph_security_responses([0])
    responses["msg-delete-ediscovery-search"] = sequence([error_entry("throttled")], [entry({})])
    fake = setup_demisto(mocker, GS_MODULES, responses)
    run = drive_vendor(make_params(operation=OPERATION_SEARCH_ONLY), *GS)
    result = run.results[0]
    assert run.visited()[-3:] == ["cleanup", "cleanup", "done"]
    assert len(fake.called("msg-delete-ediscovery-search")) == 2
    assert len(fake.called("msg-delete-ediscovery-case")) == 1  # already deleted on the first attempt: not repeated
    assert result.errors == []  # a failure that the retry fixed is not an error of the run
    assert result.success


def test_graph_security_cleanup_gives_up_after_max_attempts(mocker):
    responses = graph_security_responses([0])
    responses["msg-delete-ediscovery-case"] = [error_entry("denied")]
    fake = setup_demisto(mocker, GS_MODULES, responses)
    run = drive_vendor(make_params(operation=OPERATION_SEARCH_ONLY), *GS)
    result = run.results[0]
    assert module.MAX_CLEANUP_ATTEMPTS == 3
    assert run.visited()[-4:] == ["cleanup", "cleanup", "cleanup", "done"]  # no infinite polling
    assert len(fake.called("msg-delete-ediscovery-case")) == module.MAX_CLEANUP_ATTEMPTS
    assert len(fake.called("msg-delete-ediscovery-search")) == 1
    assert len(result.errors) == 1
    assert "Failed deleting eDiscovery case case1" in result.errors[0]
    assert "denied" in result.errors[0]
    assert not result.success


def test_graph_security_cleanup_deletes_the_case_even_when_the_search_deletion_keeps_failing(mocker):
    responses = graph_security_responses([0])
    responses["msg-delete-ediscovery-search"] = [error_entry("search locked")]
    fake = setup_demisto(mocker, GS_MODULES, responses)
    run = drive_vendor(make_params(operation=OPERATION_SEARCH_ONLY), *GS)
    result = run.results[0]
    assert len(fake.called("msg-delete-ediscovery-case")) == 1
    assert len(fake.called("msg-delete-ediscovery-search")) == module.MAX_CLEANUP_ATTEMPTS
    assert len(result.errors) == 1
    assert "Failed deleting eDiscovery search search1" in result.errors[0]


def test_graph_security_retrieve_files_is_a_no_op_with_a_note(mocker):
    setup_demisto(mocker, GS_MODULES, graph_security_responses([0]))
    result = run_vendor(make_params(operation=OPERATION_SEARCH_ONLY, retrieve_files=True), *GS)
    assert "does not return email content" in result.additional["Note"]
    assert result.file_entries == []


def test_graph_security_object_id_is_unsupported_and_creates_nothing(mocker):
    fake = setup_demisto(mocker, GS_MODULES, graph_security_responses([0]))
    result = run_vendor(make_params(object_id="o1"), *GS)
    assert "does not support searching by object_id" in result.errors[0]
    assert not fake.calls


# ----------------------------------------------------------------------------------------------------------------------
# Per-email vendors: the `verify` stage
# ----------------------------------------------------------------------------------------------------------------------
def test_verification_window_ends_unverified_after_120_seconds(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    run = drive_vendor(make_params(verify_deletion=True), "gmail", "Gmail", "Gmail")
    result = run.results[0]
    assert module.VERIFICATION_TIMEOUT_SECONDS == 120
    assert result.emails[0]["DeletionVerified"] is False
    assert (result.total_deleted, result.total_failed) == (0, 1)
    # ticks run every POLL_INTERVAL_SECONDS: the window passes on the tick that runs at t=120
    assert run.ticks == 1 + module.VERIFICATION_TIMEOUT_SECONDS // module.POLL_INTERVAL_SECONDS
    assert len(fake.called("gmail-search")) == run.ticks
    assert run.visited()[:3] == ["start", "verify", "verify"]


def test_overall_deadline_caps_the_verification_window(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    run = drive_vendor(make_params(verify_deletion=True, timeout=50), "gmail", "Gmail", "Gmail")
    result = run.results[0]
    assert run.ticks == 4  # t=0, 20, 40 and the tick at t=60 that finds the deadline passed
    assert len(fake.called("gmail-search")) == 3
    assert result.emails[0]["DeletionVerified"] is False
    assert (result.total_deleted, result.total_failed) == (0, 1)
    assert result.errors == []


def test_verification_search_error_in_a_later_tick_does_not_fail_the_emails(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": sequence(GMAIL_FOUND, GMAIL_FOUND, [error_entry("search down")])})
    run = drive_vendor(make_params(verify_deletion=True), "gmail", "Gmail", "Gmail")
    result = run.results[0]
    assert run.visited() == ["start", "verify", "verify", "done"]
    assert result.emails[0]["Deleted"] is True
    assert result.emails[0].get("DeletionVerified") is None
    assert "Failed verifying the deletion: " in result.errors[0]
    assert "search down" in result.errors[0]
    assert (result.total_deleted, result.total_failed) == (1, 0)


def test_verification_state_keeps_only_the_start_time_and_survives_json(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": sequence(GMAIL_FOUND, GMAIL_FOUND, GMAIL_EMPTY)})
    seen: list[dict[str, Any]] = []
    run = drive_vendor(
        make_params(verify_deletion=True), "gmail", "Gmail", "Gmail", on_tick=lambda tick, state: seen.append(state["vendors"][0])
    )
    assert seen[0]["stage"] == "verify"
    assert seen[0]["data"] == {"verify_started": START_EPOCH}
    assert run.results[0].emails[0]["DeletionVerified"] is True


# ----------------------------------------------------------------------------------------------------------------------
# Multi-vendor runs
# ----------------------------------------------------------------------------------------------------------------------
MIXED_MODULES = {"Gmail": "Gmail", "MsGraph": "Microsoft Graph"}


def test_graph_security_keeps_polling_while_gmail_is_done_and_gmail_is_preserved(mocker):
    responses = {**graph_security_responses(["running", "running", 2]), "gmail-search": [entry({"Gmail": [GMAIL_ITEM]})]}
    fake = setup_demisto(mocker, MIXED_MODULES, responses)
    params = make_params(operation=OPERATION_SEARCH_ONLY)
    run = drive(params)
    assert run.visited(0)[1:] == ["done"] * run.ticks  # Gmail was finished within the first tick
    assert run.visited(1)[-3:] == ["estimate_wait", "cleanup", "done"]
    assert run.ticks > 3
    assert len(fake.called("gmail-search")) == 1  # a finished vendor is never run again
    gmail, graph = run.results
    assert (gmail.total_found, gmail.aggregate, gmail.emails[0]["ObjectID"]) == (1, False, "m1")
    assert (graph.total_found, graph.aggregate) == (2, True)
    
    outputs = get_outputs(params, run.results)
    assert outputs["TotalFound"] == 3
    
    email_data = outputs["EmailData"]
    assert [(item["Brand"], item.get("AdditionalFields", {}).get("ObjectID", "")) for item in email_data] == [
        ("Gmail", "m1"),
        ("Microsoft Graph", ""),
    ]


def test_one_vendor_failing_does_not_stop_the_other(mocker):
    responses = {**graph_security_responses([4]), "gmail-search": [error_entry("gmail down")]}
    fake = setup_demisto(mocker, MIXED_MODULES, responses)
    gmail, graph = drive(make_params(operation=OPERATION_SEARCH_ONLY)).results
    assert not gmail.success
    assert "gmail down" in gmail.errors[0]
    assert graph.success
    assert graph.total_found == 4
    assert_cleanup_last(fake)


# ----------------------------------------------------------------------------------------------------------------------
# State size safeguard
# ----------------------------------------------------------------------------------------------------------------------
def state_with_bodies(*sizes: int) -> dict[str, Any]:
    vendor = module.new_vendor_state("gmail", "Gmail", "Gmail")
    vendor["result"]["emails"] = [found_email(f"m{index}", HTMLBody="x" * size) for index, size in enumerate(sizes)]
    return {"version": 1, "deadline": CLOCK.now + 10, "since": "", "command_trace": [], "vendors": [vendor]}


def test_state_size_safeguard_truncates_the_largest_bodies_first_and_marks_them(mocker):
    state = state_with_bodies(3000, 2000, 500)
    mocker.patch.object(module, "MAX_STATE_BYTES", len(module.dump_state(state)) - 1500)
    module.enforce_state_size(state)
    emails = state["vendors"][0]["result"]["emails"]
    assert len(emails[0]["HTMLBody"]) == module.HTML_BODY_PREFIX_CHARS
    assert emails[0]["HTMLBodyTruncated"] is True
    assert len(emails[1]["HTMLBody"]) == 2000  # truncating the largest body was enough
    assert "HTMLBodyTruncated" not in emails[1]
    assert len(emails[2]["HTMLBody"]) == 500
    assert len(module.dump_state(state)) <= module.MAX_STATE_BYTES


def test_state_size_safeguard_keeps_going_until_everything_fits_and_leaves_small_bodies(mocker):
    state = state_with_bodies(3000, 2000, 500)
    mocker.patch.object(module, "MAX_STATE_BYTES", 100)
    module.enforce_state_size(state)
    emails = state["vendors"][0]["result"]["emails"]
    assert [bool(email.get("HTMLBodyTruncated")) for email in emails] == [True, True, False]
    assert len(emails[2]["HTMLBody"]) == 500


def test_state_size_safeguard_does_nothing_below_the_limit():
    state = state_with_bodies(3000)
    module.enforce_state_size(state)
    assert len(state["vendors"][0]["result"]["emails"][0]["HTMLBody"]) == 3000
    assert module.MAX_STATE_BYTES == 500_000


def test_state_size_safeguard_marks_the_final_output_between_ticks(mocker):
    item = {**GMAIL_ITEM, "Body": "x" * 5000}
    found = [entry({"Gmail": [item]})]
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": sequence(found, found, GMAIL_EMPTY)})
    mocker.patch.object(module, "MAX_STATE_BYTES", 2000)
    params = make_params(verify_deletion=True)
    run = drive_vendor(params, "gmail", "Gmail", "Gmail")
    email = run.results[0].emails[0]
    assert len(email["HTMLBody"]) == module.HTML_BODY_PREFIX_CHARS
    assert email["HTMLBodyTruncated"] is True
    assert email["DeletionVerified"] is True
    
    email_data = get_email_data(params, run.results)[0]
    assert email_data["AdditionalFields"]["HTMLBodyTruncated"] is True


# ----------------------------------------------------------------------------------------------------------------------
# The polling entry point (the decorated function)
# ----------------------------------------------------------------------------------------------------------------------
ENTRY_ARGS = {
    "operation": OPERATION_SEARCH_ONLY,
    "subject": "Invoice",
    "target_mailbox": "a@example.com",
    "timeout": "1800",
    "verbose": "true",
}


def poll_until_done(args: dict[str, Any], max_calls: int = 40) -> list[Any]:
    """Calls the script like the platform does: the next call gets the ``PollingArgs`` of the previous response."""
    responses: list[Any] = []
    for _ in range(max_calls):
        module.COMMAND_TRACE.clear()  # every scheduled run is a new process
        response = module.search_and_delete_email(args)
        responses.append(response)
        if isinstance(response, list):
            return responses
        args = json.loads(json.dumps(response.scheduled_command.to_results()["PollingArgs"]))
        CLOCK.advance(module.POLL_INTERVAL_SECONDS)
    raise AssertionError("The script kept polling")


def test_entry_point_first_call_schedules_the_next_run_with_the_original_args_and_a_json_state(mocker):
    setup_demisto(mocker, GS_MODULES, graph_security_responses(["running", 3]))
    response = module.search_and_delete_email(dict(ENTRY_ARGS))
    assert isinstance(response, module.CommandResults)
    scheduled = response.scheduled_command.to_results()
    assert scheduled["PollingCommand"] == "SearchAndDeleteEmail"
    assert scheduled["NextRun"] == str(module.POLL_INTERVAL_SECONDS)
    poll_args = scheduled["PollingArgs"]
    assert {key: poll_args[key] for key in ENTRY_ARGS} == ENTRY_ARGS  # the script's own `timeout` is never overwritten
    state = json.loads(poll_args["state"])
    assert state["version"] == module.STATE_VERSION
    assert state["deadline"] == START_EPOCH + 1800
    assert [(v["key"], v["stage"]) for v in state["vendors"]] == [("msgraph_security", "estimate_start")]
    assert poll_args["hide_polling_output"] is True
    # the platform level timeout is longer than our own remaining budget, so our deadline (which triggers the cleanup) fires first
    assert scheduled["Timeout"] == str(1800 + module.CLEANUP_GRACE_SECONDS)
    assert int(scheduled["Timeout"]) > state["deadline"] - CLOCK.now


def test_entry_point_scheduled_timeout_follows_the_remaining_budget(mocker):
    setup_demisto(mocker, GS_MODULES, graph_security_responses(["running"]))
    first = module.search_and_delete_email(dict(ENTRY_ARGS))
    CLOCK.advance(100)
    second = module.search_and_delete_email(first.scheduled_command.to_results()["PollingArgs"])
    assert second.scheduled_command.to_results()["Timeout"] == str(1700 + module.CLEANUP_GRACE_SECONDS)
    assert module.scheduled_timeout({"deadline": CLOCK.now - 50}) == module.CLEANUP_GRACE_SECONDS  # never negative


def test_entry_point_progress_is_only_published_on_a_stage_change(mocker):
    setup_demisto(mocker, GS_MODULES, graph_security_responses(["running", "running", "running", 4]))
    *polls, final = poll_until_done(dict(ENTRY_ARGS))
    outputs = [poll.readable_output for poll in polls]
    assert len(polls) == 6
    assert "starting the estimate" in outputs[0]
    assert "Microsoft Graph Security: estimate running" in outputs[1]
    assert outputs[2:5] == [None, None, None]  # idle polls produce no War Room noise
    assert "cleaning up" in outputs[5]
    assert isinstance(final, list)
    assert len(final) == 1
    assert "TotalFound" in final[0].outputs
    assert final[0].outputs["TotalFound"] == 4
    assert "**Total found:** 4" in final[0].readable_output


def test_entry_point_verbose_command_trace_survives_the_ticks(mocker):
    setup_demisto(mocker, GS_MODULES, graph_security_responses(["running", 4]))
    *polls, final = poll_until_done(dict(ENTRY_ARGS))
    hr = final[0].readable_output
    assert "#### Executed commands" in hr
    for command in ("msg-create-ediscovery-case", "msg-run-estimate-statistics", "msg-delete-ediscovery-case"):
        assert command in hr  # the commands of the first ticks are listed together with the last one
    assert hr.count("msg-create-ediscovery-case") == 1


def test_entry_point_non_verbose_state_carries_no_trace(mocker):
    setup_demisto(mocker, GS_MODULES, graph_security_responses(["running", 4]))
    response = module.search_and_delete_email({**ENTRY_ARGS, "verbose": "false"})
    assert json.loads(response.scheduled_command.to_results()["PollingArgs"]["state"])["command_trace"] == []


def test_entry_point_trace_is_capped(mocker):
    state = state_with_bodies(10)
    module.COMMAND_TRACE[:] = [f"line {index}" for index in range(module.MAX_TRACE_LINES + 50)]
    state["vendors"][0]["stage"] = "done"
    state["command_trace"] = list(module.COMMAND_TRACE)
    state, _, _ = module.run_tick(make_params(verbose=True), state)
    assert len(state["command_trace"]) == module.MAX_TRACE_LINES
    assert state["command_trace"][-1] == f"line {module.MAX_TRACE_LINES + 49}"


def test_entry_point_publishes_files_in_the_retrieval_tick_and_does_not_carry_them(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail"},
        {
            "gmail-search": sequence(GMAIL_FOUND, GMAIL_EMPTY),
            "gmail-get-attachments": [
                entry({"File(val.SHA1 == obj.SHA1)": [{"Name": "a.txt", "SHA256": "abc"}]}, entry_type=entryTypes["file"])
            ],
        },
    )
    args = {
        **ENTRY_ARGS,
        "operation": OPERATION_SEARCH_AND_DELETE,
        "retrieve_files": "true",
        "verify_deletion": "true",
        "verbose": "false",
        "brands": "Gmail",
    }
    first = module.search_and_delete_email(dict(args))
    assert len(PUBLISHED) == 1
    assert PUBLISHED[0]["Type"] == entryTypes["file"]
    raw_state = first.scheduled_command.to_results()["PollingArgs"]["state"]
    vendor = json.loads(raw_state)["vendors"][0]
    assert vendor["result"]["file_entries"] == []
    assert '"EntryContext"' not in raw_state  # the file entry itself is not in the state ...
    assert vendor["result"]["emails"][0]["Attachments"] == {"a.txt": "abc"}  # ... only the name -> SHA256 map
    assert vendor["stage"] == "verify"
    final = poll_until_done(first.scheduled_command.to_results()["PollingArgs"])[-1]
    assert len(PUBLISHED) == 1  # published once, in the retrieval tick
    assert final[0].outputs["EmailData"][0]["Attachments"] == {"a.txt": "abc"}
    assert final[0].outputs["EmailData"][0]["AdditionalFields"]["Verified"] is True


def test_entry_point_search_window_is_fixed_on_the_first_tick(mocker):
    setup_demisto(mocker, GS_MODULES, graph_security_responses(["running", 4]))
    first = module.search_and_delete_email(dict(ENTRY_ARGS))
    poll_args = first.scheduled_command.to_results()["PollingArgs"]
    since = json.loads(poll_args["state"])["since"]
    CLOCK.advance(3600)
    second = module.search_and_delete_email(poll_args)
    assert json.loads(second.scheduled_command.to_results()["PollingArgs"]["state"])["since"] == since


def test_entry_point_invalid_arguments_are_reported_as_such(mocker):
    setup_demisto(mocker, {}, {})
    with pytest.raises(module.InvalidArgumentsError, match="operation must be"):
        module.search_and_delete_email({**ENTRY_ARGS, "operation": "Delete"})


def test_entry_point_unexpected_failure_returns_the_failure_results_and_stops_polling(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {})
    mocker.patch.object(module, "new_state", side_effect=module.DemistoException("boom"))
    result = module.search_and_delete_email(dict(ENTRY_ARGS))[0]
    
    assert result.entry_type == entryTypes["error"]
    assert "boom" in result.readable_output


def test_entry_point_without_any_instance_returns_the_failure_in_one_call(mocker):
    setup_demisto(mocker, {}, {})
    result = module.search_and_delete_email(dict(ENTRY_ARGS))[0]
    assert "No enabled instance" in result.readable_output
