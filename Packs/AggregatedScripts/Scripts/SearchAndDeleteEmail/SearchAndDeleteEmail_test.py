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
    vendor = module.new_vendor_state(key, brand, instance)
    return {
        "version": module.STATE_VERSION,
        "deadline": CLOCK.now + params.timeout,
        "since": params.since.isoformat(),
        "command_trace": [],
        "vendors": [vendor],
    }


def drive_vendor(params: SearchParams, key: str, brand: str, instance: str, **kwargs: Any) -> Run:
    return drive(params, single_vendor_state(params, key, brand, instance), **kwargs)


def run_vendor(params: SearchParams, key: str, brand: str, instance: str) -> module.VendorResult:
    return drive_vendor(params, key, brand, instance).results[0]


def run_all(params: SearchParams) -> list[module.VendorResult]:
    return drive(params).results


# Helpers to access unified output structures
def outputs_of(entry: Any) -> dict[str, Any]:
    """Returns the context outputs of a ``CommandResults`` entry, typed as a dict."""
    assert isinstance(entry.outputs, dict)
    return entry.outputs


def get_outputs(params: SearchParams, results: list[module.VendorResult]) -> dict[str, Any]:
    return outputs_of(module.build_command_results(params, results)[0])


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


def test_parse_args_defaults(mocker):
    setup_demisto(mocker, {}, {})
    params = module.parse_args({"operation": OPERATION_SEARCH_ONLY, "subject": "Invoice", "target_mailbox": "a@example.com"})
    assert params.delete_type == DELETE_SOFT
    assert params.mailbox_scope == SCOPE_SPECIFIC
    assert not params.retrieve_files
    assert not params.verify_deletion
    assert not params.delete
    assert (datetime.now(UTC) - params.since).total_seconds() == pytest.approx(3600, abs=5)


@pytest.mark.parametrize("value, expected", [("true", True), ("false", False), (None, False), ("", False)])
def test_parse_args_verify_deletion(mocker, value, expected):
    setup_demisto(mocker, {}, {})
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
def test_parse_args_invalid(mocker, args):
    setup_demisto(mocker, {}, {})
    with pytest.raises(module.DemistoException):
        module.parse_args(args)


def test_parse_args_all_mailboxes_does_not_require_target_mailbox(mocker):
    setup_demisto(mocker, {}, {})
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
    assert 'rfc822msgid:"abc@x"' in query
    assert "subject" not in query
    assert f"after:{int(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC).timestamp())}" in query


def test_gmail_query_subject_and_sender():
    query = module.build_gmail_query(make_params(sender_address="bad@evil.com"))
    assert 'subject:"Invoice"' in query
    assert 'from:"bad@evil.com"' in query


def test_escape_quoted():
    assert module.escape_quoted('a"b\\c') == 'a\\"b\\\\c'
    assert module.escape_quoted("plain") == "plain"


INJECTED_SUBJECT = 'x" OR subject:"'
INJECTED_SENDER = 'evil\\" OR from:"'


def test_gmail_query_keeps_quotes_and_backslashes_inside_the_value():
    query = module.build_gmail_query(make_params(subjects=[INJECTED_SUBJECT], sender_address=INJECTED_SENDER))
    assert '(subject:"x\\" OR subject:\\"")' in query
    assert 'from:"evil\\\\\\" OR from:\\""' in query
    message_query = module.build_gmail_query(make_params(internet_message_ids=['<a"b@x>']))
    assert '(rfc822msgid:"a\\"b@x")' in message_query


def test_graph_mail_filter_escapes_quotes():
    assert "contains(subject,'It''s')" in module.build_graph_mail_filter(make_params(subjects=["It's"]))


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
    assert "(Subject" not in query_single


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


def gmail_split_entry() -> dict[str, Any]:
    """One entry per batch of accounts that gmail-search-all-mailboxes returns above 500 accounts (no emails)."""
    return {
        "Type": entryTypes["note"],
        "Contents": "",
        "ContentsFormat": "markdown",
        "HumanReadable": "Searching mailboxes, please wait...",
    }


def test_gmail_all_mailboxes_split_into_background_searches_is_an_error(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search-all-mailboxes": [gmail_split_entry(), gmail_split_entry()]})
    result = run_vendor(make_params(mailbox_scope=SCOPE_ALL), "gmail", "Gmail", "Gmail")
    assert result.errors == [
        "Gmail split the all-mailboxes search into background sub-searches (more than 500 accounts), "
        "so the results are not available to this script. Use specific mailboxes or another brand."
    ]
    assert (result.total_found, result.total_deleted) == (0, 0)
    assert not result.success
    assert len(fake.called("gmail-search-all-mailboxes")) == 1
    assert not fake.called("gmail-delete-mail")


def test_gmail_all_mailboxes_below_500_accounts_is_not_an_error(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search-all-mailboxes": [entry({"Gmail": [GMAIL_ITEM]})]})
    result = run_vendor(make_params(mailbox_scope=SCOPE_ALL, operation=OPERATION_SEARCH_ONLY), "gmail", "Gmail", "Gmail")
    assert result.success
    assert result.total_found == 1
    assert len(fake.called("gmail-search-all-mailboxes")) == 1


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
    fake = setup_demisto(mocker, {"GraphMail": "O365 Outlook Mail (Using Graph API)"}, {})
    result = run_vendor(make_params(mailbox_scope=SCOPE_ALL), "msgraph_mail", "O365", "GraphMail")
    assert not result.success
    assert "can not search all mailboxes" in result.errors[0]
    assert not fake.calls


def test_graph_mail_ops_all_mailboxes_raises_a_demisto_exception():
    result = vendor_result("Microsoft Graph Mail", "MicrosoftGraphMail")
    with pytest.raises(module.DemistoException, match="Microsoft Graph Mail can not search all mailboxes"):
        module.graph_mail_ops(make_params(mailbox_scope=SCOPE_ALL), "GraphMail", result)


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
def test_run_all_reports_a_partial_failure(mocker):
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

    outputs = outputs_of(command_results)
    assert outputs["TotalFound"] == 0
    assert len(outputs["EmailData"]) == 2
    assert all(c["Success"] is False for c in outputs["EmailData"])


def test_new_state_without_any_instance_raises(mocker):
    setup_demisto(mocker, {}, {})
    with pytest.raises(module.DemistoException, match=r"^No enabled instance was found for the requested brands\.$"):
        module.new_state(make_params())


def test_no_instances_returns_failure_entry(mocker):
    setup_demisto(mocker, {}, {})
    params = make_params()
    (command_result,) = module.failure_results(params, module.DemistoException("No enabled instance was found."))
    assert command_result.entry_type == entryTypes["error"]
    email_data = outputs_of(command_result)["EmailData"]
    assert email_data[0]["Success"] is False
    assert "No enabled instance" in email_data[0]["Reason"]


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

    # It should be a NOTE, not an ERROR: the object_id lookup flagged the email as not found
    assert results[0].additional["NotFound"] is True
    assert command_results.entry_type == entryTypes["note"]
    assert "The operation failed for all the integrations" not in command_results.readable_output


def test_not_found_text_in_a_search_error_is_a_hard_failure(mocker):
    """Only object_id lookups set the structured NotFound flag: a search error that mentions 404 is still a failure."""
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": [error_entry("HttpError 404: user not found")]})
    params = make_params(operation=OPERATION_SEARCH_ONLY)
    results = run_all(params)
    assert "NotFound" not in results[0].additional
    command_results = module.build_command_results(params, results)[0]
    assert command_results.entry_type == entryTypes["error"]
    assert "The operation failed for all the integrations (Gmail)." in command_results.readable_output


def test_object_id_lookup_other_errors_are_not_flagged_as_not_found(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-get-mail": [error_entry("HttpError 403: insufficient permissions")]})
    params = make_params(operation=OPERATION_SEARCH_ONLY, object_id="m1")
    results = run_all(params)
    assert "NotFound" not in results[0].additional
    assert module.build_command_results(params, results)[0].entry_type == entryTypes["error"]


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"errors": ["boom"]}, True),
        ({"errors": ["HttpError 404"], "additional": {"NotFound": True}}, False),
        ({"errors": ["HttpError 404"]}, True),  # the error text alone is not enough
        ({"errors": ["boom"], "total_found": 1}, False),
        ({}, False),
    ],
)
def test_is_hard_failure_uses_the_structured_flag(overrides, expected):
    assert module.is_hard_failure(vendor_result(**overrides)) is expected


def test_all_failed_message_lists_the_brands_of_the_results_when_no_brands_were_given(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail", "Gmail2": "Gmail", "EWS": "EWS v2"},
        {"gmail-search": [error_entry("g down")], "ews-search-mailboxes": [error_entry("e down")]},
    )
    params = make_params(operation=OPERATION_SEARCH_ONLY, brands=[])
    hr = module.build_command_results(params, run_all(params))[0].readable_output
    assert "The operation failed for all the integrations (Gmail, EWS v2)." in hr  # deduplicated, never "()"
    assert "()" not in hr


def test_all_failed_message_falls_back_to_the_vendor_name():
    failure = module.VendorResult(vendor="None", brand="", instance="", errors=["No enabled instance"])
    hr = module.build_command_results(make_params(), [failure])[0].readable_output
    assert "The operation failed for all the integrations (None)." in hr


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


def test_verification_gmail_object_id_trashed_message_counts_as_deleted(mocker):
    """gmail-get-mail still returns a trashed message: its TRASH label (a list in gmail-get-mail) means deleted."""
    trashed = {**GMAIL_ITEM, "Labels": ["INBOX", "TRASH"]}
    fake = setup_demisto(
        mocker,
        {"Gmail": "Gmail"},
        {"gmail-get-mail": sequence([entry({"Gmail": [{**GMAIL_ITEM, "Labels": ["INBOX"]}]})], [entry({"Gmail": [trashed]})])},
    )
    params = make_params(verify_deletion=True, object_id="m1", brands=["Gmail"])
    run = drive_vendor(params, "gmail", "Gmail", "Gmail")
    result = run.results[0]
    assert len(fake.called("gmail-get-mail")) == 2
    assert run.visited() == ["start", "verify", "done"]  # verified on the first verification tick
    assert result.emails[0]["DeletionVerified"] is True
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)
    assert result.errors == []


def test_verification_gmail_object_id_message_without_trash_label_stays_unverified(mocker):
    mocker.patch.object(module, "VERIFICATION_TIMEOUT_SECONDS", 0)
    still_there = [entry({"Gmail": [{**GMAIL_ITEM, "Labels": "INBOX, UNREAD"}]})]
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-get-mail": still_there})
    result = run_vendor(make_params(verify_deletion=True, object_id="m1", brands=["Gmail"]), "gmail", "Gmail", "Gmail")
    assert result.emails[0]["DeletionVerified"] is False
    assert (result.total_deleted, result.total_failed) == (0, 1)


def test_gmail_search_label_csv_with_trash_is_parsed():
    assert module.gmail_to_email({**GMAIL_ITEM, "Labels": "INBOX, TRASH"})["Trashed"] is True
    assert module.gmail_to_email({**GMAIL_ITEM, "Labels": "INBOX"})["Trashed"] is False
    assert module.gmail_to_email(GMAIL_ITEM)["Trashed"] is False


def test_verification_graph_mail_object_id_not_found_is_verified(mocker):
    item = {"ID": "g1", "UserID": "a@example.com", "Subject": "Invoice", "ReceivedTime": "t"}
    fake = setup_demisto(
        mocker,
        {"GraphMail": "MicrosoftGraphMail"},
        {
            "msgraph-mail-get-email": sequence(
                [entry({"MSGraphMail": item})],
                [error_entry("Error in API call [404] - Not Found\n{'error': {'code': 'ErrorItemNotFound'}}")],
            )
        },
    )
    params = make_params(verify_deletion=True, object_id="g1", brands=["MicrosoftGraphMail"])
    result = run_vendor(params, "msgraph_mail", "MicrosoftGraphMail", "GraphMail")
    assert len(fake.called("msgraph-mail-get-email")) == 2
    assert result.emails[0]["DeletionVerified"] is True
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)
    assert result.errors == []
    assert "NotFound" not in result.additional  # the not-found during verification is not a "not found" search result


def test_verification_ews_object_id_not_found_is_verified(mocker):
    item = {"itemId": "i1", "mailbox": "a@example.com", "subject": "Invoice"}
    setup_demisto(
        mocker,
        {"EWS": "EWS v2"},
        {
            "ews-get-items": sequence(
                [entry({"EWS.Items": [item]})],
                [error_entry("One or more items were not found/malformed. Could not find the following IDs: {'i1'}")],
            )
        },
    )
    result = run_vendor(make_params(verify_deletion=True, object_id="i1", brands=["EWS v2"]), "ews", "EWS v2", "EWS")
    assert result.emails[0]["DeletionVerified"] is True
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)
    assert result.errors == []


def test_verification_object_id_other_lookup_error_is_not_treated_as_deleted(mocker):
    item = {"itemId": "i1", "mailbox": "a@example.com", "subject": "Invoice"}
    lookups = sequence([entry({"EWS.Items": [item]})], [error_entry("access denied")])
    setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-get-items": lookups})
    result = run_vendor(make_params(verify_deletion=True, object_id="i1", brands=["EWS v2"]), "ews", "EWS v2", "EWS")
    assert result.emails[0].get("DeletionVerified") is None
    assert "Failed verifying the deletion" in result.errors[0]


def test_ews_object_id_not_found_on_the_first_lookup_is_flagged_not_found(mocker):
    setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-get-items": [error_entry("One or more items were not found/malformed.")]})
    params = make_params(operation=OPERATION_SEARCH_ONLY, object_id="i1", brands=["EWS v2"])
    result = run_vendor(params, "ews", "EWS v2", "EWS")
    assert result.additional["NotFound"] is True
    assert module.build_command_results(params, [result])[0].entry_type == entryTypes["note"]


def test_soft_delete_moved_copy_is_not_counted_or_deleted_again(mocker):
    """Round 1 is capped (saturated) and soft deletes m1; round 2 returns the moved copy in Deleted Items with a NEW ID."""
    original = module.graph_mail_to_email({**GRAPH_MAIL_ITEM, "ID": "AAMk-1", "UserID": "a@example.com"})
    moved_copy = module.graph_mail_to_email({**GRAPH_MAIL_ITEM, "ID": "AAMk-moved", "UserID": "a@example.com"})
    rounds = iter([([original], True), ([moved_copy], False)])
    deleted: list[str] = []
    result = module.VendorResult(vendor="Microsoft Graph Mail", brand="MicrosoftGraphMail", instance="GraphMail")
    ops = module.EmailOps(lambda: next(rounds), lambda email: deleted.append(email["ObjectID"]), lambda email: [])
    module.search_and_delete(make_params(), result, ops)
    assert deleted == ["AAMk-1"]  # the moved copy is not deleted again (which would be a hard delete)
    assert [email["ObjectID"] for email in result.emails] == ["AAMk-1"]
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)


def test_soft_delete_moved_copy_two_rounds_end_to_end_graph_mail(mocker):
    item = {**GRAPH_MAIL_ITEM, "UserID": "a@example.com"}
    full_page = [
        {**item, "ID": f"g{index}", "InternetMessageID": f"<m{index}@x>"} for index in range(module.GRAPH_MAIL_PAGE_SIZE)
    ]
    moved = [{**email, "ID": f"{email['ID']}-moved"} for email in full_page]

    def list_emails(args):
        if not fake.called("msgraph-mail-delete-email"):  # round 1: capped at the maximum number of pages
            return [entry({"MSGraphMail": full_page})]
        return [entry({"MSGraphMail": moved})]  # round 2: only the moved copies (new IDs) are left

    mocker.patch.object(module, "GRAPH_MAIL_MAX_PAGES", 1)
    fake = setup_demisto(mocker, {"GraphMail": "MicrosoftGraphMail"}, {"msgraph-mail-list-emails": list_emails})
    result = run_vendor(make_params(), "msgraph_mail", "MicrosoftGraphMail", "GraphMail")
    assert len(fake.called("msgraph-mail-list-emails")) == 2
    assert len(fake.called("msgraph-mail-delete-email")) == module.GRAPH_MAIL_PAGE_SIZE
    assert all(not call["message_id"].endswith("-moved") for call in fake.called("msgraph-mail-delete-email"))
    assert (result.total_found, result.total_deleted) == (module.GRAPH_MAIL_PAGE_SIZE, module.GRAPH_MAIL_PAGE_SIZE)


def test_emails_without_internet_message_id_are_not_deduplicated_by_it():
    first = module.make_email(object_id="i1", mailbox="a@example.com")
    second = module.make_email(object_id="i2", mailbox="a@example.com")
    rounds = iter([([first], True), ([second], False)])
    result = module.VendorResult(vendor="EWS on-prem", brand="EWS v2", instance="EWS")
    module.search_and_delete(make_params(), result, module.EmailOps(lambda: next(rounds), lambda email: None, lambda email: []))
    assert result.total_found == 2


def test_same_internet_message_id_in_another_mailbox_is_still_processed():
    first = module.make_email(object_id="i1", mailbox="a@example.com", internet_message_id="<m@x>")
    second = module.make_email(object_id="i2", mailbox="b@example.com", internet_message_id="<m@x>")
    rounds = iter([([first], True), ([second], False)])
    result = module.VendorResult(vendor="EWS on-prem", brand="EWS v2", instance="EWS")
    module.search_and_delete(make_params(), result, module.EmailOps(lambda: next(rounds), lambda email: None, lambda email: []))
    assert result.total_found == 2


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
    outputs = outputs_of(entry)

    # Check outputs context
    assert "EmailData" in outputs
    assert outputs["TotalFound"] == 1
    assert outputs["TotalDeleted"] == 0
    assert outputs["TotalFailed"] == 0

    # Check table structure in readable output
    hr = entry.readable_output
    assert "|Brand|Mailbox|ID|Subject|From|To|Timestamp|Operation|Success|Reason|" in hr
    assert (
        "| Gmail | a@example.com | m1 | Invoice | bad@evil.com | a@example.com "
        "| Mon, 2 Jan 2026 03:04:05 +0000 | Search Only | true |  |"
    ) in hr
    assert "**Total found:** 1 | **Total deleted:** 0 | **Total failed:** 0" in hr


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


@pytest.mark.parametrize(
    "vendor, message",
    [
        ({"key": "evil_vendor", "stage": "start"}, "unknown vendor 'evil_vendor'"),
        ({"key": "gmail", "stage": "drop_everything"}, "unknown stage 'drop_everything'"),
        ({"stage": "start"}, "unknown vendor 'None'"),
        ("not-an-object", "every vendor must be an object"),
        ({"key": "gmail", "stage": "verify", "verify_started": None}, "bad 'verify_started' of vendor 'gmail'"),
        ({"key": "gmail", "stage": "verify"}, "bad 'verify_started' of vendor 'gmail'"),
        ({"key": "gmail", "stage": "start", "verify_started": "soon"}, "bad 'verify_started' of vendor 'gmail'"),
        ({"key": "gmail", "stage": "verify", "verify_started": True}, "bad 'verify_started' of vendor 'gmail'"),
    ],
)
def test_load_state_rejects_unknown_vendor_keys_and_stages(vendor, message):
    state = {"version": module.STATE_VERSION, "vendors": [vendor]}
    with pytest.raises(module.DemistoException, match=re.escape(f"The polling state is invalid: {message}")):
        module.load_state({"state": json.dumps(state)})


def test_load_state_rejects_vendors_that_are_not_a_list():
    with pytest.raises(module.DemistoException, match="'vendors' must be a list"):
        module.load_state({"state": json.dumps({"version": module.STATE_VERSION, "vendors": {"key": "gmail"}})})


def test_load_state_accepts_every_known_vendor_and_stage(mocker):
    setup_demisto(mocker, {}, {})
    vendors = [
        {"key": key, "stage": stage, "verify_started": START_EPOCH if stage == module.STAGE_VERIFY else None}
        for key in module.VENDORS
        for stage in sorted(module.VALID_STAGES)
    ]
    state = {"version": module.STATE_VERSION, "vendors": vendors}
    assert module.load_state({"state": json.dumps(state)}) == state


def test_run_command_raises_when_budget_is_exhausted(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    mocker.patch.object(module, "_DEADLINE", START_EPOCH + 100)
    mocker.patch.object(module, "_TIMEOUT_SECONDS", 30)
    CLOCK.advance(101)
    with pytest.raises(module.DemistoException, match="Timed out: the 30 seconds timeout was reached"):
        module.run_command("gmail-search", {}, "Gmail")
    assert not fake.calls


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
    assert seen[0]["verify_started"] == START_EPOCH
    assert set(seen[0]) == {"key", "instance", "stage", "result", "verify_started"}
    assert module.load_state({"state": json.dumps(single_vendor_state(make_params(), "gmail", "Gmail", "Gmail"))})
    assert run.results[0].emails[0]["DeletionVerified"] is True


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
# The polling entry point: every run is one tick, intermediate runs return a ScheduledCommand
# ----------------------------------------------------------------------------------------------------------------------
ENTRY_ARGS = {
    "operation": OPERATION_SEARCH_ONLY,
    "subject": "Invoice",
    "target_mailbox": "a@example.com",
    "timeout": "1800",
    "verbose": "true",
}
# Gmail with verification enabled: the run after the delete polls the verification search.
GMAIL_POLL_ARGS = {**ENTRY_ARGS, "operation": OPERATION_SEARCH_AND_DELETE, "verify_deletion": "true", "brands": "Gmail"}


def intermediate(response: Any) -> module.CommandResults:
    """The single ``CommandResults`` of an intermediate run (it carries the scheduled command)."""
    assert isinstance(response, module.CommandResults)
    assert isinstance(response.scheduled_command, module.ScheduledCommand)
    return response


def scheduled_args(response: Any) -> dict[str, Any]:
    return intermediate(response).scheduled_command._args  # type: ignore[union-attr]


def final(response: Any) -> module.CommandResults:
    """The single ``CommandResults`` of a final run (a list built by ``build_command_results``)."""
    assert isinstance(response, list)
    (result,) = response
    assert result.scheduled_command is None
    return result


def poll_until_done(args: dict[str, Any], max_calls: int = 40) -> list[Any]:
    """Calls the script like the platform does: the next call gets the scheduled args of the previous response."""
    responses: list[Any] = []
    for _ in range(max_calls):
        module.COMMAND_TRACE.clear()  # every scheduled run is a new process
        response = module.search_and_delete_email(args)
        responses.append(response)
        if isinstance(response, list):
            return responses
        args = json.loads(json.dumps(scheduled_args(response)))
        CLOCK.advance(module.POLL_INTERVAL_SECONDS)
    raise AssertionError("The script kept polling")


def test_entry_point_first_call_schedules_the_next_run_with_the_original_args_and_a_json_state(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    response = intermediate(module.search_and_delete_email(dict(GMAIL_POLL_ARGS)))
    scheduled = response.scheduled_command
    assert scheduled._command == "SearchAndDeleteEmail"  # type: ignore[union-attr]
    assert scheduled._next_run == "20"  # type: ignore[union-attr]
    assert module.POLL_INTERVAL_SECONDS == 20
    poll_args = scheduled._args  # type: ignore[union-attr]
    assert {key: poll_args[key] for key in GMAIL_POLL_ARGS} == GMAIL_POLL_ARGS  # the script's own `timeout` is kept
    assert poll_args["hide_polling_output"] is True
    state = json.loads(poll_args["state"])
    assert state["version"] == module.STATE_VERSION == 1
    assert state["deadline"] == START_EPOCH + 1800
    assert [(v["key"], v["stage"], v["verify_started"]) for v in state["vendors"]] == [("gmail", "verify", START_EPOCH)]
    assert all(set(v) == {"key", "instance", "stage", "result", "verify_started"} for v in state["vendors"])
    assert scheduled._timeout == str(1800 + module.SCHEDULE_MARGIN_SECONDS)  # type: ignore[union-attr]
    assert response.readable_output == "* Gmail: verifying the deletion"


def test_entry_point_checks_that_scheduled_commands_are_supported(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {})
    mocker.patch.object(
        module.ScheduledCommand, "raise_error_if_not_supported", side_effect=module.DemistoException("not supported")
    )
    with pytest.raises(module.DemistoException, match="not supported"):
        module.search_and_delete_email(dict(GMAIL_POLL_ARGS))


def test_entry_point_scheduled_timeout_follows_the_remaining_budget(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    first = module.search_and_delete_email(dict(GMAIL_POLL_ARGS))
    CLOCK.advance(100)
    second = intermediate(module.search_and_delete_email(scheduled_args(first)))
    assert second.scheduled_command._timeout == str(1700 + module.SCHEDULE_MARGIN_SECONDS)  # type: ignore[union-attr]


def test_entry_point_progress_is_only_published_on_a_stage_change(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": sequence(GMAIL_FOUND, GMAIL_FOUND, GMAIL_FOUND, GMAIL_EMPTY)})
    *polls, last = poll_until_done(dict(GMAIL_POLL_ARGS))
    outputs = [intermediate(poll).readable_output for poll in polls]
    assert outputs == ["* Gmail: verifying the deletion", "", ""]  # idle polls with hide_polling_output produce no text
    result = final(last)
    assert (outputs_of(result)["TotalFound"], outputs_of(result)["TotalDeleted"], outputs_of(result)["TotalFailed"]) == (1, 1, 0)
    assert outputs_of(result)["EmailData"][0]["AdditionalFields"]["Verified"] is True
    assert result.entry_type == module.EntryType.NOTE


def test_entry_point_verbose_command_trace_survives_the_ticks(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": sequence(GMAIL_FOUND, GMAIL_FOUND, GMAIL_EMPTY)})
    *_, last = poll_until_done(dict(GMAIL_POLL_ARGS))
    hr = final(last).readable_output
    assert "#### Executed commands" in hr
    assert hr.count("gmail-delete-mail") == 1  # the command of the first tick is listed together with the later ones
    assert hr.count("gmail-search ") == 3


def test_entry_point_non_verbose_state_carries_no_trace(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    response = module.search_and_delete_email({**GMAIL_POLL_ARGS, "verbose": "false"})
    assert json.loads(scheduled_args(response)["state"])["command_trace"] == []


def test_entry_point_search_window_is_fixed_on_the_first_tick(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    poll_args = scheduled_args(module.search_and_delete_email(dict(GMAIL_POLL_ARGS)))
    since = json.loads(poll_args["state"])["since"]
    CLOCK.advance(60)
    second = module.search_and_delete_email(poll_args)
    assert json.loads(scheduled_args(second)["state"])["since"] == since




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
    first = intermediate(module.search_and_delete_email(dict(args)))
    assert len(PUBLISHED) == 1
    assert PUBLISHED[0]["Type"] == entryTypes["file"]
    raw_state = scheduled_args(first)["state"]
    vendor = json.loads(raw_state)["vendors"][0]
    assert vendor["result"]["file_entries"] == []
    assert '"EntryContext"' not in raw_state  # the file entry itself is not in the state ...
    assert vendor["result"]["emails"][0]["Attachments"] == {"a.txt": "abc"}  # ... only the name -> SHA256 map
    assert vendor["stage"] == "verify"
    last = final(poll_until_done(scheduled_args(first))[-1])
    assert len(PUBLISHED) == 1  # published once, in the retrieval tick
    assert outputs_of(last)["EmailData"][0]["Attachments"] == {"a.txt": "abc"}
    assert outputs_of(last)["EmailData"][0]["AdditionalFields"]["Verified"] is True




def test_entry_point_invalid_arguments_are_reported_as_such(mocker):
    setup_demisto(mocker, {}, {})
    with pytest.raises(module.InvalidArgumentsError, match="operation must be"):
        module.search_and_delete_email({**ENTRY_ARGS, "operation": "Delete"})


def test_entry_point_unexpected_failure_returns_the_failure_results_and_stops_polling(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {})
    mocker.patch.object(module, "new_state", side_effect=module.DemistoException("boom"))
    result = final(module.search_and_delete_email(dict(ENTRY_ARGS)))

    assert result.entry_type == entryTypes["error"]
    assert "boom" in result.readable_output


def test_entry_point_without_any_instance_returns_the_failure_in_one_call(mocker):
    setup_demisto(mocker, {}, {})
    result = final(module.search_and_delete_email(dict(ENTRY_ARGS)))
    assert "No enabled instance" in result.readable_output


# ----------------------------------------------------------------------------------------------------------------------
# scheduled_timeout and the intermediate-run CommandResults
# ----------------------------------------------------------------------------------------------------------------------
def test_schedule_margin_is_two_poll_intervals():
    assert module.SCHEDULE_MARGIN_SECONDS == 2 * module.POLL_INTERVAL_SECONDS == 40


@pytest.mark.parametrize(
    "remaining, expected",
    [
        (1800, 1800 + 40),
        (100.9, 100 + 40),  # the remaining budget is truncated to whole seconds
        (0, 40),
        (-50, 40),  # the deadline passed: floored at the margin, never negative
        (-10**6, 40),
    ],
)
def test_scheduled_timeout_is_the_remaining_budget_plus_the_margin(remaining, expected):
    assert module.scheduled_timeout({"deadline": CLOCK.now + remaining}) == expected


def verifying_gmail_state() -> dict[str, Any]:
    """A Gmail vendor in the ``verify`` stage whose deleted email is still returned by the search."""
    state = single_vendor_state(make_params(), "gmail", "Gmail", "Gmail")
    vendor = state["vendors"][0]
    vendor["stage"] = module.STAGE_VERIFY
    vendor["verify_started"] = CLOCK.now
    vendor["result"].update({"emails": [found_email("m1", Deleted=True)], "total_found": 1, "total_deleted": 1})
    return state


@pytest.mark.parametrize("hide, expected", [(True, ""), ("true", ""), (None, module.POLL_MESSAGE), (False, module.POLL_MESSAGE)])
def test_intermediate_run_without_a_stage_change_hides_the_poll_message_only_when_asked(mocker, hide, expected):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    args: dict[str, Any] = {**GMAIL_POLL_ARGS, "state": module.dump_state(verifying_gmail_state())}
    if hide is not None:
        args["hide_polling_output"] = hide
    response = intermediate(module.search_and_delete_email(args))
    assert response.readable_output == expected
    next_args = scheduled_args(response)
    assert next_args["hide_polling_output"] is True
    assert json.loads(next_args["state"])["vendors"][0]["stage"] == "verify"


def test_polling_results_builds_the_scheduled_command():
    state = {**verifying_gmail_state(), "deadline": CLOCK.now + 500}
    args = {"operation": OPERATION_SEARCH_AND_DELETE, "subject": "Invoice"}
    response = module.polling_results(args, state, ["Gmail: verifying the deletion", "EWS on-prem: done"])
    assert response.readable_output == "* Gmail: verifying the deletion\n* EWS on-prem: done"
    scheduled = response.scheduled_command
    assert isinstance(scheduled, module.ScheduledCommand)
    assert scheduled._command == "SearchAndDeleteEmail"
    assert scheduled._next_run == "20"
    assert scheduled._timeout == str(500 + module.SCHEDULE_MARGIN_SECONDS)
    assert scheduled._args == {**args, "state": module.dump_state(state), "hide_polling_output": True}
    assert args == {"operation": OPERATION_SEARCH_AND_DELETE, "subject": "Invoice"}  # the caller's args are not mutated


def test_polling_results_shows_stage_changes_even_when_hidden():
    response = module.polling_results({"hide_polling_output": True}, verifying_gmail_state(), ["Gmail: done"])
    assert response.readable_output == "* Gmail: done"


# ----------------------------------------------------------------------------------------------------------------------
# Multi-vendor runs (Gmail + EWS)
# ----------------------------------------------------------------------------------------------------------------------
GMAIL_EWS_MODULES = {"Gmail": "Gmail", "EWS": "EWS v2"}
EWS_ITEM = {"itemId": "i1", "mailbox": "a@example.com", "subject": "Invoice"}


def test_gmail_keeps_verifying_while_ews_is_done_and_ews_is_preserved(mocker):
    fake = setup_demisto(
        mocker,
        GMAIL_EWS_MODULES,
        {
            "gmail-search": sequence(GMAIL_FOUND, GMAIL_FOUND, GMAIL_EMPTY),
            "ews-search-mailboxes": [entry({"EWS.Items": [EWS_ITEM]})],
            "ews-get-items": [],
            "ews-delete-items": [error_entry("ews denied")],  # nothing deleted: EWS does not verify
        },
    )
    params = make_params(verify_deletion=True)
    run = drive(params)
    assert run.visited(0) == ["start", "verify", "verify", "done"]
    assert run.visited(1) == ["start", "done", "done", "done"]
    assert run.messages[0] == ["Gmail: verifying the deletion", "EWS on-prem: done"]
    assert run.messages[1] == []
    assert run.messages[2] == ["Gmail: done"]
    assert len(fake.called("ews-search-mailboxes")) == 1  # a finished vendor is never run again
    gmail, ews = run.results
    assert (gmail.total_found, gmail.total_deleted, gmail.emails[0]["DeletionVerified"]) == (1, 1, True)
    assert (ews.total_found, ews.total_deleted, ews.total_failed) == (1, 0, 1)
    assert "ews denied" in ews.emails[0]["Reason"]
    outputs = get_outputs(params, run.results)
    assert (outputs["TotalFound"], outputs["TotalDeleted"], outputs["TotalFailed"]) == (2, 1, 1)
    assert [(item["Brand"], item["AdditionalFields"]["ObjectID"]) for item in outputs["EmailData"]] == [
        ("Gmail", "m1"),
        ("EWS v2", "i1"),
    ]


def test_entry_point_gmail_verifying_and_ews_done_across_two_runs(mocker):
    fake = setup_demisto(
        mocker,
        GMAIL_EWS_MODULES,
        {"gmail-search": sequence(GMAIL_FOUND, GMAIL_EMPTY), "ews-search-mailboxes": [entry({"EWS.Items": []})]},
    )
    args = {**GMAIL_POLL_ARGS, "brands": "Gmail,EWS v2"}
    first = intermediate(module.search_and_delete_email(dict(args)))
    assert first.readable_output == "* Gmail: verifying the deletion\n* EWS on-prem: done"
    state = json.loads(scheduled_args(first)["state"])
    assert [(v["key"], v["stage"]) for v in state["vendors"]] == [("gmail", "verify"), ("ews", "done")]
    assert [v["verify_started"] for v in state["vendors"]] == [START_EPOCH, None]

    CLOCK.advance(module.POLL_INTERVAL_SECONDS)
    second = final(module.search_and_delete_email(json.loads(json.dumps(scheduled_args(first)))))
    outputs = outputs_of(second)
    assert (outputs["TotalFound"], outputs["TotalDeleted"], outputs["TotalFailed"]) == (1, 1, 0)
    assert [item["Brand"] for item in outputs["EmailData"]] == ["Gmail", "EWS v2"]
    assert outputs["EmailData"][0]["AdditionalFields"]["Verified"] is True
    assert outputs["EmailData"][1]["Success"] is True  # EWS found nothing: a successful status row
    assert len(fake.called("ews-search-mailboxes")) == 1
    assert len(fake.called("gmail-search")) == 2


def test_one_vendor_failing_does_not_stop_the_other(mocker):
    setup_demisto(
        mocker,
        GMAIL_EWS_MODULES,
        {"gmail-search": [error_entry("gmail down")], "ews-search-mailboxes": [entry({"EWS.Items": [EWS_ITEM]})]},
    )
    gmail, ews = drive(make_params(operation=OPERATION_SEARCH_ONLY)).results
    assert not gmail.success
    assert "gmail down" in gmail.errors[0]
    assert ews.success
    assert ews.total_found == 1


def test_unexpected_exception_of_a_vendor_is_recorded_and_does_not_stop_the_other_vendor(mocker):
    mocker.patch.object(module, "gmail_search", side_effect=ValueError("kaboom"))
    setup_demisto(mocker, GMAIL_EWS_MODULES, {"ews-search-mailboxes": [entry({"EWS.Items": [EWS_ITEM]})]})
    gmail, ews = drive(make_params(operation=OPERATION_SEARCH_ONLY)).results
    assert gmail.errors == ["kaboom"]
    assert ews.total_found == 1


# ----------------------------------------------------------------------------------------------------------------------
# Microsoft Graph (Graph Security) is no longer supported
# ----------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("brand", ["Microsoft Graph", "Microsoft Graph Security", "msgraph_security"])
def test_resolve_instances_rejects_microsoft_graph_brand(mocker, brand):
    setup_demisto(mocker, {"MsGraph": "Microsoft Graph"}, {})
    with pytest.raises(
        module.DemistoException,
        match=re.escape(f"Unsupported brand(s): {brand}. Supported brands: Gmail, Microsoft Graph Mail, EWS on-prem."),
    ):
        module.resolve_instances([brand])


def test_resolve_instances_ignores_microsoft_graph_instances_when_no_brand_is_given(mocker):
    setup_demisto(mocker, {"MsGraph": "Microsoft Graph", "Gmail": "Gmail"}, {})
    assert module.resolve_instances([]) == [("gmail", "Gmail", "Gmail")]


def test_entry_point_microsoft_graph_brand_returns_an_error_result(mocker):
    fake = setup_demisto(mocker, {"MsGraph": "Microsoft Graph"}, {})
    result = final(module.search_and_delete_email({**ENTRY_ARGS, "brands": "Microsoft Graph"}))
    assert result.entry_type == entryTypes["error"]
    assert "Unsupported brand(s): Microsoft Graph." in result.readable_output
    assert not fake.calls


def test_entry_point_without_any_instance_returns_an_error_result(mocker):
    setup_demisto(mocker, {}, {})
    result = final(module.search_and_delete_email(dict(ENTRY_ARGS)))
    assert result.entry_type == entryTypes["error"]
    assert "No enabled instance was found for the requested brands." in result.readable_output
    assert outputs_of(result)["EmailData"][0]["Success"] is False


# ----------------------------------------------------------------------------------------------------------------------
# Notes
# ----------------------------------------------------------------------------------------------------------------------
def test_add_note_sets_the_first_note():
    result = vendor_result()
    module.add_note(result, "First.")
    assert result.additional["Note"] == "First."


def test_add_note_appends_with_a_space():
    result = vendor_result()
    module.add_note(result, "First.")
    module.add_note(result, "Second.")
    assert result.additional["Note"] == "First. Second."


def test_add_note_skips_a_duplicate():
    result = vendor_result()
    module.add_note(result, "First.")
    module.add_note(result, "Second.")
    module.add_note(result, "First.")
    assert result.additional["Note"] == "First. Second."


def test_graph_mail_capped_note_and_hard_delete_note_are_both_kept(mocker):
    counter = {"n": 0}

    def always_a_full_new_page(args):
        counter["n"] += 1
        item = {**GRAPH_MAIL_ITEM, "ID": f"g{counter['n']}", "InternetMessageID": f"<m{counter['n']}@x>"}
        return [entry({"MSGraphMail": [item]})]

    mocker.patch.object(module, "GRAPH_MAIL_PAGE_SIZE", 1)
    mocker.patch.object(module, "GRAPH_MAIL_MAX_PAGES", 1)
    mocker.patch.object(module, "MAX_ROUNDS", 2)
    setup_demisto(mocker, {"GraphMail": "MicrosoftGraphMail"}, {"msgraph-mail-list-emails": always_a_full_new_page})
    params = make_params(delete_type=DELETE_HARD)
    result = run_vendor(params, "msgraph_mail", "MicrosoftGraphMail", "GraphMail")
    assert result.total_deleted == 2
    note = result.additional["Note"]
    assert note.startswith("Microsoft Graph Mail can not hard delete, emails were moved to 'Deleted Items'. ")
    assert "The vendor capped the number of returned emails" in note
    assert note.count("can not hard delete") == 1


def test_vendor_notes_lists_one_line_per_vendor_with_a_note():
    with_note = vendor_result(additional={"Note": "Capped."})
    without_note = vendor_result("EWS on-prem", "EWS v2")
    no_brand = module.VendorResult(vendor="Microsoft Graph Mail", brand="", instance="x", additional={"Note": "Soft only."})
    assert module.vendor_notes([with_note, without_note, no_brand]) == (
        "* **Gmail**: Capped.\n* **Microsoft Graph Mail**: Soft only."
    )
    assert module.vendor_notes([without_note]) == ""


def test_readable_output_has_a_notes_section_also_when_emails_were_found():
    result = vendor_result(emails=[found_email()], total_found=1, additional={"Note": "Capped."})
    hr = get_hr(make_params(operation=OPERATION_SEARCH_ONLY), [result])
    assert "| Gmail | a@example.com | m1 |" in hr
    assert hr.endswith("**Total found:** 1 | **Total deleted:** 0 | **Total failed:** 0\n\n**Notes:**\n* **Gmail**: Capped.")


def test_readable_output_has_no_notes_section_without_notes():
    hr = get_hr(make_params(operation=OPERATION_SEARCH_ONLY), [vendor_result(emails=[found_email()], total_found=1)])
    assert "**Notes:**" not in hr


# ----------------------------------------------------------------------------------------------------------------------
# Small helpers and the object_id NotFound flag
# ----------------------------------------------------------------------------------------------------------------------
def test_primary_mailbox():
    assert module.primary_mailbox(module.make_email(object_id="1", mailbox=["a@x", "b@x"])) == "a@x"
    assert module.primary_mailbox(module.make_email(object_id="1", mailbox="")) == ""


def test_object_id_not_found_is_in_the_additional_fields_of_the_vendor_row(mocker):
    setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-get-items": [error_entry("One or more items were not found/malformed.")]})
    params = make_params(operation=OPERATION_SEARCH_ONLY, object_id="i1", brands=["EWS v2"])
    result = run_vendor(params, "ews", "EWS v2", "EWS")
    (row,) = get_email_data(params, [result])
    assert row["AdditionalFields"]["NotFound"] is True
    assert row["AdditionalFields"]["Instance"] == "EWS"
    assert row["Success"] is False  # the error is kept in the row, but the run is not a hard failure
    assert "not found" in row["Reason"]


def test_vendor_step_verify_without_a_deleted_email_ends_the_verification(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    vendor = {**module.new_vendor_state("gmail", "Gmail", "Gmail"), "stage": module.STAGE_VERIFY, "verify_started": CLOCK.now}
    result = vendor_result(emails=[found_email("m1", Deleted=False)])
    assert module.vendor_step(make_params(), vendor, result) == module.STAGE_DONE
    assert len(fake.called("gmail-search")) == 1
