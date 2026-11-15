import re
import time
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
    """The parsed arguments. There is no deadline (``float("inf")``) unless a test passes one."""
    values: dict[str, Any] = {
        "internet_message_ids": [],
        "object_id": "",
        "operation": OPERATION_SEARCH_AND_DELETE,
        "delete_type": DELETE_SOFT,
        "since": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        "subjects": ["Invoice"],
        "sender_address": "",
        "retrieve_files": False,
        "target_mailboxes": ["test@test"],
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
    """Any call to ``time.sleep`` fails the test, the clock is fake and the published entries are captured."""
    mocker.patch("time.sleep", side_effect=forbidden_sleep)
    CLOCK.now = START_EPOCH
    mocker.patch.object(module, "time", SimpleNamespace(time=CLOCK, sleep=forbidden_sleep))
    PUBLISHED.clear()
    mocker.patch.object(module, "return_results", side_effect=PUBLISHED.append)
    module.COMMAND_TRACE.clear()


def setup_demisto(mocker, modules: dict[str, str], responses: dict[str, Any]) -> FakeCommands:
    mocker.patch.object(
        demisto, "getModules", return_value={name: {"brand": brand, "state": "active"} for name, brand in modules.items()}
    )
    fake = FakeCommands(responses)
    mocker.patch.object(demisto, "executeCommand", side_effect=fake)
    return fake


def run_vendor(params: SearchParams, key: str, brand: str, instance: str) -> module.VendorResult:
    """Runs one vendor instance like the entry point does: the whole flow, then the publication of the retrieved files."""
    result = module.run_vendor(params, key, brand, instance)
    module.publish_files(result)
    return result


def run_all(params: SearchParams) -> list[module.VendorResult]:
    """Runs every resolved vendor instance like the entry point does."""
    return [run_vendor(params, key, brand, instance) for key, brand, instance in module.resolve_target_instances(params)]


def final(response: Any) -> module.CommandResults:
    """The single ``CommandResults`` returned by the entry point (never a scheduled command)."""
    assert isinstance(response, list)
    (result,) = response
    assert result.scheduled_command is None
    return result


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
    params = module.parse_args({"operation": OPERATION_SEARCH_ONLY, "subject": "Invoice", "target_mailbox": "test@test"})
    assert params.delete_type == DELETE_SOFT
    assert params.mailbox_scope == SCOPE_SPECIFIC
    assert not params.retrieve_files
    assert not params.delete
    assert (datetime.now(UTC) - params.since).total_seconds() == pytest.approx(3600, abs=5)
    assert params.timeout == module.DEFAULT_TIMEOUT_SECONDS
    assert params.deadline == START_EPOCH + module.DEFAULT_TIMEOUT_SECONDS  # the budget starts when the args are parsed


@pytest.mark.parametrize(
    "args",
    [
        {"operation": "Delete", "subject": "s", "target_mailbox": "test@test"},
        {"operation": OPERATION_SEARCH_ONLY, "subject": "s", "target_mailbox": "test@test", "delete_type": "Maybe"},
        {"operation": OPERATION_SEARCH_ONLY, "subject": "s", "target_mailbox": "test@test", "mailbox_scope": "Some"},
        # An empty filter would match every email in the time frame.
        {"operation": OPERATION_SEARCH_AND_DELETE, "target_mailbox": "test@test"},
        {"operation": OPERATION_SEARCH_ONLY, "subject": "s"},
        # object_id requires a mailbox and exactly one brand.
        {"operation": OPERATION_SEARCH_ONLY, "object_id": "1", "target_mailbox": "test@test"},
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


def test_module_has_no_polling_and_nothing_sleeps():
    assert not hasattr(module, "poll")
    assert not hasattr(module, "start_budget")
    assert not hasattr(module, "polling_results")
    with pytest.raises(AssertionError, match="must never sleep"):
        time.sleep(0)


MALICIOUS_MESSAGE_ID = '<test" OR Received:>=2000-01-01 OR "test@test>'


@pytest.mark.parametrize(
    "message_id",
    [
        MALICIOUS_MESSAGE_ID,
        '<te"st@test>',
        "<te st@test>",
        "<te\\st@test>",
        "<te(st)@test>",
        "<te<st@test>",
        "<test@test> OR <test@test>",
    ],
)
def test_parse_args_rejects_an_unsafe_internet_message_id(message_id):
    with pytest.raises(module.DemistoException, match="Invalid internet_message_id"):
        module.parse_args({**BASE_ARGS, "internet_message_id": message_id})


def test_entry_point_reports_an_unsafe_internet_message_id_as_invalid_arguments(mocker):
    fake = setup_demisto(mocker, {"EWS": "EWS v2"}, {})
    with pytest.raises(module.InvalidArgumentsError, match="Invalid internet_message_id"):
        module.search_and_delete_email({**ENTRY_ARGS, "internet_message_id": MALICIOUS_MESSAGE_ID, "mailbox_scope": SCOPE_ALL})
    assert not fake.calls


@pytest.mark.parametrize("message_id", ["<test+1@test>", "test+1@test", "<CAF=x_y-z.1@test>"])
def test_parse_args_accepts_a_normal_internet_message_id(message_id):
    assert module.parse_args({**BASE_ARGS, "internet_message_id": message_id}).internet_message_ids == [message_id]


@pytest.mark.parametrize("sender", ['test"@test', "test\\@test", "test @test", "test(x)@test", "test@test\tb"])
def test_parse_args_rejects_an_unsafe_sender_address(sender):
    with pytest.raises(module.DemistoException, match="Invalid sender_address"):
        module.parse_args({**BASE_ARGS, "sender_address": sender})


def test_parse_args_accepts_a_plain_sender_address():
    assert module.parse_args({**BASE_ARGS, "sender_address": " test+1@test "}).sender_address == "test+1@test"


# ----------------------------------------------------------------------------------------------------------------------
# Query builders
# ----------------------------------------------------------------------------------------------------------------------
def test_gmail_query_prefers_message_id():
    query = module.build_gmail_query(make_params(internet_message_ids=["<test@test>"], subjects=["Invoice"]))
    assert 'rfc822msgid:"test@test"' in query
    assert "subject" not in query
    assert f"after:{int(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC).timestamp())}" in query


def test_gmail_query_subject_and_sender():
    query = module.build_gmail_query(make_params(sender_address="test@test"))
    assert 'subject:"Invoice"' in query
    assert 'from:"test@test"' in query


def test_quote_phrase_replaces_quotes_and_backslashes_with_a_space():
    assert module.quote_phrase('a"b\\c') == "a b c"
    assert module.quote_phrase("plain") == "plain"


INJECTED_SUBJECT = 'x" OR subject:"'


def test_gmail_query_subject_can_not_break_out_of_the_quotes():
    query = module.build_gmail_query(make_params(subjects=[INJECTED_SUBJECT, 'a\\" OR "b']))
    assert '(subject:"x  OR subject: " OR subject:"a   OR  b")' in query
    assert query.count('"') == 4  # only the quotes that enclose the two phrases


def test_ews_query_subject_and_sender_can_not_break_out_of_the_quotes():
    query = module.build_ews_query(make_params(subjects=[INJECTED_SUBJECT]))
    assert query.startswith('Subject:"x  OR subject: " AND Received:>=')
    assert query.count('"') == 2


def test_graph_mail_filter_escapes_quotes():
    # The doubled single quote (the OData escape) is URL-encoded together with the rest of the value.
    assert "contains(subject,'It%27%27s')" in module.build_graph_mail_filter(make_params(subjects=["It's"]))


def test_graph_mail_filter_url_encodes_the_literal_values():
    """The Graph Mail integration pastes `odata` into the URL as is: `+` must not reach Graph as a (decoded) space."""
    message_filter = module.build_graph_mail_filter(make_params(internet_message_ids=["<test+1@test>", "t&e#s%@test"]))
    assert "(internetMessageId eq '<test%2B1@test>' or internetMessageId eq '<t%26e%23s%25@test>')" in message_filter
    sender_filter = module.build_graph_mail_filter(make_params(subjects=["50% off & more"], sender_address="test+1@test"))
    assert "(contains(subject,'50%25%20off%20%26%20more'))" in sender_filter
    assert "from/emailAddress/address eq 'test%2B1@test'" in sender_filter
    assert sender_filter.startswith("$filter=receivedDateTime ge 2026-01-02T03:04:05Z and ")  # the expression is untouched


def test_ews_query_wraps_a_single_message_id_in_parentheses():
    query = module.build_ews_query(make_params(internet_message_ids=["test@test"]))
    assert query == '(Message-ID:"<test@test>") AND Received:>=2026-01-02'
    assert "Subject" not in query


def test_ews_query_wraps_multiple_message_ids_in_parentheses():
    query = module.build_ews_query(make_params(internet_message_ids=["<test1@test>", "test2@test"]))
    assert query.startswith('(Message-ID:"<test1@test>" OR Message-ID:"<test2@test>") AND ')


def test_ews_query_removes_quotes_and_wraps_in_parens_if_multiple():
    query = module.build_ews_query(make_params(subjects=["sub1", 'su"b2']))
    assert '(Subject:"sub1" OR Subject:"su b2")' in query

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


def test_resolve_target_instances_object_id_counts_distinct_vendors_with_multiple_instances(mocker):
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
    assert module.resolve_target_instances(params) == [
        ("msgraph_mail", "MicrosoftGraphMail", "MSGraphMail_1"),
        ("msgraph_mail", "MicrosoftGraphMail", "MSGraphMail_2"),
    ]


def test_resolve_target_instances_object_id_requires_exactly_one_vendor(mocker):
    setup_demisto(mocker, ALL_BRAND_MODULES, {})
    with pytest.raises(module.DemistoException, match="exactly one brand"):
        module.resolve_target_instances(make_params(brands=["Gmail", "EWS v2"], object_id="obj-1"))


def test_resolve_target_instances_without_any_instance_raises(mocker):
    setup_demisto(mocker, {}, {})
    with pytest.raises(module.DemistoException, match=r"^No enabled instance was found for the requested brands\.$"):
        module.resolve_target_instances(make_params())


# ----------------------------------------------------------------------------------------------------------------------
# Gmail
# ----------------------------------------------------------------------------------------------------------------------
GMAIL_ITEM = {
    "ID": "m1",
    "Mailbox": "test@test",
    "Subject": "Invoice",
    "From": "test1@test",  # differs from the mailbox / recipient, so the From and To columns can be told apart
    "To": "test@test",
    "Headers": [{"Name": "Date", "Value": "Mon, 2 Jan 2026 03:04:05 +0000"}],
    "Body": "<b>hi</b>",
    "Attachments": [{"ID": "att", "Name": "a.txt"}],
}
GMAIL_FOUND = [entry({"Gmail": [GMAIL_ITEM]})]


def sequence(*batches: Any):
    """Returns a command responder that answers call number N with ``batches[N]`` (the last one is repeated)."""
    calls = {"n": 0}

    def respond(args: dict[str, Any]) -> Any:
        batch = batches[min(calls["n"], len(batches) - 1)]
        calls["n"] += 1
        return batch

    return respond


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
    assert len(PUBLISHED) == 1  # the file entry is published by publish_files ...
    assert PUBLISHED[0]["Type"] == entryTypes["file"]
    assert result.file_entries == []  # ... and cleared from the result
    assert fake.called("gmail-delete-mail")[0]["permanent"] == "true"
    # files must be fetched before the email is deleted
    order = [name for name, _ in fake.calls]
    assert order.index("gmail-get-attachments") < order.index("gmail-delete-mail")


def test_gmail_search_only_does_not_delete(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    result = run_vendor(make_params(operation=OPERATION_SEARCH_ONLY), "gmail", "Gmail", "Gmail")
    assert result.total_found == 1
    assert result.total_deleted == 0
    assert not fake.called("gmail-delete-mail")


def test_delete_runs_a_single_search_without_verification(mocker):
    """The deletion is not verified: the search runs once and no Verified field is returned."""
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    params = make_params()
    result = run_vendor(params, "gmail", "Gmail", "Gmail")
    assert len(fake.called("gmail-search")) == 1
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)
    assert "Verified" not in get_email_data(params, [result])[0]["AdditionalFields"]


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
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search-all-mailboxes": GMAIL_FOUND})
    result = run_vendor(make_params(mailbox_scope=SCOPE_ALL, operation=OPERATION_SEARCH_ONLY), "gmail", "Gmail", "Gmail")
    assert result.success
    assert result.total_found == 1
    assert len(fake.called("gmail-search-all-mailboxes")) == 1


def test_delete_failure_is_reported_per_email(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND, "gmail-delete-mail": [error_entry("denied")]})
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
    item = {"ID": "g1", "UserID": "test@test", "Subject": "Invoice", "HasAttachments": True, "ReceivedTime": "t"}
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
    found = {"itemId": "i1", "mailbox": "test@test", "subject": "Invoice", "sender": "test@test"}
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
        make_params(delete_type=DELETE_HARD, retrieve_files=True, sender_address="test@test"), "ews", "EWS v2", "EWS"
    )
    assert result.success
    assert result.emails[0]["HTMLBody"] == "<p>x</p>"
    assert result.emails[0]["Attachments"] == {"a.txt": "s"}
    assert fake.called("ews-delete-items")[0]["delete-type"] == "hard"
    assert fake.called("ews-search-mailboxes")[0]["email_addresses"] == "test@test"


def test_ews_all_mailboxes_sends_no_address_filter(mocker):
    fake = setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-search-mailboxes": []})
    run_vendor(make_params(mailbox_scope=SCOPE_ALL, operation=OPERATION_SEARCH_ONLY), "ews", "EWS v2", "EWS")
    assert "email_addresses" not in fake.called("ews-search-mailboxes")[0]


def test_ews_saturated_search_is_repeated_after_delete(mocker):
    calls = {"n": 0}

    def search_with_state(args):
        calls["n"] += 1
        if calls["n"] <= len(module.EWS_LIMIT_STEPS):  # first round: always capped
            return [entry({"EWS.Items": [{"itemId": f"r1-{i}", "mailbox": "test@test"} for i in range(args["limit"])]})]
        return [entry({"EWS.Items": []})]  # second round: nothing left

    setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-search-mailboxes": search_with_state, "ews-get-items": []})
    result = run_vendor(make_params(), "ews", "EWS v2", "EWS")
    assert result.total_found == 1000  # Only one limit step now
    assert result.total_deleted == 1000


def test_ews_object_id_not_found_on_the_first_lookup_is_flagged_not_found(mocker):
    setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-get-items": [error_entry("One or more items were not found/malformed.")]})
    params = make_params(operation=OPERATION_SEARCH_ONLY, object_id="i1", brands=["EWS v2"])
    result = run_vendor(params, "ews", "EWS v2", "EWS")
    assert result.additional["NotFound"] is True
    assert module.build_command_results(params, [result])[0].entry_type == entryTypes["note"]


# ----------------------------------------------------------------------------------------------------------------------
# Aggregation and error handling
# ----------------------------------------------------------------------------------------------------------------------
def test_run_all_reports_a_partial_failure(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail", "EWS": "EWS v2"},
        {"gmail-search": GMAIL_FOUND, "ews-search-mailboxes": [error_entry("ews down")]},
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
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
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
# Search rounds: soft-deleted copies and deduplication
# ----------------------------------------------------------------------------------------------------------------------
def test_soft_delete_moved_copy_is_not_counted_or_deleted_again(mocker):
    """Round 1 is capped (saturated) and soft deletes m1; round 2 returns the moved copy in Deleted Items with a NEW ID."""
    original = module.graph_mail_to_email({**GRAPH_MAIL_ITEM, "ID": "AAMk-1", "UserID": "test@test"})
    moved_copy = module.graph_mail_to_email({**GRAPH_MAIL_ITEM, "ID": "AAMk-moved", "UserID": "test@test"})
    rounds = iter([([original], True), ([moved_copy], False)])
    deleted: list[str] = []
    result = module.VendorResult(vendor="Microsoft Graph Mail", brand="MicrosoftGraphMail", instance="GraphMail")
    ops = module.EmailOps(lambda: next(rounds), lambda email: deleted.append(email["ObjectID"]), lambda email: [])
    module.search_and_delete(make_params(), result, ops)
    assert deleted == ["AAMk-1"]  # the moved copy is not deleted again (which would be a hard delete)
    assert [email["ObjectID"] for email in result.emails] == ["AAMk-1"]
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)


def test_soft_delete_moved_copy_two_rounds_end_to_end_graph_mail(mocker):
    item = {**GRAPH_MAIL_ITEM, "UserID": "test@test"}
    full_page = [
        {**item, "ID": f"g{index}", "InternetMessageID": f"<test{index}@test>"} for index in range(module.GRAPH_MAIL_PAGE_SIZE)
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
    first = module.make_email(object_id="i1", mailbox="test@test")
    second = module.make_email(object_id="i2", mailbox="test@test")
    rounds = iter([([first], True), ([second], False)])
    result = module.VendorResult(vendor="EWS on-prem", brand="EWS v2", instance="EWS")
    module.search_and_delete(make_params(), result, module.EmailOps(lambda: next(rounds), lambda email: None, lambda email: []))
    assert result.total_found == 2


def test_same_internet_message_id_in_another_mailbox_is_still_processed():
    # The mailboxes must differ: the deduplication key is (mailbox, InternetMessageID).
    first = module.make_email(object_id="i1", mailbox="test1@test", internet_message_id="<test@test>")
    second = module.make_email(object_id="i2", mailbox="test2@test", internet_message_id="<test@test>")
    rounds = iter([([first], True), ([second], False)])
    result = module.VendorResult(vendor="EWS on-prem", brand="EWS v2", instance="EWS")
    module.search_and_delete(make_params(), result, module.EmailOps(lambda: next(rounds), lambda email: None, lambda email: []))
    assert result.total_found == 2


# ----------------------------------------------------------------------------------------------------------------------
# Arguments: delete_type / timeout
# ----------------------------------------------------------------------------------------------------------------------
BASE_ARGS = {"operation": OPERATION_SEARCH_AND_DELETE, "subject": "Invoice", "target_mailbox": "test@test"}


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


@pytest.mark.parametrize("value, expected", [(None, 1800), ("", 1800), ("60", 60), (1800, 1800), ("1800", 1800), ("1", 1)])
def test_parse_args_timeout(value, expected):
    args = dict(BASE_ARGS)
    if value is not None:
        args["timeout"] = value
    params = module.parse_args(args)
    assert params.timeout == expected
    assert params.deadline == START_EPOCH + expected


def test_default_and_max_timeout_constants():
    assert module.DEFAULT_TIMEOUT_SECONDS == module.MAX_TIMEOUT_SECONDS == 1800


@pytest.mark.parametrize("value", ["1801", 1801, 3600, "86400"])
def test_parse_args_timeout_above_the_maximum_is_rejected(value):
    with pytest.raises(module.DemistoException, match="timeout must be at most 1800 seconds"):
        module.parse_args({**BASE_ARGS, "timeout": value})


@pytest.mark.parametrize("value", ["0", 0, "-5", -5, "abc", "1.5x"])
def test_parse_args_timeout_invalid(value):
    with pytest.raises(module.DemistoException, match="timeout must be a positive number of seconds."):
        module.parse_args({**BASE_ARGS, "timeout": value})


# ----------------------------------------------------------------------------------------------------------------------
# Output: command results, readable output, EmailData context
# ----------------------------------------------------------------------------------------------------------------------
GRAPH_MAIL_ITEM = {
    "ID": "AAMk-1",
    "UserID": "test@test",
    "Subject": "Undeliverable",
    "From": {"Address": "test@test"},
    "ReceivedTime": "2026-10-21T11:58:19Z",
    "InternetMessageID": "<test@test>",
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
        "| Gmail | test@test | m1 | Invoice | test1@test | test@test "
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


def test_readable_output_keeps_an_email_without_a_timestamp():
    """An email without a Date header must still be shown: only the per-vendor status rows are skipped."""
    no_date = found_email("m-no-date", Timestamp="", Deleted=True)
    result = vendor_result(emails=[no_date], total_found=1, total_deleted=1, errors=["later round failed"])
    hr = get_hr(make_params(), [result])
    assert "| Gmail | test@test | m-no-date | Invoice |" in hr
    assert hr.count("| Gmail |") == 1  # the vendor status row (errors) is not shown as an email


def test_context_vendor_failure_entry_has_no_emails_and_success_false():
    result = vendor_result(errors=["boom"], total_found=0, total_failed=0)
    entry = get_email_data(make_params(), [result])[0]
    assert entry.get("Subject") is None
    assert entry["Success"] is False
    assert entry["Reason"] == "boom"


# ----------------------------------------------------------------------------------------------------------------------
# Overall time budget (timeout): checked before each vendor instance, each search round, each Gmail page and each email
# ----------------------------------------------------------------------------------------------------------------------
def test_run_command_does_not_check_the_deadline(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    CLOCK.advance(10**9)
    assert module.run_command("gmail-search", {}, "Gmail") == GMAIL_FOUND


def test_vendors_are_not_started_when_the_deadline_passed(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail", "EWS": "EWS v2"}, {})
    params = make_params(operation=OPERATION_SEARCH_ONLY, timeout=5, deadline=CLOCK.now + 5)
    CLOCK.advance(10)  # the deadline passed before the first vendor was run
    results = run_all(params)
    assert not fake.calls
    assert [r.success for r in results] == [False, False]
    assert all(r.errors == [module.VENDOR_TIMEOUT_REASON.format(timeout=5)] for r in results)
    assert "Timed out: the 5 seconds timeout budget was exhausted before this integration ran." in results[0].errors[0]

    hr = get_hr(params, results)
    assert hr.count("exhausted before this integration ran") == 2
    assert [r.brand for r in results] == ["Gmail", "EWS v2"]


def test_vendor_that_was_not_started_before_the_deadline_is_reported_after_a_slow_vendor(mocker):
    def slow_search(args):
        CLOCK.advance(100)  # Gmail uses up the whole budget
        return GMAIL_FOUND

    fake = setup_demisto(mocker, {"Gmail": "Gmail", "EWS": "EWS v2"}, {"gmail-search": slow_search})
    params = make_params(operation=OPERATION_SEARCH_ONLY, timeout=5, deadline=CLOCK.now + 5)
    gmail, ews = run_all(params)
    assert gmail.success
    assert gmail.total_found == 1
    assert gmail.additional["Note"] == module.EMAIL_TIMEOUT_NOTE
    assert not fake.called("ews-search-mailboxes")
    assert ews.errors == [module.VENDOR_TIMEOUT_REASON.format(timeout=5)]


def test_emails_left_when_the_deadline_passes_are_reported_as_failed(mocker):
    def slow_delete(args):
        CLOCK.advance(100)  # the budget is gone after the first deletion
        return []

    second = {**GMAIL_ITEM, "ID": "m2"}
    fake = setup_demisto(
        mocker,
        {"Gmail": "Gmail"},
        {"gmail-search": [entry({"Gmail": [GMAIL_ITEM, second]})], "gmail-delete-mail": slow_delete},
    )
    result = run_vendor(make_params(timeout=30, deadline=CLOCK.now + 30), "gmail", "Gmail", "Gmail")
    assert [call["message-id"] for call in fake.called("gmail-delete-mail")] == ["m1"]
    deleted, skipped = result.emails
    assert deleted["Deleted"] is True
    assert skipped["Deleted"] is False
    assert skipped["Reason"] == module.EMAIL_TIMEOUT_REASON
    assert (result.total_found, result.total_deleted, result.total_failed) == (2, 1, 1)
    assert result.additional["Note"] == module.EMAIL_TIMEOUT_NOTE
    assert len(fake.called("gmail-search")) == 1


def test_partial_results_survive_a_failing_second_search_round(mocker):
    """Round 1 finds and deletes an email (and reports a saturated page), round 2 raises: the email is still reported."""
    rounds = iter([([module.gmail_to_email(GMAIL_ITEM)], True)])

    def gmail_search(params, instance):
        try:
            return next(rounds)
        except StopIteration:
            raise module.DemistoException("round 2 failed") from None

    mocker.patch.object(module, "gmail_search", side_effect=gmail_search)
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {})
    result = run_vendor(make_params(), "gmail", "Gmail", "Gmail")
    assert len(fake.called("gmail-delete-mail")) == 1
    assert result.total_found == 1
    assert [email["ObjectID"] for email in result.emails] == ["m1"]
    assert result.emails[0]["Deleted"] is True
    assert (result.total_deleted, result.total_failed) == (1, 0)
    assert result.errors == ["round 2 failed"]

    params = make_params()
    email_data = get_email_data(params, [result])
    # the deleted email + the failure row of the vendor
    assert len(email_data) == 2
    assert email_data[0]["AdditionalFields"]["ObjectID"] == "m1"
    assert email_data[1]["Success"] is False
    assert "round 2 failed" in email_data[1]["Reason"]


def test_gmail_pagination_stops_when_the_deadline_passes(mocker):
    def first_page(args):
        CLOCK.advance(100)  # the budget is gone when the second page would be requested
        return [entry({"Gmail": [GMAIL_ITEM], "PageToken": {"NextPageToken": "t2"}})]

    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": first_page})
    params = make_params(operation=OPERATION_SEARCH_ONLY, timeout=30, deadline=CLOCK.now + 30)
    result = run_vendor(params, "gmail", "Gmail", "Gmail")
    assert len(fake.called("gmail-search")) == 1  # the second page is not requested
    assert result.errors == []
    assert result.total_found == 1
    assert result.additional["Note"] == module.EMAIL_TIMEOUT_NOTE


# ----------------------------------------------------------------------------------------------------------------------
# The entry point: a single synchronous run that returns the final results
# ----------------------------------------------------------------------------------------------------------------------
ENTRY_ARGS = {
    "operation": OPERATION_SEARCH_ONLY,
    "subject": "Invoice",
    "target_mailbox": "test@test",
    "timeout": "1800",
    "verbose": "true",
}
DELETE_ARGS = {**ENTRY_ARGS, "operation": OPERATION_SEARCH_AND_DELETE, "brands": "Gmail"}


def test_entry_point_returns_the_final_results_in_a_single_run(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    result = final(module.search_and_delete_email(dict(DELETE_ARGS)))
    outputs = outputs_of(result)
    assert (outputs["TotalFound"], outputs["TotalDeleted"], outputs["TotalFailed"]) == (1, 1, 0)
    assert result.entry_type == module.EntryType.NOTE
    assert len(fake.called("gmail-search")) == 1
    assert len(fake.called("gmail-delete-mail")) == 1
    hr = result.readable_output
    assert "#### Executed commands" in hr
    assert hr.count("gmail-search ") == 1
    assert hr.count("gmail-delete-mail") == 1


def test_entry_point_ignores_leftover_polling_arguments(mocker):
    """The removed polling / verification arguments are ignored: the run is still single and unverified."""
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    args = {**DELETE_ARGS, "verify_deletion": "true", "state": "{not json", "hide_polling_output": True}
    result = final(module.search_and_delete_email(args))
    assert len(fake.called("gmail-search")) == 1
    assert outputs_of(result)["TotalDeleted"] == 1
    assert "Verified" not in outputs_of(result)["EmailData"][0]["AdditionalFields"]


def test_entry_point_non_verbose_has_no_command_trace(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    result = final(module.search_and_delete_email({**DELETE_ARGS, "verbose": "false"}))
    assert "#### Executed commands" not in result.readable_output


def test_entry_point_resets_the_command_trace(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": GMAIL_FOUND})
    module.COMMAND_TRACE.append("stale command of a previous run")
    hr = final(module.search_and_delete_email(dict(DELETE_ARGS))).readable_output
    assert "stale command of a previous run" not in hr
    assert "gmail-search" in hr


def test_entry_point_publishes_the_retrieved_files(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail"},
        {
            "gmail-search": GMAIL_FOUND,
            "gmail-get-attachments": [
                entry({"File(val.SHA1 == obj.SHA1)": [{"Name": "a.txt", "SHA256": "abc"}]}, entry_type=entryTypes["file"])
            ],
        },
    )
    args = {**DELETE_ARGS, "retrieve_files": "true", "verbose": "false"}
    result = final(module.search_and_delete_email(args))
    assert len(PUBLISHED) == 1
    assert PUBLISHED[0]["Type"] == entryTypes["file"]
    assert outputs_of(result)["EmailData"][0]["Attachments"] == {"a.txt": "abc"}


def test_entry_point_timeout_budget_starts_when_the_arguments_are_parsed(mocker):
    def slow_search(args):
        CLOCK.advance(100)  # Gmail uses up the whole budget
        return GMAIL_FOUND

    fake = setup_demisto(mocker, GMAIL_EWS_MODULES, {"gmail-search": slow_search})
    result = final(module.search_and_delete_email({**ENTRY_ARGS, "brands": "Gmail,EWS v2", "timeout": "5"}))
    assert not fake.called("ews-search-mailboxes")
    gmail_row, ews_row = outputs_of(result)["EmailData"]
    assert gmail_row["AdditionalFields"]["ObjectID"] == "m1"
    assert ews_row["Brand"] == "EWS v2"
    assert ews_row["Success"] is False
    assert ews_row["Reason"] == module.VENDOR_TIMEOUT_REASON.format(timeout=5)
    assert result.entry_type == module.EntryType.NOTE
    assert "**Notes:**" in result.readable_output


def test_entry_point_invalid_arguments_are_reported_as_such(mocker):
    setup_demisto(mocker, {}, {})
    with pytest.raises(module.InvalidArgumentsError, match="operation must be"):
        module.search_and_delete_email({**ENTRY_ARGS, "operation": "Delete"})


def test_entry_point_unexpected_failure_returns_the_failure_results(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {})
    mocker.patch.object(module, "resolve_target_instances", side_effect=module.DemistoException("boom"))
    result = final(module.search_and_delete_email(dict(ENTRY_ARGS)))

    assert result.entry_type == entryTypes["error"]
    assert "boom" in result.readable_output


# ----------------------------------------------------------------------------------------------------------------------
# Multi-vendor runs (Gmail + EWS)
# ----------------------------------------------------------------------------------------------------------------------
GMAIL_EWS_MODULES = {"Gmail": "Gmail", "EWS": "EWS v2"}
EWS_ITEM = {"itemId": "i1", "mailbox": "test@test", "subject": "Invoice"}


def test_multi_vendor_run_aggregates_gmail_and_ews(mocker):
    fake = setup_demisto(
        mocker,
        GMAIL_EWS_MODULES,
        {
            "gmail-search": GMAIL_FOUND,
            "ews-search-mailboxes": [entry({"EWS.Items": [EWS_ITEM]})],
            "ews-get-items": [],
            "ews-delete-items": [error_entry("ews denied")],
        },
    )
    params = make_params()
    gmail, ews = run_all(params)
    assert len(fake.called("gmail-search")) == 1
    assert len(fake.called("ews-search-mailboxes")) == 1
    assert (gmail.total_found, gmail.total_deleted, gmail.total_failed) == (1, 1, 0)
    assert (ews.total_found, ews.total_deleted, ews.total_failed) == (1, 0, 1)
    assert "ews denied" in ews.emails[0]["Reason"]
    outputs = get_outputs(params, [gmail, ews])
    assert (outputs["TotalFound"], outputs["TotalDeleted"], outputs["TotalFailed"]) == (2, 1, 1)
    assert [(item["Brand"], item["AdditionalFields"]["ObjectID"]) for item in outputs["EmailData"]] == [
        ("Gmail", "m1"),
        ("EWS v2", "i1"),
    ]


def test_entry_point_gmail_and_ews_in_a_single_run(mocker):
    fake = setup_demisto(
        mocker,
        GMAIL_EWS_MODULES,
        {"gmail-search": GMAIL_FOUND, "ews-search-mailboxes": [entry({"EWS.Items": []})]},
    )
    result = final(module.search_and_delete_email({**DELETE_ARGS, "brands": "Gmail,EWS v2"}))
    outputs = outputs_of(result)
    assert (outputs["TotalFound"], outputs["TotalDeleted"], outputs["TotalFailed"]) == (1, 1, 0)
    assert [item["Brand"] for item in outputs["EmailData"]] == ["Gmail", "EWS v2"]
    assert outputs["EmailData"][1]["Success"] is True  # EWS found nothing: a successful status row
    assert len(fake.called("ews-search-mailboxes")) == 1
    assert len(fake.called("gmail-search")) == 1


def test_one_vendor_failing_does_not_stop_the_other(mocker):
    setup_demisto(
        mocker,
        GMAIL_EWS_MODULES,
        {"gmail-search": [error_entry("gmail down")], "ews-search-mailboxes": [entry({"EWS.Items": [EWS_ITEM]})]},
    )
    gmail, ews = run_all(make_params(operation=OPERATION_SEARCH_ONLY))
    assert not gmail.success
    assert "gmail down" in gmail.errors[0]
    assert ews.success
    assert ews.total_found == 1


def test_unexpected_exception_of_a_vendor_is_recorded_and_does_not_stop_the_other_vendor(mocker):
    mocker.patch.object(module, "gmail_search", side_effect=ValueError("kaboom"))
    setup_demisto(mocker, GMAIL_EWS_MODULES, {"ews-search-mailboxes": [entry({"EWS.Items": [EWS_ITEM]})]})
    gmail, ews = run_all(make_params(operation=OPERATION_SEARCH_ONLY))
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
        item = {**GRAPH_MAIL_ITEM, "ID": f"g{counter['n']}", "InternetMessageID": f"<test{counter['n']}@test>"}
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
    assert "| Gmail | test@test | m1 |" in hr
    assert hr.endswith("**Total found:** 1 | **Total deleted:** 0 | **Total failed:** 0\n\n**Notes:**\n* **Gmail**: Capped.")


def test_readable_output_has_no_notes_section_without_notes():
    hr = get_hr(make_params(operation=OPERATION_SEARCH_ONLY), [vendor_result(emails=[found_email()], total_found=1)])
    assert "**Notes:**" not in hr


# ----------------------------------------------------------------------------------------------------------------------
# Small helpers and the object_id NotFound flag
# ----------------------------------------------------------------------------------------------------------------------
def test_primary_mailbox():
    assert module.primary_mailbox(module.make_email(object_id="1", mailbox=["test1@test", "test2@test"])) == "test1@test"
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
