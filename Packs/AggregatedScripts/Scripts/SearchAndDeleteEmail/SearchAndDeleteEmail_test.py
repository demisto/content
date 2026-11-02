from datetime import datetime, timedelta, UTC
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
        "target_mailboxes": ["a@example.com"],
        "mailbox_scope": SCOPE_SPECIFIC,
        "brands": [],
        "verbose": False,
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


@pytest.fixture(autouse=True)
def no_sleep(mocker):
    mocker.patch("SearchAndDeleteEmail.time.sleep")
    module.COMMAND_TRACE.clear()


def setup_demisto(mocker, modules: dict[str, str], responses: dict[str, Any]) -> FakeCommands:
    mocker.patch.object(
        demisto, "getModules", return_value={name: {"brand": brand, "state": "active"} for name, brand in modules.items()}
    )
    fake = FakeCommands(responses)
    mocker.patch.object(demisto, "executeCommand", side_effect=fake)
    return fake


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
    assert not params.delete
    assert (datetime.now(UTC) - params.since).total_seconds() == pytest.approx(3600, abs=5)


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


def test_poll_returns_when_value_is_ready_and_times_out(mocker):
    values = iter([None, None, "done"])
    assert module.poll(lambda: next(values), "x") == "done"
    mocker.patch("SearchAndDeleteEmail.time.monotonic", side_effect=[0, 5, 100])
    with pytest.raises(module.DemistoException, match="Timed out"):
        module.poll(lambda: None, "x", timeout=10)


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
    result = module.run_vendor(make_params(retrieve_files=True, delete_type=DELETE_HARD), "gmail", "Gmail", "Gmail")
    assert result.success
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 1, 0)
    assert result.emails[0]["Attachments"] == {"a.txt": "abc"}
    assert len(result.file_entries) == 1
    assert fake.called("gmail-delete-mail")[0]["permanent"] == "true"
    # files must be fetched before the email is deleted
    order = [name for name, _ in fake.calls]
    assert order.index("gmail-get-attachments") < order.index("gmail-delete-mail")


def test_gmail_search_only_does_not_delete(mocker):
    fake = setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": [entry({"Gmail": [GMAIL_ITEM]})]})
    result = module.run_vendor(make_params(operation=OPERATION_SEARCH_ONLY), "gmail", "Gmail", "Gmail")
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
    result = module.run_vendor(make_params(mailbox_scope=SCOPE_ALL, operation=OPERATION_SEARCH_ONLY), "gmail", "Gmail", "Gmail")
    assert result.total_found == 2
    assert [c.get("page-token") for c in fake.called("gmail-search-all-mailboxes")] == [None, "t2"]


def test_delete_failure_is_reported_per_email(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail"},
        {"gmail-search": [entry({"Gmail": [GMAIL_ITEM]})], "gmail-delete-mail": [error_entry("denied")]},
    )
    result = module.run_vendor(make_params(), "gmail", "Gmail", "Gmail")
    assert (result.total_found, result.total_deleted, result.total_failed) == (1, 0, 1)
    assert "denied" in result.emails[0]["Reason"]
    assert not result.success


# ----------------------------------------------------------------------------------------------------------------------
# Microsoft Graph Mail
# ----------------------------------------------------------------------------------------------------------------------
def test_graph_mail_all_mailboxes_is_unsupported(mocker):
    setup_demisto(mocker, {"GraphMail": "O365 Outlook Mail (Using Graph API)"}, {})
    result = module.run_vendor(make_params(mailbox_scope=SCOPE_ALL), "msgraph_mail", "O365", "GraphMail")
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
    result = module.run_vendor(make_params(retrieve_files=True), "msgraph_mail", "O365", "GraphMail")
    assert result.emails[0]["Attachments"] == {"doc.pdf": "h"}
    assert result.total_deleted == 1
    assert fake.called("msgraph-mail-delete-email")[0]["message_id"] == "g1"


# ----------------------------------------------------------------------------------------------------------------------
# Microsoft Graph Security
# ----------------------------------------------------------------------------------------------------------------------
def graph_security_responses(estimates: list[int], purge_status: str = "succeeded") -> dict[str, Any]:
    remaining = iter(estimates)
    return {
        "msg-list-ediscovery-cases": [
            entry({"MsGraph.eDiscoveryCase": [{"DisplayName": module.GRAPH_SECURITY_CASE_NAME, "CaseId": "case1"}]})
        ],
        "msg-create-ediscovery-search": [entry({"MsGraph.eDiscoverySearch": {"SearchId": "search1"}})],
        "msg-get-last-estimate-statistics-operation": lambda args: [
            entry({"MsGraph.eDiscovery.EstimateStatistics": {"Status": "succeeded", "TotalItemsCount": next(remaining)}})
        ],
        "msg-purge-ediscovery-data": [entry({"MsGraph.eDiscoveryCase.Purge": {"OperationID": "op1", "Status": "running"}})],
        "msg-list-case-operation": [entry({"MsGraph.eDiscoveryCase.Operation": {"ID": "op1", "Status": purge_status}})],
    }


def test_graph_security_search_purge_and_cleanup(mocker):
    fake = setup_demisto(mocker, {"MsGraph": "Microsoft Graph"}, graph_security_responses([3, 0]))
    result = module.run_vendor(make_params(delete_type=DELETE_HARD), "msgraph_security", "Microsoft Graph", "MsGraph")
    assert result.success
    assert (result.total_found, result.total_deleted, result.total_failed) == (3, 3, 0)
    assert fake.called("msg-purge-ediscovery-data")[0]["purge_type"] == "permanentlyDelete"
    assert fake.called("msg-delete-ediscovery-search") == [{"case_id": "case1", "search_id": "search1", "using": "MsGraph"}]


def test_graph_security_search_only_cleans_up_without_purge(mocker):
    fake = setup_demisto(mocker, {"MsGraph": "Microsoft Graph"}, graph_security_responses([5]))
    result = module.run_vendor(make_params(operation=OPERATION_SEARCH_ONLY), "msgraph_security", "Microsoft Graph", "MsGraph")
    assert result.total_found == 5
    assert result.total_deleted == 0
    assert not fake.called("msg-purge-ediscovery-data")
    assert len(fake.called("msg-delete-ediscovery-search")) == 1


def test_graph_security_cleans_up_search_when_purge_fails(mocker):
    fake = setup_demisto(mocker, {"MsGraph": "Microsoft Graph"}, graph_security_responses([3], purge_status="failed"))
    result = module.run_vendor(make_params(), "msgraph_security", "Microsoft Graph", "MsGraph")
    assert not result.success
    assert "purge operation ended with status 'failed'" in result.errors[0]
    assert len(fake.called("msg-delete-ediscovery-search")) == 1


def test_graph_security_creates_case_when_missing(mocker):
    responses = graph_security_responses([0])
    responses["msg-list-ediscovery-cases"] = []
    responses["msg-create-ediscovery-case"] = [entry({"MsGraph.eDiscoveryCase": {"CaseId": "new-case"}})]
    fake = setup_demisto(mocker, {"MsGraph": "Microsoft Graph"}, responses)
    module.run_vendor(make_params(operation=OPERATION_SEARCH_ONLY), "msgraph_security", "Microsoft Graph", "MsGraph")
    assert fake.called("msg-create-ediscovery-search")[0]["case_id"] == "new-case"


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
    result = module.run_vendor(
        make_params(delete_type=DELETE_HARD, retrieve_files=True, sender_address="bad@evil.com"), "ews", "EWS v2", "EWS"
    )
    assert result.success
    assert result.emails[0]["HTMLBody"] == "<p>x</p>"
    assert result.emails[0]["Attachments"] == {"a.txt": "s"}
    assert fake.called("ews-delete-items")[0]["delete-type"] == "hard"
    assert fake.called("ews-search-mailboxes")[0]["email_addresses"] == "a@example.com"


def test_ews_all_mailboxes_sends_no_address_filter(mocker):
    fake = setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-search-mailboxes": []})
    module.run_vendor(make_params(mailbox_scope=SCOPE_ALL, operation=OPERATION_SEARCH_ONLY), "ews", "EWS v2", "EWS")
    assert "email_addresses" not in fake.called("ews-search-mailboxes")[0]


def test_ews_saturated_search_is_repeated_after_delete(mocker):
    calls = {"n": 0}

    def search_with_state(args):
        calls["n"] += 1
        if calls["n"] <= len(module.EWS_LIMIT_STEPS):  # first round: always capped
            return [entry({"EWS.Items": [{"itemId": f"r1-{i}", "mailbox": "a@example.com"} for i in range(args["limit"])]})]
        return [entry({"EWS.Items": []})]  # second round: nothing left

    setup_demisto(mocker, {"EWS": "EWS v2"}, {"ews-search-mailboxes": search_with_state, "ews-get-items": []})
    result = module.run_vendor(make_params(), "ews", "EWS v2", "EWS")
    assert result.total_found == module.EWS_LIMIT_STEPS[-1]
    assert result.total_deleted == module.EWS_LIMIT_STEPS[-1]


# ----------------------------------------------------------------------------------------------------------------------
# Aggregation and error handling
# ----------------------------------------------------------------------------------------------------------------------
def test_run_all_aggregates_partial_failure(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail", "EWS": "EWS v2"},
        {"gmail-search": [entry({"Gmail": [GMAIL_ITEM]})], "ews-search-mailboxes": [error_entry("ews down")]},
    )
    results = module.run_all(make_params(operation=OPERATION_SEARCH_ONLY))
    assert [r.success for r in results] == [True, False]
    context = module.build_context(make_params(operation=OPERATION_SEARCH_ONLY), results)
    assert {c["Brand"] for c in context} == {"Gmail", "EWS v2"}
    assert any("ews down" in c["Reason"] for c in context)


def test_all_vendors_fail_returns_hr_and_context(mocker):
    setup_demisto(
        mocker,
        {"Gmail": "Gmail", "EWS": "EWS v2"},
        {"gmail-search": [error_entry("g down")], "ews-search-mailboxes": [error_entry("e down")]},
    )
    params = make_params(operation=OPERATION_SEARCH_ONLY)
    results = module.run_all(params)
    assert not any(r.success for r in results)
    hr = module.build_human_readable(params, results)
    assert "ALL VENDORS FAILED" in hr
    assert "g down" in hr
    assert "e down" in hr
    context = module.build_context(params, results)
    assert len(context) == 2
    assert all(c["Success"] is False and c["TotalFound"] == 0 for c in context)


def test_no_instances_returns_failure_entry(mocker):
    setup_demisto(mocker, {}, {})
    results = module.run_all(make_params())
    assert "No enabled instance" in results[0].errors[0]
    assert module.build_context(make_params(), results)[0]["Success"] is False


def test_object_id_requires_a_single_vendor(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail", "EWS": "EWS v2"}, {})
    with pytest.raises(module.DemistoException, match="exactly one brand"):
        module.run_all(make_params(object_id="1", brands=["Gmail", "EWS v2"]))


def test_verbose_lists_executed_commands(mocker):
    setup_demisto(mocker, {"Gmail": "Gmail"}, {"gmail-search": [entry({"Gmail": [GMAIL_ITEM]})]})
    params = make_params(operation=OPERATION_SEARCH_ONLY, verbose=True)
    hr = module.build_human_readable(params, module.run_all(params))
    assert "Executed commands" in hr
    assert "gmail-search" in hr
