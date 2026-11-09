import hashlib
from datetime import datetime, timedelta
from typing import Any

import pytest

import demistomock as demisto
import SearchAndDeleteEmail as sde
from CommonServerPython import CommandResults, EntryType
from SearchAndDeleteEmail import (
    DELETE_HARD,
    DELETE_SOFT,
    EWS_BRAND,
    GMAIL_BRAND,
    HANDLERS,
    MSGRAPH_MAIL_BRAND,
    MSGRAPH_SECURITY_BRAND,
    OPERATION_DELETE,
    OPERATION_SEARCH,
    SCOPE_ALL,
    SCOPE_SPECIFIC,
    UTC_TZ,
    Attachment,
    CommandError,
    EmailRecord,
    InputError,
    SearchParams,
)

ALL_BRANDS = {GMAIL_BRAND, EWS_BRAND, MSGRAPH_SECURITY_BRAND, MSGRAPH_MAIL_BRAND}
MAILBOX = "a@x.com"
NOW_ISO = datetime.now(UTC_TZ).isoformat()

""" HELPERS """


def entry(context: dict | None = None) -> dict:
    return {"Type": 1, "Contents": "", "HumanReadable": "", "EntryContext": context or {}}


def error_entry(message: str = "boom") -> dict:
    return {"Type": 4, "Contents": message, "HumanReadable": "", "EntryContext": {}}


class FakeExecutor:
    """Replaces demisto.executeCommand: `responses` maps a command to a sequence of results (each is a list of entries).

    The last result is repeated once the sequence is exhausted. Unknown commands fail the test.
    """

    def __init__(self, responses: dict[str, list[list[dict]]]):
        self.responses = {command: list(results) for command, results in responses.items()}
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, command: str, args: dict) -> list[dict]:
        self.calls.append((command, args))
        if command not in self.responses:
            raise AssertionError(f"Unexpected command: {command}")
        queue = self.responses[command]
        return queue.pop(0) if len(queue) > 1 else queue[0]

    @property
    def commands(self) -> list[str]:
        return [command for command, _ in self.calls]

    def args_of(self, command: str) -> list[dict]:
        return [args for name, args in self.calls if name == command]


def outputs_of(result: CommandResults) -> dict[str, Any]:
    assert isinstance(result.outputs, dict)
    return result.outputs


def install(mocker, responses: dict[str, list[list[dict]]]) -> FakeExecutor:
    executor = FakeExecutor(responses)
    mocker.patch.object(demisto, "executeCommand", side_effect=executor)
    return executor


def make_params(**overrides) -> SearchParams:
    values: dict[str, Any] = {
        "operation": OPERATION_SEARCH,
        "mailbox_scope": SCOPE_SPECIFIC,
        "mailboxes": [MAILBOX],
        "brands": [GMAIL_BRAND],
        "start_time": datetime.now(UTC_TZ) - timedelta(hours=1),
        "subject": "Invoice",
    }
    values.update(overrides)
    return SearchParams(**values)


def gmail_mail(message_id: str = "m1", mailbox: str = MAILBOX, **extra) -> dict:
    return {
        "ID": message_id,
        "Mailbox": mailbox,
        "Subject": "Invoice",
        "From": "evil@bad.com",
        "To": [MAILBOX],
        "Cc": [],
        "Bcc": [],
        "Html": "<b>hi</b>",
        "Body": "hi",
        "Date": NOW_ISO,
        "Labels": ["INBOX"],
        "Headers": [{"Name": "Message-ID", "Value": "<abc@bad.com>"}],
        "Attachments": [],
        **extra,
    }


def gmail_entry(*mails: dict, next_token: str = "") -> dict:
    context: dict[str, Any] = {"Gmail(val.ID && val.ID == obj.ID)": list(mails)}
    if next_token:
        context["GmailEmails"] = {"NextPageToken": next_token}
    return entry(context)


def ews_item(item_id: str = "i1", mailbox: str = MAILBOX, **extra) -> dict:
    return {
        "itemId": item_id,
        "mailbox": mailbox,
        "subject": "Invoice",
        "sender": "evil@bad.com",
        "toRecipients": [MAILBOX],
        "datetimeReceived": NOW_ISO,
        "body": "<b>hi</b>",
        "messageId": "<abc@bad.com>",
        "hasAttachments": False,
        **extra,
    }


def ews_entry(*items: dict) -> dict:
    return entry({"EWS.Items(val.itemId == obj.itemId)": list(items)})


def graph_mail(message_id: str = "g1", received: str = NOW_ISO, **extra) -> dict:
    return {
        "ID": message_id,
        "UserID": MAILBOX,
        "Subject": "Invoice",
        "From": {"Name": "Evil", "Address": "evil@bad.com"},
        "Recipients": [{"Name": "A", "Address": MAILBOX}],
        "Body": "<p>hi</p>",
        "ReceivedTime": received,
        "InternetMessageID": "<abc@bad.com>",
        "HasAttachments": False,
        **extra,
    }


def graph_mail_entry(*mails: dict) -> dict:
    return entry({"MSGraphMail(val.ID && val.ID == obj.ID)": list(mails)})


def security_responses(
    total: int = 3, statuses: tuple[str, ...] = ("succeeded",), purge_status: str = "succeeded", existing_case: bool = False
) -> dict[str, list[list[dict]]]:
    case = {"CaseId": "case1", "DisplayName": sde.MSGRAPH_SECURITY_CASE_NAME}
    case_key = "MsGraph.eDiscoveryCase(val.CaseId && val.CaseId == obj.CaseId)"
    stats_key = "MsGraph.eDiscovery.EstimateStatistics(val.id && val.id == obj.id)"
    return {
        "msg-list-ediscovery-cases": [[entry({case_key: [case]} if existing_case else {})]],
        "msg-create-ediscovery-case": [[entry({case_key: case})]],
        "msg-create-ediscovery-search": [
            [entry({"MsGraph.eDiscoverySearch(val.SearchId && val.SearchId == obj.SearchId)": {"SearchId": "search1"}})]
        ],
        "msg-run-estimate-statistics": [[entry()]],
        "msg-get-last-estimate-statistics-operation": [
            [entry({stats_key: {"status": status, "totalItemCount": total, "mailboxCount": 2}})] for status in statuses
        ],
        "msg-purge-ediscovery-data": [
            [
                entry(
                    {
                        "MsGraph.eDiscoveryCase.Purge(val.OperationID && val.OperationID == obj.OperationID)": {
                            "OperationID": "op1",
                            "Status": purge_status,
                        }
                    }
                )
            ]
        ],
        "msg-delete-ediscovery-search": [[entry()]],
    }


""" GENERIC HELPERS """


def test_dedupe_removes_empty_values_and_duplicates_keeping_order():
    assert sde.dedupe(["b", "", "a", "b", "a"]) == ["b", "a"]


def test_chunked_splits_to_chunks_of_the_given_size():
    assert list(sde.chunked([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, []),
        ("a@x.com, b@x.com", ["a@x.com", "b@x.com"]),
        ({"Name": "A", "Address": "a@x.com"}, ["a@x.com"]),
        ([{"Address": "a@x.com"}, "b@x.com", ["c@x.com"]], ["a@x.com", "b@x.com", "c@x.com"]),
    ],
)
def test_to_str_list(value, expected):
    assert sde.to_str_list(value) == expected


def test_find_header_is_case_insensitive_for_lists_and_dicts():
    assert sde.find_header([{"Name": "Message-ID", "Value": "<1@x>"}], "message-id") == "<1@x>"
    assert sde.find_header({"Message-Id": "<2@x>"}, "message-id") == "<2@x>"
    assert sde.find_header([], "message-id") == ""


def test_angle_brackets_helpers():
    assert sde.strip_angle_brackets(" <abc@x> ") == "abc@x"
    assert sde.ensure_angle_brackets("abc@x") == "<abc@x>"
    assert sde.ensure_angle_brackets("<abc@x>") == "<abc@x>"


def test_paginate_follows_tokens_until_there_are_no_more():
    pages = {"": (["a"], "t1"), "t1": (["b"], "t2"), "t2": (["c"], "")}

    assert sde.paginate(lambda token: pages[token]) == ["a", "b", "c"]


def test_paginate_stops_on_repeated_token():
    calls = []

    def fetch(token):
        calls.append(token)
        return ["x"], "same"

    assert sde.paginate(fetch) == ["x", "x"]
    assert len(calls) == 2


def test_paginate_is_bounded_by_max_pages():
    counter = iter(range(100))

    result = sde.paginate(lambda token: (["x"], f"token-{next(counter)}"), max_pages=3)

    assert result == ["x", "x", "x"]


def test_received_since():
    start = datetime.now(UTC_TZ) - timedelta(hours=1)

    assert sde.received_since("", start)
    assert sde.received_since("not a date", start)
    assert sde.received_since(NOW_ISO, start)
    assert not sde.received_since((datetime.now(UTC_TZ) - timedelta(days=3)).isoformat(), start)
    assert sde.received_since(datetime.now(UTC_TZ).replace(tzinfo=None).isoformat(), start)


def test_execute_adds_using_brand_and_raises_on_error(mocker):
    executor = install(mocker, {"cmd": [[entry()], [error_entry("bad thing")]]})

    sde.execute("cmd", {"a": 1}, GMAIL_BRAND)
    with pytest.raises(CommandError, match="bad thing"):
        sde.execute("cmd", {"a": 1}, GMAIL_BRAND)

    assert executor.args_of("cmd")[0] == {"a": 1, "using-brand": GMAIL_BRAND}


def test_get_context_matches_plain_and_dt_keys():
    entries = [entry({"Gmail(val.ID)": [{"ID": 1}], "Gmail": {"ID": 2}, "GmailEmails": {"ID": 3}})]

    assert sde.get_context(entries, "Gmail") == [{"ID": 1}, {"ID": 2}]


def test_dedupe_records_by_brand_mailbox_and_id():
    first = EmailRecord(brand=GMAIL_BRAND, mailbox="A@x.com", object_id="1")
    duplicate = EmailRecord(brand=GMAIL_BRAND, mailbox="a@x.com", object_id="1")
    other_brand = EmailRecord(brand=EWS_BRAND, mailbox="a@x.com", object_id="1")
    failure_1 = sde.error_record(GMAIL_BRAND, "x")
    failure_2 = sde.error_record(GMAIL_BRAND, "x")

    assert sde.dedupe_records([first, duplicate, other_brand, failure_1, failure_2]) == [first, other_brand, failure_1, failure_2]


""" ARGUMENT VALIDATION """


def valid_args(**overrides) -> dict:
    return {"operation": OPERATION_SEARCH, "target_mailbox": "a@x.com,a@x.com,b@x.com", "subject": "Invoice", **overrides}


def test_parse_args_happy_path_applies_defaults_and_dedupes():
    params = sde.parse_args(valid_args(internet_message_id="<1@x>,<1@x>,<2@x>"), ALL_BRANDS)

    assert params.operation == OPERATION_SEARCH
    assert params.mailbox_scope == SCOPE_SPECIFIC
    assert params.mailboxes == ["a@x.com", "b@x.com"]
    assert params.internet_message_ids == ["<1@x>", "<2@x>"]
    assert params.delete_type == DELETE_SOFT
    assert params.brands == sde.SUPPORTED_BRANDS
    assert not params.retrieve_files
    assert not params.verbose
    assert not params.verify_deletion
    assert abs((datetime.now(UTC_TZ) - params.start_time) - timedelta(hours=1)) < timedelta(minutes=1)


def test_parse_args_is_case_insensitive_for_predefined_values():
    params = sde.parse_args(valid_args(operation="search & delete", delete_type="hard", mailbox_scope="all"), ALL_BRANDS)

    assert (params.operation, params.delete_type, params.mailbox_scope) == (OPERATION_DELETE, DELETE_HARD, SCOPE_ALL)
    assert params.mailboxes == []


@pytest.mark.parametrize(
    "args, message",
    [
        ({"subject": "x", "target_mailbox": MAILBOX}, "'operation' argument is required"),
        (valid_args(operation="Delete everything"), "Invalid value 'Delete everything' for 'operation'"),
        (valid_args(delete_type="Medium"), "Invalid value 'Medium' for 'delete_type'"),
        (valid_args(mailbox_scope="Some"), "Invalid value 'Some' for 'mailbox_scope'"),
        ({"operation": OPERATION_SEARCH, "target_mailbox": MAILBOX}, "At least one of"),
        ({"operation": OPERATION_SEARCH, "subject": "x"}, "'target_mailbox' is required"),
        (valid_args(object_id="id1", target_mailbox=""), "'target_mailbox' and 'brands' must be specified"),
        (valid_args(object_id="id1", target_mailbox=MAILBOX), "'target_mailbox' and 'brands' must be specified"),
        (valid_args(object_id="id1", target_mailbox="", brands="Gmail"), "'target_mailbox' and 'brands' must be specified"),
        (valid_args(object_id="id1", target_mailbox="a@x.com,b@x.com", brands="Gmail"), "exactly one"),
        (valid_args(object_id="id1", target_mailbox=MAILBOX, brands="Gmail,EWS v2"), "exactly one"),
        (valid_args(object_id="id1", target_mailbox=MAILBOX, brands="Gmail", mailbox_scope="All"), "exactly one"),
        (valid_args(object_id="id1", target_mailbox=MAILBOX, brands="Microsoft Graph"), "not supported for Microsoft Graph"),
        (valid_args(time_frame="whenever"), "Invalid time_frame"),
    ],
)
def test_parse_args_rejects_invalid_input(args, message):
    with pytest.raises(InputError, match=message):
        sde.parse_args(args, ALL_BRANDS)


def test_parse_args_accepts_object_id_with_one_mailbox_and_one_brand():
    params = sde.parse_args(
        {"operation": OPERATION_SEARCH, "object_id": "id1", "target_mailbox": MAILBOX, "brands": "EWS v2"}, ALL_BRANDS
    )

    assert params.object_id == "id1"
    assert params.brands == [EWS_BRAND]


def test_parse_args_parses_booleans():
    params = sde.parse_args(valid_args(retrieve_files="true", verbose="true", verify_deletion="true"), ALL_BRANDS)

    assert params.retrieve_files
    assert params.verbose
    assert params.verify_deletion


@pytest.mark.parametrize(
    "time_frame, expected_delta",
    [("1 hour", timedelta(hours=1)), ("3 hours", timedelta(hours=3)), ("7 days", timedelta(days=7))],
)
def test_parse_time_frame_relative_values(time_frame, expected_delta):
    start = sde.parse_time_frame(time_frame)

    assert start.tzinfo is not None
    assert abs((datetime.now(UTC_TZ) - start) - expected_delta) < timedelta(minutes=1)


@pytest.mark.parametrize("time_frame", ["garbage", "in 2 days"])
def test_parse_time_frame_rejects_invalid_and_future_values(time_frame):
    with pytest.raises(InputError):
        sde.parse_time_frame(time_frame)


def test_get_enabled_brands_returns_only_active_brands(mocker):
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "1": {"brand": GMAIL_BRAND, "state": "active"},
            "2": {"brand": EWS_BRAND, "state": "disabled"},
        },
    )

    assert sde.get_enabled_brands() == {GMAIL_BRAND}


def test_resolve_brands_defaults_to_all_enabled_supported_brands():
    assert sde.resolve_brands([], {EWS_BRAND, GMAIL_BRAND, "Other"}) == [GMAIL_BRAND, EWS_BRAND]


def test_resolve_brands_filters_by_requested_brands_and_aliases():
    assert sde.resolve_brands(["microsoft graph security", "ews", "Gmail", "gmail"], ALL_BRANDS) == [
        MSGRAPH_SECURITY_BRAND,
        EWS_BRAND,
        GMAIL_BRAND,
    ]


def test_resolve_brands_rejects_unsupported_brand():
    with pytest.raises(InputError, match="Unsupported brand 'Foo'"):
        sde.resolve_brands(["Foo"], ALL_BRANDS)


def test_resolve_brands_rejects_brand_without_active_instance():
    with pytest.raises(InputError, match="no active instance"):
        sde.resolve_brands([EWS_BRAND], {GMAIL_BRAND})


def test_resolve_brands_rejects_when_no_supported_brand_is_enabled():
    with pytest.raises(InputError, match="No active instance"):
        sde.resolve_brands([], {"Other"})


""" GMAIL """


def test_build_gmail_query_prefers_message_ids_over_subject():
    params = make_params(internet_message_ids=["<a@x>", "b@x"], subject="ignored", sender_address="ignored@x.com")

    query = sde.build_gmail_query(params)

    assert query.startswith("(rfc822msgid:a@x OR rfc822msgid:b@x) after:")
    assert "ignored" not in query


def test_build_gmail_query_combines_subject_and_sender():
    query = sde.build_gmail_query(make_params(subject='Say "hi"', sender_address="evil@bad.com"))

    assert query.startswith('subject:"Say \\"hi\\"" from:evil@bad.com after:')


def test_search_gmail_happy_path_returns_normalized_records(mocker):
    executor = install(mocker, {"gmail-search-all-mailboxes": [[gmail_entry(gmail_mail()), entry()]]})

    records = sde.search_gmail(make_params(), [MAILBOX])

    assert len(records) == 1
    record = records[0]
    assert (record.brand, record.mailbox, record.object_id) == (GMAIL_BRAND, MAILBOX, "m1")
    assert (record.subject, record.sender, record.to, record.html) == ("Invoice", "evil@bad.com", [MAILBOX], "<b>hi</b>")
    assert record.internet_message_id == "<abc@bad.com>"
    args = executor.args_of("gmail-search-all-mailboxes")[0]
    assert args["list_accounts"] == MAILBOX
    assert args["show-only-mailboxes"] == "false"
    assert args["using-brand"] == GMAIL_BRAND


def test_search_gmail_splits_mailboxes_to_chunks(mocker):
    executor = install(mocker, {"gmail-search-all-mailboxes": [[entry()]]})
    mailboxes = [f"user{index}@x.com" for index in range(250)]

    assert sde.search_gmail(make_params(), mailboxes) == []

    sizes = [len(args["list_accounts"].split(",")) for args in executor.args_of("gmail-search-all-mailboxes")]
    assert sizes == [100, 100, 50]


def test_search_gmail_chunk_error_falls_back_to_per_mailbox_search_and_records_failure(mocker):
    executor = install(
        mocker,
        {
            "gmail-search-all-mailboxes": [[error_entry("chunk failed")]],
            "gmail-search": [[gmail_entry(gmail_mail("m1", "a@x.com"))], [error_entry("no access")]],
        },
    )

    records = sde.search_gmail(make_params(), ["a@x.com", "b@x.com"])

    assert executor.commands == ["gmail-search-all-mailboxes", "gmail-search", "gmail-search"]
    assert [record.found for record in records] == [True, False]
    assert records[1].mailbox == "b@x.com"
    assert "no access" in records[1].reason
    assert not records[1].success


def test_search_gmail_mailbox_follows_page_tokens(mocker):
    executor = install(
        mocker,
        {"gmail-search": [[gmail_entry(gmail_mail("m1"), next_token="page2")], [gmail_entry(gmail_mail("m2"))]]},
    )

    records = sde.search_gmail_mailbox(MAILBOX, "query", include_trash=True)

    assert [record.object_id for record in records] == ["m1", "m2"]
    first_args, second_args = executor.args_of("gmail-search")
    assert "page-token" not in first_args
    assert second_args["page-token"] == "page2"
    assert second_args["include-spam-trash"] == "True"


def test_search_gmail_collects_all_pages_of_a_mailbox_with_more_results(mocker):
    executor = install(
        mocker,
        {
            "gmail-search-all-mailboxes": [[gmail_entry(gmail_mail("m1"), next_token="more")]],
            "gmail-search": [[gmail_entry(gmail_mail("m1"), gmail_mail("m2"))]],
        },
    )

    records = sde.search_gmail(make_params(), [MAILBOX])

    assert sorted(record.object_id for record in records) == ["m1", "m2"]
    assert executor.args_of("gmail-search")[0]["user-id"] == MAILBOX


def test_get_gmail_by_id_uses_gmail_get_mail(mocker):
    executor = install(mocker, {"gmail-get-mail": [[gmail_entry(gmail_mail("m9"))]]})

    records = sde.get_gmail_by_id(make_params(object_id="m9"))

    assert [record.object_id for record in records] == ["m9"]
    assert executor.args_of("gmail-get-mail")[0]["message-id"] == "m9"


@pytest.mark.parametrize("delete_type, permanent", [(DELETE_SOFT, "False"), (DELETE_HARD, "True")])
def test_delete_gmail_maps_delete_type_to_permanent(mocker, delete_type, permanent):
    executor = install(mocker, {"gmail-delete-mail": [[entry()]]})
    record = EmailRecord(brand=GMAIL_BRAND, mailbox=MAILBOX, object_id="m1")

    sde.delete_gmail(make_params(delete_type=delete_type), [record])

    assert executor.args_of("gmail-delete-mail")[0]["permanent"] == permanent
    assert record.deleted
    assert record.success


def test_delete_gmail_error_marks_only_the_failed_record(mocker):
    install(mocker, {"gmail-delete-mail": [[entry()], [error_entry("denied")]]})
    first = EmailRecord(brand=GMAIL_BRAND, mailbox=MAILBOX, object_id="m1")
    second = EmailRecord(brand=GMAIL_BRAND, mailbox=MAILBOX, object_id="m2")

    sde.delete_gmail(make_params(), [first, second])

    assert first.deleted
    assert first.success
    assert not second.deleted
    assert not second.success
    assert "denied" in second.reason


def test_list_gmail_mailboxes_follows_page_tokens(mocker):
    def users_entry(address: str, token: str = "") -> dict:
        result = entry({"Account(val.ID && val.ID == obj.ID)": [{"Gmail": {"Address": address}, "Email": {"Address": address}}]})
        if token:
            result["HumanReadable"] = f"Users\nTo get further results, rerun the command with this page-token:\n{token}"
        return result

    executor = install(mocker, {"gmail-list-users": [[users_entry("a@x.com", "tok")], [users_entry("b@x.com")]]})

    assert sde.list_gmail_mailboxes(make_params()) == ["a@x.com", "b@x.com"]
    assert executor.args_of("gmail-list-users")[1]["page-token"] == "tok"


""" MICROSOFT GRAPH MAIL """


def test_build_msgraph_mail_odata_by_message_id_escapes_quotes():
    odata = sde.build_msgraph_mail_odata(make_params(internet_message_ids=["a@x", "<b'c@x>"]))

    assert odata == "$filter=internetMessageId eq '<a@x>' or internetMessageId eq '<b''c@x>'"


def test_build_msgraph_mail_odata_by_sender_and_subject():
    odata = sde.build_msgraph_mail_odata(make_params(sender_address="evil@bad.com", subject="It's"))

    assert odata == "$filter=from/emailAddress/address eq 'evil@bad.com' and contains(subject,'It''s')"


def test_search_msgraph_mail_happy_path_filters_old_emails_and_next_page_markers(mocker):
    old = (datetime.now(UTC_TZ) - timedelta(days=5)).isoformat()
    executor = install(
        mocker,
        {"msgraph-mail-list-emails": [[graph_mail_entry({"NextPage": "https://next"}, graph_mail("g1"), graph_mail("g2", old))]]},
    )

    records = sde.search_msgraph_mail(make_params(brands=[MSGRAPH_MAIL_BRAND]), [MAILBOX])

    assert [record.object_id for record in records] == ["g1"]
    record = records[0]
    assert (record.mailbox, record.sender, record.to, record.html) == (MAILBOX, "evil@bad.com", [MAILBOX], "<p>hi</p>")
    args = executor.args_of("msgraph-mail-list-emails")[0]
    assert args["user_id"] == MAILBOX
    assert args["odata"].startswith("$filter=")
    assert args["using-brand"] == MSGRAPH_MAIL_BRAND


def test_search_msgraph_mail_error_is_recorded_per_mailbox_and_other_mailboxes_continue(mocker):
    install(mocker, {"msgraph-mail-list-emails": [[error_entry("mailbox not found")], [graph_mail_entry(graph_mail())]]})

    records = sde.search_msgraph_mail(make_params(), ["bad@x.com", MAILBOX])

    assert [record.found for record in records] == [False, True]
    assert records[0].mailbox == "bad@x.com"
    assert "mailbox not found" in records[0].reason


def test_get_msgraph_mail_by_id(mocker):
    executor = install(mocker, {"msgraph-mail-get-email": [[graph_mail_entry(graph_mail("g7"))]]})

    records = sde.get_msgraph_mail_by_id(make_params(object_id="g7"))

    assert [record.object_id for record in records] == ["g7"]
    assert executor.args_of("msgraph-mail-get-email")[0] == {
        "user_id": MAILBOX,
        "message_id": "g7",
        "get_body": "true",
        "using-brand": MSGRAPH_MAIL_BRAND,
    }


def test_delete_msgraph_mail_success_and_hard_delete_note(mocker):
    executor = install(mocker, {"msgraph-mail-delete-email": [[entry()]]})
    record = EmailRecord(brand=MSGRAPH_MAIL_BRAND, mailbox=MAILBOX, object_id="g1")

    sde.delete_msgraph_mail(make_params(delete_type=DELETE_HARD), [record])

    assert executor.args_of("msgraph-mail-delete-email")[0]["message_id"] == "g1"
    assert record.deleted
    assert record.success
    assert "Hard delete is not supported" in record.details["Note"]


def test_delete_msgraph_mail_error(mocker):
    install(mocker, {"msgraph-mail-delete-email": [[error_entry("throttled")]]})
    record = EmailRecord(brand=MSGRAPH_MAIL_BRAND, mailbox=MAILBOX, object_id="g1")

    sde.delete_msgraph_mail(make_params(), [record])

    assert not record.deleted
    assert not record.success
    assert "throttled" in record.reason


def test_list_msgraph_mailboxes_uses_graph_user_integration(mocker):
    def users_entry(mail: str, next_page: str = "") -> dict:
        users: list[dict] = [{"Mail": mail}]
        if next_page:
            users.insert(0, {"NextPage": next_page})
        return entry({"MSGraphUser(val.ID && val.ID == obj.ID)": users})

    executor = install(mocker, {"msgraph-user-list": [[users_entry("a@x.com", "https://next")], [users_entry("b@x.com")]]})

    assert sde.list_msgraph_mailboxes(make_params()) == ["a@x.com", "b@x.com"]
    assert executor.args_of("msgraph-user-list")[1]["next_page"] == "https://next"


""" EWS """


def test_build_ews_query():
    query = sde.build_ews_query(make_params(subject='A "b"', sender_address="evil@bad.com"))

    assert query.startswith('Subject:"A \\"b\\"" AND From:"evil@bad.com" AND Received:>=')


def test_search_ews_by_message_id_uses_search_mailbox_per_mailbox(mocker):
    executor = install(
        mocker,
        {"ews-search-mailbox": [[ews_entry(ews_item("i1", "a@x.com"))], [error_entry("impersonation denied")]]},
    )
    params = make_params(brands=[EWS_BRAND], internet_message_ids=["<abc@bad.com>"])

    records = sde.search_ews(params, ["a@x.com", "b@x.com"])

    assert [record.found for record in records] == [True, False]
    assert records[0].object_id == "i1"
    assert records[1].mailbox == "b@x.com"
    first_args = executor.args_of("ews-search-mailbox")[0]
    assert (first_args["target-mailbox"], first_args["message-id"]) == ("a@x.com", "<abc@bad.com>")


def test_search_ews_by_query_enriches_partial_items(mocker):
    partial = ews_item("i1", body="", datetimeReceived=NOW_ISO)
    full = ews_item("i1", body="<b>full</b>", textBody="full text")
    executor = install(
        mocker,
        {"ews-search-mailboxes": [[ews_entry(partial)]], "ews-get-items": [[ews_entry(full)]]},
    )
    params = make_params(brands=[EWS_BRAND], sender_address="evil@bad.com", subject="")

    records = sde.search_ews(params, [MAILBOX])

    assert records[0].html == "<b>full</b>"
    assert records[0].details["Body"] == "full text"
    search_args = executor.args_of("ews-search-mailboxes")[0]
    assert search_args["email_addresses"] == MAILBOX
    assert 'From:"evil@bad.com"' in search_args["filter"]
    assert executor.args_of("ews-get-items")[0]["item-ids"] == "i1"


def test_search_ews_all_mailboxes_does_not_restrict_the_mailboxes(mocker):
    executor = install(mocker, {"ews-search-mailboxes": [[ews_entry(ews_item())]]})

    records = sde.search_ews(make_params(brands=[EWS_BRAND]), [])

    assert len(records) == 1
    assert "email_addresses" not in executor.args_of("ews-search-mailboxes")[0]


def test_search_ews_chunks_mailboxes_and_records_failed_chunks(mocker):
    executor = install(
        mocker, {"ews-search-mailboxes": [[error_entry("eDiscovery permission missing")], [ews_entry(ews_item())]]}
    )
    mailboxes = [f"user{index}@x.com" for index in range(sde.EWS_MAILBOX_CHUNK_SIZE + 1)]

    records = sde.search_ews(make_params(brands=[EWS_BRAND]), mailboxes)

    assert len(executor.args_of("ews-search-mailboxes")) == 2
    assert [record.found for record in records] == [False, True]
    assert "eDiscovery permission missing" in records[0].reason


def test_search_ews_filters_items_outside_the_time_frame(mocker):
    old = (datetime.now(UTC_TZ) - timedelta(days=2)).isoformat()
    install(mocker, {"ews-search-mailboxes": [[ews_entry(ews_item("i1", datetimeReceived=old), ews_item("i2"))]]})

    records = sde.search_ews(make_params(brands=[EWS_BRAND]), [MAILBOX])

    assert [record.object_id for record in records] == ["i2"]


def test_get_ews_by_id(mocker):
    executor = install(mocker, {"ews-get-items": [[ews_entry(ews_item("i5"))]]})

    records = sde.get_ews_by_id(make_params(object_id="i5"))

    assert [record.object_id for record in records] == ["i5"]
    assert executor.args_of("ews-get-items")[0]["item-ids"] == "i5"


def test_delete_ews_batches_items_per_mailbox_and_maps_delete_type(mocker):
    deleted = entry({"EWS.Items(val.itemId == obj.itemId)": [{"itemId": "i1"}, {"itemId": "i2"}]})
    executor = install(mocker, {"ews-delete-items": [[deleted], [entry()]]})
    records = [
        EmailRecord(brand=EWS_BRAND, mailbox="a@x.com", object_id="i1"),
        EmailRecord(brand=EWS_BRAND, mailbox="b@x.com", object_id="i3"),
        EmailRecord(brand=EWS_BRAND, mailbox="a@x.com", object_id="i2"),
    ]

    sde.delete_ews(make_params(delete_type=DELETE_HARD), records)

    first, second = executor.args_of("ews-delete-items")
    assert (first["target-mailbox"], first["item-ids"], first["delete-type"]) == ("a@x.com", "i1,i2", "hard")
    assert (second["target-mailbox"], second["item-ids"]) == ("b@x.com", "i3")
    assert all(record.deleted and record.success for record in records)


def test_delete_ews_marks_items_not_reported_as_failed(mocker):
    install(mocker, {"ews-delete-items": [[entry({"EWS.Items(val.itemId == obj.itemId)": [{"itemId": "i1"}]})]]})
    records = [EmailRecord(brand=EWS_BRAND, mailbox=MAILBOX, object_id=item_id) for item_id in ("i1", "i2")]

    sde.delete_ews(make_params(), records)

    assert records[0].deleted
    assert not records[1].deleted
    assert "not reported" in records[1].reason


def test_delete_ews_command_error_fails_the_whole_batch(mocker):
    install(mocker, {"ews-delete-items": [[error_entry("access denied")]]})
    records = [EmailRecord(brand=EWS_BRAND, mailbox=MAILBOX, object_id=item_id) for item_id in ("i1", "i2")]

    sde.delete_ews(make_params(), records)

    assert all(not record.success and "access denied" in record.reason for record in records)


def test_list_ews_mailboxes_only_for_message_id_searches(mocker):
    executor = install(
        mocker,
        {"ews-get-searchable-mailboxes": [[entry({"EWS.Mailboxes(val.mailbox == obj.mailbox)": [{"mailbox": "a@x.com"}]})]]},
    )

    assert sde.list_ews_mailboxes(make_params()) == []
    assert executor.calls == []
    assert sde.list_ews_mailboxes(make_params(internet_message_ids=["<1@x>"])) == ["a@x.com"]


""" MICROSOFT GRAPH SECURITY """


def test_build_kql_query_with_message_ids_and_mailboxes():
    params = make_params(internet_message_ids=["abc@x"], subject="ignored")

    query = sde.build_kql_query(params, ["a@x.com", "b@x.com"])

    assert query.startswith('kind:email AND (InternetMessageId:"<abc@x>") AND received>=')
    assert query.endswith("AND (participants:a@x.com OR participants:b@x.com)")
    assert "ignored" not in query


def test_build_kql_query_all_mailboxes_has_no_participants_clause():
    query = sde.build_kql_query(make_params(subject="Hi", sender_address="evil@bad.com"), [])

    assert 'subject:"Hi" AND from:"evil@bad.com"' in query
    assert "participants" not in query


def test_msgraph_security_search_only_creates_executes_retrieves_and_cleans_up(mocker):
    mocker.patch.object(sde.time, "sleep")
    executor = install(mocker, security_responses(total=3))

    records = sde.run_msgraph_security(make_params(brands=[MSGRAPH_SECURITY_BRAND]), [MAILBOX], delete=False)

    assert executor.commands == [
        "msg-list-ediscovery-cases",
        "msg-create-ediscovery-case",
        "msg-create-ediscovery-search",
        "msg-run-estimate-statistics",
        "msg-get-last-estimate-statistics-operation",
        "msg-delete-ediscovery-search",
    ]
    assert len(records) == 1
    assert (records[0].count, records[0].found, records[0].deleted) == (3, True, False)
    assert records[0].details["SearchID"] == "search1"
    assert executor.args_of("msg-delete-ediscovery-search")[0]["search_id"] == "search1"
    search_args = executor.args_of("msg-create-ediscovery-search")[0]
    assert search_args["data_source_scopes"] == "allTenantMailboxes"
    assert "participants:a@x.com" in search_args["content_query"]


def test_msgraph_security_reuses_existing_case(mocker):
    mocker.patch.object(sde.time, "sleep")
    executor = install(mocker, security_responses(existing_case=True))

    sde.run_msgraph_security(make_params(), [MAILBOX], delete=False)

    assert "msg-create-ediscovery-case" not in executor.commands
    assert executor.args_of("msg-create-ediscovery-search")[0]["case_id"] == "case1"


@pytest.mark.parametrize("delete_type, purge_type", [(DELETE_SOFT, "recoverable"), (DELETE_HARD, "permanentlyDelete")])
def test_msgraph_security_delete_purges_before_cleanup(mocker, delete_type, purge_type):
    mocker.patch.object(sde.time, "sleep")
    executor = install(mocker, security_responses())

    records = sde.run_msgraph_security(make_params(delete_type=delete_type), [MAILBOX], delete=True)

    assert executor.commands[-2:] == ["msg-purge-ediscovery-data", "msg-delete-ediscovery-search"]
    assert executor.args_of("msg-purge-ediscovery-data")[0]["purge_type"] == purge_type
    assert executor.args_of("msg-purge-ediscovery-data")[0]["purge_areas"] == "mailboxes"
    assert records[0].deleted
    assert records[0].success


def test_msgraph_security_polls_until_the_search_completes(mocker):
    sleep = mocker.patch.object(sde.time, "sleep")
    executor = install(mocker, security_responses(statuses=("running", "running", "succeeded")))

    records = sde.run_msgraph_security(make_params(), [MAILBOX], delete=False)

    assert len(executor.args_of("msg-get-last-estimate-statistics-operation")) == 3
    assert sleep.call_count == 2
    assert records[0].count == 3


def test_msgraph_security_no_results_skips_purge_but_still_cleans_up(mocker):
    mocker.patch.object(sde.time, "sleep")
    executor = install(mocker, security_responses(total=0))

    records = sde.run_msgraph_security(make_params(), [MAILBOX], delete=True)

    assert records == []
    assert "msg-purge-ediscovery-data" not in executor.commands
    assert "msg-delete-ediscovery-search" in executor.commands


def test_msgraph_security_cleans_up_when_the_search_operation_fails(mocker):
    mocker.patch.object(sde.time, "sleep")
    executor = install(mocker, security_responses(statuses=("failed",)))

    with pytest.raises(CommandError, match="ended with status 'failed'"):
        sde.run_msgraph_security(make_params(), [MAILBOX], delete=True)

    assert executor.commands[-1] == "msg-delete-ediscovery-search"
    assert "msg-purge-ediscovery-data" not in executor.commands


def test_msgraph_security_cleans_up_when_polling_times_out(mocker):
    mocker.patch.object(sde.time, "sleep")
    mocker.patch.object(sde, "MSGRAPH_SECURITY_POLL_MAX_ATTEMPTS", 2)
    executor = install(mocker, security_responses(statuses=("running",)))

    with pytest.raises(CommandError, match="Timed out"):
        sde.run_msgraph_security(make_params(), [MAILBOX], delete=False)

    assert len(executor.args_of("msg-get-last-estimate-statistics-operation")) == 2
    assert executor.commands[-1] == "msg-delete-ediscovery-search"


def test_msgraph_security_does_not_clean_up_when_the_search_was_not_created(mocker):
    responses = security_responses()
    responses["msg-create-ediscovery-search"] = [[error_entry("quota exceeded")]]
    executor = install(mocker, responses)

    with pytest.raises(CommandError, match="quota exceeded"):
        sde.run_msgraph_security(make_params(), [MAILBOX], delete=False)

    assert "msg-delete-ediscovery-search" not in executor.commands


def test_msgraph_security_cleanup_failure_does_not_mask_the_result(mocker):
    mocker.patch.object(sde.time, "sleep")
    log_error = mocker.patch.object(demisto, "error")
    responses = security_responses()
    responses["msg-delete-ediscovery-search"] = [[error_entry("delete failed")]]
    install(mocker, responses)

    records = sde.run_msgraph_security(make_params(), [MAILBOX], delete=True)

    assert records[0].deleted
    assert records[0].count == 3
    assert log_error.call_count == 1
    assert "delete failed" in log_error.call_args.args[0]


def test_msgraph_security_cleanup_failure_does_not_mask_the_original_error(mocker):
    mocker.patch.object(sde.time, "sleep")
    mocker.patch.object(demisto, "error")
    responses = security_responses(statuses=("failed",))
    responses["msg-delete-ediscovery-search"] = [[error_entry("delete failed")]]
    install(mocker, responses)

    with pytest.raises(CommandError, match="ended with status 'failed'"):
        sde.run_msgraph_security(make_params(), [MAILBOX], delete=False)


def test_msgraph_security_purge_failure_marks_the_record_failed(mocker):
    mocker.patch.object(sde.time, "sleep")
    responses = security_responses()
    responses["msg-purge-ediscovery-data"] = [[error_entry("purge not allowed")]]
    executor = install(mocker, responses)

    records = sde.run_msgraph_security(make_params(), [MAILBOX], delete=True)

    assert not records[0].deleted
    assert not records[0].success
    assert "purge not allowed" in records[0].reason
    assert executor.commands[-1] == "msg-delete-ediscovery-search"


def test_msgraph_security_failed_purge_status_marks_the_record_failed(mocker):
    mocker.patch.object(sde.time, "sleep")
    install(mocker, security_responses(purge_status="failed"))

    records = sde.run_msgraph_security(make_params(), [MAILBOX], delete=True)

    assert not records[0].success
    assert "status 'failed'" in records[0].reason


""" ORCHESTRATION """


def test_process_brand_search_only_does_not_delete(mocker):
    executor = install(mocker, {"gmail-search-all-mailboxes": [[gmail_entry(gmail_mail())]]})

    records = sde.process_brand(HANDLERS[GMAIL_BRAND], make_params())

    assert len(records) == 1
    assert not records[0].deleted
    assert "gmail-delete-mail" not in executor.commands


def test_process_brand_delete_flow_marks_records_deleted(mocker):
    executor = install(
        mocker,
        {"gmail-search-all-mailboxes": [[gmail_entry(gmail_mail())]], "gmail-delete-mail": [[entry()]]},
    )

    records = sde.process_brand(HANDLERS[GMAIL_BRAND], make_params(operation=OPERATION_DELETE))

    assert records[0].deleted
    assert records[0].success
    assert executor.commands == ["gmail-search-all-mailboxes", "gmail-delete-mail"]


def test_process_brand_with_object_id_gets_the_item_instead_of_searching(mocker):
    executor = install(mocker, {"gmail-get-mail": [[gmail_entry(gmail_mail("m9"))]], "gmail-delete-mail": [[entry()]]})
    params = make_params(operation=OPERATION_DELETE, object_id="m9", subject="")

    records = sde.process_brand(HANDLERS[GMAIL_BRAND], params)

    assert executor.commands == ["gmail-get-mail", "gmail-delete-mail"]
    assert records[0].deleted


def test_process_brand_does_not_delete_failed_search_placeholders(mocker):
    executor = install(mocker, {"gmail-search-all-mailboxes": [[error_entry()]], "gmail-search": [[error_entry()]]})

    records = sde.process_brand(HANDLERS[GMAIL_BRAND], make_params(operation=OPERATION_DELETE))

    assert [record.found for record in records] == [False]
    assert "gmail-delete-mail" not in executor.commands


def test_process_brand_retrieves_attachments_before_deleting(mocker, tmp_path):
    attachment_path = tmp_path / "invoice.txt"
    attachment_path.write_bytes(b"secret")
    mocker.patch.object(demisto, "getFilePath", return_value={"path": str(attachment_path), "name": "invoice.txt"})
    file_entry = {"Type": EntryType.FILE, "ID": "file-1", "File": "invoice.txt", "Contents": "", "EntryContext": {}}
    executor = install(
        mocker,
        {
            "gmail-search-all-mailboxes": [[gmail_entry(gmail_mail(Attachments=[{"ID": "a1", "Name": "invoice.txt"}]))]],
            "gmail-get-attachments": [[file_entry]],
            "gmail-delete-mail": [[entry()]],
        },
    )

    records = sde.process_brand(HANDLERS[GMAIL_BRAND], make_params(operation=OPERATION_DELETE, retrieve_files=True))

    assert executor.commands == ["gmail-search-all-mailboxes", "gmail-get-attachments", "gmail-delete-mail"]
    assert records[0].attachments == {"invoice.txt": hashlib.sha256(b"secret").hexdigest()}
    assert records[0].files[0].data == b"secret"


def test_fetch_attachments_skips_emails_without_attachments(mocker):
    executor = install(mocker, {"ews-get-attachment": [[entry()]]})
    record = EmailRecord(brand=EWS_BRAND, mailbox=MAILBOX, object_id="i1", has_attachments=False)

    sde.fetch_attachments(HANDLERS[EWS_BRAND], record)

    assert executor.calls == []


def test_fetch_attachments_failure_is_recorded_and_does_not_fail_the_record(mocker):
    install(mocker, {"ews-get-attachment": [[error_entry("cannot read attachment")]]})
    record = EmailRecord(brand=EWS_BRAND, mailbox=MAILBOX, object_id="i1", has_attachments=True)

    sde.fetch_attachments(HANDLERS[EWS_BRAND], record)

    assert record.success
    assert record.attachments == {}
    assert "cannot read attachment" in record.details["AttachmentsError"]


def test_verify_deletion_succeeds_when_the_email_is_gone(mocker):
    executor = install(
        mocker,
        {
            "gmail-search-all-mailboxes": [[gmail_entry(gmail_mail())], [entry()]],
            "gmail-delete-mail": [[entry()]],
        },
    )

    records = sde.process_brand(HANDLERS[GMAIL_BRAND], make_params(operation=OPERATION_DELETE, verify_deletion=True))

    assert records[0].deleted
    assert records[0].success
    assert records[0].verified is True
    assert len(executor.args_of("gmail-search-all-mailboxes")) == 2
    assert executor.args_of("gmail-search-all-mailboxes")[1]["include-spam-trash"] == "False"


def test_verify_deletion_fails_when_the_email_still_exists(mocker):
    install(
        mocker,
        {
            "gmail-search-all-mailboxes": [[gmail_entry(gmail_mail())], [gmail_entry(gmail_mail())]],
            "gmail-delete-mail": [[entry()]],
        },
    )

    records = sde.process_brand(HANDLERS[GMAIL_BRAND], make_params(operation=OPERATION_DELETE, verify_deletion=True))

    assert not records[0].deleted
    assert not records[0].success
    assert "still exists" in records[0].reason


def test_verify_deletion_error_is_reported_without_crashing(mocker):
    install(
        mocker,
        {
            "gmail-search-all-mailboxes": [[gmail_entry(gmail_mail())]],
            "gmail-delete-mail": [[entry()]],
        },
    )
    # HANDLERS keeps the original `search_gmail` for the search phase, so only the verification call is patched.
    mocker.patch.object(sde, "search_gmail", side_effect=RuntimeError("api down"))

    records = sde.process_brand(HANDLERS[GMAIL_BRAND], make_params(operation=OPERATION_DELETE, verify_deletion=True))

    assert not records[0].success
    assert "could not be verified" in records[0].reason


def test_verify_msgraph_mail_and_ews_use_item_lookup(mocker):
    executor = install(
        mocker,
        {
            "msgraph-mail-get-email": [[error_entry("ErrorItemNotFound")]],
            "ews-get-items": [[ews_entry(ews_item("i1"))], [entry()]],
        },
    )
    graph_record = EmailRecord(brand=MSGRAPH_MAIL_BRAND, mailbox=MAILBOX, object_id="g1")
    ews_present = EmailRecord(brand=EWS_BRAND, mailbox=MAILBOX, object_id="i1")
    ews_gone = EmailRecord(brand=EWS_BRAND, mailbox=MAILBOX, object_id="i2")

    assert sde.verify_msgraph_mail(make_params(), [graph_record]) == set()
    assert sde.verify_ews(make_params(), [ews_present, ews_gone]) == {"i1"}
    assert executor.args_of("msgraph-mail-get-email")[0]["message_id"] == "g1"


def test_verify_deletion_is_ignored_for_msgraph_security(mocker):
    mocker.patch.object(sde.time, "sleep")
    executor = install(mocker, security_responses())
    params = make_params(brands=[MSGRAPH_SECURITY_BRAND], operation=OPERATION_DELETE, verify_deletion=True)

    records = sde.process_brand(HANDLERS[MSGRAPH_SECURITY_BRAND], params)

    assert "msg-purge-ediscovery-data" in executor.commands
    assert records[0].deleted
    assert records[0].verified is None


def test_run_brand_isolates_failures_into_a_failed_record(mocker):
    install(mocker, {"gmail-search-all-mailboxes": [[gmail_entry(gmail_mail())]]})
    mocker.patch.object(sde, "process_brand", side_effect=RuntimeError("unexpected"))

    records = sde.run_brand(HANDLERS[GMAIL_BRAND], make_params())

    assert len(records) == 1
    assert (records[0].brand, records[0].found, records[0].success) == (GMAIL_BRAND, False, False)
    assert records[0].reason == "unexpected"


def test_run_all_brands_one_failing_brand_does_not_stop_the_others(mocker):
    install(
        mocker,
        {
            "gmail-search-all-mailboxes": [[error_entry("gmail down")]],
            "gmail-search": [[error_entry("gmail down")]],
            "ews-search-mailboxes": [[ews_entry(ews_item())]],
        },
    )

    records = sde.run_all_brands(make_params(brands=[GMAIL_BRAND, EWS_BRAND]))

    assert [(record.brand, record.found) for record in records] == [(GMAIL_BRAND, False), (EWS_BRAND, True)]


""" OUTPUT """


def test_compute_totals():
    deleted = EmailRecord(brand=GMAIL_BRAND, deleted=True)
    delete_failed = EmailRecord(brand=GMAIL_BRAND, success=False, reason="denied")
    brand_failure = sde.error_record(EWS_BRAND, "down")
    aggregated = EmailRecord(brand=MSGRAPH_SECURITY_BRAND, count=5, deleted=True)

    assert sde.compute_totals([deleted, delete_failed, brand_failure, aggregated]) == {
        "TotalFound": 7,
        "TotalDeleted": 6,
        "TotalFailed": 2,
    }


def test_build_email_data_hides_additional_details_unless_verbose():
    record = EmailRecord(
        brand=GMAIL_BRAND,
        mailbox="a@x.com,b@x.com",
        object_id="m1",
        subject="Invoice",
        sender="evil@bad.com",
        to=["a@x.com"],
        html="<b>x</b>",
        timestamp=NOW_ISO,
        internet_message_id="<abc@bad.com>",
        attachments={"a.txt": "hash"},
        details={"Body": "hi", "Labels": [], "Headers": None},
        deleted=True,
        verified=True,
    )

    regular = sde.build_email_data(record, make_params(operation=OPERATION_DELETE))
    verbose = sde.build_email_data(record, make_params(operation=OPERATION_DELETE, verbose=True))

    assert regular["Mailbox"] == ["a@x.com", "b@x.com"]
    assert (regular["Subject"], regular["From"], regular["To"], regular["HTML"]) == (
        "Invoice",
        "evil@bad.com",
        ["a@x.com"],
        "<b>x</b>",
    )
    assert (regular["Success"], regular["Reason"], regular["Operation"], regular["Brand"]) == (
        True,
        "",
        OPERATION_DELETE,
        GMAIL_BRAND,
    )
    assert regular["Attachments"] == {"a.txt": "hash"}
    assert regular["AdditionalFields"] == {
        "ObjectID": "m1",
        "InternetMessageID": "<abc@bad.com>",
        "Deleted": True,
        "Verified": True,
    }
    assert verbose["AdditionalFields"]["Body"] == "hi"
    assert "Labels" not in verbose["AdditionalFields"]


def test_build_command_results_context_and_human_readable():
    records = [
        EmailRecord(brand=GMAIL_BRAND, mailbox=MAILBOX, object_id="m1", subject="Invoice", deleted=True),
        sde.error_record(EWS_BRAND, "ews down"),
    ]

    results = sde.build_command_results(records, make_params(operation=OPERATION_DELETE))

    assert len(results) == 1
    result = results[0]
    assert isinstance(result, CommandResults)
    outputs = outputs_of(result)
    assert (outputs["TotalFound"], outputs["TotalDeleted"], outputs["TotalFailed"]) == (1, 1, 1)
    assert [email["Brand"] for email in outputs["EmailData"]] == [GMAIL_BRAND, EWS_BRAND]
    assert "ews down" in result.readable_output
    assert "**Total found:** 1" in result.readable_output
    assert result.entry_type == EntryType.NOTE


def test_build_command_results_without_emails_reports_zero_totals():
    result = sde.build_command_results([], make_params())[0]

    assert result.outputs == {"EmailData": [], "TotalFound": 0, "TotalDeleted": 0, "TotalFailed": 0}
    assert "No emails were found." in result.readable_output
    assert result.entry_type == EntryType.NOTE


def test_build_command_results_returns_file_entries_and_file_context(mocker):
    file_result = mocker.patch.object(sde, "fileResult", return_value={"File": "a.txt"})
    record = EmailRecord(brand=GMAIL_BRAND, mailbox=MAILBOX, files=[Attachment("a.txt", b"abc")], attachments={"a.txt": "h"})

    results = sde.build_command_results([record], make_params())

    assert len(results) == 2
    assert results[1] == {"File": "a.txt"}
    file_result.assert_called_once_with("a.txt", b"abc")
    file_context = outputs_of(results[0])["File(val.SHA256 && val.SHA256 == obj.SHA256)"]
    assert file_context == [{"Name": "a.txt", "SHA256": hashlib.sha256(b"abc").hexdigest(), "Size": 3, "Extension": "txt"}]


def test_all_brands_failing_returns_human_readable_error_and_context(mocker):
    install(mocker, {"gmail-search-all-mailboxes": [[error_entry("gmail down")]], "gmail-search": [[error_entry("gmail down")]]})
    params = make_params()

    results = sde.build_command_results(sde.run_all_brands(params), params)

    result = results[0]
    assert result.entry_type == EntryType.ERROR
    outputs = outputs_of(result)
    assert outputs["TotalFailed"] == 1
    assert outputs["TotalFound"] == 0
    assert outputs["EmailData"][0]["Success"] is False
    assert "gmail down" in outputs["EmailData"][0]["Reason"]
    assert "failed for all the integrations" in result.readable_output


""" MAIN """


def mock_main(mocker, args: dict, brands: tuple[str, ...] = (MSGRAPH_SECURITY_BRAND, GMAIL_BRAND)):
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={str(index): {"brand": brand, "state": "active"} for index, brand in enumerate(brands)},
    )
    return mocker.patch.object(sde, "return_results")


def test_main_returns_error_for_invalid_input(mocker):
    mock_main(mocker, {"subject": "x"})
    return_error = mocker.patch.object(sde, "return_error")

    sde.main()

    assert "'operation' argument is required" in return_error.call_args.args[0]


def test_main_warns_when_verify_deletion_is_used_with_msgraph_security_and_still_proceeds(mocker):
    return_results = mock_main(
        mocker,
        {"operation": OPERATION_DELETE, "target_mailbox": MAILBOX, "subject": "x", "verify_deletion": "true"},
    )
    run_all = mocker.patch.object(
        sde, "run_all_brands", return_value=[EmailRecord(brand=MSGRAPH_SECURITY_BRAND, count=2, deleted=True)]
    )

    sde.main()

    warning = return_results.call_args_list[0].args[0]
    assert warning.entry_type == EntryType.WARNING
    assert "not supported for Microsoft Graph Security" in warning.readable_output
    run_all.assert_called_once()
    assert run_all.call_args.args[0].verify_deletion is True
    final = return_results.call_args_list[1].args[0]
    assert outputs_of(final[0])["TotalDeleted"] == 2


def test_main_does_not_warn_without_verify_deletion_or_without_msgraph_security(mocker):
    return_results = mock_main(mocker, {"operation": OPERATION_SEARCH, "target_mailbox": MAILBOX, "subject": "x"})
    mocker.patch.object(sde, "run_all_brands", return_value=[])
    sde.main()
    assert return_results.call_count == 1

    return_results = mock_main(
        mocker,
        {"operation": OPERATION_DELETE, "target_mailbox": MAILBOX, "subject": "x", "verify_deletion": "true", "brands": "Gmail"},
    )
    sde.main()
    assert return_results.call_count == 1


def test_main_unexpected_exception_still_returns_results_with_failure_totals(mocker):
    return_results = mock_main(
        mocker, {"operation": OPERATION_SEARCH, "target_mailbox": MAILBOX, "subject": "x", "brands": "Gmail"}
    )
    mocker.patch.object(sde, "run_all_brands", side_effect=RuntimeError("kaboom"))
    mocker.patch.object(demisto, "error")

    sde.main()

    result = return_results.call_args.args[0][0]
    outputs = outputs_of(result)
    assert outputs["TotalFailed"] == 1
    assert outputs["EmailData"][0]["Reason"] == "kaboom"
