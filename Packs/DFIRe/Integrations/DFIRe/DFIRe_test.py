"""Unit tests for the DFIRe integration.

Each test mocks `Client._http_request` and asserts both the outbound request
shape (method, URL, body / params) and the resulting `CommandResults`. Many
command families share a single parametrised test to keep the suite compact.
"""

import pytest

import DFIRe


BASE_URL = "https://dfire.test/api"  # disable-secrets-detection


@pytest.fixture
def client(mocker):
    """A Client whose `_http_request` is a MagicMock the tests drive directly."""
    c = DFIRe.Client(
        base_url=BASE_URL,
        verify=False,
        headers={"Authorization": "Bearer dfire_ak_test"},
        proxy=False,
    )
    mocker.patch.object(c, "_http_request")
    return c


# ── Helper-function tests ─────────────────────────────────


def test_build_optional_body_filters_none():
    args = {"a": "v", "b": None, "c": 0, "d": False, "e": ""}
    body = DFIRe.build_optional_body(args, ["a", "b", "c", "d", "e", "missing"])
    # build_optional_body uses `is not None` so 0, False, "" all survive.
    assert body == {"a": "v", "c": 0, "d": False, "e": ""}


def test_extract_case_todos_handles_list(client):
    client._http_request.return_value = {"todo_checklist": [{"id": "t1"}, {"id": "t2"}]}
    assert DFIRe._extract_case_todos(client, 5) == [{"id": "t1"}, {"id": "t2"}]


def test_extract_case_todos_handles_nested_results(client):
    client._http_request.return_value = {"todo_checklist": {"results": [{"id": "t1"}]}}
    assert DFIRe._extract_case_todos(client, 5) == [{"id": "t1"}]


def test_extract_case_todos_handles_missing(client):
    client._http_request.return_value = {}
    assert DFIRe._extract_case_todos(client, 5) == []


# ── test-module ───────────────────────────────────────────


def test_test_module(client):
    client._http_request.return_value = {"results": []}
    assert DFIRe.test_module(client) == "ok"
    args, kwargs = client._http_request.call_args
    assert args[0] == "GET"
    assert args[1] == "/cases/"


# ── Search ────────────────────────────────────────────────


def test_search_command(client):
    client._http_request.return_value = {"results": [{"id": 1, "type": "case", "title": "T"}]}
    result = DFIRe.search_command(client, {"query": "test"})
    args, kwargs = client._http_request.call_args
    assert args == ("GET", "/search/")
    assert kwargs["params"] == {"q": "test"}
    assert result.outputs_prefix == "DFIRe.Search"


# ── Cases — list/get/create/update/delete ────────────────


def test_case_list_passes_all_filters(client):
    client._http_request.return_value = {"results": []}
    DFIRe.case_list_command(
        client,
        {
            "limit": "25",
            "page": "2",
            "status": "OPEN",
            "status_in": "OPEN,CLOSED",
            "severity": "high",
            "case_mode": "incident",
            "lead_investigator": "7",
            "created_at_gte": "2026-01-01T00:00:00Z",
            "created_at_lte": "2026-12-31T23:59:59Z",
            "ordering": "-created_at",
        },
    )
    args, kwargs = client._http_request.call_args
    assert args == ("GET", "/cases/")
    p = kwargs["params"]
    assert p["page_size"] == 25
    assert p["page"] == 2
    assert p["status"] == "OPEN"
    assert p["status__in"] == "OPEN,CLOSED"
    assert p["severity"] == "high"
    assert p["case_mode"] == "incident"
    assert p["lead_investigator"] == 7
    assert p["created_at__gte"] == "2026-01-01T00:00:00Z"
    assert p["created_at__lte"] == "2026-12-31T23:59:59Z"
    assert p["ordering"] == "-created_at"


def test_case_get(client):
    client._http_request.return_value = {"id": 1, "case_number": "CASE-1"}
    result = DFIRe.case_get_command(client, {"case_id": "1"})
    assert client._http_request.call_args.args == ("GET", "/cases/1/")
    assert result.outputs["id"] == 1


def test_case_create_defaults_slack_channel_false(client):
    client._http_request.return_value = {"id": 9}
    DFIRe.case_create_command(client, {"title": "T", "case_type": "6"})
    body = client._http_request.call_args.kwargs["json_data"]
    assert body["title"] == "T"
    assert body["case_type"] == 6
    # The whole point of v1.1.0: SOAR-created cases do not spawn Slack channels by default.
    assert body["create_slack_channel"] is False


def test_case_create_allows_slack_channel_opt_in(client):
    client._http_request.return_value = {"id": 9}
    DFIRe.case_create_command(client, {"title": "T", "case_type": "6", "create_slack_channel": "true"})
    assert client._http_request.call_args.kwargs["json_data"]["create_slack_channel"] is True


def test_case_create_propagates_new_fields(client):
    client._http_request.return_value = {"id": 9}
    DFIRe.case_create_command(
        client,
        {
            "title": "T",
            "case_type": "6",
            "notes": "N",
            "lead_investigator": "3",
            "investigators": "1,2,3",
            "viewers": "4,5",
            "incident_category": "2",
            "outcome_verdict": "1",
            "attributes": '{"k":"v"}',
        },
    )
    body = client._http_request.call_args.kwargs["json_data"]
    assert body["notes"] == "N"
    assert body["lead_investigator"] == 3
    assert body["investigators"] == [1, 2, 3]
    assert body["viewers"] == [4, 5]
    assert body["incident_category"] == 2
    assert body["outcome_verdict"] == 1
    assert body["attributes"] == {"k": "v"}


def test_case_update_requires_at_least_one_field(client):
    with pytest.raises(DFIRe.DemistoException, match="At least one field"):
        DFIRe.case_update_command(client, {"case_id": "1"})


def test_case_update_sends_patch_with_partial_body(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.case_update_command(client, {"case_id": "1", "title": "New", "investigators": "1,2"})
    args, kwargs = client._http_request.call_args
    assert args == ("PATCH", "/cases/1/")
    assert kwargs["json_data"] == {"title": "New", "investigators": [1, 2]}


def test_case_delete(client):
    DFIRe.case_delete_command(client, {"case_id": "1"})
    args, kwargs = client._http_request.call_args
    assert args == ("DELETE", "/cases/1/")
    assert kwargs["resp_type"] == "response"


def test_case_get_by_number(client):
    client._http_request.return_value = {"id": 1, "case_number": "CASE-1"}
    DFIRe.case_get_by_number_command(client, {"case_number": "CASE-2026-001"})
    assert client._http_request.call_args.args == ("GET", "/case/CASE-2026-001/")


# ── Case notes / timeline ─────────────────────────────────


def test_case_note_list(client):
    client._http_request.return_value = [{"id": 1}]
    DFIRe.case_note_list_command(client, {"case_id": "1"})
    args, kwargs = client._http_request.call_args
    assert args == ("GET", "/case-notes/")
    assert kwargs["params"] == {"case": 1}


def test_case_note_create(client):
    client._http_request.return_value = {"id": 2}
    DFIRe.case_note_create_command(client, {"case_id": "1", "note": "hi", "show_on_timeline": "true"})
    body = client._http_request.call_args.kwargs["json_data"]
    assert body == {"case": 1, "note": "hi", "show_on_timeline": True}


def test_timeline_list(client):
    client._http_request.return_value = {"events": []}
    DFIRe.timeline_list_command(client, {"case_id": "1"})
    assert client._http_request.call_args.args == ("GET", "/cases/1/timeline/")


def test_timeline_create_defaults_event_datetime(client):
    """The API requires event_datetime; the integration must inject a default when omitted."""
    client._http_request.return_value = {"id": 1}
    DFIRe.timeline_create_command(client, {"case_id": "1", "subject": "S"})
    body = client._http_request.call_args.kwargs["json_data"]
    assert "event_datetime" in body
    assert body["event_datetime"].endswith("Z")
    assert body["subject"] == "S"


def test_timeline_create_uses_supplied_event_datetime(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.timeline_create_command(client, {"case_id": "1", "subject": "S", "event_datetime": "2026-05-01T10:00:00Z"})
    body = client._http_request.call_args.kwargs["json_data"]
    assert body["event_datetime"] == "2026-05-01T10:00:00Z"


def test_case_timeline_change_phase(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.case_timeline_change_phase_command(client, {"case_id": "1", "phase_id": "3", "note": "Move on"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/timeline/change-phase/")
    assert kwargs["json_data"] == {"phase_id": 3, "note": "Move on"}


# ── Indicators ────────────────────────────────────────────


def test_indicator_list_passes_all_filters(client):
    client._http_request.return_value = {"results": []}
    DFIRe.indicator_list_command(
        client,
        {
            "limit": "100",
            "offset": "10",
            "search": "term",
            "stix_type": "domain-name",
            "classification": "suspicious",
            "confidence": "high",
            "tlp": "amber",
            "is_published": "true",
            "is_revoked": "false",
            "parent": "5",
            "ordering": "-created_at",
        },
    )
    p = client._http_request.call_args.kwargs["params"]
    assert p["limit"] == 100
    assert p["offset"] == 10
    assert p["search"] == "term"
    assert p["parent"] == 5
    assert p["ordering"] == "-created_at"


def test_indicator_create(client):
    client._http_request.return_value = {"id": 1, "is_existing": False}
    DFIRe.indicator_create_command(client, {"value": "1.2.3.4", "stix_type": "ipv4-addr", "tags": "a,b"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/indicators/")
    assert kwargs["json_data"]["tags"] == ["a", "b"]
    assert kwargs["ok_codes"] == (200, 201)


def test_indicator_update_requires_field(client):
    with pytest.raises(DFIRe.DemistoException):
        DFIRe.indicator_update_command(client, {"indicator_id": "1"})


def test_indicator_delete(client):
    DFIRe.indicator_delete_command(client, {"indicator_id": "1"})
    assert client._http_request.call_args.args == ("DELETE", "/indicators/1/")


@pytest.mark.parametrize(
    "command_fn,sub_path,action_label",
    [
        (DFIRe.indicator_publish_command, "publish", "Published"),
        (DFIRe.indicator_unpublish_command, "unpublish", "Unpublished"),
        (DFIRe.indicator_revoke_command, "revoke", "Revoked"),
        (DFIRe.indicator_unrevoke_command, "unrevoke", "Unrevoked"),
        (DFIRe.indicator_decompose_command, "decompose", "Decomposed"),
    ],
)
def test_indicator_lifecycle_commands(client, command_fn, sub_path, action_label):
    client._http_request.return_value = {"id": 1, sub_path: True}
    result = command_fn(client, {"indicator_id": "1"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", f"/indicators/1/{sub_path}/")
    assert kwargs["json_data"] == {}
    assert action_label in result.readable_output


def test_indicator_add_tags(client):
    client._http_request.return_value = {"id": 1, "tags": ["a", "b"]}
    DFIRe.indicator_add_tags_command(client, {"indicator_id": "1", "tags": "a,b"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/indicators/1/add-tags/")
    assert kwargs["json_data"] == {"tags": ["a", "b"]}


def test_indicator_add_tags_requires_tags(client):
    with pytest.raises(DFIRe.DemistoException, match="tags"):
        DFIRe.indicator_add_tags_command(client, {"indicator_id": "1", "tags": ""})


def test_indicator_enrich(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.indicator_enrich_command(client, {"indicator_id": "1", "providers": "dns,whois", "force": "true"})
    body = client._http_request.call_args.kwargs["json_data"]
    assert body == {"providers": ["dns", "whois"], "force": True}


def test_indicator_enrichment_list(client):
    client._http_request.return_value = {"enrichments": []}
    DFIRe.indicator_enrichment_list_command(client, {"indicator_id": "1"})
    assert client._http_request.call_args.args == ("GET", "/indicators/1/enrichments/")


def test_indicator_correlated_list(client):
    client._http_request.return_value = {"results": []}
    DFIRe.indicator_correlated_list_command(client, {})
    assert client._http_request.call_args.args == ("GET", "/indicators/correlated/")


def test_ioc_extract(client):
    client._http_request.return_value = {"candidates": [{"value": "1.2.3.4", "stix_type": "ipv4-addr"}]}
    DFIRe.ioc_extract_command(client, {"text": "see 1.2.3.4"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/ioc/extract/")
    assert kwargs["json_data"] == {"text": "see 1.2.3.4"}


def test_indicator_check_with_values_arg(client):
    client._http_request.return_value = {"results": [{"value": "1.2.3.4", "exists": False}]}
    DFIRe.indicator_check_command(client, {"values": "1.2.3.4,5.6.7.8", "stix_type": "ipv4-addr"})
    body = client._http_request.call_args.kwargs["json_data"]
    assert body == {
        "indicators": [
            {"value": "1.2.3.4", "stix_type": "ipv4-addr"},
            {"value": "5.6.7.8", "stix_type": "ipv4-addr"},
        ]
    }


def test_indicator_check_with_indicators_json(client):
    client._http_request.return_value = {"results": []}
    DFIRe.indicator_check_command(client, {"indicators": '[{"value":"a","stix_type":"domain-name"}]'})
    body = client._http_request.call_args.kwargs["json_data"]
    assert body == {"indicators": [{"value": "a", "stix_type": "domain-name"}]}


def test_indicator_check_requires_either_form(client):
    with pytest.raises(DFIRe.DemistoException):
        DFIRe.indicator_check_command(client, {})


# ── Bulk indicator commands (parametrised) ────────────────


@pytest.mark.parametrize(
    "command_fn,sub_path,extra_args,expected_extra",
    [
        (
            DFIRe.indicator_bulk_classify_command,
            "bulk-classify",
            {"classification": "malicious"},
            {"classification": "malicious"},
        ),
        (
            DFIRe.indicator_bulk_confidence_command,
            "bulk-confidence",
            {"confidence": "high"},
            {"confidence": "high"},
        ),
        (
            DFIRe.indicator_bulk_tag_command,
            "bulk-tag",
            {"tags": "a,b", "mode": "add"},
            {"tags": ["a", "b"], "mode": "add"},
        ),
        (
            DFIRe.indicator_bulk_tlp_command,
            "bulk-tlp",
            {"tlp": "amber"},
            {"tlp": "amber"},
        ),
        (DFIRe.indicator_bulk_publish_command, "bulk-publish", {}, {}),
        (DFIRe.indicator_bulk_revoke_command, "bulk-revoke", {}, {}),
        (DFIRe.indicator_bulk_delete_command, "bulk-delete", {}, {}),
    ],
)
def test_indicator_bulk_commands(client, command_fn, sub_path, extra_args, expected_extra):
    client._http_request.return_value = {"updated": 2}
    args = {"indicator_ids": "1,2", **extra_args}
    command_fn(client, args)
    call_args, call_kwargs = client._http_request.call_args
    assert call_args == ("POST", f"/indicators/{sub_path}/")
    body = call_kwargs["json_data"]
    assert body["indicator_ids"] == [1, 2]
    for k, v in expected_extra.items():
        assert body[k] == v


def test_indicator_bulk_classify_requires_classification(client):
    with pytest.raises(DFIRe.DemistoException):
        DFIRe.indicator_bulk_classify_command(client, {"indicator_ids": "1"})


def test_indicator_bulk_commands_reject_empty_ids(client):
    with pytest.raises(DFIRe.DemistoException, match="indicator_ids"):
        DFIRe.indicator_bulk_publish_command(client, {"indicator_ids": ""})


# ── Case indicators ───────────────────────────────────────


def test_case_indicator_list(client):
    client._http_request.return_value = [{"id": 1, "indicator": {"id": 9}}]
    DFIRe.case_indicator_list_command(client, {"case_id": "1"})
    assert client._http_request.call_args.args == ("GET", "/cases/1/indicators/")


def test_case_indicator_add_includes_new_fields(client):
    client._http_request.return_value = {"id": 5}
    DFIRe.case_indicator_add_command(
        client,
        {
            "case_id": "1",
            "value": "1.2.3.4",
            "stix_type": "ipv4-addr",
            "source": "automated",
            "valid_until": "2026-12-31T00:00:00Z",
            "publish": "true",
            "decompose": "false",
            "tags": "a,b",
        },
    )
    body = client._http_request.call_args.kwargs["json_data"]
    assert body["source"] == "automated"
    assert body["valid_until"] == "2026-12-31T00:00:00Z"
    assert body["publish"] is True
    assert body["decompose"] is False
    assert body["tags"] == ["a", "b"]


def test_case_indicator_remove(client):
    DFIRe.case_indicator_remove_command(client, {"case_id": "1", "association_id": "2"})
    args, kwargs = client._http_request.call_args
    assert args == ("DELETE", "/cases/1/indicators/2/")
    assert kwargs["resp_type"] == "response"


# ── Items ─────────────────────────────────────────────────


def test_item_get_accepts_uuid_string(client):
    """Regression: items have UUID ids; arg_to_number used to coerce and break this."""
    uuid = "d9230268-8ad9-4d1d-812d-bee11c1c51ca"
    client._http_request.return_value = {"uuid": uuid, "name": "x"}
    DFIRe.item_get_command(client, {"item_id": uuid})
    assert client._http_request.call_args.args == ("GET", f"/items/{uuid}/")


def test_item_get_requires_item_id(client):
    with pytest.raises(DFIRe.DemistoException):
        DFIRe.item_get_command(client, {})


def test_item_resolve_short_id(client):
    client._http_request.return_value = {"uuid": "d9230268-..."}
    DFIRe.item_resolve_short_id_command(client, {"short_id": "d9230268"})
    assert client._http_request.call_args.args == ("GET", "/item/d9230268/")


def test_item_list(client):
    client._http_request.return_value = [{"uuid": "x"}]
    DFIRe.item_list_command(client, {"case_id": "1"})
    args, kwargs = client._http_request.call_args
    assert args == ("GET", "/items/")
    assert kwargs["params"] == {"case": 1}


def test_item_create(client):
    client._http_request.return_value = {"uuid": "x"}
    DFIRe.item_create_command(
        client,
        {"case_id": "1", "item_type": "19", "location": "loc", "name": "n"},
    )
    body = client._http_request.call_args.kwargs["json_data"]
    assert body["case"] == 1
    assert body["item_type"] == 19
    assert body["location"] == "loc"
    assert body["name"] == "n"


# ── Attachments ───────────────────────────────────────────


def test_attachment_list(client):
    client._http_request.return_value = [{"id": 1}]
    DFIRe.attachment_list_command(client, {"item_uuid": "u"})
    args, kwargs = client._http_request.call_args
    assert args == ("GET", "/attachments/")
    assert kwargs["params"] == {"item": "u"}


def test_attachment_get(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.attachment_get_command(client, {"attachment_id": "1"})
    assert client._http_request.call_args.args == ("GET", "/attachments/1/")


def test_attachment_delete(client):
    DFIRe.attachment_delete_command(client, {"attachment_id": "1"})
    args, kwargs = client._http_request.call_args
    assert args == ("DELETE", "/attachments/1/")
    assert kwargs["resp_type"] == "response"


def test_attachment_upload_orchestrates_init_chunks_complete(client, mocker, tmp_path):
    """Confirms the three-phase chunked upload calls init, upload, complete in order."""
    sample = tmp_path / "blob.bin"
    sample.write_bytes(b"x" * 12)

    # demisto.getFilePath returns where the War Room file lives on disk.
    mocker.patch.object(DFIRe.demisto, "getFilePath", return_value={"path": str(sample), "name": "blob.bin"})

    # init → upload (called per chunk) → complete
    client._http_request.side_effect = [
        {"session_id": "sess", "chunk_size": 5},  # init: 5-byte chunks → 3 chunks for 12 bytes
        {"chunk_index": 0},
        {"chunk_index": 1},
        {"chunk_index": 2},
        {"id": 99, "status": "processing"},  # complete
    ]
    DFIRe.attachment_upload_command(client, {"entry_id": "e1", "case_id": "1", "category": "general"})
    calls = client._http_request.call_args_list
    assert calls[0].args == ("POST", "/attachments/chunked/init/")
    assert calls[1].args == ("POST", "/attachments/chunked/sess/upload/")
    assert calls[-1].args == ("POST", "/attachments/chunked/sess/complete/")


# ── Users ─────────────────────────────────────────────────


def test_user_list(client):
    client._http_request.return_value = [{"id": 1, "username": "admin"}]
    DFIRe.user_list_command(client, {})
    assert client._http_request.call_args.args == ("GET", "/users/")


# ── Case AI / reports ─────────────────────────────────────


def test_case_generate_summary_uses_get_and_reads_text(client):
    """Regression: this endpoint is GET (not POST) and returns text/plain (not JSON)."""
    client._http_request.return_value = "Case Summary for CASE-1\n----\nstatus: OPEN"
    result = DFIRe.case_generate_summary_command(client, {"case_id": "1"})
    args, kwargs = client._http_request.call_args
    assert args == ("GET", "/cases/1/generate-summary/")
    assert kwargs["resp_type"] == "text"
    assert result.outputs["summary"].startswith("Case Summary")


def test_case_chat(client):
    client._http_request.return_value = {"reply": "ok"}
    DFIRe.case_chat_command(client, {"case_id": "1", "message": "hi"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/chat/")
    assert kwargs["json_data"] == {"message": "hi"}


def test_case_update_report_uses_explicit_args(client):
    """v1.1.2: explicit report_id/report_text, not a raw body blob."""
    client._http_request.return_value = {"ok": True}
    DFIRe.case_update_report_command(client, {"case_id": "1", "report_id": "5", "report_text": "new text"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/update-report/")
    assert kwargs["json_data"] == {"id": 5, "report_text": "new text"}


def test_case_can_report_list(client):
    client._http_request.return_value = {"results": []}
    DFIRe.case_can_report_list_command(client, {"case_id": "1"})
    assert client._http_request.call_args.args == ("GET", "/cases/1/can-reports/")


def test_case_can_report_generate(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.case_can_report_generate_command(client, {"case_id": "1"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/can-reports/generate/")
    assert kwargs["json_data"] == {}


def test_case_investigation_report_get(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.case_investigation_report_get_command(client, {"case_id": "1"})
    assert client._http_request.call_args.args == ("GET", "/cases/1/investigation-report/")


def test_case_investigation_report_generate_requires_section_id(client):
    with pytest.raises(KeyError):
        DFIRe.case_investigation_report_generate_command(client, {"case_id": "1"})


def test_case_investigation_report_generate_sends_section_id(client):
    client._http_request.return_value = {"content": "x"}
    DFIRe.case_investigation_report_generate_command(client, {"case_id": "1", "section_id": "8"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/investigation-report/generate/")
    assert kwargs["json_data"] == {"section_id": 8}


def test_case_investigation_report_ready_for_qa_sends_section_id(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.case_investigation_report_ready_for_qa_command(client, {"case_id": "1", "section_id": "13"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/investigation-report/ready-for-qa/")
    assert kwargs["json_data"] == {"section_id": 13}


def test_case_investigation_report_finalize(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.case_investigation_report_finalize_command(client, {"case_id": "1"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/investigation-report/finalize/")
    assert kwargs["json_data"] == {}


# ── Todos ─────────────────────────────────────────────────


def test_case_todo_list_derives_from_case(client):
    """Regression: API has no GET /todo/; the integration pulls them from case.todo_checklist."""
    client._http_request.return_value = {
        "id": 1,
        "todo_checklist": [{"id": "u1", "title": "Triage"}],
    }
    result = DFIRe.case_todo_list_command(client, {"case_id": "1"})
    assert client._http_request.call_args.args == ("GET", "/cases/1/")
    assert result.outputs == [{"id": "u1", "title": "Triage"}]


def test_case_todo_get_filters_from_case(client):
    client._http_request.return_value = {
        "id": 1,
        "todo_checklist": [{"id": "u1", "title": "Triage"}, {"id": "u2", "title": "Contain"}],
    }
    result = DFIRe.case_todo_get_command(client, {"case_id": "1", "todo_id": "u2"})
    assert result.outputs["title"] == "Contain"


def test_case_todo_get_raises_when_missing(client):
    client._http_request.return_value = {"todo_checklist": []}
    with pytest.raises(DFIRe.DemistoException, match="No todo"):
        DFIRe.case_todo_get_command(client, {"case_id": "1", "todo_id": "u-missing"})


def test_case_todo_assign(client):
    client._http_request.return_value = {"status": "success"}
    DFIRe.case_todo_assign_command(client, {"case_id": "1", "todo_id": "u1", "assignee_id": "3"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/todo/u1/assign/")
    assert kwargs["json_data"] == {"assignee_id": 3}


def test_case_todo_note_set_uses_put(client):
    """Regression: this endpoint is PUT (not POST)."""
    client._http_request.return_value = {"status": "success"}
    DFIRe.case_todo_note_set_command(client, {"case_id": "1", "todo_id": "u1", "note": "hello"})
    args, kwargs = client._http_request.call_args
    assert args == ("PUT", "/cases/1/todo/u1/note/")
    assert kwargs["json_data"] == {"note": "hello"}


def test_case_todo_attach_runbook(client):
    client._http_request.return_value = {"status": "success"}
    DFIRe.case_todo_attach_runbook_command(client, {"case_id": "1", "todo_id": "u1", "runbook_slug": "rb"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/todo/u1/attach-runbook/")
    assert kwargs["json_data"] == {"runbook_slug": "rb"}


def test_case_todo_detach_runbook(client):
    client._http_request.return_value = {"status": "success"}
    DFIRe.case_todo_detach_runbook_command(client, {"case_id": "1", "todo_id": "u1"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", "/cases/1/todo/u1/detach-runbook/")
    assert kwargs["json_data"] == {}


# ── Timers ────────────────────────────────────────────────


def test_case_timer_list(client):
    client._http_request.return_value = {"results": []}
    DFIRe.case_timer_list_command(client, {"case_id": "1"})
    assert client._http_request.call_args.args == ("GET", "/cases/1/timers/")


def test_case_timer_get(client):
    client._http_request.return_value = {"id": 1}
    DFIRe.case_timer_get_command(client, {"case_id": "1", "timer_id": "2"})
    assert client._http_request.call_args.args == ("GET", "/cases/1/timers/2/")


@pytest.mark.parametrize(
    "command_fn,sub_path",
    [
        (DFIRe.case_timer_complete_command, "complete"),
        (DFIRe.case_timer_reset_command, "reset"),
    ],
)
def test_case_timer_actions(client, command_fn, sub_path):
    client._http_request.return_value = {"id": 1}
    command_fn(client, {"case_id": "1", "timer_id": "2"})
    args, kwargs = client._http_request.call_args
    assert args == ("POST", f"/cases/1/timers/2/{sub_path}/")
    assert kwargs["json_data"] == {}


# ── Reference-data list commands ──────────────────────────


@pytest.mark.parametrize(
    "command_fn,endpoint",
    [
        (DFIRe.case_type_list_command, "/case-types/"),
        (DFIRe.item_type_list_command, "/item-types/"),
        (DFIRe.item_flag_list_command, "/item-flags/"),
        (DFIRe.incident_category_list_command, "/incident-categories/"),
        (DFIRe.incident_phase_list_command, "/incident-phases/"),
        (DFIRe.outcome_verdict_list_command, "/outcome-verdicts/"),
        (DFIRe.project_list_command, "/projects/"),
        (DFIRe.runbook_list_command, "/runbooks/"),
        (DFIRe.group_list_command, "/groups/"),
    ],
)
def test_reference_data_list_commands(client, command_fn, endpoint):
    client._http_request.return_value = [{"id": 1, "name": "x"}]
    command_fn(client, {})
    assert client._http_request.call_args.args == ("GET", endpoint)
