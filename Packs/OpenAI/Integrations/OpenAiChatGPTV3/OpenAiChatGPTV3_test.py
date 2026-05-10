import json
from datetime import datetime, UTC
from typing import cast

import pytest
from CommonServerPython import *
from OpenAiChatGPTV3 import EmailParts


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_text(path: str) -> str:
    with open(path) as f:
        return f.read()


# region Existing tests - GPT chat / email
def test_extract_assistant_message():
    """Tests extraction from a valid response with choices and message."""

    from OpenAiChatGPTV3 import extract_assistant_message

    mock_response = util_load_json("test_data/mock_response.json")
    extracted_message = extract_assistant_message(response=mock_response)
    assert extracted_message == "Hello! How can I assist you today?"


@pytest.mark.parametrize("entry_id, should_raise_error", [("VALID_ENTRY_ID", False), ("INVALID_ENTRY_ID", True), ("", True)])
def test_get_email_parts(mocker, entry_id, should_raise_error):
    """Tests email parsing and parts extraction."""

    from OpenAiChatGPTV3 import get_email_parts

    def mock_file(_entry_id: str):
        if _entry_id == "VALID_ENTRY_ID":
            return {"path": "./test_data/attachment_malicious_url.eml", "name": "attachment_malicious_url.eml"}
        elif _entry_id == "INVALID_ENTRY_ID":
            return {"path": "./test_data/dummy_file.txt", "name": "dummy_file.txt"}
        return None

    mocker.patch.object(demisto, "getFilePath", side_effect=mock_file)
    if should_raise_error:
        with pytest.raises(Exception):
            get_email_parts(entry_id=entry_id)
    else:
        headers, text_body, html_body, file_name = get_email_parts(entry_id=entry_id)
        assert headers == util_load_json("test_data/expected_headers.json")
        assert text_body == "Body of the text"
        assert html_body.replace("\r\n", "\n") == util_load_text("test_data/expected_html_body.txt")


@pytest.mark.parametrize(
    "email_part, args",
    [
        (EmailParts.HEADERS, {"entryId": "XYZ", "additionalInstructions": "Identify spoofing."}),
        (EmailParts.BODY, {"entryId": "123", "additionalInstructions": "Identify data breaches."}),
    ],
)
def test_check_email_parts(mocker, email_part: str, args: dict):
    """Tests 'check_email_parts' function."""

    from OpenAiChatGPTV3 import OpenAiClient, check_email_part

    mocker.patch.object(OpenAiClient, "_http_request", return_value=util_load_json("test_data/mock_response.json"))
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "./test_data/attachment_malicious_url.eml", "name": "attachment_malicious_url.eml"},
    )

    client = OpenAiClient(url="DUMMY_URL", api_key="DUMMY_API_KEY", model="gpt-4", proxy=False, verify=False)
    check_email_part(email_part, client, args)


@pytest.mark.parametrize(
    "args",
    [
        {"reset_conversation_history": True, "message": "Hi There!", "max_tokens": "100", "temperature": "0.1", "top_p": "0.1"},
        {
            "reset_conversation_history": True,
            "message": "Hi There!",
        },
        {
            "reset_conversation_history": False,
            "message": "Hi There!",
        },
    ],
    ids=["test-send-message-with-params", "test-send-message-no-params", "test-send-message-no-reset"],
)
def test_send_message_command(mocker, args):
    from OpenAiChatGPTV3 import OpenAiClient, send_message_command

    mocker.patch.object(OpenAiClient, "_http_request", return_value=util_load_json("test_data/mock_response.json"))
    mocker.patch.object(
        demisto,
        "context",
        return_value={
            "OpenAiChatGPTV3": {"Conversation": [{"user": "Hi There!", "assistant": "Hello! How can I assist you today?"}]}
        },
    )

    client = OpenAiClient(url="DUMMY_URL", api_key="DUMMY_API_KEY", model="gpt-4", proxy=False, verify=False)
    result, _ = send_message_command(client, args)
    assert result.outputs_prefix == "OpenAiChatGPTV3.Conversation"


# endregion


# region Event Collector tests - shared helpers
def _make_client(**overrides):
    """Build an OpenAiClient with all keys populated for event-collector tests.

    Pass `admin_api_key=""` / `compliance_api_key=""` / `compliance_base_url=...`
    via `overrides` to exercise guard branches.
    """
    from OpenAiChatGPTV3 import OpenAiClient

    return OpenAiClient(
        url=overrides.get("url", "https://api.openai.com/"),
        api_key=overrides.get("api_key", "CHAT_KEY"),
        model=overrides.get("model", "gpt-4"),
        proxy=overrides.get("proxy", False),
        verify=overrides.get("verify", False),
        admin_api_key=overrides.get("admin_api_key", "ADMIN_KEY"),
        compliance_api_key=overrides.get("compliance_api_key", "COMPLIANCE_KEY"),
        compliance_base_url=overrides.get("compliance_base_url", "https://api.chatgpt.com"),
    )


# endregion


# region Event Collector tests - small pure helpers
@pytest.mark.parametrize(
    "event, expected",
    [
        pytest.param({"id": "abc"}, "abc", id="happy-id-key"),
        pytest.param({"log_id": "xyz"}, "xyz", id="happy-log_id-fallback"),
        pytest.param({"event_id": 7}, "7", id="happy-numeric-coerced-to-string"),
        pytest.param({"uuid": "u-1"}, "u-1", id="happy-uuid-fallback"),
        pytest.param({"id": "primary", "log_id": "secondary"}, "primary", id="precedence-id-over-log_id"),
        pytest.param({"unrelated": "v"}, None, id="bad-no-known-key"),
        pytest.param({}, None, id="bad-empty-dict"),
    ],
)
def test_event_id(event, expected):
    """`event_id` picks the first present key in (id, log_id, event_id, uuid)."""
    from OpenAiChatGPTV3 import event_id

    assert event_id(event) == expected


@pytest.mark.parametrize(
    "events, previous_ids, expected_ids",
    [
        pytest.param([{"id": "1"}, {"id": "2"}, {"id": "3"}], ["1", "3"], ["2"], id="happy-filters-known"),
        pytest.param([{"id": "1"}, {"id": "2"}], [], ["1", "2"], id="happy-no-previous-returns-all"),
        pytest.param([], ["1"], [], id="bad-empty-events-returns-empty"),
        pytest.param([{"id": "1"}, {"id": "1"}], ["1"], [], id="edge-all-events-filtered"),
    ],
)
def test_deduplicate_events(events, previous_ids, expected_ids):
    """`deduplicate_events` drops events whose id is in `previous_ids`."""
    from OpenAiChatGPTV3 import deduplicate_events

    result = deduplicate_events(events, previous_ids=previous_ids)
    assert [e["id"] for e in result] == expected_ids


@pytest.mark.parametrize(
    "event, expect_time",
    [
        pytest.param(
            {"id": "a", "effective_at": int(datetime(2099, 1, 1, tzinfo=UTC).timestamp())},
            "2099-01-01T00:00:00Z",
            id="happy-effective_at-mapped-to-_time",
        ),
        pytest.param({"id": "a"}, None, id="bad-missing-effective_at-no-_time"),
        pytest.param({"id": "a", "effective_at": "not-a-number"}, None, id="bad-non-numeric-effective_at-no-_time"),
    ],
)
def test_enrich_audit_event(event, expect_time):
    """Audit enrichment: strict `_time` from `effective_at` only, plus fixed `source_log_type`."""
    from OpenAiChatGPTV3 import enrich_audit_event, SourceLogType

    enrich_audit_event(event)
    assert event["source_log_type"] == SourceLogType.AUDIT
    if expect_time is None:
        assert "_time" not in event
    else:
        assert event["_time"] == expect_time


@pytest.mark.parametrize(
    "event, api_event_type, expect_time, expect_source_log_type",
    [
        pytest.param(
            {"id": "c", "timestamp": "2099-01-01T12:34:56Z"},
            "AUDIT_LOG",
            "2099-01-01T12:34:56Z",
            "compliance_audit_log",
            id="happy-audit_log-mapped",
        ),
        pytest.param(
            {"id": "c", "timestamp": "2099-01-02T08:00:00Z"},
            "APP_LOG",
            "2099-01-02T08:00:00Z",
            "app_log",
            id="happy-app_log-mapped",
        ),
        # `_time` must come strictly from `timestamp` - `end_time` must NOT be used as a fallback.
        pytest.param(
            {"id": "c", "end_time": "2099-01-02T08:00:00Z"},
            "APP_LOG",
            None,
            "app_log",
            id="bad-no-timestamp-no-_time-no-fallback-to-end_time",
        ),
    ],
)
def test_enrich_compliance_event(event, api_event_type, expect_time, expect_source_log_type):
    """Compliance enrichment: strict `_time` from `timestamp`, `source_log_type` per API event_type mapping."""
    from OpenAiChatGPTV3 import enrich_compliance_event

    enrich_compliance_event(event, api_event_type)
    assert event["source_log_type"] == expect_source_log_type
    assert event["_event_type"] == api_event_type
    if expect_time is None:
        assert "_time" not in event
    else:
        assert event["_time"] == expect_time


@pytest.mark.parametrize(
    "first_fetch_input, days_offset",
    [
        pytest.param("1 day", 1, id="happy-1-day"),
        pytest.param("3 days", 3, id="happy-3-days"),
        # An unparseable input falls back to "1 day ago" per the implementation.
        pytest.param("not-a-real-time", 1, id="bad-unparseable-falls-back-1-day"),
    ],
)
def test_parse_first_fetch_to_unix_seconds(first_fetch_input, days_offset):
    """`parse_first_fetch_to_unix_seconds` returns a Unix-second integer, with a `1 day` fallback on bad input."""
    from OpenAiChatGPTV3 import parse_first_fetch_to_unix_seconds

    result = parse_first_fetch_to_unix_seconds(first_fetch_input)
    assert isinstance(result, int)

    expected = int((datetime.now(UTC) - timedelta(days=days_offset)).timestamp())
    # Allow a small clock-drift window (test runtime + arg_to_datetime parse latency).
    assert abs(result - expected) < 30


@pytest.mark.parametrize(
    "first_fetch_input, days_offset",
    [
        pytest.param("1 day", 1, id="happy-1-day"),
        pytest.param("7 days", 7, id="happy-7-days"),
        pytest.param("definitely-not-a-time", 1, id="bad-unparseable-falls-back-1-day"),
    ],
)
def test_parse_first_fetch_to_iso(first_fetch_input, days_offset):
    """`parse_first_fetch_to_iso` returns a clean ISO 8601 timestamp (no microseconds)."""
    from OpenAiChatGPTV3 import parse_first_fetch_to_iso

    result = parse_first_fetch_to_iso(first_fetch_input)
    assert isinstance(result, str)
    # Format check: YYYY-MM-DDTHH:MM:SSZ (no microseconds, ends with Z).
    assert result.endswith("Z")
    parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    expected = datetime.now(UTC) - timedelta(days=days_offset)
    assert abs((parsed - expected).total_seconds()) < 30


def test_selected_audit_enabled_and_compliance_event_types():
    """Selection helpers should classify user-facing labels into Audit vs Compliance buckets."""
    from OpenAiChatGPTV3 import (
        ComplianceEvent,
        EventType,
        selected_audit_enabled,
        selected_compliance_event_types,
    )

    selected = [EventType.AUDIT, EventType.AUDIT_LOG, EventType.APP_LOG]
    assert selected_audit_enabled(selected) is True
    api_types = selected_compliance_event_types(selected)
    assert ComplianceEvent.AUDIT_LOG in api_types
    assert ComplianceEvent.APP_LOG in api_types

    # Negative: no Audit selected -> helper returns False; no Compliance -> empty list.
    assert selected_audit_enabled([EventType.APP_LOG]) is False
    assert selected_compliance_event_types([EventType.AUDIT]) == []


# endregion


# region Event Collector tests - integration params parsing
@pytest.mark.parametrize(
    "params, expected",
    [
        pytest.param(
            {
                "url": "https://api.openai.com",
                "apikey": {"password": "FAKE_CHAT_KEY"},
                "admin_api_key": {"password": "FAKE_ADMIN_KEY"},
                "compliance_api_key": {"password": "FAKE_COMPLIANCE_KEY"},
                "compliance_url": "https://fake-compliance.invalid",
                "model-freetext": "fake-model-x",
                "insecure": False,
                "proxy": False,
                "event_types_to_fetch": ["OpenAI Audit logs", "Compliance Audit"],
            },
            {
                "base_url": "https://api.openai.com/",
                "api_key": "FAKE_CHAT_KEY",
                "admin_api_key": "FAKE_ADMIN_KEY",
                "compliance_api_key": "FAKE_COMPLIANCE_KEY",
                "compliance_base_url": "https://fake-compliance.invalid",
                "model": "fake-model-x",
                "verify": True,
                "proxy": False,
            },
            id="happy-full-config-credentials-dict",
        ),
        pytest.param(
            {
                "apikey": "FAKE_RAW_STRING_KEY",  # Not wrapped in {"password": ...}
                "model-select": "fake-model-y",
                "insecure": True,
                "proxy": True,
                "event_types_to_fetch": [],
            },
            {
                "base_url": "https://api.openai.com/",  # default
                "api_key": "FAKE_RAW_STRING_KEY",
                "admin_api_key": "",
                "compliance_api_key": "",
                "compliance_base_url": "https://api.chatgpt.com",  # integration default
                "model": "fake-model-y",
                "verify": False,
                "proxy": True,
            },
            id="happy-defaults-and-raw-string-key",
        ),
    ],
)
def test_parse_integration_params_happy_paths(params, expected):
    """`parse_integration_params` extracts all fields and applies the documented defaults."""
    from OpenAiChatGPTV3 import parse_integration_params

    config = parse_integration_params(params)
    for key, value in expected.items():
        assert config[key] == value, f"Mismatch on '{key}': {config[key]!r} != {value!r}"


@pytest.mark.parametrize(
    "params, expected_substr",
    [
        pytest.param(
            {
                "event_types_to_fetch": ["NotAnEventType"],
            },
            "Invalid event type",
            id="bad-unknown-event-type",
        ),
        pytest.param(
            {
                "admin_api_key": {"password": ""},
                "event_types_to_fetch": ["OpenAI Audit logs"],
            },
            "Admin API Key",
            id="bad-audit-without-admin-key",
        ),
        pytest.param(
            {
                "compliance_api_key": {"password": ""},
                "event_types_to_fetch": ["Compliance Audit"],
            },
            "Compliance API Key",
            id="bad-compliance-without-compliance-key",
        ),
    ],
)
def test_parse_integration_params_bad_paths(params, expected_substr):
    """`parse_integration_params` raises informative `DemistoException` for invalid combos."""
    from OpenAiChatGPTV3 import parse_integration_params

    with pytest.raises(DemistoException) as exc_info:
        parse_integration_params(params)
    assert expected_substr in str(exc_info.value)


@pytest.mark.parametrize(
    "event_types, admin_key, compliance_key, expect_raises, expected_substr",
    [
        pytest.param([], "", "", False, None, id="happy-empty-selection-no-validation"),
        pytest.param(
            ["OpenAI Audit logs", "Compliance Audit"],
            "admin",
            "compliance",
            False,
            None,
            id="happy-both-keys-both-groups",
        ),
        pytest.param(["OpenAI Audit logs"], "", "any", True, "Admin API Key", id="bad-audit-missing-admin-key"),
        pytest.param(
            ["Compliance Audit", "Apps"],
            "any",
            "",
            True,
            "Compliance API Key",
            id="bad-compliance-missing-compliance-key",
        ),
    ],
)
def test_validate_event_types_credentials_correlation(event_types, admin_key, compliance_key, expect_raises, expected_substr):
    """Cross-validate selected event types vs. provided credentials."""
    from OpenAiChatGPTV3 import validate_event_types_credentials_correlation

    if expect_raises:
        with pytest.raises(DemistoException) as exc_info:
            validate_event_types_credentials_correlation(
                event_types_to_fetch=event_types,
                admin_api_key=admin_key,
                compliance_api_key=compliance_key,
            )
        assert expected_substr in str(exc_info.value)
    else:
        # Should not raise.
        validate_event_types_credentials_correlation(
            event_types_to_fetch=event_types,
            admin_api_key=admin_key,
            compliance_api_key=compliance_key,
        )


# endregion


# region Event Collector tests - parse_concatenated_json
@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param(
            '{"a":1,"nested":{"x":2}}{"b":2}\n{"c":3}',
            [{"a": 1, "nested": {"x": 2}}, {"b": 2}, {"c": 3}],
            id="happy-concatenated-objects",
        ),
        pytest.param(
            '{"a":1}\n  {"b":2}\n\n{"c":3}\n',
            [{"a": 1}, {"b": 2}, {"c": 3}],
            id="happy-jsonl-with-whitespace",
        ),
        pytest.param(
            '{"a":1}"ignored"42[1,2,3]{"b":2}',
            [{"a": 1}, {"b": 2}],
            id="happy-non-dict-top-level-values-skipped",
        ),
        pytest.param("", [], id="bad-empty-body-returns-empty-list"),
        pytest.param("   \n  ", [], id="bad-whitespace-only-returns-empty-list"),
        pytest.param('{"a":1}garbage', [{"a": 1}], id="bad-trailing-garbage-stops-parser-keeps-decoded"),
    ],
)
def test_parse_concatenated_json(body, expected):
    """`parse_concatenated_json` splits a stream of concatenated JSON / JSONL into a list of dicts."""
    from OpenAiChatGPTV3 import parse_concatenated_json

    assert parse_concatenated_json(body) == expected


def test_parse_concatenated_json_loads_fixture_file():
    """End-to-end check using a synthetic concatenated-JSON body stored under test_data/."""
    from OpenAiChatGPTV3 import parse_concatenated_json

    body = util_load_text("test_data/compliance_log_content_concatenated.txt")
    records = parse_concatenated_json(body)
    assert len(records) == 3
    assert records[0]["actor"] == "FAKE_ACTOR_A"
    assert records[-1]["action"] == "dummy_action_three"


# endregion


# region Event Collector tests - Client guards & wire format
@pytest.mark.parametrize(
    "client_kwargs, call_kwargs, expected_substr",
    [
        pytest.param(
            {"admin_api_key": ""},
            {},
            "Admin API Key",
            id="bad-audit-without-admin-key",
        ),
    ],
)
def test_get_audit_logs_guards(client_kwargs, call_kwargs, expected_substr):
    """`Client.get_audit_logs` must refuse to fire without an Admin API key."""
    client = _make_client(**client_kwargs)
    with pytest.raises(DemistoException) as exc_info:
        client.get_audit_logs(**call_kwargs)
    assert expected_substr in str(exc_info.value)


def test_get_audit_logs_uses_cursor_when_present(mocker):
    """Happy path: when `after=` is provided, the request must NOT include `effective_at[gt]`."""
    from OpenAiChatGPTV3 import OpenAiClient

    client = _make_client()
    response = util_load_json("test_data/audit_logs_page_response.json")
    http_mock = mocker.patch.object(OpenAiClient, "_http_request", return_value=response)

    result = client.get_audit_logs(after="FAKE_AUDIT_CURSOR_PREV", effective_at_gt=1000)
    assert result["last_id"] == "FAKE_AUDIT_CURSOR_AAAA"

    request_params = http_mock.call_args.kwargs["params"]
    assert request_params["after"] == "FAKE_AUDIT_CURSOR_PREV"
    # When a cursor is present, the time-seed must be ignored (cursor wins).
    assert "effective_at[gt]" not in request_params


def test_get_audit_logs_uses_time_seed_on_first_call(mocker):
    """First-ever call (no cursor) must seed the request with `effective_at[gt]`."""
    from OpenAiChatGPTV3 import OpenAiClient

    client = _make_client()
    http_mock = mocker.patch.object(OpenAiClient, "_http_request", return_value={"data": [], "has_more": False})

    client.get_audit_logs(after=None, effective_at_gt=1234567890)

    request_params = http_mock.call_args.kwargs["params"]
    assert request_params["effective_at[gt]"] == 1234567890
    assert "after" not in request_params


@pytest.mark.parametrize(
    "client_kwargs, call_kwargs, expected_substr",
    [
        pytest.param(
            {"compliance_api_key": ""},
            {"workspace_id": "FAKE_WORKSPACE_ID", "event_types": ["APP_LOG"], "after": "2099-01-01T00:00:00Z"},
            "Compliance API Key",
            id="bad-no-compliance-key",
        ),
        pytest.param(
            {"compliance_api_key": "FAKE_COMPLIANCE_KEY"},
            {"workspace_id": "", "event_types": ["APP_LOG"], "after": "2099-01-01T00:00:00Z"},
            "Workspace ID",
            id="bad-no-workspace-id",
        ),
    ],
)
def test_list_compliance_logs_guards(client_kwargs, call_kwargs, expected_substr):
    """`Client.list_compliance_logs` must refuse to fire without both a key and a workspace."""
    client = _make_client(**client_kwargs)
    with pytest.raises(DemistoException) as exc_info:
        client.list_compliance_logs(**call_kwargs)
    assert expected_substr in str(exc_info.value)


@pytest.mark.parametrize(
    "upstream, expected_data, expected_last_end_time",
    [
        pytest.param(
            {
                "data": [{"id": "FAKE_LISTING_001", "end_time": "2099-01-02T00:00:00Z"}],
                "has_more": False,
                "last_end_time": "2099-01-02T00:00:00Z",
            },
            [{"id": "FAKE_LISTING_001", "end_time": "2099-01-02T00:00:00Z"}],
            "2099-01-02T00:00:00Z",
            id="happy-dict-shape-with-last_end_time",
        ),
        pytest.param(
            [{"id": "FAKE_LISTING_002", "end_time": "2099-02-01T00:00:00Z"}],
            [{"id": "FAKE_LISTING_002", "end_time": "2099-02-01T00:00:00Z"}],
            None,
            id="happy-legacy-bare-list-shape-normalized",
        ),
        pytest.param(None, [], None, id="bad-non-list-non-dict-response-normalized-empty"),
        pytest.param({}, [], None, id="bad-empty-dict-response-normalized-empty"),
    ],
)
def test_list_compliance_logs_normalizes_response(mocker, upstream, expected_data, expected_last_end_time):
    """`list_compliance_logs` must normalize any upstream shape into `{data, last_end_time}`."""
    from OpenAiChatGPTV3 import OpenAiClient

    client = _make_client()
    mocker.patch.object(OpenAiClient, "_http_request", return_value=upstream)
    result = client.list_compliance_logs(workspace_id="FAKE_WORKSPACE_ID", event_types=["APP_LOG"], after="2099-01-01T00:00:00Z")
    assert result["data"] == expected_data
    assert result.get("last_end_time") == expected_last_end_time


def test_get_compliance_log_content_parses_concatenated_json(mocker):
    """`get_compliance_log_content` fetches as text and parses concatenated JSON into a list of dicts."""
    from OpenAiChatGPTV3 import OpenAiClient

    client = _make_client()
    body = util_load_text("test_data/compliance_log_content_concatenated.txt")
    mocker.patch.object(OpenAiClient, "_http_request", return_value=body)

    records = client.get_compliance_log_content(workspace_id="FAKE_WORKSPACE_ID", log_id="FAKE_LISTING_002")
    assert len(records) == 3
    assert all(isinstance(r, dict) for r in records)
    assert records[0]["action"] == "dummy_action_one"


def test_get_compliance_log_content_requires_compliance_key():
    """Bad path: missing Compliance API Key must raise before any HTTP request."""
    client = _make_client(compliance_api_key="")
    with pytest.raises(DemistoException) as exc_info:
        client.get_compliance_log_content(workspace_id="FAKE_WORKSPACE_ID", log_id="FAKE_LISTING_002")
    assert "Compliance API Key" in str(exc_info.value)


@pytest.mark.parametrize(
    "client_kwargs, call_kwargs, expected_substr",
    [
        pytest.param(
            {"compliance_api_key": ""},
            {"workspace_id": "FAKE_WORKSPACE_ID"},
            "Compliance API Key",
            id="bad-no-compliance-key",
        ),
        pytest.param(
            {"compliance_api_key": "FAKE_COMPLIANCE_KEY"},
            {"workspace_id": ""},
            "Workspace ID",
            id="bad-no-workspace-id",
        ),
    ],
)
def test_list_compliance_users_guards(client_kwargs, call_kwargs, expected_substr):
    """`list_compliance_users` enforces the same key + workspace prerequisites as listing logs."""
    client = _make_client(**client_kwargs)
    with pytest.raises(DemistoException) as exc_info:
        client.list_compliance_users(**call_kwargs)
    assert expected_substr in str(exc_info.value)


@pytest.mark.parametrize(
    "upstream, expected_count",
    [
        pytest.param({"data": [{"id": "FAKE_USER_A"}, {"id": "FAKE_USER_B"}]}, 2, id="happy-dict-shape"),
        pytest.param([{"id": "FAKE_USER_A"}], 1, id="happy-legacy-bare-list"),
        pytest.param("not-a-collection", 0, id="bad-unexpected-type-returns-empty"),
    ],
)
def test_list_compliance_users_normalizes_response(mocker, upstream, expected_count):
    """`list_compliance_users` returns a list regardless of upstream response shape."""
    from OpenAiChatGPTV3 import OpenAiClient

    client = _make_client()
    mocker.patch.object(OpenAiClient, "_http_request", return_value=upstream)
    users = client.list_compliance_users(workspace_id="FAKE_WORKSPACE_ID", limit=10)
    assert isinstance(users, list)
    assert len(users) == expected_count


def test_send_events_routes_to_correct_dataset(mocker):
    """`send_events` must call `send_events_to_xsiam` with the requested vendor + product."""
    import OpenAiChatGPTV3 as module

    client = _make_client()
    sender = mocker.patch.object(module, "send_events_to_xsiam")

    events = [{"id": "e1"}]
    client.send_events(events, product=module.Config.PRODUCT_AUDIT)

    sender.assert_called_once_with(events=events, vendor=module.Config.VENDOR, product=module.Config.PRODUCT_AUDIT)


def test_send_events_skips_when_empty(mocker):
    """`send_events` must NOT call the XSIAM sender when there are no events."""
    import OpenAiChatGPTV3 as module

    client = _make_client()
    sender = mocker.patch.object(module, "send_events_to_xsiam")

    client.send_events([], product=module.Config.PRODUCT_COMPLIANCE)
    sender.assert_not_called()


# endregion


# region Event Collector tests - fetch_audit_logs
def test_fetch_audit_logs_returns_events_and_advances_cursor(mocker):
    """Happy path: a single page is fetched, events enriched, and the API `last_id` cursor persisted."""
    from OpenAiChatGPTV3 import OpenAiClient, fetch_audit_logs, LastRunKey, SourceLogType

    client = _make_client()
    response = util_load_json("test_data/audit_logs_page_response.json")
    mocker.patch.object(OpenAiClient, "_http_request", return_value=response)

    events, updates = fetch_audit_logs(client=client, last_run={}, max_fetch=10, first_fetch="1 day")

    assert [e["id"] for e in events] == ["FAKE_AUDIT_EVENT_001", "FAKE_AUDIT_EVENT_002"]
    assert all(e["source_log_type"] == SourceLogType.AUDIT for e in events)
    # The cursor returned by the API is what gets persisted - verbatim.
    assert updates[LastRunKey.AUDIT_AFTER] == "FAKE_AUDIT_CURSOR_AAAA"
    # Audit no longer keeps an explicit ID-list / time HWM in last_run.
    assert "audit_effective_at" not in updates
    assert "audit_last_ids" not in updates


def test_fetch_audit_logs_resumes_from_stored_cursor(mocker):
    """Happy path: stored cursor is forwarded as `after=`; first-fetch time-seed is NOT used."""
    from OpenAiChatGPTV3 import OpenAiClient, fetch_audit_logs, LastRunKey

    client = _make_client()
    response = {
        "data": [{"id": "FAKE_AUDIT_EVENT_003", "effective_at": 1200}],
        "has_more": False,
        "last_id": "FAKE_AUDIT_CURSOR_BBBB",
    }
    http_mock = mocker.patch.object(OpenAiClient, "_http_request", return_value=response)

    last_run = {LastRunKey.AUDIT_AFTER: "FAKE_AUDIT_CURSOR_AAAA"}
    events, updates = fetch_audit_logs(client=client, last_run=last_run, max_fetch=10, first_fetch="1 day")

    assert [e["id"] for e in events] == ["FAKE_AUDIT_EVENT_003"]
    assert updates[LastRunKey.AUDIT_AFTER] == "FAKE_AUDIT_CURSOR_BBBB"

    request_params = http_mock.call_args.kwargs.get("params", {})
    assert request_params.get("after") == "FAKE_AUDIT_CURSOR_AAAA"
    assert "effective_at[gt]" not in request_params


def test_fetch_audit_logs_empty_first_fetch_returns_no_events_and_no_updates(mocker):
    """Bad path: first-ever fetch returns an empty page - no events, no cursor persisted."""
    from OpenAiChatGPTV3 import OpenAiClient, fetch_audit_logs

    client = _make_client()
    mocker.patch.object(OpenAiClient, "_http_request", return_value={"data": [], "has_more": False})
    events, updates = fetch_audit_logs(client=client, last_run={}, max_fetch=10, first_fetch="1 day")
    assert events == []
    assert updates == {}


# endregion


# region Event Collector tests - fetch_compliance_logs
def test_fetch_compliance_logs_two_step_flow(mocker):
    """Happy path: list endpoint -> per-id content fetch -> per-record enrichment + cursor persistence."""
    from OpenAiChatGPTV3 import OpenAiClient, fetch_compliance_logs, LastRunKey, ComplianceEvent, SourceLogType

    client = _make_client()
    listing_response = util_load_json("test_data/compliance_listing_response.json")
    contents = {
        "FAKE_LISTING_001": [{"id": "FAKE_LISTING_001", "timestamp": "2099-01-01T00:00:00Z", "actor": "FAKE_ACTOR_A"}],
        "FAKE_LISTING_002": [
            {"id": "FAKE_LISTING_002", "timestamp": "2099-01-02T00:00:00Z", "actor": "FAKE_ACTOR_B"},
            {"id": "FAKE_LISTING_002", "timestamp": "2099-01-02T00:00:01Z", "actor": "FAKE_ACTOR_C"},
        ],
    }
    mocker.patch.object(OpenAiClient, "list_compliance_logs", return_value=listing_response)
    mocker.patch.object(OpenAiClient, "get_compliance_log_content", side_effect=lambda workspace_id, log_id: contents[log_id])

    events, updates = fetch_compliance_logs(
        client=client,
        workspace_id="FAKE_WORKSPACE_ID",
        api_event_types=[ComplianceEvent.AUDIT_LOG, ComplianceEvent.APP_LOG],
        last_run={},
        max_fetch=100,
        first_fetch="1 day",
    )

    # FAKE_LISTING_001 -> 1 record, FAKE_LISTING_002 -> 2 records (JSONL-shaped content) = 3 events total.
    assert len(events) == 3
    assert events[0]["source_log_type"] == SourceLogType.COMPLIANCE_AUDIT_LOG
    assert events[1]["source_log_type"] == SourceLogType.APP_LOG
    # `last_end_time` is read from the listing response, NOT computed from individual entries.
    assert updates[LastRunKey.COMPLIANCE_LAST_END_TIME] == "2099-01-02T00:00:00Z"
    # Only FAKE_LISTING_002 shares the end_time with the cursor, so it's the only id stored for tie-dedup.
    assert updates[LastRunKey.COMPLIANCE_LAST_IDS] == ["FAKE_LISTING_002"]


def test_fetch_compliance_logs_dedupes_against_previous_ids(mocker):
    """Happy path: listings whose IDs were already seen at the persisted `last_end_time` are skipped."""
    from OpenAiChatGPTV3 import OpenAiClient, fetch_compliance_logs, LastRunKey, ComplianceEvent

    client = _make_client()
    listings = [
        {"id": "FAKE_LISTING_001", "event_type": ComplianceEvent.AUDIT_LOG, "end_time": "2099-01-02T00:00:00Z"},
        {"id": "FAKE_LISTING_002", "event_type": ComplianceEvent.AUDIT_LOG, "end_time": "2099-01-02T00:00:00Z"},
    ]
    listing_response = {"data": listings, "last_end_time": "2099-01-02T00:00:00Z", "has_more": False}
    mocker.patch.object(OpenAiClient, "list_compliance_logs", return_value=listing_response)
    mocker.patch.object(
        OpenAiClient,
        "get_compliance_log_content",
        side_effect=lambda workspace_id, log_id: [{"id": log_id, "timestamp": "2099-01-02T00:00:00Z"}],
    )

    last_run = {
        LastRunKey.COMPLIANCE_LAST_END_TIME: "2099-01-02T00:00:00Z",
        LastRunKey.COMPLIANCE_LAST_IDS: ["FAKE_LISTING_001"],
    }
    events, updates = fetch_compliance_logs(
        client=client,
        workspace_id="FAKE_WORKSPACE_ID",
        api_event_types=[ComplianceEvent.AUDIT_LOG],
        last_run=last_run,
        max_fetch=100,
        first_fetch="1 day",
    )

    assert [e["id"] for e in events] == ["FAKE_LISTING_002"]
    assert updates[LastRunKey.COMPLIANCE_LAST_END_TIME] == "2099-01-02T00:00:00Z"
    # Same cursor as previous run - merge stored IDs with newly-seen IDs at the same timestamp.
    assert sorted(updates[LastRunKey.COMPLIANCE_LAST_IDS]) == ["FAKE_LISTING_001", "FAKE_LISTING_002"]


def test_fetch_compliance_logs_no_listings_advances_cursor_only(mocker):
    """Bad path: no listings returned, but the API's `last_end_time` still moves forward -> persist it."""
    from OpenAiChatGPTV3 import OpenAiClient, fetch_compliance_logs, LastRunKey, ComplianceEvent

    client = _make_client()
    mocker.patch.object(
        OpenAiClient,
        "list_compliance_logs",
        return_value={"data": [], "last_end_time": "2099-02-01T00:00:00Z", "has_more": False},
    )

    last_run = {LastRunKey.COMPLIANCE_LAST_END_TIME: "2099-01-01T00:00:00Z"}
    events, updates = fetch_compliance_logs(
        client=client,
        workspace_id="FAKE_WORKSPACE_ID",
        api_event_types=[ComplianceEvent.AUDIT_LOG],
        last_run=last_run,
        max_fetch=100,
        first_fetch="1 day",
    )
    assert events == []
    assert updates[LastRunKey.COMPLIANCE_LAST_END_TIME] == "2099-02-01T00:00:00Z"
    assert updates[LastRunKey.COMPLIANCE_LAST_IDS] == []


def test_fetch_compliance_logs_content_failure_isolated(mocker):
    """Bad path: a single content-fetch failure must NOT abort processing of other listings."""
    from OpenAiChatGPTV3 import OpenAiClient, fetch_compliance_logs, ComplianceEvent

    client = _make_client()
    listings = [
        {"id": "FAKE_LISTING_001", "event_type": ComplianceEvent.AUDIT_LOG, "end_time": "2099-01-02T00:00:00Z"},
        {"id": "FAKE_LISTING_002", "event_type": ComplianceEvent.AUDIT_LOG, "end_time": "2099-01-02T00:00:01Z"},
    ]
    listing_response = {"data": listings, "last_end_time": "2099-01-02T00:00:01Z", "has_more": False}

    def content_side_effect(workspace_id, log_id):
        if log_id == "FAKE_LISTING_001":
            raise DemistoException("simulated content fetch failure")
        return [{"id": log_id, "timestamp": "2099-01-02T00:00:01Z"}]

    mocker.patch.object(OpenAiClient, "list_compliance_logs", return_value=listing_response)
    mocker.patch.object(OpenAiClient, "get_compliance_log_content", side_effect=content_side_effect)

    events, _ = fetch_compliance_logs(
        client=client,
        workspace_id="FAKE_WORKSPACE_ID",
        api_event_types=[ComplianceEvent.AUDIT_LOG],
        last_run={},
        max_fetch=100,
        first_fetch="1 day",
    )
    # FAKE_LISTING_001 failed and was skipped; FAKE_LISTING_002 succeeded and produced one event.
    assert [e["id"] for e in events] == ["FAKE_LISTING_002"]


# endregion


# region Event Collector tests - command-level (fetch-events / openai-get-events)
def test_fetch_events_command_runs_streams_in_parallel_and_routes_datasets(mocker):
    """`fetch_events_command` runs both streams, sends each to its own dataset, persists merged last_run."""
    import OpenAiChatGPTV3 as module

    client = _make_client()
    audit_events = [{"id": "FAKE_AUDIT_EVENT_001"}]
    compliance_events = [{"id": "FAKE_COMPLIANCE_EVENT_001"}, {"id": "FAKE_COMPLIANCE_EVENT_002"}]

    mocker.patch.object(
        module, "fetch_audit_logs", return_value=(audit_events, {module.LastRunKey.AUDIT_AFTER: "FAKE_AUDIT_CURSOR_AAAA"})
    )
    mocker.patch.object(
        module,
        "fetch_compliance_logs",
        return_value=(compliance_events, {module.LastRunKey.COMPLIANCE_LAST_END_TIME: "2099-02-01T00:00:00Z"}),
    )
    sender = mocker.patch.object(module.OpenAiClient, "send_events")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")

    params = {
        "event_types_to_fetch": ["OpenAI Audit logs", "Compliance Audit"],
        "workspace_id": "FAKE_WORKSPACE_ID",
        "first_fetch": "1 day",
        "audit_max_fetch": 100,
        "compliance_max_fetch": 50,
    }
    module.fetch_events_command(client=client, params=params)

    # Both streams pushed - each with its own product.
    products_used = sorted(
        call.kwargs.get("product", call.args[1] if len(call.args) > 1 else None) for call in sender.call_args_list
    )
    assert products_used == sorted([module.Config.PRODUCT_AUDIT, module.Config.PRODUCT_COMPLIANCE])

    # Last_run is the merged set of per-stream updates.
    persisted = set_last_run.call_args.args[0]
    assert persisted[module.LastRunKey.AUDIT_AFTER] == "FAKE_AUDIT_CURSOR_AAAA"
    assert persisted[module.LastRunKey.COMPLIANCE_LAST_END_TIME] == "2099-02-01T00:00:00Z"


def test_fetch_events_command_failure_in_one_stream_does_not_block_the_other(mocker, capfd):
    """`fetch_events_command` must isolate stream failures - one stream's exception cannot stop the other.

    The audit-stream failure path intentionally calls `demisto.error()`, which writes to stdout.
    `capfd.disabled()` lets the test ignore that allowed-by-design output (the conftest fixture
    `check_std_out_err` would otherwise fail any test that emits anything on stdout/stderr).
    """
    import OpenAiChatGPTV3 as module

    client = _make_client()

    mocker.patch.object(module, "fetch_audit_logs", side_effect=DemistoException("simulated audit failure"))
    mocker.patch.object(
        module,
        "fetch_compliance_logs",
        return_value=(
            [{"id": "FAKE_COMPLIANCE_EVENT_001"}],
            {module.LastRunKey.COMPLIANCE_LAST_END_TIME: "2099-02-02T00:00:00Z"},
        ),
    )
    sender = mocker.patch.object(module.OpenAiClient, "send_events")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")

    params = {
        "event_types_to_fetch": ["OpenAI Audit logs", "Compliance Audit"],
        "workspace_id": "FAKE_WORKSPACE_ID",
        "first_fetch": "1 day",
    }
    with capfd.disabled():
        # Must NOT raise - the audit failure is caught (and its `demisto.error` log is expected
        # output) and the compliance stream still pushes.
        module.fetch_events_command(client=client, params=params)

    pushed_products = [call.kwargs.get("product", call.args[1] if len(call.args) > 1 else None) for call in sender.call_args_list]
    assert module.Config.PRODUCT_COMPLIANCE in pushed_products
    assert module.Config.PRODUCT_AUDIT not in pushed_products


def test_fetch_events_command_no_event_types_selected_is_a_noop(mocker):
    """Bad path: if no event types are selected, neither stream runs and last_run is left untouched."""
    import OpenAiChatGPTV3 as module

    client = _make_client()
    audit_mock = mocker.patch.object(module, "fetch_audit_logs")
    compliance_mock = mocker.patch.object(module, "fetch_compliance_logs")
    sender = mocker.patch.object(module.OpenAiClient, "send_events")
    mocker.patch.object(demisto, "getLastRun", return_value={"unrelated": "preserved"})
    set_last_run = mocker.patch.object(demisto, "setLastRun")

    module.fetch_events_command(client=client, params={"event_types_to_fetch": []})
    audit_mock.assert_not_called()
    compliance_mock.assert_not_called()
    sender.assert_not_called()
    # Still calls setLastRun once with the original dict (preserves unrelated keys).
    assert set_last_run.call_args.args[0] == {"unrelated": "preserved"}


@pytest.mark.parametrize(
    "should_push, expected_send_calls",
    [
        pytest.param(False, 0, id="happy-no-push-by-default"),
        pytest.param(True, 2, id="happy-push-flag-pushes-both-datasets"),
    ],
)
def test_get_events_command(mocker, should_push, expected_send_calls):
    """`openai-get-events` returns events as `CommandResults`; only pushes when `should_push_events=true`."""
    import OpenAiChatGPTV3 as module

    client = _make_client()
    mocker.patch.object(module, "fetch_audit_logs", return_value=([{"id": "FAKE_AUDIT_EVENT_001"}], {}))
    mocker.patch.object(module, "fetch_compliance_logs", return_value=([{"id": "FAKE_COMPLIANCE_EVENT_001"}], {}))
    sender = mocker.patch.object(module.OpenAiClient, "send_events")

    args = {
        "event_type": "OpenAI Audit logs,Compliance Audit",
        "limit": "10",
        "should_push_events": should_push,
    }
    params = {"workspace_id": "FAKE_WORKSPACE_ID"}
    result = module.get_events_command(client=client, args=args, params=params)

    # `outputs` always carries every fetched event regardless of the push flag.
    outputs = cast(list, result.outputs)
    assert {e["id"] for e in outputs} == {"FAKE_AUDIT_EVENT_001", "FAKE_COMPLIANCE_EVENT_001"}
    assert sender.call_count == expected_send_calls


# endregion
