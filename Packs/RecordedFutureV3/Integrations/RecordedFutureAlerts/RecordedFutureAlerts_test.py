from __future__ import annotations

from typing import Any

import demistomock as demisto
import pytest
import RecordedFutureAlerts

Client = RecordedFutureAlerts.Client
Actions = RecordedFutureAlerts.Actions
CommandResults = RecordedFutureAlerts.CommandResults


# Test Client


def _capture_http_call(monkeypatch: pytest.MonkeyPatch, method_name: str) -> dict[str, Any]:
    """Patch Client.*method_name* and capture arguments."""

    captured: dict[str, Any] = {}

    def _fake_http(self, *, url_suffix: str, params=None, json_data=None, **kwargs):
        captured.update(url_suffix=url_suffix, params=params, json_data=json_data)
        return {"ok": True}

    monkeypatch.setattr(Client, method_name, _fake_http, raising=True)
    return captured


def test_client_whoami_delegates_to_get(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(demisto, "args", dict, raising=True)
    captured = _capture_http_call(monkeypatch, "_get")

    client = Client(base_url="x", verify=False, headers={})
    client.whoami()

    assert captured["url_suffix"] == "/info/whoami"


def test_client_alert_search_delegates_to_get(monkeypatch: pytest.MonkeyPatch):
    expected_args = {
        "limit": "10",
        "created_from": "2024-01-01T00:00:00Z",
        "include_classic_alerts": "true",
        "statuses": "New",
    }
    monkeypatch.setattr(demisto, "args", lambda: expected_args, raising=True)
    captured = _capture_http_call(monkeypatch, "_get")

    client = Client(base_url="x", verify=False, headers={})
    client.alert_search()

    assert captured["url_suffix"] == "/v3/alert/search"
    assert captured["params"] == expected_args


def test_client_alert_rule_search_delegates_to_get(
    monkeypatch: pytest.MonkeyPatch,
):
    expected_args = {"rule_name": "Malware", "limit": "5"}
    monkeypatch.setattr(demisto, "args", lambda: expected_args, raising=True)
    captured = _capture_http_call(monkeypatch, "_get")

    client = Client(base_url="x", verify=False, headers={})
    client.alert_rule_search()

    assert captured["url_suffix"] == "/v3/alert/rules"
    assert captured["params"] == expected_args


def test_client_alert_update_delegates_to_post(
    monkeypatch: pytest.MonkeyPatch,
):
    expected_json = {
        "alert_id": "1",
        "status": "InProgress",
        "comment": "Investigating",
        "assignee": "analyst@example.com",
    }
    monkeypatch.setattr(demisto, "args", lambda: expected_json, raising=True)
    captured = _capture_http_call(monkeypatch, "_post")

    client = Client(base_url="x", verify=False, headers={})
    client.alert_update()

    assert captured["url_suffix"] == "/v3/alert/update"
    assert captured["json_data"] == expected_json


def test_client_alert_lookup_delegates_to_get(monkeypatch: pytest.MonkeyPatch):
    captured = _capture_http_call(monkeypatch, "_get")

    client = Client(base_url="x", verify=False, headers={})
    client.alert_lookup("42")

    assert captured["url_suffix"] == "/v3/alert/lookup"
    assert captured["params"] == {"alert_id": "42"}


def test_client_get_alert_image_calls_http_request(
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict[str, Any] = {}

    image_data = b"bytes"

    def _fake_http(self, *, url_suffix: str, params=None, resp_type=None, **kwargs):
        captured.update(url_suffix=url_suffix, params=params, resp_type=resp_type)
        return image_data

    monkeypatch.setattr(Client, "_http_request", _fake_http, raising=True)

    client = Client(base_url="x", verify=False, headers={})
    result = client.get_alert_image(
        alert_type="classic-alert",
        alert_id="1234",
        image_id="img1",
        alert_subtype="classic-alert",
    )

    assert result == image_data

    assert captured["url_suffix"] == "/v3/alert/image"
    assert captured["resp_type"] == "content"
    assert captured["params"] == {
        "alert_type": "classic-alert",
        "alert_subtype": "classic-alert",
        "alert_id": "1234",
        "image_id": "img1",
    }


def test_client_fetch_incidents_delegates_to_post(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        demisto,
        "getLastRun",
        lambda: {
            "next_query_classic": {"query_from": None},
            "next_query_playbook": {"query_from": None},
        },
        raising=True,
    )

    integration_conf = {"first_fetch": 60, "max_fetch": 10}
    monkeypatch.setattr(demisto, "params", lambda: integration_conf, raising=True)

    captured = _capture_http_call(monkeypatch, "_post")

    client = Client(base_url="x", verify=False, headers={})
    client.fetch_incidents()

    assert captured["url_suffix"] == "/v3/alert/fetch"

    json_data = captured["json_data"]
    assert json_data["integration_config"] == integration_conf
    assert json_data["classic_query_params"] == {"query_from": None}
    assert json_data["playbook_query_params"] == {"query_from": None}


# Test Action


def test_actions_alert_search_pass_through(monkeypatch: pytest.MonkeyPatch):
    expected: list[CommandResults] = [CommandResults(readable_output="hi")]
    monkeypatch.setattr(Client, "alert_search", lambda *_: expected, raising=True)

    actions = Actions(Client(base_url="x", verify=False, headers={}))
    assert actions.alert_search_command() is expected


def test_actions_alert_rule_search_pass_through(
    monkeypatch: pytest.MonkeyPatch,
):
    expected: list[CommandResults] = [CommandResults(readable_output="hi")]
    monkeypatch.setattr(Client, "alert_rule_search", lambda *_: expected, raising=True)

    actions = Actions(Client(base_url="x", verify=False, headers={}))
    assert actions.alert_rule_search_command() is expected


def test_actions_alert_update_pass_through(monkeypatch: pytest.MonkeyPatch):
    expected: list[CommandResults] = [CommandResults(readable_output="hi")]
    monkeypatch.setattr(Client, "alert_update", lambda *_: expected, raising=True)

    actions = Actions(Client(base_url="x", verify=False, headers={}))
    assert actions.alert_update_command() is expected


@pytest.mark.parametrize(
    "image_id,expected_file_name",
    [
        ("img:abcd", "abcd.png"),
        ("img:1234", "1234.png"),
    ],
)
def test_get_file_name_from_image_id(image_id: str, expected_file_name: str):
    assert Actions._get_file_name_from_image_id(image_id) == expected_file_name


def test_actions_fetch_incidents_builds_incident_objects(
    monkeypatch: pytest.MonkeyPatch,
):
    mock_alerts = [
        {"title": "Alert A", "created": "2024-01-01T00:00:00Z", "id": "a"},
        {"title": "Alert B", "created": "2024-01-02T00:00:00Z", "id": "b"},
    ]
    mock_next = {"foo": "bar"}

    def _fake_fetch_incidents(self):
        return {
            "alerts": mock_alerts,
            "next_query_classic": mock_next,
            "next_query_playbook": mock_next,
        }

    monkeypatch.setattr(Client, "fetch_incidents", _fake_fetch_incidents, raising=True)

    captured_incidents = {}
    monkeypatch.setattr(demisto, "incidents", lambda i: captured_incidents.update(i=i))
    monkeypatch.setattr(demisto, "setLastRun", lambda v: captured_incidents.update(last=v))

    actions = Actions(Client(base_url="x", verify=False, headers={}))
    actions.fetch_incidents()

    assert len(captured_incidents["i"]) == 2
    assert captured_incidents["last"]["next_query_classic"] == mock_next


def test_actions_get_alert_images_no_images(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        demisto,
        "incident",
        lambda: {"CustomFields": {"alertid": "42"}},
        raising=True,
    )

    lookup_outputs = {
        "alert_id": "42",
        "type": "classic-alert",
        "subtype": "classic-alert",
        "images": [],
    }

    monkeypatch.setattr(
        Client,
        "alert_lookup",
        lambda *_: [CommandResults(outputs=lookup_outputs)],
        raising=True,
    )

    monkeypatch.setattr(demisto, "context", dict)

    res = Actions(Client(base_url="x", verify=False, headers={})).get_alert_images_command()

    assert res[0].readable_output.startswith("No screenshots found in alert details.")


def test_actions_get_alert_images_fetches_missing(
    monkeypatch: pytest.MonkeyPatch,
):
    img_ids = ["img:1", "img:2"]

    monkeypatch.setattr(
        demisto,
        "incident",
        lambda: {"CustomFields": {"alertid": "42"}},
        raising=True,
    )

    lookup_outputs = {
        "alert_id": "42",
        "type": "classic-alert",
        "subtype": "classic-alert",
        "images": img_ids,
    }

    monkeypatch.setattr(
        Client,
        "alert_lookup",
        lambda *_: [CommandResults(outputs=lookup_outputs)],
        raising=True,
    )

    # No files in context so both images are missing
    monkeypatch.setattr(demisto, "context", dict)

    calls = []

    def _fake_get_image_and_create_attachment(self, *_, **__):
        calls.append(1)
        return {"name": "file.png", "path": "123"}

    monkeypatch.setattr(
        Actions,
        "_get_image_and_create_attachment",
        _fake_get_image_and_create_attachment,
        raising=True,
    )

    res = Actions(Client(base_url="x", verify=False, headers={})).get_alert_images_command()

    # Ensure both images attempted.
    assert len(calls) == len(img_ids)
    assert "Fetched" in res[0].readable_output


def test_actions_get_alert_images_fetches_only_missing(
    monkeypatch: pytest.MonkeyPatch,
):
    img_ids = ["img:1", "img:2"]

    monkeypatch.setattr(
        demisto,
        "incident",
        lambda: {"CustomFields": {"alertid": "42"}},
        raising=True,
    )

    lookup_outputs = {
        "alert_id": "42",
        "type": "classic-alert",
        "subtype": "classic-alert",
        "images": img_ids,
    }

    monkeypatch.setattr(
        Client,
        "alert_lookup",
        lambda *_: [CommandResults(outputs=lookup_outputs)],
        raising=True,
    )

    # Context already contains 1.png - derived from "img:1"
    context_with_one_image = {"File": [{"Name": "1.png"}]}
    monkeypatch.setattr(demisto, "context", lambda: context_with_one_image)

    calls = []

    def _fake_get_image_and_create_attachment(self, *_, **__):
        calls.append(1)
        return {"name": "2.png", "path": "123"}

    monkeypatch.setattr(
        Actions,
        "_get_image_and_create_attachment",
        _fake_get_image_and_create_attachment,
        raising=True,
    )

    res = Actions(Client(base_url="x", verify=False, headers={})).get_alert_images_command()

    assert len(calls) == 1
    assert "Fetched 1 new image" in res[0].readable_output


# Test Main


def _exercise_main(monkeypatch: pytest.MonkeyPatch, command: str, actions_attr: str):
    """Utility to run *main* with *command* and record side-effects."""

    monkeypatch.setattr(demisto, "command", lambda: command, raising=True)
    monkeypatch.setattr(
        demisto,
        "params",
        lambda: {"url": "x", "credentials": {"password": "token"}},
        raising=True,
    )

    expected = [CommandResults(readable_output="done")]
    call_counter = {"n": 0}

    def _fake_action(self):
        call_counter["n"] += 1
        return expected

    monkeypatch.setattr(Actions, actions_attr, _fake_action, raising=True)

    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        RecordedFutureAlerts,
        "return_results",
        lambda v: captured.update(res=v),
        raising=True,
    )

    RecordedFutureAlerts.main()

    assert call_counter["n"] == 1
    assert captured["res"] is expected


def test_main_dispatch_rf_alerts(monkeypatch: pytest.MonkeyPatch):
    _exercise_main(monkeypatch, command="rf-alerts", actions_attr="alert_search_command")


def test_main_dispatch_rf_alert_rules(monkeypatch: pytest.MonkeyPatch):
    _exercise_main(
        monkeypatch,
        command="rf-alert-rules",
        actions_attr="alert_rule_search_command",
    )


def test_main_dispatch_rf_alert_update(monkeypatch: pytest.MonkeyPatch):
    _exercise_main(
        monkeypatch,
        command="rf-alert-update",
        actions_attr="alert_update_command",
    )


def test_main_dispatch_rf_alert_images(monkeypatch: pytest.MonkeyPatch):
    _exercise_main(
        monkeypatch,
        command="rf-alert-images",
        actions_attr="get_alert_images_command",
    )
