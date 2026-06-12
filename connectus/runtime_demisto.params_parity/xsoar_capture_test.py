"""Hermetic tests for :func:`xsoar_capture.capture_xsoar_params`.

These tests pin down the function's RETURN CONTRACT: it returns a 2-tuple
``(captured, filled)`` where ``filled`` is the XSOAR-side instance-creation
payload (the filled params dict sent to ``create_integration_instance``). This
payload is surfaced in the persisted results envelope for debugging.

Every external touch-point (client build, server config, instance create/
delete, test-module run, YML parse) is monkeypatched so the tests stay fully
hermetic (NO network / tenant / docker).
"""
from __future__ import annotations

import xsoar_capture
from xsoar_capture import (
    PARITY_DUMP_PARAM_KEY,
    PARITY_DUMP_PARAM_VALUE,
    capture_xsoar_params,
)


def _stub_happy_path(monkeypatch, *, captured_sentinel):
    """Monkeypatch every dependency so capture_xsoar_params reaches success.

    Records the ``filled`` dict actually passed to create_integration_instance
    so the test can assert the returned payload matches what was sent.
    """
    sent = {}

    monkeypatch.setattr(
        xsoar_capture,
        "parse_integration_yml",
        lambda path: {"name": "MyIntegration", "configuration": [{"name": "url"}]},
    )
    monkeypatch.setattr(
        xsoar_capture,
        "fill_params_from_yml",
        lambda yml_params, overrides: dict(overrides),
    )
    monkeypatch.setattr(xsoar_capture, "create_client", lambda: object())
    monkeypatch.setattr(
        xsoar_capture, "get_integration_config", lambda client, name: {"some": "config"}
    )

    def _fake_create(client, name, server_config, filled):
        sent["filled"] = filled
        return {"id": "instance-123"}, None

    monkeypatch.setattr(xsoar_capture, "create_integration_instance", _fake_create)
    monkeypatch.setattr(
        xsoar_capture,
        "run_test_module_and_capture_params",
        lambda client, module_instance: captured_sentinel,
    )
    monkeypatch.setattr(
        xsoar_capture, "delete_integration_instance", lambda client, instance_id: True
    )
    return sent


def test_returns_captured_and_filled_payload_tuple(monkeypatch):
    """SUCCESS → returns (captured, filled); filled == payload sent to create."""
    captured_sentinel = {"url": "https://example.com", "captured": True}
    sent = _stub_happy_path(monkeypatch, captured_sentinel=captured_sentinel)

    result = capture_xsoar_params(
        integration_yml_path="/tmp/fake.yml",
        overrides={"url": "https://example.com"},
    )

    assert isinstance(result, tuple)
    assert len(result) == 2
    captured, payload = result
    assert captured is captured_sentinel
    # The returned payload is exactly the filled dict handed to the creator ...
    assert payload == sent["filled"]
    # ... and it includes the auto-injected magic key.
    assert payload[PARITY_DUMP_PARAM_KEY] == PARITY_DUMP_PARAM_VALUE
    assert payload["url"] == "https://example.com"


def test_no_name_returns_none_none(monkeypatch):
    """EARLY failure before `filled` is built (no name) → (None, None)."""
    monkeypatch.setattr(
        xsoar_capture,
        "parse_integration_yml",
        lambda path: {"name": "", "configuration": []},
    )

    result = capture_xsoar_params(integration_yml_path="/tmp/fake.yml")

    assert result == (None, None)


def test_falsy_server_config_returns_none_filled(monkeypatch):
    """Failure AFTER `filled` is built (no server config) → (None, filled)."""
    monkeypatch.setattr(
        xsoar_capture,
        "parse_integration_yml",
        lambda path: {"name": "MyIntegration", "configuration": []},
    )
    monkeypatch.setattr(
        xsoar_capture,
        "fill_params_from_yml",
        lambda yml_params, overrides: dict(overrides),
    )
    monkeypatch.setattr(xsoar_capture, "create_client", lambda: object())
    monkeypatch.setattr(
        xsoar_capture, "get_integration_config", lambda client, name: None
    )

    captured, payload = capture_xsoar_params(
        integration_yml_path="/tmp/fake.yml", overrides={"k": "v"}
    )

    assert captured is None
    assert payload is not None
    assert payload[PARITY_DUMP_PARAM_KEY] == PARITY_DUMP_PARAM_VALUE
    assert payload["k"] == "v"


def test_instance_creation_failure_returns_none_filled(monkeypatch):
    """create_integration_instance failure → (None, filled)."""
    monkeypatch.setattr(
        xsoar_capture,
        "parse_integration_yml",
        lambda path: {"name": "MyIntegration", "configuration": []},
    )
    monkeypatch.setattr(
        xsoar_capture,
        "fill_params_from_yml",
        lambda yml_params, overrides: dict(overrides),
    )
    monkeypatch.setattr(xsoar_capture, "create_client", lambda: object())
    monkeypatch.setattr(
        xsoar_capture, "get_integration_config", lambda client, name: {"ok": 1}
    )
    monkeypatch.setattr(
        xsoar_capture,
        "create_integration_instance",
        lambda client, name, server_config, filled: (None, "boom"),
    )

    captured, payload = capture_xsoar_params(
        integration_yml_path="/tmp/fake.yml", overrides={"k": "v"}
    )

    assert captured is None
    assert payload is not None
    assert payload["k"] == "v"
