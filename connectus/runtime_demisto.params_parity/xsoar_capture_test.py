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

    def _fake_create(client, name, server_config, filled, extra_fields=None):
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
        lambda client, name, server_config, filled, extra_fields=None: (None, "boom"),
    )

    captured, payload = capture_xsoar_params(
        integration_yml_path="/tmp/fake.yml", overrides={"k": "v"}
    )

    assert captured is None
    assert payload is not None
    assert payload["k"] == "v"


# ---------------------------------------------------------------------------
# create_client proxy bypass
# ---------------------------------------------------------------------------
#
# The idex CLI / VS Code injects HTTPS_PROXY into the subprocess env; a
# corporate proxy then 403s the CONNECT tunnel to the tenant's api-<host>.
# The demisto_client SDK reads HTTPS_PROXY directly (os.getenv) and hands it to
# a raw urllib3.ProxyManager that ignores NO_PROXY, so the only reliable fix is
# to build the tenant client WITHOUT a proxy. These tests pin that behavior.


class _FakeConfiguration:
    def __init__(self):
        self.proxy = "SENTINEL_NOT_SET"


class _FakeApiClient:
    def __init__(self):
        self.configuration = _FakeConfiguration()
        self.user_agent = None


class _FakeClient:
    def __init__(self):
        self.api_client = _FakeApiClient()


def _install_fake_configure(monkeypatch):
    """Replace demisto_client.configure with a spy returning a fake client.

    Returns the dict that records the kwargs configure() was called with.
    """
    recorded: dict = {}

    def fake_configure(**kwargs):
        recorded.update(kwargs)
        client = _FakeClient()
        # Mimic the real SDK: it would set configuration.proxy from the proxy
        # arg (or HTTPS_PROXY). We set it to the passed proxy so the test can
        # verify create_client() neutralizes it afterwards.
        client.api_client.configuration.proxy = kwargs.get("proxy")
        return client

    monkeypatch.setattr(xsoar_capture.demisto_client, "configure", fake_configure)
    return recorded


def test_create_client_passes_empty_proxy_even_when_https_proxy_set(monkeypatch):
    """create_client() must pass proxy="" to configure(), not the env proxy."""
    monkeypatch.setenv("HTTPS_PROXY", "http://corp-proxy:8080")
    monkeypatch.setenv("HTTP_PROXY", "http://corp-proxy:8080")
    recorded = _install_fake_configure(monkeypatch)

    xsoar_capture.create_client(
        base_url="https://tenant.example.com",
        api_key="k",
        auth_id="4",
    )

    # The SDK's only fallback to HTTPS_PROXY happens when proxy is None; passing
    # an empty string prevents that fallback and yields a direct PoolManager.
    assert recorded.get("proxy") == ""


def test_create_client_nulls_configuration_proxy(monkeypatch):
    """create_client() must defensively null configuration.proxy on the client."""
    monkeypatch.setenv("HTTPS_PROXY", "http://corp-proxy:8080")
    _install_fake_configure(monkeypatch)

    client = xsoar_capture.create_client(
        base_url="https://tenant.example.com",
        api_key="k",
        auth_id="4",
    )

    assert client.api_client.configuration.proxy is None


# ---------------------------------------------------------------------------
# generate_dummy_value_for_param — param-type → dummy-value contract.
#
# Regression guard for the type-code collision that made a type-14 ENCRYPTED
# TEXT AREA secret (e.g. Zoom's `key` / an SSHKey) get emitted as a LIST
# ``["<override_key>"]`` via the multi-select branch. XSOAR cannot store a list
# into a scalar secret field, so the captured value came back "" on BOTH parity
# sides — a false "OK" verdict. Type 14 must be a SCALAR sentinel; multi-select
# is type 16.
# ---------------------------------------------------------------------------
def test_type_14_encrypted_textarea_is_scalar_not_list():
    """type 14 (encrypted text area, e.g. private key) → scalar sentinel."""
    value = xsoar_capture.generate_dummy_value_for_param(
        {"name": "key", "type": 14}
    )
    assert value == "<override_key>"
    assert not isinstance(value, list)


def test_type_16_multi_select_is_a_list():
    """type 16 (multi select) → a LIST, not a scalar."""
    value = xsoar_capture.generate_dummy_value_for_param(
        {"name": "tags", "type": 16, "options": ["a", "b"]}
    )
    assert value == ["a"]


def test_type_16_multi_select_non_empty_default_returns_empty_list():
    """type 16 with a non-empty default → [] (the opposite of the default)."""
    value = xsoar_capture.generate_dummy_value_for_param(
        {"name": "tags", "type": 16, "options": ["a", "b"], "defaultvalue": ["a"]}
    )
    assert value == []


def test_type_15_single_select_picks_non_default_scalar():
    """type 15 (single select) → a scalar option that is NOT the YML default."""
    value = xsoar_capture.generate_dummy_value_for_param(
        {"name": "region", "type": 15, "options": ["us", "eu"], "defaultvalue": "us"}
    )
    assert value == "eu"
    assert not isinstance(value, list)


def test_multi_select_and_encrypted_textarea_constants_match_xsoar():
    """Pin the canonical XSOAR type codes so the collision can't recur."""
    assert xsoar_capture.PARAM_TYPE_ENCRYPTED_TEXTAREA == 14
    assert xsoar_capture.PARAM_TYPE_SINGLE_SELECT == 15
    assert xsoar_capture.PARAM_TYPE_MULTI_SELECT == 16


# ---------------------------------------------------------------------------
# type-9 auth dummy: hiddenusername suppression (Akamai credentials_*)
# ---------------------------------------------------------------------------
def test_type9_hiddenusername_param_yields_no_identifier():
    """For a hiddenusername:true type-9 field (e.g. Akamai's credentials_access_token)
    the dummy MUST carry a password but MUST NOT inject a populated identifier —
    otherwise it re-introduces a spurious mismatch after the normalizer reduction."""
    value = xsoar_capture.generate_dummy_value_for_param(
        {"name": "credentials_access_token", "type": 9, "hiddenusername": True}
    )
    assert isinstance(value, dict)
    assert value.get("password")  # password is always present and non-empty
    # identifier absent or empty (never a populated dummy username).
    assert not value.get("identifier")


def test_type9_without_hiddenusername_still_yields_identifier():
    """Contrast: a NORMAL type-9 field (no hiddenusername) still injects a
    populated dummy identifier so a real username participates in the comparison."""
    value = xsoar_capture.generate_dummy_value_for_param(
        {"name": "credentials", "type": 9}
    )
    assert isinstance(value, dict)
    assert value.get("password")
    assert value.get("identifier")  # populated dummy username retained
