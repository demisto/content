from unittest.mock import patch

import pytest

import RelayShield


def _client():
    return RelayShield.Client(base_url="https://api.relayshield.net", api_key="rs_live_testkey", verify=True, proxy=False)


def test_domain_command_finding():
    client = _client()
    with patch.object(
        client,
        "call",
        return_value={
            "queried": "evil.com",
            "verdict": "CRITICAL",
            "findings": [{"type": "typosquat_suspected"}],
            "checked_at": "2026-07-22T00:00:00Z",
        },
    ):
        results = RelayShield.domain_command(client, {"domain": "evil.com"})
    assert len(results) == 1
    r = results[0]
    assert r.indicator.dbot_score.score == 3
    assert r.indicator.domain == "evil.com"


def test_domain_command_clean_maps_to_unknown_not_good():
    """A clean result must map to DBotScore Unknown (0), never Good (1) --
    "no known finding" is not the same claim as "verified safe"."""
    client = _client()
    with patch.object(client, "call", return_value={"queried": "clean.com", "verdict": None, "findings": []}):
        results = RelayShield.domain_command(client, {"domain": "clean.com"})
    assert results[0].indicator.dbot_score.score == 0


def test_ip_command():
    client = _client()
    with patch.object(
        client,
        "call",
        return_value={
            "queried": "1.2.3.4",
            "reputation": 50,
            "malicious_votes": 2,
            "as_owner": "Evil Corp",
            "country": "US",
        },
    ):
        results = RelayShield.ip_command(client, {"ip": "1.2.3.4"})
    assert results[0].indicator.dbot_score.score == 3
    assert results[0].indicator.asn == "Evil Corp"


def test_email_command_combines_breach_and_session():
    client = _client()
    with patch.object(
        client,
        "call",
        side_effect=[
            {"found": True, "sources": ["breach1"]},
            {"found": True, "sessions": [{"severity": "CRITICAL", "service_category": "email"}]},
        ],
    ):
        results = RelayShield.email_command(client, {"email": "victim@example.com"})
    r = results[0]
    assert r.indicator.dbot_score.score == 3
    assert r.outputs["breach_found"] is True
    assert r.outputs["session_risk_found"] is True


def test_mcp_registry_risk_command_requires_input():
    client = _client()
    try:
        RelayShield.mcp_registry_risk_command(client, {})
        pytest.fail("should have raised")
    except ValueError:
        pass


def test_mcp_registry_risk_command():
    client = _client()
    with patch.object(
        client,
        "call",
        return_value={
            "queried": "https://evil-mcp.test",
            "verdict": "HIGH",
            "findings": [{"type": "typosquat_suspected"}],
        },
    ):
        result = RelayShield.mcp_registry_risk_command(client, {"server_url": "https://evil-mcp.test"})
    # Assert on the structured outputs with an equality check rather than a
    # substring search over the rendered markdown. A `"..." in <url string>`
    # test is what CodeQL flags as incomplete URL substring sanitization, and
    # the exact-match form is a stricter assertion anyway.
    assert result.outputs["queried"] == "https://evil-mcp.test"
    assert result.outputs["verdict"] == "HIGH"


def test_cert_expiry_command():
    client = _client()
    with patch.object(client, "call", return_value={"days_remaining": 3, "risk_level": "CRITICAL"}):
        result = RelayShield.cert_expiry_command(client, {"domain": "example.com"})
    assert result.outputs["days_remaining"] == 3


def test_supply_chain_command_requires_input():
    client = _client()
    try:
        RelayShield.supply_chain_command(client, {})
        pytest.fail("should have raised")
    except ValueError:
        pass


def test_supply_chain_command():
    client = _client()
    with patch.object(
        client,
        "call",
        return_value={
            "domains_checked": 2,
            "highest_risk": "HIGH",
            "critical_vendors": [],
        },
    ):
        result = RelayShield.supply_chain_command(client, {"vendor_domains": ["a.com", "b.com"]})
    assert result.outputs["domains_checked"] == 2


def test_client_call_raises_on_error_envelope():
    client = _client()
    with patch.object(RelayShield.BaseClient, "_http_request", return_value={"ok": False, "error": "bad request"}):
        try:
            client.call("/v1/metered/domain", {"domain": "x.com"})
            pytest.fail("should have raised")
        except RelayShield.DemistoException as e:
            assert "bad request" in str(e)


@pytest.mark.parametrize(
    "params",
    [
        {"credentials": None, "api_key": None},
        {"credentials": {}, "api_key": None},
        {},
    ],
)
def test_main_missing_api_key_does_not_raise_attributeerror(mocker, params):
    """XSOAR stores an unset encrypted parameter as an explicit None, so
    params.get("api_key", {}) returns None rather than the default and chaining
    .get() on it used to raise AttributeError. main() must surface a readable
    configuration error instead."""
    mocker.patch.object(RelayShield.demisto, "params", return_value=params)
    mocker.patch.object(RelayShield.demisto, "args", return_value={})
    mocker.patch.object(RelayShield.demisto, "command", return_value="test-module")
    return_error = mocker.patch.object(RelayShield, "return_error")

    RelayShield.main()

    message = return_error.call_args[0][0]
    assert "AttributeError" not in message
    assert "API Key is required" in message
