from unittest.mock import Mock

import pytest
import requests

from CommonServerPython import Common, DBotScoreReliability, DemistoException
from IsMalicious import Client, dbot_verdict, reputation_command

import IsMalicious


@pytest.mark.parametrize(
    "response,expected",
    [
        ({"malicious": False, "lookupStatus": "unknown", "riskScore": {"score": 0}}, 0),
        ({"malicious": False, "sources": [{"name": "context-only"}]}, 0),
        ({"malicious": False, "riskScore": {"score": 0, "level": "safe"}}, 0),
        ({"malicious": True, "delisted": True}, 0),
        ({"malicious": True, "evidence": {"verdict": "malicious"}}, 3),
        ({"malicious": False, "evidence": {"verdict": "suspicious"}}, 2),
        ({"malicious": False, "evidence": {"verdict": "clean"}}, 1),
        ({"malicious": True}, 3),
    ],
)
def test_dbot_mapping(response, expected):
    assert dbot_verdict(response)[0] == expected


def client():
    return Client(base_url="https://api.ismalicious.com", verify=True, headers={"X-API-KEY": "synthetic-encoded-credential"})


def test_http_query_encoding(requests_mock):
    query = "https://example.invalid/path?a=1&b=2"
    requests_mock.get("https://api.ismalicious.com/check", json={"malicious": False})
    client().check(query)
    assert requests_mock.last_request.qs["query"] == [query]
    assert requests_mock.last_request.headers["X-API-KEY"] == "synthetic-encoded-credential"
    assert requests_mock.last_request.qs["enrichment"] == ["standard"]


@pytest.mark.parametrize("status", [401, 403, 429, 500, 302])
def test_http_errors_are_explicit(requests_mock, status):
    requests_mock.get(
        "https://api.ismalicious.com/check",
        status_code=status,
        json={"malicious": True},
        headers={"Location": "https://example.invalid/redirect"},
    )
    with pytest.raises(DemistoException):
        client().check("example.invalid")
    assert len(requests_mock.request_history) == 1


def test_timeout_not_clean(requests_mock):
    requests_mock.get("https://api.ismalicious.com/check", exc=requests.Timeout)
    with pytest.raises(DemistoException):
        client().check("example.invalid")


@pytest.mark.parametrize("payload", [[], {}, {"malicious": "false"}])
def test_invalid_response(requests_mock, payload):
    requests_mock.get("https://api.ismalicious.com/check", json=payload)
    with pytest.raises(DemistoException):
        client().check("example.invalid")


@pytest.mark.parametrize(
    "kind,value,context",
    [
        ("ip", "8.8.8.8", "IP"),
        ("domain", "example.invalid", "Domain"),
        ("url", "https://example.invalid/path?a=1&b=2", "URL"),
        ("file", "a" * 64, "File"),
    ],
)
def test_standard_and_vendor_context(kind, value, context):
    c = Mock()
    c.check.return_value = {
        "malicious": True,
        "evidence": {"verdict": "malicious", "reasons": ["synthetic"]},
        "riskScore": {"score": 90},
        "confidence": {"score": 60},
        "blocklistHits": 2,
    }
    result = reputation_command(c, {kind: value}, kind, DBotScoreReliability.F)[0]
    assert result.outputs["RiskScore"] == 90
    assert result.outputs["Confidence"] == 60
    assert result.outputs["BlocklistHits"] == 2
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert any(key.startswith(context + "(") for key in result.indicator.to_context())
    assert result.raw_response == c.check.return_value


def test_missing_values_rejected():
    with pytest.raises(ValueError):
        reputation_command(Mock(), {}, "ip", DBotScoreReliability.F)


def test_file_path_is_not_uploaded():
    c = Mock()
    with pytest.raises(ValueError):
        reputation_command(c, {"file": "/etc/passwd"}, "file", DBotScoreReliability.F)
    c.check.assert_not_called()


def test_batch_is_bounded():
    c = Mock()
    with pytest.raises(ValueError):
        reputation_command(c, {"ip": ["8.8.8.8"] * 51}, "ip", DBotScoreReliability.F)
    c.check.assert_not_called()


def test_url_commas_preserved():
    c = Mock()
    c.check.return_value = {"malicious": False}
    value = "https://example.invalid/path?q=one,two"
    reputation_command(c, {"url": value}, "url", DBotScoreReliability.F)
    c.check.assert_called_once_with(value)


def test_url_array_supported():
    c = Mock()
    c.check.return_value = {"malicious": False}
    values = ["https://example.invalid/a,b", "https://example.invalid/c"]
    assert len(reputation_command(c, {"url": values}, "url", DBotScoreReliability.F)) == 2
    assert [call.args[0] for call in c.check.call_args_list] == values


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip", "malicious.example.invalid"),
        ("ip", "999.1.1.1"),
        ("domain", "8.8.8.8"),
        ("domain", "https://example.invalid"),
        ("domain", "-bad.example"),
        ("domain", "localhost"),
        ("url", "example.invalid"),
        ("url", "ftp://example.invalid/a"),
        ("url", "https://example.invalid:bad"),
        ("url", "https://user:password@example.invalid"),
        ("file", "/etc/passwd"),
    ],
)
def test_wrong_type_rejected_before_requests(kind, value):
    c = Mock()
    with pytest.raises(ValueError):
        reputation_command(c, {kind: value}, kind, DBotScoreReliability.F)
    c.check.assert_not_called()


def test_batch_prevalidated_before_requests():
    c = Mock()
    with pytest.raises(ValueError):
        reputation_command(c, {"ip": ["8.8.8.8", "example.invalid"]}, "ip", DBotScoreReliability.F)
    c.check.assert_not_called()


def test_ipv6_supported():
    c = Mock()
    c.check.return_value = {"malicious": False}
    reputation_command(c, {"ip": "2001:4860:4860::8888"}, "ip", DBotScoreReliability.F)
    c.check.assert_called_once_with("2001:4860:4860::8888")


@pytest.mark.parametrize("params", [{}, {"credentials": None}, {"credentials": {}}, {"credentials": {"password": ""}}])
def test_missing_credentials_report_error_before_client_creation(monkeypatch, params):
    monkeypatch.setattr(IsMalicious.demisto, "params", Mock(return_value=params))
    create_client = Mock()
    report_error = Mock()
    monkeypatch.setattr(IsMalicious, "Client", create_client)
    monkeypatch.setattr(IsMalicious, "return_error", report_error)

    IsMalicious.main()

    create_client.assert_not_called()
    report_error.assert_called_once_with("IsMalicious integration failed: The complete X-API-KEY credential is required.")
