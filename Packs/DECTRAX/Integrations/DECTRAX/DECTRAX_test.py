"""Unit tests for DECTRAX Cortex XSOAR Integration."""

import pytest
from unittest.mock import MagicMock
from DECTRAX import Client, get_blocked_ips_command, check_ip_command, test_module as dectrax_test_module, Common


@pytest.fixture
def mock_client():
    client = Client(base_url="https://api.dectrax.com", api_key="test-api-key")
    return client


def test_test_module(mock_client):
    mock_client.test_connection = MagicMock(return_value="ok")
    assert dectrax_test_module(mock_client) == "ok"
    mock_client.test_connection.assert_called_once()


def test_get_blocked_ips_command(mock_client):
    mock_edl_text = "198.51.100.14\n203.0.113.88\n# Comment\n192.0.2.1\n"
    mock_client._http_request = MagicMock(return_value=mock_edl_text)

    results = get_blocked_ips_command(mock_client, {"limit": 2})

    assert results.outputs_prefix == "DECTRAX.BlockedIP"
    assert len(results.outputs) == 2
    assert results.outputs[0]["IP"] == "198.51.100.14"
    assert results.outputs[1]["IP"] == "203.0.113.88"
    assert "198.51.100.14" in results.readable_output


def test_check_ip_blocked(mock_client):
    mock_client.get_edl_firewall = MagicMock(return_value=["198.51.100.14", "203.0.113.88"])
    mock_client.get_ip_telemetry = MagicMock(return_value={"interactions": 5, "severity": "CRITICAL"})

    results = check_ip_command(mock_client, {"ip": "198.51.100.14"})

    assert results.outputs["Address"] == "198.51.100.14"
    assert results.outputs["Blocked"] is True
    assert results.outputs["Score"] == Common.DBotScore.BAD
    assert results.indicator.dbot_score.score == Common.DBotScore.BAD


def test_check_ip_clean(mock_client):
    mock_client.get_edl_firewall = MagicMock(return_value=["198.51.100.14"])
    mock_client.get_ip_telemetry = MagicMock(return_value={})

    results = check_ip_command(mock_client, {"ip": "8.8.8.8"})

    assert results.outputs["Address"] == "8.8.8.8"
    assert results.outputs["Blocked"] is False
    assert results.outputs["Score"] == Common.DBotScore.NONE
    assert results.indicator.dbot_score.score == Common.DBotScore.NONE


def test_check_ip_missing_param(mock_client):
    with pytest.raises(ValueError, match="Parameter 'ip' is required"):
        check_ip_command(mock_client, {})
