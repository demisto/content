import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from CybleThreatIntel import (
    Client,
    calculate_verdict,
    get_time_range,
    epoch_to_iso,
    cyble_ioc_lookup_command,
    fetch_indicators_command,
    VerdictEnum,
    ConfidenceLevel,
)


# -------------------------------------------------------------------
#   CLIENT INITIALIZATION
# -------------------------------------------------------------------
def test_client_initialization():
    params = {"base_url": "https://api.example.com/", "access_token": {"password": "XYZ"}}
    c = Client(params)

    assert c.base_url == "https://api.example.com"
    assert c.access_token == "XYZ"
    assert c.headers["Authorization"] == "Bearer XYZ"


# -------------------------------------------------------------------
#   HTTP POST – SUCCESS
# -------------------------------------------------------------------
@patch("CybleThreatIntel.requests.post")
def test_http_post_success(mock_post):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"ok": True}
    mock_post.return_value = resp

    client = Client({"base_url": "https://example.com", "access_token": {"password": "a"}})
    r = client.http_post("/y/iocs", {"x": 1})

    assert r == {"ok": True}
    mock_post.assert_called_once()


# -------------------------------------------------------------------
#   HTTP POST – FAILURE
# -------------------------------------------------------------------
@patch("CybleThreatIntel.requests.post")
def test_http_post_failure(mock_post):
    resp = MagicMock()
    resp.status_code = 500
    resp.raise_for_status.side_effect = Exception("Server Error")
    resp.text = "error"
    mock_post.return_value = resp

    client = Client({"base_url": "https://example.com", "access_token": {"password": "a"}})

    with pytest.raises(Exception):
        client.http_post("/y/iocs", {})


# -------------------------------------------------------------------
#   DATE RANGE LOGIC
# -------------------------------------------------------------------
def test_get_time_range_without_last_run():
    now = datetime.utcnow()
    gte, lte = get_time_range(5, {})

    g = datetime.fromisoformat(gte)
    assert (now - g).seconds <= 5 * 3600 + 5  # small tolerance


def test_get_time_range_with_last_run():
    now = datetime.utcnow().isoformat()
    gte, lte = get_time_range(6, {"last_fetch": now})

    assert gte == now


# -------------------------------------------------------------------
#   EPOCH TO ISO
# -------------------------------------------------------------------
def test_epoch_to_iso():
    ts = 1700000000
    result = epoch_to_iso(ts)
    assert result.endswith("Z")


# -------------------------------------------------------------------
#   VERDICT MATRIX
# -------------------------------------------------------------------
@pytest.mark.parametrize(
    "risk,conf,expected",
    [
        (10, "Low", VerdictEnum.UNKNOWN.value),
        (10, "Medium", VerdictEnum.SUSPICIOUS.value),
        (10, "High", VerdictEnum.NOT_MALICIOUS.value),
        (30, "Low", VerdictEnum.UNKNOWN.value),
        (30, "Medium", VerdictEnum.SUSPICIOUS.value),
        (70, "High", VerdictEnum.MALICIOUS.value),
        (80, "Low", VerdictEnum.SUSPICIOUS.value),
        (80, "High", VerdictEnum.MALICIOUS.value),
    ],
)
def test_calculate_verdict_values(risk, conf, expected):
    assert calculate_verdict(risk, conf) == expected


# -------------------------------------------------------------------
#   IOC LOOKUP COMMAND – NO RESULTS
# -------------------------------------------------------------------
@patch("CybleThreatIntel.return_error")
@patch("CybleThreatIntel.Client.ioc_lookup")
def test_ioc_lookup_no_results(mock_lookup, mock_return):
    mock_lookup.return_value = {"data": {"iocs": []}}

    c = Client({"base_url": "x", "access_token": {"password": "a"}})
    result = cyble_ioc_lookup_command(c, {"ioc": "1.1.1.1"})

    assert "No results found" in result.readable_output


# -------------------------------------------------------------------
#   IOC LOOKUP – WITH RESULTS
# -------------------------------------------------------------------
@patch("CybleThreatIntel.Client.ioc_lookup")
def test_ioc_lookup_success(mock_lookup):
    mock_lookup.return_value = {
        "data": {
            "iocs": [
                {"ioc": "bad.com", "ioc_type": "domain", "first_seen": 1700000000}
            ]
        }
    }

    c = Client({"base_url": "x", "access_token": {"password": "a"}})
    result = cyble_ioc_lookup_command(c, {"ioc": "bad.com"})

    assert "bad.com" in result.readable_output
    assert result.outputs["IOC"] == "bad.com"


# -------------------------------------------------------------------
#   FETCH INDICATORS – MAIN LOGIC
# -------------------------------------------------------------------
@patch("CybleThreatIntel.demisto")
def test_fetch_indicators_happy_path(mock_demisto):
    mock_demisto.args.return_value = {}
    mock_demisto.getLastRun.return_value = {}
    mock_demisto.setLastRun = MagicMock()
    mock_demisto.createIndicators = MagicMock()

    client = Client({"base_url": "x", "access_token": {"password": "a"}})

    client.fetch_iocs = MagicMock(return_value={
        "success": True,
        "data": {
            "iocs": [
                {
                    "ioc": "1.1.1.1",
                    "ioc_type": "IP",
                    "risk_score": 80,
                    "confidence_rating": "High",
                    "first_seen": 1700000000,
                    "last_seen": 1700000500,
                    "sources": ["test"],
                    "behaviour_tags": [],
                    "target_countries": [],
                    "target_regions": [],
                    "target_industries": [],
                    "related_malware": [],
                    "related_threat_actors": [],
                }
            ]
        },
    })

    params = {"first_fetch": 1, "max_fetch": 50}

    count = fetch_indicators_command(client, params)

    assert count == 1
    mock_demisto.createIndicators.assert_called_once()
    mock_demisto.setLastRun.assert_called()


# -------------------------------------------------------------------
#   FETCH INDICATORS – RETRY FAILURE
# -------------------------------------------------------------------
@patch("CybleThreatIntel.demisto")
def test_fetch_indicators_retry_fail(mock_demisto):

    mock_demisto.args.return_value = {}
    mock_demisto.getLastRun.return_value = {}

    client = Client({"base_url": "x", "access_token": {"password": "a"}})

    client.fetch_iocs = MagicMock(side_effect=Exception("fail"))

    params = {"first_fetch": 1, "max_fetch": 50}

    count = fetch_indicators_command(client, params)

    assert count == 0
