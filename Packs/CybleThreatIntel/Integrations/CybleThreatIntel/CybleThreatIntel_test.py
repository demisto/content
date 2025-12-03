import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from CybleThreatIntel import (
    Client,
    calculate_verdict,
    get_time_range,
    epoch_to_iso,
    cyble_ioc_lookup_command,
    fetch_indicators_command,
    VerdictEnum,
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
    mock_lookup.return_value = {"data": {"iocs": [{"ioc": "SAMPLE_IOC", "ioc_type": "custom", "first_seen": 1700000000}]}}

    c = Client({"base_url": "x", "access_token": {"password": "a"}})
    result = cyble_ioc_lookup_command(c, {"ioc": "SAMPLE_IOC"})

    assert result.outputs["IOC"] == "SAMPLE_IOC"


# -------------------------------------------------------------------
#   FETCH INDICATORS – MAIN LOGIC
# -------------------------------------------------------------------


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


from unittest.mock import Mock


def test_calculate_verdict_invalid_inputs():
    assert calculate_verdict("bad", "weird") == "Unknown"
    assert calculate_verdict(-10, "low") == "Unknown"
    assert calculate_verdict(200, "high") == "Malicious"


def test_ioc_lookup_missing_argument(mocker):
    client = Mock()
    with pytest.raises(Exception) as e:
        cyble_ioc_lookup_command(client, {})
    assert "Missing required argument: ioc" in str(e.value)
