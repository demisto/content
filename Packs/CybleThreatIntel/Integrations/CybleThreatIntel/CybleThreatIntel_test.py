import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from CybleThreatIntel import (
    Client,
    calculate_verdict,
    get_time_range,
    epoch_to_iso,
    fmt_date,
    cyble_ioc_lookup_command,
    fetch_indicators_command,
    VerdictEnum,
    get_execution_timeout_seconds,
    should_stop_before_next_page,
    parse_resume_state,
    save_fetch_checkpoint,
    save_chunk_completed_checkpoint,
    map_cyble_ioc_type,
    build_indicator_from_ioc,
    TIME_TO_RUN_BUFFER_SECONDS,
    DEFAULT_EXECUTION_TIMEOUT_SECONDS,
)


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
    mocker.patch("CybleThreatIntel.return_error", side_effect=Exception("Missing required argument: ioc"))

    with pytest.raises(Exception) as e:
        cyble_ioc_lookup_command(client, {})
    assert "Missing required argument: ioc" in str(e.value)


def test_client_init_empty(mocker):
    params = {}
    client = Client(params)
    assert client.base_url == ""
    assert client.access_token == ""
    assert client.headers["Authorization"] == "Bearer "


def test_client_http_post_failure(mocker):
    client = Client({"base_url": "http://test.com", "access_token": {"password": "token"}})
    mock_resp = mocker.Mock()
    mock_resp.status_code = 400
    mock_resp.text = "Bad request"
    mock_resp.raise_for_status.side_effect = Exception("HTTP error")
    mocker.patch("requests.post", return_value=mock_resp)

    try:
        client.http_post("/endpoint", {"key": "value"})
    except Exception as e:
        assert "HTTP error" in str(e)


def test_epoch_to_iso_invalid():
    assert epoch_to_iso("invalid") is None


def test_fmt_date_none_and_invalid():
    assert fmt_date(None) == "None"
    assert "invalid" in fmt_date("invalid")


def test_client_init_edge_case(mocker):
    # edge case: empty access_token dict and trailing slash in URL
    client = Client({"base_url": "https://api.test.com/", "access_token": {"password": ""}})
    assert client.base_url == "https://api.test.com"
    assert client.access_token == ""


def test_epoch_to_iso_invalid_timestamp():
    # invalid timestamp should return None
    assert epoch_to_iso("not_a_timestamp") is None


def test_calculate_verdict_edge_cases():
    # risk_score None, confidence_rating None
    assert calculate_verdict(None, None) == "Unknown"
    # extreme low/high values beyond 0-100
    assert calculate_verdict(-50, "Low") == "Unknown"
    assert calculate_verdict(150, "High") == "Malicious"


def test_get_time_range_first_run_with_last_fetch():
    last_run = {"last_fetch": "2025-12-01T00:00:00"}
    gte, lte = get_time_range(5, last_run)
    assert gte == "2025-12-01T00:00:00"


def test_get_execution_timeout_seconds_from_calling_context(mocker):
    mocker.patch(
        "CybleThreatIntel.demisto.callingContext",
        {"context": {"TimeoutDuration": 900_000_000_000}},
    )
    assert get_execution_timeout_seconds() == 900.0


def test_get_execution_timeout_seconds_default(mocker):
    mocker.patch("CybleThreatIntel.demisto.callingContext", {"context": {}})
    assert get_execution_timeout_seconds() == float(DEFAULT_EXECUTION_TIMEOUT_SECONDS)


def test_should_stop_before_next_page_first_page():
    execution_start = datetime.utcnow()
    assert should_stop_before_next_page(0, 0, execution_start) is False


def test_should_stop_before_next_page_low_remaining_budget(mocker):
    execution_start = datetime.utcnow() - timedelta(seconds=170)
    mocker.patch("CybleThreatIntel.get_execution_timeout_seconds", return_value=180.0)
    assert should_stop_before_next_page(1, 20.0, execution_start) is True


def test_should_stop_before_next_page_enough_budget(mocker):
    execution_start = datetime.utcnow() - timedelta(seconds=30)
    mocker.patch("CybleThreatIntel.get_execution_timeout_seconds", return_value=900.0)
    assert should_stop_before_next_page(1, 20.0, execution_start) is False


def test_parse_resume_state():
    assert parse_resume_state({}) == (1, None)
    assert parse_resume_state({"page": "1"}) == (1, None)
    assert parse_resume_state({"page": "3", "chunk_lte": "2025-12-01T01:00:00"}) == (3, "2025-12-01T01:00:00")


@patch("CybleThreatIntel.demisto.setLastRun")
def test_save_fetch_checkpoint(mock_set_last_run):
    save_fetch_checkpoint("2025-12-01T00:00:00", 4, "2025-12-01T01:00:00")
    mock_set_last_run.assert_called_once_with(
        {
            "last_fetch": "2025-12-01T00:00:00",
            "page": "4",
            "chunk_lte": "2025-12-01T01:00:00",
        }
    )


@patch("CybleThreatIntel.demisto.setLastRun")
def test_save_chunk_completed_checkpoint(mock_set_last_run):
    save_chunk_completed_checkpoint("2025-12-01T01:00:00")
    mock_set_last_run.assert_called_once_with({"last_fetch": "2025-12-01T01:00:00"})


@patch("CybleThreatIntel.demisto.createIndicators")
@patch("CybleThreatIntel.demisto.setLastRun")
@patch("CybleThreatIntel.demisto")
def test_fetch_indicators_saves_checkpoint_per_page(mock_demisto, mock_set_last_run, mock_create_indicators, mocker):
    mock_demisto.args.return_value = {}
    mock_demisto.getLastRun.return_value = {}
    mocker.patch("CybleThreatIntel.get_execution_timeout_seconds", return_value=900.0)

    client = Client({"base_url": "x", "credentials": {"password": "a"}})
    client.fetch_iocs = MagicMock(
        side_effect=[
            {"success": True, "data": {"iocs": [{"ioc": "1.1.1.1", "ioc_type": "IPv4"}]}},
            {"success": True, "data": {"iocs": []}},
        ]
    )

    count = fetch_indicators_command(client, {"initial_interval": 1, "limit": 100})

    assert count == 1
    assert mock_create_indicators.call_count == 1
    submitted = mock_create_indicators.call_args[0][0]
    assert submitted[0]["type"] == "IP"
    assert submitted[0]["value"] == "1.1.1.1"
    checkpoint_calls = [
        call
        for call in mock_set_last_run.call_args_list
        if call.args[0].get("page") == "2"
    ]
    assert checkpoint_calls
    completed_calls = [call for call in mock_set_last_run.call_args_list if "page" not in call.args[0]]
    assert completed_calls


@pytest.mark.parametrize(
    "raw_type,value,expected",
    [
        ("IPv4", "1.1.1.1", "IP"),
        ("ip", "1.1.1.1", "IP"),
        ("IPv6", "2001:db8::1", "IPv6"),
        ("Domain", "evil.com", "Domain"),
        ("URL", "https://evil.com", "URL"),
        ("FileHash-MD5", "d41d8cd98f00b204e9800998ecf8427e", "File"),
        ("FileHash-SHA256", "a" * 64, "File"),
        ("Email", "a@b.com", "Email"),
        ("Wallet-Address", "0xabc", None),
        ("", "8.8.8.8", "IP"),  # fall back to value detection
    ],
)
def test_map_cyble_ioc_type(raw_type, value, expected):
    assert map_cyble_ioc_type(raw_type, value) == expected


def test_build_indicator_from_ioc_skips_empty_and_unknown():
    assert build_indicator_from_ioc({"ioc": "", "ioc_type": "IPv4"}) is None
    assert build_indicator_from_ioc({"ioc": "x", "ioc_type": "Wallet-Address"}) is None
    indicator = build_indicator_from_ioc({"ioc": "evil.com", "ioc_type": "Domain", "risk_score": 80})
    assert indicator is not None
    assert indicator["type"] == "Domain"
    assert indicator["value"] == "evil.com"


@patch("CybleThreatIntel.demisto.createIndicators")
@patch("CybleThreatIntel.demisto.setLastRun")
@patch("CybleThreatIntel.demisto")
def test_fetch_indicators_exits_before_timeout(mock_demisto, mock_set_last_run, mock_create_indicators, mocker):
    mock_demisto.args.return_value = {}
    mock_demisto.getLastRun.return_value = {}
    mocker.patch("CybleThreatIntel.get_execution_timeout_seconds", return_value=180.0)
    mocker.patch("CybleThreatIntel.should_stop_before_next_page", side_effect=[False, True])

    client = Client({"base_url": "x", "credentials": {"password": "a"}})
    client.fetch_iocs = MagicMock(
        return_value={"success": True, "data": {"iocs": [{"ioc": "1.1.1.1", "ioc_type": "ip"}]}}
    )

    count = fetch_indicators_command(client, {"initial_interval": 1, "limit": 100})

    assert count == 1
    assert client.fetch_iocs.call_count == 1
    assert mock_create_indicators.call_count == 1


@patch("CybleThreatIntel.demisto.createIndicators")
@patch("CybleThreatIntel.demisto.setLastRun")
@patch("CybleThreatIntel.demisto")
def test_fetch_stops_at_per_fetch_cap(mock_demisto, mock_set_last_run, mock_create_indicators, mocker):
    """Non-TIM: only one page of 100 should be submitted; page must not keep advancing."""
    mock_demisto.args.return_value = {}
    mock_demisto.getLastRun.return_value = {}
    mocker.patch("CybleThreatIntel.get_execution_timeout_seconds", return_value=900.0)
    mocker.patch("CybleThreatIntel.should_stop_before_next_page", return_value=False)

    page_payload = {
        "success": True,
        "data": {"iocs": [{"ioc": f"1.1.1.{i}", "ioc_type": "IPv4"} for i in range(100)]},
    }
    client = Client({"base_url": "x", "credentials": {"password": "a"}})
    client.fetch_iocs = MagicMock(return_value=page_payload)

    count = fetch_indicators_command(
        client, {"initial_interval": 1, "limit": 100, "max_indicators_per_fetch": 100}
    )

    assert count == 100
    assert mock_create_indicators.call_count == 1
    assert client.fetch_iocs.call_count == 1
    # Next page checkpointed for resume
    assert any(call.args[0].get("page") == "2" for call in mock_set_last_run.call_args_list)
