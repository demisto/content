import json
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

import FeedCyberintPremium

BASE_URL = "https://feed-example.com"
TOKEN = "example_token"
FEED_PATH = "/ioc-intel/feed-api/v1/feed/jsonl"
ENRICH_PATH = "/ioc-intel/enrichment-api/v1/enrichment"


def load_mock_response() -> str:
    with open("test_data/premium_indicators.jsonl") as file:
        return file.read()


def load_mock_empty_response() -> str:
    with open("test_data/empty.jsonl") as file:
        return file.read()


@pytest.fixture()
def mock_client(mocker) -> FeedCyberintPremium.Client:
    # ContentClient.__init__ touches the XSOAR runtime (support_multithreading),
    # which isn't available under demistomock — bypass it in tests.
    mocker.patch("FeedCyberintPremium.ContentClient.__init__", return_value=None)
    client = FeedCyberintPremium.Client(
        base_url=BASE_URL,
        access_token=TOKEN,
        verify=False,
        proxy=False,
    )
    client._base_url = BASE_URL
    client._verify = False
    client._headers = {}
    client._ok_codes = ()
    return client


def _http_responder(feed_text: str | list[str] | None = None, enrich_json: dict | None = None):
    """Build a side_effect for Client._http_request that routes by url_suffix."""
    feed_responses = feed_text if isinstance(feed_text, list) else ([feed_text] if feed_text is not None else [])
    feed_iter = iter(feed_responses)

    def side_effect(*args, **kwargs):
        url_suffix = kwargs.get("url_suffix", "")
        if url_suffix == FEED_PATH:
            return next(feed_iter)
        if url_suffix == ENRICH_PATH:
            return enrich_json
        raise AssertionError(f"Unexpected url_suffix: {url_suffix}")

    return side_effect


def test_fetch_feed_page(mocker, mock_client: FeedCyberintPremium.Client):
    """
    Scenario: Test fetching a single page of IOCs from the premium feed.

    Given: mock_client.
    When: Called fetch_feed_page.
    Then: Ensure that indicators are returned.
    """
    mocker.patch.object(FeedCyberintPremium.Client, "_http_request", side_effect=_http_responder(feed_text=load_mock_response()))

    with patch("FeedCyberintPremium.auto_detect_indicator_type") as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if "." in str(x) and len(str(x)) < 16 else "URL"
        indicators = mock_client.fetch_feed_page(filters={}, limit=10, offset=0)

    assert indicators is not None
    assert len(indicators) > 0


def test_get_indicators_command(mocker, mock_client):
    """
    Scenario: Test retrieving indicators via get_indicators_command.

    Given: mock_client.
    When: Called the get_indicators_command.
    Then: Ensure that the result is returned.
    """
    mocker.patch.object(FeedCyberintPremium.Client, "_http_request", side_effect=_http_responder(feed_text=load_mock_response()))

    args = {"limit": 10, "offset": 0}

    with patch("FeedCyberintPremium.auto_detect_indicator_type") as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x and "." in str(x) and len(str(x)) < 16 else "URL"
        result = FeedCyberintPremium.get_indicators_command(mock_client, args)

    assert result is not None
    assert result.outputs is not None
    assert len(result.outputs) > 0


def test_get_indicators_command_with_filters(mocker, mock_client):
    """
    Scenario: Test retrieving indicators with filters.

    Given: mock_client with filters.
    When: Called the get_indicators_command with indicator_type and severity_min.
    Then: Ensure that the result is returned and filters were sent to the API.
    """
    http_mock = mocker.patch.object(
        FeedCyberintPremium.Client, "_http_request", side_effect=_http_responder(feed_text=load_mock_response())
    )

    args = {
        "limit": 10,
        "offset": 0,
        "indicator_type": "ipv4",
        "severity_min": "3",
        "malicious": "yes",
    }

    with patch("FeedCyberintPremium.auto_detect_indicator_type") as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x and "." in str(x) and len(str(x)) < 16 else "URL"
        result = FeedCyberintPremium.get_indicators_command(mock_client, args)

    assert result is not None

    body = http_mock.call_args.kwargs["json_data"]
    assert body["filters"]["indicator_type"] == ["ipv4"]
    assert body["filters"]["severity_min"] == 3
    assert body["filters"]["malicious"] == "yes"


@mock.patch("FeedCyberintPremium.demisto")
@mock.patch("FeedCyberintPremium.is_execution_time_exceeded")
def test_fetch_indicators_with_publish(
    is_execution_time_exceeded_mock,
    mock_demisto,
    mocker,
    mock_client: FeedCyberintPremium.Client,
):
    """
    Scenario: Test that fetch publishes indicators page-by-page.

    Given: mock_client with 2 pages (page 1 has data, page 2 is empty).
    When: Called fetch_indicators_with_publish.
    Then:
    - demisto.createIndicators is called once (for the one non-empty page).
    - The published indicators have the correct XSOAR format.
    """
    is_execution_time_exceeded_mock.return_value = False
    mock_demisto.getIntegrationContext.return_value = {"offset": 0}
    mock_demisto.debug = MagicMock()
    mock_demisto.setIntegrationContext = MagicMock()
    mock_demisto.createIndicators = MagicMock()

    mocker.patch.object(
        FeedCyberintPremium.Client,
        "_http_request",
        side_effect=_http_responder(feed_text=[load_mock_response(), load_mock_empty_response()]),
    )

    with patch("FeedCyberintPremium.auto_detect_indicator_type") as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x and "." in str(x) and len(str(x)) < 16 else "File"
        total = FeedCyberintPremium.fetch_indicators_with_publish(
            client=mock_client,
            tlp_color="GREEN",
            filters={},
            feed_tags=["test"],
        )

    assert total > 0
    assert mock_demisto.createIndicators.call_count >= 1
    first_call_args = mock_demisto.createIndicators.call_args_list[0][0][0]
    assert first_call_args[0]["service"] == "Cyberint Premium Feed"
    assert "rawJSON" in first_call_args[0]
    assert first_call_args[0]["fields"]["trafficlightprotocol"] == "GREEN"
    assert first_call_args[0]["fields"]["tags"] == ["test"]


@mock.patch("FeedCyberintPremium.demisto")
@mock.patch("FeedCyberintPremium.is_execution_time_exceeded")
def test_fetch_saves_offset_on_timeout(
    is_execution_time_exceeded_mock,
    mock_demisto,
    mock_client: FeedCyberintPremium.Client,
):
    """
    Scenario: When execution time is exceeded, offset is saved for next run.

    Given: is_execution_time_exceeded returns True immediately.
    When: Called fetch_indicators_with_publish.
    Then: offset is saved to integration context, no indicators published.
    """
    is_execution_time_exceeded_mock.return_value = True
    mock_demisto.getIntegrationContext.return_value = {"offset": 40000, "last_fetch_time": "2025-01-01T00:00:00Z"}
    mock_demisto.debug = MagicMock()
    mock_demisto.setIntegrationContext = MagicMock()
    mock_demisto.createIndicators = MagicMock()

    total = FeedCyberintPremium.fetch_indicators_with_publish(
        client=mock_client,
        tlp_color="",
        filters={},
        feed_tags=[],
    )

    assert total == 0
    call_args = mock_demisto.setIntegrationContext.call_args[0][0]
    assert call_args["offset"] == 40000
    mock_demisto.createIndicators.assert_not_called()


@mock.patch("FeedCyberintPremium.demisto")
@mock.patch("FeedCyberintPremium.is_execution_time_exceeded")
def test_fetch_indicators_command_incremental(
    is_execution_time_exceeded_mock,
    mock_demisto,
    mocker,
    mock_client: FeedCyberintPremium.Client,
):
    """
    Scenario: On subsequent runs, fetch only new indicators since last run.

    Given: integration context has last_fetch_time set.
    When: Called fetch_indicators_command.
    Then:
    - The API request includes added_to_feed_after matching last_fetch_time.
    - last_fetch_time is updated after successful fetch.
    """
    is_execution_time_exceeded_mock.return_value = False
    mock_demisto.getIntegrationContext.return_value = {
        "offset": 0,
        "last_fetch_time": "2025-01-05T00:00:00Z",
    }
    mock_demisto.debug = MagicMock()
    mock_demisto.setIntegrationContext = MagicMock()
    mock_demisto.createIndicators = MagicMock()

    http_mock = mocker.patch.object(
        FeedCyberintPremium.Client,
        "_http_request",
        side_effect=_http_responder(feed_text=[load_mock_response(), load_mock_empty_response()]),
    )

    params = {
        "feed": True,
        "indicator_type": "All",
    }

    with patch("FeedCyberintPremium.auto_detect_indicator_type") as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x and "." in str(x) and len(str(x)) < 16 else "File"
        FeedCyberintPremium.fetch_indicators_command(mock_client, params)

    first_body = http_mock.call_args_list[0].kwargs["json_data"]
    assert first_body["filters"]["added_to_feed_after"] == "2025-01-05T00:00:00Z"

    final_ctx = mock_demisto.setIntegrationContext.call_args_list[-1][0][0]
    assert "last_fetch_time" in final_ctx
    assert final_ctx["offset"] == 0


@mock.patch("FeedCyberintPremium.demisto")
@mock.patch("FeedCyberintPremium.is_execution_time_exceeded")
def test_fetch_indicators_command_first_run(
    is_execution_time_exceeded_mock,
    mock_demisto,
    mocker,
    mock_client: FeedCyberintPremium.Client,
):
    """
    Scenario: On first run (no last_fetch_time), uses first_fetch window.

    Given: integration context has no last_fetch_time.
    When: Called fetch_indicators_command with first_fetch="3 days".
    Then: The API request includes added_to_feed_after from ~3 days ago.
    """
    is_execution_time_exceeded_mock.return_value = False
    mock_demisto.getIntegrationContext.return_value = {}
    mock_demisto.debug = MagicMock()
    mock_demisto.setIntegrationContext = MagicMock()
    mock_demisto.createIndicators = MagicMock()

    http_mock = mocker.patch.object(
        FeedCyberintPremium.Client,
        "_http_request",
        side_effect=_http_responder(feed_text=[load_mock_response(), load_mock_empty_response()]),
    )

    params = {
        "feed": True,
        "indicator_type": "All",
        "first_fetch": "3 days",
    }

    with patch("FeedCyberintPremium.auto_detect_indicator_type") as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x and "." in str(x) and len(str(x)) < 16 else "File"
        FeedCyberintPremium.fetch_indicators_command(mock_client, params)

    first_body = http_mock.call_args_list[0].kwargs["json_data"]
    assert "added_to_feed_after" in first_body["filters"]


def test_raw_to_indicator():
    """Test raw_to_indicator conversion."""
    item = {
        "indicator_type": "ipv4",
        "indicator_value": "1.1.1.1",
        "activity": "CnC Server",
        "confidence": 90,
        "severity": 4,
        "malicious": "yes",
        "kill_chain_stage": "command-and-control",
        "first_seen": "2025-01-01T12:00:00Z",
        "last_seen": "2025-01-06T12:49:40Z",
        "is_blocking": True,
        "is_unique": True,
        "malware_types": ["Trojan"],
        "has_cve": False,
        "has_campaign": True,
        "valid_until": "2025-07-06T13:00:00Z",
    }

    with patch("FeedCyberintPremium.auto_detect_indicator_type") as mock_auto_detect:
        mock_auto_detect.return_value = "IP"
        result = FeedCyberintPremium.raw_to_indicator(item, tlp_color="AMBER", feed_tags=["tag1"])

    assert result is not None
    assert result["type"] == "IP"
    assert result["value"] == "1.1.1.1"
    assert result["service"] == "Cyberint Premium Feed"
    assert result["fields"]["severity"] == "High"
    assert result["fields"]["trafficlightprotocol"] == "AMBER"
    assert result["fields"]["tags"] == ["tag1"]
    assert result["fields"]["hascampaign"] is True


def test_raw_to_indicator_returns_none_for_invalid():
    """Test that raw_to_indicator returns None for unrecognized values."""
    with patch("FeedCyberintPremium.auto_detect_indicator_type") as mock_auto_detect:
        mock_auto_detect.return_value = None
        result = FeedCyberintPremium.raw_to_indicator({"indicator_value": "not-valid"}, tlp_color="", feed_tags=[])
    assert result is None

    result = FeedCyberintPremium.raw_to_indicator({}, tlp_color="", feed_tags=[])
    assert result is None


def test_build_filters():
    """Test building filters from integration parameters."""
    params = {
        "indicator_type": "IP,Domain",
        "activity": "CnC Server,Phishing",
        "confidence_min": "50",
        "severity_min": "3",
        "malicious": "yes",
    }

    filters = FeedCyberintPremium.build_filters(params)

    assert filters["indicator_type"] == ["ipv4", "domain"]
    assert filters["activity"] == ["CnC Server", "Phishing"]
    assert filters["confidence_min"] == 50
    assert filters["severity_min"] == 3
    assert filters["malicious"] == "yes"


def test_build_filters_all_types():
    """Test that 'All' indicator type results in no type filter."""
    params = {"indicator_type": "All"}

    filters = FeedCyberintPremium.build_filters(params)

    assert "indicator_type" not in filters


def test_build_filters_from_args():
    """Test building filters from command arguments."""
    args = {
        "indicator_type": "ipv4,domain",
        "severity_min": "3",
        "added_to_feed_after": "2025-01-01T00:00:00Z",
    }

    filters = FeedCyberintPremium.build_filters_from_args(args)

    assert filters["indicator_type"] == ["ipv4", "domain"]
    assert filters["severity_min"] == 3
    assert filters["added_to_feed_after"] == "2025-01-01T00:00:00Z"


def test_premium_header_transformer():
    """Test the premium_header_transformer function."""
    assert FeedCyberintPremium.premium_header_transformer("indicator_type") == "Indicator Type"
    assert FeedCyberintPremium.premium_header_transformer("indicator_value") == "Indicator Value"
    assert FeedCyberintPremium.premium_header_transformer("activity") == "Activity"
    assert FeedCyberintPremium.premium_header_transformer("confidence") == "Confidence"
    assert FeedCyberintPremium.premium_header_transformer("severity") == "Severity"
    assert FeedCyberintPremium.premium_header_transformer("malicious") == "Malicious"
    assert FeedCyberintPremium.premium_header_transformer("kill_chain_stage") == "Kill Chain Stage"
    assert FeedCyberintPremium.premium_header_transformer("first_seen") == "First Seen"
    assert FeedCyberintPremium.premium_header_transformer("last_seen") == "Last Seen"
    assert FeedCyberintPremium.premium_header_transformer("added_to_feed") == "Added to Feed"
    assert FeedCyberintPremium.premium_header_transformer("is_blocking") == "Is Blocking"
    assert FeedCyberintPremium.premium_header_transformer("has_cve") == "Has CVE"
    assert FeedCyberintPremium.premium_header_transformer("has_campaign") == "Has Campaign"


def test_test_module(mocker, mock_client):
    """Test the test_module function."""
    mocker.patch.object(FeedCyberintPremium.Client, "_http_request", side_effect=_http_responder(feed_text=load_mock_response()))

    with patch("FeedCyberintPremium.auto_detect_indicator_type") as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP"
        result = FeedCyberintPremium.test_module(mock_client)

    assert result == "ok"


def test_enrich_command_ipv4(mocker, mock_client):
    """Test enrichment of an IPv4 indicator."""
    with open("test_data/enrichment_ipv4.json") as f:
        mock_response = json.load(f)

    mocker.patch.object(FeedCyberintPremium.Client, "_http_request", side_effect=_http_responder(enrich_json=mock_response))

    args = {"type": "ipv4", "value": "192.0.2.1"}
    result = FeedCyberintPremium.enrich_command(mock_client, args)

    assert result is not None
    assert result.outputs["indicator_type"] == "ipv4"
    assert result.outputs["indicator_value"] == "1.1.1.1"
    assert result.outputs["activity"] == "CnC Server"
    assert result.outputs["confidence"] == 90
    assert result.outputs["severity"] == 4
    assert result.outputs["malicious"] == "yes"
    assert result.outputs["malware_family"] == "LockBit"
    assert "APT28" in result.outputs["threat_actors"]
    assert "CVE-2024-1234" in result.outputs["cves"]
    assert result.outputs["enrichment"]["geo"]["country"] == "Russia"
    assert result.outputs["enrichment"]["asn"]["number"] == 12345

    assert "Indicator Details" in result.readable_output
    assert "Threat Intelligence" in result.readable_output
    assert "TTPs" in result.readable_output
    assert "IPv4 Enrichment" in result.readable_output


def test_enrich_command_domain(mocker, mock_client):
    """Test enrichment of a domain indicator."""
    with open("test_data/enrichment_domain.json") as f:
        mock_response = json.load(f)

    http_mock = mocker.patch.object(
        FeedCyberintPremium.Client, "_http_request", side_effect=_http_responder(enrich_json=mock_response)
    )

    args = {"type": "domain", "value": "malicious-example.com"}
    result = FeedCyberintPremium.enrich_command(mock_client, args)

    assert result is not None
    assert result.outputs["indicator_type"] == "domain"
    assert result.outputs["indicator_value"] == "malicious-example.com"
    assert result.outputs["activity"] == "Phishing"
    assert result.outputs["enrichment"]["ips"] == ["2.2.2.2", "3.3.3.3"]
    assert result.outputs["enrichment"]["whois"]["registrant_name"] == "John Doe"

    assert "Indicator Details" in result.readable_output
    assert "Domain Enrichment" in result.readable_output

    body = http_mock.call_args.kwargs["json_data"]
    assert body["type"] == "domain"
    assert body["value"] == "malicious-example.com"


def test_enrich_command_no_enrichment(mocker, mock_client):
    """Test enrichment when no type-specific enrichment data is returned."""
    mock_response = {
        "indicator_type": "ipv4",
        "indicator_value": "9.9.9.9",
        "activity": "Unknown",
        "confidence": 10,
        "severity": 1,
        "malicious": "inconclusive",
        "first_seen": None,
        "last_seen": None,
        "valid_until": None,
        "kill_chain_stage": None,
        "malware_types": [],
        "malware_family": None,
        "origin_countries": [],
        "targeted_countries": [],
        "targeted_sectors": [],
        "targeted_brands": [],
        "threat_actors": [],
        "campaigns": [],
        "cves": [],
        "ttps": [],
        "tags": [],
        "enrichment": None,
    }

    mocker.patch.object(FeedCyberintPremium.Client, "_http_request", side_effect=_http_responder(enrich_json=mock_response))

    args = {"type": "ipv4", "value": "9.9.9.9"}
    result = FeedCyberintPremium.enrich_command(mock_client, args)

    assert result is not None
    assert result.outputs["indicator_value"] == "9.9.9.9"
    assert "Indicator Details" in result.readable_output
    assert "IPv4 Enrichment" not in result.readable_output
