import pytest

from ThreatMonThreatFeed import (
    build_indicators,
    calculate_verdict,
    fetch_indicators_command,
    get_indicators_command,
    map_indicator_type,
    parse_indicator,
    strip_port,
)
from ThreatMonThreatFeed import test_module as run_test_module


class MockClient:
    """
    A minimal stand-in for the Client class, so the tests do not perform HTTP calls.
    """

    def __init__(self, response=None, exception=None):
        self.response = response or {}
        self.exception = exception
        self.calls: list = []

    def get_daily_iocs(self, data_type="all", size=500, collection_ids=None):
        self.calls.append({"data_type": data_type, "size": size, "collection_ids": collection_ids})
        if self.exception:
            raise self.exception
        return self.response


IOC_IP = {
    "ioc_value": "1.2.3.4:8080",
    "ioc_type": "ip",
    "extracted_ip": "1.2.3.4",
    "source": ["ThreatmonIntel"],
    "tags": ["c2"],
    "categories": ["malware"],
    "confidence_level": 90,
    "severity": "high",
    "status": "active",
    "isp": "Example ISP",
    "resolved_ips": ["1.2.3.4"],
    "geo_location": "TR",
    "score": 95,
    "created_at": "2026-01-02T00:00:00Z",
}

IOC_DOMAIN = {
    "ioc_value": "malicious.example.com",
    "ioc_type": "domain",
    "created_at": "2026-01-03T00:00:00Z",
}


@pytest.mark.parametrize(
    "ioc_type, expected",
    [
        ("ip", "IP"),
        ("IPv4", "IP"),
        ("domain", "Domain"),
        ("url", "URL"),
        ("file_hash", "File"),
        ("md5 hash", "File"),
    ],
)
def test_map_indicator_type(ioc_type, expected):
    """
    Given: A ThreatMon ioc_type value of a supported indicator type.
    When: Mapping it to an XSOAR indicator type.
    Then: The matching FeedIndicatorType is returned.
    """
    assert map_indicator_type(ioc_type) == expected


@pytest.mark.parametrize("ioc_type", ["", None, "something-else"])
def test_map_indicator_type_unknown_returns_none(ioc_type):
    """
    Given: A missing or unrecognized ioc_type.
    When: Mapping it to an XSOAR indicator type.
    Then: None is returned so the caller can skip the indicator.
    """
    assert map_indicator_type(ioc_type) is None


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1.2.3.4:8080", "1.2.3.4"),
        ("1.2.3.4", "1.2.3.4"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("2001:db8::1", "2001:db8::1"),
    ],
)
def test_strip_port(value, expected):
    """
    Given: An indicator value that may contain a port, including IPv6 forms.
    When: Stripping the port.
    Then: The port is removed for IPv4 and bracketed IPv6, and unbracketed IPv6 is left intact.
    """
    assert strip_port(value) == expected


def test_parse_indicator_ip_strips_port():
    """
    Given: An IP IOC whose value contains a port and which has an extracted_ip field.
    When: Parsing it into an XSOAR indicator.
    Then: The indicator value is the bare IP, and the rawJSON and service keys are present.
    """
    indicator = parse_indicator(IOC_IP, feed_tags=["ThreatMon"], tlp_color="GREEN")

    assert indicator["value"] == "1.2.3.4"
    assert indicator["type"] == "IP"
    assert indicator["service"] == "ThreatMon"
    assert indicator["rawJSON"] == IOC_IP


def test_parse_indicator_builds_fields_and_tags():
    """
    Given: An IOC containing metadata, tags, categories and source.
    When: Parsing it into an XSOAR indicator.
    Then: The tags are merged without duplicates and the metadata is mapped to indicator fields.
    """
    indicator = parse_indicator(IOC_IP, feed_tags=["ThreatMon", "c2"], tlp_color="AMBER")
    fields = indicator["fields"]

    assert fields["tags"] == ["c2", "malware", "ThreatmonIntel", "ThreatMon"]
    assert fields["confidence"] == 90
    assert fields["threatseverity"] == "high"
    assert fields["isp"] == "Example ISP"
    assert fields["geolocation"] == "TR"
    assert fields["trafficlightprotocol"] == "AMBER"
    assert "Severity: high" in fields["description"]
    assert "API Score: 95" in fields["description"]


def test_parse_indicator_without_tlp_color():
    """
    Given: An IOC and an empty TLP color.
    When: Parsing it into an XSOAR indicator.
    Then: The trafficlightprotocol field is not set.
    """
    indicator = parse_indicator(IOC_DOMAIN, feed_tags=[], tlp_color="")

    assert indicator["value"] == "malicious.example.com"
    assert indicator["type"] == "Domain"
    assert "trafficlightprotocol" not in indicator["fields"]


def test_parse_indicator_skips_untyped_and_valueless():
    """
    Given: An IOC that has no value, or an unrecognized type.
    When: Parsing it into an XSOAR indicator.
    Then: None is returned so the caller can skip it, instead of raising.
    """
    assert parse_indicator({"ioc_type": "ip"}, feed_tags=[], tlp_color=None) is None
    assert parse_indicator({"ioc_value": "something", "ioc_type": "unknown-type"}, feed_tags=[], tlp_color=None) is None


@pytest.mark.parametrize(
    "reputation, expected",
    [
        ("None", 0),
        ("Good", 1),
        ("Suspicious", 2),
        ("Bad", 3),
        ("Malicious", 3),
        ("Unrecognized value", 3),
    ],
)
def test_calculate_verdict(reputation, expected):
    """
    Given: A feedReputation configuration value.
    When: Calculating the DBot score for the fetched indicators.
    Then: The matching DBot score is returned, defaulting to Bad (3).
    """
    assert calculate_verdict(reputation) == expected


def test_run_test_module_success():
    """
    Given: An API that responds successfully.
    When: Running the test-module command.
    Then: 'ok' is returned and only a single IOC is requested.
    """
    client = MockClient(response={"iocs": [IOC_IP]})

    assert run_test_module(client, {"data_type": "ip"}) == "ok"
    assert client.calls == [{"data_type": "ip", "size": 1, "collection_ids": None}]


def test_run_test_module_failure():
    """
    Given: An API that raises an error.
    When: Running the test-module command.
    Then: A descriptive failure message is returned instead of raising.
    """
    client = MockClient(exception=Exception("Unauthorized"))

    assert run_test_module(client, {}) == "Test failed: Unauthorized"


def test_build_indicators_applies_feed_tags():
    """
    Given: A feedTags parameter configured by the user.
    When: Building indicators.
    Then: The user tags are applied to the indicators alongside the ThreatMon source tag.
    """
    client = MockClient(response={"iocs": [IOC_DOMAIN]})

    indicators, _ = build_indicators(client, {"feedTags": "internal,priority"}, limit=100)

    assert indicators[0]["fields"]["tags"] == ["ThreatMon", "internal", "priority"]


def test_fetch_indicators_first_run():
    """
    Given: An empty last run and an API returning two IOCs.
    When: Fetching indicators.
    Then: Both IOCs are returned, scored, and the newest timestamp is stored in the last run.
    """
    client = MockClient(response={"iocs": [IOC_IP, IOC_DOMAIN]})
    params = {"data_type": "all", "tlp_color": "RED", "feedReputation": "Bad", "collection_ids": "abc,def"}

    indicators, last_run = fetch_indicators_command(client, params, limit=100, last_run={})

    assert len(indicators) == 2
    assert {indicator["value"] for indicator in indicators} == {"1.2.3.4", "malicious.example.com"}
    assert all(indicator["score"] == 3 for indicator in indicators)
    assert last_run == {"last_timestamp": "2026-01-03T00:00:00Z"}
    assert client.calls == [{"data_type": "all", "size": 100, "collection_ids": "abc,def"}]


def test_fetch_indicators_skips_already_fetched():
    """
    Given: A last run holding a timestamp newer than one of the returned IOCs.
    When: Fetching indicators.
    Then: The already fetched IOC is skipped and only the newer one is returned.
    """
    client = MockClient(response={"iocs": [IOC_IP, IOC_DOMAIN]})

    indicators, last_run = fetch_indicators_command(client, {}, limit=500, last_run={"last_timestamp": "2026-01-02T00:00:00Z"})

    assert len(indicators) == 1
    assert indicators[0]["value"] == "malicious.example.com"
    assert last_run == {"last_timestamp": "2026-01-03T00:00:00Z"}


def test_fetch_indicators_empty_response():
    """
    Given: An API returning no IOCs.
    When: Fetching indicators.
    Then: No indicators are returned and the previous last run is preserved.
    """
    client = MockClient(response={"iocs": []})

    indicators, last_run = fetch_indicators_command(client, {}, limit=500, last_run={"last_timestamp": "2026-01-02T00:00:00Z"})

    assert indicators == []
    assert last_run == {"last_timestamp": "2026-01-02T00:00:00Z"}


def test_fetch_indicators_raises_on_api_error(capfd):
    """
    Given: An API that raises an error.
    When: Fetching indicators.
    Then: The error is propagated so the fetch run is marked as failed.
    """
    client = MockClient(exception=Exception("Connection error"))

    with capfd.disabled(), pytest.raises(Exception, match="Connection error"):
        fetch_indicators_command(client, {}, limit=500, last_run={})


def test_get_indicators_command_returns_table():
    """
    Given: An API returning IOCs.
    When: Running the get-indicators command with a limit.
    Then: A CommandResults with a markdown table and the raw response is returned, limited in size.
    """
    client = MockClient(response={"iocs": [IOC_IP, IOC_DOMAIN]})

    result = get_indicators_command(client, {}, {"limit": "1"})

    assert "Indicators from ThreatMon" in result.readable_output
    assert len(result.raw_response) == 1


def test_get_indicators_command_no_results():
    """
    Given: An API returning no IOCs.
    When: Running the get-indicators command.
    Then: A friendly "no indicators" message is returned.
    """
    client = MockClient(response={"iocs": []})

    result = get_indicators_command(client, {}, {})

    assert "No indicators were found" in result.readable_output
