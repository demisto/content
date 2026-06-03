import json

import pytest
from CommonServerPython import CommandResults, DemistoException, FeedIndicatorType

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
MOCK_COLLECTION_UUID = "abcd1234-ef56-7890-abcd-ef1234567890"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_test_module(requests_mock):
    """Tests the test_module validation command."""
    from FeedSOCRadarThreatFeed import Client, test_module

    mock_socradar_api_key = "APIKey"

    # Mock auth check
    auth_suffix = f"threat/intelligence/check/auth?key={mock_socradar_api_key}"
    mock_auth_response = util_load_json("test_data/check_auth_response.json")
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{auth_suffix}", json=mock_auth_response)

    # Mock feed list endpoint
    feed_suffix = f"threat/intelligence/feed_list/{MOCK_COLLECTION_UUID}.json?key={mock_socradar_api_key}&v=2"
    mock_feed_response = util_load_json("test_data/feed_list_response.json")
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{feed_suffix}", json=mock_feed_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="",
        tags="",
        verify=False,
        proxy=False,
    )

    response = test_module(client, [MOCK_COLLECTION_UUID])

    assert response == "ok"


def test_test_module_handles_authorization_error(requests_mock):
    """Tests the test_module validation command authorization error."""
    from FeedSOCRadarThreatFeed import MESSAGES, Client, test_module

    mock_socradar_api_key = "WrongAPIKey"
    suffix = f"threat/intelligence/check/auth?key={mock_socradar_api_key}"
    mock_response = util_load_json("test_data/check_auth_response_auth_error.json")
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response, status_code=401)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="",
        tags="",
        verify=False,
        proxy=False,
    )
    with pytest.raises(DemistoException, match=MESSAGES["AUTHORIZATION_ERROR"]):
        test_module(client, [])


def test_fetch_indicators(requests_mock):
    """Tests the fetch_indicators function with the new UUID-based API."""
    from FeedSOCRadarThreatFeed import Client, fetch_indicators

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json("test_data/feed_list_response.json")
    feed_suffix = f"threat/intelligence/feed_list/{MOCK_COLLECTION_UUID}.json?key={mock_socradar_api_key}&v=2"
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{feed_suffix}", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False,
    )

    indicators = fetch_indicators(client=client, collection_uuids=[MOCK_COLLECTION_UUID], limit=1)

    expected_output = util_load_json("test_data/fetch_indicators_expected_output.json")

    assert indicators == expected_output
    assert len(indicators) == 1


def test_fetch_indicators_handles_error(requests_mock):
    """Tests the fetch_indicators function when API returns an error."""
    from FeedSOCRadarThreatFeed import Client, fetch_indicators

    mock_socradar_api_key = "APIKey"
    feed_suffix = f"threat/intelligence/feed_list/{MOCK_COLLECTION_UUID}.json?key={mock_socradar_api_key}&v=2"
    requests_mock.get(
        f"{SOCRADAR_API_ENDPOINT}/{feed_suffix}",
        json={"error": "Not Found"},
        status_code=404,
    )

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False,
    )

    indicators = fetch_indicators(client=client, collection_uuids=[MOCK_COLLECTION_UUID], limit=1)
    assert len(indicators) == 0


def test_fetch_indicators_multiple_uuids(requests_mock):
    """Tests fetching indicators from multiple collection UUIDs."""
    from FeedSOCRadarThreatFeed import Client, fetch_indicators

    mock_socradar_api_key = "APIKey"
    uuid1 = "uuid-1111-1111-1111-111111111111"
    uuid2 = "uuid-2222-2222-2222-222222222222"
    mock_response = util_load_json("test_data/feed_list_response.json")

    feed_suffix1 = f"threat/intelligence/feed_list/{uuid1}.json?key={mock_socradar_api_key}&v=2"
    feed_suffix2 = f"threat/intelligence/feed_list/{uuid2}.json?key={mock_socradar_api_key}&v=2"
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{feed_suffix1}", json=mock_response)
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{feed_suffix2}", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False,
    )

    indicators = fetch_indicators(client=client, collection_uuids=[uuid1, uuid2])

    # 3 indicators per collection, 2 collections = 6 total
    assert len(indicators) == 6


def test_fetch_indicators_multiple_uuids_with_limit(requests_mock):
    """Tests fetching indicators from multiple UUIDs respects global limit."""
    from FeedSOCRadarThreatFeed import Client, fetch_indicators

    mock_socradar_api_key = "APIKey"
    uuid1 = "uuid-1111-1111-1111-111111111111"
    uuid2 = "uuid-2222-2222-2222-222222222222"
    mock_response = util_load_json("test_data/feed_list_response.json")

    feed_suffix1 = f"threat/intelligence/feed_list/{uuid1}.json?key={mock_socradar_api_key}&v=2"
    feed_suffix2 = f"threat/intelligence/feed_list/{uuid2}.json?key={mock_socradar_api_key}&v=2"
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{feed_suffix1}", json=mock_response)
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{feed_suffix2}", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False,
    )

    indicators = fetch_indicators(client=client, collection_uuids=[uuid1, uuid2], limit=4)

    assert len(indicators) == 4


def test_get_indicators_command(requests_mock):
    """Tests the get_indicators_command function."""
    from FeedSOCRadarThreatFeed import Client, get_indicators_command

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json("test_data/feed_list_response.json")
    feed_suffix = f"threat/intelligence/feed_list/{MOCK_COLLECTION_UUID}.json?key={mock_socradar_api_key}&v=2"
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{feed_suffix}", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False,
    )

    mock_args = {"limit": 1, "collection_uuids": MOCK_COLLECTION_UUID}

    result = get_indicators_command(client, mock_args)

    expected_context = util_load_json("test_data/get_indicators_expected_context.json")

    assert isinstance(result, CommandResults)
    assert f"Indicators from SOCRadar Collection Based IOC Feed ({MOCK_COLLECTION_UUID}):" in result.readable_output
    assert result.outputs == expected_context


def test_get_indicators_command_handles_error(requests_mock):
    """Tests the get_indicators_command function when API returns an error."""
    from FeedSOCRadarThreatFeed import Client, get_indicators_command

    mock_socradar_api_key = "APIKey"
    feed_suffix = f"threat/intelligence/feed_list/{MOCK_COLLECTION_UUID}.json?key={mock_socradar_api_key}&v=2"
    requests_mock.get(
        f"{SOCRADAR_API_ENDPOINT}/{feed_suffix}",
        json={"error": "Not Found"},
        status_code=404,
    )

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False,
    )
    mock_args = {"limit": 1, "collection_uuids": MOCK_COLLECTION_UUID}
    result = get_indicators_command(client, mock_args)
    assert isinstance(result, CommandResults)
    assert len(result.outputs) == 0


def test_date_string_to_iso_format_parsing():
    """Tests the date_string_to_iso_format_parsing function."""
    from FeedSOCRadarThreatFeed import date_string_to_iso_format_parsing

    mock_date_str = "2025-04-10 19:52:57"
    formatted_date = date_string_to_iso_format_parsing(mock_date_str)

    assert formatted_date == "2025-04-10T19:52:57Z"


def test_build_entry_context():
    """Tests the build_entry_context function."""
    from FeedSOCRadarThreatFeed import build_entry_context

    mock_indicators = util_load_json("test_data/build_entry_context_input.json")
    context_entry = build_entry_context(mock_indicators)
    expected_context_entry = util_load_json("test_data/build_entry_context_expected_entry.json")

    assert context_entry == expected_context_entry


def test_reset_last_fetch_dict():
    """Tests the reset_last_fetch_dict function."""
    from FeedSOCRadarThreatFeed import reset_last_fetch_dict

    result = reset_last_fetch_dict()

    assert isinstance(result, CommandResults)
    assert "Fetch history has been successfully deleted!" in result.readable_output


CONVERT_DEMISTO_INDICATOR_TYPE_INPUTS = [
    ("hostname", FeedIndicatorType.Domain),
    ("domain", FeedIndicatorType.Domain),
    ("url", FeedIndicatorType.URL),
    ("ip", FeedIndicatorType.IP),
    ("hash", FeedIndicatorType.File),
]


@pytest.mark.parametrize(
    "socradar_indicator_type, demisto_indicator_type",
    CONVERT_DEMISTO_INDICATOR_TYPE_INPUTS,
)
def test_convert_to_demisto_indicator_type(socradar_indicator_type, demisto_indicator_type):
    from FeedSOCRadarThreatFeed import convert_to_demisto_indicator_type

    assert convert_to_demisto_indicator_type(socradar_indicator_type) == demisto_indicator_type


def test_parse_raw_indicators():
    """Tests the parse_raw_indicators method of the Client class."""
    from FeedSOCRadarThreatFeed import Client

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key="APIKey",
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False,
    )

    raw_indicators = util_load_json("test_data/feed_list_response.json")
    parsed = client.parse_raw_indicators(raw_indicators)

    assert len(parsed) == 3
    assert parsed[0]["value"] == "a5593da0e43c4879fc8c5eb7f92fbafa96d698a2"
    assert parsed[0]["type"] == FeedIndicatorType.File
    assert parsed[1]["value"] == "192.168.1.100"
    assert parsed[1]["type"] == FeedIndicatorType.IP
    assert parsed[2]["value"] == "malicious-domain.example.com"
    assert parsed[2]["type"] == FeedIndicatorType.Domain
    # Verify tags and TLP are set
    assert parsed[0]["fields"]["tags"] == ["TEST"]
    assert parsed[0]["fields"]["trafficlightprotocol"] == "GREEN"


def test_parse_raw_indicators_empty():
    """Tests parse_raw_indicators with empty input."""
    from FeedSOCRadarThreatFeed import Client

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key="APIKey",
        tlp_color="",
        tags="",
        verify=False,
        proxy=False,
    )

    parsed = client.parse_raw_indicators([])
    assert len(parsed) == 0

    parsed = client.parse_raw_indicators([None, {}, None])
    assert len(parsed) == 0
