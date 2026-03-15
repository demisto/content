import pytest
from CommonServerPython import FeedIndicatorType
from FeedProofpoint import Client, fetch_indicators_command, get_indicators_command

url = "https://example.com"
auth_code = "cool"
client = Client(url, auth_code)


def test_fetch_ips(requests_mock):
    ip_path = "./TestData/detailed-iprep.txt"
    with open(ip_path) as f:
        data = f.read()
    requests_mock.get("https://example.com/cool/reputation/detailed-iprepdata.txt", text=data)
    indicators = fetch_indicators_command(client, client.IP_TYPE)
    assert len(indicators) == 4


def test_fetch_domains(requests_mock):
    ip_path = "./TestData/detalied-domainrepdata.txt"
    with open(ip_path) as f:
        data = f.read()
    requests_mock.get("https://example.com/cool/reputation/detailed-domainrepdata.txt", text=data)
    indicators = fetch_indicators_command(client, client.DOMAIN_TYPE)
    assert len(indicators) == 12
    # making sure all domains are not of type domain glob
    domains = [ind for ind in indicators if ind.get("type") == FeedIndicatorType.Domain]
    domain_globs = [ind for ind in indicators if ind.get("type") == FeedIndicatorType.DomainGlob]
    assert len(domains) == 9
    assert len(domain_globs) == 3
    assert any("*" not in ind.get("value") for ind in domains)
    assert all("*" in ind.get("value") for ind in domain_globs)


def test_fetch_domains_with_invalid_category(requests_mock):
    """
    Given:
    - A domain feed with invalid (non-numeric) category values
    When:
    - Executing fetch_indicators_command
    Then:
    - Validate that the function handles invalid category values gracefully
    - Verify that indicators with invalid categories have "Unknown" as category_name
    """
    test_path = "./TestData/domain-with-invalid-category.txt"
    with open(test_path) as f:
        data = f.read()
    requests_mock.get("https://example.com/cool/reputation/detailed-domainrepdata.txt", text=data)
    indicators = fetch_indicators_command(client, client.DOMAIN_TYPE)

    # Verify we got all indicators including those with invalid categories
    assert len(indicators) == 5

    # Test case 1: Non-numeric category (domain name)
    invalid_category_indicator = next((ind for ind in indicators if ind.get("value") == "malicious.com"), None)
    assert invalid_category_indicator is not None
    assert invalid_category_indicator["rawJSON"]["category_name"] == "Unknown"

    # Test case 2: Out of bounds category index
    out_of_bounds_indicator = next((ind for ind in indicators if ind.get("value") == "outofbounds.com"), None)
    assert out_of_bounds_indicator is not None
    assert out_of_bounds_indicator["rawJSON"]["category_name"] == "Unknown"

    # Test case 3: Empty category
    empty_category_indicator = next((ind for ind in indicators if ind.get("value") == "empty-category.com"), None)
    assert empty_category_indicator is not None
    assert empty_category_indicator["rawJSON"]["category_name"] == "Unknown"


@pytest.mark.parametrize("tags", (["tag1, tag2"], []))
def test_feed_param(tags, requests_mock):
    """
    Given:
    - tags parameters
    When:
    - Executing any command on feed
    Then:
    - Validate the tags supplied exists in the indicators
    """
    client._tags = tags
    ip_path = "./TestData/detailed-iprep.txt"
    with open(ip_path) as f:
        data = f.read()
    requests_mock.get("https://example.com/cool/reputation/detailed-iprepdata.txt", text=data)
    indicators = fetch_indicators_command(client, client.IP_TYPE)
    assert tags == indicators[0]["fields"]["tags"]


def test_get_indicators_command(mocker):
    """
    Given:
    - tags parameters
    When:
    - Executing get_indicators_command
    Then:
    - Validate that the function returns expected markdown table,
        empty dictionary as context, and list of fetched indicators
        for a valid indicator type and limit value.
    """
    mocker.patch.object(
        client, "get_indicators", return_value=[{"type": "domain", "value": "example.com"}, {"type": "ip", "value": "1.2.3.4"}]
    )
    args = {"indicator_type": "all", "limit": "2"}
    expected_hr = "### Indicators from Proofpoint Feed\n|type|value|\n|---|---|\n| domain | example.com |\n| ip | 1.2.3.4 |\n"
    expected_indicators = [{"type": "domain", "value": "example.com"}, {"type": "ip", "value": "1.2.3.4"}]
    hr, context, indicators = get_indicators_command(client, args)
    assert hr == expected_hr
    assert context == {}
    assert indicators == expected_indicators
