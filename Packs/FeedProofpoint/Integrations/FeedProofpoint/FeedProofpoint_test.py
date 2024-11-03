import pytest
from FeedProofpoint import Client, fetch_indicators_command, get_indicators_command
from CommonServerPython import FeedIndicatorType

url = "https://example.com"
auth_code = "cool"
client = Client(url, auth_code)


def test_fetch_ips(requests_mock):
    ip_path = "./TestData/detailed-iprep.txt"
    with open(ip_path) as f:
        data = f.read()
    requests_mock.get(
        "https://example.com/cool/reputation/detailed-iprepdata.txt", text=data
    )
    indicators = fetch_indicators_command(client, client.IP_TYPE)
    assert len(indicators) == 4


def test_fetch_domains(requests_mock):
    ip_path = "./TestData/detalied-domainrepdata.txt"
    with open(ip_path) as f:
        data = f.read()
    requests_mock.get(
        "https://example.com/cool/reputation/detailed-domainrepdata.txt", text=data
    )
    indicators = fetch_indicators_command(client, client.DOMAIN_TYPE)
    assert len(indicators) == 12
    # making sure all domains are not of type domain glob
    domains = [ind for ind in indicators if ind.get('type') == FeedIndicatorType.Domain]
    domain_globs = [ind for ind in indicators if ind.get('type') == FeedIndicatorType.DomainGlob]
    assert len(domains) == 9
    assert len(domain_globs) == 3
    assert all(['*' not in ind.get('value') for ind in domains])
    assert all(['*' in ind.get('value') for ind in domain_globs])


@pytest.mark.parametrize('tags', (['tag1, tag2'], []))
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
    requests_mock.get(
        "https://example.com/cool/reputation/detailed-iprepdata.txt", text=data
    )
    indicators = fetch_indicators_command(client, client.IP_TYPE)
    assert tags == indicators[0]['fields']['tags']


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
    mocker.patch.object(client, "get_indicators", return_value=[
        {"type": "domain", "value": "example.com"},
        {"type": "ip", "value": "1.2.3.4"}
    ])
    args = {"indicator_type": "all", "limit": "2"}
    expected_hr = '### Indicators from Proofpoint Feed\n|type|value|\n|---|---|\n| domain | example.com |\n| ip | 1.2.3.4 |\n'
    expected_indicators = [
        {"type": "domain", "value": "example.com"},
        {"type": "ip", "value": "1.2.3.4"}
    ]
    hr, context, indicators = get_indicators_command(client, args)
    assert hr == expected_hr
    assert context == {}
    assert indicators == expected_indicators
