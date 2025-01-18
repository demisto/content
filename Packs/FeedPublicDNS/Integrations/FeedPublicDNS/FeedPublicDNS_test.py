import pytest

from FeedPublicDNS import Client, fetch_indicators_command


@pytest.mark.parametrize('enrichment_excluded', [True, False])
def test_fetch_indicators_command(requests_mock, enrichment_excluded):
    """
    Given:
    When:
    Then:
    """
    expected = [
        {
            'value': '192.168.0.1',
            'type': 'IP',
            'rawJSON': {
                'value': '192.168.0.1',
                'type': 'IP'
            },
            'fields': {
                'tags': ['test'],
                'trafficlightprotocol': 'test color'
            }
        },
        {
            'value': '10.0.0.1',
            'type': 'IP',
            'rawJSON': {
                'value': '10.0.0.1',
                'type': 'IP'
            },
            'fields': {
                'tags': ['test'],
                'trafficlightprotocol': 'test color'
            }
        }
    ]
    if enrichment_excluded:
        for ind in expected:
            ind['enrichmentExcluded'] = True

    url = 'https://public-dns.info/nameservers-all.txt'
    mock_response = '192.168.0.1\n10.0.0.1'
    requests_mock.get(url, text=mock_response)

    client = Client(url, tags=['test'], tlp_color='test color')

    indicators = fetch_indicators_command(client, enrichment_excluded=enrichment_excluded)

    assert indicators == expected
