import json
from FeedJSON import *


def test_amazon_ip_feed(requests_mock):
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    # mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    # requests_mock.get('https://ip-ranges.amazonaws.com/ip-ranges.json', json=ip_ranges)
    with requests_mock.Mocker() as m:
        m.get('https://ip-ranges.amazonaws.com/ip-ranges.json', json=ip_ranges)

        client = Client(
            url='https://ip-ranges.amazonaws.com/ip-ranges.json',
            credentials={},
            extractor="prefixes[?service=='AMAZON']",
            indicator='indicator',
            source_name='json',
            fields=['ipv6_prefix', 'region', 'service'],
            insecure=True
        )

        indicators = fetch_indicators_command(client=client, indicator_type='ip')
        assert indicators is not None
