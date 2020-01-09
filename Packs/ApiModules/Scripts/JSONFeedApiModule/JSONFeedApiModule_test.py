import json
from JSONFeedApiModule import *
import requests_mock


def test_json_feed():
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    with requests_mock.Mocker() as m:
        m.get('https://ip-ranges.amazonaws.com/ip-ranges.json', json=ip_ranges)

        client = Client(
            url='https://ip-ranges.amazonaws.com/ip-ranges.json',
            credentials={'username': 'test', 'password': 'test'},
            extractors=["prefixes[?service=='AMAZON']"],
            indicator='ip_prefix',
            fields=['ipv6_prefix', 'region', 'service'],
            insecure=True
        )

        indicators = fetch_indicators_command(client=client, indicator_type='ip')
        assert len(jmespath.search(expression="[].rawJSON.service", data=indicators)) == 1117
