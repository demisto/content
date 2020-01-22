from JSONFeedApiModule import Client, fetch_indicators_command, jmespath
from CommonServerPython import *
import requests_mock


def test_json_feed_no_config():
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    with requests_mock.Mocker() as m:
        m.get('https://ip-ranges.amazonaws.com/ip-ranges.json', json=ip_ranges)

        client = Client(
            url='https://ip-ranges.amazonaws.com/ip-ranges.json',
            credentials={'username': 'test', 'password': 'test'},
            extractor="prefixes[?service=='AMAZON']",
            indicator='ip_prefix',
            fields=['ipv6_prefix', 'region', 'service'],
            insecure=True
        )

        indicators = fetch_indicators_command(client=client, indicator_type='ip')
        assert len(jmespath.search(expression="[].rawJSON.service", data=indicators)) == 1117


def test_json_feed_with_config():
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    feed_name_to_config = {
        'AMAZON': {
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'extractor': "prefixes[?service=='AMAZON']",
            'indicator': 'ip_prefix',
            'indicator_type': FeedIndicatorType.IP,
            'fields': ['region', 'service']
        }
    }

    with requests_mock.Mocker() as m:
        m.get('https://ip-ranges.amazonaws.com/ip-ranges.json', json=ip_ranges)

        client = Client(
            url='https://ip-ranges.amazonaws.com/ip-ranges.json',
            credentials={'username': 'test', 'password': 'test'},
            feed_name_to_config=feed_name_to_config,
            insecure=True
        )

        indicators = fetch_indicators_command(client=client, indicator_type='ip')
        assert len(jmespath.search(expression="[].rawJSON.service", data=indicators)) == 1117
