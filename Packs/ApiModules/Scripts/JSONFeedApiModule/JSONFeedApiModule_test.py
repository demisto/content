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
            fields=['region', 'service'],
            insecure=True
        )

        indicators = fetch_indicators_command(client=client, indicator_type='CIDR', feedTags=['test'],
                                              auto_detect=False)
        assert len(jmespath.search(expression="[].rawJSON.service", data=indicators)) == 1117


def test_json_feed_with_config():
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    feed_name_to_config = {
        'AMAZON': {
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'extractor': "prefixes[?service=='AMAZON']",
            'indicator': 'ip_prefix',
            'indicator_type': FeedIndicatorType.CIDR,
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

        indicators = fetch_indicators_command(client=client, indicator_type='CIDR', feedTags=['test'],
                                              auto_detect=False)
        assert len(jmespath.search(expression="[].rawJSON.service", data=indicators)) == 1117


def test_json_feed_with_config_mapping():
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    feed_name_to_config = {
        'AMAZON': {
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'extractor': "prefixes[?service=='AMAZON']",
            'indicator': 'ip_prefix',
            'indicator_type': FeedIndicatorType.CIDR,
            'fields': ['region', 'service'],
            'mapping': {
                'region': 'Region'
            }
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

        indicators = fetch_indicators_command(client=client, indicator_type='CIDR', feedTags=['test'],
                                              auto_detect=False)
        assert len(jmespath.search(expression="[].rawJSON.service", data=indicators)) == 1117
        indicator = indicators[0]
        custom_fields = indicator['fields']
        assert 'Region' in custom_fields
        assert 'region' in indicator['rawJSON']


FLAT_LIST_OF_INDICATORS = '''{
    "hooks": [
    "1.1.1.1",
    "2.2.2.2",
    "3.3.3.3"
    ]
}'''


def test_list_of_indicators_with_no_json_object():
    feed_name_to_config = {
        'Github': {
            'url': 'https://api.github.com/meta',
            'extractor': "hooks",
            'indicator': None
        }
    }

    with requests_mock.Mocker() as m:
        m.get('https://api.github.com/meta', json=json.loads(FLAT_LIST_OF_INDICATORS))

        client = Client(
            url='https://api.github.com/meta',
            feed_name_to_config=feed_name_to_config,
            insecure=True
        )

        indicators = fetch_indicators_command(client=client, indicator_type=None, feedTags=['test'], auto_detect=True)
        assert len(indicators) == 3
        assert indicators[0].get('value') == '1.1.1.1'
        assert indicators[0].get('type') == 'IP'
        assert indicators[1].get('rawJSON') == {'indicator': '2.2.2.2'}
