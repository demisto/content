from JSONFeedApiModule import Client, fetch_indicators_command, jmespath, get_no_update_value
from CommonServerPython import *
import requests_mock
import demistomock as demisto


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

        indicators, _ = fetch_indicators_command(client=client, indicator_type='CIDR', feedTags=['test'],
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

        indicators, _ = fetch_indicators_command(client=client, indicator_type='CIDR', feedTags=['test'],
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

        indicators, _ = fetch_indicators_command(client=client, indicator_type='CIDR', feedTags=['test'],
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

        indicators, _ = fetch_indicators_command(client=client, indicator_type=None, feedTags=['test'],
                                                 auto_detect=True)
        assert len(indicators) == 3
        assert indicators[0].get('value') == '1.1.1.1'
        assert indicators[0].get('type') == 'IP'
        assert indicators[1].get('rawJSON') == {'indicator': '2.2.2.2'}


def test_post_of_indicators_with_no_json_object():
    feed_name_to_config = {
        'Github': {
            'url': 'https://api.github.com/meta',
            'extractor': "hooks",
            'indicator': None
        }
    }

    with requests_mock.Mocker() as m:
        matcher = m.post('https://api.github.com/meta', json=json.loads(FLAT_LIST_OF_INDICATORS),
                         request_headers={'content-type': 'application/x-www-form-urlencoded'})

        client = Client(
            url='https://api.github.com/meta',
            feed_name_to_config=feed_name_to_config,
            insecure=True, data='test=1'
        )

        indicators, _ = fetch_indicators_command(client=client, indicator_type=None, feedTags=['test'], auto_detect=True)
        assert matcher.last_request.text == 'test=1'
        assert len(indicators) == 3
        assert indicators[0].get('value') == '1.1.1.1'
        assert indicators[0].get('type') == 'IP'
        assert indicators[1].get('rawJSON') == {'indicator': '2.2.2.2'}


def test_parse_headers():
    headers = """Authorization: Bearer X
User-Agent:test

Stam : Ba
"""
    res = Client.parse_headers(headers)
    assert res['Authorization'] == 'Bearer X'
    assert res['User-Agent'] == 'test'
    assert res['Stam'] == 'Ba'
    assert len(res) == 3


def test_get_no_update_value_empty_context():
    """
    Given
    - response with last_modified and etag headers.

    When
    - Running get_no_update_value method with empty integration context.

    Then
    - Ensure that the response is True.
    """
    class MockResponse:
        headers = {'last_modified': 'Fri, 30 Jul 2021 00:24:13 GMT',  # guardrails-disable-line
                   'etag': 'd309ab6e51ed310cf869dab0dfd0d34b'}  # guardrails-disable-line
    no_update = get_no_update_value(MockResponse())
    assert no_update


def test_get_no_update_value(mocker):
    """
    Given
    - response with last_modified and etag headers with the same values like in the integration context.

    When
    - Running get_no_update_value method.

    Then
    - Ensure that the response is False
    """
    mocker.patch.object(demisto, 'getIntegrationContext',
                        return_value={'last_modified': 'Fri, 30 Jul 2021 00:24:13 GMT',  # guardrails-disable-line
                                      'etag': 'd309ab6e51ed310cf869dab0dfd0d34b'})  # guardrails-disable-line

    class MockResponse:
        headers = {'last_modified': 'Fri, 30 Jul 2021 00:24:13 GMT',  # guardrails-disable-line
                   'etag': 'd309ab6e51ed310cf869dab0dfd0d34b'}  # guardrails-disable-line
    no_update = get_no_update_value(MockResponse())
    assert not no_update
