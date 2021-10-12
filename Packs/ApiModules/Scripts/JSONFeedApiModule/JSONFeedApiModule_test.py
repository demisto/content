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


def test_get_no_update_value(mocker):
    """
    Given
    - valid response with last_modified and etag headers.

    When
    - Running get_no_update_value method.

    Then
    - Ensure that the response is False
    """
    mocker.patch.object(demisto, 'debug')

    class MockResponse:
        headers = {'Last-Modified': 'Fri, 30 Jul 2021 00:24:13 GMT',  # guardrails-disable-line
                   'ETag': 'd309ab6e51ed310cf869dab0dfd0d34b'}  # guardrails-disable-line
        status_code = 200
    no_update = get_no_update_value(MockResponse())
    assert not no_update
    assert demisto.debug.call_args[0][0] == 'New indicators fetched - the Last-Modified value has been updated,' \
                                            ' createIndicators will be executed with noUpdate=False.'


def test_build_iterator_not_modified_header(mocker):
    """
    Given
    - response with status code 304(Not Modified)

    When
    - Running build_iterator method.

    Then
    - Ensure that the no_update value is True
    """
    mocker.patch.object(demisto, 'debug')
    with requests_mock.Mocker() as m:
        m.get('https://api.github.com/meta', status_code=304)

        client = Client(
            url='https://api.github.com/meta'
        )
        result, no_update = client.build_iterator(feed={'url': 'https://api.github.com/meta'})
        assert not result
        assert no_update
        assert demisto.debug.call_args[0][0] == 'No new indicators fetched, ' \
                                                'createIndicators will be executed with noUpdate=True.'


def test_get_no_update_value_without_headers(mocker):
    """
    Given
    - response without last_modified and etag headers.

    When
    - Running get_no_update_value.

    Then
    - Ensure that the response is False.
    """
    mocker.patch.object(demisto, 'debug')

    class MockResponse:
        headers = {}
        status_code = 200
    no_update = get_no_update_value(MockResponse())
    assert not no_update
    assert demisto.debug.call_args[0][0] == 'Last-Modified and Etag headers are not exists,' \
                                            'createIndicators will be executed with noUpdate=False.'
