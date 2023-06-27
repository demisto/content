from JSONFeedApiModule import Client, fetch_indicators_command, jmespath, get_no_update_value
from CommonServerPython import *
import pytest
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


CONFIG_PARAMETERS = [
    (
        {
            'AMAZON$$CIDR': {
                'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
                'extractor': "prefixes[?service=='AMAZON']",
                'indicator': 'ip_prefix',
                'indicator_type': FeedIndicatorType.CIDR,
                'fields': ['region', 'service']
            }
        },
        1117,
        0
    ),
    (
        {
            'AMAZON$$CIDR': {
                'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
                'extractor': "prefixes[?service=='AMAZON']",
                'indicator': 'ip_prefix',
                'indicator_type': FeedIndicatorType.CIDR,
                'fields': ['region', 'service']
            },
            'AMAZON$$IPV6': {
                'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
                'extractor': "ipv6_prefixes[?service=='AMAZON']",
                'indicator': 'ipv6_prefix',
                'indicator_type': FeedIndicatorType.IPv6,
                'fields': ['region', 'service']
            },
            'CLOUDFRONT': {
                'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
                'extractor': "prefixes[?service=='CLOUDFRONT']",
                'indicator': 'ip_prefix',
                'indicator_type': FeedIndicatorType.CIDR,
                'fields': ['region', 'service']
            }
        },
        1465,
        36
    )
]


@pytest.mark.parametrize('config, total_indicators, indicator_with_several_tags', CONFIG_PARAMETERS)
def test_json_feed_with_config(config, total_indicators, indicator_with_several_tags):
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    with requests_mock.Mocker() as m:
        m.get('https://ip-ranges.amazonaws.com/ip-ranges.json', json=ip_ranges)

        client = Client(
            url='https://ip-ranges.amazonaws.com/ip-ranges.json',
            credentials={'username': 'test', 'password': 'test'},
            feed_name_to_config=config,
            insecure=True
        )

        indicators, _ = fetch_indicators_command(client=client, indicator_type='CIDR', feedTags=['test'],
                                                 auto_detect=False)
        assert len(jmespath.search(expression="[].rawJSON.service", data=indicators)) == total_indicators
        assert len([i for i in indicators if ',' in i.get('rawJSON').get('service', '')]) == indicator_with_several_tags


def test_json_feed_with_config_mapping():
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    feed_name_to_config = {
        'AMAZON$$CIDR': {
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
    - Ensure that the last run is saved as expected
    """
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'setLastRun')

    expected_last_run = {
        'lastRun': '2018-10-24T14:13:20+00:00',
        'feed_name': {
            'last_modified': 'Fri, 30 Jul 2021 00:24:13 GMT',
            'etag': 'd309ab6e51ed310cf869dab0dfd0d34b'}
    }

    class MockResponse:
        headers = {'Last-Modified': 'Fri, 30 Jul 2021 00:24:13 GMT',  # guardrails-disable-line
                   'ETag': 'd309ab6e51ed310cf869dab0dfd0d34b'}  # guardrails-disable-line
        status_code = 200
    no_update = get_no_update_value(MockResponse(), 'feed_name')
    assert not no_update
    assert demisto.debug.call_args[0][0] == 'New indicators fetched - the Last-Modified value has been updated,' \
                                            ' createIndicators will be executed with noUpdate=False.'
    assert demisto.setLastRun.call_args[0][0] == expected_last_run


def test_build_iterator_not_modified_header(mocker):
    """
    Given
    - Last run has etag and last_modified in it
    - response with status code 304(Not Modified)

    When
    - Running build_iterator method.

    Then
    - Ensure that the no_update value is True
    - Request is called with the headers "If-None-Match" and "If-Modified-Since"
    """
    feed_name = 'mock_feed_name'
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'getLastRun', return_value={feed_name: {'etag': '0', 'last_modified': 'now'}})
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.5.0"})

    with requests_mock.Mocker() as m:
        m.get('https://api.github.com/meta', status_code=304)

        client = Client(
            url='https://api.github.com/meta'
        )
        result, no_update = client.build_iterator(feed={'url': 'https://api.github.com/meta'}, feed_name=feed_name)
        assert not result
        assert no_update
        assert demisto.debug.call_args[0][0] == 'No new indicators fetched, ' \
                                                'createIndicators will be executed with noUpdate=True.'
        assert 'If-None-Match' in client.headers
        assert 'If-Modified-Since' in client.headers


def test_build_iterator_with_version_6_2_0(mocker):
    """
    Given
    - server version 6.2.0

    When
    - Running build_iterator method.

    Then
    - Ensure that the no_update value is True
    - Request is called without headers "If-None-Match" and "If-Modified-Since"
    """
    feed_name = 'mock_feed_name'
    mocker.patch.object(demisto, 'debug')
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})

    with requests_mock.Mocker() as m:
        m.get('https://api.github.com/meta', status_code=304)

        client = Client(
            url='https://api.github.com/meta',
            headers={}
        )
        result, no_update = client.build_iterator(feed={'url': 'https://api.github.com/meta'}, feed_name=feed_name)
        assert not result
        assert no_update
        assert 'If-None-Match' not in client.headers
        assert 'If-Modified-Since' not in client.headers


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
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.5.0"})

    class MockResponse:
        headers = {}
        status_code = 200
    no_update = get_no_update_value(MockResponse(), 'feed_name')
    assert not no_update
    assert demisto.debug.call_args[0][0] == 'Last-Modified and Etag headers are not exists,' \
                                            'createIndicators will be executed with noUpdate=False.'


def test_version_6_2_0(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})


def test_fetch_indicators_command_google_ip_ranges(mocker):
    """
    Given
    - indicators response from google ip feed

    When
    - Running fetch indicators command

    Then
    - Ensure that all indicators values exist and are not 'None'
    """
    from JSONFeedApiModule import fetch_indicators_command
    client = Client(
        url='',
        headers={},
        feed_name_to_config={
            'CIDR': {
                'url': 'https://www.test.com/ipranges/goog.json',
                'extractor': 'prefixes[]', 'indicator': 'ipv4Prefix', 'indicator_type': 'CIDR'
            }
        }
    )

    mocker.patch.object(
        client, 'build_iterator', return_value=(
            [{'ipv4Prefix': '1.1.1.1'}, {'ipv4Prefix': '1.2.3.4'}, {'ipv6Prefix': '1111:1111::/28'}], True
        ),
    )

    indicators, _ = fetch_indicators_command(client, indicator_type=None, feedTags=[], auto_detect=None, limit=100)
    for indicator in indicators:
        assert indicator.get('value')


def test_json_feed_with_config_mapping_with_aws_feed_no_update(mocker):
    """
    Given
    - Feed config from AWS feed, with last_run from the same feed, emulating the first
      fetch after updating the AWS Feed integration when there is no update to the feed.
      (the last_run object contains an 'AMAZON' entry)

    When
    - Running fetch indicators command

    Then
    - Ensure that the correct message displays in demisto.debug, and the last_run object
     remained the same, and continue to have the previous AWS feed config name 'AMAZON'.
     (the last_run object contains an 'AMAZON' entry)
    """
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    mocker.patch.object(demisto, 'debug')
    last_run = mocker.patch.object(demisto, 'setLastRun')

    feed_name_to_config = {
        'AMAZON$$CIDR': {
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
    mocker.patch('CommonServerPython.is_demisto_version_ge', return_value=True)
    mocker.patch('JSONFeedApiModule.is_demisto_version_ge', return_value=True)
    mock_last_run = {"AMAZON": {"last_modified": '2019-12-17-23-03-10', "etag": "etag"}}
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)

    with requests_mock.Mocker() as m:
        m.get('https://ip-ranges.amazonaws.com/ip-ranges.json', json=ip_ranges, status_code=304,)

        client = Client(
            url='https://ip-ranges.amazonaws.com/ip-ranges.json',
            credentials={'username': 'test', 'password': 'test'},
            feed_name_to_config=feed_name_to_config,
            insecure=True
        )

        fetch_indicators_command(client=client, indicator_type='CIDR', feedTags=['test'], auto_detect=False)
        assert demisto.debug.call_args[0][0] == 'No new indicators fetched, createIndicators will be executed with noUpdate=True.'
        assert last_run.call_count == 0


def test_json_feed_with_config_mapping_with_aws_feed_with_update(mocker):
    """
    Given
    - Feed config from AWS feed, with last_run from the same feed, emulating the first
      fetch after updating the AWS Feed, when there is an update to the indicators
      (the last_run object contains an 'AMAZON' entry)

    When
    - Running fetch indicators command

    Then
    - Ensure that the correct message displays in demisto.debug, and the last_run object
      contains the new feed config name 'AMAZON$$CIDR'
    """
    with open('test_data/amazon_ip_ranges.json') as ip_ranges_json:
        ip_ranges = json.load(ip_ranges_json)

    mocker.patch.object(demisto, 'debug')
    last_run = mocker.patch.object(demisto, 'setLastRun')

    feed_name_to_config = {
        'AMAZON$$CIDR': {
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
    mocker.patch('CommonServerPython.is_demisto_version_ge', return_value=True)
    mocker.patch('JSONFeedApiModule.is_demisto_version_ge', return_value=True)
    mock_last_run = {"AMAZON": {"last_modified": '2019-12-17-23-03-10', "etag": "etag"}}
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)

    with requests_mock.Mocker() as m:
        m.get('https://ip-ranges.amazonaws.com/ip-ranges.json', json=ip_ranges, status_code=200,
              headers={'Last-Modified': 'Fri, 30 Jul 2021 00:24:13 GMT',  # guardrails-disable-line
                       'ETag': 'd309ab6e51ed310cf869dab0dfd0d34b'})  # guardrails-disable-line)

        client = Client(
            url='https://ip-ranges.amazonaws.com/ip-ranges.json',
            credentials={'username': 'test', 'password': 'test'},
            feed_name_to_config=feed_name_to_config,
            insecure=True
        )

        fetch_indicators_command(client=client, indicator_type='CIDR', feedTags=['test'], auto_detect=False)
        assert demisto.debug.call_args[0][0] == 'New indicators fetched - the Last-Modified value has been updated,' \
               ' createIndicators will be executed with noUpdate=False.'
        assert "AMAZON$$CIDR" in last_run.call_args[0][0]
