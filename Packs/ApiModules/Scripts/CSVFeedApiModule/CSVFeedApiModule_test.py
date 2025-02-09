
import requests_mock
from CSVFeedApiModule import *
import pytest


def test_get_indicators_1():
    """Test with 1 fieldname"""
    feed_url_to_config = {
        'https://ipstack.com': {
            'fieldnames': ['value'],
            'indicator_type': 'IP'
        }
    }

    with open('test_data/ip_ranges.txt') as ip_ranges_txt:
        ip_ranges = ip_ranges_txt.read().encode('utf8')

    with requests_mock.Mocker() as m:
        itype = 'IP'
        args = {
            'indicator_type': itype,
            'limit': 35
        }
        m.get('https://ipstack.com', content=ip_ranges)
        client = Client(
            url="https://ipstack.com",
            feed_url_to_config=feed_url_to_config,
        )
        hr, indicators_ec, raw_json = get_indicators_command(client, args)
        assert not indicators_ec
        for ind_json in raw_json:
            ind_val = ind_json.get('value')
            ind_type = ind_json.get('type')
            ind_rawjson = ind_json.get('rawJSON')
            assert ind_val
            assert ind_type == itype
            assert ind_rawjson['value'] == ind_val
            assert ind_rawjson['type'] == ind_type


def test_get_indicators_with_mapping():
    """Test with 1 fieldname"""
    feed_url_to_config = {
        'https://ipstack.com': {
            'fieldnames': ['value', 'a'],
            'indicator_type': 'IP',
            'mapping': {
                'AAA': 'a'
            }
        }
    }

    with open('test_data/ip_ranges.txt') as ip_ranges_txt:
        ip_ranges = ip_ranges_txt.read()

    with requests_mock.Mocker() as m:
        itype = 'IP'
        args = {
            'indicator_type': itype,
            'limit': 35
        }
        m.get('https://ipstack.com', content=ip_ranges.encode('utf-8'))
        client = Client(
            url="https://ipstack.com",
            feed_url_to_config=feed_url_to_config
        )
        hr, indicators_ec, raw_json = get_indicators_command(client, args)
        assert not indicators_ec
        for ind_json in raw_json:
            ind_val = ind_json.get('value')
            ind_map = ind_json['fields'].get('AAA')
            ind_type = ind_json.get('type')
            ind_rawjson = ind_json.get('rawJSON')
            assert ind_val
            assert ind_type == itype
            assert ind_map == 'a'
            assert ind_rawjson['value'] == ind_val
            assert ind_rawjson['type'] == ind_type


def test_get_indicators_2():
    """Test with 1 fieldname that's not called indicator"""
    feed_url_to_config = {
        'https://ipstack.com': {
            'fieldnames': ['special_ind'],
            'indicator_type': 'IP'
        }
    }

    with open('test_data/ip_ranges.txt') as ip_ranges_txt:
        ip_ranges = ip_ranges_txt.read().encode('utf8')

    with requests_mock.Mocker() as m:
        itype = 'IP'
        args = {
            'indicator_type': itype,
            'limit': 35
        }
        m.get('https://ipstack.com', content=ip_ranges)
        client = Client(
            url="https://ipstack.com",
            feed_url_to_config=feed_url_to_config,
        )
        hr, indicators_ec, raw_json = get_indicators_command(client, args)
        assert not indicators_ec
        for ind_json in raw_json:
            ind_val = ind_json.get('value')
            ind_type = ind_json.get('type')
            ind_rawjson = ind_json.get('rawJSON')
            assert ind_val
            assert ind_type == itype
            assert ind_rawjson['value'] == ind_val
            assert ind_rawjson['type'] == ind_type


def test_get_feed_content():
    """Test that it can handle both zipped and unzipped files correctly"""
    with open('test_data/ip_ranges.txt', 'rb') as ip_ranges_txt:
        ip_ranges_unzipped = ip_ranges_txt.read()

    with open('test_data/ip_ranges.gz', 'rb') as ip_ranges_gz:
        ip_ranges_zipped = ip_ranges_gz.read()

    expected_output = ip_ranges_unzipped.decode('utf8').split('\n')

    feed_url_to_config = {
        'https://ipstack1.com': {
            'content': ip_ranges_unzipped
        },
        'https://ipstack2.com': {
            'content': ip_ranges_unzipped,
            'is_zipped_file': False,
        },
        'https://ipstack3.com': {
            'content': ip_ranges_zipped,
            'is_zipped_file': True
        }
    }

    with requests_mock.Mocker() as m:
        for url in feed_url_to_config:
            client = Client(
                url=url,
                feed_url_to_config=feed_url_to_config,
            )

            m.get(url, content=feed_url_to_config.get(url).get('content'))
            raw_response = requests.get(url)

            assert client.get_feed_content_divided_to_lines(url, raw_response) == expected_output


@pytest.mark.parametrize('date_string,expected_result', [
    ("2020-02-10 13:39:14", '2020-02-10T13:39:14Z'), ("2020-02-10T13:39:14", '2020-02-10T13:39:14Z'),
    ("2020-02-10 13:39:14.123", '2020-02-10T13:39:14Z'), ("2020-02-10T13:39:14.123", '2020-02-10T13:39:14Z'),
    ("2020-02-10T13:39:14Z", '2020-02-10T13:39:14Z'), ("2020-11-01T04:16:13-04:00", '2020-11-01T08:16:13Z')])
def test_date_format_parsing(date_string, expected_result):
    """
    Given
    - A string represting a date.
    When
    - running date_format_parsing on the date.
    Then
    - Ensure the datestring is converted to the ISO-8601 format.
    """
    assert expected_result == date_format_parsing(date_string)


class TestTagsParam:
    def test_tags_exists(self):
        """
        Given:
        - tags ['tag1', 'tag2'] params

        When:
        - Running get indicators/fetch indicators

        Then:
        - Validating tags key exists with given tags
        """
        tags = ['tag1', 'tag2']
        feed_url_to_config = {
            'https://ipstack.com': {
                'fieldnames': ['value'],
                'indicator_type': 'IP'
            }
        }

        with open('test_data/ip_ranges.txt') as ip_ranges_txt:
            ip_ranges = ip_ranges_txt.read().encode('utf8')

        with requests_mock.Mocker() as m:
            itype = 'IP'
            args = {
                'indicator_type': itype,
                'limit': 35
            }
            m.get('https://ipstack.com', content=ip_ranges)
            client = Client(
                url="https://ipstack.com",
                feed_url_to_config=feed_url_to_config,
                feedTags=tags
            )
            _, _, indicators = get_indicators_command(client, args, tags)
            assert tags == indicators[0]['fields']['tags']

    def test_tags_not_exists(self):
        """
        Given:
        - No tags param

        When:
        - Running get indicators/fetch indicators

        Then:
        - Validating tags key exists with an empty list.
        """
        feed_url_to_config = {
            'https://ipstack.com': {
                'fieldnames': ['value'],
                'indicator_type': 'IP'
            }
        }

        with open('test_data/ip_ranges.txt') as ip_ranges_txt:
            ip_ranges = ip_ranges_txt.read().encode('utf8')

        with requests_mock.Mocker() as m:
            itype = 'IP'
            args = {
                'indicator_type': itype,
                'limit': 35
            }
            m.get('https://ipstack.com', content=ip_ranges)
            client = Client(
                url="https://ipstack.com",
                feed_url_to_config=feed_url_to_config,
                feedTags=[]
            )
            _, _, indicators = get_indicators_command(client, args)
            assert indicators[0]['fields']['tags'] == []


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_create_fields_mapping():
    """
    Given:
    - Raw json of the csv row extracted

    When:
    - Fetching indicators from csv rows

    Then:
    - Validate the mapping is done correctly
    """
    raw_json = util_load_json("test_data/create_field_mapping_test.json")
    mapping = {
        'Value': ('Name', '^([A-Z]{1}[a-z]+)', None),
        'Country': 'Country Name',
        'Count': ('Count', lambda count: 'Low' if count < 5 else 'High')
    }
    result = create_fields_mapping(raw_json, mapping)
    assert result == {
        'Value': 'John',
        'Country': 'United States',
        'Count': 'Low'
    }


def test_get_indicators_with_relations():
    """
    Given:
    - Raw json of the csv row extracted

    When:
    - Fetching indicators from csv rows
    - create_relationships param is set to True

    Then:
    - Validate the returned list of indicators have relations.
    """

    feed_url_to_config = {
        'https://ipstack.com': {
            'fieldnames': ['value', 'a'],
            'indicator_type': 'IP',
            'relationship_entity_b_type': 'IP',
            'relationship_name': 'resolved-from',
            'mapping': {
                'AAA': 'a',
                'relationship_entity_b': ('a', r'.*used\s+by\s(.*?)\s', None),
            }
        }
    }
    expected_res = ([{'value': 'test.com', 'type': 'IP',
                      'rawJSON': {'value': 'test.com', 'a': 'Domain used by Test c&c',
                                  None: ['2021-04-22 06:03',
                                         'https://test.com/manual/test-iplist.txt'],
                                  'type': 'IP'},
                      'fields': {'AAA': 'Domain used by Test c&c', 'relationship_entity_b': 'Test',
                                 'tags': []},
                      'relationships': [
                          {'name': 'resolved-from', 'reverseName': 'resolves-to', 'type': 'IndicatorToIndicator',
                           'entityA': 'test.com', 'entityAFamily': 'Indicator', 'entityAType': 'IP',
                           'entityB': 'Test', 'entityBFamily': 'Indicator', 'entityBType': 'IP',
                           'fields': {}}]}], True)

    ip_ranges = 'test.com,Domain used by Test c&c,2021-04-22 06:03,https://test.com/manual/test-iplist.txt'

    with requests_mock.Mocker() as m:
        itype = 'IP'
        m.get('https://ipstack.com', content=ip_ranges.encode('utf8'))
        client = Client(
            url="https://ipstack.com",
            feed_url_to_config=feed_url_to_config
        )
        indicators = fetch_indicators_command(client, default_indicator_type=itype, auto_detect=False,
                                              limit=35, create_relationships=True)
        assert indicators == expected_res


def test_fetch_indicators_with_enrichment_excluded(requests_mock):
    """
    Given:
    - Raw json of the csv row extracted

    When:
    - Fetching indicators from csv rows
    - enrichment_excluded param is set to True

    Then:
    - Validate the returned list of indicators have enrichment exclusion set.
    """

    feed_url_to_config = {
        'https://ipstack.com': {
            'fieldnames': ['value', 'a'],
            'indicator_type': 'IP',
            'relationship_entity_b_type': 'IP',
            'relationship_name': 'resolved-from',
            'mapping': {
                'AAA': 'a',
                'relationship_entity_b': ('a', r'.*used\s+by\s(.*?)\s', None),
            }
        }
    }
    expected_res = ([{'value': 'test.com', 'type': 'IP',
                      'rawJSON': {'value': 'test.com', 'a': 'Domain used by Test c&c',
                                  None: ['2021-04-22 06:03',
                                         'https://test.com/manual/test-iplist.txt'],
                                  'type': 'IP'},
                      'fields': {'AAA': 'Domain used by Test c&c', 'relationship_entity_b': 'Test',
                                 'tags': []},
                      'relationships': [],
                      'enrichmentExcluded': True,
                      }],
                    True)

    ip_ranges = 'test.com,Domain used by Test c&c,2021-04-22 06:03,https://test.com/manual/test-iplist.txt'

    itype = 'IP'
    requests_mock.get('https://ipstack.com', content=ip_ranges.encode('utf8'))
    client = Client(
        url="https://ipstack.com",
        feed_url_to_config=feed_url_to_config
    )
    indicators = fetch_indicators_command(client, default_indicator_type=itype, auto_detect=False,
                                          limit=35, create_relationships=False, enrichment_excluded=True)
    assert indicators == expected_res


def test_get_indicators_without_relations():
    """
    Given:
    - Raw json of the csv row extracted

    When:
    - Fetching indicators from csv rows
    - create_relationships param is set to False

    Then:
    - Validate the returned list of indicators dont return relationships.
    """

    feed_url_to_config = {
        'https://ipstack.com': {
            'fieldnames': ['value', 'a'],
            'indicator_type': 'IP',
            'relationship_entity_b_type': 'IP',
            'relationship_name': 'resolved-from',
            'mapping': {
                'AAA': 'a',
                'relationship_entity_b': ('a', r'.*used\s+by\s(.*?)\s', None),
            }
        }
    }
    expected_res = ([{'value': 'test.com', 'type': 'IP',
                      'rawJSON': {'value': 'test.com', 'a': 'Domain used by Test c&c',
                                  None: ['2021-04-22 06:03',
                                         'https://test.com/manual/test-iplist.txt'],
                                  'type': 'IP'},
                      'fields': {'AAA': 'Domain used by Test c&c', 'relationship_entity_b': 'Test',
                                 'tags': []}, 'relationships': []}], True)

    ip_ranges = 'test.com,Domain used by Test c&c,2021-04-22 06:03,https://test.com/manual/test-iplist.txt'

    with requests_mock.Mocker() as m:
        itype = 'IP'
        m.get('https://ipstack.com', content=ip_ranges.encode('utf8'))
        client = Client(
            url="https://ipstack.com",
            feed_url_to_config=feed_url_to_config
        )
        indicators = fetch_indicators_command(client, default_indicator_type=itype, auto_detect=False,
                                              limit=35, create_relationships=False)
        assert indicators == expected_res


def test_get_no_update_value(mocker):
    """
    Given
    - response with last_modified and etag headers with the same values like in the integration context.

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

    no_update = get_no_update_value(MockResponse(), 'https://test.com/manual/test-iplist.txt')
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
    - Ensure that the results are empty and No_update value is True.
    """
    mocker.patch.object(demisto, 'debug')
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.5.0"})
    with requests_mock.Mocker() as m:
        m.get('https://api.github.com/meta', status_code=304)

        client = Client(
            url='https://api.github.com/meta'
        )
        result = client.build_iterator()
        assert result
        assert result[0]['https://api.github.com/meta']
        assert list(result[0]['https://api.github.com/meta']['result']) == []
        assert result[0]['https://api.github.com/meta']['no_update']
        assert demisto.debug.call_args[0][0] == 'No new indicators fetched, ' \
                                                'createIndicators will be executed with noUpdate=True.'


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
    mocker.patch.object(demisto, 'debug')
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})

    with requests_mock.Mocker() as m:
        m.get('https://api.github.com/meta', status_code=304)

        client = Client(
            url='https://api.github.com/meta',
            headers={}
        )
        result = client.build_iterator()
        assert result[0]['https://api.github.com/meta']['no_update']
        assert list(result[0]['https://api.github.com/meta']['result']) == []
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

    class MockResponse:
        headers = {}
        status_code = 200

    no_update = get_no_update_value(MockResponse(), 'https://test.com/manual/test-iplist.txt')
    assert not no_update
    assert demisto.debug.call_args[0][0] == 'Last-Modified and Etag headers are not exists,' \
                                            'createIndicators will be executed with noUpdate=False.'


def test_build_iterator_modified_headers(mocker):
    """
    Given
    - Using basic authentication
    - Last run has etag and last_modified in it

    When
    - Running build_iterator method.

    Then
    - Ensure that prepreq.headers are not overwritten when using basic authentication.
    """
    mocker.patch.object(demisto, 'debug')
    mock_session = mocker.patch.object(requests.Session, 'send')
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.5.0"})
    mocker.patch('demistomock.getLastRun', return_value={
        'https://api.github.com/meta': {
            'etag': 'etag',
            'last_modified': '2023-05-29T12:34:56Z'
        }})

    client = Client(
        url='https://api.github.com/meta',
        credentials={'identifier': 'user', 'password': 'password'},
    )

    result = client.build_iterator()
    assert 'Authorization' in mock_session.call_args[0][0].headers
    assert result


@pytest.mark.parametrize('has_passed_time_threshold_response, expected_result', [
    (True, {}),
    (False, {'If-None-Match': 'etag', 'If-Modified-Since': '2023-05-29T12:34:56Z'})
])
def test_build_iterator__with_and_without_passed_time_threshold(mocker, has_passed_time_threshold_response, expected_result):
    """
    Given
    - A boolean result from the has_passed_time_threshold function
    When
    - Running build_iterator method.
    Then
    - Ensure the next request headers will be as expected:
        case 1: has_passed_time_threshold_response is True, no headers will be added
        case 2: has_passed_time_threshold_response is False, headers containing 'last_modified' and 'etag' will be added
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.5.0"})
    mock_session = mocker.patch.object(requests.Session, 'send')
    mocker.patch('CSVFeedApiModule.has_passed_time_threshold', return_value=has_passed_time_threshold_response)
    mocker.patch('demistomock.getLastRun', return_value={
        'https://api.github.com/meta': {
            'etag': 'etag',
            'last_modified': '2023-05-29T12:34:56Z',
            'last_updated': '2023-05-05T09:09:06Z'
        }})
    client = Client(
        url='https://api.github.com/meta',
        credentials={'identifier': 'user', 'password': 'password'})

    client.build_iterator()
    assert mock_session.call_args[0][0].headers.get('If-None-Match') == expected_result.get('If-None-Match')
    assert mock_session.call_args[0][0].headers.get('If-Modified-Since') == expected_result.get('If-Modified-Since')


def test_get_indicators_command(mocker):
    """
            Given: params with tlp_color set to RED and enrichmentExcluded set to False
            When: Calling get_indicators_command
            Then: validate enrichment_excluded is set to True
    """
    from CSVFeedApiModule import get_indicators_command
    client_mock = mocker.Mock()
    args = {
        'indicator_type': 'IP',
        'limit': '50'
    }
    tags = ['tag1', 'tag2']
    tlp_color_red_params = {
        'tlp_color': 'RED',
        'enrichmentExcluded': False
    }
    mocker.patch.object(demisto, 'params', return_value=tlp_color_red_params)
    mocker.patch('CSVFeedApiModule.is_xsiam_or_xsoar_saas', return_value=True)
    fetch_mock = mocker.patch('CSVFeedApiModule.fetch_indicators_command', return_value=([], None))
    get_indicators_command(client_mock, args, tags)

    fetch_mock.assert_called_with(
        client_mock,
        'IP',
        None,
        50,
        False,
        True  # This verifies that enrichment_excluded is set to True
    )
