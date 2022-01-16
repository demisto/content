from HTTPFeedApiModule import get_indicators_command, Client, datestring_to_server_format, feed_main,\
    fetch_indicators_command, get_no_update_value
import requests_mock
import demistomock as demisto


def test_get_indicators():
    with open('test_data/asn_ranges.txt') as asn_ranges_txt:
        asn_ranges = asn_ranges_txt.read().encode('utf8')

    with requests_mock.Mocker() as m:
        itype = 'ASN'
        args = {
            'indicator_type': itype,
            'limit': 35
        }
        feed_type = {
            'https://www.spamhaus.org/drop/asndrop.txt': {
                'indicator_type': 'ASN',
                'indicator': {
                    'regex': '^AS[0-9]+'
                },
                'fields': [
                    {
                        'asndrop_country': {
                            'regex': r'^.*;\W([a-zA-Z]+)\W+',
                            'transform': r'\1'
                        }
                    },
                    {
                        'asndrop_org': {
                            'regex': r'^.*\|\W+(.*)',
                            'transform': r'\1'
                        }
                    }
                ]
            }
        }
        m.get('https://www.spamhaus.org/drop/asndrop.txt', content=asn_ranges)
        client = Client(
            url="https://www.spamhaus.org/drop/asndrop.txt",
            source_name='spamhaus',
            ignore_regex='^;.*',
            feed_url_to_config=feed_type
        )
        args['indicator_type'] = 'ASN'
        _, _, raw_json = get_indicators_command(client, args)
        for ind_json in raw_json:
            ind_val = ind_json.get('value')
            ind_type = ind_json.get('type')
            ind_rawjson = ind_json.get('rawJSON')
            assert ind_val
            assert ind_type == itype
            assert ind_rawjson['value'] == ind_val
            assert ind_rawjson['type'] == ind_type


def test_get_indicators_json_params():
    with open('test_data/asn_ranges.txt') as asn_ranges_txt:
        asn_ranges = asn_ranges_txt.read().encode('utf8')

    with requests_mock.Mocker() as m:
        itype = 'ASN'
        args = {
            'indicator_type': itype,
            'limit': 35
        }
        indicator_json = '''
        {
            "regex": "^AS[0-9]+"
        }
        '''
        fields_json = r'''
        {
            "asndrop_country": {
                    "regex":"^.*;\\W([a-zA-Z]+)\\W+",
                    "transform":"\\1"
                },
            "asndrop_org": {
                  "regex":"^.*\\|\\W+(.*)",
                  "transform":"\\1"
               }
        }
        '''

        m.get('https://www.spamhaus.org/drop/asndrop.txt', content=asn_ranges)
        client = Client(
            url="https://www.spamhaus.org/drop/asndrop.txt",
            source_name='spamhaus',
            ignore_regex='^;.*',
            indicator=indicator_json,
            fields=fields_json,
            indicator_type='ASN'
        )
        args['indicator_type'] = 'ASN'
        _, _, raw_json = get_indicators_command(client, args)
        for ind_json in raw_json:
            ind_val = ind_json.get('value')
            ind_type = ind_json.get('type')
            ind_rawjson = ind_json.get('rawJSON')
            assert ind_val
            assert ind_type == itype
            assert ind_rawjson['value'] == ind_val
            assert ind_rawjson['type'] == ind_type


def test_custom_fields_creator():
    custom_fields_mapping = {
        "old_field1": "new_field1",
        "old_field2": "new_field2"
    }
    client = Client(
        url="https://www.spamhaus.org/drop/asndrop.txt",
        feed_url_to_config="some_stuff",
        custom_fields_mapping=custom_fields_mapping
    )

    attributes = {
        'old_field1': "value1",
        'old_field2': "value2"
    }

    custom_fields = client.custom_fields_creator(attributes)

    assert custom_fields.get('new_field1') == "value1"
    assert custom_fields.get('new_field2') == "value2"
    assert "old_field1" not in custom_fields.keys()
    assert "old_filed2" not in custom_fields.keys()


def test_datestring_to_server_format():
    """
    Given
    - A string represting a date.

    When
    - running datestring_to_server_format on the date.

    Then
    - Ensure the datestring is converted to the ISO-8601 format.
    """
    datestring1 = "2020-02-10 13:39:14"
    datestring2 = "2020-02-10T13:39:14"
    datestring3 = "2020-02-10 13:39:14.123"
    datestring4 = "2020-02-10T13:39:14.123"
    datestring5 = "2020-02-10T13:39:14Z"
    datestring6 = "2020-11-01T04:16:13-04:00"
    assert '2020-02-10T13:39:14Z' == datestring_to_server_format(datestring1)
    assert '2020-02-10T13:39:14Z' == datestring_to_server_format(datestring2)
    assert '2020-02-10T13:39:14Z' == datestring_to_server_format(datestring3)
    assert '2020-02-10T13:39:14Z' == datestring_to_server_format(datestring4)
    assert '2020-02-10T13:39:14Z' == datestring_to_server_format(datestring5)
    assert '2020-11-01T08:16:13Z' == datestring_to_server_format(datestring6)


def test_get_feed_config():
    custom_fields_mapping = {
        "old_field1": "new_field1",
        "old_field2": "new_field2"
    }
    client = Client(
        url="https://www.spamhaus.org/drop/asndrop.txt",
        feed_url_to_config="some_stuff",
        custom_fields_mapping=custom_fields_mapping
    )
    # Check that if an empty .get_feed_config is called, an empty dict returned
    assert {} == client.get_feed_config()


def test_feed_main_fetch_indicators(mocker, requests_mock):
    """
    Given
    - Parameters (url, ignore_regex, feed_url_to_config and tags) to configure a feed.

    When
    - Fetching indicators.

    Then
    - Ensure createIndicators is called with 466 indicators to fetch.
    - Ensure one of the indicators is fetched as expected.
    """
    feed_url = 'https://www.spamhaus.org/drop/asndrop.txt'
    indicator_type = 'ASN'
    tags = 'tag1,tag2'
    tlp_color = 'AMBER'
    feed_url_to_config = {
        'https://www.spamhaus.org/drop/asndrop.txt': {
            'indicator_type': indicator_type,
            'indicator': {
                'regex': '^AS[0-9]+'
            },
            'fields': [
                {
                    'asndrop_country': {
                        'regex': r'^.*;\W([a-zA-Z]+)\W+',
                        'transform': r'\1'
                    }
                },
                {
                    'asndrop_org': {
                        'regex': r'^.*\|\W+(.*)',
                        'transform': r'\1'
                    }
                }
            ]
        }
    }

    mocker.patch.object(
        demisto, 'params',
        return_value={
            'url': feed_url,
            'ignore_regex': '^;.*',
            'feed_url_to_config': feed_url_to_config,
            'feedTags': tags,
            'tlp_color': tlp_color
        }
    )
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    mocker.patch.object(demisto, 'createIndicators')

    with open('test_data/asn_ranges.txt') as asn_ranges_txt:
        asn_ranges = asn_ranges_txt.read().encode('utf8')

    requests_mock.get(feed_url, content=asn_ranges)
    feed_main('great_feed_name')

    # verify createIndicators was called with 466 indicators
    assert demisto.createIndicators.call_count == 1
    indicators = demisto.createIndicators.call_args[0][0]
    assert len(indicators) == 466

    # verify one of the expected indicators
    assert {
        'rawJSON': {
            'asndrop_country': 'US',
            'asndrop_org': 'LAKSH CYBERSECURITY AND DEFENSE LLC',
            'tags': tags.split(','),
            'trafficlightprotocol': 'AMBER',
            'type': indicator_type,
            'value': 'AS397539'
        },
        'type': indicator_type,
        'value': 'AS397539',
        'fields': {'tags': ['tag1', 'tag2'], 'trafficlightprotocol': 'AMBER'}
    } in indicators


def test_feed_main_test_module(mocker, requests_mock):
    """
    Given
    - Parameters (url, ignore_regex, feed_url_to_config and tags) to configure a feed.

    When
    - Running test-module (clicking on Test).

    Then
    - Ensure 'ok' is returned.
    """
    feed_url = 'https://www.spamhaus.org/drop/asndrop.txt'
    indicator_type = 'ASN'
    tags = 'tag1,tag2'
    tlp_color = 'AMBER'
    feed_url_to_config = {
        'https://www.spamhaus.org/drop/asndrop.txt': {
            'indicator_type': indicator_type,
            'indicator': {
                'regex': '^AS[0-9]+'
            },
            'fields': [
                {
                    'asndrop_country': {
                        'regex': r'^.*;\W([a-zA-Z]+)\W+',
                        'transform': r'\1'
                    }
                },
                {
                    'asndrop_org': {
                        'regex': r'^.*\|\W+(.*)',
                        'transform': r'\1'
                    }
                }
            ]
        }
    }

    mocker.patch.object(
        demisto, 'params',
        return_value={
            'url': feed_url,
            'ignore_regex': '^;.*',
            'feed_url_to_config': feed_url_to_config,
            'feedTags': tags,
            'tlp_color': tlp_color
        }
    )
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')

    with open('test_data/asn_ranges.txt') as asn_ranges_txt:
        asn_ranges = asn_ranges_txt.read().encode('utf8')

    requests_mock.get(feed_url, content=asn_ranges)
    feed_main('great_feed_name')

    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results['HumanReadable'] == 'ok'


def test_get_indicators_with_relations():
    """
    Given:
    - feed url config including relations values
    When:
    - Fetching indicators
    - create_relationships param is set to True
    Then:
    - Validate the returned list of indicators return relationships.
    """

    feed_url_to_config = {
        'https://www.spamhaus.org/drop/asndrop.txt': {
            "indicator_type": 'IP',
            "indicator": {
                "regex": r"^.+,\"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\"?",
                "transform": "\\1"
            },
            'relationship_name': 'indicator-of',
            'relationship_entity_b_type': 'STIX Malware',
            "fields": [{
                'firstseenbysource': {
                    "regex": r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})",
                    "transform": "\\1"
                },
                "port": {
                    "regex": r"^.+,.+,(\d{1,5}),",
                    "transform": "\\1"
                },
                "updatedate": {
                    "regex": r"^.+,.+,.+,(\d{4}-\d{2}-\d{2})",
                    "transform": "\\1"
                },
                "malwarefamily": {
                    "regex": r"^.+,.+,.+,.+,(.+)",
                    "transform": "\\1"
                },
                "relationship_entity_b": {
                    "regex": r"^.+,.+,.+,.+,\"(.+)\"",
                    "transform": "\\1"
                }
            }],
        }
    }
    expected_res = ([{'value': '127.0.0.1', 'type': 'IP',
                     'rawJSON': {'malwarefamily': '"Test"', 'relationship_entity_b': 'Test', 'value': '127.0.0.1',
                                 'type': 'IP', 'tags': []},
                      'relationships': [
                         {'name': 'indicator-of', 'reverseName': 'indicated-by', 'type': 'IndicatorToIndicator',
                          'entityA': '127.0.0.1', 'entityAFamily': 'Indicator', 'entityAType': 'IP',
                          'entityB': 'Test',
                          'entityBFamily': 'Indicator', 'entityBType': 'STIX Malware', 'fields': {}}],
                      'fields': {'tags': []}}], True)

    asn_ranges = '"2021-01-17 07:44:49","127.0.0.1","3889","online","2021-04-22","Test"'
    with requests_mock.Mocker() as m:
        m.get('https://www.spamhaus.org/drop/asndrop.txt', content=asn_ranges.encode('utf-8'))
        client = Client(
            url="https://www.spamhaus.org/drop/asndrop.txt",
            source_name='spamhaus',
            ignore_regex='^;.*',
            feed_url_to_config=feed_url_to_config,
            indicator_type='ASN'
        )
        indicators = fetch_indicators_command(client, feed_tags=[], tlp_color=[], itype='IP', auto_detect=False,
                                              create_relationships=True)

        assert indicators == expected_res


def test_get_indicators_without_relations():
    """
    Given:
    - feed url config including relations values
    When:
    - Fetching indicators
    - create_relationships param is set to False
    Then:
    - Validate the returned list of indicators dont return relationships.
    """

    feed_url_to_config = {
        'https://www.spamhaus.org/drop/asndrop.txt': {
            "indicator_type": 'IP',
            "indicator": {
                "regex": r"^.+,\"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\"?",
                "transform": "\\1"
            },
            'relationship_name': 'indicator-of',
            'relationship_entity_b_type': 'STIX Malware',
            "fields": [{
                'firstseenbysource': {
                    "regex": r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})",
                    "transform": "\\1"
                },
                "port": {
                    "regex": r"^.+,.+,(\d{1,5}),",
                    "transform": "\\1"
                },
                "updatedate": {
                    "regex": r"^.+,.+,.+,(\d{4}-\d{2}-\d{2})",
                    "transform": "\\1"
                },
                "malwarefamily": {
                    "regex": r"^.+,.+,.+,.+,(.+)",
                    "transform": "\\1"
                },
                "relationship_entity_b": {
                    "regex": r"^.+,.+,.+,.+,\"(.+)\"",
                    "transform": "\\1"
                }
            }],
        }
    }
    expected_res = ([{'value': '127.0.0.1', 'type': 'IP',
                     'rawJSON': {'malwarefamily': '"Test"', 'relationship_entity_b': 'Test', 'value': '127.0.0.1',
                                 'type': 'IP', 'tags': []},
                      'fields': {'tags': []}}], True)

    asn_ranges = '"2021-01-17 07:44:49","127.0.0.1","3889","online","2021-04-22","Test"'
    with requests_mock.Mocker() as m:
        m.get('https://www.spamhaus.org/drop/asndrop.txt', content=asn_ranges.encode('utf-8'))
        client = Client(
            url="https://www.spamhaus.org/drop/asndrop.txt",
            source_name='spamhaus',
            ignore_regex='^;.*',
            feed_url_to_config=feed_url_to_config,
            indicator_type='ASN'
        )
        indicators = fetch_indicators_command(client, feed_tags=[], tlp_color=[], itype='IP', auto_detect=False,
                                              create_relationships=False)

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
    no_update = get_no_update_value(MockResponse(), 'https://www.spamhaus.org/drop/asndrop.txt')
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
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.5.0"})

    class MockResponse:
        headers = {}
        status_code = 200
    no_update = get_no_update_value(MockResponse(), 'https://www.spamhaus.org/drop/asndrop.txt')
    assert not no_update
    assert demisto.debug.call_args[0][0] == 'Last-Modified and Etag headers are not exists,' \
                                            'createIndicators will be executed with noUpdate=False.'
