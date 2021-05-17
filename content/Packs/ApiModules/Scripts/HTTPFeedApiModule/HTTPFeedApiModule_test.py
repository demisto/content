from HTTPFeedApiModule import get_indicators_command, Client, datestring_to_server_format, feed_main
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
        'value': 'AS397539'
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
