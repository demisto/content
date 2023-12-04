import copy
from dateutil.parser import parse

from FeedAlienVaultOTXTaxii import parse_indicators, get_latest_indicator_time

TEST_DATA = [
    {
        'indicator': 'http://demsito.demisto.com/',
        'type': 'URL',
        'stix_title': 'URL - http://demsito.demisto.com/',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/111',
        'stix_package_information_source': 'Alienvault OTX',
        'added_time': '2020-02-23T12:03:31Z'
    }, {
        'indicator': '39eb39ad9fad2710be03c18de6985c20',
        'htype': 'md5',
        'type': 'File',
        'stix_title': 'FileHash-MD5 - 39eb39ad9fad2710be03c18de6985c20',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
        'stix_package_information_source': 'Alienvault OTX',
        'added_time': '2020-02-23T12:03:31Z'
    }, {
        'indicator': 'demisto.com',
        'type': 'Domain',
        'stix_title': 'hostname - demisto.com',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
        'stix_package_information_source': 'Alienvault OTX',
        'added_time': '2020-02-23T12:03:31Z'
    }, {
        'indicator': '1.2.3.4',
        'type': 'IP',
        'stix_title': 'IP - 1.2.3.4',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
        'stix_package_information_source': 'Alienvault OTX',
        'added_time': '2020-02-23T12:03:31Z'
    }, {
        'indicator': '1.2.3.4/24',
        'type': 'CIDR',
        'stix_title': 'CIDR - 1.2.3.4/24',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
        'stix_package_information_source': 'Alienvault OTX',
        'added_time': '2020-02-23T12:03:31Z'
    }

]

RESULT_PARSED_INDICATORS = [
    {'type': 'URL',
     'stix_title': 'URL - http://demsito.demisto.com/',
     'stix_package_title': 'demisto',
     'stix_package_description': '',
     'stix_package_short_description': 'https://otx.alienvault.com/pulse/111',
     'stix_package_information_source': 'Alienvault OTX', 'added_time': '2020-02-23T12:03:31Z',
     'value': 'http://demsito.demisto.com/',
     'fields': {'description': 'https://otx.alienvault.com/pulse/111', 'tags': ['tag1', 'tag2'],
                'firstseenbysource': '2020-02-23T12:03:31Z'
                },
     'rawJSON': {'indicator': 'http://demsito.demisto.com/', 'type': 'URL',
                 'stix_title': 'URL - http://demsito.demisto.com/', 'stix_package_title': 'demisto',
                 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/111',
                 'stix_package_information_source': 'Alienvault OTX', 'value': 'http://demsito.demisto.com/',
                 'added_time': '2020-02-23T12:03:31Z',
                 'fields': {'description': 'https://otx.alienvault.com/pulse/111', 'tags': ['tag1', 'tag2'],
                            'firstseenbysource': '2020-02-23T12:03:31Z'
                            }}},
    {'htype': 'md5', 'type': 'File', 'stix_title': 'FileHash-MD5 - 39eb39ad9fad2710be03c18de6985c20',
     'stix_package_title': 'demisto', 'stix_package_description': '',
     'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111', 'added_time': '2020-02-23T12:03:31Z',
     'stix_package_information_source': 'Alienvault OTX', 'value': '39eb39ad9fad2710be03c18de6985c20',
     'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2'],
                'firstseenbysource': '2020-02-23T12:03:31Z'
                },
     'rawJSON': {'indicator': '39eb39ad9fad2710be03c18de6985c20', 'htype': 'md5',
                 'type': 'File', 'stix_title': 'FileHash-MD5 - 39eb39ad9fad2710be03c18de6985c20',
                 'stix_package_title': 'demisto', 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
                 'added_time': '2020-02-23T12:03:31Z',
                 'stix_package_information_source': 'Alienvault OTX', 'value': '39eb39ad9fad2710be03c18de6985c20',
                 'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2'],
                            'firstseenbysource': '2020-02-23T12:03:31Z'
                            }}},
    {'type': 'Domain', 'stix_title': 'hostname - demisto.com',
     'stix_package_title': 'demisto', 'stix_package_description': '',
     'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111', 'added_time': '2020-02-23T12:03:31Z',
     'stix_package_information_source': 'Alienvault OTX', 'value': 'demisto.com',
     'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2'],
                'firstseenbysource': '2020-02-23T12:03:31Z'
                },
     'rawJSON': {'indicator': 'demisto.com', 'type': 'Domain', 'stix_title': 'hostname - demisto.com',
                 'stix_package_title': 'demisto', 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
                 'added_time': '2020-02-23T12:03:31Z',
                 'stix_package_information_source': 'Alienvault OTX',
                 'value': 'demisto.com', 'fields': {'description': 'https://otx.alienvault.com/pulse/1111',
                                                    'firstseenbysource': '2020-02-23T12:03:31Z',
                                                    'tags': ['tag1', 'tag2'], }}},
    {'type': 'IP', 'stix_title': 'IP - 1.2.3.4', 'stix_package_title': 'demisto',
     'stix_package_description': '', 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
     'stix_package_information_source': 'Alienvault OTX', 'value': '1.2.3.4', 'added_time': '2020-02-23T12:03:31Z',
     'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2'],
                'firstseenbysource': '2020-02-23T12:03:31Z'
                },
     'rawJSON': {'indicator': '1.2.3.4', 'type': 'IP', 'stix_title': 'IP - 1.2.3.4', 'stix_package_title': 'demisto',
                 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
                 'added_time': '2020-02-23T12:03:31Z',
                 'stix_package_information_source': 'Alienvault OTX', 'value': '1.2.3.4',
                 'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2'],
                            'firstseenbysource': '2020-02-23T12:03:31Z'
                            }}},
    {'type': 'CIDR', 'stix_title': 'CIDR - 1.2.3.4/24', 'stix_package_title': 'demisto',
     'stix_package_description': '', 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
     'stix_package_information_source': 'Alienvault OTX', 'value': '1.2.3.4/24', 'added_time': '2020-02-23T12:03:31Z',
     'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2'],
                'firstseenbysource': '2020-02-23T12:03:31Z'
                },
     'rawJSON': {'indicator': '1.2.3.4/24', 'type': 'CIDR', 'stix_title': 'CIDR - 1.2.3.4/24',
                 'stix_package_title': 'demisto', 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
                 'added_time': '2020-02-23T12:03:31Z',
                 'stix_package_information_source': 'Alienvault OTX', 'value': '1.2.3.4/24',
                 'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2'],
                            'firstseenbysource': '2020-02-23T12:03:31Z'
                            }}}]

RESULT_ONLY_INDICATORS_LIST = ['http://demsito.demisto.com/',
                               '39eb39ad9fad2710be03c18de6985c20', 'demisto.com', '1.2.3.4', '1.2.3.4/24']


def test_parse_indicators():
    # parse_indicators is deleting the indicator key, so deep copying the test data
    test_data = copy.deepcopy(TEST_DATA)
    parsed_list, only_indicator_list = parse_indicators(test_data, [], tags=['tag1', 'tag2'], tlp_color=None)
    assert parsed_list == RESULT_PARSED_INDICATORS
    assert only_indicator_list == RESULT_ONLY_INDICATORS_LIST


def test_parse_indicators_with_tlp():
    for indicator in RESULT_PARSED_INDICATORS:
        indicator['fields']['trafficlightprotocol'] = 'RED'
        indicator['rawJSON']['fields']['trafficlightprotocol'] = 'RED'

    # parse_indicators is deleting the indicator key, so deep copying the test data
    test_data = copy.deepcopy(TEST_DATA)
    parsed_list, only_indicator_list = parse_indicators(test_data, [], tags=['tag1', 'tag2'], tlp_color='RED')
    assert parsed_list == RESULT_PARSED_INDICATORS
    assert only_indicator_list == RESULT_ONLY_INDICATORS_LIST


def test_get_latest_indicator_time():
    indicators_list = [
        {'added_time': '2020-02-23T12:03:31Z'},
        {'added_time': '2020-02-23T13:13:31Z'},
        {'added_time': '2020-02-23T13:03:31Z'}
    ]

    assert get_latest_indicator_time(indicators_list) == parse('2020-02-23T13:13:31Z')
