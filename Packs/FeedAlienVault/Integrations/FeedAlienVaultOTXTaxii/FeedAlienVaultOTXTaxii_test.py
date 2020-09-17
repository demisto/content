from FeedAlienVaultOTXTaxii import parse_indicators

TEST_DATA = [
    {
        'indicator': 'http://demsito.demisto.com/',
        'type': 'URL',
        'stix_title': 'URL - http://demsito.demisto.com/',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/111',
        'stix_package_information_source': 'Alienvault OTX'
    }, {
        'indicator': '39eb39ad9fad2710be03c18de6985c20',
        'htype': 'md5',
        'type': 'File',
        'stix_title': 'FileHash-MD5 - 39eb39ad9fad2710be03c18de6985c20',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
        'stix_package_information_source': 'Alienvault OTX'
    }, {
        'indicator': 'demisto.com',
        'type': 'Domain',
        'stix_title': 'hostname - demisto.com',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
        'stix_package_information_source': 'Alienvault OTX'
    }, {
        'indicator': '1.2.3.4',
        'type': 'IP',
        'stix_title': 'IP - 1.2.3.4',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
        'stix_package_information_source': 'Alienvault OTX'
    }, {
        'indicator': '1.2.3.4/24',
        'type': 'CIDR',
        'stix_title': 'CIDR - 1.2.3.4/24',
        'stix_package_title': 'demisto',
        'stix_package_description': '',
        'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
        'stix_package_information_source': 'Alienvault OTX'
    }

]

RESULT_PARSED_INDICATORS = [
    {'type': 'URL',
     'stix_title': 'URL - http://demsito.demisto.com/',
     'stix_package_title': 'demisto',
     'stix_package_description': '',
     'stix_package_short_description': 'https://otx.alienvault.com/pulse/111',
     'stix_package_information_source': 'Alienvault OTX',
     'value': 'http://demsito.demisto.com/',
     'fields': {'description': 'https://otx.alienvault.com/pulse/111', 'tags': ['tag1', 'tag2']},
     'rawJSON': {'indicator': 'http://demsito.demisto.com/', 'type': 'URL',
                 'stix_title': 'URL - http://demsito.demisto.com/', 'stix_package_title': 'demisto',
                 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/111',
                 'stix_package_information_source': 'Alienvault OTX', 'value': 'http://demsito.demisto.com/',
                 'fields': {'description': 'https://otx.alienvault.com/pulse/111', 'tags': ['tag1', 'tag2']}}},
    {'htype': 'md5', 'type': 'File', 'stix_title': 'FileHash-MD5 - 39eb39ad9fad2710be03c18de6985c20',
     'stix_package_title': 'demisto', 'stix_package_description': '',
     'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
     'stix_package_information_source': 'Alienvault OTX', 'value': '39eb39ad9fad2710be03c18de6985c20',
     'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2']},
     'rawJSON': {'indicator': '39eb39ad9fad2710be03c18de6985c20', 'htype': 'md5',
                 'type': 'File', 'stix_title': 'FileHash-MD5 - 39eb39ad9fad2710be03c18de6985c20',
                 'stix_package_title': 'demisto', 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
                 'stix_package_information_source': 'Alienvault OTX', 'value': '39eb39ad9fad2710be03c18de6985c20',
                 'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2']}}},
    {'type': 'Domain', 'stix_title': 'hostname - demisto.com',
     'stix_package_title': 'demisto', 'stix_package_description': '',
     'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
     'stix_package_information_source': 'Alienvault OTX', 'value': 'demisto.com',
     'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2']},
     'rawJSON': {'indicator': 'demisto.com', 'type': 'Domain', 'stix_title': 'hostname - demisto.com',
                 'stix_package_title': 'demisto', 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
                 'stix_package_information_source': 'Alienvault OTX',
                 'value': 'demisto.com', 'fields': {'description': 'https://otx.alienvault.com/pulse/1111',
                                                    'tags': ['tag1', 'tag2']}}},
    {'type': 'IP', 'stix_title': 'IP - 1.2.3.4', 'stix_package_title': 'demisto',
     'stix_package_description': '', 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
     'stix_package_information_source': 'Alienvault OTX', 'value': '1.2.3.4',
     'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2']},
     'rawJSON': {'indicator': '1.2.3.4', 'type': 'IP', 'stix_title': 'IP - 1.2.3.4', 'stix_package_title': 'demisto',
                 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
                 'stix_package_information_source': 'Alienvault OTX', 'value': '1.2.3.4',
                 'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2']}}},
    {'type': 'CIDR', 'stix_title': 'CIDR - 1.2.3.4/24', 'stix_package_title': 'demisto',
     'stix_package_description': '', 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
     'stix_package_information_source': 'Alienvault OTX', 'value': '1.2.3.4/24',
     'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2']},
     'rawJSON': {'indicator': '1.2.3.4/24', 'type': 'CIDR', 'stix_title': 'CIDR - 1.2.3.4/24',
                 'stix_package_title': 'demisto', 'stix_package_description': '',
                 'stix_package_short_description': 'https://otx.alienvault.com/pulse/1111',
                 'stix_package_information_source': 'Alienvault OTX', 'value': '1.2.3.4/24',
                 'fields': {'description': 'https://otx.alienvault.com/pulse/1111', 'tags': ['tag1', 'tag2']}}}]

RESULT_ONLY_INDICATORS_LIST = ['http://demsito.demisto.com/',
                               '39eb39ad9fad2710be03c18de6985c20', 'demisto.com', '1.2.3.4', '1.2.3.4/24']


def test_parse_inndicators():
    parsed_list, only_indicator_list = parse_indicators(TEST_DATA, [], tags=['tag1', 'tag2'])
    assert parsed_list == RESULT_PARSED_INDICATORS
    assert only_indicator_list == RESULT_ONLY_INDICATORS_LIST
