from HTTPFeedApiModule import get_indicators_command, Client
import requests_mock


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
        hr, _, raw_json = get_indicators_command(client, args)
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
        hr, _, raw_json = get_indicators_command(client, args)
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
