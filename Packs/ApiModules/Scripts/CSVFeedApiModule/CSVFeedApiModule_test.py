# import requests_mock
from CSVFeedApiModule import *
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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
            assert [] == indicators[0]['fields']['tags']


def test_date_format_parsing():
    formatted_date = date_format_parsing('2020-02-01 12:13:14')
    assert formatted_date == '2020-02-01T12:13:14Z'

    formatted_date = date_format_parsing('2020-02-01 12:13:14.11111')
    assert formatted_date == '2020-02-01T12:13:14Z'


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
