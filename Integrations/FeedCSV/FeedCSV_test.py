from FeedCSV import *
import requests_mock


def test_get_indicators_1():
    """Test with 1 fieldname"""
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
            fieldnames='indicator',
        )
        hr, indicators_ec, raw_json = get_indicators_command(client, args)
        indicators_ec = indicators_ec.get('CSV.Indicator')
        assert len(indicators_ec) == 35
        for ind_json in raw_json:
            ind_val = ind_json.get('value')
            ind_type = ind_json.get('type')
            ind_rawjson = ind_json.get('rawJSON')
            assert ind_val
            assert ind_type == itype
            assert ind_rawjson['value'] == ind_val
            assert ind_rawjson['type'] == ind_type


def test_get_indicators_2():
    """Test with 1 fieldname that's not called indicator"""
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
            fieldnames='special_ind',
        )
        hr, indicators_ec, raw_json = get_indicators_command(client, args)
        indicators_ec = indicators_ec.get('CSV.Indicator')
        assert len(indicators_ec) == 35
        for ind_json in raw_json:
            ind_val = ind_json.get('value')
            ind_type = ind_json.get('type')
            ind_rawjson = ind_json.get('rawJSON')
            assert ind_val
            assert ind_type == itype
            assert ind_rawjson['value'] == ind_val
            assert ind_rawjson['type'] == ind_type
