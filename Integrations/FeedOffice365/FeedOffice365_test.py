import pytest
import requests_mock
from FeedO365 import Client, get_indicators_command, fetch_indicators_command
from test_data.feed_data import RESPOSNE_DATA


def test_fetch_indicators_command():
    with requests_mock.Mocker() as mock:
        url_dict = {
            "FeedURL": 'https://endpoints.office.com/endpoints/worldwide',
            "Region": 'Worldwide',
            "Service": 'Any'
        }
        mock.get(url_dict.get('FeedURL'), json=RESPOSNE_DATA)
        client = Client([url_dict], indicator='ips')
        indicators = fetch_indicators_command(client)
        assert len(indicators) == 4


@pytest.mark.parametrize('command, args, response, length', [
    (get_indicators_command, {'limit': 2, 'indicator': 'ips'}, RESPOSNE_DATA, 4),
    (get_indicators_command, {'limit': 2, 'indicator': 'urls'}, RESPOSNE_DATA, 5)
])  # noqa: E124
def test_commands(command, args, response, length, mocker):
    url_dict = {
        "FeedURL": 'https://endpoints.office.com/endpoints/worldwide',
        "Region": 'Worldwide',
        "Service": 'Any'
    }
    client = Client([url_dict], args.get('indicator'), False, False)
    mocker.patch.object(client, 'build_iterator', return_value=response)
    human_readable, indicators_ec, raw_json = command(client, args.get('indicator'))
    indicators_ec = indicators_ec.get('Office365.Indicator')
    assert len(indicators_ec) == length
    for indicator_json in indicators_ec:
        indicator_val = indicator_json.get('Value')
        indicator_type = indicator_json.get('Type')
        indicator_rawjson = indicator_json.get('rawJSON')
        assert indicator_val
        assert indicator_type == args.get('indicator')[:-1]
        assert indicator_rawjson['Value'] == indicator_val
        assert indicator_rawjson['Type'] == indicator_type
