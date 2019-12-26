import pytest
import requests_mock
from FeedO365 import Client, get_indicators_command, fetch_indicators_command
from test_data.feed_data import RESPOSNE_DATA


def test_fetch_indicators_command():
    with requests_mock.Mocker() as mock:
        mock.get('https://endpoints.office.com', json=RESPOSNE_DATA)
        client = Client(["https://endpoints.office.com"], indicator_type='ips')
        indicators = fetch_indicators_command(client)
        print(indicators)
        assert len(indicators) == 4


@pytest.mark.parametrize('command, args, response, length', [
    (get_indicators_command, {'limit': 2, 'indicator_type': 'ips'}, RESPOSNE_DATA, 4),
    (get_indicators_command, {'limit': 2, 'indicator_type': 'urls'}, RESPOSNE_DATA, 5)
])  # noqa: E124
def test_commands(command, args, response, length, mocker):
    client = Client(['https://endpoints.office.com'], args.get('indicator_type'), False, False)
    mocker.patch.object(client, 'build_iterator', return_value=response)
    human_readable, indicators_ec, raw_json = command(client, args.get('indicator_type'))
    indicators_ec = indicators_ec.get('O365.Indicator')
    assert len(indicators_ec) == length
    for indicator_json in indicators_ec:
        indicator_val = indicator_json.get('Value')
        indicator_type = indicator_json.get('Type')
        indicator_rawjson = indicator_json.get('rawJSON')
        assert indicator_val
        assert indicator_type == args.get('indicator_type')[:-1]
        assert indicator_rawjson['Value'] == indicator_val
        assert indicator_rawjson['Type'] == indicator_type
