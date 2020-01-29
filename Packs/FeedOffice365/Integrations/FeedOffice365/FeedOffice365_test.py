import pytest
import requests_mock

FeedOffice365 = __import__("Feed Office365")
from FeedOffice365 import Client, get_indicators_command, fetch_indicators_command
from test_data.feed_data import RESPONSE_DATA


def test_fetch_indicators_command():
    with requests_mock.Mocker() as mock:
        url_dict = {
            "FeedURL": 'https://endpoints.office.com/endpoints/worldwide',
            "Region": 'Worldwide',
            "Service": 'Any'
        }
        mock.get(url_dict.get('FeedURL'), json=RESPONSE_DATA)
        client = Client([url_dict], indicator='ips')
        indicators = fetch_indicators_command(client)
        assert len(indicators) == 4


@pytest.mark.parametrize('command, args, response, length', [
    (get_indicators_command, {'limit': 2, 'indicator_type': 'IPS'}, RESPONSE_DATA, 4),
    (get_indicators_command, {'limit': 2, 'indicator_type': 'URLS'}, RESPONSE_DATA, 6)
])  # noqa: E124
def test_commands(command, args, response, length, mocker):
    url_dict = {
        "FeedURL": 'https://endpoints.office.com/endpoints/worldwide',
        "Region": 'Worldwide',
        "Service": 'Any'
    }
    client = Client([url_dict], args, False, False)
    mocker.patch.object(client, 'build_iterator', return_value=response)
    human_readable, indicators_ec, raw_json = command(client, args)
    indicators = raw_json.get('raw_response')
    assert len(indicators) == length
    for indicator_json in indicators:
        indicator_val = indicator_json.get('value')
        indicator_type = indicator_json.get('type')
        assert indicator_val
        if indicator_type == 'URL':
            assert indicator_type == args.get('indicator_type')[:-1]
        elif indicator_type == 'Domain':
            pass
        else:
            assert indicator_type.startswith(args.get('indicator_type')[:-1])
