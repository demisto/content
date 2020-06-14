import pytest
from FeedUnit42 import Client, get_indicators_command, fetch_indicators
from test_data.feed_data import RESPONSE_DATA


def test_fetch_indicators_command(mocker):
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_indicators', return_value=RESPONSE_DATA)
    indicators = fetch_indicators(client)
    assert len(indicators) == 10


@pytest.mark.parametrize('command, args, response, length', [
    (get_indicators_command, {'limit': 2}, RESPONSE_DATA, 2),
    (get_indicators_command, {'limit': 5}, RESPONSE_DATA, 5),
])  # noqa: E124
def test_commands(command, args, response, length, mocker):
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_indicators', return_value=response)
    _, ec_, _ = command(client, args)
    indicators = ec_.get('Unit42(val.value && val.value == obj.value)')
    assert len(indicators) == length
