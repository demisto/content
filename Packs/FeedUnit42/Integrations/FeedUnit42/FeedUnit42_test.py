import pytest
from FeedUnit42 import Client, get_indicators_command, fetch_indicators
from test_data.feed_data import RESPONSE_DATA


@pytest.mark.parametrize('command, args, response, length', [
    (get_indicators_command, {'limit': 2}, RESPONSE_DATA, 2),
    (get_indicators_command, {'limit': 5}, RESPONSE_DATA, 5),
])  # noqa: E124
def test_commands(command, args, response, length, mocker):
    """Unit test
    Given
    - get_indicators_command func
    - command args
    - command raw response
    When
    - mock the Client's get_indicators.
    Then
    - convert the result to human readable table
    - create the context
    validate the entry context
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_indicators', return_value=response)
    _, ec_, _ = command(client, args)
    indicators = ec_.get('Unit42(val.value && val.value == obj.value)')
    assert len(indicators) == length


def test_fetch_indicators_command(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's get_indicators.
    Then
    - run the fetch incidents command using the Client
    Validate the amount of indicators fetched
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_indicators', return_value=RESPONSE_DATA)
    indicators = fetch_indicators(client)
    assert len(indicators) == 10


def test_feed_tags_param(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the feed tags param.
    - mock the Client's get_indicators.
    Then
    - run the fetch incidents command using the Client
    Validate The value of the tags field.
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_indicators', return_value=RESPONSE_DATA)
    indicators = fetch_indicators(client, ['test_tag'])
    assert indicators[0].get('fields').get('tags') == ['malicious-activity', 'test_tag']
