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
    assert set(indicators[0].get('fields').get('tags')) == set({'malicious-activity', 'test_tag'})


def test_fetch_indicators_with_mitre_external_reference(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's get_indicators.
    Then
    - run the fetch incidents command using the Client
    Validate the connections in between the indicators
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_indicators', return_value=RESPONSE_DATA)
    indicators = fetch_indicators(client)
    for indicator in indicators:
        indicator_fields = indicator.get('fields')
        if indicator_fields.get('indicatoridentification') == 'indicator--010bb9ad-5686-485d-97e5-93c2187e56ce':
            assert indicator_fields.get('mitreexternalreferences') == [
                {'description': 'Ballenthin', 'source_name': 'FireEye WMI 2015', 'url': 'example.com'},
                {'external_id': 'T1047', 'source_name': 'mitre-attack',
                 'url': 'https://attack.mitre.org/techniques/T1047'},
                {'description': 'Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.',
                 'source_name': 'MSDN WMI', 'url': 'https://msdn.microsoft.com/en-us/library/aa394582.aspx'},
                {'description': 'Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.',
                 'source_name': 'TechNet RPC', 'url': 'https://technet.microsoft.com/en-us/library/cc787851.aspx'},
                {'description': 'Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.',
                 'source_name': 'Wikipedia SMB', 'url': 'https://en.wikipedia.org/wiki/Server_Message_Block'}]
            break


def test_fetch_indicators_with_malware_reference(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's get_indicators.
    Then
    - run the fetch incidents command using the Client
    Validate the connections in between the indicators
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_indicators', return_value=RESPONSE_DATA)
    indicators = fetch_indicators(client)
    for indicator in indicators:
        indicator_fields = indicator.get('fields')
        if indicator_fields.get('indicatoridentification') == 'indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be':
            assert set(indicator_fields.get('malwarefamily')) == set({'Muirim', 'Muirim2'})
            break
