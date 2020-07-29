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
    - mock the Client's get_stix_objects.
    Then
    - convert the result to human readable table
    - create the context
    validate the raw_response
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_stix_objects', return_value=response)
    command_results = command(client, args)
    indicators = command_results.raw_response
    assert len(indicators) == length


def test_fetch_indicators_command(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's get_stix_objects.
    Then
    - run the fetch incidents command using the Client
    Validate the amount of indicators fetched
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_stix_objects', return_value=RESPONSE_DATA)
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
    - mock the Client's get_stix_objects.
    Then
    - run the fetch incidents command using the Client
    Validate The value of the tags field.
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_stix_objects', return_value=RESPONSE_DATA)
    indicators = fetch_indicators(client, ['test_tag'])
    assert set(indicators[0].get('fields').get('tags')) == set({'malicious-activity', 'test_tag'})


def test_fetch_indicators_with_mitre_external_reference(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's get_stix_objects.
    Then
    - run the fetch incidents command using the Client
    Validate the connections in between the indicators
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_stix_objects', return_value=RESPONSE_DATA)
    indicators = fetch_indicators(client)
    for indicator in indicators:
        indicator_fields = indicator.get('fields')
        if indicator_fields.get('indicatoridentification') == 'indicator--010bb9ad-5686-485d-97e5-93c2187e56ce':
            assert indicator_fields.get('feedrelatedindicators') == {
                'type': 'MITRE ATT&CK',
                'value': ['T1047'],
                'description': [
                    'example.com',
                    'https://attack.mitre.org/techniques/T1047',
                    'https://msdn.microsoft.com/en-us/library/aa394582.aspx',
                    'https://technet.microsoft.com/en-us/library/cc787851.aspx',
                    'https://en.wikipedia.org/wiki/Server_Message_Block'
                ]
            }

            break


def test_fetch_indicators_with_malware_reference(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's get_stix_objects.
    Then
    - run the fetch incidents command using the Client
    Validate the connections in between the indicators
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'get_stix_objects', return_value=RESPONSE_DATA)
    indicators = fetch_indicators(client)
    for indicator in indicators:
        indicator_fields = indicator.get('fields')
        if indicator_fields.get('indicatoridentification') == 'indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be':
            assert set(indicator_fields.get('malwarefamily')) == set({'Muirim', 'Muirim2'})
            break
