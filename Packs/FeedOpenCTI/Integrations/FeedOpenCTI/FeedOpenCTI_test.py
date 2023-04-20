from FeedOpenCTI import get_indicators_command, fetch_indicators_command, get_indicators
from test_data.feed_data import RESPONSE_DATA, RESPONSE_DATA_WITHOUT_INDICATORS
from CommonServerPython import CommandResults
from pycti import StixCyberObservable


class StixObservable:
    def list(self):
        return self


class Client:
    temp = ''
    stix_cyber_observable = StixCyberObservable


def test_get_indicators(mocker):
    """Tests get_indicators function
    Given
        The following indicator types: 'registry-key-value', 'user-account' that were chosen by the user.
    When
        - `fetch_indicators_command` or `get_indicators_command` are calling the get_indicators function
    Then
        - convert the result to indicators list
        - validate the length of the indicators list
        - validate the new_last_id that is saved into the integration context is the same as the ID returned by the
            command.
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA)
    new_last_id, indicators = get_indicators(client, indicator_type=['registry-key-value', 'user-account'], limit=10)
    assert len(indicators) == 2
    assert new_last_id == 'YXJyYXljb25uZWN0aW9uOjI='


def test_fetch_indicators_command(mocker):
    """Tests fetch_indicators_command function
    Given
        The following indicator types: 'registry-key-value', 'user-account' that were chosen by the user.
    When
        - Calling `fetch_indicators_command`
    Then
        - convert the result to indicators list
        - validate the length of the indicators list
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA)
    indicators = fetch_indicators_command(client, indicator_type=['registry-key-value', 'user-account'], max_fetch=200)
    assert len(indicators) == 2


def test_get_indicators_command(mocker):
    """Tests get_indicators_command function
    Given
        The following indicator types: 'registry-key-value', 'user-account' that were chosen by the user and 'limit': 2
    When
        - Calling `get_indicators_command`
    Then
        - convert the result to human readable table
        - validate the readable_output, raw_response.
    """
    client = Client
    args = {
        'indicator_types': 'registry-key-value,user-account',
        'limit': 2
    }
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA)
    results: CommandResults = get_indicators_command(client, args)
    assert len(results.raw_response) == 2
    assert "Indicators from OpenCTI" in results.readable_output


def test_get_indicators_command_with_no_data_to_return(mocker):
    """Tests get_indicators_command function with no data to return
    Given
        The following indicator types: 'registry-key-value', 'user-account' that were chosen by the user.
    When
        - Calling `get_indicators_command`
    Then
        - validate the response to have a "No indicators" string
    """
    client = Client
    args = {
        'indicator_types': ['registry-key-value', 'user-account']
    }
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_WITHOUT_INDICATORS)
    results: CommandResults = get_indicators_command(client, args)
    assert "No indicators" in results.readable_output
