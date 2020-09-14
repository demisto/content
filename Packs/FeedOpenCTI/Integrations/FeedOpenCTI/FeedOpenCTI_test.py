import pytest
from FeedOpenCTI import get_indicators_command, fetch_indicators_command, get_indicators
from test_data.feed_data import RESPONSE_DATA, RESPONSE_DATA_WITHOUT_INDICATORS
from CommonServerPython import CommandResults


class StiObservable:
    def list(self):
        return self


class Client:
    temp = ''
    stix_observable = StiObservable


def test_get_indicators(mocker):
    """Tests get_indicators function
    Given
        'indicator_types': ['value', 'user-account']
    When
        - `fetch_indicators_command` or `fetch_indicators_command` are calling the get_indicators function
    Then
        - convert the result to indicators list
        - validate the the indicators list
        - validate the the new_last_id to set
    """
    client = Client
    mocker.patch.object(client.stix_observable, 'list', return_value=RESPONSE_DATA)
    new_last_id, indicators = get_indicators(client, indicator_type=['value', 'user-account'])
    assert len(indicators) == 2
    assert new_last_id == 'YXJyYXljb25uZWN0aW9uOjI='


def test_fetch_indicators_command(mocker):
    """Tests fetch_indicators_command function
    Given
        'indicator_types': ['value', 'user-account']
    When
        - Calling `fetch_indicators_command`
    Then
        - convert the result to indicators list
        - validate the the indicators list
    """
    client = Client
    mocker.patch.object(client.stix_observable, 'list', return_value=RESPONSE_DATA)
    indicators = fetch_indicators_command(client, indicator_type=['value', 'user-account'])
    assert len(indicators) == 2


def test_get_indicators_command(mocker):
    """Tests get_indicators_command function
    Given
        'indicator_types': ['value', 'user-account'], 'limit': 2
    When
        - Calling `get_indicators_command`
    Then
        - convert the result to human readable table
        - validate the readable_output, raw_response.
    """
    client = Client
    args = {
        'indicator_types': ['value', 'user-account'],
        'limit': 2
    }
    mocker.patch.object(client.stix_observable, 'list', return_value=RESPONSE_DATA)
    results: CommandResults = get_indicators_command(client, args)
    assert len(results.raw_response) == 2
    assert "Indicators from OpenCTI" in results.readable_output


def test_get_indicators_command_with_no_data_to_return(mocker):
    """Tests get_indicators_command function with no data to return
    Given
        'indicator_types': ['value', 'user-account'], 'limit': 2
    When
        - Calling `get_indicators_command`
    Then
        - validate it returns that there are no indicators
    """
    client = Client
    args = {
        'indicator_types': ['value', 'user-account'],
        'limit': 2
    }
    mocker.patch.object(client.stix_observable, 'list', return_value=RESPONSE_DATA_WITHOUT_INDICATORS)
    results: CommandResults = get_indicators_command(client, args)
    assert "No indicators" in results.readable_output
