import json

import pytest

from CommonServerPython import DemistoException, CommandResults, FeedIndicatorType

SOCRADAR_API_ENDPOINT = 'https://platform.socradar.com/api'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(requests_mock):
    """Tests the test_module validation command.
    """
    from FeedSOCRadarThreatFeed import Client, test_module

    mock_socradar_api_key = "APIKey"
    auth_suffix = f'threat/intelligence/check/auth?key={mock_socradar_api_key}'
    mock_response = util_load_json('test_data/check_auth_response.json')
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{auth_suffix}', json=mock_response)

    collection_name_list = ['MockCollectionName']
    indicator_suffix = f'threat/intelligence/socradar_collections?key={mock_socradar_api_key}' \
                       f'&collection_names={collection_name_list[0]}' \
                       f'&limit=1' \
                       f'&offset=0'
    mock_response = util_load_json('test_data/get_indicators_response.json')
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{indicator_suffix}', json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="",
        tags="",
        verify=False,
        proxy=False
    )

    response = test_module(client, collection_name_list)

    assert response == 'ok'


def test_test_module_handles_authorization_error(requests_mock):
    """Tests the test_module validation command authorization error.
    """
    from FeedSOCRadarThreatFeed import Client, test_module, MESSAGES

    mock_socradar_api_key = "WrongAPIKey"
    suffix = f'threat/intelligence/check/auth?key={mock_socradar_api_key}'
    mock_response = util_load_json('test_data/check_auth_response_auth_error.json')
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response, status_code=401)
    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="",
        tags="",
        verify=False,
        proxy=False
    )
    with pytest.raises(DemistoException, match=MESSAGES['AUTHORIZATION_ERROR']):
        test_module(client, [])


def test_fetch_indicators(requests_mock):
    """Tests the fetch-indicators function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar Threat Intelligence Collections API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from FeedSOCRadarThreatFeed import Client, fetch_indicators

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/fetch_indicators_response.json')
    suffix = f'threat/intelligence/socradar_collections?key={mock_socradar_api_key}' \
             f'&collection_names=MockCollectionName'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False
    )

    collections_to_fetch = ['MockCollectionName']

    indicators = fetch_indicators(
        client=client,
        collections_to_fetch=collections_to_fetch,
        limit=1
    )

    expected_output = util_load_json('test_data/fetch_indicators_expected_output.json')

    assert indicators == expected_output
    assert len(indicators) == 1


def test_fetch_indicators_handles_error(requests_mock):
    """Tests the fetch_indicators function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar SOCRadar Threat Intelligence Collections API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from FeedSOCRadarThreatFeed import Client, fetch_indicators

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/fetch_indicators_response_error.json')
    suffix = f'threat/intelligence/socradar_collections?key={mock_socradar_api_key}' \
             f'&collection_names=MockCollectionName'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False
    )

    collections_to_fetch = ['MockCollectionName']
    indicators = fetch_indicators(
        client=client,
        collections_to_fetch=collections_to_fetch,
        limit=1
    )
    assert len(indicators) == 0


def test_get_indicators_command(requests_mock):
    """Tests the get_indicators_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar Threat Intelligence Collections API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from FeedSOCRadarThreatFeed import Client, get_indicators_command

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/get_indicators_response.json')
    suffix = f'threat/intelligence/socradar_collections?key={mock_socradar_api_key}' \
             f'&collection_names=MockCollectionName'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False
    )

    mock_args = {
        'limit': 1,
        'collections_to_fetch': 'MockCollectionName'
    }

    result = get_indicators_command(client, mock_args)

    expected_output = util_load_json('test_data/get_indicators_expected_output.json')
    expected_context = util_load_json('test_data/get_indicators_expected_context.json')

    assert isinstance(result, CommandResults)
    assert 'Indicators from SOCRadar ThreatFeed Collections (MockCollectionName):' in result.readable_output
    assert result.outputs == expected_context
    assert result.raw_response == expected_output


def test_get_indicators_command_handles_error(requests_mock):
    """Tests the get_indicators_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar SOCRadar Threat Intelligence Collections API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from FeedSOCRadarThreatFeed import Client, get_indicators_command

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/get_indicators_response_error.json')
    suffix = f'threat/intelligence/socradar_collections?key={mock_socradar_api_key}' \
             f'&collection_names=MockCollectionName'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        tlp_color="GREEN",
        tags=["TEST"],
        verify=False,
        proxy=False
    )
    mock_args = {
        'limit': 1,
        'collections_to_fetch': 'MockCollectionName'
    }
    result = get_indicators_command(client, mock_args)
    assert isinstance(result, CommandResults)
    assert len(result.outputs) == 0


def test_date_string_to_iso_format_parsing():
    """Tests the date_string_to_iso_format_parsing function.
    """
    from FeedSOCRadarThreatFeed import date_string_to_iso_format_parsing

    mock_date_str = "1111-11-11 11:11:11"
    formatted_date = date_string_to_iso_format_parsing(mock_date_str)

    assert formatted_date


def test_build_entry_context():
    """Tests the build_entry_context function.
    """
    from FeedSOCRadarThreatFeed import build_entry_context

    mock_indicators = util_load_json('test_data/build_entry_context_input.json')
    context_entry = build_entry_context(mock_indicators)
    expected_context_entry = util_load_json('test_data/build_entry_context_expected_entry.json')

    assert context_entry == expected_context_entry


def test_reset_last_fetch_dict():
    """Tests the reset_last_fetch_dict function.
    """
    from FeedSOCRadarThreatFeed import reset_last_fetch_dict

    result = reset_last_fetch_dict()

    assert isinstance(result, CommandResults)
    assert 'Fetch history has been successfully deleted!' in result.readable_output


CONVERT_DEMISTO_INDICATOR_TYPE_INPUTS = [
    ('hostname', FeedIndicatorType.Domain), ('url', FeedIndicatorType.URL), ('ip', FeedIndicatorType.IP),
    ('hash', FeedIndicatorType.File)
]


@pytest.mark.parametrize('socradar_indicator_type, demisto_indicator_type', CONVERT_DEMISTO_INDICATOR_TYPE_INPUTS)
def test_convert_to_demisto_indicator_type(socradar_indicator_type, demisto_indicator_type):
    from FeedSOCRadarThreatFeed import convert_to_demisto_indicator_type

    assert convert_to_demisto_indicator_type(socradar_indicator_type) == demisto_indicator_type
