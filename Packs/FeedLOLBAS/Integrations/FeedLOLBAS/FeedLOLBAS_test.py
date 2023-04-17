import json
import io

import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def mock_client():
    """
        Create a mock client for testing.
    """
    from FeedLOLBAS import Client
    return Client(
        base_url='https://example/api',
        verify=False,
        proxy=False,
        create_relationships=True,
        feed_tags=['tag1', 'tag2'],
        tlp_color='TEST',
    )


def test_parse_response():
    """
        Given: A response from the LOLBAS API.
        When: Parsing the response.
        Then: Ensure the response is parsed correctly.
    """
    from FeedLOLBAS import parse_response
    mock_response = util_load_json('test_data/response.json')
    expected_response = util_load_json('test_data/expected_parse_response.json')

    response = parse_response(mock_response.get('text'))
    assert response == expected_response


def test_create_indicators():
    """
        Given: A list of parsed indicators.
        When: Creating XSOAR indicators from the list.
        Then: Ensure the indicators are created correctly.
    """
    from FeedLOLBAS import create_indicators

    client = mock_client()
    mock_pre_indicators = util_load_json('test_data/expected_parse_response.json')
    expected_response = util_load_json('test_data/expected_create_indicators.json')

    response = create_indicators(client, mock_pre_indicators)
    assert response == expected_response


def test_create_relationship_list():
    """
        Given: A list of XSOAR indicators.
        When: Creating relationships between the indicators.
        Then: Ensure the relationships are created correctly.
    """
    from FeedLOLBAS import create_relationship_list
    mock_indicators = util_load_json('test_data/expected_create_indicators.json')
    expected_response = util_load_json('test_data/expected_create_relationships.json')

    response = create_relationship_list(mock_indicators)
    assert response == expected_response


def test_create_relationships():
    """
        Given: A list of XSOAR indicators.
        When: create_relationships enabled.
        Then: Ensure the relationship list are added correctly to the indicator list.
    """
    from FeedLOLBAS import create_relationships
    client = mock_client()
    mock_indicators = util_load_json('test_data/expected_create_indicators.json')
    expected_response = {'value': '$$DummyIndicator$$', 'relationships': [
        {'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': 'AppInstaller.exe',
         'entityAFamily': 'Indicator', 'entityAType': 'Tool', 'entityB': 'T1105', 'entityBFamily': 'Indicator',
         'entityBType': 'Attack Pattern', 'fields': {}},
        {'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': 'Aspnet_Compiler.exe',
         'entityAFamily': 'Indicator', 'entityAType': 'Tool', 'entityB': 'T1127', 'entityBFamily': 'Indicator',
         'entityBType': 'Attack Pattern', 'fields': {}}]}

    response = create_relationships(client, mock_indicators)
    relationship_indicator = response[2]
    assert relationship_indicator == expected_response


def test_fetch_indicators(mocker):
    """
        Given: A list of XSOAR indicators.
        When: Calling fetch-indicators command.
        Then: Ensure the indicators are fetched and created correctly.
    """
    from FeedLOLBAS import fetch_indicators
    client = mock_client()
    mocked_response = util_load_json('test_data/response.json').get('text')
    mocker.patch.object(client, 'get_indicators', return_value=mocked_response)
    expected_response = util_load_json('test_data/expected_fetch_indicators.json')

    response = fetch_indicators(client)
    assert response == expected_response


def test_create_relationship_list_no_mitre_id():
    """
        Given: A list of XSOAR indicators.
        When: Creating relationships between the indicators.
        Then: Ensure the relationships are created correctly.
    """
    from FeedLOLBAS import create_relationship_list
    mock_indicators = [{'value': 'test_indicator'}, {'value': 'test_indicator2', 'fields': {}}]

    response = create_relationship_list(mock_indicators)
    assert response == []


@pytest.mark.parametrize('pre_parsed_detections, expected',
                         [("", []), ("test", []), ("test1: test_detection, test2: test_detection",
                                                   [{'Type': 'test1', 'Content': ' test_detection'},
                                                    {'Type': ' test2', 'Content': ' test_detection'}])])
def test_parse_detections(pre_parsed_detections, expected):
    """
        Given: A list of detections.
        When: Parsing the detections.
        Then: Ensure the detections are parsed correctly.
    """
    from FeedLOLBAS import parse_detections

    response = parse_detections(pre_parsed_detections)
    assert response == expected
