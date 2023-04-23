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
        verify=False,
        proxy=False,
        create_relationships=True,
        feed_tags=['tag1', 'tag2'],
        tlp_color='TEST',
    )


def test_create_indicators():
    """
        Given: A list of parsed indicators.
        When: Creating XSOAR indicators from the list.
        Then: Ensure the indicators are created correctly.
    """
    from FeedLOLBAS import create_indicators

    client = mock_client()
    mock_pre_indicators = util_load_json('test_data/response.json')
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
    mocked_response = util_load_json('test_data/response.json')
    mocker.patch.object(client, 'get_indicators', return_value=mocked_response)
    expected_response = util_load_json('test_data/expected_fetch_indicators.json')

    response, _ = fetch_indicators(client)
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


def test_negative_limit():
    """
        Given: A negative limit.
        When: Calling get_indicators.
        Then: Ensure ValueError is raised with the right message.
    """
    from FeedLOLBAS import get_indicators
    limit = -1
    client = mock_client()

    with pytest.raises(ValueError) as ve:
        get_indicators(client, limit)
    assert ve.value.args[0] == "Limit must be a positive number."


def test_get_indicators(mocker):
    """
        Given:
    """
    from FeedLOLBAS import get_indicators
    client = mock_client()
    limit = 1
    mocked_response = util_load_json('test_data/response.json')
    mocker.patch.object(client, 'get_indicators', return_value=mocked_response)
    expected_outputs = util_load_json('test_data/expected_get_indicators_outputs.json')
    expected_hr = '### LOLBAS indicators\n|Name|Description|' \
                  '\n|---|---|\n| AppInstaller.exe | Tool used for installation of AppX/MSIX applications on Windows 10 |\n'

    res = get_indicators(client, limit)

    assert len(res.outputs) == 1
    assert res.outputs == [expected_outputs]
    assert res.readable_output == expected_hr
