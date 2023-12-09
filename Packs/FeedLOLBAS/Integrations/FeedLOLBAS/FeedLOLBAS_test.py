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
        base_url="example.com",
        verify=False,
        proxy=False,
        create_relationships=True,
        feed_tags=['tag1', 'tag2'],
        tlp_color='TEST',
    )


def test_build_indicators(mocker):
    """
        Given: A list of parsed indicators.
        When: Creating XSOAR indicators from the list.
        Then: Ensure the indicators are created correctly.
    """
    from FeedLOLBAS import build_indicators

    client = mock_client()
    mock_pre_indicators = util_load_json('test_data/response.json')
    expected_response = util_load_json('test_data/expected_build_indicators.json')
    mocked_mitre_data = util_load_json('test_data/mocked_mitre_data.json')
    mocker.patch.object(client, 'get_mitre_data', return_value=mocked_mitre_data)

    response = build_indicators(client, mock_pre_indicators)
    assert response == expected_response


def test_create_relationship_list(mocker):
    """
        Given: A list of XSOAR indicators.
        When: Creating relationships between the indicators.
        Then: Ensure the relationships are created correctly.
    """
    from FeedLOLBAS import create_relationship_list
    mock_indicators = util_load_json('test_data/expected_build_indicators.json')
    expected_response = util_load_json('test_data/expected_create_relationships.json')
    mocked_mitre_data = util_load_json('test_data/mocked_mitre_data.json')
    mocker.patch('FeedLOLBAS.build_mitre_tags', return_value=mocked_mitre_data)
    res = []
    for indicator in mock_indicators:
        res.append(create_relationship_list(indicator))
    assert res == expected_response


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
    mocked_mitre_data = util_load_json('test_data/mocked_mitre_data.json')
    mocker.patch.object(client, 'get_mitre_data', return_value=mocked_mitre_data)
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
    result = []
    for indicator in mock_indicators:
        response = create_relationship_list(indicator)
        if response:
            result.append(response)
    assert result == []


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
        Given: response from LOLBas api.
        When: Calling get_indicators.
        Then: Verify that the returned indicators are limited and that the output/hr is the expected one.
    """
    from FeedLOLBAS import get_indicators
    client = mock_client()
    limit = 1
    mocked_response = util_load_json('test_data/response.json')
    mocker.patch.object(client, 'get_indicators', return_value=mocked_response)
    mocked_mitre_data = util_load_json('test_data/mocked_mitre_data.json')
    mocker.patch.object(client, 'get_mitre_data', return_value=mocked_mitre_data)
    expected_outputs = util_load_json('test_data/expected_get_indicators_outputs.json')
    expected_hr = '### LOLBAS indicators\n|Name|Description|\n|---|---|\n' \
                  '| AppInstaller.exe | Tool used for installation of AppX/MSIX applications on Windows 10 |\n'
    res = get_indicators(client, limit)

    assert len(res.outputs) == 1
    assert res.outputs == expected_outputs
    assert res.readable_output == expected_hr
