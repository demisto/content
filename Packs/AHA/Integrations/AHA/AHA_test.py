import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401
from AHA import Client, get_command, edit_command
from AHA import AHA_TYPE


headers = {
    'Authorization': 'Bearer test_key',
}
BASE_URL = 'https://example.com.aha.io/api/v1/'


def mock_client(mocker, http_request_result=None, throw_error=False):

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'current_refresh_token': 'refresh_token'})
    client = Client(headers=headers, base_url=BASE_URL, proxy=False, verify=False, url='DEMO')
    if http_request_result:
        mocker.patch.object(client, '_http_request', return_value=http_request_result)

    if throw_error:
        err_msg = 'Error in API call [400] - BAD REQUEST}'
        mocker.patch.object(client, '_http_request', side_effect=DemistoException(err_msg, res={}))

    return client


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_main(mocker):
    """
    Given:
        - All return values from helper functions are valid
    When:
        - main function test-module is executed
    Then:
        - Return ok result to War-Room
    """
    from AHA import main

    mocker.patch.object(
        demisto, 'params', return_value={
            'url': 'example.com',
            'project_name': 'DEMO',
            'api_key': {'password': 'test_api'},
        }
    )
    mocker.patch('AHA.Client.get', return_value={'name': 'test'})
    mocker.patch.object(
        demisto, 'command',
        return_value='test-module'
    )
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == 'ok'


def test_notImplementedCommand(mocker):
    """
    Given:
        - All return values from helper functions are valid
    When:
        - Calling main function with invalid command
    Then:
        - Return sys.exit(0)
    """
    from AHA import main

    mocker.patch.object(
        demisto, 'params', return_value={
            'url': 'example.com',
            'project_name': 'DEMO',
            'api_key': {'password': 'test_api'},
        }
    )
    mocker.patch('AHA.Client.get', return_value={'name': 'test'})
    mocker.patch.object(
        demisto, 'command',
        return_value='tests-module'
    )
    mocker.patch.object(demisto, 'results')
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        main()
    assert pytest_wrapped_e.type is SystemExit
    assert pytest_wrapped_e.value.code == 0


def test_Module(mocker):
    """
    Given:
        - client is properly configured
    When:
        - calling test-module
    Then:
        - Return ok result
    """
    from AHA import test_module
    client = mock_client(mocker, util_load_json('test_data/get_all_features.json'))
    results = test_module(client=client)
    assert results == 'ok'


def test_getFeatures(mocker):
    """
        When:
            - Requesting all features
        Then:
            - Asserts get a list of expected length with all features.
    """
    client = mock_client(mocker, util_load_json('test_data/get_all_features.json'))
    results = get_command(client=client, aha_type=AHA_TYPE.FEATURES, from_date='2022-01-01')
    assert len(results.outputs) == 3
    assert len(results.outputs[0].get('ideas')) == 1
    assert results.outputs[0].get('ideas')[0] == 'DEMO-I-299'


def test_getIdeas(mocker):
    """
        When:
            - Requesting all ideas
        Then:
            - Asserts get a list of expected length with all ideas.
    """
    client = mock_client(mocker, util_load_json('test_data/get_all_ideas.json'))
    results = get_command(client=client, aha_type=AHA_TYPE.IDEAS, from_date='2022-01-01')
    assert len(results.outputs) == 4


@pytest.mark.parametrize('file_path, aha_type, from_date',
                         [('test_data/empty_feature_result.json', AHA_TYPE.FEATURES, '3000-01-01'),
                          ('test_data/empty_idea_result.json', AHA_TYPE.IDEAS, '3000-01-01')])
def test_getFeaturesFromDate(mocker, file_path, aha_type, from_date):
    """
        When:
            - Requesting all features with created date of the future
        Then:
            - Return en empty list
    """
    client = mock_client(mocker, util_load_json(file_path))
    results = get_command(client=client, aha_type=aha_type, from_date=from_date)
    assert len(results.outputs) == 0


def test_getAFeature(mocker):
    """
        When:
            - Requesting a specific feature
        Then:
            - Returns the requested feature
    """
    client = mock_client(mocker, util_load_json('test_data/get_specific_feature.json'))
    result = get_command(client=client, aha_type=AHA_TYPE.FEATURES, from_date='2020-01-01', aha_object_name='DEMO-10')
    assert len(result.outputs) == 1
    assert result.outputs[0]['reference_num'] == 'DEMO-10'


def test_getAnIdea(mocker):
    """
        When:
            - Requesting a specific idea
        Then:
            - Returns the requested idea
    """
    client = mock_client(mocker, util_load_json('test_data/get_specific_idea.json'))
    result = get_command(client=client, aha_type=AHA_TYPE.IDEAS, from_date='2020-01-01', aha_object_name='DEMO-I-2895')
    assert len(result.outputs) == 1
    assert result.outputs[0]['reference_num'] == 'DEMO-I-2895'


def test_editFeatureField(mocker):
    """
        When:
            - Requesting to update fields in a feature.
        Then:
            - Return the feature with updated fields.
    """
    client = mock_client(mocker, util_load_json('test_data/update_feature_fields.json'))
    result = edit_command(client=client, aha_type=AHA_TYPE.FEATURES, aha_object_name='DEMO-10',
                          fields='{"name": "DEMO-10", "description": "new description", "status": "Closed"}')
    assert len(result.outputs) == 1
    output = result.outputs[0]
    assert output.get('name') == 'Demo-10'
    assert output.get('description') == 'test desc'
    assert output.get('workflow_status') == 'Closed'


def test_editIdeaStatus(mocker):
    """
        When:
            - Requesting to update status in an idea.
        Then:
            - Return the idea with an updated field.
    """
    client = mock_client(mocker, util_load_json('test_data/update_idea_status.json'))
    result = edit_command(client=client, aha_type=AHA_TYPE.IDEAS, aha_object_name='DEMO-I-2895', fields='{}')
    assert len(result.outputs) == 1
    output = result.outputs[0]
    assert output.get('name') == '[Test] Mirroring'
    assert output.get('description') == 'Aha Jira Mirroring'
    assert output.get('workflow_status') == 'Shipped'


def test_editSpecificFeatureField(mocker):
    """
        When:
            - Requesting to update a specific field in a feature.
        Then:
            - Return the feature with only the specific field updated.
    """
    new_name = 'change just name'
    client = mock_client(mocker, util_load_json('test_data/update_feature_field.json'))
    result = edit_command(client=client, aha_type=AHA_TYPE.FEATURES, aha_object_name='DEMO-10',
                          fields=f'{{"description": "{new_name}"}}')
    assert len(result.outputs) == 1
    output = result.outputs[0]
    assert output.get('name') == new_name
    assert output.get('description') == 'description'
    assert output.get('workflow_status') == 'Closed'
