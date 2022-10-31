import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from AHA import Client, get_features, edit_feature
import io


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
    with io.open(path, mode='r', encoding='utf-8') as f:
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
    mocker.patch('AHA.Client.get_features', return_value={'name': 'test'})
    mocker.patch.object(
        demisto, 'command',
        return_value='test-module'
    )
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == 'ok'


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
    results = get_features(client=client, from_date='2022-01-01')
    assert len(results.outputs) == 3


def test_getFeaturesFromDate(mocker):
    """
        When:
            - Requesting all features with created date of the future
        Then:
            - Return en empty list
    """
    client = mock_client(mocker, util_load_json('test_data/empty_feature_result.json'))
    results = get_features(client=client, from_date='3000-01-01')
    assert len(results.outputs) == 0


def test_getSpecificFeature(mocker):
    """
        When:
            - Requesting a specific feature
        Then:
            - Returns the requested feature
    """
    client = mock_client(mocker, util_load_json('test_data/get_specific_feature.json'))
    result = get_features(client=client, from_date='2020-01-01', feature_name='DEMO-10')
    assert len(result.outputs) == 1
    assert result.outputs[0]['reference_num'] == 'DEMO-10'


def test_editFeatureField(mocker):
    """
        When:
            - Requesting to update fields in a feautre.
        Then:
            - Return the feature with updated fields.
    """
    client = mock_client(mocker, util_load_json('test_data/update_feature_fields.json'))
    result = edit_feature(client=client, feature_name='DEMO-10', fields={'name': 'DEMO-10', 'description': 'new description',
                          'status': 'Closed'})
    assert len(result.outputs) == 1
    output = result.outputs[0]
    assert output.get('name') == 'Demo-10'
    assert output.get('description') == 'test desc'
    assert output.get('workflow_status') == 'Closed'


def test_editSpecificFeatureField(mocker):
    """
        When:
            - Requesting to update a specific field in a feautre.
        Then:
            - Return the feature with only the specific field updated.
    """
    new_description = 'change just description'
    client = mock_client(mocker, util_load_json('test_data/update_feature_field.json'))
    result = edit_feature(client=client, feature_name='DEMO-10', fields={'description': new_description})
    assert len(result.outputs) == 1
    output = result.outputs[0]
    assert output.get('name') == 'Demo-10'
    assert output.get('description') == new_description
    assert output.get('workflow_status') == 'Closed'
