import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from AHA import Client, get_features, get_feature, edit_feature
import pytest
import io


apikey = demisto.contentSecrets['AutoFocusTagsFeed']['api_key']

headers = {
    'Authorization': f"Bearer {apikey}",
}
BASE_URL = "https://paloalto-networks.aha.io/api/v1/"


def mock_client(mocker, http_request_result=None, throw_error=False):

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'current_refresh_token': 'refresh_token'})
    client = Client(headers=headers, base_url=BASE_URL, proxy=False, verify=False)
    if http_request_result:
        mocker.patch.object(client, '_http_request', return_value=http_request_result)

    if throw_error:
        err_msg = "Error in API call [400] - BAD REQUEST}"
        mocker.patch.object(client, '_http_request', side_effect=DemistoException(err_msg, res={}))

    return client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_getFeatures(mocker):
    """
        When:
            - Requesting all features
        Then:
            - Asserts get all features
    """
    client = mock_client(mocker, util_load_json('test_data/get_all_features.json'))
    results = get_features(client=client, fromDate="2022-01-01")
    assert len(results.outputs) == 30


def test_getFeaturesFromDate(mocker):
    """
        When:
            - Requesting all features with created date of the future
        Then:
            - Return en empty list
    """
    client = mock_client(mocker, util_load_json('test_data/empty_feature_result.json'))
    results = get_features(client=client, fromDate="3000-01-01")
    assert len(results.outputs) == 0


def test_getSpecificFeature(mocker):
    """
        When:
            - Requesting a specific feature
        Then:
            - Return the requested feature
    """
    client = mock_client(mocker, util_load_json('test_data/get_specific_feature.json'))
    result = get_feature(client=client, featureName="DEMO-10")
    assert result.outputs['reference_num'] == "DEMO-10"


def test_getSpecificFeatureWithSpecificFields(mocker):
    """
        When:
            - Requesting a specific feature with specific fields
        Then:
            - Return the requested feature with the specified fields
    """
    client = mock_client(mocker, util_load_json('test_data/get_specific_feature_specific_fields.json'))
    result = get_feature(client=client, featureName="DEMO-10", fieldsList=["workflow_status", "name"])
    if "reference_num" in result.outputs:
        pytest.fail("There should NOT be a reference_num field in output.")
    assert result.outputs['name'] == "Push based weather alerts"


def test_updateFeatureField(mocker):
    """
        When:
            - Requesting to update fields in a feautre.
        Then:
            - Return the feature with updated fields.
    """
    client = mock_client(mocker, util_load_json('test_data/update_feature_fields.json'))
    result = edit_feature(client=client, featureName="DEMO-10", fields={"name": "DEMO-10", "description": "new description",
                          "status": "Closed"})
    assert result.outputs['name'] == "DEMO-10"
    assert result.outputs['description']['body'] == "new description"
    assert result.outputs['workflow_status']['name'] == "Closed"
