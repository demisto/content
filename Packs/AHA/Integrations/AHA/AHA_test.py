import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from AHA import Client, get_all_features
import io

# TODO create mock tests should be statless 
# 

apikey = ""
headers = {
    'Authorization': f"Bearer {apikey}",
}
base_url = "https://paloalto-networks.aha.io/api/v1/"
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


#TODO change name 
# TODO this is an example of how to work with mock 
def test_check_the_status_of_an_action_requested_on_a_case_command(mocker):
    """
        When:
            - Checking status of an action request on a case
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/get_features.json'))
    results = get_all_features(client, "2022-01-01")
    assert len(results.outputs) > 0


def test_getFeatures():
    client = Client(headers=headers, base_url=base_url, proxy=False, verify=False)
    result = client.list_features()
    assert len(result['features']) > 0
    result


def test_getFeaturesFromDate():
    client = Client(headers=headers, base_url=base_url, proxy=False, verify=False)
    result = client.list_features("2023-09-12")
    assert len(result['features']) == 0


def test_getSpecificFeature():
    client = Client(headers=headers, base_url=base_url, proxy=False, verify=False)
    result = client.get_feature("DEMO-10")
    assert result['feature']['reference_num'] == "DEMO-10"


def test_updateFeatureField():
    client = Client(headers=headers, base_url=base_url, proxy=False, verify=False)
    fields = {"score": 29, "workflow_status": {"name": "Closed"}}
    result = client.update_feature(featureName="DEMO-36", fields=fields)
    assert result['feature']['reference_num'] == "DEMO-36"
    assert result['feature']['workflow_status']['name'] == "Closed"
