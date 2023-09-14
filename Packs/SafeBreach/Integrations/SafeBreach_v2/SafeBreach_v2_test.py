import json
import pytest
import demistomock as demisto
from CommonServerPython import *
from SafeBreach_v2 import get_insights_command, get_remediation_data_command, rerun_simulation_command, \
    get_safebreach_simulation_command, get_indicators_command, insight_rerun_command, Client

MOCK_URL = "https://safebreach-fake-api.com"
MOCK_ACCOUNT_ID = '1234567'
MOCK_API_KEY = 'a1b2c3d4e5'
INSIGHT_ID = '9'
SIMULATION_ID = '8fae303defd52a7745044ce2ba54a391'

client = Client(
    base_url=MOCK_URL,
    api_key=MOCK_API_KEY,
    account_id=MOCK_ACCOUNT_ID,
    proxies=handle_proxy(),
    verify=False,
    tags=['tag1', 'tag2'],
)


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


REMEDATION_DATA_LIST = load_test_data('./test_data/remediation_data.json')
GET_INSIGHTS_LIST = load_test_data('./test_data/insights.json')
SIMULATION = load_test_data('./test_data/simulation.json')
NODES = load_test_data('./test_data/nodes.json')
REMEDATION_DATA_LIST_UNVAILD_STRING = load_test_data('./test_data/remediation_data_with_unvaild_string.json')


def test_get_insights(requests_mock, mocker):
    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights?type=actionBased',
                      json=GET_INSIGHTS_LIST)
    requests_mock.get(
        f'{MOCK_URL}/api/config/v1/accounts/{MOCK_ACCOUNT_ID}/nodes?details=true&deleted=true&assets=true',
        json=NODES)
    mocker.patch.object(demisto, 'args', return_value={'insightIds': [9]})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': MOCK_URL})

    res = get_insights_command(client, demisto.args(), True)
    assert demisto.results.call_count == 1
    outputs = demisto.results.call_args[0][0]
    context = outputs['EntryContext']
    fake_safebreach_context = {
        "Id": 9,
        "Category": 'Endpoint',
        "Severity": "High"
    }

    assert fake_safebreach_context['Id'] == context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Id']
    assert fake_safebreach_context['Category'] == context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Category']
    assert fake_safebreach_context['Severity'] == context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Severity']
    assert len(res) == 1


def test_get_remediation_data(requests_mock, mocker):
    mocker.patch.object(demisto, 'args', return_value={'insightId': INSIGHT_ID})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': MOCK_URL})

    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights?type=actionBased',
                      json=GET_INSIGHTS_LIST)
    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights/{INSIGHT_ID}/remediation',
                      json=REMEDATION_DATA_LIST)
    requests_mock.get(
        f'{MOCK_URL}/api/config/v1/accounts/{MOCK_ACCOUNT_ID}/nodes?details=true&deleted=true&assets=true',
        json=NODES)
    get_remediation_data_command(client, demisto.args(), True)
    assert demisto.results.call_count == 1
    outputs = demisto.results.call_args[0][0]
    context = outputs['EntryContext']
    sha256_to_check = '109c702578b261d0eda01506625423f5a2b8cc107b0d8dfad84d39fb02bfa5cb'
    assert context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Id'] == INSIGHT_ID
    assert context['SafeBreach.Insight(val.Id == obj.Id)'][0]['RawRemediationData'][0]['type'] == 'SHA256'
    assert context['SafeBreach.Insight(val.Id == obj.Id)'][0]['RawRemediationData'][0]['value'] == sha256_to_check
    assert context['File(val.SHA256 == obj.SHA256)'][0]['SHA256'] == sha256_to_check
    assert context['DBotScore(val.Indicator == obj.Indicator)'][0]['Indicator'] == sha256_to_check


def test_rerun_insight(requests_mock, mocker):
    mocker.patch.object(demisto, 'args', return_value={'insightIds': '9'})
    mocker.patch.object(demisto, 'results')

    response = {
        "data": {
            "name": "Insight (XSOAR) - Test",
            "moveIds": [
                1,
                2,
                3,
                4,
            ],
            "nodeIds": ['nodeID1', 'nodeID2'],
            "draft": False,
            "ranBy": -1,
            "ranFrom": "UI",
            "isRerun": True,
            "assetIds": [],
            "moveSetIds": [],
            "force": True,
            "queueId": 107,
            "runId": "1584966046845.34",
            "pauseDuration": 0,
            "pausePeriods": [],
            "totalJobs": 0
        }
    }
    requests_mock.post(f'{MOCK_URL}/api/orch/v1/accounts/{MOCK_ACCOUNT_ID}/queue',
                       json=response)
    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights?type=actionBased',
                      json=GET_INSIGHTS_LIST)
    insight_rerun_command(client, demisto.args())
    assert demisto.results.call_count == 1
    outputs = demisto.results.call_args[0][0]
    context = outputs['EntryContext']
    assert context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Id'] == int(INSIGHT_ID)
    assert context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Rerun'][0]['Id'] == response['data']['runId']


def test_get_indicators(requests_mock, mocker):
    mocker.patch.object(demisto, 'args', return_value={'limit': '10'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': MOCK_URL})

    for insight_id in [5, 6, 8, 9, 13, 14, 17]:
        requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights/{insight_id}/remediation',
                          json=REMEDATION_DATA_LIST)

    requests_mock.get(
        f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights?type=actionBased',
        json=GET_INSIGHTS_LIST)
    requests_mock.get(
        f'{MOCK_URL}/api/config/v1/accounts/{MOCK_ACCOUNT_ID}/nodes?details=true&deleted=true&assets=true',
        json=NODES)
    insight_category = ['Endpoint', 'Web']
    insight_data_type = ['Hash', 'Domain']
    hash_to_search = '109c702578b261d0eda01506625423f5a2b8cc107b0d8dfad84d39fb02bfa5cb'
    res = get_indicators_command(client, insight_category, insight_data_type, 'AMBER', demisto.args())
    assert demisto.results.call_count == 0
    assert res[0]['value'] == hash_to_search
    assert res[0]['type'] == 'File'


def test_get_indicators_exception(requests_mock, mocker):
    mocker.patch.object(demisto, 'args', return_value={'limit': '10'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': MOCK_URL})

    for insight_id in [5, 6, 8, 9, 13, 14, 17]:
        requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights/{insight_id}/remediation',
                          json=REMEDATION_DATA_LIST_UNVAILD_STRING)

    requests_mock.get(
        f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights?type=actionBased',
        json=GET_INSIGHTS_LIST)
    requests_mock.get(
        f'{MOCK_URL}/api/config/v1/accounts/{MOCK_ACCOUNT_ID}/nodes?details=true&deleted=true&assets=true',
        json=NODES)
    insight_category = ['Endpoint', 'Web']
    insight_data_type = ['Hash', 'Domain']
    hash_to_search = '0000000000000000000000000000000000000000000000000000000000000000'
    res = get_indicators_command(client, insight_category, insight_data_type, 'AMBER', demisto.args())
    assert demisto.results.call_count == 0
    assert res[0]['value'] == hash_to_search
    assert res[0]['type'] == 'File'


def test_get_simulation(requests_mock, mocker):
    mocker.patch.object(demisto, 'args', return_value={'simulationId': SIMULATION_ID})
    mocker.patch.object(demisto, 'results')

    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/executions/{SIMULATION_ID}',
                      json=SIMULATION)

    get_safebreach_simulation_command(client, demisto.args())
    assert demisto.results.call_count == 1
    outputs = demisto.results.call_args[0][0]
    context = outputs['EntryContext']
    assert context['SafeBreach.Simulation(val.Id == obj.Id)']['Id'] == SIMULATION_ID


def test_rerun_simulation(requests_mock, mocker):
    mocker.patch.object(demisto, 'args', return_value={'simulationId': SIMULATION_ID})
    mocker.patch.object(demisto, 'results')
    response = {
        "data": {
            "name": "Rerun (Demisto) - Simulation",
            "moveIds": [
                1,
                2,
                3,
                4,
            ],
            "nodeIds": ['nodeID1', 'nodeID2'],
            "draft": False,
            "ranBy": -1,
            "ranFrom": "UI",
            "isRerun": True,
            "assetIds": [],
            "moveSetIds": [],
            "force": True,
            "queueId": 107,
            "runId": "1584966046845.34",
            "pauseDuration": 0,
            "pausePeriods": [],
            "totalJobs": 0
        }
    }
    requests_mock.post(f'{MOCK_URL}/api/orch/v1/accounts/{MOCK_ACCOUNT_ID}/queue',
                       json=response)
    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/executions/{SIMULATION_ID}',
                      json=SIMULATION)
    rerun_simulation_command(client, demisto.args())
    assert demisto.results.call_count == 1
    outputs = demisto.results.call_args[0][0]
    context = outputs['EntryContext']
    assert context['SafeBreach.Simulation(val.Id == obj.Id)']['Id'] == SIMULATION_ID
    assert context['SafeBreach.Simulation(val.Id == obj.Id)']['Rerun']['Id'] == response['data']['runId']


@pytest.mark.parametrize('tlp_color', ['', None, 'AMBER'])
def test_feed_tags_and_tlp_color(requests_mock, mocker, tlp_color):
    """
    Given:
    - client which has tag params
    - different values for tlp_color
    When:
    - Executing get indicators command on feed
    Then:
    - Validate the tags supplied are added to the tags list in addition to the tags that were there before
    - Validate that trafficlightprotocol indicator type is assigned correctly
    """
    mocker.patch.object(demisto, 'args', return_value={'limit': '10'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value={'url': MOCK_URL})

    for insight_id in [5, 6, 8, 9, 13, 14, 17]:
        requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights/{insight_id}/remediation',
                          json=REMEDATION_DATA_LIST)

    requests_mock.get(
        f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights?type=actionBased',
        json=GET_INSIGHTS_LIST)
    requests_mock.get(
        f'{MOCK_URL}/api/config/v1/accounts/{MOCK_ACCOUNT_ID}/nodes?details=true&deleted=true&assets=true',
        json=NODES)
    insight_category = ['Endpoint', 'Web']
    insight_data_type = ['Hash', 'Domain']
    res = get_indicators_command(client, insight_category, insight_data_type, tlp_color, demisto.args())
    assert all(elem in res[0]['fields']['tags'] for elem in ['tag1', 'tag2'])
    if tlp_color:
        assert res[0]['fields']['trafficlightprotocol'] == tlp_color
    else:
        assert not res[0]['fields'].get('trafficlightprotocol')
