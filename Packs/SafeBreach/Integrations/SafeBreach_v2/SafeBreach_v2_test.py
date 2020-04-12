import json
import demistomock as demisto
from SafeBreach_v2 import *

# from CommonServerPython import *
from SafeBreach_v2 import get_safebreach_simulation_command, get_indicators_command, \
    rerun_simulation_command

MOCK_URL = "https://safebreach-fake-api.com"
MOCK_ACCOUNT_ID = '1234567'
MOCK_API_KEY = 'a1b2c3d4e5'
INSIGHT_ID = '9'
SIMULATION_ID = '8fae303defd52a7745044ce2ba54a391'

client = Client(
    base_url=MOCK_URL,
    api_key=MOCK_API_KEY,
    account_id=MOCK_ACCOUNT_ID,
    proxies=False,
    verify=False,
)


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


REMEDATION_DATA_LIST = load_test_data('./test_data/remediation_data.json')
GET_INSIGHTS_LIST = load_test_data('./test_data/insights.json')
SIMULATION = load_test_data('./test_data/simulation.json')


def test_get_insights(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={'insightIds': [9]})
    mocker.patch.object(demisto, 'results')

    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights?type=actionBased',
                      json=GET_INSIGHTS_LIST)

    res = get_insights_command(client, demisto.args(), True)
    assert demisto.results.call_count == 1
    outputs = demisto.results.call_args[0][0]
    context = outputs['EntryContext']
    fake_safebreach_context = {
        "Id": 9,
        "Category": 'Endpoint',
        "Severity": "Medium"
    }

    assert fake_safebreach_context['Id'] == context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Id']
    assert fake_safebreach_context['Category'] == context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Category']
    assert fake_safebreach_context['Severity'] == context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Severity']
    assert len(res) == 1


def test_get_remediation_data(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={'insightId': INSIGHT_ID})
    mocker.patch.object(demisto, 'results')

    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights?type=actionBased',
                      json=GET_INSIGHTS_LIST)
    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights/{INSIGHT_ID}/remediation',
                      json=REMEDATION_DATA_LIST)

    get_remediation_data_command(client, demisto.args(), True)
    assert demisto.results.call_count == 1
    outputs = demisto.results.call_args[0][0]
    context = outputs['EntryContext']
    sha256_to_check = '109c702578b261d0eda01506625423f5a2b8cc107b0d8dfad84d39fb02bfa5cb'
    assert context['SafeBreach.Insight(val.Id == obj.Id)'][0]['Id'] == INSIGHT_ID
    assert context['File(val.SHA256 == obj.SHA256)'][0]['SHA256'] == sha256_to_check
    assert context['DBotScore(val.Indicator == obj.Indicator)'][0]['Indicator'] == sha256_to_check


def test_rerun_insight(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={'insightId': '9'})
    mocker.patch.object(demisto, 'results')

    response = {
        "data": {
            "name": "Insight (Demisto) - Test",
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
    assert context['SafeBreach.Insight(val.Id == obj.Id)']['Id'] == INSIGHT_ID
    assert context['SafeBreach.Insight(val.Id == obj.Id)']['Rerun'][0]['Id'] == response['data']['runId']


def test_get_indicators(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={'limit': '10'})
    mocker.patch.object(demisto, 'results')
    for insight_id in [5, 6, 8, 9, 13, 14, 17]:
        requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights/{insight_id}/remediation',
                          json=REMEDATION_DATA_LIST)

    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/insights?type=actionBased',
                      json=GET_INSIGHTS_LIST)
    insight_category = ['Endpoint', 'Web']
    insight_data_type = ['Hash', 'Domain']
    hash_to_search = '109c702578b261d0eda01506625423f5a2b8cc107b0d8dfad84d39fb02bfa5cb'
    res = get_indicators_command(client, insight_category, insight_data_type, demisto.args())
    assert demisto.results.call_count == 0
    assert res[0]['value'] == hash_to_search
    assert res[0]['type'] == 'File'


def test_get_simulation(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={'simulationId': SIMULATION_ID})
    mocker.patch.object(demisto, 'results')

    requests_mock.get(f'{MOCK_URL}/api/data/v1/accounts/{MOCK_ACCOUNT_ID}/executions/{SIMULATION_ID}',
                      json=SIMULATION)

    get_safebreach_simulation_command(client, demisto.args())
    assert demisto.results.call_count == 1
    outputs = demisto.results.call_args[0][0]
    context = outputs['EntryContext']
    assert context['SafeBreach.Simulation(val.Id == obj.Id)']['Id'] == SIMULATION_ID


def test_rerun_simulation(mocker, requests_mock):
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
