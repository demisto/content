import io
import json
import pytest

import demistomock as demisto
from importlib import import_module

sentinelone_v2 = import_module('SentinelOne-V2')
main = sentinelone_v2.main


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def demisto_mocker_2_1(mocker):
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': 1558541949000})
    mocker.patch.object(demisto, 'incidents')


@pytest.fixture()
def demisto_mocker_2_0(mocker):
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.0',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': 1558541949000})
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'results')


def test_fetch_incidents__2_1(mocker, requests_mock, demisto_mocker_2_1):

    """
    When:
        fetch-incident and API version is 2.1
    Returns:
        All the threats received by the API as incidents regardless to the rank.
    """
    raw_threat_response = util_load_json('test_data/get_threats_2_1_raw_response.json')
    incidents_for_fetch = util_load_json('test_data/incidents_2_1.json')
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    requests_mock.get('https://usea1.sentinelone.net/web/api/v2.1/threats', json=raw_threat_response)

    main()

    assert demisto.incidents.call_count == 1
    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == 4
    assert incidents[0]['occurred'] == '2019-09-15T12:05:49.095889Z'
    assert incidents[1]['occurred'] == '2019-09-15T12:14:42.440985Z'
    assert incidents[2]['occurred'] == '2019-09-15T12:14:43.349807Z'
    assert incidents[3]['occurred'] == '2019-09-15T12:14:44.069617Z'
    assert incidents_for_fetch == incidents


def test_fetch_incidents__2_0(mocker, requests_mock, demisto_mocker_2_0):
    """
    When:
        fetch-incident and API version is 2.0
    Returns:
        List of incidents with rank threshold matches to the fetch_threat_rank.
    """
    raw_threat_response = util_load_json('test_data/get_threats_2_0_raw_response.json')
    incidents_for_fetch = util_load_json('test_data/incidents_2_0.json')
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    requests_mock.get('https://usea1.sentinelone.net/web/api/v2.0/threats', json=raw_threat_response)

    main()

    assert demisto.incidents.call_count == 1
    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == 2
    assert incidents[0]['occurred'] == '2019-09-15T12:05:49.095889Z'
    assert incidents[1]['occurred'] == '2019-09-15T12:14:42.440985Z'
    assert incidents_for_fetch == incidents


def test_get_threats_outputs():
    """
    When:
        parsing raw response from the API to XSOAR output
    Returns:
        List of threat outputs.
    """
    raw_threat_response = util_load_json('test_data/get_threats_2_1_raw_response.json')['data']
    expected = util_load_json('test_data/threats_outputs.json')
    threats_output = list(sentinelone_v2.get_threats_outputs(raw_threat_response))
    assert expected == threats_output


def test_get_agents_outputs():
    """
    When:
        parsing raw response of agents from the API to XSOAR output
    Returns:
        List of agents.
    """
    raw_agent_response = util_load_json('test_data/agents_raw_response.json')
    expected = util_load_json('test_data/agent_outputs.json')
    agent_output = list(sentinelone_v2.get_agents_outputs(raw_agent_response))
    assert expected == agent_output
