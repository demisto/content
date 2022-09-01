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


def test_fetch_file(mocker, requests_mock):
    """
    When:
        fetch file request submitted
    Returns
        "String that it was successfully initiated"
    """
    agent_id = 1
    requests_mock.post(f'https://usea1.sentinelone.net/web/api/v2.1/agents/{agent_id}/actions/fetch-files', json={})

    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-fetch-file')
    mocker.patch.object(demisto, 'args', return_value={
        'agent_id': agent_id,
        'file_path': "/does/not/matter/for/test",
        'password': "doesnotmatterfortest"
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    sentinelone_v2.return_results.assert_called_once_with(
        f"Intiated fetch-file action for /does/not/matter/for/test on Agent {agent_id}")


def test_download_fetched_file(mocker, requests_mock, capfd):
    """
    When:
        request sent to retrieve a downloaded file
    Return:
        File entry of the file downloaded
    """
    agent_id = 1
    with open('test_data/download_fetched_file.zip', 'rb') as f:
        dffzip_contents = f.read()

    requests_mock.get(f'https://usea1.sentinelone.net/web/api/v2.1/agents/{agent_id}/uploads/1', content=dffzip_contents)

    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-download-fetched-file')
    mocker.patch.object(demisto, 'args', return_value={
        'agent_id': agent_id,
        'activity_id': "1",
        'password': "password"  # This matches the password of the `download_fetched_file.zip` file in test_data
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results, file_result = call[0].args[0]

    assert command_results.outputs['Path'] == "download_fetched_file/"


def test_get_blocklist(mocker, requests_mock):
    """
    When:
        Request is made to retrieve the blocklist
    Return:
        The blocklist
    """
    raw_blockist_response = util_load_json('test_data/get_blocklist.json')
    blocklist_results = util_load_json('test_data/get_blocklist_results.json')
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/restrictions?tenant=True&groupIds=group_id&siteIds=site_id"
                      "&accountIds=account_id&skip=0&limit=1&sortBy=updatedAt&sortOrder=desc",
                      json=raw_blockist_response)

    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-blocklist')
    mocker.patch.object(demisto, 'args', return_value={
        'offset': "0",
        'limit': "1",
        'group_ids': ["group_id"],
        'site_ids': ["site_id"],
        'account_ids': ["account_id"],
        'global': "true"
    })

    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]

    assert command_results.outputs == blocklist_results


def test_remove_hash_from_blocklist(mocker, requests_mock):
    """
    When:
        A hash is removed from the blocklist
    Return:
        Status that it has been removed from the blocklist
    """
    raw_blockist_response = util_load_json('test_data/remove_hash_from_blocklist.json')
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/restrictions?tenant=True&skip=0&limit=4&sortBy=updatedAt&"
                      "sortOrder=asc&value__contains=f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
                      json=raw_blockist_response)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-remove-hash-from-blocklist')
    mocker.patch.object(demisto, 'args', return_value={
        'sha1': 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
    })

    mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = sentinelone_v2.return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs['hash'] == 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
    assert outputs['status'] == 'Removed 1 entries from blocklist'


def test_add_hash_to_blocklist(mocker, requests_mock):
    """
    When:
        A hash is added to the blocklist
    Return:
        CommandResults with outputs set to a dict that has the hash and a response message
    """
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-add-hash-to-blocklist')
    mocker.patch.object(demisto, 'args', return_value={
        'sha1': 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
    })

    mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = sentinelone_v2.return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs['hash'] == 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
    assert outputs['status'] == 'Added to blocklist'


def test_update_threat_analyst_verdict(mocker, requests_mock):
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/threats/analyst-verdict", json={"data": {"affected": 1}})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-update-threats-verdict')
    mocker.patch.object(demisto, 'args', return_value={
        'threat_ids': '1234567890',
        'verdict': 'true_positive'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'ID': '1234567890', 'Updated': True, 'Update': {'Action': 'true_positive'}}]


def test_update_alert_analyst_verdict(mocker, requests_mock):
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/alerts/analyst-verdict",
                       json={"data": {"affected": 1}})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-update-alerts-verdict')
    mocker.patch.object(demisto, 'args', return_value={
        'alert_ids': '1234567890',
        'verdict': 'true_positive'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'ID': '1234567890', 'Updated': True, 'Update': {'Action': 'true_positive'}}]


def test_update_threat_status(mocker, requests_mock):
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/threats/incident", json={"data": {"affected": 1}})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-update-threats-status')
    mocker.patch.object(demisto, 'args', return_value={
        'threat_ids': '1234567890',
        'status': 'in_progress'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'ID': '1234567890', 'Updated': True, 'Status': 'in_progress'}]


def test_update_alert_status(mocker, requests_mock):
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/alerts/incident",
                       json={"data": {"affected": 1}})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-update-alerts-status')
    mocker.patch.object(demisto, 'args', return_value={
        'alert_ids': '1234567890',
        'status': 'in_progress'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'ID': '1234567890', 'Updated': True, 'Status': 'in_progress'}]


def test_create_star_rule(mocker, requests_mock):
    raw_star_rule_response = util_load_json('test_data/create_star_rule_response.json')
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/rules", json=raw_star_rule_response)
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-create-star-rule')
    mocker.patch.object(demisto, 'args', return_value={
        'name': 'sample',
        'description': 'description',
        'query': 'sample query',
        'query_type': 'events',
        'rule_severity': 'Low',
        'account_ids': '1234567890',
        'group_ids': '1234567890',
        'site_ids': '123456789',
        'expiration_mode': 'Permanent',
        'expiration_date': '',
        'network_quarantine': "true",
        'treatAsThreat': 'suspicious'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == {}


def test_enable_star_rules(mocker, requests_mock):
    requests_mock.put("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/rules/enable", json={"data": {"affected": 1}})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-enable-star-rules')
    mocker.patch.object(demisto, 'args', return_value={
        'rule_ids': '1234567890'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'ID': '1234567890', 'Enabled': True}]


def test_disable_star_rules(mocker, requests_mock):
    requests_mock.put("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/rules/disable", json={"data": {"affected": 1}})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-disable-star-rules')
    mocker.patch.object(demisto, 'args', return_value={
        'rule_ids': '1234567890'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'ID': '1234567890', 'Disabled': True}]


def test_delete_star_rule(mocker, requests_mock):
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/rules", json={"data": {"affected": 1}})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-delete-star-rule')
    mocker.patch.object(demisto, 'args', return_value={
        'rule_ids': '1234567890'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'ID': '1234567890', 'Deleted': True}]
