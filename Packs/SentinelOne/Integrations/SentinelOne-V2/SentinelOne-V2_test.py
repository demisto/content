import json
import pytest
import demistomock as demisto
from importlib import import_module

sentinelone_v2 = import_module('SentinelOne-V2')
main = sentinelone_v2.main


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def demisto_mocker_2_1(mocker):
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4',
                                                         'fetch_type': 'Threats'})
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': 1558541949000})
    mocker.patch.object(demisto, 'incidents')


@pytest.fixture()
def demisto_mocker_2_0(mocker):
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.0',
                                                         'fetch_threat_rank': '4',
                                                         'fetch_type': 'Threats'})
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


@pytest.mark.parametrize(
    'block_site_ids, expected_status', [
        ('site1,site2', 'Added to scoped blocklist'), (None, 'Added to global blocklist')
    ]
)
def test_add_hash_to_blocklist(mocker, requests_mock, block_site_ids, expected_status):
    """
    Given:
       - Case A: A hash is added to the blocklist with sites
       - Case B: A hash is added to the blocklist without sites

    When:
       - running the sentinelone-add-hash-to-blocklist command

    Then:
       - Case A: make sure the sites are added to the request and output is valid
       - Case B: make sure there are no site IDs added to the request and output is valid

    """
    blocked_sha_requests_mock = requests_mock.post(
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []}
    )

    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4',
                                                         'block_site_ids': block_site_ids})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-add-hash-to-blocklist')
    mocker.patch.object(demisto, 'args', return_value={
        'sha1': 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
    })

    mocker.patch.object(sentinelone_v2, "return_results")

    main()

    site_ids_body_request = blocked_sha_requests_mock.last_request.json().get('filter').get('siteIds')
    if block_site_ids:
        assert site_ids_body_request
    else:
        assert not site_ids_body_request

    call = sentinelone_v2.return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs['hash'] == 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
    assert outputs['status'] == expected_status


def test_remove_item_from_whitelist(mocker, requests_mock):
    """
    When:
        A hash is removed from the whitelist
    Return:
        Status that it has been removed from the whitelist
    """
    raw_whitelist_response = util_load_json('test_data/remove_item_from_whitelist.json')
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/exclusions?osTypes=windows&type=white_hash"
                      "&value__contains=f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2&"
                      "includeChildren=True&includeParents=True&limit=5",
                      json=raw_whitelist_response)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/exclusions", json={"data": []})

    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-remove-item-from-whitelist')
    mocker.patch.object(demisto, 'args', return_value={
        # 'sha1': 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
        'item': "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
        'exclusion_type': "white_hash", 'os_type': "windows"
    })

    mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = sentinelone_v2.return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs['item'] == 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
    assert outputs['status'] == 'Removed 1 entries from whitelist'


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


def test_get_events(mocker, requests_mock):
    """
    Given:
    When: run get events
    Then: ensure the context output are as expected and contained the 'ProcessID' and 'EventID' as id keys
    """
    from CommonServerPython import CommandResults

    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/dv/events", json={'data': [
        {'ProcessID': 'ProcessID_1', 'EventID': 'EventID_1'},
        {'ProcessID': 'ProcessID_2', 'EventID': 'EventID_2'}
    ]})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-events')
    mocker.patch.object(demisto, 'args', return_value={
        'query_id': '1234567890'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    expected_context = CommandResults(
        outputs_prefix='SentinelOne.Event',
        outputs_key_field=['ProcessID', 'EventID'],
        outputs=[{}]).to_context().get('EntryContext', {})

    call = sentinelone_v2.return_results.call_args_list
    context_outputs = call[0].args[0].outputs
    assert all(key in context_outputs for key in expected_context)


def test_run_remote_script(mocker, requests_mock):
    """
    Given
        - required arguments i.e account_id, script_id, output_description, task_description, agent_ids and output_directory
    When
        - running sentinelone-run-remote-script command
    Then
        - returns a table of result had the affected process details
    """
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/remote-scripts/execute",
                       json={"data": {"affected": 1}})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-run-remote-script')
    mocker.patch.object(demisto, 'args', return_value={
        'account_ids': '1234567890',
        'script_id': '1',
        'output_destination': 'test',
        'task_description': 'test',
        'output_directory': 'file',
        'agent_ids': '2'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == {'affected': 1}


def test_initiate_endpoint_scan(mocker, requests_mock):
    """
    Given
        - required agent_ids argument
    When
        - running sentinelone-initiate-endpoint-scan command
    Then
        - returns a table of result had the details, like agent id and status of the scan
    """
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/agents/actions/initiate-scan",
                       json={"data": {"affected": 1}})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-initiate-endpoint-scan')
    mocker.patch.object(demisto, 'args', return_value={
        'agent_ids': '123456'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'Agent ID': '123456', 'Initiated': True}]


def test_get_installed_applications(mocker, requests_mock):
    """
    Given
        - required agent_ids argument
    When
        - running sentinelone-get-installed-applications command
    Then
        - returns a table of result had the list of installed applications on the provided agent
    """
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/agents/applications",
                      json={"data": [{"name": "test", "publisher": "abc", "size": 50,
                            "version": "2.1", "installedDate": "2023-02-10"}]})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-installed-applications')
    mocker.patch.object(demisto, 'args', return_value={
        'agent_ids': '123456'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'InstalledOn': '2023-02-10', 'Name': 'test', 'Publisher': 'abc', 'Size': 50, 'Version': '2.1'}]  # noqa


def test_get_remote_script_status(mocker, requests_mock):
    """
    Given
        - required parentTaskId argument
    When
        - running sentinelone-get-remote-script-task-status command
    Then
        - returns a table of result had the list of taskIds which are available on ParentTaskIds
    """
    json_output = {
        "data": [
            {
                "accountId": "1234567890",
                "accountName": "Metron Team",
                "agentComputerName": "MSEDGEWIN10",
                "agentId": "0987654321",
                "agentIsActive": True,
                "agentIsDecommissioned": False,
                "agentMachineType": "desktop",
                "agentOsType": "windows",
                "agentUuid": "25682583752987932878722323",
                "createdAt": "2024-07-30T06:43:22.938877Z",
                "description": "A test get cloud services",
                "detailedStatus": "Execution completed successfully",
                "groupId": "12334654321",
                "groupName": "Default Group",
                "id": "123456",
                "initiatedBy": "user",
                "initiatedById": "099999",
                "parentTaskId": "123456789",
                "scriptResultsSignature": "34324324324324235r24fe2r2333432",
                "siteId": "99999999",
                "siteName": "Default site",
                "status": "completed",
                "statusCode": None,
                "statusDescription": "Completed",
                "type": "script_execution",
                "updatedAt": "2024-07-30T06:44:50.881432Z"
            }
        ]
    }
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/remote-scripts/status",
                      json=json_output)
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-remote-script-task-status')
    mocker.patch.object(demisto, 'args', return_value={
        'parent_task_id': '123456789'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert_response = util_load_json('test_data/get_remote_script_task_status.json')
    assert command_results.outputs == assert_response


def test_remote_script_results(mocker, requests_mock):
    """
    Given
        - required taskIds argument
    When
        - running sentinelone-get-remote-script-task-results command
    Then
        - returns file details
    """
    task_ids = "1234566"
    output_json = {
        "data": {
            "download_links": [
                {
                    "downloadUrl": "https://url/1",
                    "fileName": "file1.zip",
                    "taskId": task_ids
                }
            ],
            "errors": []
        }
    }
    requests_mock.post('https://usea1.sentinelone.net/web/api/v2.1/remote-scripts/fetch-files', json=output_json)
    requests_mock.get('https://url/1', json={})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-remote-script-task-results')
    mocker.patch.object(demisto, 'args', return_value={
        'task_ids': task_ids,
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()
    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    outputs = command_results[0].outputs
    assert outputs[0].get("taskId") == task_ids
    assert outputs[0].get("fileName") == "file1.zip"
    assert outputs[0].get("downloadUrl") == "https://url/1"


def test_get_power_query_results(mocker, requests_mock):
    """
    Given
        - required query, from_date and to_date arguments
    When
        - running sentinelone-get-power-query-results command
    Then
        - returns a table of result if data present
    """
    json_output = util_load_json('test_data/get_power_query_response.json')
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/dv/events/pq-ping",
                      json=json_output)
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-power-query-results')
    mocker.patch.object(demisto, 'args', return_value={
        'query_id': 'pq123456789',
        'from_date': '2024-08-20T04:49:26.257525Z',
        'to_date': '2024-08-21T04:49:26.257525Z',
        'query': 'event.time = * | columns eventTime = event.time, agentUuid = agent.uuid, siteId = site.id'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()
    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    readable_output = ('### SentinelOne - Get Power Query Results for ID pqe5a4cbb0a0f0981f4125976b49fb0ebb'
                       '\nRecommendation: Result set limited to 1000 rows by default. To display more rows, add'
                       ' a command like \"| limit 10000\".\n\nSummary information and details about the power query'
                       '\n|Agent Uuid|Event Time|Site Id|\n|---|---|---|\n'
                       '| ed8f14f1-f35b-0eca-1c1e-e31e97aefc71 | 1724151854609 | 123456789 |\n'
                       '| ed8f14f1-f35b-0eca-1c1e-e31e97aefc71 | 1724151823332 | 123456789 |\n')
    assert command_results.readable_output == readable_output


def test_get_power_query_results_without_query_id(mocker, requests_mock):
    """
    Given
        - required query, from_date and to_date arguments
    When
        - running sentinelone-get-power-query-results command
    Then
        - returns a table of result if data present
    """
    json_output = util_load_json('test_data/get_power_query_response.json')
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/dv/events/pq",
                       json=json_output)
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-power-query-results')
    mocker.patch.object(demisto, 'args', return_value={
        'from_date': '2024-08-20T04:49:26.257525Z',
        'to_date': '2024-08-21T04:49:26.257525Z',
        'query': 'event.time = * | columns eventTime = event.time, agentUuid = agent.uuid, siteId = site.id'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()
    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    readable_output = ('### SentinelOne - Get Power Query Results for ID pqe5a4cbb0a0f0981f4125976b49fb0ebb'
                       '\nRecommendation: Result set limited to 1000 rows by default. To display more rows, add'
                       ' a command like \"| limit 10000\".\n\nSummary information and details about the power query'
                       '\n|Agent Uuid|Event Time|Site Id|\n|---|---|---|\n'
                       '| ed8f14f1-f35b-0eca-1c1e-e31e97aefc71 | 1724151854609 | 123456789 |\n'
                       '| ed8f14f1-f35b-0eca-1c1e-e31e97aefc71 | 1724151823332 | 123456789 |\n')
    assert command_results.readable_output == readable_output


def test_get_remote_data_command(mocker, requests_mock):
    """
    Given
        - an incident ID on the remote system
    When
        - running get_remote_data_command with changes to make on an incident
    Then
        - returns the relevant incident entity from the remote system with the relevant incoming mirroring fields
    """
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/threats",
                      json={"data": [{"name": "test", "id": "123456"}]})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='get-remote-data')
    mocker.patch.object(demisto, 'args', return_value={
        'id': '123456', 'lastUpdate': '321456'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = vars(call[0].args[0])
    assert command_results == {
        'mirrored_object': {
            'name': 'test',
            'id': '123456',
            'incident_type': 'SentinelOne Incident'
        },
        'entries': []
    }


def test_list_installed_singularity_mark_apps(mocker, requests_mock):
    """
    Given
        - all of these are optional arguments, but for this case, providing the id argument
    When
        - running sentinelone-list-installed-singularity-marketplace-applications command
    Then
        - returns a table of result had the list of installed singularity marketplace applications
    """
    json_output = util_load_json('test_data/get_singularity_marketplace_apps_response.json')
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/singularity-marketplace/applications",
                      json=json_output)
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-list-installed-singularity-marketplace-applications')
    mocker.patch.object(demisto, 'args', return_value={
        'id': '123456'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'ID': '123456', 'Account': 'SentinelOne', 'AccountId': '1234567890', 'ApplicationCatalogId': '90909090909090', 'applicationCatalogName': 'SentinelOne Threat Intelligence IOC Ingestion', 'AlertMessage': '', 'CreatedAt': '2025-01-23T13:11:23.12758', 'Creator': 'admin@user.sentinelone.net', 'CreatorId': '212212121211212', 'DesiredStatus': 'active', 'HasAlert': False, 'LastEntityCreatedAt': '2025-01-23T13:11:23.127579', 'Modifier': 'admin@user.sentinelone.net', 'ModifierId': '212212121211212', 'ScopeId': '1230123012301230', 'ScopeLevel': 'account', 'Status': 'active', 'UpdatedAt': '2025-01-23T13:11:25.96604', 'ApplicationInstanceName': 'SentinelOne Threat Intelligence IOC Ingestion'}]  # noqa


def test_get_service_users(mocker, requests_mock):
    """
    Given
        - all of these are optional arguments, but for this case, providing the ids argument
    When
        - running sentinelone-get-service-users command
    Then
        - returns a table of result had the list of service users
    """
    json_output = util_load_json('test_data/get_service_users_response.json')
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/service-users",
                      json=json_output)
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-service-users')
    mocker.patch.object(demisto, 'args', return_value={
        'ids': '123456'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{'ID': '123456', 'ApiTokenCreatedAt': '2025-01-30T10:12:09.458490Z', 'ApiTokenExpiresAt': '2025-03-01T10:12:08Z', 'CreatedAt': '2025-01-30T10:12:09.407923Z', 'CreatedById': '123456789099', 'CreatedByName': 'sentinelone', 'Description': None, 'LastActivation': '2025-02-04T10:00:07.637184Z', 'Name': 'Service user for SentinelOne Alert Ingestion app for 0101010101010 site id', 'Scope': 'site', 'UpdatedAt': '2025-01-30T10:12:09.405748Z', 'UpdatedById': '2323232323232323', 'UpdatedByName': 'sentinelone', 'ScopeRolesRoleId': '999999999', 'ScopeRolesRoleName': 'Admin', 'ScopeRolesAccountName': 'SentinelOne', 'ScopeRolesId': '0101010101010'}]  # noqa


def test_get_modified_remote_data_command(mocker, requests_mock):
    """
    Given
        - arguments - lastUpdate time
        - raw incidents (results of get_incidents_ids and get_fetch_detections)
    When
        - running get_modified_remote_data_command
    Then
        - returns a list of incidents and detections IDs that were modified since the lastUpdate time
    """
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/threats",
                      json={"data": [{"name": "test", "id": "123456"}]})
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='get-modified-remote-data')
    mocker.patch.object(demisto, 'args', return_value={
        'id': '123456', 'lastUpdate': '2023-02-16 09:35:40.020660+00:00'
    })
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = vars(call[0].args[0])
    assert command_results == {'modified_incident_ids': ['123456']}


def test_update_remote_system_command(requests_mock):
    """
    Given
        - incident changes (one of the mirroring field changed or it was closed in XSOAR)
    When
        - outgoing mirroring triggered by a change in the incident
    Then
        - the relevant incident is updated with the corresponding fields in the remote system
        - the returned result corresponds to the incident ID
    """
    args = {
        'delta': {'sentinelonethreatanalystverdict': '', 'sentinelonethreatstatus': '', 'closeNotes': 'a test'},
        'incidentChanged': True,
        'remoteId': "123456"
    }
    command_result = sentinelone_v2.update_remote_system_command(requests_mock, args)
    assert command_result == "123456"


def test_get_mapping_fields_command():
    """
    Given
        - nothing
    When
        - running get_mapping_fields_command
    Then
        - the result fits the expected mapping scheme
    """
    result = sentinelone_v2.get_mapping_fields_command()
    assert result.scheme_types_mappings[0].type_name == 'SentinelOne Incident'
    assert list(result.scheme_types_mappings[0].fields.keys()) == ['analystVerdict', 'incidentStatus']


def test_get_dv_query_status(mocker, requests_mock):
    """
    Given: queryId
    When: run get_status
    Then: ensure the context output are as expected and contained the Query Status
    """
    requests_mock.get('https://usea1.sentinelone.net/web/api/v2.1/dv/query-status',
                      json={
                          'data': {
                              'QueryID': '1234567890',
                              'progressStatus': 100,
                              'queryModeInfo': {
                                  'lastActivatedAt': '2022-07-19T21:20:54+00:00',
                                  'mode': 'scalyr'
                              },
                              'responseState': 'FINISHED',
                              'warnings': None
                          }
                      })
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-dv-query-status')
    mocker.patch.object(demisto, 'args', return_value={
        'query_id': '1234567890'
    })
    mocker.patch.object(sentinelone_v2, 'return_results')
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs.get('QueryID') == '1234567890'
    assert command_results.outputs.get('responseState') == 'FINISHED'


def test_get_agent_mac(mocker, requests_mock):
    """
        Given: agentId
        When: run get_status
        Then: ensures returned context details are as expected
    """

    requests_mock.get('https://usea1.sentinelone.net/web/api/v2.1/agents',
                      json={
                          'data': [{
                              'computerName': 'computerName_test',
                              'id': 'agentId_test',
                              'networkInterfaces': [{
                                  'int_name': 'int_name_test',
                                  'inet': 'ip_test',
                                  'physical': 'mac_test'
                              }]
                          }]
                      })
    mocker.patch.object(demisto, 'params', return_value={'token': 'token',
                                                         'url': 'https://usea1.sentinelone.net',
                                                         'api_version': '2.1',
                                                         'fetch_threat_rank': '4'})
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-agent-mac')
    mocker.patch.object(demisto, 'args', return_value={
        'agent_id': '1234567890'
    })
    mocker.patch.object(sentinelone_v2, 'return_results')
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs[0].get('agent_id') == 'agentId_test'
    assert command_results.outputs[0].get('ip') == 'ip_test'
    assert command_results.outputs[0].get('mac') == 'mac_test'
