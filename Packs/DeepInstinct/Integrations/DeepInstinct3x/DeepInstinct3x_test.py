import json
import DeepInstinct3x
import demistomock as demisto

params = {
    "apikey": "key",
    "base_url": "https://demisto.poc.deepinstinctweb.com",
    "after_id": 0
}

mock_device = {
    "id": 1,
    "os": "WINDOWS",
    "osv": "Windows",
    "ip_address": "192.168.88.80",
    "mac_address": "00:00:00:00:00:00",
    "hostname": "Mock_2020-04-09 17:49:39.408405_1",
    "domain": "",
    "scanned_files": 0,
    "tag": "",
    "connectivity_status": "OFFLINE",
    "deployment_status": "REGISTERED",
    "last_registration": "2020-04-09T14:49:39.722292Z",
    "last_contact": "2020-04-09T14:49:39.711487Z",
    "distinguished_name": "OU=Organizations & Sites,DC=bancshares,DC=mib",
    "group_name": "Windows Default Group",
    "group_id": 3,
    "policy_name": "Windows Default Policy",
    "policy_id": 3,
    "log_status": "NA",
    "agent_version": "2.3.1.12",
    "brain_version": "115wt",
    "msp_name": "MSP 1",
    "msp_id": 1,
    "tenant_name": "Tenant 1",
    "tenant_id": 1
}

mock_groups = [
    {
        "name": "Android Default Group",
        "os": "ANDROID",
        "policy_id": 1,
        "id": 1,
        "is_default_group": True,
        "msp_name": "MSP 1",
        "msp_id": 1
    },
    {
        "name": "iOS Default Group",
        "os": "IOS",
        "policy_id": 2,
        "id": 2,
        "is_default_group": True,
        "msp_name": "MSP 1",
        "msp_id": 1
    }
]

mock_policies = [
    {
        "id": 2,
        "os": "IOS",
        "name": "iOS Default Policy",
        "is_default_policy": True,
        "msp_name": "MSP 1",
        "msp_id": 1
    },
    {
        "id": 3,
        "os": "WINDOWS",
        "name": "Windows Default Policy",
        "is_default_policy": True,
        "msp_name": "MSP 1",
        "msp_id": 1
    }
]


mock_events = {
    "last_id": 2,
    "events":
        [
            {
                "file_type": "ZIP",
                "file_hash": "d1838b541ff7ffe6489d120d89dfa855665fd2c708491f336c7267069387053f",
                "file_archive_hash": "d1838b541ff7ffe6489d120d89dfa855665fd2c708491f336c7267069387053f",
                "path": "c:\\temp\\file.exe",
                "file_size": 18127052,
                "threat_severity": "NONE",
                "certificate_thumbprint": None,
                "certificate_vendor_name": None,
                "deep_classification": None,
                "file_status": "NOT_UPLOADED",
                "sandbox_status": "NOT_READY_TO_GENERATE",
                "model": "FileEvent",
                "id": 1,
                "device_id": 1,
                "type": "STATIC_ANALYSIS",
                "trigger": "BRAIN",
                "action": "PREVENTED",
                "timestamp": "2020-04-09T14:49:41.154850Z",
                "insertion_timestamp": "2020-04-09T14:49:41.170331Z",
                "close_timestamp": "2020-04-12T14:11:39.145856Z",
                "close_trigger": "CLOSED_BY_ADMIN",
                "reoccurrence_count": 0,
                "last_reoccurrence": None,
                "last_action": None,
                "status": "CLOSED",
                "comment": None,
                "recorded_device_info": {
                    "os": "WINDOWS",
                    "mac_address": "00:00:00:00:00:00",
                    "hostname": "Mock_2020-04-09 17:49:39.408405_1",
                    "tag": "",
                    "group_name": "Windows Default Group",
                    "policy_name": "Windows Default Policy",
                    "tenant_name": "Tenant 1"
                },
                "msp_name": "MSP 1",
                "msp_id": 1,
                "tenant_name": "Tenant 1",
                "tenant_id": 1
            },
            {
                "file_type": "ZIP",
                "file_hash": "edf34902ff17838b4bc709ff15b5265dd49f652ee75a1adf69df9ae5bc52f960",
                "file_archive_hash": "edf34902ff17838b4bc709ff15b5265dd49f652ee75a1adf69df9ae5bc52f960",
                "path": "c:\\temp\\file2.exe",
                "file_size": 15090736,
                "threat_severity": "NONE",
                "certificate_thumbprint": None,
                "certificate_vendor_name": None,
                "deep_classification": None,
                "file_status": "NOT_UPLOADED",
                "sandbox_status": "NOT_READY_TO_GENERATE",
                "model": "FileEvent",
                "id": 2,
                "device_id": 2,
                "type": "STATIC_ANALYSIS",
                "trigger": "BRAIN",
                "action": "PREVENTED",
                "timestamp": "2020-04-09T14:49:41.805228Z",
                "insertion_timestamp": "2020-04-09T14:49:41.810047Z",
                "close_timestamp": None,
                "close_trigger": None,
                "reoccurrence_count": 0,
                "last_reoccurrence": None,
                "last_action": None,
                "status": "OPEN",
                "comment": None,
                "recorded_device_info": {
                    "os": "WINDOWS",
                    "mac_address": "00:00:00:00:00:00",
                    "hostname": "Mock_2020-04-09 17:49:41.170765_1",
                    "tag": "",
                    "group_name": "Windows Default Group",
                    "policy_name": "Windows Default Policy",
                    "tenant_name": "Tenant 1"
                },
                "msp_name": "MSP 1",
                "msp_id": 1,
                "tenant_name": "Tenant 1",
                "tenant_id": 1
            }
        ]
}


def test_get_device_command(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'device_id': mock_device['id']})
    requests_mock.get("{0}/api/v1/devices/{1}".format(params['base_url'], mock_device['id']), json=mock_device)
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.get_specific_device()
    result = demisto.results.call_args[0][0]
    assert result['Contents'] == mock_device


def test_get_all_groups(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    requests_mock.get("{0}/api/v1/groups".format(params['base_url']), json=mock_groups)
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.get_all_groups()
    result = demisto.results.call_args[0][0]
    assert result['Contents'] == mock_groups


def test_get_all_policies(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    requests_mock.get("{0}/api/v1/policies".format(params['base_url']), json=mock_policies)
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.get_all_policies()
    result = demisto.results.call_args[0][0]
    assert result['Contents'] == mock_policies


def test_get_events(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'first_event_id': 0})
    requests_mock.get(f"{params['base_url']}/api/v1/events?after_event_id=0", json=mock_events)
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.get_events()
    result = demisto.results.call_args[0][0]
    assert result['Contents'] == mock_events['events']


def test_fetch_incidents(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'first_fetch': 0})
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_id': 0})
    requests_mock.get("{0}/api/v1/events?after_event_id=0".format(params['base_url']), json=mock_events)
    requests_mock.get("{0}/api/v1/events?after_event_id=2".format(params['base_url']), json={})
    mocker.patch.object(demisto, "incidents")
    DeepInstinct3x.fetch_incidents()
    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == len(mock_events['events'])
    assert incidents[0]['rawJSON'] == json.dumps(mock_events['events'][0])
    assert incidents[1]['rawJSON'] == json.dumps(mock_events['events'][1])


def test_get_suspicious_events_command(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'first_event_id': 0})
    requests_mock.get("{0}/api/v1/suspicious-events?after_event_id=0".format(params['base_url']), json=mock_events)
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.get_suspicious_events()
    result = demisto.results.call_args[0][0]
    assert result['Contents'] == mock_events['events']


def test_add_hash_to_denylist(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'policy_id': 0, 'file_hash': 'dummyhash', 'comment': ""})
    requests_mock.post("{0}/api/v1/policies/0/deny-list/hashes/dummyhash".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.add_hash_to_denylist()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_add_hash_to_allowlist(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'policy_id': 0, 'file_hash': 'dummyhash', 'comment': ""})
    requests_mock.post("{0}/api/v1/policies/0/allow-list/hashes/dummyhash".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.add_hash_to_allowlist()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_remove_hash_from_denylist(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'policy_id': 0, 'file_hash': 'dummyhash'})
    requests_mock.delete("{0}/api/v1/policies/0/deny-list/hashes".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.remove_hash_from_denylist()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_remove_hash_from_allowlist(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'policy_id': 0, 'file_hash': 'dummyhash'})
    requests_mock.delete("{0}/api/v1/policies/0/allow-list/hashes".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.remove_hash_from_allowlist()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_add_devices_to_group(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'group_id': 0, 'device_ids': '0,1'})
    requests_mock.post("{0}/api/v1/groups/0/add-devices".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.add_devices_to_group()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_isolate_from_network(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'device_ids': '0,1'})
    requests_mock.post("{0}/api/v1/devices/actions/isolate-from-network".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.isolate_from_network()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_release_from_isolation(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'device_ids': '0,1'})
    requests_mock.post("{0}/api/v1/devices/actions/release-from-isolation".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.release_from_isolation()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_terminate_remote_processes(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'event_ids': '0,1'})
    requests_mock.post("{0}/api/v1/devices/actions/terminate-remote-process".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.terminate_remote_processes()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_close_events(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'event_ids': '0,1'})
    requests_mock.post("{0}/api/v1/events/actions/close".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.close_events()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_upload_logs(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'device_id': 0})
    requests_mock.post("{0}/api/v1/devices/0/actions/upload-logs".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.upload_logs()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'


def test_enable_device(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'device_id': 0})
    requests_mock.post("{0}/api/v1/devices/0/actions/enable".format(params['base_url']))
    mocker.patch.object(demisto, 'results')
    DeepInstinct3x.enable_device()
    result = demisto.results.call_args[0][0]
    assert result == 'ok'
