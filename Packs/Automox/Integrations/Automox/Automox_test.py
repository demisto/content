"""Automox Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import demistomock as demisto
from Automox import Client

TEST_URL = "http://fake-api.com"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_mock_client():

    return Client(
        base_url=TEST_URL,
        verify=False,
        headers=None,
        proxy=False
    )


def test_remove_keys():
    from Automox import remove_keys

    test_data = {
        "keep": {
            "remove": True,
        },
        "remove": [
            {
                "remove": True,
            },
            {
                "remove": True,
            }
        ],
        "foo": {
            "bar": True,
            "remove": True,
        }
    }

    exclude_keys = [
        "remove",
        "foo.remove",
    ]

    sanitized_data = remove_keys(exclude_keys, test_data)

    assert 'remove' in sanitized_data['keep']
    assert 'remove' not in sanitized_data
    assert 'remove' not in sanitized_data['foo']
    assert 'bar' in sanitized_data['foo']


def test_remove_key():
    from Automox import remove_key

    test_data = {
        "keep": {
            "remove": True,
        },
        "remove": [
            {
                "remove": True,
            },
            {
                "remove": True,
            }
        ],
    }

    keys_to_traverse = ['remove', 'remove']

    sanitized_data = remove_key(keys_to_traverse, test_data)

    assert 'remove' not in sanitized_data['remove'][0]
    assert 'remove' not in sanitized_data['remove'][1]
    assert 'keep' in sanitized_data


def test_get_default_server_group_id(requests_mock):
    from Automox import get_default_server_group_id

    client = util_mock_client()
    expected_response = util_load_json("./test_data/automox-groups-list.json")

    requests_mock.get(f"{TEST_URL}/servergroups", json=expected_response)

    org_id = 1
    result = get_default_server_group_id(client, org_id)

    assert result == 1


def test_action_on_vulnerability_sync_batch(requests_mock):
    from Automox import action_on_vulnerability_sync_batch

    org_id = 1
    batch_id = 1

    requests_mock.post(f"{TEST_URL}/orgs/{org_id}/tasks/batches/{batch_id}/accept", status_code=204)
    requests_mock.post(f"{TEST_URL}/orgs/{org_id}/tasks/batches/{batch_id}/reject", status_code=204)

    client = util_mock_client()

    args = {
        "org_id": org_id,
        "batch_id": batch_id,
        "action": "accept"
    }

    result = action_on_vulnerability_sync_batch(client, args)

    assert "Action: accept" in result.readable_output
    assert "ID: 1" in result.readable_output

    args = {
        "org_id": org_id,
        "batch_id": batch_id,
        "action": "reject"
    }

    result = action_on_vulnerability_sync_batch(client, args)

    assert "Action: reject" in result.readable_output
    assert "ID: 1" in result.readable_output


def test_action_on_vulnerability_sync_task(requests_mock):
    from Automox import action_on_vulnerability_sync_task

    org_id = 1
    task_id = 1

    requests_mock.patch(f"/orgs/{org_id}/tasks/{task_id}", status_code=204)

    args = {
        'org_id': org_id,
        'task_id': task_id,
        'action': "execute",
    }

    client = util_mock_client()
    result = action_on_vulnerability_sync_task(client, args)

    assert "Action: execute" in result.readable_output
    assert "ID: 1" in result.readable_output

    args = {
        'org_id': org_id,
        'task_id': task_id,
        'action': "cancel",
    }

    result = action_on_vulnerability_sync_task(client, args)

    assert "Action: cancel" in result.readable_output
    assert "ID: 1" in result.readable_output


def test_create_group(requests_mock):
    from Automox import create_group

    org_id = 1

    expected_response = util_load_json("./test_data/automox-group-create.json")
    requests_mock.post(f"{TEST_URL}/servergroups", json=expected_response)

    args = {
        'color': '#FFFFFF',
        'name': 'Test Group',
        'notes': 'My notes',
        'refresh_interval': 360,
        'parent_server_group_id': 1,
        'policy_list': [0],
    }

    client = util_mock_client()
    result = create_group(client, args)
    group = result.outputs

    assert group['ui_color'] == args['color']
    assert group['name'] == args['name']
    assert group['notes'] == args['notes']
    assert group['refresh_interval'] == args['refresh_interval']
    assert group['parent_server_group_id'] == args['parent_server_group_id']
    assert group['policies'] == args['policy_list']
    assert group['organization_id'] == org_id


def test_delete_device(requests_mock):
    from Automox import delete_device
    org_id = 1
    device_id = 123

    requests_mock.delete(f"{TEST_URL}/servers/{device_id}")

    args = {
        'org_id': org_id,
        'device_id': device_id,
    }

    client = util_mock_client()
    result = delete_device(client, args)

    assert f"Device: {device_id}" in result.readable_output


def test_delete_group(requests_mock):
    from Automox import delete_group
    org_id = 1
    group_id = 1

    requests_mock.delete(f"{TEST_URL}/servergroups/{group_id}")

    args = {
        'org_id': org_id,
        'group_id': group_id,
    }

    client = util_mock_client()
    result = delete_group(client, args)

    assert f"Group: {group_id}" in result.readable_output


def test_get_vulnerability_sync_batch(requests_mock):
    from Automox import get_vulnerability_sync_batch
    org_id = 1
    batch_id = 1

    expected_response = util_load_json("./test_data/automox-vulnerability-sync-batch-get.json")
    requests_mock.get(f"{TEST_URL}/orgs/{org_id}/tasks/batches/{batch_id}", json=expected_response)

    args = {
        'org_id': org_id,
        'batch_id': batch_id
    }

    client = util_mock_client()
    result = get_vulnerability_sync_batch(client, args)

    assert result.outputs_prefix == "Automox.VulnSyncBatch"
    assert result.outputs['id'] == 1
    assert result.outputs['organization_id'] == 1


def test_list_devices(requests_mock):
    from Automox import list_devices

    expected_response = util_load_json("./test_data/automox-devices-list.json")
    requests_mock.get(f"{TEST_URL}/servers", json=expected_response)

    client = util_mock_client()

    args = {
        'org_id': 1,
        'group_id': 10,
        'limit': 50,
        'page': 0,
    }

    result = list_devices(client, args)

    outputs = result.outputs

    assert result.outputs_prefix == "Automox.Devices"
    assert len(outputs) == 1
    assert "detail" not in outputs[0]


def test_list_groups(requests_mock):
    from Automox import list_groups
    org_id = 1

    expected_response = util_load_json("./test_data/automox-groups-list.json")
    requests_mock.get(f"{TEST_URL}/servergroups", json=expected_response)

    args = {
        'org_id': org_id,
        'limit': 50,
        'page': 0,
    }

    client = util_mock_client()
    result = list_groups(client, args)

    assert result.outputs_prefix == "Automox.Groups"
    assert "wsus_config" not in result.outputs[0]
    assert result.outputs[0]['organization_id'] == org_id


def test_list_organization_users(requests_mock):
    from Automox import list_organization_users
    org_id = 1

    expected_response = util_load_json("./test_data/automox-organization-users-list.json")
    requests_mock.get(f"{TEST_URL}/users", json=expected_response)

    args = {
        'org_id': org_id,
        'limit': 50,
        'page': 0,
    }

    client = util_mock_client()
    result = list_organization_users(client, args)

    assert result.outputs_prefix == "Automox.Users"
    assert "prefs" not in result.outputs[0]
    assert result.outputs[0]['orgs'][0]['id'] == org_id


def test_list_organizations(requests_mock):
    from Automox import list_organizations

    expected_response = util_load_json("./test_data/automox-organizations-list.json")
    requests_mock.get(f"{TEST_URL}/orgs", json=expected_response)

    args = {
        "limit": 50,
        "page": 0,
    }

    client = util_mock_client()
    result = list_organizations(client, args)

    assert result.outputs_prefix == "Automox.Organizations"
    assert "addr1" not in result.outputs[0]


def test_list_policies(requests_mock):
    from Automox import list_policies
    org_id = 1

    expected_response = util_load_json("./test_data/automox-policies-list.json")
    requests_mock.get(f"{TEST_URL}/policies", json=expected_response)

    args = {
        "org_id": org_id,
        "limit": 50,
        "page": 0,
    }

    client = util_mock_client()
    result = list_policies(client, args)

    assert result.outputs_prefix == "Automox.Policies"
    assert result.outputs[0]['organization_id'] == org_id


def test_list_vulnerability_sync_batches(requests_mock):
    from Automox import list_vulnerability_sync_batches
    org_id = 1

    expected_response = util_load_json("./test_data/automox-vulnerability-sync-batches-list.json")
    requests_mock.get(f"{TEST_URL}/orgs/{org_id}/tasks/batches", json=expected_response)

    args = {
        'org_id': org_id,
        'limit': 50,
        'page': 0,
    }

    client = util_mock_client()
    result = list_vulnerability_sync_batches(client, args)

    assert result.outputs_prefix == "Automox.VulnSyncBatches"
    assert result.outputs[0]['organization_id'] == org_id


def test_list_vulnerability_sync_tasks(requests_mock):
    from Automox import list_vulnerability_sync_tasks
    org_id = 10586
    batch_id = 1

    expected_response = util_load_json("./test_data/automox-vulnerability-sync-tasks-list.json")
    requests_mock.get(f"{TEST_URL}/orgs/{org_id}/tasks", json=expected_response)

    args = {
        'org_id': org_id,
        'batch_id': batch_id,
        'status': None,
        'limit': 50,
        'page': 0,
    }

    client = util_mock_client()
    result = list_vulnerability_sync_tasks(client, args)

    assert result.outputs_prefix == "Automox.VulnSyncTasks"
    assert result.outputs[0]['organization_id'] == org_id


def test_run_command(requests_mock):
    from Automox import run_command
    org_id = 1
    device_id = 1
    command_type_name = "GetOS"
    args = ""

    requests_mock.post(f"{TEST_URL}/servers/{device_id}/queues", status_code=201, json={})

    args = {
        'org_id': org_id,
        'device_id': device_id,
        'command': command_type_name,
        'args': args,
    }

    client = util_mock_client()
    result = run_command(client, args)

    assert f"Command: {command_type_name}" in result.readable_output
    assert f"device ID: {device_id}" in result.readable_output


def test_update_device(requests_mock):
    from Automox import update_device
    device_id = 1

    expected_response = util_load_json("./test_data/automox-device-get.json")
    requests_mock.get(f"{TEST_URL}/servers/{device_id}", json=expected_response)
    requests_mock.put(f"{TEST_URL}/servers/{device_id}", status_code=204)

    args = {
        'device_id': device_id,
        'server_group_id': 1,
        'custom_name': "Custom name string",
        'tags': "tag1,tag2",
        'ip_addrs': "1.1.1.1",
        'exception': False,
    }

    client = util_mock_client()
    result = update_device(client, args)

    assert f"Device: {device_id}" in result.readable_output


def test_update_group(requests_mock):
    from Automox import update_group
    group_id = 1
    name = "Test Group"

    expected_response = util_load_json("./test_data/automox-groups-list.json")
    requests_mock.get(f"{TEST_URL}/servergroups/{group_id}", json=expected_response)
    requests_mock.put(f"{TEST_URL}/servergroups/{group_id}", status_code=204, json={})

    args = {
        'group_id': group_id,
        'color': '#FFFFFF',
        'name': name,
        'notes': 'My notes',
        'refresh_interval': 360,
        'parent_server_group_id': 1,
        'policies': "0",
    }

    client = util_mock_client()
    result = update_group(client, args)

    assert f"Group: {group_id} ({name})" in result.readable_output


def test_upload_vulnerability_sync_file(requests_mock, mocker):
    from Automox import upload_vulnerability_sync_file
    org_id = 10586
    report_source = "Generic Report"
    entry_id = "123"
    csv_file_name = "report.csv"
    task_type = "patch"

    expected_response = util_load_json("./test_data/automox-vulnerability-sync-file-upload.json")
    requests_mock.post(f"{TEST_URL}/orgs/{org_id}/tasks/{task_type}/batches/upload", json=expected_response)

    mock_file = {
        'id': 'test_id',
        'path': 'test_data/xsoar_vuln_test.csv',
        'name': 'xsoar_vuln_test.csv',
    }
    mocker.patch.object(demisto, 'getFilePath', return_value=mock_file)

    args = {
        'org_id': org_id,
        'reports_source': report_source,
        'entry_id': entry_id,
        'csv_file_name': csv_file_name,
        'task_type': task_type,
    }

    client = util_mock_client()
    result = upload_vulnerability_sync_file(client, args)

    assert result.outputs_prefix == "Automox.VulnUpload"
    assert result.outputs['batch_id'] > 0
