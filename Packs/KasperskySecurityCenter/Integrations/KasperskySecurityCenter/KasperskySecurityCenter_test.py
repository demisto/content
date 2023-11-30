import json

import pytest

from KasperskySecurityCenter import (GROUP_FIELDS, HOST_DETAILED_FIELDS,
                                     HOST_FIELDS, Client, add_group,
                                     delete_group, get_host, get_policy,
                                     list_groups,
                                     list_host_software_applications,
                                     list_host_software_patches, list_hosts,
                                     list_policies, list_software_applications,
                                     list_software_patches)

SERVER_URL = 'https://server:13299/api/v1.0'


@pytest.fixture()
def client():
    return Client(base_url=SERVER_URL)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_list_hosts(client, requests_mock):
    """
    Given:
        - Filter to list hosts by
    When:
        - Running list hosts command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    wstr_filter = 'KLHST_WKS_OS_NAME = "Microsoft Windows Server 2016"'
    limit = '10'
    args = {
        'filter': wstr_filter,
        'limit': limit,
    }
    find_hosts_api_response = util_load_json('./test_data/find_response.json')
    requests_mock.post(SERVER_URL + '/HostGroup.FindHosts', json=find_hosts_api_response)
    hosts_items_api_response = util_load_json('./test_data/hosts_list_response.json')
    requests_mock.post(SERVER_URL + '/ChunkAccessor.GetItemsChunk', json=hosts_items_api_response)

    result = list_hosts(client=client, args=args)

    assert requests_mock.request_history[0].json() == {
        'wstrFilter': wstr_filter,
        'lMaxLifeTime': 600,
        'vecFieldsToReturn': HOST_FIELDS,
    }
    assert requests_mock.request_history[1].json() == {
        'strAccessor': find_hosts_api_response['strAccessor'],
        'nStart': 0,
        'nCount': int(limit),
    }
    assert result.outputs == [
        host.get('value') for host in hosts_items_api_response.get('pChunk', {}).get('KLCSP_ITERATOR_ARRAY')
    ]


def test_get_host(client, requests_mock):
    """
    Given:
        - Name of host to get
    When:
        - Running get host command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    hostname = '025ed284-389b-44c5-a9ef-6e723f7d9466'
    args = {
        'hostname': hostname,
    }
    find_hosts_api_response = util_load_json('./test_data/find_response.json')
    requests_mock.post(SERVER_URL + '/HostGroup.FindHosts', json=find_hosts_api_response)
    host_get_api_response = util_load_json('./test_data/host_get_response.json')
    requests_mock.post(SERVER_URL + '/ChunkAccessor.GetItemsChunk', json=host_get_api_response)

    result = get_host(client=client, args=args)

    assert requests_mock.request_history[0].json() == {
        'wstrFilter': f'KLHST_WKS_HOSTNAME = "{hostname}"',
        'lMaxLifeTime': 600,
        'vecFieldsToReturn': HOST_DETAILED_FIELDS,
    }
    assert requests_mock.request_history[1].json() == {
        'strAccessor': find_hosts_api_response['strAccessor'],
        'nStart': 0,
        'nCount': 50,
    }
    assert result.outputs == host_get_api_response['pChunk']['KLCSP_ITERATOR_ARRAY'][0]['value']


def test_list_groups(client, requests_mock):
    """
    Given:
        - None
    When:
        - Running list groups command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    find_hosts_api_response = util_load_json('./test_data/find_response.json')
    requests_mock.post(SERVER_URL + '/HostGroup.FindGroups', json=find_hosts_api_response)
    groups_items_api_response = util_load_json('./test_data/groups_list_response.json')
    requests_mock.post(SERVER_URL + '/ChunkAccessor.GetItemsChunk', json=groups_items_api_response)

    result = list_groups(client=client, args={})

    assert requests_mock.request_history[0].json() == {
        'wstrFilter': '',
        'lMaxLifeTime': 600,
        'vecFieldsToReturn': GROUP_FIELDS,
    }
    assert requests_mock.request_history[1].json() == {
        'strAccessor': find_hosts_api_response['strAccessor'],
        'nStart': 0,
        'nCount': 50,
    }
    assert result.outputs == [
        host.get('value') for host in groups_items_api_response.get('pChunk', {}).get('KLCSP_ITERATOR_ARRAY')
    ]


def test_add_group(client, requests_mock):
    """
    Given:
        - Name of group to add
        - ID of parent group
    When:
        - Running add group command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    name = 'TestGroup'
    parent_id = '1'
    args = {
        'name': name,
        'parent_id': parent_id,
    }
    api_response = util_load_json('./test_data/group_add_response.json')
    requests_mock.post(SERVER_URL + '/HostGroup.AddGroup', json=api_response)

    result = add_group(client=client, args=args)

    assert requests_mock.request_history[0].json() == {
        'pInfo': {
            'name': name,
            'parentId': int(parent_id),
        }
    }
    assert result.outputs == {'id': api_response['PxgRetVal'], 'name': name}


def test_delete_group(client, requests_mock):
    """
    Given:
        - ID of group to delete
    When:
        - Running delete group command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    group_id = '4'
    args = {
        'group_id': group_id,
    }
    api_response = util_load_json('./test_data/action_response.json')
    requests_mock.post(SERVER_URL + '/HostGroup.RemoveGroup', json=api_response)

    result = delete_group(client=client, args=args)

    assert requests_mock.request_history[0].json() == {
        'nGroup': int(group_id),
        'nFlags': 1,
    }
    assert result.readable_output == 'Delete group action was submitted'


def test_list_software_applications(client, requests_mock):
    """
    Given:
        - None
    When:
        - Running list software applications command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    api_response = util_load_json('./test_data/software_applications_response.json')
    requests_mock.post(SERVER_URL + '/InventoryApi.GetInvProductsList', json=api_response)

    result = list_software_applications(client=client)

    assert result.outputs == [
        app.get('value') for app in api_response.get('PxgRetVal', {}).get('GNRL_EA_PARAM_1', [])
    ]


def test_list_software_patches(client, requests_mock):
    """
    Given:
        - None
    When:
        - Running list software applications command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    api_response = util_load_json('./test_data/software_patches_response.json')
    requests_mock.post(SERVER_URL + '/InventoryApi.GetInvPatchesList', json=api_response)

    result = list_software_patches(client=client)

    assert result.outputs == [
        app.get('value') for app in api_response.get('PxgRetVal', {}).get('GNRL_EA_PARAM_1', [])
    ]


def test_list_host_software_applications(client, requests_mock):
    """
    Given:
        - ID of host to get application of
    When:
        - Running list host software applications command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    hostname = '025ed284-389b-44c5-a9ef-6e723f7d9466'
    args = {
        'hostname': hostname,
    }

    api_response = util_load_json('./test_data/software_applications_response.json')
    requests_mock.post(SERVER_URL + '/InventoryApi.GetHostInvProducts', json=api_response)

    result = list_host_software_applications(client=client, args=args)

    assert requests_mock.request_history[0].json() == {
        'szwHostId': hostname,
    }
    assert result.outputs == [
        app.get('value') for app in api_response.get('PxgRetVal', {}).get('GNRL_EA_PARAM_1', [])
    ]


def test_list_host_software_patches(client, requests_mock):
    """
    Given:
        - ID of host to get patches of
    When:
        - Running list host software application patches command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    hostname = '025ed284-389b-44c5-a9ef-6e723f7d9466'
    args = {
        'hostname': hostname,
    }

    api_response = util_load_json('./test_data/software_patches_response.json')
    requests_mock.post(SERVER_URL + '/InventoryApi.GetHostInvPatches', json=api_response)

    result = list_host_software_patches(client=client, args=args)

    assert requests_mock.request_history[0].json() == {
        'szwHostId': hostname,
    }
    assert result.outputs == [
        app.get('value') for app in api_response.get('PxgRetVal', {}).get('GNRL_EA_PARAM_1', [])
    ]


def test_list_policies(client, requests_mock):
    """
    Given:
        - None
    When:
        - Running list policies command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    api_response = util_load_json('./test_data/policies_list_response.json')
    requests_mock.post(SERVER_URL + '/Policy.GetPoliciesForGroup', json=api_response)

    result = list_policies(client=client, args={})

    assert requests_mock.request_history[0].json() == {
        'nGroupId': -1,
    }
    assert result.outputs == [policy['value'] for policy in api_response['PxgRetVal']]


def test_get_policy(client, requests_mock):
    """
    Given:
        - ID of policy to get
    When:
        - Running get policy command
    Then:
        - Verify requests are sent as expected
        - Verify command outputs are as expected
    """
    policy_id = '1'
    args = {
        'policy_id': policy_id,
    }

    api_response = util_load_json('./test_data/policies_list_response.json')
    requests_mock.post(SERVER_URL + '/Policy.GetPolicyData', json=api_response)

    result = get_policy(client=client, args=args)

    assert requests_mock.request_history[0].json() == {
        'nPolicy': int(policy_id),
    }
    assert result.outputs == api_response['PxgRetVal']
