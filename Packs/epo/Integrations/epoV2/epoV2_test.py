"""Imports"""
from epoV2 import *

"""
import pytest
import demistomock as demisto
from CommonServerPython import Common
"""

EPO_URL = 'https://test.com'

''' HELPER FUNCTIONS '''


def load_test_data_txt(file_path):
    with open(file_path) as f:
        return f.read()


def test_error_message(requests_mock):
    """
    Testing the error message generated
    Args:
        requests_mock ():

    Returns:
        test results
    """
    epo_core_help_error_response = load_test_data_txt('test_data/epo_error_message_validation.txt')
    requests_mock.get(f'{EPO_URL}/remote/core.help?%3Aoutput=json&command=ERROR', text=epo_core_help_error_response)
    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ":output": "json",
        "command": "ERROR"
    }

    try:
        epo_help_command(client, args=args)
    except DemistoException as exp:
        assert exp.message == 'Error occurred. Status: (Error) Code: (0) Result: Command was not found: ERROR'


def test_epo_help_command(requests_mock):
    """
    Unit test for the epo_help_command
    Args:
        requests_mock (): mocking the http GET request
    Returns:
    test Passed or Failed
    """

    epo_core_help_response = load_test_data_txt('test_data/epo_help_command.txt')
    requests_mock.get(f'{EPO_URL}/remote/core.help?%3Aoutput=json', text=epo_core_help_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ":output": "json",
        "search": "clienttask.find"
    }

    result = epo_help_command(client, args=args)
    expected_output = '#### ePO Help\n- **clienttask.find [searchText]** -  Finds client tasks\n'

    assert expected_output == result.readable_output


def test_epo_get_latest_dat_command(requests_mock):
    """
    Unit test to validate epo_get_latest_dat_command
    Args:
        request_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    epo_latest_dat_file_response = load_test_data_txt('test_data/epo_get_latest_dat_command.ini')
    epo_latest_dat_file_response = epo_latest_dat_file_response.replace('\n', '\r\n')
    requests_mock.get('http://update.nai.com/products/commonupdater/gdeltaavv.ini', text=epo_latest_dat_file_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    result = epo_get_latest_dat_command(client)

    assert result.outputs is not None
    assert result.readable_output == 'McAfee ePO Latest DAT file version available is: **10167**\n'


def test_epo_get_current_dat_command(requests_mock):
    """
    Unit test to validate epo_get_current_dat_command
    Args:
        request_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    epo_get_current_dat_file_response = load_test_data_txt('test_data/epo_get_current_dat_command.txt')
    epo_get_current_dat_file_response = epo_get_current_dat_file_response.replace('\n', '\n\r')
    requests_mock.get(f'{EPO_URL}/remote/repository.findPackages?:output=json&searchText=VSCANDAT1000',
                      text=epo_get_current_dat_file_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    result = epo_get_current_dat_command(client)

    assert result.outputs is not None
    assert result.readable_output == 'McAfee ePO Current DAT file version in repository is: **10166**\n'


def test_epo_command_command(requests_mock):
    """
    Unit test to validate epo_get_command_command
    Args:
        request_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    epo_command_command_response = load_test_data_txt('test_data/epo_command_command.txt')

    requests_mock.get(f'{EPO_URL}/remote/repository.findPackages?:output=json&searchText=VSCANDAT1000',
                      text=epo_command_command_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ":output": "json",
        "command": "repository.findPackages",
        "searchText": "VSCANDAT1000"
    }

    result = epo_command_command(client, args)

    epo_command_command_result = load_test_data_txt('test_data/epo_command_command_results.txt')

    assert result.outputs is None
    assert result.raw_response == epo_command_command_result


def test_epo_update_client_dat_command(requests_mock):
    """
       Unit test to validate epo_update_client_dat_command
       Args:
           request_mock ():mocking the http GET request
       Returns:
       test Passed or Failed
       """
    epo_get_client_task_id_by_name = load_test_data_txt('test_data/epo_get_client_task_id_by_name.txt')
    requests_mock.get(f'{EPO_URL}/remote/clienttask.run?names=192.168.1.102&%3Aoutput=json&productId=EPOAGENTMETA'
                      f'&taskId=33&retryAttempts=1&retryIntervalInSeconds=5&abortAfterMinutes=5&stopAfterMinutes=20'
                      f'&randomizationInterval=0',
                      text="OK:\nSucceeded")
    requests_mock.get(f'{EPO_URL}/remote/clienttask.find?searchText=VSEContentUpdateDemisto&%3Aoutput=json',
                      text=epo_get_client_task_id_by_name)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'systems': '192.168.1.102',
        ':output': 'json',
        'productId': 'EPOAGENTMETA',
        'taskId': '33',
        'retryAttempts': '1',
        'retryIntervalInSeconds': '5',
        'abortAfterMinutes': '5',
        'stopAfterMinutes': '20',
        'randomizationInterval': '0'
    }

    result = epo_update_client_dat_command(client, args)

    assert result.outputs is None
    assert result.readable_output == 'ePO client DAT update task started: Succeeded'


def test_epo_get_system_tree_groups_command(requests_mock):
    """
    Unit test to validate epo_get_system_tree_groups_command
    Args:
        request_mock ():mocking the http GET request

    Returns:
    test Passed or Failed
    """
    epo_get_system_tree_groups_response = load_test_data_txt('test_data/epo_get_system_tree_groups_command.txt')
    requests_mock.get(f'{EPO_URL}/remote/system.findGroups?%3Aoutput=json&searchText=workgroup',
                      text=epo_get_system_tree_groups_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ':output': 'json',
        'search': 'workgroup'
    }

    result = epo_get_system_tree_groups_command(client, args)

    assert result.outputs == [{'groupId': 6, 'groupPath': 'My Organization\\Lost&Found\\WORKGROUP'}]


def test_epo_find_systems_command(requests_mock):
    """
    Unit test to validate epo_find_systems_command
    Args:
        request_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    epo_find_systems_command_response = load_test_data_txt('test_data/epo_find_systems_command.txt')
    epo_get_system_tree_groups_response = load_test_data_txt('test_data/epo_get_system_tree_groups.txt')
    requests_mock.get(f'{EPO_URL}/remote/system.findGroups?%3Aoutput=json', text=epo_get_system_tree_groups_response)
    requests_mock.get(f'{EPO_URL}/remote/epogroup.findSystems?%3Aoutput=json&groupId=2',
                      text=epo_find_systems_command_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ':output': 'json',
        'groupId': '2'
    }

    result = epo_find_systems_command(client, args)

    assert len(result) == 7
    assert result[0].outputs[0] == {'AutoID': 2, 'CPUSerialNum': '', 'CPUSpeed': 0, 'CPUType': '',
                                    'ComputerName': '10.0.0.1', 'DefaultLangID': '', 'Description': None,
                                    'DomainName': '',
                                    'FreeDiskSpace': 0, 'FreeMemory': 0, 'IPAddress': '', 'Hostname': '',
                                    'IPSubnet': None,
                                    'IPSubnetMask': None, 'IPV4x': None, 'IPV6': None, 'IPXAddress': '',
                                    'NetAddress': '', 'NumOfCPU': 0, 'OSBuildNum': 0, 'OSOEMID': '',
                                    'OSPlatform': '', 'OSServicePackVer': '', 'OSType': '', 'OSVersion': '',
                                    'ParentID': 7, 'SubnetAddress': '', 'SubnetMask': '', 'SystemDescription': None,
                                    'SysvolFreeSpace': 0, 'SysvolTotalSpace': 0, 'TimeZone': '', 'TotalDiskSpace': 0,
                                    'TotalPhysicalMemory': 0, 'UserName': '', 'UserProperty1': None,
                                    'UserProperty2': None, 'UserProperty3': None, 'UserProperty4': None,
                                    'AgentGUID': None, 'AgentVersion': None, 'ExcludedTags': '', 'LastUpdate': None,
                                    'ManagedState': 0, 'Tags': 'Scan Now'}


def test_epo_find_system_command(requests_mock):
    """
    Unit test to validate epo_find_system_command
    Args:
        requests_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    epo_find_system_command_response = load_test_data_txt('test_data/epo_find_system_command.txt')

    requests_mock.get(f'{EPO_URL}/remote/system.find?%3Aoutput=json&searchText=192.168.1.102',
                      text=epo_find_system_command_response)
    requests_mock.get(f'{EPO_URL}/remote/system.find?%3Aoutput=json&searchText=192.168.1.105',
                      text='OK:\n[ ]')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ':output': 'json',
        'searchText': '192.168.1.102'
    }

    result = epo_find_system_command(client, args)

    assert len(result.outputs) == 1
    assert result.outputs[0] == {'AutoID': 3, 'CPUSerialNum': 'N/A', 'CPUSpeed': 2600,
                                 'CPUType': 'Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz', 'ComputerName': 'tie',
                                 'DefaultLangID': '0409', 'Description': None, 'DomainName': '(none)',
                                 'FreeDiskSpace': 93781, 'FreeMemory': 261951488, 'IPAddress': '',
                                 'Hostname': 'tie', 'IPSubnet': '', 'IPSubnetMask': '', 'IPV4x': 1084752230,
                                 'IPV6': '', 'IPXAddress': 'N/A', 'NetAddress': '000C29B1EE8E', 'NumOfCPU': 8,
                                 'OSBuildNum': 0, 'OSOEMID': 'McAfee TIE Platform Server 3.0.0.480',
                                 'OSPlatform': 'Server', 'OSServicePackVer': '189-1.mlos2.x86_64',
                                 'OSType': 'Linux', 'OSVersion': '4.9', 'ParentID': 2, 'SubnetAddress': '',
                                 'SubnetMask': '', 'SystemDescription': 'N/A', 'SysvolFreeSpace': 0,
                                 'SysvolTotalSpace': 0, 'TimeZone': 'UTC', 'TotalDiskSpace': 104488,
                                 'TotalPhysicalMemory': 8364199936, 'UserName': 'root', 'UserProperty1': None,
                                 'UserProperty2': None, 'UserProperty3': None, 'UserProperty4': None,
                                 'AgentGUID': 'E0F52A7C-A841-11E7-0467-000C2936A49A', 'AgentVersion': '',
                                 'ExcludedTags': '', 'LastUpdate': '2021-11-21T13:11:42-08:00', 'ManagedState': 1,
                                 'Tags': 'DXLBROKER, Server, TIESERVER'}

    args = {
        ':output': 'json',
        'searchText': '192.168.1.105'
    }

    result = epo_find_system_command(client, args)

    assert result.outputs is None
    assert result.readable_output == '#### Systems in the System Tree\nNo systems found\n'

    args = {
        ':output': 'json',
        'searchText': '192.168.1.102',
        'verbose': 'true'
    }

    result = epo_find_system_command(client, args)

    assert result.outputs
    assert result.outputs[0] == {'AutoID': 3, 'CPUSerialNum': 'N/A', 'CPUSpeed': 2600,
                                 'CPUType': 'Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz', 'ComputerName': 'tie',
                                 'DefaultLangID': '0409', 'Description': None, 'DomainName': '(none)',
                                 'FreeDiskSpace': 93781, 'FreeMemory': 261951488, 'IPAddress': '',
                                 'Hostname': 'tie', 'IPSubnet': '', 'IPSubnetMask': '', 'IPV4x': 1084752230,
                                 'IPV6': '', 'IPXAddress': 'N/A', 'NetAddress': '000C29B1EE8E', 'NumOfCPU': 8,
                                 'OSBuildNum': 0, 'OSOEMID': 'McAfee TIE Platform Server 3.0.0.480',
                                 'OSPlatform': 'Server', 'OSServicePackVer': '189-1.mlos2.x86_64',
                                 'OSType': 'Linux', 'OSVersion': '4.9', 'ParentID': 2, 'SubnetAddress': '',
                                 'SubnetMask': '', 'SystemDescription': 'N/A', 'SysvolFreeSpace': 0,
                                 'SysvolTotalSpace': 0, 'TimeZone': 'UTC', 'TotalDiskSpace': 104488,
                                 'TotalPhysicalMemory': 8364199936, 'UserName': 'root', 'UserProperty1': None,
                                 'UserProperty2': None, 'UserProperty3': None, 'UserProperty4': None,
                                 'AgentGUID': 'E0F52A7C-A841-11E7-0467-000C2936A49A', 'AgentVersion': '',
                                 'ExcludedTags': '', 'LastUpdate': '2021-11-21T13:11:42-08:00', 'ManagedState': 1,
                                 'Tags': 'DXLBROKER, Server, TIESERVER'}
    assert result.readable_output.find('EPOLeafNode.AgentVersion | ') >= 0


def test_epo_wakeup_agent_command(requests_mock):
    """
    Unit test to validate epo_wakeup_agent_command
    Args:
        requests_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    requests_mock.get(f'{EPO_URL}/remote/system.wakeupAgent?%3Aoutput=json&names=192.168.1.102',
                      text='OK:\n"completed: 1\\nfailed: 0\\nexpired: 0"')
    requests_mock.get(f'{EPO_URL}/remote/system.wakeupAgent?%3Aoutput=json&names=192.168.1.105',
                      text='OK:\n"No systems found to wake up.  Please enter valid computer ids\u002fnames."')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ':output': 'json',
        'names': '192.168.1.102'
    }

    result = epo_wakeup_agent_command(client, args)

    assert result.outputs is None
    assert result.readable_output == '#### ePO agents was awaken.\n| Completed | Failed | Expired |\n|-|-|-|\n|1|0|0|'

    args = {
        ':output': 'json',
        'names': '192.168.1.105'
    }

    result = epo_wakeup_agent_command(client, args)

    assert result.outputs is None
    assert result.readable_output == '#### No systems were found.'


def test_epo_apply_tag_command(requests_mock):
    """
    Unit test to validate epo_epo_apply_tag_command
    Args:
        requests_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    requests_mock.get(f'{EPO_URL}/remote/system.applyTag?%3Aoutput=json&names=192.168.1.102&tagName=Server',
                      text='OK:\n0')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ':output': 'json',
        'names': '192.168.1.102',
        'tagName': 'Server'
    }

    result = epo_apply_tag_command(client, args)

    assert result.outputs is None
    assert result.readable_output == 'ePO could not find server or server already assigned to the given tag.\n'


def test_epo_clear_tag_command(requests_mock):
    """
    Unit test to validate epo_epo_clear_tag_command
    Args:
        requests_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    requests_mock.get(f'{EPO_URL}/remote/system.clearTag?%3Aoutput=json&names=192.168.1.102&tagName=Server',
                      text='OK:\n0')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ':output': 'json',
        'names': '192.168.1.102',
        'tagName': 'Server'
    }

    result = epo_clear_tag_command(client, args)

    assert result.outputs is None
    assert result.readable_output == 'ePO could not find server or server already assigned to the given tag.\n'


def test_epo_list_tag_command(requests_mock):
    """
    Unit test to validate epo_epo_list_tag_command
    Args:
        requests_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    epo_list_tag_command_response = load_test_data_txt('test_data/epo_list_tag_command.txt')
    requests_mock.get(f'{EPO_URL}/remote/system.findTag?%3Aoutput=json&searchText=TIESERVER',
                      text=epo_list_tag_command_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ':output': 'json',
        'searchText': 'TIESERVER',
    }

    result = epo_list_tag_command(client, args)

    assert result.outputs == [{'tagId': 4, 'tagName': 'TIESERVER', 'tagNotes': 'Apply Tag to TIEServers'}]
    assert result.readable_output == '### ePO Tags\n|tagId|tagName|tagNotes|\n|---|---|---|\n| 4 | TIESERVER | Apply ' \
                                     'Tag to TIEServers |\n'


def test_epo_get_tables_command(requests_mock):
    """
    Unit test to validate epo_get_tables_command
    Args:
        requests_mock ():mocking the http GET request
    Returns:
    test Passed or Failed
    """
    epo_get_tables_command_response = load_test_data_txt('test_data/epo_get_tables_command.txt')
    requests_mock.get(f'{EPO_URL}/remote/core.listTables?%3Aoutput=json&table=Tags',
                      text=epo_get_tables_command_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ':output': 'json',
        'table': 'tags',
    }

    result = epo_get_tables_command(client, args)

    assert result.outputs is None
    assert result.readable_output.startswith("### ePO tables")
    assert result.readable_output.find('string_lookup') >= 0


def test_epo_query_table_command(requests_mock):
    """
        Unit test to validate epo_query_tables_command
    Args:
        requests_mock ():mocking the http GET request
    Returns:
        test Passed or Failed
    """
    epo_query_table_command_response = load_test_data_txt('test_data/epo_query_table_command.txt')
    requests_mock.get(f'{EPO_URL}/remote/core.executeQuery?target=EPOEvents&select=(select EPOEvents.AutoID '
                      f'EPOEvents.DetectedUTC EPOEvents.ReceivedUTC)&:output=json',
                      text=epo_query_table_command_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        ':output': 'json',
        'target': 'EPOEvents',
        'select': '(select EPOEvents.AutoID EPOEvents.DetectedUTC EPOEvents.ReceivedUTC)'
    }

    result = epo_query_table_command(client, args)

    assert len(result.outputs) == 5
    assert result.readable_output.find('EPOEvents.ReceivedUTC') >= 0


def test_epo_get_version_command(requests_mock):
    """
       Unit test to validate epo_get_version_command
    Args:
       requests_mock ():mocking the http GET request
    Returns:
       test Passed or Failed
    """
    requests_mock.get(f'{EPO_URL}/remote/epo.getVersion?:output=json',
                      text='OK:\n"5.3.2"')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    result = epo_get_version_command(client)

    assert result.outputs == '5.3.2'
    assert result.readable_output == '### ePO version is: 5.3.2'


def test_epo_move_system_command(requests_mock):
    """
       Unit test to validate epo_get_version_command
    Args:
       requests_mock ():mocking the http GET request
    Returns:
       test Passed or Failed
    """
    requests_mock.get(f'{EPO_URL}/remote/system.move?names=TIE&parentGroupId=2',
                      text='OK:\ntrue')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'names': 'TIE',
        'parentGroupId': '2'
    }
    result = epo_move_system_command(client, args)

    assert result.outputs is None
    assert result.readable_output == 'System(s) TIE moved successfully to GroupId 2'


def test_epo_advanced_command(requests_mock):
    """
       Unit test to validate epo_advanced_command
    Args:
       requests_mock ():mocking the http GET request
    Returns:
       test Passed or Failed
    """
    epo_advanced_command_command_response = load_test_data_txt('test_data/epo_advanced_command_command.txt')
    epo_advanced_command_command_response_second = load_test_data_txt(
        'test_data/epo_advanced_command_command_second.txt')

    requests_mock.get(f'{EPO_URL}/remote/clienttask.find?searchText=On-demand&%3Aoutput=json',
                      text=epo_advanced_command_command_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'command': 'clienttask.find',
        'commandArgs': 'searchText:On-demand'
    }
    result = epo_advanced_command_command(client, args)

    assert result.outputs is None
    assert result.readable_output.find('### ePO command *clienttask.find* results:') >= -1

    requests_mock.get(f'{EPO_URL}/remote/clienttask.run?names=TIE&productId=ENDP_AM_1000&taskId=28&retryAttempts=2'
                      f'&retryIntervalInSeconds=120&useAllAgentHandlers=False&stopAfterMinutes=180&%3Aoutput=json',
                      text=epo_advanced_command_command_response_second)

    args = {
        'command': 'clienttask.run',
        'commandArgs': 'names:TIE,productId:ENDP_AM_1000,taskId:28,retryAttempts:2,retryIntervalInSeconds:120,'
                       'useAllAgentHandlers:False,stopAfterMinutes:180'
    }
    result = epo_advanced_command_command(client, args)

    assert result.outputs is None
    assert result.readable_output == '#### ePO command *clienttask.run * results:\n  Succeeded'


def test_epo_find_client_task_command(requests_mock):
    """
       Unit test to validate epo_find_client_task_command
    Args:
       requests_mock ():mocking the http GET request
    Returns:
       test Passed or Failed
    """
    epo_find_client_task_command_response = load_test_data_txt('test_data/epo_find_client_task_command.txt')
    requests_mock.get(f'{EPO_URL}/remote/clienttask.find?searchText=endp&%3Aoutput=json',
                      text=epo_find_client_task_command_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'searchText': 'endp'
    }
    result = epo_find_client_task_command(client, args)

    assert result.outputs
    assert result.readable_output.startswith('### ePO command *clienttask.find* results:') >= -1


def test_epo_find_policy_command(requests_mock):
    """
       Unit test to validate epo_find_policy_command
    Args:
       requests_mock ():mocking the http GET request
    Returns:
       test Passed or Failed
    """
    epo_find_policy_command_response = load_test_data_txt('test_data/epo_find_policy_command.txt')
    requests_mock.get(f'{EPO_URL}/remote/policy.find?searchText=endp&%3Aoutput=json',
                      text=epo_find_policy_command_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'searchText': 'endp'
    }
    result = epo_find_policy_command(client, args)

    assert len(result.outputs) == 34
    assert result.readable_output.startswith('### ePO Policies:')


def test_epo_assign_policy_to_group_command(requests_mock):
    """
       Unit test to validate epo_assign_policy_to_group_command
    Args:
       requests_mock ():mocking the http GET request
    Returns:
       test Passed or Failed
    """
    requests_mock.get(f'{EPO_URL}/remote/policy.assignToGroup?%3Aoutput=json&groupId=2&productId=ENDP_AM_1000'
                      f'&objectId=90&resetInheritance=False',
                      text='OK:\ntrue')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'groupId': '2',
        'productId': 'ENDP_AM_1000',
        'objectId': '90'
    }
    result = epo_assign_policy_to_group(client, args)

    assert result.outputs is None
    assert result.readable_output == 'Policy productId:ENDP_AM_1000 objectId:90 assigned successfully to GroupId 2'


def test_epo_assign_policy_to_system_command(requests_mock):
    """
       Unit test to validate epo_assign_policy_to_group_command
    Args:
       requests_mock ():mocking the http GET request
    Returns:
       test Passed or Failed
    """
    epo_assign_policy_to_system_response = load_test_data_txt('test_data/epo_assign_policy_to_system.txt')
    epo_assign_policy_to_system_response_err = load_test_data_txt('test_data/epo_assign_policy_to_system_err.txt')
    requests_mock.get(f'{EPO_URL}/remote/policy.assignToSystem?%3Aoutput=json&names=192.168.1.102&'
                      f'productId=ENDP_FW_META&typeId=29&objectId=63',
                      text=epo_assign_policy_to_system_response)
    requests_mock.get(f'{EPO_URL}/remote/policy.assignToSystem?%3Aoutput=json&names=192.168.1.105&'
                      f'productId=ENDP_FW_META&typeId=29&objectId=63',
                      text=epo_assign_policy_to_system_response_err)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'names': '192.168.1.102',
        'productId': 'ENDP_FW_META',
        'objectId': '63',
        'typeId': '29'
    }
    result = epo_assign_policy_to_system(client, args)

    assert result.outputs is None
    assert result.readable_output.find('Assign policy succeeded') >= 0

    args = {
        'names': '192.168.1.105',
        'productId': 'ENDP_FW_META',
        'objectId': '63',
        'typeId': '29'
    }
    result = epo_assign_policy_to_system(client, args)

    assert result.outputs is None
    assert result.readable_output.find('Unable to take action on the computer because it may not exist') >= 0


def test_epo_list_issues(requests_mock):
    """
        Unit test to validate epo_list_issues
    Args:
        requests_mock ():mocking the http GET request
    Returns:
        test Passed or Failed
    """
    epo_list_issues_command_response = load_test_data_txt('test_data/epo_list_issues_comand.txt')
    requests_mock.get(f'{EPO_URL}/remote/issue.listIssues?%3Aoutput=json',
                      text=epo_list_issues_command_response)

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {

    }
    result = epo_list_issues_command(client, args)

    assert result.outputs[0]['assigneeName'] == 'dxl'
    assert result.readable_output


def test_epo_delete_issue(requests_mock):
    """
        Unit test to validate epo_delete_issie
    Args:
        requests_mock ():mocking the http GET request
    Returns:
        test Passed or Failed
    """
    requests_mock.get(f'{EPO_URL}/remote/issue.deleteIssue?%3Aoutput=json&id=2',
                      text='OK:\n9')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'id': '2'
    }
    result = epo_delete_issue_command(client, args)

    assert result.readable_output == 'Issue with id=9 was deleted'


def test_epo_update_issue(requests_mock):
    """
        Unit test to validate epo_delete_issie
    Args:
        requests_mock ():mocking the http GET request
    Returns:
        test Passed or Failed
    """
    requests_mock.get(f'{EPO_URL}/remote/issue.updateIssue?id=9&name=WISSAM&desc=Test1&state=NEW',
                      text='OK:\n9')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'id': '9',
        'name': 'WISSAM',
        'description': 'Test1',
        'state': 'NEW'
    }
    result = epo_update_issue_command(client, args)

    assert result.readable_output == 'Issue with id=9 was updated'


def test_epo_create_issue(requests_mock):
    """
        Unit test to validate epo_create_issie
    Args:
        requests_mock ():mocking the http GET request
    Returns:
        test Passed or Failed
    """
    requests_mock.get(f'{EPO_URL}/remote/issue.createIssue?%3Aoutput=json&name=auto-gen-epo-integration&desc'
                      f'=automatically+generated+by+dmst+Integration+v2',
                      text='OK:\n5')

    client = Client(
        base_url=f'{EPO_URL}/remote', headers={}, auth=('', '')
    )

    args = {
        'name': 'auto-gen-epo-integration',
        'description': 'automatically generated by dmst Integration v2'
    }
    result = epo_create_issue_command(client, args)

    assert result.outputs[0]['id'] == 5
    assert result.readable_output == 'Issue with the following ID: 5 was created successfully'
