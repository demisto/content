import os

from AnsibleApiModule import dict2md, rec_ansible_key_strip, generate_ansible_inventory, generic_ansible
from TestsInput.markdown import MOCK_SINGLE_LEVEL_LIST, EXPECTED_MD_LIST, MOCK_SINGLE_LEVEL_DICT, EXPECTED_MD_DICT
from TestsInput.markdown import MOCK_MULTI_LEVEL_DICT, EXPECTED_MD_MULTI_DICT, MOCK_MULTI_LEVEL_LIST
from TestsInput.markdown import EXPECTED_MD_MULTI_LIST, MOCK_MULTI_LEVEL_LIST_ID_NAMES, EXPECTED_MD_MULTI_LIST_ID_NAMES
from TestsInput.ansible_keys import MOCK_ANSIBLE_DICT, EXPECTED_ANSIBLE_DICT, MOCK_ANSIBLELESS_DICT, \
    EXPECTED_ANSIBLELESS_DICT
from TestsInput.ansible_inventory import ANSIBLE_INVENTORY_HOSTS_LIST, ANSIBLE_INVENTORY_HOSTS_CSV_LIST
from TestsInput.ansible_inventory import ANSIBLE_INVENTORY_HOST_w_PORT, ANSIBLE_INVENTORY_INT_PARAMS
from unittest.mock import patch

fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "network")


def test_dict2md_simple_lists():
    """
    Scenario: Given a simple single level dict or list, dict2md should output a dot point list equivalent

    Given:
    - List of strings
    - Single level dict

    When:
    - Convert to markdownMOCK_ANSIBLE_DICT
    - Validate that the returned text is converted to a markdown list correctly

    """
    markdown_list = dict2md(MOCK_SINGLE_LEVEL_LIST)
    markdown_dict = dict2md(MOCK_SINGLE_LEVEL_DICT)

    assert markdown_list == EXPECTED_MD_LIST
    assert markdown_dict == EXPECTED_MD_DICT


def test_dict2md_complex_lists():
    """
    Scenario: Given a complex multi level dict dict2md should output the markdown equivalent with appropriate level headings

    Given:
    - Multi-level dict
    - List of dicts
    - List of dicts including id and name keys

    When:
    - Convert to markdown

    Then:
    - Validate that the returned text is converted to a markdown correctly

        """
    markdown_multi_dict = dict2md(MOCK_MULTI_LEVEL_DICT)
    markdown_multi_list = dict2md(MOCK_MULTI_LEVEL_LIST)
    markdown_multi_list_id_name = dict2md(MOCK_MULTI_LEVEL_LIST_ID_NAMES)

    assert markdown_multi_dict == EXPECTED_MD_MULTI_DICT
    assert markdown_multi_list == EXPECTED_MD_MULTI_LIST
    assert markdown_multi_list_id_name == EXPECTED_MD_MULTI_LIST_ID_NAMES


def test_rec_ansible_key_strip():
    """
    Scenario: Given a multi level dict rec_ansible_key_strip should recursively remove the string 'ansible_' from any keys

    Given:
    - Multi-level dict with some keys starting with ansible_
    - Multi-level dict with no keys starting with ansible_

    When:
    - rec_ansible_key_strip is used to santise the value

    Then:
    - Return de-branded result

    """
    ansible_dict = rec_ansible_key_strip(MOCK_ANSIBLE_DICT)
    ansibleless_dict = rec_ansible_key_strip(MOCK_ANSIBLELESS_DICT)

    assert ansible_dict == EXPECTED_ANSIBLE_DICT
    assert ansibleless_dict == EXPECTED_ANSIBLELESS_DICT


def test_generate_ansible_inventory_hosts():
    """
    Scenario: Given different types of host input a valid ansible inventory should be generated

    Given:
    A. hosts as a python list
    B. comma seperated list of hosts
    C. host with port specified in args overriding integration port config
    D. host with type of local

    When:
    - credentials are valid

    Then:
    A. Valid Ansible inventory dict is generated with correct number of hosts
    B. Valid Ansible inventory dict is generated with correct number of hosts
    C. Correct port should be present if integration default overridden by command args
    D. host address should not be recorded if host type is local
    """

    # A
    list_inv, _ = generate_ansible_inventory(ANSIBLE_INVENTORY_HOSTS_LIST, ANSIBLE_INVENTORY_INT_PARAMS,
                                             host_type="ssh")
    assert len(list_inv.get('all').get('hosts')) == 3

    # B
    comma_inv, _ = generate_ansible_inventory(ANSIBLE_INVENTORY_HOSTS_CSV_LIST, ANSIBLE_INVENTORY_INT_PARAMS,
                                              host_type="ssh")
    assert len(comma_inv.get('all').get('hosts')) == 2

    # C
    port_override_inv, _ = generate_ansible_inventory(
        ANSIBLE_INVENTORY_HOST_w_PORT, ANSIBLE_INVENTORY_INT_PARAMS, host_type="ssh")
    assert port_override_inv.get('all').get('hosts').get('123.123.123.123:45678').get('ansible_port') == '45678'
    assert port_override_inv.get('all').get('hosts').get('123.123.123.123:45678').get(
        'ansible_host') == '123.123.123.123'

    # D
    local_inv, _ = generate_ansible_inventory(ANSIBLE_INVENTORY_HOST_w_PORT, ANSIBLE_INVENTORY_INT_PARAMS,
                                              host_type="local")
    assert local_inv == {'all': {'hosts': {'localhost': {'ansible_connection': 'local'}}}}


def test_generate_ansible_inventory_creds():
    """
    Scenario: Given different types of credentials the appropriate one should be selected

        Given:
        A. username / sshkey for NXOS host
        B. SSH credential for Linux host
        C. windows winrm credentials

    When:
    - valid host address

    Then:
    - Valid Ansible Inventory dict is generated as appropriate for host type
    """

    # A
    nxos_inv, nxos_sshkey = generate_ansible_inventory(
        ANSIBLE_INVENTORY_HOST_w_PORT, ANSIBLE_INVENTORY_INT_PARAMS, host_type="nxos")
    assert nxos_sshkey == 'aaaaaaaaaaaaaa'
    assert nxos_inv.get('all').get('hosts').get('123.123.123.123:45678').get('ansible_network_os') == 'nxos'
    assert nxos_inv.get('all').get('hosts').get('123.123.123.123:45678').get('ansible_become_method') == 'enable'
    assert nxos_inv.get('all').get('hosts').get('123.123.123.123:45678').get('ansible_user') == 'joe'

    # B
    ssh_inv, ssh_sshkey = generate_ansible_inventory(ANSIBLE_INVENTORY_HOST_w_PORT, ANSIBLE_INVENTORY_INT_PARAMS,
                                                     host_type="ssh")
    assert ssh_sshkey == 'aaaaaaaaaaaaaa'
    assert ssh_inv.get('all').get('hosts').get('123.123.123.123:45678').get('ansible_network_os') is None
    assert ssh_inv.get('all').get('hosts').get('123.123.123.123:45678').get('ansible_user') == 'joe'

    # C
    winrm_inv, winrm_sshkey = generate_ansible_inventory(
        ANSIBLE_INVENTORY_HOST_w_PORT, ANSIBLE_INVENTORY_INT_PARAMS, host_type="winrm")
    assert winrm_sshkey == ''
    assert winrm_inv.get('all').get('hosts').get('123.123.123.123:45678').get('ansible_user') == 'joe'
    assert winrm_inv.get('all').get('hosts').get('123.123.123.123:45678').get('ansible_winrm_transport') == 'ntlm'
    assert winrm_inv.get('all').get('hosts').get('123.123.123.123:45678').get('ansible_connection') == 'winrm'


class Object(object):
    pass


def test_generic_ansible():
    """
    Scenario: Given valid arguments, mock events from ansible-runner, ensure context/readable output matches expectations

    Given:
    - valid host args for single windows host 123.123.123.123
    - valid username / password
    - command win-audit-policy-system
    - args subcategory="File System" audit_type="failure"

    When:
    - mock events from ansible-runner show that a change to policy was made successfully

    Then:
    - Valid context/readable output
    """

    # Inputs
    args = {'host': "123.123.123.123", 'subcategory': 'File System', 'audit_type': 'failure'}
    int_params = {'port': 5985, 'creds': {'identifier': 'bill', 'password': 'xyz321', 'credentials': {}}}
    host_type = "winrm"

    # Mock results from Ansible run
    mock_ansible_results = Object()
    mock_ansible_results.events = [{'uuid': 'cf26f7c4-6eca-48b2-8294-4bd263cfb2e0', 'counter': 1, 'stdout': '',
                                    'start_line': 0, 'end_line': 0,
                                    'runner_ident': 'd5a00f7c-7fb6-424a-a8f9-83556bdb2360',
                                    'event': 'playbook_on_start', 'pid': 674619,
                                    'created': '2021-06-01T15:57:37.638813',
                                    'event_data': {}},
                                   {'uuid': 'cc29d328-9d35-4193-ba18-e82e98eaf0c6', 'counter': 2, 'stdout': '',
                                    'start_line': 0, 'end_line': 0,
                                    'runner_ident': 'd5a00f7c-7fb6-424a-a8f9-83556bdb2360',
                                    'event': 'runner_on_start', 'pid': 674619, 'created': '2021-06-01T15:57:37.668136',
                                    'parent_uuid': 'a736a224-f5d0-0add-444b-000000000009', 'event_data': {}},
                                   {'uuid': '4770effd-5088-430c-aee2-621bee4f3f00', 'counter': 3,
                                    'stdout': '123.123.123.123 | SUCCESS => {\r\n    "changed": false,\r\n\
                                            "current_audit_policy": {\r\n        "file system": "failure"\r\n    }\r\n}',
                                    'start_line': 0, 'end_line': 6,
                                    'runner_ident': 'd5a00f7c-7fb6-424a-a8f9-83556bdb2360', 'event': 'runner_on_ok',
                                    'pid': 674619, 'created': '2021-06-01T15:57:40.592040',
                                    'parent_uuid': 'a736a224-f5d0-0add-444b-000000000009', 'event_data': {}}]

    # Expected results
    expected_readable = """# 123.123.123.123 -  SUCCESS \n  * changed: False
  * ## Current_Audit_Policy
    * file system: failure
"""
    expected_outputs = [{'changed': False, 'current_audit_policy': {
        'file system': 'failure'}, 'host': '123.123.123.123', 'status': 'SUCCESS'}]

    with patch('ansible_runner.run', return_value=mock_ansible_results):
        CommandResults = generic_ansible('microsoftwindows', 'win_audit_policy_system', args, int_params, host_type)

        assert CommandResults.readable_output == expected_readable
        assert CommandResults.outputs == expected_outputs


def test_generic_ansible_with_problematic_stdout():
    """
    Scenario: Given valid arguments, mock events from ansible-runner, ensure context/readable output matches expectations

    Given:
    - valid host args for single windows host 123.123.123.123
    - valid username / password
    - command win-audit-policy-system
    - args subcategory="File System" audit_type="failure"

    When:
    - mock events from ansible-runner show that a change to policy was made successfully

    Then:
    - Valid context/readable output
    """

    # Inputs
    args = {'host': "123.123.123.123", 'subcategory': 'File System', 'audit_type': 'failure'}
    int_params = {'port': 5985, 'creds': {'identifier': 'bill', 'password': 'xyz321', 'credentials': {}}}
    host_type = "winrm"

    # Mock results from Ansible run
    mock_ansible_results = Object()

    with open(os.path.join(os.path.join("TestsInput", "stdout.txt")), encoding='unicode_escape') as f:
        stdout = f.read()

    mock_ansible_results.events = [{'uuid': 'cf26f7c4-6eca-48b2-8294-4bd263cfb2e0', 'counter': 1, 'stdout': '',
                                    'start_line': 0, 'end_line': 0,
                                    'runner_ident': 'd5a00f7c-7fb6-424a-a8f9-83556bdb2360',
                                    'event': 'playbook_on_start', 'pid': 674619,
                                    'created': '2021-06-01T15:57:37.638813',
                                    'event_data': {}},
                                   {'uuid': 'cc29d328-9d35-4193-ba18-e82e98eaf0c6', 'counter': 2, 'stdout': '',
                                    'start_line': 0, 'end_line': 0,
                                    'runner_ident': 'd5a00f7c-7fb6-424a-a8f9-83556bdb2360',
                                    'event': 'runner_on_start', 'pid': 674619,
                                    'created': '2021-06-01T15:57:37.668136',
                                    'parent_uuid': 'a736a224-f5d0-0add-444b-000000000009', 'event_data': {}},
                                   {'uuid': '4770effd-5088-430c-aee2-621bee4f3f00', 'counter': 3,
                                    'stdout': stdout,
                                    'start_line': 0, 'end_line': 6,
                                    'runner_ident': 'd5a00f7c-7fb6-424a-a8f9-83556bdb2360',
                                    'event': 'runner_on_ok',
                                    'pid': 674619, 'created': '2021-06-01T15:57:40.592040',
                                    'parent_uuid': 'a736a224-f5d0-0add-444b-000000000009', 'event_data': {}}]

    # Expected results
    expected_readable = """# \x1b[0;32m10.2.25.44 -  SUCCESS \n  * changed: False\n  * ## Deprecations
  * ## Warnings\n"""

    expected_outputs = [
        {'changed': False, 'deprecations': [], 'warnings': [], 'host': '\x1b[0;32m10.2.25.44', 'status': 'SUCCESS'}]

    with patch('ansible_runner.run', return_value=mock_ansible_results):
        CommandResults = generic_ansible('microsoftwindows', 'win_audit_policy_system', args, int_params, host_type)

        assert CommandResults.readable_output == expected_readable
        assert CommandResults.outputs == expected_outputs
