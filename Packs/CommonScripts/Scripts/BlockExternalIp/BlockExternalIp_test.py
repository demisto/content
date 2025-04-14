import json

import pytest

from CommonServerPython import *


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_create_final_human_readable_success():
    """
    Given:
       - The integration, the ip_list, and the rule_name
    When:
       - creating the human readable that sums the execution of each integration flow.
    Then:
       - The correct human readable string is returned.
    """
    from BlockExternalIp import create_final_human_readable
    expected_hr = '### The IP was blocked successfully\n|IP|Status|Result|Created rule name|Used integration|\n|---|---|---|---|---|\n| 1.1.1.1 | Done | Success | test_rule | Palo Alto Networks - Prisma SASE |\n'
    result_hr = create_final_human_readable('', 'Palo Alto Networks - Prisma SASE', ['1.1.1.1'], 'test_rule')
    assert result_hr == expected_hr


def test_create_final_human_readable_failure():
    """
    Given:
       - A failure message the integration, the ip_list, and the rule_name
    When:
       - Creating the human readable that sums the execution of each integration flow.
    Then:
       - The correct human readable string is returned.
    """
    from BlockExternalIp import create_final_human_readable
    expected_hr = '### Failed to block the IP\n|IP|Status|Result|Used integration|Message|\n|---|---|---|---|---|\n| 1.1.1.1 | Done | Failed | Cisco ASA | Failed to execute cisco-asa-create-rule command. Error: You are trying to create a rule that already exists. |\n'
    failure_message = 'Failed to execute cisco-asa-create-rule command. Error: You are trying to create a rule that already exists.'
    used_integration = 'Cisco ASA'
    ip_list = ['1.1.1.1']
    result_hr = create_final_human_readable(failure_message, used_integration, ip_list)
    assert result_hr == expected_hr


def test_create_final_context_success():
    """
    Given:
       - The integration, the ip_list, and the rule_name
    When:
       - Creating the context that sums the execution of each integration flow.
    Then:
       - The correct context data list of dict is returned.
    """
    from BlockExternalIp import create_final_context
    used_integration = 'FortiGate'
    ip_list = ['1.1.1.1', '2.2.2.2']
    expected_context = [{'IP': '1.1.1.1', 'results': {'Brand': 'FortiGate', 'Message': '', 'Result': 'OK'}}, {'IP': '2.2.2.2', 'results': {'Brand': 'FortiGate', 'Message': '', 'Result': 'OK'}}]
    result_context = create_final_context('', used_integration, ip_list)
    assert result_context == expected_context


def test_create_final_context_():
    """
    Given:
       - A failure message the integration, the ip_list, and the rule_name
    When:
       - Creating the context that sums the execution of each integration flow.
    Then:
       - The correct context data list of dict is returned.
    """
    from BlockExternalIp import create_final_context
    failure_message = 'Failed to execute cisco-asa-create-rule command. Error: You are trying to create a rule that already exists.'
    used_integration = 'Cisco ASA'
    ip_list = ['1.1.1.1']
    expected_context = [{'IP': '1.1.1.1', 'results': {'Brand': 'Cisco ASA', 'Message': 'Failed to execute cisco-asa-create-rule command. Error: You are trying to create a rule that already exists.', 'result': 'Failed'}}]
    result_context = create_final_context(failure_message, used_integration, ip_list)
    assert result_context == expected_context


def test_prepare_context_and_hr_multiple_executions():
    """
    Given:
       - A list of responses from demosto.executeCommand
    When:
       - Creating the context that sums the execution of each integration flow.
    Then:
       - The correct context data list of dict is returned.
    """
    from BlockExternalIp import prepare_context_and_hr_multiple_executions
    responses = util_load_json('test_data/prisma_sase_responses.json').get('success')
    verbose = True
    ip_list = ['7.7.7.7']
    expected_hr = [
        "The item you're searching for does not exist within the Prisma SASE API.",
        '### Address Object Created\n|Address Value|Folder|Id|Name|Type|\n|---|---|---|---|---|\n| 7.7.7.7 | Shared | 11111111-1111-1111-1111-111111111111 | 7.7.7.7 | ip_netmask |\n',
        "Waiting for all data to push for job id 845",
        '### The IP was blocked successfully\n|IP|Status|Result|Used integration|\n|---|---|---|---|\n| 7.7.7.7 | Done | Success | Palo Alto Networks - Prisma SASE |\n'
    ]
    results = prepare_context_and_hr_multiple_executions(responses, verbose, '', ip_list)
    assert len(results) == 4
    for result, hr in zip(results, expected_hr):
        assert result.readable_output == hr


def test_prepare_context_and_hr():
    """
    Given:
       - A list containing 1 response from demosto.executeCommand
    When:
       - Creating the context that sums the execution of each integration flow.
    Then:
       - The correct context data list of dict is returned.
    """
    from BlockExternalIp import prepare_context_and_hr
    response = util_load_json('test_data/cisco_asa_responses.json').get('cisco_asa_successful_block')
    verbose = True
    ip_list = ['1.1.2.2']
    expected_hr = ['### Created new rule. ID: 1111111111\n|ID|Source|Dest|Permit|Interface|InterfaceType|IsActive|Position|SourceService|DestService|\n|---|---|---|---|---|---|---|---|---|---|\n| 1111111111 | 0.0.0.0 | 1.1.2.2 | false |  | Global | true | 11 | ip | ip |\n',
                   '### The IP was blocked successfully\n|IP|Status|Result|Used integration|\n|---|---|---|---|\n| 1.1.2.2 | Done | Success | Cisco ASA |\n']
    expected_context = [{'IP': '1.1.2.2', 'results': {'Brand': 'Cisco ASA', 'Message': '', 'Result': 'OK'}}]

    results = prepare_context_and_hr(response, verbose, ip_list)
    for result, hr in zip(results, expected_hr):
        assert result.readable_output == hr
    assert results[1].outputs == expected_context


def test_get_relevant_context():
    """
        Given:
           - The EntryContext of a response and a wanted key.
        When:
           - There is a need for an information that can be found in the context.
        Then:
           - Returns the relevant context from the EntryContext.
        """
    from BlockExternalIp import get_relevant_context
    response = util_load_json('test_data/prisma_sase_responses.json').get('address_group_list')
    entry_context = response[0].get('EntryContext', {})
    result = get_relevant_context(entry_context, 'PrismaSase.Address')
    expected_context = {'address_value': '1.1.2.2', 'folder': 'Shared', 'id': '11111111-1111-1111-1111-111111111111', 'name': '1.1.2.2', 'type': 'ip_netmask'}
    assert result == expected_context

def test_check_value_exist_in_context():
   """
   Given:
      - The value we want to check if exists, the context to search on, and the relevant key in the context.
   When:
      - Running pan-os flow and checking whether a specific tag exists, a specific name, etc.
   Then:
      - Returns True when the value is found, False otherwise.
   """
   from BlockExternalIp import check_value_exist_in_context
   context = util_load_json('test_data/pan_os_responses.json').get('address_group_list_context')
   key = 'Match'
   tag_exist = '3.4.5.6'
   tag_not_exist = '1.1.1.1'
   result_exist = check_value_exist_in_context(tag_exist, context, key)
   result_not_exist = check_value_exist_in_context(tag_not_exist, context, key)
   assert result_exist
   assert not result_not_exist


@pytest.mark.parametrize('address_group, expected_match', [
   ("dynamic_address_group_test_pb3", "3.4.5.6"),  # a Match of type string
   ("test1", ""), # non existing grou
   ("pan-os-test-group", "tag1 or tag2"), # a Match of type dict
   ("test-playbook-do-not-delete", "") # an address_group that doesn't have a Match value
])
def test_get_match_by_name(address_group, expected_match):
   """
   Given:
      - The name of the address group, and the context.
   When:
      - Running pan-os flow to check if the address group has existing match value that we should add to them.
   Then:
      - Returns the current match value ot an empty string it the address group doesn't have one.
   """
   from BlockExternalIp import get_match_by_name
   context = util_load_json('test_data/pan_os_responses.json').get('address_group_list_context')
   result = get_match_by_name(address_group, context)
   assert result == expected_match


def test_update_brands_to_run(mocker):
   """
   Given:
      - The list of brands that should be executed.
   When:
      - Running the script block-external-ip.
   Then:
      - Return The list of brands that were executed in previous runs and a set of the brands that should be executed in the current run.
   """
   from BlockExternalIp import update_brands_to_run
   brands_to_run = ['Panorama', 'FortiGate']
   expected_executed_brands = ['FortiGate']
   expected_updated_brands_to_run = {'Panorama'}
   context = {
       'executed_brands': str(expected_executed_brands)
   }
   mocker.patch.object(demisto, 'context', return_value=context)
   result_executed_brands, result_updated_brands_to_run = update_brands_to_run(brands_to_run)
   assert expected_executed_brands == result_executed_brands
   assert expected_updated_brands_to_run == result_updated_brands_to_run


def test_prisma_sase_candidate_config_push_false():
    """
    Given:
      - auto_commit = false, and an object to save the responses of execute command.
    When:
      - Running the script block-external-ip for the prisma-sase brand, checking if a commit should be executed or not.
    Then:
      - A command result with a warning is returned.
    """
    from BlockExternalIp import prisma_sase_candidate_config_push
    expected_auto_commit_message = ("Not commiting the changes in Palo Alto Networks - Prisma SASE, since auto_commit=False."
                                    " Please do so manually for the changes to take affect.")
    result_auto_commit_message = prisma_sase_candidate_config_push(False, [])
    assert result_auto_commit_message.readable_output == expected_auto_commit_message


def test_prisma_sase_candidate_config_push_true(mocker):
    """
    Given:
      - auto_commit = true, and an object to save the responses of execute command.
    When:
      - Running the script block-external-ip for the prisma-sase brand, checking if a commit should be executed or not.
    Then:
      - Verify the correct outputs are returned from the function.
    """
    from BlockExternalIp import prisma_sase_candidate_config_push
    responses = []
    entries = util_load_json('test_data/prisma_sase_responses.json').get('candidate_config_push')
    mocker_object = mocker.patch.object(demisto, 'executeCommand', return_value=entries)
    result_auto_commit_message = prisma_sase_candidate_config_push(True, responses)
    assert not result_auto_commit_message
    assert len(responses) == 1
    mocker_object.assert_called_with("prisma-sase-candidate-config-push",
                                     {"folders": "Remote Networks, Mobile Users, Service Connections"})


def test_prisma_sase_security_rule_update_needed(mocker):
    """
    Given:
      - rule_name, address_group, a responses list.
    When:
      - Running the script block-external-ip for the prisma-sase brand, checking if a rule update should be performed.
    Then:
      - Verify the correct outputs are returned from the function, the response of the command in case it was executed, otherwise [].
    """
    from BlockExternalIp import prisma_sase_security_rule_update
    rule_name = "rules"
    address_group = "test_debug1"
    res_rule_list = util_load_json('test_data/prisma_sase_responses.json').get('security_rule_list')
    responses = [res_rule_list]
    entries = util_load_json('test_data/prisma_sase_responses.json').get('security_rule_update')
    mocker_object = mocker.patch.object(demisto, 'executeCommand', return_value=entries)
    result = prisma_sase_security_rule_update(rule_name, address_group, responses)
    assert result == entries
    assert len(responses) == 2
    mocker_object.assert_called_with("prisma-sase-security-rule-update",
                                     {'rule_id': '11111111-1111-1111-1111-111111111111',
                                      'action': 'deny',
                                      'destination': address_group})


def test_prisma_sase_security_rule_update_not_needed():
    """
    Given:
      - rule_name, address_group, a responses list.
    When:
      - Running the script block-external-ip for the prisma-sase brand, checking if a rule update should be performed.
        In this case the address_group is in the rule destination, no need for a rule update.
    Then:
      - Verify the correct outputs are returned from the function, the response of the command in case it was executed, otherwise [].
    """
    from BlockExternalIp import prisma_sase_security_rule_update
    rule_name = "rules"
    address_group = "test_debug"
    res_rule_list = util_load_json('test_data/prisma_sase_responses.json').get('security_rule_list')
    responses = [res_rule_list]
    result = prisma_sase_security_rule_update(rule_name, address_group, responses)
    assert not result


def test_prisma_sase_block_ip_object_not_exist(mocker):
    """
    Given:
      - The arguments for running the prisma flow.
    When:
      - Running the script block-external-ip for the prisma-sase brand.
    Then:
      - Verify the correct outputs are returned from the function, the first command result should contain that the ip does not exist.
    """
    from BlockExternalIp import prisma_sase_block_ip
    args = {
        "ip": "1.2.3.7",
        "address_group": "test_debug2",
        "verbose": True,
        "rule_name": "rules",
        "auto_commit": False
    }
    res_address_object_list = util_load_json('test_data/prisma_sase_responses.json').get('address_object_list_1237')
    res_create_object = util_load_json('test_data/prisma_sase_responses.json').get('address_object_create1237')
    res_address_group_list = util_load_json('test_data/prisma_sase_responses.json').get('address_group_list1237')
    res_address_group_update = util_load_json('test_data/prisma_sase_responses.json').get('address_group_update1237')
    mocker.patch.object(demisto, 'executeCommand', side_effect=[res_address_object_list,
                                                                res_create_object,
                                                                res_address_group_list,
                                                                res_address_group_update])
    results = prisma_sase_block_ip(args)
    assert len(results) == 6
    assert results[0].readable_output == "The item you're searching for does not exist within the Prisma SASE API."
    assert results[1].readable_output == '### Address Object Created\n|Address Value|Folder|Id|Name|Type|\n|---|---|---|---|---|\n| 1.2.3.7 | Shared | 11111111-1111-1111-1111-111111111111 | 1.2.3.7 | ip_netmask |\n'
    assert results[2].readable_output == '### Address Groups\n|Id|Name|Description|Addresses|Dynamic Filter|\n|---|---|---|---|---|\n| id | test_debug2 |  | 1.2.3.6 |  |\n'
    assert results[3].readable_output == '### Address Group updated\n|Addresses|Folder|Id|Name|\n|---|---|---|---|\n| 1.2.3.6,<br>1.2.3.7 | Shared | id | test_debug2 |\n'
    assert results[4].readable_output == '### The IP was blocked successfully\n|IP|Status|Result|Created rule name|Used integration|\n|---|---|---|---|---|\n| 1.2.3.7 | Done | Success | rules | Palo Alto Networks - Prisma SASE |\n'
    assert results[5].readable_output == 'Not commiting the changes in Palo Alto Networks - Prisma SASE, since auto_commit=False. Please do so manually for the changes to take affect.'


def test_pan_os_commit_status(mocker):
    """
    Given:
      - The commit job id.
    When:
      - Running the script block-external-ip for the panorama brand, and we need to check the commit status.
    Then:
      - Verify the correct outputs are returned from the function.
    """
    from BlockExternalIp import pan_os_commit_status
    args = {
        'commit_job_id': "2925"
    }
    responses = []
    res_commit_status = util_load_json('test_data/pan_os_responses.json').get('commit_status')
    mocker_object = mocker.patch.object(demisto, 'executeCommand',return_value=res_commit_status)
    result = pan_os_commit_status(args, responses)
    assert result.readable_output == '### Commit Status:\n|JobID|Status|\n|---|---|\n| 2925 | Success |\n'
    assert len(responses) == 1
    mocker_object.assert_called_with("pan-os-commit-status", {"job_id": "2925"})


def test_pan_os_check_trigger_push_to_device(mocker):
    """
    Given:
      - A list with the pan-os responses so far.
    When:
      - Running the script block-external-ip for the panorama brand, to verify if this is a Panorama instance.
    Then:
      - True since it is a panorama instance.
    """
    from BlockExternalIp import pan_os_check_trigger_push_to_device
    responses = []
    res_pan_os = util_load_json('test_data/pan_os_responses.json').get('pan_os_check_panorama')
    mocker_object = mocker.patch.object(demisto, 'executeCommand', return_value=res_pan_os)
    result = pan_os_check_trigger_push_to_device(responses)
    assert result
    mocker_object.assert_called_with("pan-os", {'cmd': '<show><system><info></info></system></show>', 'type': 'op'})


def test_pan_os_check_trigger_push_to_device_not_panorama(mocker):
    """
    Given:
      - A list with the pan-os responses so far.
    When:
      - Running the script block-external-ip for the panorama brand, to verify if this is a Panorama instance.
    Then:
      - False since it is not a panorama instance.
    """
    from BlockExternalIp import pan_os_check_trigger_push_to_device
    responses = []
    res_pan_os = util_load_json('test_data/pan_os_responses.json').get('pan_os_check_not_panorama')
    mocker_object = mocker.patch.object(demisto, 'executeCommand', return_value=res_pan_os)
    result = pan_os_check_trigger_push_to_device(responses)
    assert not result
    mocker_object.assert_called_with("pan-os", {'cmd': '<show><system><info></info></system></show>', 'type': 'op'})


def test_pan_os_push_to_device(mocker):
    """
    Given:
      - A list with the pan-os responses so far.
    When:
      - Running the script block-external-ip for the panorama brand, to trigger the push for the panorama devices.
    Then:
      - The correct output is returned, and the push_job_id has been updated in the context.
    """
    from BlockExternalIp import pan_os_push_to_device
    responses = []
    res_push_to_device = util_load_json('test_data/pan_os_responses.json').get('push_to_device')
    mocker.patch.object(demisto, 'executeCommand', return_value=res_push_to_device)
    mocker_object = mocker.patch.object(demisto, 'setContext', return_value={})
    result = pan_os_push_to_device({}, responses)
    assert result.readable_output == '### Push to Device Group:\n|DeviceGroup|JobID|Status|\n|---|---|---|\n| device-group | 2936 | Pending |\n'
    mocker_object.assert_called_with('push_job_id', '2936')


def test_pan_os_push_status(mocker):
    """
    Given:
      - The command arguments and a lost of the previous responses.
    When:
      - Running the script block-external-ip for the panorama brand, to check what is the status of the push for
        the panorama devices action.
    Then:
      - The correct output is returned.
    """
    from BlockExternalIp import pan_os_push_status
    args = {
        'push_job_id': '2936'
    }
    responses = []
    res_push_to_device_status = util_load_json('test_data/pan_os_responses.json').get('push_status')
    mocker_object = mocker.patch.object(demisto, 'executeCommand', return_value=res_push_to_device_status)
    result = pan_os_push_status(args, responses)
    assert result.readable_output == '### Push to Device Group:\n|JobID|Status|\n|---|---|\n| 2936 | ACT |\n'
    mocker_object.assert_called_with("pan-os-push-status", {'job_id': '2936'})
    assert len(responses) == 1


def test_final_part_pan_os(mocker):
    """
    Given:
      - The command arguments and a lost of the previous responses.
    When:
      - Running the script block-external-ip for the panorama brand, at the end of the flow.
    Then:
      - Verify the context was cleared and the execute command is called with the correct arguments.
    """
    from BlockExternalIp import final_part_pan_os
    tag = 'new_tag3'
    ip_list = ['1.2.3.7']
    args = {
        'tag': tag,
        'ip_list': ip_list,
        'verbose': False,
        'rule_name': 'rule_name'
    }
    responses = []
    res_register_ip_tag = util_load_json('test_data/pan_os_responses.json').get('register_ip_tag')
    mocker_register_ip = mocker.patch.object(demisto, 'executeCommand', return_value=res_register_ip_tag)
    mocker_set_context = mocker.patch.object(demisto, 'setContext', return_value={})
    final_part_pan_os(args, responses)
    assert mocker_set_context.call_count == 3
    mocker_register_ip.assert_called_with('pan-os-register-ip-tag', {'tag': tag, 'IPs': ip_list})


def test_pan_os_commit(mocker):
    """
    Given:
      - The command arguments and a list of the previous responses.
    When:
      - Running the script block-external-ip for the panorama brand, triggering the commit action.
    Then:
      - Verify the context was set with the correct arguments, and the output is correct.
    """
    from BlockExternalIp import pan_os_commit
    args = {
        'ip_list': ['1.2.3.7'],
        'rule_name': 'new_rule3',
        'log_forwarding_name': '',
        'address_group': 'new_add_group3',
        'tag': 'new_tag3',
        'auto_commit': True,
        'verbose': True,
        'brands': ['Panorama']
    }
    responses = []
    res_commit = util_load_json('test_data/pan_os_responses.json').get('pan_os_commit')
    mocker_commit = mocker.patch.object(demisto, 'executeCommand', return_value=res_commit)
    mocker_set_context = mocker.patch.object(demisto, 'setContext', return_value={})
    result = pan_os_commit(args, responses)
    mocker_commit.assert_called_with("pan-os-commit", {'polling': True})
    mocker_set_context.assert_called_with('commit_job_id', '2925')
    assert result.readable_output == '### Commit Status:\n|JobID|Status|\n|---|---|\n| 2925 | Pending |\n'
    assert len(responses) == 1


def test_pan_os_create_update_address_group_create(mocker):
    """
    Given:
      - The address group, relevant context, tag, and a list of the previous responses.
    When:
      - Running the script block-external-ip for the panorama brand, creating a new address group.
    Then:
      - Verify the pan-os-create-address-group was called with the correct arguments.
    """
    from BlockExternalIp import pan_os_create_edit_address_group, get_relevant_context
    address_group = 'new_add_group3'
    res_address_group_list = util_load_json('test_data/pan_os_responses.json').get('address_group_list')
    res_address_group_create = util_load_json('test_data/pan_os_responses.json').get('create_address_group')
    context_address_group_list = get_relevant_context(res_address_group_list[0].get('EntryContext', {}), 'Panorama.AddressGroups')
    tag = 'new_tag3'
    responses = []
    mocker_address_group_create = mocker.patch.object(demisto, 'executeCommand', return_value=res_address_group_create)
    pan_os_create_edit_address_group(address_group, context_address_group_list, tag, responses)
    mocker_address_group_create.assert_called_with("pan-os-create-address-group",
                                                   {'name': address_group, 'type': 'dynamic', 'match': tag})
    assert len(responses) == 1


def test_pan_os_create_update_address_group_edit(mocker):
    """
    Given:
      - The address group, relevant context, tag, and a list of the previous responses.
    When:
      - Running the script block-external-ip for the panorama brand, update an existing address group.
    Then:
      - Verify the pan-os-edit-address-group was called with the correct arguments.
    """
    from BlockExternalIp import pan_os_create_edit_address_group, get_relevant_context
    address_group = 'testing2'
    res_address_group_list = util_load_json('test_data/pan_os_responses.json').get('address_group_list')
    res_address_group_edit = util_load_json('test_data/pan_os_responses.json').get('edit_address_group')
    context_address_group_list = get_relevant_context(res_address_group_list[0].get('EntryContext', {}), 'Panorama.AddressGroups')
    tag = 'some_tag2'
    expected_match = 'xsiam-blocked-external-ip or shalom21 or some_tag or some_tag1 or some_tag2'
    responses = []
    mocker_address_group_edit = mocker.patch.object(demisto, 'executeCommand', return_value=res_address_group_edit)
    pan_os_create_edit_address_group(address_group, context_address_group_list, tag, responses)
    mocker_address_group_edit.assert_called_with("pan-os-edit-address-group",
                                                 {'name': address_group, 'type': 'dynamic', 'match': expected_match})
    assert len(responses) == 1


def test_pan_os_create_edit_rule_create(mocker):
    """
    Given:
      - The rule name, relevant context, address group, log forwarding name, and a list of the previous responses.
    When:
      - Running the script block-external-ip for the panorama brand, create new rule.
    Then:
      - Verify the pan-os-create-rule was called with the correct arguments.
    """
    from BlockExternalIp import pan_os_create_edit_rule, get_relevant_context
    address_group = 'testing2'
    rule_name = 'rule_name1'
    expected_create_rule_args = {'action': 'deny', 'rulename': rule_name, 'pre_post': 'pre-rulebase',
                                 'source': address_group}
    expected_calls = [mocker.call('pan-os-create-rule', expected_create_rule_args),
                      mocker.call('pan-os-move-rule', {'rulename': rule_name, 'where': 'top', 'pre_post': 'pre-rulebase'})]
    res_rules_list = util_load_json('test_data/pan_os_responses.json').get('list_rules')
    res_rule_create = util_load_json('test_data/pan_os_responses.json').get('create_rule')
    res_rule_move = util_load_json('test_data/pan_os_responses.json').get('move_rule')
    context_rule_list = get_relevant_context(res_rules_list[0].get('EntryContext', {}), 'Panorama.SecurityRule')
    responses = []
    mocker_execute_command = mocker.patch.object(demisto, 'executeCommand', side_effect=[res_rule_create, res_rule_move])
    pan_os_create_edit_rule(rule_name, context_rule_list, address_group, '', responses)
    assert len(responses) == 2
    assert mocker_execute_command.call_count == 2
    mocker_execute_command.assert_has_calls(expected_calls)


def test_pan_os_create_edit_rule_edit(mocker):
    """
    Given:
      - The rule name, relevant context, address group, log forwarding name, and a list of the previous responses.
    When:
      - Running the script block-external-ip for the panorama brand, update an existing rule.
    Then:
      - Verify the pan-os-edit-rule was called with the correct arguments.
    """
    from BlockExternalIp import pan_os_create_edit_rule, get_relevant_context
    address_group = 'testing2'
    rule_name = 'new_rule'
    expected_edit_rule_args = {'rulename': rule_name, 'element_to_change': 'source', 'element_value': address_group, 'pre_post': 'pre-rulebase'}
    expected_calls = [mocker.call('pan-os-edit-rule', expected_edit_rule_args),
                      mocker.call('pan-os-move-rule', {'rulename': rule_name, 'where': 'top', 'pre_post': 'pre-rulebase'})]
    res_rules_list = util_load_json('test_data/pan_os_responses.json').get('list_rules')
    res_rule_edit = util_load_json('test_data/pan_os_responses.json').get('edit_rule')
    res_rule_move = util_load_json('test_data/pan_os_responses.json').get('move_rule')
    context_rule_list = get_relevant_context(res_rules_list[0].get('EntryContext', {}), 'Panorama.SecurityRule')
    responses = []
    mocker_execute_command = mocker.patch.object(demisto, 'executeCommand', side_effect=[res_rule_edit, res_rule_move])
    pan_os_create_edit_rule(rule_name, context_rule_list, address_group, '', responses)
    assert len(responses) == 2
    assert mocker_execute_command.call_count == 2
    mocker_execute_command.assert_has_calls(expected_calls)
