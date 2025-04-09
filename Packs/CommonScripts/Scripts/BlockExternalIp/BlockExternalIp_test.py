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




def test_checkpoint_object_names_to_members():
   """
   Given:
      - The command context and the ips.
   When:
      - Running the script block-external-ip for the checkpoint brand, getting the names of the current ips objects names.
   Then:
      - The correct object names.
   """
   from BlockExternalIp import checkpoint_object_names_to_members
   context = util_load_json('test_data/checkpoint_responses.json').get('show_object_name_to_members')
   ip_list = ['1.1.1.1', '1.2.2.2']
   expected_names = ['1.1.1.1', '1.2.2.2']
   result = checkpoint_object_names_to_members(context, ip_list)
   assert expected_names == result


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
    result_auto_commit, result_auto_commit_message = prisma_sase_candidate_config_push(False, [])
    assert not result_auto_commit
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
    mocker.patch.object(demisto, 'executeCommand', return_value=entries)
    result_auto_commit, result_auto_commit_message = prisma_sase_candidate_config_push(True, responses)
    assert not result_auto_commit_message
    assert len(responses) == 1
    assert result_auto_commit


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
    mocker.patch.object(demisto, 'executeCommand', return_value=entries)
    result = prisma_sase_security_rule_update(rule_name, address_group, responses)
    assert result == entries
    assert len(responses) == 2
