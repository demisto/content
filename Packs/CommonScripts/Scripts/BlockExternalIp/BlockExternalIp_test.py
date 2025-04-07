import json

from Packs.Base.Scripts.DBotFindSimilarIncidents.DBotFindSimilarIncidents_test import expected_results


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
