import demistomock as demisto
import pytest
from GetFailedTasks import main, get_rest_api_instance_to_use
from test_data.constants import INCIDENTS_RESULT, TASKS_RESULT, SERVER_URL


@pytest.mark.parametrize('modules,expected_output,num_of_instances', [({}, None, 0),
                                                                      ({"Demisto REST API_instance_1": {
                                                                          "brand": "Demisto REST API",
                                                                          "category": "Utilities",
                                                                          "defaultIgnored": "false",
                                                                          "state": "active"
                                                                      }, }, "Demisto REST API_instance_1", 1),
                                                                      ({"Demisto REST API_instance_1": {
                                                                          "brand": "Demisto REST API",
                                                                          "category": "Utilities",
                                                                          "defaultIgnored": "false",
                                                                          "state": "active"
                                                                      }, "Demisto REST API_instance_2": {
                                                                          "brand": "Demisto REST API",
                                                                          "category": "Utilities",
                                                                          "defaultIgnored": "false",
                                                                          "state": "active"
                                                                      }, }, "GetFailedTasks: This script can only run "
                                                                            "with a single instance of the "
                                                                            "Demisto REST API. "
                                                                            "Specify the instance name in "
                                                                            "the 'rest_api_"
                                                                            "instance' argument.", 2),
                                                                      ({"Demisto REST API_instance_1": {
                                                                          "brand": "Demisto REST API",
                                                                          "category": "Utilities",
                                                                          "defaultIgnored": "false",
                                                                          "state": "active"
                                                                      }, "Demisto REST API_instance_2": {
                                                                          "brand": "Demisto REST API",
                                                                          "category": "Utilities",
                                                                          "defaultIgnored": "false",
                                                                          "state": "disabled"
                                                                      }, }, "Demisto REST API_instance_1", 1)
                                                                      ])
def test_get_rest_api_instance_to_use(mocker, modules, expected_output, num_of_instances):
    """
    Given:
        all modules that are configured

    When:
        Execute this script

    Then:
        return error if there are more than one demisto rest api instance.
        Otherwise, return name of instance to use.
    """
    mocker.patch.object(demisto, 'getModules', return_value=modules)
    mocker.patch.object(demisto, 'results')
    if num_of_instances <= 1:
        assert get_rest_api_instance_to_use() == expected_output
    else:
        with pytest.raises(SystemExit):
            get_rest_api_instance_to_use()
        contents = demisto.results.call_args[0][0]
        assert contents['Contents'] == expected_output


def mock_execute_command(command_name, args):
    if command_name == 'getIncidents':
        return INCIDENTS_RESULT
    elif command_name == 'demisto-api-post':
        return TASKS_RESULT
    elif command_name == 'GetServerURL':
        return SERVER_URL


def test_get_failed_tasks(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=mock_execute_command)
    mocker.patch.object(demisto, 'results')

    main()

    human_readable = demisto.results.call_args[0][0].get('HumanReadable')
    assert '|Incident Created Date|Incident ID|Task Name|Task ID|Playbook Name|Command Name|Error Entry ID|' in \
           human_readable
    assert human_readable.count('AutoFocusPolling') == 3

    entry_context = demisto.results.call_args[0][0].get('EntryContext')
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('Number of total errors') == 6
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('total of failed incidents') == 3

    assert entry_context.get('GetFailedTasks', [])[2] == {'Command Description': 'RunPollingCommand',
                                                          'Command Name': 'RunPollingCommand',
                                                          'Error Entry ID': ['4@7', '5@7'],
                                                          'Incident Created Date': '2020-09-29 14:02:45.82647067Z',
                                                          'Incident ID': '3',
                                                          'Incident Owner': 'admin',
                                                          'Number of Errors': 2,
                                                          'Playbook Name': 'AutoFocusPolling',
                                                          'Task ID': '3',
                                                          'Task Name': 'RunPollingCommand'}
