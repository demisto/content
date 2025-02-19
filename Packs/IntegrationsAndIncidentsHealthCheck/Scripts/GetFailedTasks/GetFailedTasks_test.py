from pytest_mock import MockerFixture
import demistomock as demisto
import pytest
import json
from GetFailedTasks import main, get_failed_tasks_output, get_incident_tasks_using_internal_request, get_incident_data, \
    get_custom_scripts_map_id_and_name, get_rest_api_instance, filter_playbooks_failures
from test_data.constants import INCIDENTS_RESULT, RESTAPI_TAS_RESULT, INTERNAL_TASKS_RESULT


def mock_execute_command(command_name, _):
    if command_name == 'getIncidents':
        return INCIDENTS_RESULT
    elif command_name == 'core-api-post':
        return RESTAPI_TAS_RESULT
    return None


@pytest.mark.parametrize('rest_api_instacne', ['rest_api_instacne', None])
def test_get_failed_tasks(mocker, rest_api_instacne):
    mocker.patch.object(demisto, 'args', return_value={'rest_api_instance': rest_api_instacne})
    mocker.patch.object(demisto, 'executeCommand', side_effect=mock_execute_command)
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=INTERNAL_TASKS_RESULT)
    mocker.patch.object(demisto, 'results')
    mocker.patch('GetFailedTasks.get_tenant_name', return_value='test')

    main()

    human_readable = demisto.results.call_args[0][0].get('HumanReadable')
    assert '|Incident Created Date|Incident ID|Task Name|Task ID|Playbook Name|Command Name|Brand Name|Error Entry ID|' in \
           human_readable
    assert human_readable.count('AutoFocusPolling') == 3

    entry_context = demisto.results.call_args[0][0].get('EntryContext')
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('Number of total errors') == 6
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('total of failed incidents') == 3

    assert entry_context.get('GetFailedTasks', [])[1] == {'Command Name': '',
                                                          'Brand Name': None,
                                                          'Error Entry ID': ['8@3', '9@3'],
                                                          'Incident Created Date': '2020-09-29T14:02:45.82647067Z',
                                                          'Incident ID': '3',
                                                          'Incident Owner': 'admin',
                                                          'Number of Errors': 2,
                                                          'Playbook Name': 'AutoFocusPolling',
                                                          'Task ID': '3',
                                                          'Task Name': 'Fail',
                                                          'Command Description': 'command desc'}


@pytest.mark.parametrize('tasks,expected_outputs', [
    ([], ([], 0)),
    (json.loads(INTERNAL_TASKS_RESULT.get('body')), ([{
        'Command Name': '',
        'Brand Name': None,
        'Error Entry ID': ['8@3', '9@3'],
        'Incident Created Date': '2020-09-29T14:02:45.82647067Z',
        'Incident ID': '3',
        'Incident Owner': 'admin',
        'Number of Errors': 2,
        'Playbook Name': 'AutoFocusPolling',
        'Task ID': '3',
        'Task Name': 'Fail',
        'Command Description': 'command desc'
    }], 2))
])
def test_get_failed_tasks_output(tasks, expected_outputs):
    """
        Given:
            - A list of tasks

        When:
            - Running the get_failed_tasks_output function

        Then:
            - Validates that the response is as expected.
    """
    tasks_res, num_tasks = get_failed_tasks_output(tasks, INCIDENTS_RESULT[0].get('Contents').get('data')[1])

    assert tasks_res == expected_outputs[0]
    assert num_tasks == expected_outputs[1]


def test_get_failed_tasks_output_with_tasks(mocker):
    """
    Given: A list of failing tasks and an incident object.
    When: Calling get_failed_tasks_output function.
    Then: It should return the expected task outputs and the correct number of error entries.
    """
    # Mock data
    tasks = [
        {
            "entries": ["error1", "error2"],
            "task": {"scriptId": "brand1|||script1", "name": "Task 1", "description": "Description 1"},
            "ancestors": ["Playbook 1"],
            "id": "task1"
        },
        {
            "entries": ["error3"],
            "task": {"scriptId": "script2", "name": "Task 2"},
            "ancestors": ["Playbook 2"],
            "id": "task2"
        }
    ]
    incident = {"id": "incident1", "created": "2023-01-01", "owner": "admin"}
    custom_scripts_map = {"script1": "Custom Script 1", "script2": "Custom Script 2"}

    # Expected output
    expected_outputs = [
        {
            "Incident ID": "incident1",
            "Playbook Name": "Playbook 1",
            "Task Name": "Task 1",
            "Error Entry ID": ["error1", "error2"],
            "Number of Errors": 2,
            "Task ID": "task1",
            "Incident Created Date": "2023-01-01",
            "Command Name": "Custom Script 1",
            "Brand Name": "brand1",
            "Incident Owner": "admin",
            "Command Description": "Description 1"
        },
        {
            "Incident ID": "incident1",
            "Playbook Name": "Playbook 2",
            "Task Name": "Task 2",
            "Error Entry ID": ["error3"],
            "Number of Errors": 1,
            "Task ID": "task2",
            "Incident Created Date": "2023-01-01",
            "Command Name": "Custom Script 2",
            "Brand Name": None,
            "Incident Owner": "admin"
        }
    ]

    # Call the function
    result, total_errors = get_failed_tasks_output(tasks, incident, custom_scripts_map)

    # Assert the results
    assert result == expected_outputs
    assert total_errors == 3


@pytest.mark.parametrize('response,expected_result', [
    (INTERNAL_TASKS_RESULT, json.loads(INTERNAL_TASKS_RESULT.get('body'))),
    ({}, [])
])
def test_get_incident_tasks_using_internal_request(mocker, response, expected_result):
    """
        Given:
            - A response of an internal request to get failed tasks of an incident.

        When:
            - Running the get_incident_tasks_using_internal_request function

        Then:
            - Validates that the returned tasks is as expected.
    """
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=response)
    mocker.patch.object(demisto, 'error')

    result = get_incident_tasks_using_internal_request(RESTAPI_TAS_RESULT[0]["Contents"]["response"][0])
    assert result == expected_result


def test_get_incident_data_using_rest_api_instance(mocker):
    """
        Given:
            - An incident and an Core REST API instance.

        When:
            - Running the get_incident_data function.

        Then:
            - Validates that get_incident_tasks_using_rest_api_instance was called.
    """
    mock_res = mocker.patch('GetFailedTasks.get_incident_tasks_using_rest_api_instance', return_value=[])
    mocker.patch('GetFailedTasks.get_tenant_name', return_value='test')
    result = get_incident_data(INCIDENTS_RESULT[0].get('Contents').get('data')[1], {}, 'instance_mock')
    assert mock_res.call_count == 1
    assert result[0] == []


def test_get_incident_data_using_internal_http_request(mocker):
    """
        Given:
            - An incident and no Core REST API instance.

        When:
            - Running the get_incident_data function.

        Then:
            - Validates that get_incident_tasks_using_internal_request was called.
    """
    mock_res = mocker.patch('GetFailedTasks.get_incident_tasks_using_internal_request', return_value=[])
    result = get_incident_data(INCIDENTS_RESULT[0].get('Contents').get('data')[1], {}, None)
    assert mock_res.call_count == 1
    assert result[0] == []


def test_get_rest_api_instance_with_provided_instance(mocker):
    """
    Given:
        A REST API instance is provided as an argument.
    When:
        The get_rest_api_instance function is called.
    Then:
        It should return the provided REST API instance and log a debug message.
    """
    mock_debug = mocker.patch('GetFailedTasks.demisto.debug')

    result = get_rest_api_instance('test_instance')

    assert result == 'test_instance'
    mock_debug.assert_called_once_with("Using REST API instance: test_instance, that provided as an argument.")


def test_get_rest_api_instance_without_provided_instance_using_internal_request(mocker):
    """
    Given:
        No REST API instance is provided and the internal HTTP request succeeds.
    When:
        The get_rest_api_instance function is called.
    Then:
        It should return None and log a debug message about using internal HTTP request.
    """
    mocker.patch('GetFailedTasks.get_incident_tasks_using_internal_request')
    mock_debug = mocker.patch('GetFailedTasks.demisto.debug')

    result = get_rest_api_instance(None)

    assert result is None
    mock_debug.assert_called_once_with("Using internal HTTP request to retrieve incident tasks.")


def test_get_rest_api_instance_without_provided_instance_using_rest_api(mocker):
    """
    Given:
        No REST API instance is provided and the internal HTTP request fails.
    When:
        The get_rest_api_instance function is called.
    Then:
        It should return a REST API instance from get_rest_api_instance_to_use and log appropriate debug messages.
    """
    mocker.patch('GetFailedTasks.get_incident_tasks_using_internal_request', side_effect=ValueError)
    mocker.patch('GetFailedTasks.get_rest_api_instance_to_use', return_value='auto_instance')
    mock_debug = mocker.patch('GetFailedTasks.demisto.debug')

    result = get_rest_api_instance(None)

    assert result == 'auto_instance'
    mock_debug.assert_called_with("Using REST API instance: auto_instance to retrieve incident tasks.")


def test_get_custom_scripts_map_id_and_name_with_rest_api(mocker: MockerFixture):
    """
    Given:
        A REST API instance is provided.
    When:
        The get_custom_scripts_map_id_and_name function is called.
    Then:
        It should use the core-api-post command and return the correct script map.
    """
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_execute_command.return_value = [{
        'Contents': {
            'response': {
                'scripts': [
                    {'id': 'script1', 'name': 'Script One'},
                    {'id': 'script2', 'name': 'Script Two'}
                ]
            }
        },
        "Type": 1
    }]

    result = get_custom_scripts_map_id_and_name('rest_api_instance')

    assert result == {'script1': 'Script One', 'script2': 'Script Two'}
    mock_execute_command.assert_called_once_with(
        'core-api-post',
        {
            'uri': 'automation/search',
            'body': {'query': 'system:F'},
            'using': 'rest_api_instance'
        }
    )


def test_get_custom_scripts_map_id_and_name_without_rest_api(mocker):
    """
    Given:
        No REST API instance is provided.
    When:
        The get_custom_scripts_map_id_and_name function is called.
    Then:
        It should use the internalHttpRequest and return the correct script map.
    """
    mock_internal_request = mocker.patch('GetFailedTasks.demisto.internalHttpRequest')
    mock_internal_request.return_value = {
        'statusCode': 200,
        'body': json.dumps({
            'scripts': [
                {'id': 'script3', 'name': 'Script Three'},
                {'id': 'script4', 'name': 'Script Four'}
            ]
        })
    }

    result = get_custom_scripts_map_id_and_name()

    assert result == {'script3': 'Script Three', 'script4': 'Script Four'}
    mock_internal_request.assert_called_once_with(
        method='POST',
        uri='automation/search',
        body={'query': 'system:F'}
    )


def test_filter_playbooks_failures():
    """
    Given:
        - A list of tasks, some of which are of type "playbook" and appear in the ancestors of other tasks.

    When:
        - Running the filter_playbooks_failures function.

    Then:
        - Ensure that tasks of type "playbook" whose names appear in the ancestors of other tasks are removed.
        - Ensure that tasks not matching this condition remain in the output.
    """
    tasks = [
        {"id": "1", "type": "playbook", "task": {"name": "Playbook1"}, "ancestors": []},
        {"id": "2", "type": "regular", "task": {"name": "Task1"}, "ancestors": ["Playbook1"]},
        {"id": "3", "type": "playbook", "task": {"name": "Playbook2"}, "ancestors": ["Playbook1"]}
    ]

    # Expected output: Playbook1 should be removed because it is in the ancestors of Task1.
    expected_filtered_tasks = [
        {"id": "2", "type": "regular", "task": {"name": "Task1"}, "ancestors": ["Playbook1"]},
        {"id": "3", "type": "playbook", "task": {"name": "Playbook2"}, "ancestors": ["Playbook1"]}
    ]

    filtered_tasks = filter_playbooks_failures(tasks)
    assert filtered_tasks == expected_filtered_tasks
