from pytest_mock import MockerFixture
import demistomock as demisto
import pytest
import json
from GetFailedTasks import main, get_failed_tasks_output, get_incident_tasks_using_internal_request, get_incident_data, \
    get_custom_scripts_map_id_and_name
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
    assert '|Incident Created Date|Incident ID|Task Name|Task ID|Playbook Name|Command Name|Error Entry ID|' in \
           human_readable
    assert human_readable.count('AutoFocusPolling') == 3

    entry_context = demisto.results.call_args[0][0].get('EntryContext')
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('Number of total errors') == 6
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('total of failed incidents') == 3

    assert entry_context.get('GetFailedTasks', [])[1] == {'Command Name': '',
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
    result = get_incident_data(INCIDENTS_RESULT[0].get('Contents').get('data')[1], 'instance_mock')
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
    result = get_incident_data(INCIDENTS_RESULT[0].get('Contents').get('data')[1], None)
    assert mock_res.call_count == 1
    assert result[0] == []


def test_get_incident_data_internal_http_request_fail(mocker):
    """
        Given:
            - An incident and no Core REST API instance.

        When:
            - Running the get_incident_data function.

        Then:
            - Validates that get_incident_tasks_using_rest_api_instance was called after
              get_incident_tasks_using_internal_request raised an exception.
    """
    internal_request_mock_res = mocker.patch('GetFailedTasks.get_incident_tasks_using_internal_request', side_effect=ValueError)
    mocker.patch('GetFailedTasks.get_rest_api_instance_to_use', return_value='instance_mock')
    mocker.patch('GetFailedTasks.get_tenant_name', return_value='test')
    api_instanc_mock_res = mocker.patch('GetFailedTasks.get_incident_tasks_using_rest_api_instance', return_value=[])

    result = get_incident_data(INCIDENTS_RESULT[0].get('Contents').get('data')[1])
    assert internal_request_mock_res.call_count == 1
    assert api_instanc_mock_res.call_count == 1
    assert result[0] == []


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
