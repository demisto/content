import demistomock as demisto
import pytest
import json
from GetFailedTasks import main, get_failed_tasks_output, get_incident_tasks_using_internal_request, get_incident_data
from test_data.constants import INCIDENTS_RESULT, RESTAPI_TAS_RESULT, INTERNAL_TASKS_RESULT


def mock_execute_command(command_name, _):
    if command_name == 'getIncidents':
        return INCIDENTS_RESULT
    elif command_name == 'demisto-api-post':
        return RESTAPI_TAS_RESULT


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
            - An incident and an Demisto Rest Api instance.

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
            - An incident and no Demisto Rest Api instance.

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
            - An incident and no Demisto Rest Api instance.

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
