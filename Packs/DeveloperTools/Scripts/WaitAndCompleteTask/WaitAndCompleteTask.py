from time import sleep
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback

POSSIBLE_STATES = ['New', 'InProgress', 'Completed', 'Waiting', 'Error', 'Skipped', 'Blocked']

''' STANDALONE FUNCTION '''


def get_incident_tasks_by_state(incident_id: int, task_states: Optional[list] = None) -> list:
    """

    Args:
        incident_id: Incident id to pull its tasks.
        task_states: States to get. None to get all tasks with all tasks.

    Returns:
        Tasks with given states related to given incident.
    """
    args: Dict[str, Any] = {
        'incidentId': incident_id
    }
    # leave states empty to get all tasks
    if task_states:
        args['states'] = ','.join(task_states)
    raw_response = demisto.executeCommand('DemistoGetIncidentTasksByState', args=args)
    if is_error(raw_response):
        raise Exception(f'Failed to execute script: DemistoGetIncidentTasksByState. '
                        f'Error: {get_error(raw_response)}')
    return raw_response[0].get("Contents") if raw_response[0].get("Contents") else []


def complete_task_by_id(task_id, task_parent_id, incident_id, complete_option=None) -> str:
    """

    Args:
        task_id: task's id to complete
        task_parent_id: parent playbook task id to complete
        incident_id: relevant incident
        complete_option: path option to choose

    Returns:
        taskComplete automation result
    """
    args = assign_params(
        id=task_id,
        parentPlaybookID=task_parent_id,
        incidentId=incident_id,
        input=complete_option
    )

    raw_response = demisto.executeCommand('taskComplete', args=args)
    if is_error(raw_response):
        raise Exception(f'Failed to execute script: taskComplete. Error: {get_error(raw_response)}')
    return raw_response[0].get("Contents") if raw_response[0].get("Contents") else ''


''' COMMAND FUNCTION '''


def wait_and_complete_task_command(args: Dict[str, Any]) -> CommandResults:
    """

    Args:
        args: Script arguments

    Returns:
        CompletedTask - Tasks that was completed by script
        FoundTasks - Tasks that was found by script, and already completed, not by this script

    """
    task_states = argToList(args.get('task_states'))
    if not all(state in POSSIBLE_STATES for state in task_states):
        raise Exception(f'task_states are bad. Possible values: {POSSIBLE_STATES}')

    complete_option = args.get('complete_option')
    incident_id = args.get('incident_id')
    if not incident_id:
        incident = demisto.incidents()[0]
        incident_id = incident.get('id')
    task_name = args.get('task_name')
    complete_task = argToBoolean(args.get('complete_task', 'false'))
    max_timeout = arg_to_number(args.get('max_timeout', 60))
    interval_between_tries = arg_to_number(args.get('interval_between_tries', 3))

    completed_tasks = []
    found_tasks = []

    start_time = time.time()

    while True:

        tasks_by_states = get_incident_tasks_by_state(incident_id, task_states)
        requested_task = None

        # find task to complete if was given task name
        if task_name:
            for task in tasks_by_states:
                if task['name'] == task_name:
                    requested_task = task
                    break

        if requested_task and complete_task:
            # complete the requested task
            complete_task_by_id(
                requested_task.get('id'),
                requested_task.get('parentPlaybookID'),
                incident_id,
                complete_option
            )
            completed_tasks.append(requested_task.get('name'))
            break

        elif requested_task:
            # just validate that task was found and not complete it
            found_tasks.append(requested_task.get('name'))
            break

        elif not task_name and tasks_by_states and complete_task:
            # complete all tasks, which state is task_states
            for task in tasks_by_states:
                complete_res = complete_task_by_id(
                    task.get('id'),
                    task.get('parentPlaybookID'),
                    incident_id,
                    complete_option
                )
                if 'Task is completed already' in complete_res:
                    found_tasks.append(task.get('name'))
                else:
                    completed_tasks.append(task.get('name'))

            break

        elif not task_name and tasks_by_states:
            # just validate that task was found and not complete it
            found_tasks.extend(task.get('name') for task in tasks_by_states)
            break

        if time.time() - start_time > max_timeout:  # type: ignore[operator]
            break

        sleep(float(interval_between_tries))  # type: ignore[arg-type]

    if not completed_tasks and not found_tasks:
        if task_name and task_states:
            raise Exception(f'The task "{task_name}" did not reach the {" or ".join(task_states)} state.')
        elif task_name:
            raise Exception(f'The task "{task_name}" was not found by script.')
        elif task_states:
            raise Exception(f'None of the tasks reached the {" or ".join(task_states)} state.')
        else:
            raise Exception('No tasks were found.')

    outputs = {'CompletedTask': completed_tasks,
               'FoundTask': found_tasks}

    human_readable = tableToMarkdown(name='', t=outputs, headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='WaitAndCompleteTask',
        outputs_key_field='',
        outputs=outputs,
        readable_output=human_readable
    )


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    try:
        return_results(wait_and_complete_task_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute WaitAndCompleteTask. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
