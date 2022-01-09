import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback

POSSIBLE_STATES = ['New', 'InProgress', 'Completed', 'Waiting', 'Error', 'Skipped', 'Blocked']

''' STANDALONE FUNCTION '''


def get_incident_tasks_by_state(incident_id, task_states):
    args = {
        'incidentId': incident_id
    }
    # leave states empty to get all tasks
    if task_states:
        args['states'] = task_states
    try:
        return demisto.executeCommand('DemistoGetIncidentTasksByState', args=args)
    except Exception as e:
        demisto.debug(f'Failed to excexute script: DemistoGetIncidentTasksByState. Error: {e}')
        return []


''' COMMAND FUNCTION '''


def wait_and_complete_task_command(args: Dict[str, Any]) -> CommandResults:
    incident = demisto.incidents()[0]
    task_states = argToList(args.get('task_states'))
    # todo: how to check if all states are valid
    if not task_states in POSSIBLE_STATES:
        raise Exception('states are bad')

    complete_option = args.get('complete_option')
    incident_id = args.get('incident_id')
    if not incident_id:
        incident_id = incident.get('id')
    task_name = args.get('task_name')
    complete_task = argToBoolean(args.get('complete_task'))

    tasks_by_states = get_incident_tasks_by_state(incident_id, task_states)

    return CommandResults(
        outputs_prefix='WaitAndCompleteTask',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(wait_and_complete_task_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute WaitAndCompleteTask. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
