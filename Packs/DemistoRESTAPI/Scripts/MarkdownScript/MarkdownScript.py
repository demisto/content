"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback

''' STANDALONE FUNCTION '''


# TODO: REMOVE the following dummy function:
def basescript_dummy(dummy: str) -> Dict[str, str]:
    """Returns a simple python dict with the information provided
    in the input (dummy).

    :type dummy: ``str``
    :param dummy: string to add in the dummy dict that is returned

    :return: dict as {"dummy": dummy}
    :rtype: ``str``
    """

    return {"dummy": dummy}


# TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


''' COMMAND FUNCTION '''


# TODO: REMOVE the following dummy command function
def create_markdown_tasks(args: Dict[str, Any]) -> CommandResults:
    incident_id = args.get('incident_id')
    if not incident_id:
        raise ValueError('Incident ID is required')
    hunting_task_ids = argToList(args.get('hunting_task_ids'))
    mitigation_task_ids = argToList(args.get('mitigation_task_ids'))
    remediation_task_ids = argToList(args.get('remediation_task_ids'))
    eradication_task_ids = argToList(args.get('eradication_task_ids'))

    all_tasks = list(
        set(hunting_task_ids) | set(mitigation_task_ids) | set(remediation_task_ids) | set(eradication_task_ids))
    res = demisto.executeCommand('GetIncidentsTasksById',
                                 {'incident_id': incident_id, 'task_ids': ','.join(all_tasks)})
    if isError(res[0]):
        raise DemistoException('Command GetIncidentsTasksById was not successful')

    tasks = demisto.get(res[0], 'Contents')
    hunting_table = []
    mitigation_table = []
    remediation_table = []
    eradication_table = []

    for task in tasks:
        task_id = task.get('id')
        task_name = task.get('name')
        task_state = task.get('state')
        task_completion_time = task.get('completedDate') if task.get(
            'completedDate') != '0001-01-01T00:00:00Z' else 'Not Started'
        row = {'Task Name': task_name, 'Task State': task_state, 'Completion Time': task_completion_time}
        if task_id in hunting_task_ids:
            hunting_table.append(row)
        if task_id in mitigation_task_ids:
            mitigation_table.append(row)
        if task_id in remediation_task_ids:
            remediation_table.append(row)
        if task_id in eradication_task_ids:
            eradication_table.append(row)
    headers = ['Task Name', 'Task State', 'Completion Time']
    hunting_table_md = tableToMarkdown('Hunting Tasks', hunting_table, headers=headers)
    mitigation_table_md = tableToMarkdown('Remediation Tasks', mitigation_table, headers=headers)
    remediation_table_md = tableToMarkdown('Mitigation Tasks', remediation_table, headers=headers)
    eradication_table_md = tableToMarkdown('Eradication Tasks', eradication_table, headers=headers)

    full_table = hunting_table_md + mitigation_table_md + remediation_table_md + eradication_table_md

    return CommandResults(
        readable_output=full_table
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(create_markdown_tasks(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute MarkdownScript. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
