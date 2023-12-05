import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

from CommonServerUserPython import *

from typing import Any


''' STANDALONE FUNCTION '''


def mapToArray(map: dict):
    arr: List = []
    for key in map:
        arr.append(map[key])

    return arr


def getSubPlaybookTasks(tasks: List):
    readyTasks: List = []
    if tasks:
        for task in tasks:
            if task.type == 'playbook' and task.subPlaybook:
                readyTasks.append(getSubPlaybookTasks(mapToArray(task.subPlaybook.tasks)))
            readyTasks.append(task)
    return readyTasks


def getAllPlaybookTasks(tasks: List):
    if not tasks or len(tasks) == 0:
        return []

    return getSubPlaybookTasks(tasks)


''' COMMAND FUNCTION '''


# TODO: REMOVE the following dummy command function
def get_task_by_name_command(args: dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')
    task_name = args.get('name', '')
    inc_id = args.get('inc_id', '')
    if not inc_id:
        raise ValueError('inc_id not specified')

    res = execute_command('cortex-api-get', {'uri': f'/investigation/{inc_id}/workplan'})
    if isError(res[0]):
        return res[0]

    workplan = res[0].get('Contents', {}).get('response', {}).get('invPlaybook', {})
    if not workplan or not workplan.tasks or len(workplan.tasks) == 0:
        return 'Workplan for incident ' + inc_id + ', has no tasks.'

    tasks = mapToArray(workplan.tasks)
    allTasks = getAllPlaybookTasks(tasks)
    res: List = []
    for id in allTasks:
        task = allTasks[id]
        if task.task.name == task_name:
            res.append({
                'id': task.id,
                'name': task.task.name,
                'type': task.type,
                'owner': task.assignee,
                'state': task.state,
                'scriptId': task.task.scriptId,
                'startDate': task.startDate,
                'dueDate': task.dueDate,
                'completedDate': task.completedDate,
                'parentPlaybookID': task.parentPlaybookID,
                'completedBy': task.completedBy
            })

    # Call the standalone function and get the raw response
    result = res

    return CommandResults(
        outputs_prefix='GetIncidentTasksByName',
        outputs_key_field='name',
        outputs=result,
        readable_output=tableToMarkdown(f'Tasks with name {task_name} (Incident # {inc_id})', res,
                                        ['id', 'name', 'state', 'owner', 'scriptId']),
        raw_response=result)


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_task_by_name_command(demisto.args()))
    except Exception as ex:

        return_error(f'Failed to execute DemistoGetIncidentTasksByName. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
