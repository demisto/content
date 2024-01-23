import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any


TASK_STATES = {
    'new': '',
    'inprogress': 'inprogress',
    'completed': 'Completed',
    'waiting': 'Waiting',
    'error': 'Error',
    'looperror': 'LoopError',
    'skipped': 'WillNotBeExecuted',
    'blocked': 'Blocked'
}

''' STANDALONE FUNCTION '''


def map_to_array(m: dict) -> list:
    arr = []
    for k in m:
        arr.append(m[k])
    return arr


def get_sub_playbook_tasks(tasks: list) -> list:
    readyTasks = []
    for task in tasks:
        if task.get('type') == 'playbook' and task.get('subPlaybook'):
            readyTasks.extend(get_sub_playbook_tasks(map_to_array(task.get('subPlaybook', {}).get('tasks'))))
        readyTasks.append(task)

    return readyTasks


def get_all_playbook_tasks(tasks: list) -> list:
    if (not tasks) or len(tasks) == 0:
        return []

    return get_sub_playbook_tasks(tasks)


def get_states(states: str) -> dict:
    input_states = states.split(",")
    if 'error' in input_states:
        input_states.append('loopError')

    readyStates = {}
    for state in input_states:
        systemState = TASK_STATES.get(state.strip().lower(), None)
        if systemState is not None:
            readyStates[systemState] = True

    if len(readyStates) == 0:
        for k in TASK_STATES:
            readyStates[TASK_STATES[k]] = True

    return readyStates


def is_task_match(task: dict, name: str | None, tag: str | None, states: dict) -> bool:
    task_task = task.get('task', {})
    name_match = name is None or task_task.get('name', '').lower() == name.lower()
    tag_match = tag is None or tag in task_task.get('tags', [])
    state_match = len(states) == 0 or states.get(task.get('state'), False)

    return name_match and tag_match and state_match


def format_title(name: str | None, tag: str | None, states: str) -> str:
    items: list[str] = []
    if name is not None:
        items.append(f'name "{name}" ')
    if tag:
        items.append(f'tag "{tag}" ')
    if states:
        items.append(f'states "{states}" ')
    return f'Tasks with {"and ".join(items)}'.strip()


''' COMMAND FUNCTION '''


def get_task_by_state_command(args: dict[str, Any]) -> CommandResults:
    name = args.get('name', None)
    tag = args.get('tag', None)
    states = get_states(args.get('states', ''))
    inc_id = args.get('inc_id')
    res = demisto.executeCommand('core-api-get', {'uri': f'/investigation/{inc_id}/workplan'})
    if isError(res[0]):
        raise Exception(res)
        # return_error(res)

    workplan = res[0].get('Contents', {}).get('response', {}).get('invPlaybook')
    if not workplan or not workplan.get('tasks', None) or len(workplan.get('tasks', [])) == 0:
        return CommandResults(outputs_prefix='Tasks', outputs=[],
                              readable_output=f'Workplan for incident {inc_id} has no tasks.')

    tasks = map_to_array(workplan.get('tasks'))
    allTasks = get_all_playbook_tasks(tasks)
    res = []

    for task in allTasks:
        if is_task_match(task, name, tag, states):
            res.append({
                'id': task.get('id'),
                'name': task.get('task', {}).get('name', ''),
                'type': task.get('type'),
                'owner': task.get('assignee'),
                'state': task.get('state'),
                'scriptId': task.get('task', {}).get('scriptId'),
                'startDate': task.get('startDate'),
                'dueDate': task.get('dueDate'),
                'completedDate': task.get('completedDate'),
                'parentPlaybookID': task.get('parentPlaybookID'),
                'completedBy': task.get('completedBy')
            })

    entry = CommandResults(outputs_prefix='Tasks',
                           outputs=res,
                           readable_output=tableToMarkdown(
                               f'{format_title(name, tag,args.get("states", ""))}(Incident  # {inc_id})',
                               res,
                               ['id', 'name', 'state', 'owner', 'scriptId']),
                           entry_type=EntryType.NOTE)

    return entry


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_task_by_state_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute Script Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
