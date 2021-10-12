from CommonServerPython import *


def get_sub_playbook_tasks(tasks):
    ready_tasks = []
    for task in tasks.values():
        demisto.info(f'{task=}')
        if task.get('type') == 'playbook' and task.get('subPlaybook'):
            ready_tasks.extend(get_sub_playbook_tasks(task.get('subPlaybook').get('tasks')))
        ready_tasks.append(task)
    return ready_tasks


def filter_tasks(tasks, task_ids, task_states):
    filtered_tasks = []
    for task in tasks:
        task_state = task.get('state') if task.get('state') else 'New'
        task_id = task.get('id')
        if (not task_ids or task_id in task_ids) and (not task_states or task_state in task_states):
            filtered_tasks.append(assign_params(id=task_id,
                                                name=demisto.get(task, 'task.name'),
                                                type=task.get('type'),
                                                owner=task.get('assignee'),
                                                state=task_state,
                                                scriptId=demisto.get(task, 'task.scriptId'),
                                                startDate=task.get('startDate'),
                                                dueDate=task.get('dueDate'),
                                                completedDate=task.get('completedDate'),
                                                parentPlaybookID=task.get('parentPlaybookID'),
                                                completedBy=task.get('completedBy')))

    return filtered_tasks


def get_all_playbook_tasks(tasks):
    if not tasks:
        return []
    return get_sub_playbook_tasks(tasks)


def get_tasks_command(incident_id, task_ids, task_states):
    res = demisto.executeCommand('demisto-api-get', {'uri': f'/investigation/{incident_id}/workplan'})
    if isError(res[0]):
        raise DemistoException('Command is not valid')
    workplan = demisto.get(res[0], 'Contents.response.invPlaybook')
    tasks = workplan.get('tasks')
    if not workplan or not tasks:
        raise DemistoException(f'Workplan for incident {incident_id}, has no tasks.')
    tasks = get_all_playbook_tasks(tasks)
    filtered_tasks = filter_tasks(tasks, task_ids, task_states)
    return CommandResults(outputs_prefix='Tasks',
                          outputs_key_field='id',
                          entry_type=EntryType.NOTE,
                          outputs=filtered_tasks,
                          readable_output=tableToMarkdown(
                              f'Tasks with states: {task_states if task_states else "All states"} (Incident #{incident_id})',
                              filtered_tasks,
                              headers=['id', 'name', 'state', 'owner', 'scriptId'])
                          )


def main():
    try:
        args = demisto.args()
        incident_id = args.get('incident_id')
        task_states = argToList(args.get('states'))
        task_ids = argToList(args.get('task_ids'))
        return_results(get_tasks_command(incident_id, task_ids, task_states))
    except DemistoException as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
