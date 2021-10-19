from CommonServerPython import *
import itertools


def find_start_task(tasks: Dict):
    for task in tasks.values():
        if task.get('type') == 'start':
            return task
    return DemistoException('No start task was configured')


def traverse_tasks(tasks: List[Dict], current_task: Dict, results: List[Dict], prev_task: Dict = None, title: str = None, visited: Set = None):
    if visited is None:
        visited = set()
    task_id = current_task.get('id')
    task_type = current_task.get('type')
    if task_id not in visited:
        visited.add(task_id)
        if task_type == 'start' or task_type == 'title':
            new_title = demisto.get(current_task, 'task.name')
            if not new_title:
                new_title = 'Start'
            title = f'{title} - {new_title}' if prev_task and prev_task.get('type') == 'title' else new_title
        else:
            results.append(assign_task_output(current_task, title))

        next_tasks_ids = set().union(*demisto.get(current_task, 'nextTasks').values())
        next_tasks = [tasks.get(task_id) for task_id in next_tasks_ids]
        for next_task in next_tasks:
            traverse_tasks(tasks, next_task, results, current_task, title, visited)


def assign_task_output(task: Dict, section: str):
    task_started_date = task.get('startDate') if task.get(
        'startDate') != '0001-01-01T00:00:00Z' else 'Not Started'
    task_completion_time = task.get('completedDate') if task.get(
        'completedDate') != '0001-01-01T00:00:00Z' else 'Not Started'
    return assign_params(id=task.get('id'),
                         name=demisto.get(task, 'task.name'),
                         section=section,
                         type=task.get('type'),
                         owner=task.get('assignee'),
                         state=task.get('state'),
                         scriptId=demisto.get(task, 'task.scriptId'),
                         startDate=task_started_date,
                         dueDate=task.get('dueDate'),
                         completedDate=task_completion_time,
                         parentPlaybookID=task.get('parentPlaybookID'),
                         completedBy=task.get('completedBy'))


def get_tasks_command():
    incident_id = demisto.incident().get('investigationId')
    res = demisto.executeCommand('demisto-api-get', {'uri': f'/investigation/{incident_id}/workplan'})
    if isError(res[0]):
        raise DemistoException('Command is not valid')
    workplan = demisto.get(res[0], 'Contents.response.invPlaybook')
    tasks = workplan.get('tasks')
    if not workplan or not tasks:
        raise DemistoException(f'Workplan for incident {incident_id}, has no tasks.')
    start_task = find_start_task(tasks)
    results = []
    traverse_tasks(tasks, start_task, results)
    groups = {}
    def group_func(x): return x.get('section')
    for k, g in itertools.groupby(sorted(results, key=group_func), key=group_func):
        groups[k] = list(g)

    md = ''.join([tableToMarkdown(f'Section {k}', g, headers=['id', 'name',
                                                              'state', 'completedDate']) for k, g in groups.items()])
    return CommandResults(outputs_prefix='Tasks',
                          outputs_key_field='id',
                          entry_type=EntryType.NOTE,
                          outputs=results,
                          readable_output=md)


def main():
    try:
        return_results(get_tasks_command())
    except DemistoException as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
