from CommonServerPython import *
import copy

def find_start_task(tasks: Dict):
    for task in tasks.values():
        if task.get('type') == 'start':
            return task
    return DemistoException('No start task was configured')


def traverse_tasks(tasks: Dict[str, Dict],
                   current_task: Dict,
                   results: Dict,
                   prev_task: Dict = None,
                   path: List[str] = None,
                   visited: Set = None) -> None:

    if visited is None:
        visited = set()
    if path is None:
        path = []
    if prev_task is None:
        prev_task = {}

    task_id = current_task.get('id')
    task_type = current_task.get('type')
    if task_id not in visited:
        visited.add(task_id)
        if task_type == 'start' or task_type == 'title':
            title = demisto.get(current_task, 'task.name')
            if not title:
                title = 'Start'
            new_path = path + [title] if prev_task and prev_task.get('type') == 'title' else [title]
        else:
            task = assign_task_output(current_task, path)
            dct = results
            for p in path:
                dct.setdefault(p, {})
                dct = dct[p]
            dct.setdefault('tasks', []).append(task)
            new_path = path

        next_tasks_ids: Set = set().union(*demisto.get(current_task, 'nextTasks').values())
        next_tasks: List[Dict] = [tasks.get(task_id) for task_id in next_tasks_ids]  # type: ignore
        for next_task in next_tasks:
            traverse_tasks(tasks, next_task, results, current_task, new_path, visited)


def assign_task_output(task: Dict, path: List[str]):
    task_started_date = task.get('startDate') if task.get(
        'startDate') != '0001-01-01T00:00:00Z' else 'Not Started'
    task_completion_time = task.get('completedDate') if task.get(
        'completedDate') != '0001-01-01T00:00:00Z' else 'Not Started'
    due_date = task.get('dueDate') if task.get(
        'dueDate') != '0001-01-01T00:00:00Z' else 'Not Started'

    task_state = task.get('state') if task.get('state') else 'Not Started'
    return assign_params(id=task.get('id'),
                         name=demisto.get(task, 'task.name'),
                         section='/'.join(path),
                         type=task.get('type'),
                         owner=task.get('assignee'),
                         state=task_state,
                         scriptId=demisto.get(task, 'task.scriptId'),
                         startDate=task_started_date,
                         dueDate=due_date,
                         completedDate=task_completion_time,
                         parentPlaybookID=task.get('parentPlaybookID'),
                         completedBy=task.get('completedBy'))


def add_url_to_tasks(tasks, workplan_url):
    tasks = copy.deepcopy(tasks)
    for task in tasks:
        task_id = task.get('id')
        task_url = os.path.join(workplan_url, task_id)
        task['id'] = f"[{task_id}]({task_url})"
    return tasks


def get_tasks_command(incident_id):
    urls = demisto.demistoUrls()
    workplan_url = urls.get('workPlan')

    res = demisto.executeCommand('demisto-api-get', {'uri': f'/investigation/{incident_id}/workplan'})
    if isError(res[0]):
        raise DemistoException('Command is not valid')
    workplan = demisto.get(res[0], 'Contents.response.invPlaybook')
    tasks = workplan.get('tasks')
    if not workplan or not tasks:
        raise DemistoException(f'Workplan for incident {incident_id}, has no tasks.')
    start_task = find_start_task(tasks)
    tasks_nested_results: Dict = {}
    traverse_tasks(tasks, start_task, tasks_nested_results)
    task_results = []
    md_lst = []
    headers = ['id', 'name', 'state', 'completedDate']
    for k1, v1 in tasks_nested_results.items():
        if 'tasks' in v1.keys():
            tasks = list(v1.values())[0]
            task_results.extend(tasks)
            tasks = add_url_to_tasks(tasks, workplan_url)
            md_lst.append(tableToMarkdown(k1, tasks, headers=headers)[1:])
        else:
            md_lst.append(f'## {k1}')
            for k2, v2 in v1.items():
                tasks = list(v2.values())[0]
                task_results.extend(tasks)
                tasks = add_url_to_tasks(tasks, workplan_url)
                md_lst.append(tableToMarkdown(k2, tasks, headers=headers))

    md = '\n'.join(md_lst)
    return CommandResults(outputs_prefix='Tasks',
                          outputs_key_field='id',
                          entry_type=EntryType.NOTE,
                          raw_response=tasks_nested_results,
                          outputs=task_results,
                          readable_output=md
                          )


def main():
    try:
        incident_id = demisto.args().get('incident_id')
        if not incident_id:
            incident_id = demisto.incident().get('investigationId')
        return_results(get_tasks_command(incident_id))
    except DemistoException as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
