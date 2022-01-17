from CommonServerPython import *
import copy
from itertools import chain
import traceback


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
    """
    A function to traverse playbook tasks and gather all the information about the tasks in `results`

    Args:
        tasks:
            Tasks in the structure of the DEMISTO API
        current_task:
            The current task we traverse on
        results:
            The results Dictionary. The tasks will be stored on the path of the task
        prev_task:
            The task we we're previously on
        path:
            This is a list of the section headers in the way to the task
        visited:
            Set if the visited tasks

    Returns:

    """
    if visited is None:
        visited = set()
    if path is None:
        path = []
    if prev_task is None:
        prev_task = {}

    task_id = current_task.get('id')
    task_type = current_task.get('type')
    task_state = current_task.get('state')
    if task_id not in visited:
        visited.add(task_id)
        if task_type == 'start' or task_type == 'title':
            title = demisto.get(current_task, 'task.name')
            if not title:
                title = 'Start'
            new_path = path + [title] if prev_task and prev_task.get('type') == 'title' else [title]
        elif task_type == 'condition' or task_state == 'WillNotBeExecuted':
            new_path = path
        else:
            task = assign_task_output(current_task, path)
            # This is for accessing the correct `path` in results to store the specific task
            dct = results
            for p in path:
                dct.setdefault(p, {})
                dct = dct[p]
            dct.setdefault('tasks', []).append(task)
            new_path = path
        if current_task.get('nextTasks'):
            next_tasks_ids = chain(*demisto.get(current_task, 'nextTasks').values())
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


def add_url_to_tasks(tasks: List[Dict[str, str]], workplan_url: str):
    tasks = copy.deepcopy(tasks)
    for task in tasks:
        task_id = task['id']
        task_url = os.path.join(workplan_url, task_id)
        task['id'] = f"[{task_id}]({task_url})"
    return tasks


def get_tasks(incident_id: str):
    urls = demisto.demistoUrls()  # works in multi tenant env as well
    workplan_url = urls.get('workPlan')
    res = demisto.executeCommand('demisto-api-get', {'uri': f'/investigation/{incident_id}/workplan'})
    if isError(res[0]):
        raise DemistoException(
            'Encountered an error while getting workplan.'
            ' Please make sure your Demisto REST API is configured properly.')
    workplan = demisto.get(res[0], 'Contents.response.invPlaybook')
    tasks = workplan.get('tasks')
    if not workplan or not tasks:
        raise DemistoException(f'Workplan for incident {incident_id}, has no tasks.')
    start_task = find_start_task(tasks)
    tasks_nested_results: Dict = {}
    traverse_tasks(tasks, start_task, tasks_nested_results)
    task_results, md = get_tasks_and_readable(tasks_nested_results, workplan_url)
    return CommandResults(outputs_prefix='Tasks',
                          outputs_key_field='id',
                          entry_type=EntryType.NOTE,
                          raw_response=tasks_nested_results,
                          outputs=task_results,
                          readable_output=md
                          )


def get_tasks_and_readable(tasks_nested_results: Dict[str, Dict], workplan_url: Optional[str] = None):
    task_results: List[Dict] = []
    md_lst = []
    headers = ['id', 'name', 'state', 'completedDate']

    # Go over all nested task, and fill the md table accordingly, and fill the tasks list
    # I assume the nested task is nested only in two levels
    for k1, v1 in tasks_nested_results.items():
        if 'tasks' in v1.keys():
            tasks = v1.get('tasks')
            task_results.extend(tasks)  # type: ignore
            tasks = add_url_to_tasks(tasks, workplan_url) if workplan_url else tasks  # type: ignore
            md_lst.append(tableToMarkdown(k1, tasks, headers=headers)[1:])  # this is for making the title bigger
        else:
            md_lst.append(f'## {k1}')
            for k2, v2 in v1.items():
                tasks = v2.get('tasks')
                task_results.extend(tasks)  # type: ignore
                tasks = add_url_to_tasks(tasks, workplan_url) if workplan_url else tasks  # type: ignore
                md_lst.append(tableToMarkdown(k2, tasks, headers=headers))
    md = '\n'.join(md_lst)
    return task_results, md


def main():
    try:
        incident_id = demisto.args().get('investigation_id')
        if not incident_id:
            incident_id = demisto.incident().get('id')
        return_results(get_tasks(incident_id))
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute  GetTasksWithSections.\nError:\n{str(e)}')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
