from CommonServerPython import *

import traceback

SECTIONS_TO_KEEP = ('Threat Hunting', 'Mitigation', 'Remediation', 'Eradication')

HEADER_TRANSFORM = {'id': 'Task ID', 'name': 'Task Name', 'state': 'Task State', 'completedDate': 'Completion Time'}

''' COMMAND FUNCTION '''


def add_url_to_tasks(tasks: Dict, workplan_url: str):
    tasks = tasks.copy()
    for task in tasks:
        task_id = task.get('id')
        task_url = os.path.join(workplan_url, task_id)
        task['id'] = f"[{task_id}]({task_url})"
    return tasks


def set_incident_with_count(all_tasks: List[Dict[str, str]]):
    completed_tasks = list(filter(lambda x: x['state'] == 'Completed', all_tasks))
    hunting_completed_tasks = list(filter(lambda x: 'hunting' in x['section'].lower(), completed_tasks))
    mitigation_completed_tasks = list(filter(lambda x: 'mitigation' in x['section'].lower(), completed_tasks))
    remediation_completed_tasks = list(filter(lambda x: 'remediation' in x['section'].lower(), completed_tasks))
    eradication_completed_tasks = list(filter(lambda x: 'eradication' in x['section'].lower(), completed_tasks))

    number_of_total_tasks = len(all_tasks)
    number_of_completed_tasks = len(completed_tasks)
    number_of_remaining_tasks = number_of_total_tasks - number_of_completed_tasks
    number_of_completed_hunting_tasks = len(hunting_completed_tasks)
    number_of_completed_mitigation_tasks = len(mitigation_completed_tasks)
    number_of_completed_remediation_tasks = len(remediation_completed_tasks)
    number_of_completed_eradication_tasks = len(eradication_completed_tasks)

    incident_id = demisto.incident().get('id')

    incident = {'id': incident_id, 'customFields': {'totaltaskcount': number_of_total_tasks,
                                                    'completedtaskcount': number_of_completed_tasks,
                                                    'remainingtaskcount': number_of_remaining_tasks,
                                                    'eradicationtaskcount': number_of_completed_eradication_tasks,
                                                    'huntingtaskcount': number_of_completed_hunting_tasks,
                                                    'mitigationtaskcount': number_of_completed_mitigation_tasks,
                                                    'remediationtaskcount': number_of_completed_remediation_tasks}}

    res = demisto.executeCommand('setIncident', incident)

    if isError(res[0]):
        raise DemistoException('Command setIncident was not successful')


def create_markdown_tasks() -> CommandResults:
    urls = demisto.demistoUrls()  # works in multi tenant env as well
    workplan_url = urls.get('workPlan')
    res = demisto.executeCommand('GetTasksWithSections', {})
    if isError(res[0]):
        raise DemistoException('Command GetTasksWithSections was not successful')

    tasks_nested_results = demisto.get(res[0], 'Contents')
    all_tasks, md = get_tasks_and_readable(tasks_nested_results, workplan_url)
    set_incident_with_count(all_tasks)
    return CommandResults(readable_output=md)


def get_tasks_and_readable(tasks_nested_results: Dict[str, Dict], workplan_url: Optional[str] = None):
    # This will keep only wanted keys and sort them by their order
    tasks_nested_results = get_sorted_sections(tasks_nested_results)
    all_tasks: List[Dict] = []
    headers = ['id', 'name', 'state', 'completedDate']
    md_lst = []
    for section in SECTIONS_TO_KEEP:
        md_lst.append(f"## {section}")
        v1 = tasks_nested_results.get(section)
        if v1 is None:
            md_lst.append('**No tasks found**')
            continue
        if 'tasks' in v1.keys():
            tasks = v1.get('tasks')
            all_tasks.extend(tasks)  # type: ignore
            tasks = add_url_to_tasks(tasks, workplan_url) if workplan_url else tasks  # type: ignore
            md_lst.append(
                tableToMarkdown('', tasks, headers=headers, headerTransform=lambda x: HEADER_TRANSFORM.get(x)))
        else:
            for k2, v2 in v1.items():
                tasks = v2.get('tasks')
                all_tasks.extend(tasks)  # type: ignore
                tasks = add_url_to_tasks(tasks, workplan_url) if workplan_url else tasks  # type: ignore
                md_lst.append(
                    tableToMarkdown(k2, tasks, headers=headers, headerTransform=lambda x: HEADER_TRANSFORM.get(x)))
    md = '\n'.join(md_lst)
    return all_tasks, md


def get_sorted_sections(tasks_nested_results):
    tasks_nested_results = {key: value for key, value in tasks_nested_results.items() if key in SECTIONS_TO_KEEP}
    tasks_nested_results = {key: value for key, value in sorted(
        tasks_nested_results.items(), key=lambda x: SECTIONS_TO_KEEP.index(x[0]))}
    return tasks_nested_results


''' MAIN FUNCTION '''


def main():
    try:
        return_results(
            create_markdown_tasks()
        )
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute SetIRProceduresMarkdown. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins',):
    main()
