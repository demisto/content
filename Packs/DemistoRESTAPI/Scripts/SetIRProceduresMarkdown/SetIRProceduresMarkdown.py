"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

from CommonServerPython import *

from typing import Dict, Any
import traceback

SECTIONS_TO_KEEY = {'Mitigation', 'Remediation', 'Eradication', 'Threat Hunting'}

''' COMMAND FUNCTION '''


def add_url_to_tasks(tasks, workplan_url):
    tasks = tasks.copy()
    for task in tasks:
        task_id = task.get('id')
        task_url = os.path.join(workplan_url, task_id)
        task['id'] = f"[{task_id}]({task_url})"
    return tasks


def create_markdown_tasks() -> CommandResults:
    urls = demisto.demistoUrls()
    workplan_url = urls.get('workPlan')
    res = demisto.executeCommand('GetTasksWithSections', {})
    if isError(res[0]):
        raise DemistoException('Command GetIncidentsTasksById was not successful')

    all_tasks = []
    tasks_nested_results = demisto.get(res[0], 'Contents')
    headers = ['id', 'name', 'state', 'completedDate']
    md_lst = []
    for k1, v1 in tasks_nested_results.items():
        if k1 not in SECTIONS_TO_KEEY:
            continue
        if 'tasks' in v1.keys():
            tasks = list(v1.values())[0]
            all_tasks.extend(tasks)
            tasks = add_url_to_tasks(tasks, workplan_url)
            md_lst.append(tableToMarkdown(k1, tasks, headers=headers)[1:])
        else:
            md_lst.append(f'## {k1}')
            for k2, v2 in v1.items():
                tasks = list(v2.values())[0]
                all_tasks.extend(tasks)
                tasks = add_url_to_tasks(tasks, workplan_url)
                md_lst.append(tableToMarkdown(k2, tasks, headers=headers))

    completed_tasks = list(filter(lambda x: x.get('state') == 'Completed', all_tasks))
    hunting_completed_tasks = list(filter(lambda x: 'hunting' in x.get('section').lower(), completed_tasks))
    mitigation_completed_tasks = list(filter(lambda x: 'mitigation' in x.get('section').lower(), completed_tasks))
    remediation_completed_tasks = list(filter(lambda x: 'remediation' in x.get('section').lower(), completed_tasks))
    eradication_completed_tasks = list(filter(lambda x: 'eradication' in x.get('section').lower(), completed_tasks))

    number_of_total_tasks = len(all_tasks)
    number_of_completed_tasks = len(completed_tasks)
    number_of_remaining_tasks = number_of_total_tasks - number_of_completed_tasks
    number_of_completed_hunting_tasks = len(hunting_completed_tasks)
    number_of_completed_mitigation_tasks = len(mitigation_completed_tasks)
    number_of_completed_remediation_tasks = len(remediation_completed_tasks)
    number_of_completed_eradication_tasks = len(eradication_completed_tasks)
    table = assign_params(number_of_total_tasks=number_of_total_tasks,
                          number_of_completed_tasks=number_of_completed_tasks,
                          number_of_remaining_tasks=number_of_remaining_tasks,
                          number_of_completed_hunting_tasks=number_of_completed_hunting_tasks,
                          number_of_completed_mitigation_tasks=number_of_completed_mitigation_tasks,
                          number_of_completed_remediation_tasks=number_of_completed_remediation_tasks,
                          number_of_completed_eradication_tasks=number_of_completed_eradication_tasks)

    md_lst.insert(0, tableToMarkdown('Task Overview', table, headerTransform=string_to_table_header)[2:])

    md = '\n'.join(md_lst)
    return CommandResults(readable_output=md)


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
