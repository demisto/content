from dateparser import parse

import demistomock as demisto
from CommonServerPython import *
MAX_ENTRIES = 30


def get_clickable_incident_id(incident_id):
    incident_id_url = os.path.join("Custom/caseinfoid", incident_id)
    if not is_xsiam_or_xsoar_saas():
        incident_id_url = f'#/{incident_id_url}'
    return f'[{incident_id}]({incident_id_url})'


def get_open_to_do_tasks_of_current_user() -> List[Dict]:
    body = {
        "dataType": "todos",
        "query": "assignee:\"{me}\" and status:\"open\"",
        "widgetType": "table",
        "size": MAX_ENTRIES,
    }
    todo_tasks_query_res = demisto.internalHttpRequest(
        'POST',
        '/v2/statistics/widgets/query',
        json.dumps(body)
    )

    table = []

    if todo_tasks_query_res.get('statusCode') == 200:
        todo_tasks = json.loads(todo_tasks_query_res.get('body', '{}'))
        todo_tasks_data = todo_tasks.get('data') or []
        for task in todo_tasks_data:
            if task.get('status', '') == 'open':  # table includes only open tasks
                title = task.get('title', '')
                description = task.get('description', '')
                task_id = task.get('id', '')
                if sla := task.get('dueDate', ''):
                    sla_dt = parse(sla)
                    assert sla_dt is not None, f'could not parse {sla}'
                    sla = sla_dt.strftime('%Y-%m-%d %H:%M:%S%z')
                opened_by = task.get('dbotCreatedBy', '')
                table.append({
                    'Task Name': title,
                    'Task Description': description,
                    'Task ID': task_id,
                    'SLA': sla,
                    'Opened By': opened_by,
                    'Incident ID': get_clickable_incident_id(incident_id=task.get('incidentId', ''))
                })
    else:
        demisto.error(f'Failed running POST query to /v2/statistics/widgets/query.\n{str(todo_tasks_query_res)}')

    return table


def main():  # pragma: no cover
    try:
        results = get_open_to_do_tasks_of_current_user()
        if len(results) >= MAX_ENTRIES:
            table_name = f'My ToDo Tasks (First {MAX_ENTRIES} Tasks)'
        else:
            table_name = f'My ToDo Tasks ({len(results)})'
        readable_output = tableToMarkdown(table_name, results, headers=list(results[0].keys()) if results else None)
        cmd_results = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': readable_output
        }
        return_results(cmd_results)

    except Exception as e:
        return_error(f'Failed to execute MyToDoTasksWidget Script. Error: {str(e)}', e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
