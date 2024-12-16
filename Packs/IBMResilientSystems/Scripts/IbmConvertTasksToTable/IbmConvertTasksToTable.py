import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def convert_to_table():
    incident = demisto.incident()
    task_entries = []
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident from context but returned None")
    demisto.debug(f'ibm_convert_tasks_to_table {incident=}')
    fields = incident.get('CustomFields', [])

    if fields:
        tasks = fields.get('ibmsecurityqradarsoartasks', [])
        for data in tasks:
            parsed_data = json.loads(data)
            new_task_entry = {
                'Phase': parsed_data.get('Phase', ''),
                'ID': parsed_data.get('ID', ''),
                'Name': parsed_data.get('Name', ''),
                'Status': parsed_data.get('Status', ''),
                'Instructions': parsed_data.get('Instructions', ''),
                'DueDate': parsed_data.get('DueDate', ''),
                'Owner': parsed_data.get('Owner', ''),
                'Required': parsed_data.get('Required', '')
            }
            task_entries.append(new_task_entry)
    if not task_entries:
        return CommandResults(readable_output='No tasks were found for this incident')
    demisto.debug(f"ibm_convert_tasks_to_table {task_entries=}")
    markdown = tableToMarkdown("", task_entries, sort_headers=False)
    return CommandResults(
        readable_output=markdown
    )


def main():
    try:
        return_results(convert_to_table())
    except Exception as e:
        return_error(f'Got an error while parsing: {e}', error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
