import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

THRESHOLDS = {
    'numberofincidentsIObiggerthan10mb': 1,
    'numberofincidentsIObiggerthan1mb': 10,
}


def find_largest_input_or_output(all_args_list, is_table_result) -> dict:
    if is_table_result is True:
        max_arg = {'size': 0}
        for arg in all_args_list:
            if arg.get('size') > max_arg.get('size'):
                max_arg = arg
    else:
        max_arg = {'Size(MB)': 0}
        for arg in all_args_list:
            if arg.get('Size(MB)') > max_arg.get('Size(MB)'):
                max_arg = arg

    return max_arg


def get_largest_inputs_and_outputs(inputs_and_outputs, largest_inputs_and_outputs, incident_id, is_table_result) -> None:
    inputs = []
    outputs = []
    urls = demisto.demistoUrls()
    server_url = urls.get('server', '')
    incident_url = os.path.join(server_url, '#', 'incident', incident_id)
    if inputs_and_outputs:
        # In case no inputs and outputs are found a getInvPlaybookMetaData will return a string.
        # in that case we ignore the results and move on.
        if isinstance(inputs_and_outputs, str):
            return

        if is_table_result is True:
            for task in inputs_and_outputs:
                task_id = task.get('id')
                if 'outputs' in task:
                    for output in task.get('outputs'):
                        task_url = os.path.join(server_url, '#', 'WorkPlan', incident_id, task_id)
                        outputs.append({
                            'incidentid': f"{incident_id}",
                            'taskid': f"{task_id}",
                            'taskName': task.get('name'),
                            'name': output.get('name'),
                            'size': float(output.get('size', 0)) / 1024,
                            "inputoroutput": 'Output',
                        })

                else:
                    for arg in task.get('args'):
                        task_url = os.path.join(server_url, '#', 'WorkPlan', incident_id, task_id)
                        inputs.append({
                            'incidentid': f"{incident_id}",
                            'taskid': f"{task_id}",
                            'taskname': task.get('name'),
                            'name': arg.get('name'),
                            'size': float(arg.get('size', 0)) / 1024,
                            'inputoroutput': "Input",
                        })

        if is_table_result is False:
            for task in inputs_and_outputs:
                task_id = task.get('id')
                if 'outputs' in task:
                    for output in task.get('outputs'):
                        task_url = os.path.join(server_url, '#', 'WorkPlan', incident_id, task_id)
                        outputs.append({
                            'IncidentID': f"[{incident_id}]({incident_url})",
                            'TaskID': f"[{task_id}]({task_url})",
                            'TaskName': task.get('name'),
                            'Name': output.get('name'),
                            'Size(MB)': float(output.get('size', 0)) / 1024,
                            "inputoroutput": 'Output',
                        })

                else:
                    for arg in task.get('args'):
                        task_url = os.path.join(server_url, '#', 'WorkPlan', incident_id, task_id)
                        inputs.append({
                            'IncidentID': f"[{incident_id}]({incident_url})",
                            'TaskID': f"[{task_id}]({task_url})",
                            'TaskName': task.get('name'),
                            'Name': arg.get('name'),
                            'Size(MB)': float(arg.get('size', 0)) / 1024,
                            'InputOrOutput': "Input",
                        })

    if inputs:
        largest_inputs_and_outputs.append(find_largest_input_or_output(inputs, is_table_result))

    if outputs:
        largest_inputs_and_outputs.append(find_largest_input_or_output(outputs, is_table_result))


def get_extra_data_from_investigations(investigations: list, is_table_result) -> list:
    largest_inputs_and_outputs: List = []
    for inv in investigations:
        raw_output = execute_command(
            'getInvPlaybookMetaData',
            args={
                "incidentId": inv.get('IncidentID'),
            },
        )

        inputs_and_outputs = raw_output.get('tasks')
        get_largest_inputs_and_outputs(inputs_and_outputs,
                                       largest_inputs_and_outputs,
                                       inv.get('IncidentID'),
                                       is_table_result)
    return largest_inputs_and_outputs


def format_table(incidentsList):
    new_table = []
    if incidentsList:
        for entry in incidentsList:
            new_entry = {'incidentid': entry['incidentid'],
                         'details': f"TaskID: {entry['taskid']}\nTaskName: {entry['taskname']}\nArgument: {entry['name']}",
                         'size': str(round(entry['size'], 2)) + " MB", 'inputoroutput': entry['inputoroutput']}
            new_table.append(new_entry)
        return new_table


def main():
    try:
        args = demisto.args()
        incident_thresholds = args.get('Thresholds', THRESHOLDS)

        daysAgo = datetime.today() - timedelta(days=30)
        is_table_result = argToBoolean(args.get('table_result', True))

        raw_output = execute_command('GetLargestInvestigations',
                                     args={
                                         'from': args.get('from', str(daysAgo.strftime("%Y-%m-%d"))),
                                         'to': args.get('to'),
                                         'table_result': 'true',
                                         'ignore_deprecated': 'true'
                                     })
        investigations = raw_output.get('data')
        data = get_extra_data_from_investigations(investigations, is_table_result)

        if not is_table_result:
            return_results(tableToMarkdown('Largest Inputs And Outputs In Incidents', data))
        else:
            actionableItems = []
            incidentsList = []
            incidentsListBiggerThan10 = []
            for entry in data:
                if entry['size'] > 10:
                    incidentsListBiggerThan10.append(entry)
                else:
                    incidentsList.append(entry)
            numIncidentsList = len(incidentsList)
            numIncidentsListBiggerThan10 = len(incidentsListBiggerThan10)
            analyzeFields = {
                "healthcheckinvestigationswithlargeinputoutput": format_table(incidentsList),
                #"healthcheckinvestigationsinputoutputbiggerthan10mb": format_table(incidentsListBiggerThan10),
                #"healthchecknumberofinvestigationsinputoutputbiggerthan1mb": numIncidentsList,
                #"healthchecknumberofinvestigationsinputoutputbiggerthan10mb": numIncidentsListBiggerThan10,
            }
            demisto.executeCommand('setIncident', analyzeFields)

            # Add actionable items
            DESCRIPTION = [
                "incidents were found with large input and output, improve your task configuration",
                "incidents were found with very large input and output bigger than 10 MB, improve your task configuration"
            ]
            RESOLUTION = [
                "Extending Context and Ignore Outputs: https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context",
            ]

            if numIncidentsList >= incident_thresholds['numberofincidentsIObiggerthan1mb']:
                actionableItems.append({'category': 'DB analysis',
                                        'severity': 'Medium',
                                        'description': '{} {}'.format(numIncidentsList, DESCRIPTION[0]),
                                        'resolution': RESOLUTION[0],
                                        })
            if numIncidentsListBiggerThan10 >= incident_thresholds['numberofincidentsIObiggerthan10mb']:
                actionableItems.append({'category': 'DB analysis',
                                        'severity': 'High',
                                        'description': '{} {}'.format(numIncidentsListBiggerThan10, DESCRIPTION[1]),
                                        'resolution': RESOLUTION[0]
                                        })
            results = CommandResults(
                outputs_prefix="dbstatactionableitems",
                outputs=actionableItems)

            return_results(results)

    except Exception as exc:
        return_error(f'Failed to execute GetLargestInputsAndOutputsInIncidents.\nError: {exc}', error=exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
