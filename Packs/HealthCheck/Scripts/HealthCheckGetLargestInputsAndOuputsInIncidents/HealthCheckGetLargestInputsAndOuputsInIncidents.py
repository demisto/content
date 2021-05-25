import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


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
        raw_output = demisto.executeCommand('getInvPlaybookMetaData',
                                            args={
                                                "incidentId": inv.get('IncidentID'),
                                            })
        if is_error(raw_output):
            raise DemistoException(f'Failed to run getInvPlaybookMetaData:\n{get_error(raw_output)}')

        inputs_and_outputs = raw_output[0].get('Contents', {}).get('tasks')
        get_largest_inputs_and_outputs(inputs_and_outputs, largest_inputs_and_outputs, inv.get('IncidentID'), is_table_result)
    return largest_inputs_and_outputs


def main():
    try:
        args = demisto.args()
        Thresholds = {
            "numberofincidentsIObiggerthan10mb": 1,
            "numberofincidentsIObiggerthan1mb": 10
        }
        thresholds = args.get('Thresholds', Thresholds)

        daysAgo = datetime.today() - timedelta(days=30)
        is_table_result = argToBoolean(args.get('table_result', False))

        raw_output = demisto.executeCommand('GetLargestInvestigations',
                                            args={
                                                'from': args.get('from', str(daysAgo.strftime("%Y-%m-%d"))),
                                                'to': args.get('to'),
                                                'table_result': 'true',
                                            })
        if is_error(raw_output):
            raise DemistoException(f'Failed to run GetLargestInvestigations:\n{get_error(raw_output)}')

        investigations = raw_output[0].get('Contents', {}).get('data')
        data = get_extra_data_from_investigations(investigations, is_table_result)

        if not is_table_result:
            return_results(tableToMarkdown('Largest Inputs And Outputs In Incidents', data))
        else:
            actionableItems = []
            incidentsList = []
            incidentsListBiggerThan10 = []
            for entry in data:
                if entry['size'] > 10:
                    entry['size'] = str(entry['size']) + " MB"
                    # incidentsList.append(entry)
                    incidentsListBiggerThan10.append(entry)
                else:
                    entry['size'] = str(entry['size']) + " MB"
                    incidentsList.append(entry)
            numIncidentsList = len(incidentsList)
            numIncidentsListBiggerThan10 = len(incidentsListBiggerThan10)
            analyzeFields = {
                "investigationsinputoutputbiggerthan1mb": incidentsList,
                "investigationsinputoutputbiggerthan10mb": incidentsListBiggerThan10,
                "numberofinvestigationsinputoutputbiggerthan1mb": numIncidentsList,
                "numberofinvestigationsinputoutputbiggerthan10mb": numIncidentsListBiggerThan10
            }

            demisto.executeCommand('setIncident', analyzeFields)

            # Add actionable items
            DESCRIPTION = [
                "incidents were found with large and input and output, improve your task configuration",
                "incidents were found with large and input and output bigger than 10 MB, improve your task configuration"
            ]
            RESOLUTION = [
                "Extending Context and Ignore Outputs: https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context",
            ]

            if numIncidentsList >= thresholds['numberofincidentsIObiggerthan1mb']:
                actionableItems.append({'category': 'DB analysis',
                                        'severity': 'Medium',
                                        'description': "{} {}".format(numIncidentsList, DESCRIPTION[0]),
                                        'resolution': '{}'.format(RESOLUTION[0])
                                        })
            if numIncidentsListBiggerThan10 >= thresholds['numberofincidentsIObiggerthan10mb']:
                actionableItems.append({'category': 'DB analysis',
                                        'severity': 'High',
                                        'description': "{} {}".format(numIncidentsListBiggerThan10, DESCRIPTION[1]),
                                        'resolution': '{}'.format(RESOLUTION[0])
                                        })
            results = CommandResults(
                readable_output="HealthCheckFileSysLog Done",
                outputs_prefix="dbstatactionableitems",
                outputs=actionableItems)

            return_results(results)

    except Exception as exc:
        return_error(f'Failed to execute GetLargestInputsAndOuputsInIncidents.\nError: {exc}', error=exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
