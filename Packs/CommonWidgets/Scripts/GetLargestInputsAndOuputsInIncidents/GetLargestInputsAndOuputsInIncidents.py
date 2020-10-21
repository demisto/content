import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import traceback


def find_largest_input_or_output(all_args_list) -> dict:
    max_arg = {'Size(MB)': 0}
    for arg in all_args_list:
        if arg.get('Size(MB)') > max_arg.get('Size(MB)'):
            max_arg = arg

    return max_arg


def get_largest_inputs_and_outputs(inputs_and_outputs, largest_inputs_and_outputs, incident_id) -> None:
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
                        'Size(MB)': output.get('size'),
                        "InputOrOutput": 'Output'
                    })

            else:
                for arg in task.get('args'):
                    task_url = os.path.join(server_url, '#', 'WorkPlan', incident_id, task_id)
                    inputs.append({
                        'IncidentID': f"[{incident_id}]({incident_url})",
                        'TaskID': f"[{task_id}]({task_url})",
                        'TaskName': task.get('name'),
                        'Name': arg.get('name'),
                        'Size(MB)': arg.get('size'),
                        'InputOrOutput': "Input"
                    })
    if inputs:
        largest_inputs_and_outputs.append(find_largest_input_or_output(inputs))

    if outputs:
        largest_inputs_and_outputs.append(find_largest_input_or_output(outputs))


def get_extra_data_from_investigations(investigations: list) -> list:
    largest_inputs_and_outputs: List = []
    for inv in investigations:
        inputs_and_outputs = demisto.executeCommand('getInvPlaybookMetaData',
                                                    args={
                                                        "incidentId": inv.get('IncidentID')
                                                    })[0].get('Contents').get('tasks')
        get_largest_inputs_and_outputs(inputs_and_outputs, largest_inputs_and_outputs, inv.get('IncidentID'))
    return largest_inputs_and_outputs


def main():
    try:
        raw_output = demisto.executeCommand('GetLargestInvestigations',
                                            args={'from': demisto.args().get('from'), 'to': demisto.args().get('to'),
                                                  'table_result': 'true'}
                                            )
        investigations = raw_output[0].get('Contents', {}).get('data')
        demisto.results(tableToMarkdown('Largest Inputs And Outputs In Incidents',
                                        get_extra_data_from_investigations(investigations)))
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetLargestInputsAndOuputsInIncidents. Error: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
