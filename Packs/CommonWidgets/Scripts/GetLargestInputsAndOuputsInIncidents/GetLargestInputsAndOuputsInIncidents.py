import traceback
from operator import itemgetter

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def find_largest_input_or_output(all_args_list):
    max_arg = {'Size': 0}
    for arg in all_args_list:
        if arg.get('Size') > max_arg.get('Size'):
            max_arg = arg

    return max_arg


def get_largest_inputs_and_outputs(inputs_and_outputs, largest_inputs_and_outputs, incident_id):
    inputs = []
    outputs = []
    if inputs_and_outputs:
        for task in inputs_and_outputs:
            if 'outputs' in task:
                for output in task.get('outputs'):
                    outputs.append({
                        'IncidentID': incident_id,
                        'TaskID': task.get('id'),
                        'TaskName': task.get('name'),
                        'Name': output.get('name'),
                        'Size': output.get('size'),
                        "InputOrOutput": 'Output'
                    })

            else:
                for arg in task.get('args'):
                    inputs.append({
                        'IncidentID': incident_id,
                        'TaskID': task.get('id'),
                        'TaskName': task.get('name'),
                        'Name': arg.get('name'),
                        'Size': arg.get('size'),
                        'InputOrOutput': "Input"
                    })
    if inputs:
        largest_inputs_and_outputs.append(find_largest_input_or_output(inputs))

    if outputs:
        largest_inputs_and_outputs.append(find_largest_input_or_output(outputs))


def format_inputs_and_outputs_to_widget_table(largest_inputs_and_outputs):
    widget_table = {
        'data': sorted(largest_inputs_and_outputs, key=itemgetter('Size'), reverse=True),
        'total': len(largest_inputs_and_outputs)
    }

    return widget_table


def get_extra_data_from_investigations(investigations):
    largest_inputs_and_outputs: List = []
    for inv in investigations:
        inputs_and_outputs = demisto.executeCommand('getInvPlaybookMetaData',
                                                    args={
                                                        "incidentId": inv.get('IncidentID')
                                                    })[0].get('Contents').get('tasks')
        get_largest_inputs_and_outputs(inputs_and_outputs, largest_inputs_and_outputs, inv.get('IncidentID'))

    return format_inputs_and_outputs_to_widget_table(largest_inputs_and_outputs)


def main():
    try:
        raw_output = demisto.executeCommand('GetLargestInvestigations', args={'from': demisto.args().get('from'),
                                                                              'to': demisto.args().get('to')})
        investigations = raw_output[0].get('Contents', {}).get('data')
        demisto.results(get_extra_data_from_investigations(investigations))
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetLargestInputsAndOuputsInIncidents. Error: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
