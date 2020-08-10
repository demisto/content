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


def get_extra_data_from_investigations(investigations):
    largest_inputs_and_outputs = []
    for inv in investigations:
        outputs = []
        inputs = []
        inputs_and_outputs = demisto.executeCommand('getInvPlaybookMetaData',
                                                    args={
                                                        "incidentId": inv.get('IncidentID')
                                                    })[0].get('Contents').get('tasks')
        if inputs_and_outputs:
            for task in inputs_and_outputs:
                if 'outputs' in task:
                    for output in task.get('outputs'):
                        outputs.append({
                            'IncidentID': inv.get('IncidentID'),
                            'TaskID': task.get('id'),
                            'TaskName': task.get('name'),
                            'Name': output.get('name'),
                            'Size': output.get('size'),
                            "InputOrOutput": 'Output'
                        })

                else:
                    for arg in task.get('args'):
                        inputs.append({
                            'IncidentID': inv.get('IncidentID'),
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

    widget_table = {
        'data': sorted(largest_inputs_and_outputs, key=itemgetter('Size'), reverse=True),
        'total': len(largest_inputs_and_outputs)
    }

    return widget_table


def main():
    try:
        raw_output = demisto.executeCommand('LargestInvestigationsWidget', args={})
        investigations = raw_output[0].get('Contents').get('data')
        demisto.results(get_extra_data_from_investigations(investigations))
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute LargestInputsAndOuputsInIncidents. Error: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
