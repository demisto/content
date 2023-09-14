import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Union, List


def pentera_operation_to_incident(full_action_report: list, custom_fields_output: Union[str, bool], context_key: str):
    def _init_missing_keys_in_operation_details(operation_details: dict, missing_keys_to_init: set):
        for missing_key_to_init in missing_keys_to_init:
            operation_details[missing_key_to_init] = None

    incidents_dict = {}

    for far_tuple in full_action_report:
        operation_type = far_tuple.get('Operation Type')
        if not operation_type:
            raise ValueError('No "Operation Type" found')

        if operation_type not in incidents_dict:
            incidents_dict[operation_type] = {
                'name': f'Pentera Insight: {operation_type}',
                'details': f'Pentera Insight details: {operation_type}',
                'penteraoperationtype': operation_type,
                'penteraoperationdetails': [far_tuple.get('Parameters')]
            }
        else:
            incidents_dict[operation_type]['penteraoperationdetails'].append(far_tuple.get('Parameters'))

    for incident in incidents_dict.values():
        # Collect all 'Parameters' distinct keys
        params_list: List[dict] = incident['penteraoperationdetails']
        keys = set()
        for params_dict in params_list:
            for params_key in params_dict:
                keys.add(params_key)

        # Initialize missing keys in details
        for params_dict in params_list:
            missing_keys_to_initialize = keys - set(params_dict.keys())
            _init_missing_keys_in_operation_details(params_dict, missing_keys_to_initialize)

        # Dump the JSON structure in the key if custom_fields_output is enabled
        if custom_fields_output:
            cf_dict = {custom_fields_output: params_list}
            incident['penteraoperationdetails_cf'] = json.dumps(cf_dict)

    list_of_aggregated_incidents = [value for value in incidents_dict.values()]
    context = {context_key: list_of_aggregated_incidents}
    return (
        '### Map Pentera Operation to Incident',
        context,
        list_of_aggregated_incidents
    )


def main():
    try:
        full_action_report = argToList(demisto.args().get('full_action_report'))
        custom_fields_output = demisto.args().get('custom_fields_output', False)
        context_key = demisto.args().get('context_key', 'PenteraIncidents')

        return_outputs(*pentera_operation_to_incident(full_action_report, custom_fields_output, context_key))

    except Exception as e:
        return_error(f'Failed in PenteraOperationToIncident incidents aggregation: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
