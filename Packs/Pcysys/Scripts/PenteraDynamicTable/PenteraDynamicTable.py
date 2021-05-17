import demistomock as demisto
from CommonServerPython import *


def pentera_dynamic_table(incident: dict = None):
    if not incident:
        raise ValueError('No incident')

    custom_fields = incident.get('CustomFields')
    if not custom_fields:
        raise ValueError('No custom fields')

    operation_type = custom_fields.get('penteraoperationtype')
    if not operation_type:
        raise ValueError('No Pentera Operation Type')

    details_grid = custom_fields.get('penteraoperationdetails')
    if not details_grid:
        raise ValueError('No details grid')

    details_table = tableToMarkdown(operation_type, details_grid)
    return details_table


def main():
    try:
        incident = demisto.incidents()[0]
        details_table = pentera_dynamic_table(incident)
        return_outputs(readable_output=details_table)

    except Exception as e:
        return_error(f'Error in creating PenteraDynamicTable: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
