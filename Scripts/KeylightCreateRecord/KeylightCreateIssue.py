import demistomock as demisto
from CommonServerPython import *

import json

"""
This script is used to simplify the process of creating or updating a record in Keylight (v2).
You can add fields that you want in the record as script arguments and or in the
code and have the format for the `kl-create-record` and `kl-update-record` commands in a jiffy.

Fill out the args below and add arguments accordingly.
`args` dict contains the record fields you want to create in the component via create/update records

`lookup_fields` - specifies which of the fields are lookup fields and what component are they taken from.

Output - you can find the json to create/update your records in `Keylight.JSON`
"""
##############################################################
args = {
    # 'field_name': 'field_value',
    'Task ID': demisto.args().get('task_id'),            # Example
    'Audit Project': demisto.args().get('project')       # Example
}

lookup_fields = {
    # 'argName': 'componentName',
    'Audit Project': 'Audit Projects'       # Example
}


##############################################################

def get_lookup_id(lookup_value, records):
    for record in records:
        if record.get('DisplayName', '') == lookup_value:
            return record.get('ID', -1)
    raise ValueError(f"Could not find {lookup_value} in the specified component.")


def get_component_id_by_name(component_name):
    for component in components:
        if component.get('Name') == component_name:
            return component.get("ID", -1)
    raise ValueError("Could not find component.")


components = demisto.executeCommand("kl-get-component", {})[0].get('Contents', {})

final_json = []
for field_name in args.keys():
    if field_name in lookup_fields.keys():
        component_id = get_component_id_by_name(lookup_fields.get(field_name))
        records = demisto.executeCommand("kl-get-records", {'component_id': component_id})[0].get('Contents', {})
        lookup_field_id = get_lookup_id(args[field_name], records)
        field = {
            'fieldName': field_name,
            'value': lookup_field_id,
            'isLookup': True
        }
        final_json.append(field)
    else:
        field = {
            'fieldName': field_name,
            'value': args[field_name],
            'isLookup': False
        }
        final_json.append(field)

return_outputs(json.dumps(final_json, indent=4), {'Keylight.JSON': json.dumps(final_json)}, final_json)
