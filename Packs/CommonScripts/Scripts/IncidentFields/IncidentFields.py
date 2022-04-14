import demistomock as demisto
from CommonServerPython import *


def build_field_context_data(field):
    field_context_data = {
        'name': field['name'],
        'shortName': field['cliName'],
        'type': field['type'],
        'associatedToAll': field['associatedToAll']
    }

    if not field_context_data['associatedToAll']:
        if len(field.get('associatedTypes') or []) != 0:
            field_context_data['associatedTypes'] = field['associatedTypes']
        else:
            field_context_data['associatedTypes'] = None
    else:
        field_context_data['associatedTypes'] = 'all'

    return field_context_data


def main():
    # get incident fields
    res = demisto.executeCommand('demisto-api-get', {'uri': '/incidentfields'})
    if is_error(res):
        return_error(res[0]['Contents'])

    fields = res[0]['Contents']['response']

    # 'fields' contains non-incident fields (evidence and indicator), as well, so let's make a version
    #  containing only incident fields
    incident_fields = [field for field in fields if field['id'].startswith('incident_')]

    # get arguments
    args = demisto.args()

    exclude_system_fields = False
    if 'exclude_system_fields' in args and argToBoolean(args['exclude_system_fields']):
        exclude_system_fields = True

    use_short_name = False
    if 'short_names' in args and argToBoolean(args['short_names']):
        use_short_name = True

    # build a dict of all field and their associated case types
    output_fields = {}
    for field in incident_fields:

        if exclude_system_fields and field['system']:
            continue

        field_name = field['name']
        if use_short_name:
            field_name = field['cliName']

        output_fields[field_name] = build_field_context_data(field)

    # output results
    demisto.results(output_fields)


if __name__ in ["__builtin__", "builtins"]:
    main()
