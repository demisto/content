import demistomock as demisto
from CommonServerPython import *


def get_field_by_long_name(fields, name):
    for field in fields:
        if field['name'] == name:
            return field
    return None


def get_field_by_short_name(fields, name):
    for field in fields:
        if field['cliName'] == name:
            return field
    return None


def get_short_name(value):
    return re.sub(r'[^A-Za-z0-9]', '', value).lower()


def main():
    # get incident fields
    res = demisto.executeCommand('demisto-api-get', {'uri': '/incidentfields'})
    if is_error(res):
        return_error(res[0]['Contents'])

    fields = res[0]['Contents']['response']

    # 'fields' contains non-incident fields, as well, so let's make a version containing only incident fields
    incident_fields = [field for field in fields if field['id'].startswith('incident_')]

    # get arguments
    args = demisto.args()

    custom_only = False
    if 'custom' in args and argToBoolean(args['custom']) is True:
        custom_only = True

    short_names = False
    if 'short_names' in args and argToBoolean(args['short_names']) is True:
        short_names = True

    # build a dict of all field types and their associated case types
    types = {}
    for field in incident_fields:

        if custom_only is True and field['system'] is True:
            continue

        field_name = field['name']
        if short_names is True:
            field_name = field['cliName']

        output_field = {
            'name': field['name'],
            'shortName': field['cliName'],
            'type': field['type'],
            'associatedToAll': field['associatedToAll']
        }

        if output_field['associatedToAll'] is False:
            if len(field['associatedTypes']) != 0:
                output_field['associatedTypes'] = field['associatedTypes']
            else:
                output_field['associatedTypes'] = None
        else:
            output_field['associatedTypes'] = 'all'
        types[field_name] = output_field

    # output results
    demisto.results(types)


if __name__ in ["__builtin__", "builtins"]:
    main()
