import demistomock as demisto
from CommonServerPython import *
from pprint import pformat


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

    incident_type = args['incident_type']

    exclude_system = False
    if 'custom' in args and argToBoolean(args['custom']) is True:
        exclude_system = True

    name_key = 'name'
    if 'short_names' in args and argToBoolean(args['short_names']) is True:
        name_key = 'cliName'

    explicit_only = False
    if 'explicit_only' in args and argToBoolean(args['explicit_only']) is True:
        explicit_only = True

    # generate results
    types = []
    if exclude_system is True:
        # only return non-system fields
        for field in incident_fields:  # using multiple if statements for readability
            if field['system'] is False:  # exclude system fields
                if field['associatedToAll'] is True and explicit_only is False:
                    # if explicit_only is false, include fields associated to all incident types
                    types.append(field[name_key])
                elif field['associatedTypes'] is not None and incident_type in field['associatedTypes']:
                    # include fields where incident type is in associatedTypes
                    types.append(field[name_key])

    else:
        # return all fields
        for field in incident_fields:  # using multiple if statements for readability
            if field['associatedToAll'] is True and explicit_only is False:
                # if explicit_only is false, include fields associated to all incident types
                types.append(field[name_key])
            elif field['associatedTypes'] is not None and incident_type in field['associatedTypes']:
                # include fields where incident type is in associatedTypes
                types.append(field[name_key])

    # output results
    if 'pprint' in args and argToBoolean(args['pprint']) is True:
        demisto.results(pformat(types))
    else:
        demisto.results(types)


if __name__ in ["__builtin__", "builtins"]:
    main()
