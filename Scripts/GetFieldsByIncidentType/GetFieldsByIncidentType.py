import demistomock as demisto
from CommonServerPython import *
from pprint import pformat


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

    incident_type = args['incident_type']

    exclude_system = False
    if 'exclude_system' in args and argToBoolean(args['exclude_system']):
        exclude_system = True

    name_key = 'name'
    if 'short_names' in args and argToBoolean(args['short_names']):
        name_key = 'cliName'

    explicit_only = False
    if 'explicit_only' in args and argToBoolean(args['explicit_only']):
        explicit_only = True

    # generate results

    matched_fields = []
    for field in incident_fields:  # using multiple if statements for readability
        if exclude_system and not field['system']:
            # skip non-system fields if exclude_system is true
            continue
        elif field['associatedToAll'] and not explicit_only:
            # if explicit_only is false, include fields associated to all incident types
            matched_fields.append(field[name_key])
        elif field['associatedTypes'] is not None and incident_type in field['associatedTypes']:
            # include fields where incident type is in associatedTypes
            matched_fields.append(field[name_key])

    # output results
    if 'pprint' in args and argToBoolean(args['pprint']):
        demisto.results(pformat(matched_fields))
    else:
        demisto.results(matched_fields)


if __name__ in ["__builtin__", "builtins"]:
    main()
