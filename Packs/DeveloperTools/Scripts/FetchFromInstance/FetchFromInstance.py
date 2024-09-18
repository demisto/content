import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


def get_instance_name(args):
    if args.get("instance_name"):
        return args['instance_name']

    brand_name = args.get("brand_name")
    if brand_name:
        context_modules = demisto.getModules()
        for module_name, module in context_modules.items():
            if module.get("brand") == brand_name and module.get('state') == 'active':
                return module_name.replace(' ', '_')

    raise Exception("No instance name was found")


''' MAIN FUNCTION '''


def main():
    res = []
    incidents_context = []
    context = {}
    args = demisto.args()
    add_to_context = argToBoolean(args.get('add_to_context'))
    expect_data = argToBoolean(args.get('expect_data'))

    instance_name = get_instance_name(args)
    instance_name = instance_name.replace(" ", "_")
    command = f'!{instance_name}-fetch'

    response = demisto.executeCommand(command, {})

    try:
        if not response and expect_data:
            raise Exception(f"Error occurred while fetching incidents from {instance_name}")

        for inc in response:
            contents = inc.get('Contents', '')
            error_msg_in_incident = demisto.args().get('error_msg_in_incident')
            if error_msg_in_incident and error_msg_in_incident in str(contents):
                return_error("Error message '{}' encountered while fetching incidents from {}: {}".format(
                    error_msg_in_incident, instance_name, str(contents)))
            if re.match("invalid character \'[a-zA-Z]\' looking for beginning of value", str(contents), re.IGNORECASE):
                return_error(f"Error occurred while fetching incidents from {instance_name}: {str(contents)}")
            if add_to_context:
                try:
                    for entry in contents:
                        raw_json = ''
                        if isinstance(entry, dict):
                            raw_json = entry.get('rawJSON')  # type: ignore
                        if raw_json:
                            incidents_context.append(json.loads(raw_json))
                except TypeError:
                    return_error('Could not retrieve JSON data from the response contents')

        if not response and not expect_data:
            response = "No data returned"

        context['FetchedIncidents'] = incidents_context
        res.append({"Type": entryTypes["note"], "ContentsFormat": formats["json"], "Contents": response,
                    "EntryContext": context})

    except Exception as ex:
        return_error(ex)

    demisto.results(res)


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
