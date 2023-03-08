import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
fields = demisto.args().get('fields').split(",")
fields = [x.strip() for x in fields]
incident_types = demisto.args().get('incident_types').split(",")
incident_types = [x.strip() for x in incident_types]

action = demisto.args().get('action')


# get the current fields and incident types from the system
current_fields = demisto.executeCommand("demisto-api-get", {"uri": "/incidentfields"})[0]["Contents"]['response']
current_types = demisto.executeCommand("demisto-api-get", {"uri": "/incidenttype"})[0]["Contents"]['response']

# build quick lists of the field machinenames, and names of incident types
current_fields_cli_list = [x["cliName"] for x in current_fields]
current_types_list = [x["name"] for x in current_types]

# error checking for Ori, verify the fields provided and the incident types actually exist
for it in incident_types:
    if it not in current_types_list:
        return_error(f"{it} is not a valid Incident Type, check the Incident Type Name from the Advanced menu (Settings)")

for f in fields:
    if f not in current_fields_cli_list:
        return_error(
            f"{f} is not a valid field machinename, check the field from the Advanced menu (Settings) to get the machinename of the field.")

# add or remove the incident types from the fields

results = {
    "Modified": [],
    "Unmodified": []
}

for f in fields:
    field = next(item for item in current_fields if item["cliName"] == f)
    if not field['associatedToAll']:
        if action == "add":
            # add the incident type to the field
            field["associatedTypes"] = list(set(field.get('associatedTypes', []) + incident_types))
            demisto.executeCommand("demisto-api-post", {"uri": "/incidentfield", "body": field})
            results["Modified"].append(f)
        else:
            # prevent removing the field from any system associated incident types
            incident_types = [x for x in incident_types if x not in field.get('systemAssociatedTypes')]
            field["associatedTypes"] = [x for x in field.get('associatedTypes') if x not in incident_types]
            demisto.executeCommand("demisto-api-post", {"uri": "/incidentfield", "body": field})
            print(field)
            results["Modified"].append(f)

    else:
        results["Unmodified"].append(f)

result = CommandResults(readable_output=tableToMarkdown(f"Fields updated, action:{action}", results, removeNull=True))
return_results(result)
