import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# check if this is a new Incident or not
incident = demisto.incident().get("id")

# if new Incident, the ID will be empty:
if not incident:

    # get the XSOAR IncidentTypesFromList XSOAR List, and split on the comma
    types_list = demisto.executeCommand("getList", {"listName": "IncidentTypesFromList"})[0]["Contents"]

    # check if the list exists, if not, display the default options.
    if "Item not found" in types_list:
        # do nothing, return the original values from the field
        pass
    else:
        # split the Incident Types based on the comma
        types_list = types_list.split(",")

        # strip whitespace
        types_list = [x.strip() for x in types_list]

        # return the options to display to the user
        return_results({'hidden': False, 'options': types_list})

# if it's an existing Incident, prevent changing the type from the UI.
else:
    # get the current Incident Type, and only return that type.
    incident_type = demisto.incident().get("type")
    return_results({'hidden': False, 'options': [incident_type]})
