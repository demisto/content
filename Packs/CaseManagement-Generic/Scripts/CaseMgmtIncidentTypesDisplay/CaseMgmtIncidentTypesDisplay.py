import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# Requirements - Create an XSOAR List called IncidentTypesFromList a list of comma separated Incident Types
# Example: Incident Type 1,Incident Type 2, Incident Type 3

# check if this is a new Incident or not
incident = demisto.incident().get("id")

# if new Incident, the ID will be empty:
if not incident:
    # get the XSOAR IncidentTypesFromList XSOAR List, and split on the comma
    types_list = demisto.executeCommand("getList", {"listName": "IncidentTypesFromList"})[0]["Contents"].split(",")

    # strip whitespace
    types_list = [x.strip() for x in types_list]

    # return the options to display to the user
    return_results({'hidden': False, 'options': types_list})

# if it's an existing Incident, prevent changing the type from the UI.
else:
    # get the current Incident Type, and only return that type.
    incident_type = demisto.incident().get("type")
    return_results({'hidden': False, 'options': [incident_type]})
