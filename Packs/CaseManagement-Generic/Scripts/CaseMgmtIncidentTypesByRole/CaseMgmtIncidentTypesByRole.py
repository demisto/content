import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# check if this is a new Incident or not
incident = demisto.incident().get("id")

# if new Incident, the ID will be empty:
if not incident:

    # get the XSOAR IncidentTypesRBAC XSOAR List
    types_list = demisto.executeCommand("getList", {"listName": "IncidentTypesRBAC"})[0]["Contents"]

    # check if the list exists, if not, display the default options.
    if "Item not found" in types_list:
        # do nothing, return the original values from the field
        pass
    else:
        # make sure the list is valid json, if it's invalid or another error, return the original values from the field
        try:
            role_list = json.loads(types_list)

            # get the users roles
            roles = demisto.executeCommand("getUsers", {"current": "true"})[0].get("Contents")[0].get("allRoles")

            # set default Incident types for all roles
            allowedTypes = role_list["Default"]

            # for each role the user has, add their types if the role exists in the list
            for role in roles:
                if role in role_list:
                    allowedTypes.extend(role_list[role])

            # remove duplicates
            allowedTypes = list(set(allowedTypes))

            demisto.results({'hidden': False, 'options': allowedTypes})
        except ValueError:
            pass
        except Exception:
            pass
else:
    # if it's an existing Incident, prevent changing the type from the UI.
    # get the current Incident Type, and only return that type.
    incident_type = demisto.incident().get("type")
    return_results({'hidden': False, 'options': [incident_type]})
