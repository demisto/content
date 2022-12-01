import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# get the users roles
roles = demisto.executeCommand("getUsers", {"current": "true"})[0].get("Contents")[0].get("allRoles")

# get the XSOAR list
role_list = json.loads(demisto.executeCommand("getList", {"listName": "IncidentTypeRBAC"})[0]["Contents"])

# set default Incident types for all roles
allowedTypes = role_list["Default"]

# for each role the user has, add their types
for role in roles:
    allowedTypes.extend(role_list[role])

# make the list unique
allowedTypes = list(set(allowedTypes))

# magic
demisto.results({'hidden': False, 'options': allowedTypes})
