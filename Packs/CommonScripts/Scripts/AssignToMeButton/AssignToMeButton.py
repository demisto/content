import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# get incident id
incident_id = demisto.incidents()[0].get('id')

# get demisto user
user = demisto.executeCommand("getUsers", {"current": True})

username = user[0].get('Contents')[0].get('username')

# set the Incident Owner
demisto.executeCommand("setOwner", {"owner": username})

demisto.results(f"This one is all yours {username}!")
