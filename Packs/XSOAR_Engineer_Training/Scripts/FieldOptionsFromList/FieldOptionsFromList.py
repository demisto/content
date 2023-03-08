import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# This is a field display script, that will present options pulled from an XSOAR list.

# get the list
field_values = demisto.executeCommand("getList", {"listName": "Training Custom Field Values"})[0]['Contents']

# default tools list if there is no list from above.
default_options = "Option 1,Option 2,Option 3"

# check if the list exists, if not create it:
if "Item not found" in field_values:
    demisto.executeCommand("createList", {"listName": "Training Custom Field Values", "listData": default_options})
    field_values = json.loads(demisto.executeCommand("getList", {"listName": "Training Custom Field Values"})[0]["Contents"])

options = field_values.split(",")
demisto.results({'hidden': False, 'options': options})
