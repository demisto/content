import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Post processing script for that returns an error if the Owner isn't assigned.
# This is an example script, should work...

# get incident details
inc = demisto.incidents()[0]
owner = inc.get('owner')

if not owner:
    return_error("An Owner must be assigned before closing this Incident")
