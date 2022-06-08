import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]
field = demisto.args()['field']
name = field['name']

# Get values from list
WSJF_LIST = execute_command("getList", {"listName": "WSJFCalculations"})
wsjf_json = json.loads(WSJF_LIST)


# Find key match and build array
if name in wsjf_json:
    options = list(wsjf_json[name].keys())

results = {'hidden': False, 'options': options}


demisto.results(results)
