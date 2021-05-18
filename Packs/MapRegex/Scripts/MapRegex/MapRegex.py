import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Get the arguments
args = demisto.args()

# Get the input value
value = args.get('value')
results = value

# Get and parse the JSON input
try:
    json_regex = json.loads(args.get('json_regex'))
except Exception as err:
    return_error(err)

for k, v in json_regex.items():
    if re.search(v, value):
        results = k
        break

return_results(results)
