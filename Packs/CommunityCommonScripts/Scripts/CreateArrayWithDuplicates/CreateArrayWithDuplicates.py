import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
data = demisto.args().get('arrayData')

separator = demisto.args().get('separator')
contextKey = demisto.args().get('contextKey')
newArray = []
results = {}

for item in data.split(separator):
    newArray.append(item.strip())

results['array'] = newArray

results = CommandResults(
    outputs_prefix=contextKey,
    outputs_key_field=contextKey,
    outputs=results
)

return_results(results)
