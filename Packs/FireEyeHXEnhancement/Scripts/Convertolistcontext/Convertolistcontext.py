import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

val = demisto.args().get('contextval')
results = [{}]  # type: ignore
for key in val.keys():
    if key != 'Domain':
        results[0][key] = val[key]
comm = CommandResults(outputs_prefix='convertedEndpoint', outputs=results)
return_results(comm)
