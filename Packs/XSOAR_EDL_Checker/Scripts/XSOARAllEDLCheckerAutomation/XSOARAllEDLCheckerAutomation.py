import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# run the xsoaredlchecker-get-edl command
results = demisto.executeCommand('xsoaredlchecker-get-edl', {})

# grab the raw contents from each instance
output = [x['Contents'] for x in results]

# build and return the result consolidated result
readable = tableToMarkdown("XSOAR EDL Checker Response", output, headers=['Name', 'Status', 'Response', 'ItemsOnList'])
result = CommandResults(readable_output=readable, outputs_prefix='EDLChecker', outputs=output, ignore_auto_extract=True)
return_results(result)
