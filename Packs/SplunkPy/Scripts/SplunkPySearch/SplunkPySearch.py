import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

query = demisto.args()['query']
rows = demisto.args()['rows']

headers = ""
query = query + ' | head ' + rows
res = demisto.executeCommand('splunk-search', {'using-brand': 'splunkpy', 'query': query})
contents = res[0]['Contents']

if isError(res[0]):
    return_error("Error occured. " + str(contents))

if (res and len(res) > 0 and contents):
    if not isinstance(contents[0], dict):
        headers = "results"
    demisto.results({"Type": 1, "Contents": contents, "ContentsFormat": "json", "EntryContext": {},
                     "HumanReadable": tableToMarkdown("Splunk Search results for: " + query, contents, headers)})
else:
    demisto.results('No results.')
