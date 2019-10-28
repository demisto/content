import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
merge_with = demisto.args().get("merge_with")
value = demisto.args().get("value")

if not merge_with and not value:
    demisto.results(None)
    sys.exit(0)

if not isinstance(merge_with, list):
    if not merge_with:
        incident_field_name = []
    else:
        merge_with = [merge_with]

if not isinstance(value, list):
    if not value:
        value = []
    else:
        value = [value]

result = merge_with + value
demisto.results(result)
