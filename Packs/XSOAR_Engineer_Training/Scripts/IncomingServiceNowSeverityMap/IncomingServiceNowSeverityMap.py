import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# use the below script to translate incoming ServiceNow severity values to XSOAR values.

text = demisto.args().get('value')

xsoar_map = {
    "1": "3",
    "2": "2",
    "3": "1"
}

demisto.results(xsoar_map.get(str(text)))
