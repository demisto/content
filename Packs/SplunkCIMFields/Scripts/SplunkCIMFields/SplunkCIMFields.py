import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re

args = demisto.args()
inc = args.get('inc')
data = args.get('value')


def splunk_cim_fields(match):
    return data.replace('$' + match + '$', inc.get(match))


matches = re.findall("\$([^\$]*)\$", data)

for match in matches:
    data = splunk_cim_fields(match)

return_results(data)
