import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

try:
    indicatorValues = str(demisto.args().get('indicatorValues'))
    reason = demisto.args().get('reason', '')
    indicatorQuery = re.sub(',', ' or ', indicatorValues)
    searchQuery = 'value:(' + indicatorQuery + ')'
    res = demisto.executeCommand("deleteIndicators", {"query": searchQuery, "doNotWhitelist": "false", "reason": reason})
    resp = res[0]
    if isError(resp):
        raise Exception(resp['Contents'])
    else:
        demisto.results(resp['Contents'])

except Exception as ex1:
    return_error(str(ex1))
