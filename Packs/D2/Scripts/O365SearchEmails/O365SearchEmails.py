import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = []
dArgs = demisto.args()
dArgs['using'] = dArgs['system']
REGEX_RESULTS = r"Search results\: \{([^}]*)\}"

delArg = demisto.get(dArgs, 'delete')
if type(delArg) in [str, str] and delArg.lower() == 'true':
    demisto.log('[*] Script set to also delete found emails.')
    resCmdName = demisto.executeCommand("D2O365SearchAndDelete", dArgs)
else:
    resCmdName = demisto.executeCommand("D2O365ComplianceSearch", dArgs)
try:
    for entry in resCmdName:
        if isError(entry):
            res = resCmdName
            break
        else:
            myData = demisto.get(entry, 'Contents')
            match = re.search(REGEX_RESULTS, myData)
            if match and match.groups():
                searchResults = match.groups()[0]
                res.append({"Type": entryTypes["note"], "ContentsFormat": formats["text"], "Contents": searchResults})
except Exception as ex:
    res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                "Contents": "Error occurred while parsing output from command. Exception info:\n" + str(ex) + "\n\nInvalid output:\n" + str(resCmdName)})
demisto.results(res)
