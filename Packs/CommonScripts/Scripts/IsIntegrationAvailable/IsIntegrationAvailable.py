import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

brandName = demisto.get(demisto.args(), 'brandname')
allInstances = demisto.getModules()
brandInstances = [instanceName for instanceName in allInstances if allInstances[instanceName]['brand'].lower(
) == brandName.lower() and demisto.get(allInstances[instanceName], 'state') and allInstances[instanceName]['state'] == 'active']
if brandInstances:
    demisto.setContext('brandInstances', brandInstances)
    demisto.results('yes')
else:
    demisto.results('no')
