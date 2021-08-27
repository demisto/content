import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
brandName = "Demisto REST API"
instanceName = demisto.args().get('instanceName')
allInstances = demisto.getModules()
brandInstances = [instanceName for instanceName in allInstances if allInstances[instanceName]['brand'].lower(
) == brandName.lower() and demisto.get(allInstances[instanceName], 'state') and allInstances[instanceName]['state'] == 'active']
if brandInstances and instanceName in brandInstances:
    instance = allInstances.get(instanceName)
    instance['name'] = instanceName
    demisto.setContext('DemsistoAPIInstances', instance)
    demisto.results('yes')
else:
    demisto.results('no')
