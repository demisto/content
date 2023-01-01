import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
brands_names = ["demisto rest api", "core rest api"]

instanceName = demisto.args().get('instanceName')
allInstances = demisto.getModules()
brandInstances = [instanceName for instanceName in allInstances if allInstances[instanceName]['brand'].lower(
) in brands_names and demisto.get(allInstances[instanceName], 'state') and allInstances[instanceName]['state'] == 'active']
if brandInstances and instanceName in brandInstances:
    instance = allInstances.get(instanceName)
    instance['name'] = instanceName
    if instance['brand'].lower() == 'demisto rest api':
        demisto.setContext('DemistoAPIInstances', instance)
    else:
        demisto.setContext('CoreAPIInstances', instance)
    demisto.results('yes')
else:
    demisto.results('no')
