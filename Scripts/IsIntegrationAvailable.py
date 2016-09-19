brandName = demisto.get(demisto.args(), 'brandname')
allInstances = demisto.getModules()
brandInstances = [instanceName for instanceName in allInstances if allInstances[instanceName]['brand'].lower() == brandName.lower()]
if brandInstances:
    demisto.setContext('brandInstances', brandInstances)
    demisto.results('yes')
else:
    demisto.results('no')
