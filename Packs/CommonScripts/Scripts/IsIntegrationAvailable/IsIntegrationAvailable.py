import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def is_integration_available(brandName, allInstances):
    brandInstances = [instanceName for instanceName in allInstances
                      if allInstances[instanceName]['brand'].lower() == brandName.lower()
                      and demisto.get(allInstances[instanceName], 'state')
                      and allInstances[instanceName]['state'] == 'active']
    if brandInstances:
        demisto.setContext('brandInstances', brandInstances)
        demisto.results('yes')
    else:
        demisto.results('no')


def main():
    brandName = demisto.get(demisto.args(), 'brandname')
    allInstances = demisto.getModules()
    is_integration_available(brandName, allInstances)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
