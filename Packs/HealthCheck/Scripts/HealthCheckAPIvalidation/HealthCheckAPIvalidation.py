import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def isDemistoAPIIntegrationAvailable():

    brandName = "Demisto REST API"
    allInstances = demisto.getModules()
    brandInstances = [instanceName for instanceName in allInstances if allInstances[instanceName]['brand'].lower(
    ) == brandName.lower() and demisto.get(allInstances[instanceName], 'state') and allInstances[instanceName]['state'] == 'active']
    if brandInstances:
        return True
    else:
        return False


def isAdminAPIInstance():
    isAdminExist = False
    incident = demisto.incidents()[0]
    accountName = incident.get('account')
    accountName = f"acc_{accountName}" if accountName != "" else ""

    res = demisto.executeCommand(
        "demisto-api-post",
        {
            "uri": f"{accountName}/user/preferences",
            "body": {
                "size": 500
            },
        })
    for module in res:
        if module['Contents']['response']['id'] == 'admin':
            isAdminExist = True

    return isAdminExist


errors = []
# Check if Demisto REST API integration was defined
if not isDemistoAPIIntegrationAvailable():
    errors.append('No API integration defined')

# Check if Demisto REST API integration defined with admin API key
if not isAdminAPIInstance():
    errors.append('API instance is not Admin')

if errors:
    return_error(f"Demisto REST API Validation failed, check: {errors}")
