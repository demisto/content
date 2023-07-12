import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def isDemistoAPIIntegrationAvailable():

    brandNames = ["Demisto REST API", "Core REST API"]
    allInstances = demisto.getModules()
    brandInstances = [
        instanceName for instanceName in allInstances
        if allInstances[instanceName]['brand'].lower() in [brandName.lower() for brandName in brandNames]
        and demisto.get(allInstances[instanceName], 'state') and allInstances[instanceName]['state'] == 'active'
    ]

    if len(brandInstances) == 1:
        return 1
    elif len(brandInstances) > 1:
        return 2
    else:
        return 0


def isAdminAPIInstance():
    isDefaultAdminExist = False
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
        if module['Type'] == 4:
            continue
        if isinstance(module['Contents'], str):
            return_error(module['Contents'])
        elif module.get('Contents', {}).get('response', {}).get('defaultAdmin', {}):
            isDefaultAdminExist = True
        else:
            continue

    return isDefaultAdminExist


errors = [""]
# Check if Demisto REST API integration was defined and number of instances
ApiIntegrations = isDemistoAPIIntegrationAvailable()
if ApiIntegrations == 0:
    errors.append('No API integration defined')

if ApiIntegrations == 2:
    errors.append("Too many API integrations were defined")

# Check if Demisto REST API integration defined with DefaultAdmin API key
if not isAdminAPIInstance():
    errors.append('API instance is not using Admin')

if len(errors) > 1:
    strerror = "\n".join(errors)
    return_error(f"Demisto REST API Validation failed due to: {strerror}")
else:
    return_results("Done")
