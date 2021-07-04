import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]
accountName = incident.get('account')
accountName = f"acc_{accountName}" if accountName != "" else ""

res = demisto.executeCommand(
    "demisto-api-post",
    {
        "uri": f"{accountName}/settings/integration/search",
        "body": {
            "size": 500
        },
    })[0]["Contents"]["response"]

enabledInstances = list(filter(lambda x: x['enabled'] == "true", res['instances']))
enabledInstancesNames = []
for instance in enabledInstances:
    if instance['name'] in ['testmodule', 'd2']:
        continue
    else:
        enabledInstancesNames.append({'instancename': instance['name']})

demisto.executeCommand('setIncident', {'healthcheckenabledinstances': enabledInstancesNames})
demisto.executeCommand('setIncident', {'healthchecknumberofengines': res['engines']['total']})
