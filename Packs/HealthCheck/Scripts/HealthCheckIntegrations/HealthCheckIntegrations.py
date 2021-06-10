import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
res = demisto.executeCommand(
    "demisto-api-post",
    {
        "uri": "/settings/integration/search",
        "body": {
            "size": 500
        },
    })[0]["Contents"]["response"]


enabledInstances = list(filter(lambda x: x['enabled'] == "true", res['instances']))
print(res[])
enabledInstancesNames = []
for instance in enabledInstances:
    if instance['name'] in ['testmodule', 'd2']:
        continue
    else:
        enabledInstancesNames.append({'instances': instance['name']})

demisto.executeCommand('setIncident', {'enabledinstances': enabledInstancesNames})
demisto.executeCommand('setIncident', {'numberofengines': res['engines']['total']})
