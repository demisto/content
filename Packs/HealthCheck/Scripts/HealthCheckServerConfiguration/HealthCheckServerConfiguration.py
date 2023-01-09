import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


DR = "False"
AE = True
res = []
new_json = []

# Add actionable items
DESCRIPTION = [
    "The conf key: \"{}\" should be used only for debugging purposes",
    "The conf key: \"{}\" should be used only for a good reason",
    "The conf key: \"{}\" was set to ",
    "Entries indexing is not disabled",
    "Auto extract for tasks is not disabled, you may consider changing it",
    "The conf key: \"playbook.willnotexecute.eval.limit\" should be set to 1"
]
RESOLUTION = [
    "Remove the configuration key",
    "If you are not fully aware of the implication of using XSOAR without a Docker- please contact customer support",
    "Set the session timeout: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PPsBCAW",
    "Index War Room Entries: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/5-5/"
    "cortex-xsoar-admin/incidents/incidents-management/war-room-overview/index-war-room-entries",
    "Make sure you are aware of the purpose of this key: Docker containers overloaded: https://docs.paloaltonetworks.com/"
    "cortex/cortex-xsoar/6-0/cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server",
    "This configuration key should be used only in rare circumstances, please contact customer support",
    "The key should be used only for debugging purposes, remove the configuration key when not in use",
    "You should consider disabling it: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/5-5/"
    "cortex-xsoar-admin/manage-indicators/auto-extract-indicators",
    "The key improves system performance and was added by default to version 6.1"
]


def checkKeyValue(config):
    global EVAL, DR, AE
    for (key, value) in config.items():
        if type(value) is dict:
            checkKeyValue(value)
        if type(value) is not dict:
            new_json.append({'key': key, 'value': str(value)})

        # Actionable items rules:
        if key == "log.http.traffic" and value == "true":
            res.append({"category": "Configuration", "severity": "Medium",
                        "description": DESCRIPTION[0].format(key), "resolution": RESOLUTION[0]})
            continue

        if key == "python.executable.no.docker" and value == "true":
            res.append({"category": "Configuration", "severity": "Medium",
                        "description": DESCRIPTION[1].format(key), "resolution": RESOLUTION[1]})
            continue

        if key == "security.timeout" and int(value) > 60:
            res.append({"category": "Configuration", "severity": "Medium",
                        "description": DESCRIPTION[2].format(key, value), "resolution": RESOLUTION[2]})
            continue

        if key == "db.index.entry.disable" and value == "false":
            res.append({"category": "Configuration", "severity": "High",
                        "description": DESCRIPTION[3], "resolution": RESOLUTION[3]})
            continue
        if key == "containers.high.water.mark" and int(value) > 20:
            res.append({"category": "Configuration", "severity": "Medium",
                        "description": DESCRIPTION[2].format(key, str(value)), "resolution": RESOLUTION[4]})
            continue

        if key == "containers.low.water.mark" and int(value) < 2:
            res.append({"category": "Configuration", "severity": "Medium",
                        "description": DESCRIPTION[2].format(key, str(value)), "resolution": RESOLUTION[5]})
            continue

        if key == "ingestion.samples.save-mapped" and value == "true":
            res.append({"category": "Configuration", "severity": "Medium",
                        "description": DESCRIPTION[0].format(key), "resolution": RESOLUTION[6]})
            continue

        if key == "ui.livebackup" and value == "true":
            DR = "True"
            continue

        if key == "reputation.calc.algorithm.tasks" and int(value) == 1:
            AE = False
            continue


# v2 Update by JS (ver: 23/03/2021.1)


buildNumber = demisto.executeCommand("DemistoVersion", {})[0]['Contents']['DemistoVersion']['buildNumber']
# in local development instances, the build number will be "REPLACE_THIS_WITH_CI_BUILD_NUM"
buildNumber = f'{buildNumber}' if buildNumber != "REPLACE_THIS_WITH_CI_BUILD_NUM" else "618658"
if int(buildNumber) <= 618657:
    EVAL = True
else:
    EVAL = False

try:
    config_json = demisto.executeCommand("demisto-api-get", {"uri": "/system/config"})[0]["Contents"]["response"]
    new_json = []
    res = []
    checkKeyValue(config_json)

    demisto.executeCommand("setIncident", {"xsoarserverconfiguration": new_json})

    if AE:
        res.append({"category": "Configuration", "severity": "Medium",
                    "description": DESCRIPTION[4], "resolution": RESOLUTION[7]})

    results = CommandResults(
        readable_output="HealthCheckConfServer Done",
        outputs_prefix="HealthCheck.ActionableItems",
        outputs=res)

    return_results(results)

except ValueError:  # includes simplejson.decoder.JSONDecodeError
    return_results('Decoding JSON has failed')
