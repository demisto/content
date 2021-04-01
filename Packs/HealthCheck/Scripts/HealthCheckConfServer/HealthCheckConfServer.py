import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

DR = "False"
AE = True

buildNumber = demisto.executeCommand("DemistoVersion", {})[0]['Contents']['DemistoVersion']['buildNumber']
if int(buildNumber) <= 618657:
    EVAL = True
else:
    EVAL = False

path = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})
if path[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')

try:
    with open(path[0]['Contents']['path'], 'r') as file:
        file_json = json.loads(file.read())
        new_json = []
        res = []
        for (key, value) in file_json.items():
            new_json.append({'key': key, 'value': str(value)})

            # Actionable items rules:
            if key == "log.http.traffic" and value == "true":
                res.append({"category": "Configuration", "severity": "Medium",
                            "description": "The conf key: \"{}\" should be used only for debugging purposes".format(key)})

            if key == "python.executable.no.docker" and value == "true":
                res.append({"category": "Configuration", "severity": "Medium",
                            "description": "The conf key: \"{}\" should be used only for a good reason".format(key)})

            if key == "security.timeout" and int(value) > 60:
                res.append({"category": "Configuration", "severity": "Medium",
                            "description": "The conf key: \"{}\" was set to {}".format(key, value)})

            if key == "db.index.entry.disable" and value == "false":
                res.append({"category": "Configuration", "severity": "High", "description": "Entries indexing is not disabled"})

            if key == "containers.high.water.mark" and int(value) > 20:
                res.append({"category": "Configuration", "severity": "Medium",
                            "description": "The conf key: \"{}\" was set to {}".format(key, str(value))})

            if key == "containers.low.water.mark" and int(value) < 2:
                res.append({"category": "Configuration", "severity": "Medium",
                            "description": "The conf key: \"{}\" was set to {}".format(key, str(value))})

            if key == "ingestion.samples.save-mapped" and value == "true":
                res.append({"category": "Configuration", "severity": "Medium",
                            "description": "The conf key: \"{}\" should be used only for debugging purposes".format(key)})

            if key == "ui.livebackup" and value == "true":
                DR = "True"

            if key == "reputation.calc.algorithm.tasks" and int(value) == 1:
                AE = False

            if key == "playbook.willnotexecute.eval.limit" and int(value) == 1:
                EVAL = False

    demisto.executeCommand("setIncident", {"confgrid": new_json, "dr": DR})

    if AE:
        res.append({"category": "Configuration", "severity": "Medium",
                    "description": "Auto extract for tasks is not disabled, you may consider changing it"})

    if EVAL:
        res.append({"category": "Configuration", "severity": "Medium",
                    "description": "The conf key: \"playbook.willnotexecute.eval.limit\" should be set to 1"})

    results = CommandResults(
        readable_output="HealthCheckConfServer Done",
        outputs_prefix="actionableitems",
        outputs=res)

    return_results(results)

except ValueError:  # includes simplejson.decoder.JSONDecodeError
    demisto.results('Decoding JSON has failed')
