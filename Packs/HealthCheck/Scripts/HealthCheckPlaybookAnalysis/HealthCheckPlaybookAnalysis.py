import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
customPlaybooks = demisto.executeCommand(
    "demisto-api-post", {"uri": "/playbook/search", "body": {"query": "system:F"}})[0]["Contents"]["response"]["playbooks"]
builtinPlaybooks = demisto.executeCommand(
    "demisto-api-post", {"uri": "/playbook/search", "body": {"query": "system:T"}})[0]["Contents"]["response"]["playbooks"]

builtinPlaybooksNames = []
res = []

for builtinPlaybook in builtinPlaybooks:
    builtinPlaybooksNames.append(builtinPlaybook["name"])

for customPlaybook in customPlaybooks:

    for builtinPlaybooksName in builtinPlaybooksNames:
        if builtinPlaybooksName in customPlaybook["name"]:
            res.append({"category": "Playbooks", "severity": "Low",
                        "description": "The playbook: \"{}\" may be a copy of a built-in playbook, you may consider using out of the box playbooks".format(customPlaybook["name"])})

    if "Sleep" in customPlaybook["scriptIds"]:
        res.append({"category": "Playbooks", "severity": "Low",
                    "description": "The playbook: \"{}\" is using a sleep command, you may consider changing it".format(customPlaybook["name"])})

    if str(customPlaybook).count("Builtin|||setIncident") >= 4:
        res.append({"category": "Playbooks", "severity": "Low",
                    "description": "The playbook: \"{}\" is using the setIncident command 4 times or more, which could result with DB version violation".format(customPlaybook["name"])})

    if "EmailAskUser" in customPlaybook["scriptIds"]:
        res.append({"category": "Playbooks", "severity": "Low",
                    "description": "The playbook: \"{}\" is using the \"EmailAskUser\" functionality, you may consider switching it to Data Collection".format(customPlaybook["name"])})

    if len(customPlaybook["tasks"]) > 30:
        res.append({"category": "Playbooks", "severity": "Low",
                    "description": "The playbook: \"{}\" is using over 30 tasks, you may want to use sub-playbooks for better organization of playbook tasks".format(customPlaybook["name"])})

results = CommandResults(
    readable_output="HealthCheckPlaybookAnalysis Done",
    outputs_prefix="actionableitems",
    outputs=res)

return_results(results)
