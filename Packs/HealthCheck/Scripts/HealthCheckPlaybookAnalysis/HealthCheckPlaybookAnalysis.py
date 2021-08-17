import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


args = demisto.args()

DESCRIPTION = [
    'The playbook: "{}" may be a copy of a built-in playbook, you may consider using out of the box playbooks',

    'The playbook: "{}" is using a sleep command, you may consider changing it',

    'The playbook: "{}" is using the setIncident command 4 times or more, which could result with DB version violation',

    'The playbook: "{}" is using the "EmailAskUser" functionality, you may consider switching it to Data Collection',

    'The playbook: "{}" is using over 30 tasks, you may want to use sub-playbooks for better '
    + 'organization of playbook tasks',
]

RESOLUTION = [
    "Consider using out of the box playbooks",

    "Consider changing it to prefered methods such as: https://xsoar.pan.dev/docs/playbooks/generic-polling "
    + "https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PPOaCAO",

    "Consider joining some of the setIncident tasks",

    "Communication Tasks: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
    + "cortex-xsoar-admin/playbooks/playbook-tasks/communication-tasks",

    "Sub-playbook Tutorial: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
    + "cortex-xsoar-admin/playbooks/configure-a-sub-playbook-loop/sub-playbook-tutorial",
]


Thresholds = {
    "CustomPlaybookSetIncidentCount": 4,
    "CustomPlaybookLength": 30,
}

incident = demisto.incidents()[0]
account_name = incident.get('account')
account_name = f'acc_{account_name}/' if account_name != "" else ""

thresholds = args.get('Thresholds', Thresholds)

customPlaybooks = demisto.executeCommand(
    "demisto-api-post", {"uri": f"{account_name}playbook/search",
                         "body": {"query": "system:F"}})[0]["Contents"]["response"]["playbooks"]
builtinPlaybooks = demisto.executeCommand(
    "demisto-api-post", {"uri": f"{account_name}playbook/search",
                         "body": {"query": "system:T"}})[0]["Contents"]["response"]["playbooks"]

builtinPlaybooksNames = []
res = []
if customPlaybooks is not None:
    for builtinPlaybook in builtinPlaybooks:
        builtinPlaybooksNames.append(builtinPlaybook["name"])

    for customPlaybook in customPlaybooks:

        for builtinPlaybooksName in builtinPlaybooksNames:
            if builtinPlaybooksName in customPlaybook["name"]:
                res.append({"category": "Playbooks", "severity": "Low",
                            "description": f"{DESCRIPTION[0]}".format(customPlaybook["name"]),
                            "resolution": f"{RESOLUTION[0]}"
                            })

        if "Sleep" in customPlaybook["scriptIds"]:
            res.append({"category": "Playbooks", "severity": "Low",
                        "description": f"{DESCRIPTION[1]}".format(customPlaybook["name"]),
                        "resolution": f"{RESOLUTION[1]}"
                        })

        if str(customPlaybook).count("Builtin|||setIncident") >= thresholds['CustomPlaybookSetIncidentCount']:
            res.append({"category": "Playbooks", "severity": "Low",
                        "description": f"{DESCRIPTION[2]}".format(customPlaybook["name"]),
                        "resolution": f"{RESOLUTION[2]}"
                        })

        if "EmailAskUser" in customPlaybook["scriptIds"]:
            res.append({"category": "Playbooks", "severity": "Low",
                        "description": f"{DESCRIPTION[3]}".format(customPlaybook["name"]),
                        "resolution": f"{RESOLUTION[3]}"
                        })

        if len(customPlaybook["tasks"]) > thresholds['CustomPlaybookLength']:
            res.append({"category": "Playbooks", "severity": "Low",
                        "description": f"{DESCRIPTION[4]}".format(customPlaybook["name"]),
                        "resolution": f"{RESOLUTION[4]}"
                        })

results = CommandResults(
    readable_output="HealthCheckPlaybookAnalysis Done",
    outputs_prefix="HealthCheck.ActionableItems",
    outputs=res)

return_results(results)
