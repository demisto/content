import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Dict, Any

vcuris = [
    "/vc/history/list/all/-1",
    "/vc/history/playbook/all/-1",
    "/vc/history/automation/all/-1",
    "/vc/history/incidenttype/all/-1",
    "/vc/history/incidentfield/all/-1",
    "/vc/history/layoutscontainer/all/-1",
    "/vc/history/reputation/all/-1",
    "/vc/history/generictype/all/-1",
    "/vc/history/integration/all/-1",
    "/vc/history/preprocessrule/all/-1"
]


def main():
    try:
        # Get the local, uncommitted changed objects
        changes = demisto.executeCommand("demisto-api-get", {
            'uri': "/vc/changes/uncommitted"
        })[0]['Contents']['response']

        # Build the changed object dictionary
        itypes: Dict[str, Dict[str, Dict[str, Any]]]
        itypes = {}

        if changes is not None:
            for item in changes:
                if "message" in item:
                    msg = item['message']
                else:
                    msg = "no message"
                if item['type'] not in itypes:
                    itypes[item['type']] = {}
                itypes[item['type']][item['name']] = {"action": item['action'], "message": msg, "history": []}

        # Get all the commit histories
        commits = []
        for uri in vcuris:
            commits.append(demisto.executeCommand("demisto-api-get", {
                "uri": uri
            })[0]['Contents']['response']['commits'])

        # Add commit histories to the changed objects
        for ctype in commits:
            for c in ctype:
                # Skip commit history if no changed objects of same type
                if c['type'] not in itypes:
                    continue
                # Skip commit history if no changed object of same name
                if c['name'] not in itypes[c['type']]:
                    continue
                if c['commitMessage'] == "":
                    c['commitMessage'] = "no message"
                a = {
                    "action": c['action'],
                    "message": c['commitMessage']
                }
                itypes[c['type']][c['name']]['history'].append(a)

        # Generate output
        output = "## Current Local Changes History\n"
        for typekey, value in itypes.items():
            output += f"### {typekey}\n"
            for key, value in value.items():
                output += f"#### {key}:\n"
                # If no commit history found (that includes the most recent action), use the most recent action
                if len(itypes[typekey][key]['history']) == 0:
                    a = {
                        "action": itypes[typekey][key]['action'],
                        "message": itypes[typekey][key]['message']
                    }
                    itypes[typekey][key]['history'].append(a)
                for entry in itypes[typekey][key]['history']:
                    output += f"{entry['action']}, {entry['message']}\n"

        demisto.executeCommand("setIncident", {'customFields': json.dumps({"contenttestingcommithistory": output})})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"ChangeHistory: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
