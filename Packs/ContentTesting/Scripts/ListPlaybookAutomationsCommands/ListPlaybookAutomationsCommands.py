import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Final Test: 6.10
import uuid
from typing import Dict


def GetAutomationName(id):
    results = demisto.executeCommand("demisto-api-post", {
        "uri": f"/automation/load/{id}"
    })[0]['Contents']
    if 'response' in results:
        if 'name' in results['response']:
            return results['response']['name']
    return ""


def GetPlaybooks():
    response = demisto.executeCommand("demisto-api-post", {
        "uri": "/playbook/search",
        "body": {"query": "hidden:F AND deprecated:F"}
    })[0]['Contents']['response']['playbooks']

    playbooks = []
    for r in response:
        playbooks.append(r)
    return playbooks


def GetAutomationsUsed(playbooks):
    automations: Dict[str, Dict[str, str]]
    automations = {}
    for p in playbooks:
        for key, t in p['tasks'].items():
            if "scriptId" in t['task'].keys():
                s = t['task']['scriptId']
                try:
                    uuid.UUID(s)
                    s = GetAutomationName(s)
                except ValueError:
                    pass
                if s != "":
                    if p['name'] not in automations:
                        automations[p['name']] = {}
                    automations[p['name']][s] = ""
    return automations


def main():
    try:
        scripts = GetAutomationsUsed(GetPlaybooks())
        output = ""
        for key, val in scripts.items():
            output += f"### {key}\n"
            for akey, aval in val.items():
                output += f"{akey}\n"
        demisto.executeCommand("setIncident", {'customFields': json.dumps({"contenttestingcontentautomations": output})})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"ListPlaybookAutomationsCommands: Exception failed to execute. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
