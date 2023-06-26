import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
This automation should be run in dev environments. It will consume 100% CPU for 10 - 20 minutes or more -
depending on the amount of playbook and automation content.
It is set to timeout at 15 minutes in Advanced settings. This may need to be increased if content amount is large.
It only parses python scripts to see if additional automations/commands are invoked via demisto.executeCommand or
execute_command. Javascript automations are not parsed
Command names passed in a variable to demisto.executeCommand or execute_command are not reported.
If a python automation fails to parse, an error is reported in the war room: any automations it calls are not reported.
Integration commands and builtins are not parsed.

"""

import ast


def GetAutomation(scriptid: str):
    results = demisto.executeCommand("demisto-api-post", {
        "uri": f"/automation/load/{scriptid}"
    })
    if is_error(results):
        return f"MISSING_SCRIPT_FOR_ID_{scriptid}", "", ""
    response = results[0]['Contents']['response']
    return response['name'], response['script'], response['type']


def GetAutomationName(scriptid: str) -> str:
    octets = scriptid.split('-')
    if len(octets) == 5:
        if len(octets[0]) == 8 and len(octets[1]) == 4 and len(octets[2]) == 4 and len(octets[3]) == 4 and len(octets[4]) == 12:
            results = demisto.executeCommand("demisto-api-post", {
                "uri": f"/automation/load/{scriptid}"
            })
            if is_error(results):
                return f"MISSING_SCRIPT_FOR_ID_{scriptid}"
            return results[0]['Contents']['response']['name']
    octets = scriptid.split('|')
    if len(octets) == 4:
        return ""

    return scriptid


def CalledAutomation(scrname: str, script: str) -> list:
    if script == "":
        return []
    try:
        lines = ast.dump(ast.parse(script), indent="").splitlines()  # type: ignore
    except Exception as ex:
        return_results(f"CalledAutomation: Error parsing script {scrname} - Error: {str(ex)}")
        return []

    watchname = False
    watchatt = False
    watcharg = False
    watchval = False
    names = []

    for lin in lines:
        if not watchname and "Call" in lin:
            watchname = True
            continue
        if watchname:
            if 'func=Name' in lin:
                name = lin.split("'")[1]
                if name == "execute_command":
                    watcharg = True
                    continue
            if 'func=Attribute' in lin:
                watchatt = True
                continue
            if watchatt:
                if 'attr=' in lin:
                    name = lin.split("'")[1]
                    watchatt = False
                    if name == "executeCommand":
                        watcharg = True
                        continue
            if watcharg:
                if "args=[" in lin:
                    watcharg = False
                    watchval = True
                    continue
            if watchval:
                if "Constant(value=" in lin:
                    parts = lin.split("'")
                    if len(parts) > 1:
                        name = parts[1]
                        watchval = False
                        watchname = False
                        names.append(name)

    final = []
    names = list(set(names))
    for n in names:
        if n != "":
            final.append(n)
    return final


def GetPlaybooks(query: str) -> list:
    if query != "":
        query = " AND " + query
    playbooks = demisto.executeCommand("demisto-api-post", {
        "uri": "/playbook/search",
        "body": {"query": f"hidden:F AND deprecated:F {query}"}
    })[0]['Contents']['response']['playbooks']
    return playbooks


def GetEntities(playbooks: list) -> dict:
    entities = {}

    for p in playbooks:
        pbname = p['name']
        entities[pbname] = {'etype': "playbook", 'pcalled': [], 'pcalls': [], 'scalled': [], 'scalls': []}
        for key, t in p['tasks'].items():
            if t['type'] == "playbook":
                spbname = t['task'].get('name', "notaskname")
                if spbname not in entities:
                    entities[spbname] = {'etype': "playbook", 'pcalled': [], 'pcalls': [], 'scalled': [], 'scalls': []}
                entities[pbname]['pcalls'].append(spbname)  # type: ignore
                entities[spbname]['pcalled'].append(pbname)  # type: ignore
            elif "scriptId" in t['task'].keys():
                scrname = GetAutomationName(t['task']['scriptId'])
                if scrname != "":
                    scrname, script, stype = GetAutomation(scrname)
                else:
                    scrname = t['task']['scriptId']
                    script = ""
                    stype = ""
                if scrname not in entities:
                    entities[scrname] = {'etype': "script", 'pcalled': [], 'pcalls': [], 'scalled': [], 'scalls': []}
                entities[pbname]['scalls'].append(scrname)  # type: ignore
                entities[scrname]['pcalled'].append(pbname)  # type: ignore
                if stype == "python":
                    calls = CalledAutomation(scrname, script)
                else:
                    calls = []
                if len(calls) > 0:
                    entities[scrname]['scalls'].extend(calls)  # type: ignore
                    for s in calls:
                        if s not in entities:
                            entities[s] = {'etype': "script", 'pcalled': [], 'pcalls': [], 'scalled': [], 'scalls': []}
                        entities[s]['scalled'].append(scrname)  # type: ignore

    return entities


def PlaybookCsv(key: str, ent: dict) -> str:
    output = ""
    calls = list(set(ent['pcalls']))
    if len(calls) > 0:
        for val in calls:
            output += f"Playbook, {key}, Calls, Playbook, {val}\n"

    calls = list(set(ent['scalls']))
    if len(calls) > 0:
        for val in calls:
            output += f"Playbook, {key}, Calls, Automation, {val}\n"

    calls = list(set(ent['pcalled']))
    if len(calls) > 0:
        for val in calls:
            output += f"Playbook, {key}, Calledby, Playbook, {val}\n"

    return (output)


def ScriptCsv(key: str, ent: dict) -> str:
    output = ""
    calls = list(set(ent['scalls']))
    if len(calls) > 0:
        for val in calls:
            output += f"Automation, {key}, Calls, Automation, {val}\n"

    calls = list(set(ent['scalled']))
    if len(calls) > 0:
        for val in calls:
            output += f"Automation, {key}, Calledby, Automation, {val}\n"

    calls = list(set(ent['pcalled']))
    if len(calls) > 0:
        for val in calls:
            output += f"Automation, {key}, Calledby, Playbook, {val}\n"

    return (output)


def PlaybookMarkdown(key: str, ent: dict) -> str:
    output = f"{key}\n\n"
    calls = list(set(ent['pcalls']))
    if len(calls) > 0:
        for val in calls:
            output += f"    Calls: Playbook: {val}\n"

    calls = list(set(ent['scalls']))
    if len(calls) > 0:
        for val in calls:
            output += f"    Calls: Automation: {val}\n"

    calls = list(set(ent['pcalled']))
    if len(calls) > 0:
        for val in calls:
            output += f"    Called by: Playbook: {val}\n"

    return (output)


def ScriptMarkdown(key: str, ent: dict) -> str:
    output = f"{key}\n\n"
    calls = list(set(ent['scalls']))
    if len(calls) > 0:
        for val in calls:
            output += f"    Calls: Automation: {val}\n"

    calls = list(set(ent['scalled']))
    if len(calls) > 0:
        for val in calls:
            output += f"    Called by: Automation: {val}\n"

    calls = list(set(ent['pcalled']))
    if len(calls) > 0:
        for val in calls:
            output += f"    Called by: Playbook: {val}\n"

    return (output)


def main():
    try:
        args = demisto.args()
        outfmt = args['format']
        filename = args.get("filename", "dependencies.txt")
        pbquery = args.get("query", "")
        playbooks = GetPlaybooks(pbquery)
        entities = GetEntities(playbooks)
        output = ""

        if outfmt == "markdown" or outfmt == "":
            output += "### Playbooks\n"
        for key, ent in entities.items():
            if ent['etype'] == "playbook":
                if outfmt == "csv":
                    output += PlaybookCsv(key, ent)
                else:
                    output += PlaybookMarkdown(key, ent)

        if outfmt == "markdown" or outfmt == "":
            output += "### Automations\n"
        for key, ent in entities.items():
            if ent['etype'] == "script":
                if outfmt == "csv":
                    output += ScriptCsv(key, ent)
                else:
                    output += ScriptMarkdown(key, ent)

        if outfmt == "csv":
            demisto.results(fileResult(filename, output))
        else:
            field = args.get("fieldname", "").strip()
            if field != "":
                demisto.executeCommand("setIncident", {'customFields': json.dumps({field: output})})
            else:
                demisto.results({
                    "ContentsFormat": formats["markdown"],
                    "Contents": output
                })

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"ContentDependencies: Exception failed to execute. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
