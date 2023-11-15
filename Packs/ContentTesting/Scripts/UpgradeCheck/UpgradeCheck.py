import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Dict, List

INDENT = "##### "


def NewVersion(curver):
    parts = curver.split(".")
    parts[2] = str(int(parts[2]) + 1)
    return ".".join(parts)


def NewMinVersion(curver):
    parts = curver.split(".")
    parts[2] = "0"
    parts[1] = str(int(parts[1]) + 1)
    return ".".join(parts)


def NewMajVersion(curver):
    parts = curver.split(".")
    parts[2] = "0"
    parts[1] = "0"
    parts[0] = str(int(parts[0]) + 1)
    return ".".join(parts)


def CleanMarkdown(text):
    return re.sub('["*","#","-", ":"]', '', text)


def ChangeList(text):
    commits = text.split("\n")
    changes = []

    for line in commits:
        if line != "" and line != "- ":
            changes.append(line.strip().replace("- ", "").replace("-", ""))
    return changes


def CheckUpdates(packs, types, playbook, layout):
    pbupdated = False
    loupdated = False
    for p in packs:
        if p in types:
            if types[p]['playbook'] == playbook:
                pbupdated = True
            if types[p]['layout'] == layout:
                loupdated = True

    return pbupdated, loupdated


def GetUpgradedPacks():
    response = demisto.executeCommand("demisto-api-get", {
        'uri': "/contentpacks/installed-expired",
        'body': ""
    })[0]['Contents']['response']
    upgradePacks = {}
    changesPacks = {}

    for r in response:
        if r['updateAvailable']:
            packid = r['packID']
            upgradePacks[packid] = r
            changes = ""
            breaking = ""

            newver = NewVersion(r['currentVersion'])
            if newver in r['changelog'].keys():
                changes = r['changelog'][newver]['releaseNotes']
                breaking = r['changelog'][newver]['breakingChangesNotes']
            newver = NewMinVersion(r['currentVersion'])
            if newver in r['changelog'].keys():
                changes = r['changelog'][newver]['releaseNotes']
                breaking = r['changelog'][newver]['breakingChangesNotes']
            newver = NewMajVersion(r['currentVersion'])
            if newver in r['changelog'].keys():
                changes = r['changelog'][newver]['releaseNotes']
                breaking = r['changelog'][newver]['breakingChangesNotes']

            changesPacks[packid] = {"changes": changes, "breaking": breaking}

    return upgradePacks, changesPacks


def FilterPacks(packs, upgradePacks, changesPacks):
    packlist = [p.lower().replace(" ", "") for p in packs.split(",")]
    if len(packlist) == 1 and packlist[0] == "":
        return upgradePacks, changesPacks

    upgrade = upgradePacks.copy()
    for packid, pack in upgrade.items():
        if packid.lower().replace(" ", "") in packlist:
            continue
        else:
            del upgradePacks[packid]
            del changesPacks[packid]

    return upgradePacks, changesPacks


def GetUpgradedIntegrations(packs):
    response = demisto.executeCommand("demisto-api-post", {
        'uri': "/settings/integration/search",
        "body": {}
    })[0]['Contents']['response']
    configs = response['configurations']
    instances = response['instances']
    integrations = {}
    integmap = {}

    for packid, p in packs.items():
        integs = p['contentItems'].get('integration', [])
        if integs is not None:
            for i in integs:
                integmap[i['name']] = packid

    for c in configs:
        instid = c['id']
        if c['packName'] == "Palo Alto Networks Cortex XDR - Investigation and Response":
            instid = "Palo Alto Networks Cortex XDR - Investigation and Response"
        if instid in integmap.keys():
            packid = integmap[instid]
            integrations[packid] = {
                "classifier": c.get('defaultClassifier', ""),
                "mapperin": c.get('defaultMapperIn', ""),
                "mapperout": c.get('defaultMapperOut', ""),
                "instance": ""
            }

    for i in instances:
        instid = i['brand']
        name = i['name']
        if instid == "Cortex XDR - IR":
            instid = "Palo Alto Networks Cortex XDR - Investigation and Response"
        if instid in integmap.keys():
            packid = integmap[instid]
            integrations[packid]['instance'] = name

    return integrations


def GetCustomPlaybooks():
    response = demisto.executeCommand("demisto-api-post", {
        'uri': "/playbook/search",
        "body": {'query': "system:F AND hidden:F AND deprecated:F"}
    })[0]['Contents']['response']['playbooks']
    playbooks = []

    for r in response:
        # if r['packID'] == "":
        playbooks.append(r)
    return playbooks


def GetFieldKey(inoutfield):
    if type(inoutfield) is list:
        output = []
        for item in inoutfield:
            if 'key' in item:
                output.append(item['key'])
            elif 'contextPath' in item:
                output.append(item['contextPath'])
            else:
                output.append(item)
        output = ','.join(output)
    else:
        output = re.sub('["$","{","}"]', '', inoutfield)
    return (output)


def GetFieldsUsed(playbooks):
    usedfields: Dict[str, List[str]]
    usedfields = {}
    regex = re.compile("\$\{incident\.[^}]+\}")

    for p in playbooks:
        name = p['name']
        usedfields[name] = []
        if p['inputs'] is not None:
            usedfields[name].append(GetFieldKey(p['inputs']))
        if p['outputs'] is not None:
            usedfields[name].append(GetFieldKey(p['outputs']))

        for key, t in p['tasks'].items():
            if "scriptArguments" in t.keys():
                for m in regex.findall(json.dumps(t)):
                    usedfields[name].append(GetFieldKey(m))

    return usedfields


def GetSubplaybooksUsed(playbooks):
    usedplaybooks = []
    for p in playbooks:
        for key, t in p['tasks'].items():
            if t['type'] == 'playbook':
                if 'name' in p and 'name' in t['task']:
                    usedplaybooks.append({"parent": p['name'], "child": t['task']['name']})

    return (usedplaybooks)


def GetAutomationsUsed(playbooks):
    automations = []
    for p in playbooks:
        if len(p['scriptIds']) != 0:
            for s in p['scriptIds']:
                if 'name' in p:
                    automations.append({"playbook": p['name'], "scripts": s})

    return automations


def GetUpgradedScripts(packs, scripts):
    scriptdict = {}
    for index, value in enumerate(scripts):
        scriptdict[value['scripts']] = value
    upgscripts = []

    for p in packs:
        response = demisto.executeCommand("demisto-api-get", {
            "uri": f"/contentpacks/marketplace/{p}",
            "body": ""
        }
        )[0]['Contents']['response']
        automations = response['contentItems']['automation']

        if automations is not None:
            for a in automations:
                if a['name'] in scriptdict.keys():
                    s = scriptdict[a['name']]
                    upgscripts.append({"playbook": s['playbook'], "pack": p, "script": s['scripts']})

    return upgscripts


def GetUpgradedIncidentTypes(packs):
    response = demisto.executeCommand("demisto-api-get", {
        'uri': "/incidenttype",
        'body': ""
    }
    )[0]['Contents']['response']
    uptypes = {}
    custtypes = []
    for r in response:
        pb = r.get('playbookId', "<none>")
        lo = r.get('layout', "<none>")
        if not r['system']:
            custype = {'id': r['id'], 'playbook': pb, 'layout': lo, 'packid': "<none>"}
            custtypes.append(custype)
        pi = r.get('packID', "<none>")
        if pi in packs.keys():
            uptypes[pi] = {'playbook': pb, 'layout': lo, 'packid': pi}
    return (uptypes, custtypes)


def BuildItem(pack, key):
    md = f"{key}:\n"
    items = pack['contentItems'][key]
    if items is not None:
        for i in items:
            if 'name' in i:
                md += f"{i['name']}\n"
    if md != f"{key}:\n":
        return (md)
    return ("")


def ImpactMD(upgradePacks, integinstances, types, custypes, subplaybooks, upgradescripts, usedfields):
    md = ""
    md += "#### Custom_Playbooks:\n"
    md += f"{INDENT}Automations_Used:\n"
    md += "|Custom Playbook|Content Pack|Automation|\n"
    md += "|---|---|---|\n"
    for s in upgradescripts:
        md += f"| {s['playbook']} | {s['pack']} | {s['script']} |\n"

    md += f"{INDENT}Subplaybooks_Used:\n"
    md += "|Playbook|Sub-Playbook|\n"
    md += "|---|---|\n"
    for p in subplaybooks:
        md += f"| {p['parent']} | {p['child']} |\n"

    md += f"{INDENT}Fields_Used_Inputs_Outputs:\n"
    md += "|Playbook|Fields|\n"
    md += "|---|---|\n"
    for key, val in usedfields.items():
        for f in val:
            md += f"| {key} | {f} |\n"

    md += "#### Custom_Incident_Types:\n"
    md += "|Incident Type|Object Type|Object|\n"
    md += "|---|---|---|\n"
    for c in custypes:
        if c['id'] != "Unclassified":
            pbupd, loupd = CheckUpdates(upgradePacks, types, c['playbook'], c['layout'])
            if pbupd:
                md += f"| {c['id']} | Playbook | {c['playbook']} |\n"
            if loupd:
                md += f"| {c['id']} | Layout   | {c['layout']}   |\n"

    md += "#### Integration_Instances:\n"
    for key, i in integinstances.items():
        if i['instance'] != "":
            md += f"{INDENT}Instance: {i['instance']}\n"
            if i['classifier'] != "":
                md += f"Classifier: {i['classifier']}\n"
            if i['mapperin'] != "":
                md += f"Mapperin: {i['mapperin']}\n"
            if i['mapperout'] != "":
                md += f"Mapperout: {i['mapperout']}\n"

    return (md)


def UpgradeMD(upgradePacks, changes):
    md = ""

    for p in upgradePacks:
        md += f"\n#### {p}:\n"

        newmd = BuildItem(upgradePacks[p], 'incidentfield')
        if newmd != "":
            md += f"{INDENT} {newmd}"

        newmd = BuildItem(upgradePacks[p], 'integration')
        if newmd != "":
            md += f"{INDENT} {newmd}"

        newmd = BuildItem(upgradePacks[p], 'incidenttype')
        if newmd != "":
            md += f"{INDENT} {newmd}"

        newmd = BuildItem(upgradePacks[p], 'playbook')
        if newmd != "":
            md += f"{INDENT} {newmd}"

        newmd = BuildItem(upgradePacks[p], 'layoutscontainer')
        if newmd != "":
            md += f"{INDENT} {newmd}"

        newmd = BuildItem(upgradePacks[p], 'automation')
        if newmd != "":
            md += f"{INDENT} {newmd}"

        md += f"{INDENT}changes:\n"
        chglist = ChangeList(CleanMarkdown(changes[p]['changes']))
        if chglist is not None:
            for c in chglist:
                md += f"{c}\n"

        breaking = CleanMarkdown(changes[p]['breaking'])
        if breaking.strip() != "":
            md += f"{INDENT}breaking:\n"
            md += f"{breaking}\n"

    return (md)


def main():
    try:
        packs = demisto.args().get("packs", "")
        upgradePacks, changesPacks = GetUpgradedPacks()
        upgradePacks, changesPacks = FilterPacks(packs, upgradePacks, changesPacks)
        upgradeIntegs = GetUpgradedIntegrations(upgradePacks)
        upgradeTypes, customTypes = GetUpgradedIncidentTypes(upgradePacks)
        playbooks = GetCustomPlaybooks()
        subplaybooks = GetSubplaybooksUsed(playbooks)
        scripts = GetAutomationsUsed(playbooks)
        fields = GetFieldsUsed(playbooks)
        upgradeScripts = GetUpgradedScripts(changesPacks, scripts)

        impact = ImpactMD(upgradePacks, upgradeIntegs, upgradeTypes, customTypes, subplaybooks, upgradeScripts, fields)
        demisto.executeCommand("setIncident", {'customFields': json.dumps({"contenttestingcontentimpacts": impact})})
        details = UpgradeMD(upgradePacks, changesPacks)
        demisto.executeCommand("setIncident", {'customFields': json.dumps({"contenttestingcontentdetails": details})})

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UpgradeCheck: Exception failed to execute. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
