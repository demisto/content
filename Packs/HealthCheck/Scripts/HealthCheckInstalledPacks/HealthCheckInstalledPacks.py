import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
packs = []
pack_list = []
cv_list = []
update_list = []
need_update = 0
not_certified = 0


config_json = demisto.executeCommand("demisto-api-get", {"uri": "/contentpacks/installed-expired"})[0]["Contents"]["response"]

for item in config_json:
    packs.append({"packs": item['id'], "currentversion": item['currentVersion'], 'updateavailable': item['updateAvailable']})
    pack_list.append({"packs": item['id'], "currentversion": item['currentVersion'], 'updateavailable': item['updateAvailable'],
                      "fsv": item['fromServerVersion'], "tsv": item['toServerVersion'], "certification": item['certification']})
    if item['updateAvailable']:
        need_update += 1
    if item['certification'].lower() != 'certified':
        not_certified += 1


res = []

if need_update > 0:
    res.append({"category": "Content packs", "severity": "Low",
                "description": "There are content packs that require an update",
                "resolution": "Navigate to the market place and update the outdated packs"
                })

if not_certified > 0:
    res.append({"category": "Content packs", "severity": "Low",
                "description": "There are uncertified content packs in use",
                "resolution": "Consider to remove these packs"
                })


demisto.executeCommand("setIncident", {
    'installedpacks': packs,
    'totalpacksinstalled': len(packs),
    'packsneedupdate': need_update
})

results = CommandResults(
    readable_output="HealchCheckInstalledPacks Done",
    outputs_prefix="actionableitems",
    outputs=res)

return_results(results)
