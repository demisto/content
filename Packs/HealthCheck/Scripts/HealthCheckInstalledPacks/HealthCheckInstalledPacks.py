import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
packs_num = []
packs = []
pack_list = []
cv_list = []
update_list = []
need_update = 0

path = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})
if path[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')

else:
    try:
        with open(path[0]['Contents']['path'], 'r') as f:
            for line in f:
                if '"name":' in line:
                    result = re.search('name":\s\W.*', line)
                    # demisto.results((result.group(0).split(':')[1]).replace(',',''))
                    pack = (result.group(0).split(':')[1]).replace(',', '').replace('"', '')
                    packs_num.append(pack)
                    pack_list.append(pack)

                if '"currentVersion":' in line:
                    result = re.search('"currentVersion":\s\W.*', line)
                    cv = (result.group(0).split(':')[1]).replace(',', '').replace('"', '')
                    cv_list.append(cv)

                if '"updateAvailable":' in line:
                    result = re.search('"updateAvailable":\W+.*', line)
                    update = (result.group(0).split(':')[1]).replace(',', '').strip()
                    update_list.append(update)

                    if (update == "true"):
                        need_update += 1

        for x, y, z in zip(pack_list, cv_list, update_list):
            packs.append({"packs": x, "currentversion": y, 'updateavailable': z})

        res = None
        if need_update > 0:
            res = [{"category": "Content packs", "severity": "Low", "description": "There are content packs that require an update"}]

        demisto.executeCommand("setIncident", {
            'installedpacks': packs,
            'totalpacksinstalled': len(packs_num),
            'packsneedupdate': need_update
        })

        results = CommandResults(
            readable_output="HealchCheckInstalledPacks Done",
            outputs_prefix="actionableitems",
            outputs=res)

        return_results(results)

    except UnicodeDecodeError:
        demisto.results("Could not read file")
