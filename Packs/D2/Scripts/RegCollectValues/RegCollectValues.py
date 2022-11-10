import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def Reg2Markdown(baseKey, regResp):
    res, mdRows = [], ''
    if isError(regResp[0]):
        res += regResp
    elif len(regResp) > 1:
        contents = 'Unexpected output from D2RegQuery - more than one entry returned:\n' + '\n'.join([str(x) for x in regResp])
        res.append({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                   'Contents': contents})
    else:
        subkeys = regResp[0]['Contents']
        for sk in subkeys:
            if type(subkeys[sk]) == dict:
                for ssk in subkeys[sk]:
                    mdRows += '\n|' + str(baseKey) + '\\' + str(sk) + '|' + str(ssk) + '|' + str(subkeys[sk][ssk]) + '|'
            else:
                mdRows += '\n|' + str(baseKey) + '|' + str(sk) + '|' + str(subkeys[sk]) + '|'
    return (res, mdRows)


# Note: Don't use !d2_status as that only shows systems with generated agents - the correct way is below:
res = []
regPath = NormalizeRegistryPath(demisto.args()['regpath'])
for system in demisto.investigation()['systems']:
    if system['os'] == 'windows':
        mdTable = '### Values retrieved from system *' + system['name'] + '*'
        mdTable += '\n|Key|SubKey|Value|'
        mdTable += '\n|-----|------|-----|'
        cmdResp = demisto.executeCommand('D2RegQuery', {'using': system['name'], 'regpath': regPath})
        moreEntries, moreRows = Reg2Markdown(regPath, cmdResp)
        mdTable += moreRows
        res += moreEntries
        res.append({'Type': entryTypes['note'], 'ContentsFormat': formats['markdown'], 'Contents': mdTable})
demisto.results(res)
