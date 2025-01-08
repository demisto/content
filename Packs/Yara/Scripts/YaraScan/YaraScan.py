import demistomock as demisto
from CommonServerPython import *
# The script uses the Python yara library to scan a file or files
''' IMPORTS '''
import yara

''' GLOBAL VARIABLES '''

yaraLogo = "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"  # noqa


def main():

    entries = list()
    args = demisto.args()
    entryIDs = argToList(args.get('entryIDs'))

    fileInfos = list()
    for item in entryIDs:
        res = demisto.executeCommand("getFilePath", {"id": item})
        if is_error(res):
            return_error(get_error(res))
        if type(res[0]['Contents']) is dict:
            fileInfo = {
                "name": res[0]['Contents']['name'],
                "id": res[0]['Contents']['ID'],
                "path": res[0]['Contents']['path'],
                "entryID": item
            }
            fileInfos.append(fileInfo)
    if len(fileInfos) < 1:
        return_error('No files were found for scanning, please check the entry IDs')

    yaraRuleRaw = args.get('yaraRule')

    for fileInfo in fileInfos:
        with open(fileInfo['path'], 'rb') as fp:
            thisMatch = {
                "Filename": fileInfo['name'],
                "entryID": fileInfo['entryID'],
                "fileID": fileInfo['id'],
                "HasMatch": False,
                "HasError": False,
                "MatchCount": 0,
                "Matches": list(),
                "Errors": list()
            }
            try:
                cRule = yara.compile(source=yaraRuleRaw)
            except Exception as err:
                thisMatch['HasError'] = True
                thisMatch['Errors'].append(str(err))
                entries.append(thisMatch)
                continue
            try:
                matches = cRule.match(data=fp.read())
            except Exception as err:
                thisMatch['HasError'] = True
                thisMatch['Errors'].append(str(err))
                entries.append(thisMatch)
                continue

            if len(matches) > 0:
                thisMatch['HasMatch'] = True
            else:
                thisMatch['HasMatch'] = False
            for match in matches:
                matchData = dict()
                matchData['RuleName'] = match.rule
                matchData['Meta'] = match.meta
                matchData['Strings'] = str(match.strings)
                matchData['Tags'] = match.tags
                matchData['Namespace'] = match.namespace
                thisMatch['Matches'].append(matchData)
                thisMatch['MatchCount'] += 1
            entries.append(thisMatch)

    md = "![](data:image/png;base64,{})\n\n{}".format(
        yaraLogo,
        tableToMarkdown('Yara Scan Results:', entries, ['Filename', 'entryID', 'HasMatch', 'HasError', 'MatchCount', 'Matches']))
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': entries,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {'Yara(val.entryID && val.entryID==obj.entryID)': entries}
    })


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
