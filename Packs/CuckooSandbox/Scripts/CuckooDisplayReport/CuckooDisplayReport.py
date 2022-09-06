import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    # ALL_SECTIONS = ["info","statistics","network","dropped","suricata","debug","procmemory","signatures","decompression",
    # "malfamily","behavior","target","malscore","static","feeds","strings","virustotal"]
    res = []
    if 'reportentryid' not in demisto.args() and 'reportfilepath' not in demisto.args() and 'reportdata' not in demisto.args():
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                        "Contents": 'You must provide reportdata, reportentryid or reportfilepath. '})
        sys.exit()
    showAllSections = False
    BASIC_SECTIONS = ["info", "target", "signatures", "malscore", "strings", "static"]
    showSections = demisto.get(demisto.args(), 'sections')
    if showSections and showSections.lower() != 'all':
        showSections = argToList(showSections) if showSections else BASIC_SECTIONS
    else:
        showAllSections = True
    try:
        report = None
        if 'reportdata' in demisto.args():
            report = json.loads(demisto.args()['reportdata'])
        else:
            try:
                if 'reportfilepath' in demisto.args():
                    filePath = demisto.args()['reportfilepath']
                else:
                    filePath = demisto.executeCommand('getFilePath',
                                                      {'id': demisto.args()['reportentryid']})[0]['Contents']['path']
                with open(filePath, 'rb') as jsonFile:
                    report = json.load(jsonFile)
            except Exception:
                entry = demisto.executeCommand('getEntry', {'id': demisto.args()['reportentryid']})[0]
                if isError(entry):
                    demisto.results(entry)
                    sys.exit()
                else:
                    report = entry['Contents']

    except Exception as ex:
        res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "Error occurred while loading report. Exception info:\n" + str(ex)})

    if not report:
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                        "Contents": 'Failed to load report JSON from the provided source argument.'})
        sys.exit()

    if showAllSections:
        showSections = list(report.keys())
    for s in showSections:
        try:
            if s not in report:
                res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                           "Contents": 'Requested section ' + s + ' missing from report.'})
                continue

            if s == 'info':
                t = report['info']
                info_data = {k: formatCell(t[k]) for k in t}
                res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": info_data})
            elif s == 'signatures':
                t = report['signatures']
                signatures_data = [{k: formatCell(row[k]) for k in row} for row in t]
                res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": signatures_data})
            elif s == 'malscore':
                res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"],
                           "Contents": {'Malscore': report['malscore']}})
            elif s == 'strings':
                strings = demisto.get(report, 'strings')
                if strings:
                    strings_data = [{'Strings': s} for s in strings]
                    res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": strings_data})
            elif s == 'debug':
                t = demisto.get(report, 'debug')
                if t:
                    for part in ['errors', 'log']:
                        if part in t and t[part]:
                            debug_data = [{part: s} for s in t[part]]
                            res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": debug_data})
            elif s == 'screenshots':
                t = demisto.get(report, 'screenshots')
                if t:
                    screenshots_data = [{'screenshots': s} for s in t]
                    res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": screenshots_data})

            elif s == 'statistics':
                t = demisto.get(report, 'statistics')
                if t and isinstance(t, list):
                    for subtable in t:
                        if t[subtable]:
                            data = [{k: formatCell(row[k]) for k in row} for row in t[subtable]]
                            res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": data})
            elif s == 'behavior':
                t = demisto.get(report, 'behavior')
                if t and isinstance(t, list):
                    for subtable in t:
                        if t[subtable]:
                            behavior_data = [{k: formatCell(row[k]) for k in row} for row in t[subtable]]
                            res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"],
                                        "Contents": behavior_data})
            else:
                data = report[s] if isinstance(report[s], list) else [report[s]]
                data = [{k: formatCell(row[k]) for k in row} for row in data]
                res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": data})
                # res.append({"Type": entryTypes["note"], "ContentsFormat": formats["json"], "Contents": report[s]})
        except Exception as ex:
            res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                        "Contents": "Error occurred while parsing section " + s + " from report. Exception info:\n" + str(ex)})
    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
