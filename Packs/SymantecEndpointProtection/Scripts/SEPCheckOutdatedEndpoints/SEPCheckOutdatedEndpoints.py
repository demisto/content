import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time


def parseSepAvDef(s, res):
    import re
    VERSIONS_REGEX = r'([^ ]*) [^\d]*(\d*)'
    v = -1.0
    d = ''
    try:
        m = re.match(VERSIONS_REGEX, s)
        d = m.group(1)  # type: ignore
        v = float(m.group(2))  # type: ignore
        return d, v
    except Exception as ex:
        res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "Error occurred while parsing AV Def version. "
                                "Exception info:\n" + str(ex) + "\n\nInvalid input:\n" + str(s)})
        demisto.results(res)
        sys.exit()


def check_outdated_endpoints():
    res: list = []
    reqAvDef = demisto.get(demisto.args(), 'requiredavdefversion')
    strReqDate, reqVer = parseSepAvDef(reqAvDef, res)
    reqDate = time.strptime(strReqDate, '%m/%d/%Y')

    resp = demisto.executeCommand('sep-client-content', {})
    if isError(resp[0]):
        demisto.results(resp)
    else:
        data = demisto.get(resp[0], 'Contents.clientDefStatusList')
        outdated = []

        for row in data:
            strRowDate, rowVer = parseSepAvDef(row['version'], res)
            rowDate = time.strptime(strRowDate, '%Y-%m-%d')
            if rowDate < reqDate or rowVer < reqVer:
                outdated.append(row)

        if outdated:
            res.append("yes")
            txtSEPOutdatedVersions = 'Outdated versions found:\n' + \
                '\n'.join(['%d endpoints using version %s' % (row['clientsCount'], row['version']) for row in outdated])
            demisto.setContext('txtSEPOutdatedVersions', txtSEPOutdatedVersions)
            md = tblToMd('Outdated endpoints', outdated)
            res.append({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': md})
        else:
            res.append("no")
            demisto.setContext('txtSEPOutdatedVersions', '')
            res.append({"Type": entryTypes["note"], "ContentsFormat": formats["text"],
                        "Contents": "All endpoints are up to date."})
    demisto.results(res)


def main():  # pragma: no cover
    try:
        check_outdated_endpoints()
    except Exception as e:
        err_msg = f'Encountered an error while running the script: [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
