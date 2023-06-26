import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


# ssh command to run, json format, param = query to execute
COMMAND = 'osqueryi --json "{0}"'


def main():
    systems = argToList(demisto.args().get('system'))
    query = demisto.args().get('query')

    res = []
    error_res = []

    if query and systems:
        for system in systems:
            temp_res = demisto.executeCommand("RemoteExec", {'cmd': COMMAND.format(str(query)), 'system': system})
            if isError(temp_res[0]):
                temp_res_contents = temp_res[0]['Contents']
                error_res += [{"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                               "Contents": f'An Error occurred on remote system:\"{system}\". Error={temp_res_contents}.'}]
            else:
                data = json.loads(temp_res[0]['Contents'])
                res += [{'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'],
                        "Contents": tblToMd("{0} results:".format(system), data)}]

    demisto.results(res + error_res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
