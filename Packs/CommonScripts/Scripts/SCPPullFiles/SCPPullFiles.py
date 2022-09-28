import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def scp_pull_files(args):
    res = []  # type: ignore
    s2f = demisto.get(args, 'systems2files')
    if s2f:
        s2f = json.loads(s2f)
        if not isinstance(s2f, dict):
            res = {"Type": entryTypes["error"], "ContentsFormat": formats["text"],  # type: ignore
                   "Contents": "Wrong argument provided. Not a dict. Dump of args: " + json.dumps(
                       args, indent=4)}
        else:
            for k in s2f:
                res += demisto.executeCommand("copy-from", {'using': k, 'file': s2f[k]})
                demisto.info('Copying file ' + s2f[k] + ' from device ' + k)
    return res


def main():
    args = demisto.args()
    demisto.results(scp_pull_files(args))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
