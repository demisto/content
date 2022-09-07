import subprocess

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    ret = []
    sysargs = None

    cmdarg = demisto.args()['cmd']
    if 'sysargs' in demisto.args():
        sysargs = demisto.args()['sysargs']

    if sysargs is None:
        output = None
        try:
            output = subprocess.check_output(cmdarg, shell=True)
        except subprocess.CalledProcessError as e:
            output = e.output
        ret.append(output)
    else:
        ret.append(subprocess.check_output([cmdarg, sysargs]))

    ret = [r.decode() for r in ret]     # type:ignore[union-attr]
    ec = {'Command': cmdarg, 'Results': ret[0]}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ret,
        'HumanReadable': ret[0],
        'EntryContext': {'CommandResults': ec}
    })
    sys.exit(0)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
