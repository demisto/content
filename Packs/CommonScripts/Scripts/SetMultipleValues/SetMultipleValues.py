import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    keys = [k.strip() for k in demisto.args()['keys'].split(',')]
    values = [v.strip() for v in demisto.args()['values'].split(',')]
    ec = {demisto.args()['parent'] + '(true)': dict(zip(keys, values))}
    demisto.results({'Type': entryTypes['note'], 'Contents': ec, 'ContentsFormat': formats['json'],
                     'HumanReadable': 'Keys ' + ','.join(keys) + ' set', 'EntryContext': ec})


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
