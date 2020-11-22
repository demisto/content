import demistomock as demisto
from CommonServerPython import *
from itertools import groupby


def find_value_by_key(k, d):
    if not isinstance(d, dict):
        raise Exception("{} d is not a dictionary".format(d))
    if k.startswith('CustomFields.'):
        if 'CustomFields' not in d:
            return
        cf = d.get('CustomFields', None)
        if not cf:
            return
        rk = k.split('.')[1]
    else:
        cf = d
        rk = k

    if rk not in cf:
        return
    return cf[rk]


def group_by(args):
    values = args.get('value')
    keys = argToList(args.get('keys'))
    outputkey = args.get('outputkey')
    separator = args.get('separator')

    if values is None or values == [None]:
        raise Exception("Value parameter is None!")
    if not isinstance(values, list):
        values = [values]

    def getkey(x):
        ok = dict()
        for k in keys:
            ok[k] = find_value_by_key(k, x)
        return json.dumps(ok)

    s = {}
    for k, v in groupby(sorted(values, key=getkey), key=getkey):
        s[k] = separator.join([find_value_by_key(outputkey, e) for e in v])

    ret = []
    for k in s.keys():
        jl = json.loads(k)
        jl['value'] = s[k]
        ret.append(jl)
    return ret


def main(args):
    demisto.results(group_by(args))


if __name__ in ('builtins', '__builtin__'):
    main(demisto.args())
