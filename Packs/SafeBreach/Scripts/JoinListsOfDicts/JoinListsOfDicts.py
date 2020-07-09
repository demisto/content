import demistomock as demisto
from CommonServerPython import *
from itertools import product


def find_value_by_key(k, d):
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


def do_merge(left, right, leftkey, rightkey):

    ret = list()
    for p in product(left, right):
        l, r = p
        #leftkey = "CustomFields.safebreachinsightids"
        lv = find_value_by_key(leftkey, l)  # [13,14]
        rv = find_value_by_key(rightkey, r)

        if not lv or not rv:
            continue
        if not isinstance(lv, list):
            lv = [lv]
        demisto.info("lv: {}, rv: {}".format(lv, str(rv)))
        if str(rv) in lv:
            demisto.info("matched: lv-{} and rv-{}".format(lv, str(rv)))
            ret.append({**l, **r})
    return ret


def merge(args):
    left = args.get('value')
    right = args.get('right')
    leftkey = args.get('key')
    rightkey = args.get('rightkey', leftkey)

    if not left or not right or not leftkey or not rightkey:
        raise ValueError('Invalid inputs')
    return do_merge(left, right, leftkey, rightkey)


def main(args):
    x = merge(args)
    demisto.info("result: {}".format(x))
    demisto.results(x)


if __name__ in ('builtins', '__builtin__'):
    main(demisto.args())
