import demistomock as demisto
from itertools import product


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


def do_merge(left, right, leftkey, rightkey):
    if not isinstance(left, list):
        left = [left]
    if not isinstance(right, list):
        right = [right]
    ret = list()
    for p in product(left, right):
        l, r = p

        lv = find_value_by_key(leftkey, l)
        rv = find_value_by_key(rightkey, r)

        if not lv or not rv:
            continue
        if not isinstance(lv, list):
            lv = [lv]
        if str(rv) in lv:
            ret.append({**l, **r})
    return ret


def merge(args):
    left = args.get('value')  # left list of dicts / single dict
    right = args.get('right')  # right list of dicts / single dict
    leftkey = args.get('key')  # key of the join from the left dict
    rightkey = args.get('rightkey', leftkey)  # key of the join from the right dict

    return do_merge(left, right, leftkey, rightkey)


def main(args):
    x = merge(args)
    demisto.results(x)


if __name__ in ('builtins', '__builtin__'):
    main(demisto.args())
