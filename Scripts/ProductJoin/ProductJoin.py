import demistomock as demisto
from CommonServerPython import *

from itertools import product


def parse_list(lst):
    lst = lst if isinstance(lst, list) else lst.split(',')
    return map(lambda _: str(_).strip(), lst)  # clean and convert to str for join

def product_join(args):
    sep = args.get('join')
    list1 = parse_list(args.get('value'))
    list2 = parse_list(args.get('list2'))

    ret = []
    for item in product(list1, list2):
        ret.append(sep.join(item))

    return ret


def main(args):
    demisto.results(product_join(args))


if __name__ in ('builtins', '__builtin__'):
    main(demisto.args())
