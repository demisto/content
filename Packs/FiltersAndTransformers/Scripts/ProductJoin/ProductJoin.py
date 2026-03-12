from itertools import product

import demistomock as demisto


def parse_list(lst):
    if isinstance(lst, list):  # handle list
        if len(lst) == 1:
            lst = str(lst[0]).split(",")
    else:
        lst = str(lst).split(",")

    return map(lambda _: str(_).strip(), lst)  # noqa: C417  # clean and convert to str for join


def product_join(args):
    sep = args.get("join")
    list1 = parse_list(args.get("value"))
    list2 = parse_list(args.get("list2"))

    ret = []
    for item in product(list1, list2):
        ret.append(sep.join(item))

    return ret


def main(args):
    demisto.results(product_join(args))


if __name__ in ("builtins", "__builtin__"):
    main(demisto.args())
