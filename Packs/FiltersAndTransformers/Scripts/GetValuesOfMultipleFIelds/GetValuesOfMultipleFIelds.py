import demistomock as demisto

from typing import List, Dict


def update_list(_list: List, update_with):
    if isinstance(update_with, list):
        _list.extend(update_with)
    else:
        _list.append(update_with)


def main():
    args: Dict = demisto.args()
    root = args.get('key')
    if root:
        if not isinstance(root, list):
            root = [root]
        keys: List = args.get('list', '').split(',')

        t: List = []
        for obj in root:
            for _key in keys:
                temp = obj.get(_key) if obj else None
                if temp:
                    update_list(t, temp)

        initial_value = args.get('value')
        if initial_value:
            update_list(t, initial_value)
        demisto.results(t)


if __name__ in ('builtins', '__builtin__'):
    main()
