import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict


def main():

    try:
        args: Dict = demisto.args()
        root = args.get('key', [])

        for i in root:
            if isinstance(root[i], str) or isinstance(root[i], int):
                root[i] = [root[i]]

        max_len = max([len(root[i]) for i in root])

        for i in root:
            if len(root[i]) < max_len:
                root[i] = root[i] + list([" "] * (max_len - len(root[i])))

        t = [dict(zip(root, i)) for i in zip(*root.values())]
        for arg in t:
            for key, val in arg.items():
                if isinstance(val, str):
                    arg[key] = val.strip()

        [remove_nulls_from_dictionary(i) for i in t]
        demisto.results(t)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not convert\n{e}')


if __name__ in ('builtins', '__builtin__'):
    main()
