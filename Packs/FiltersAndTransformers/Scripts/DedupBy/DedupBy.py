import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any, List


def demisto_get(obj: Any, path: Any) -> Any:
    """
    demisto.get(), this supports a syntax of path escaped with backslash.
    """
    def split_context_path(path: str) -> List[str]:
        nodes = []
        node = []
        itr = iter(path)
        for c in itr:
            if c == '\\':
                try:
                    node.append(next(itr))
                except StopIteration:
                    node.append('\\')
            elif c == '.':
                nodes.append(''.join(node))
                node = []
            else:
                node.append(c)
        nodes.append(''.join(node))
        return nodes

    if not isinstance(obj, dict):
        return None

    for part in split_context_path(path):
        if obj and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


class Key(object):
    def __init__(self, value: Any, path: Optional[str] = None) -> None:
        self.__value = value if path is None else demisto_get(value, path)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Key):
            return False
        elif type(self.__value) != type(other.__value):
            return False
        elif isinstance(self.__value, (bool, int, float, str)) or self.__value is None:
            return self.__value == other.__value
        else:
            return json.dumps(self.__value) == json.dumps(other.__value)

    def __hash__(self) -> int:
        if isinstance(self.__value, (bool, int, float, str)) or self.__value is None:
            return hash((type(self.__value), self.__value))
        else:
            return hash((type(self.__value), json.dumps(self.__value)))


def main():
    try:
        args = assign_params(**demisto.args())
        if value := args.get('value', []):
            temp = {}
            if paths := argToList(args.get('keys')):
                for v in value:
                    k = tuple([Key(v, path) for path in paths])
                    if k not in temp:
                        temp[k] = v
            else:
                for v in value:
                    k = Key(v)
                    if k not in temp:
                        temp[k] = v
            value = list(temp.values())

        return_results(value)
    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

