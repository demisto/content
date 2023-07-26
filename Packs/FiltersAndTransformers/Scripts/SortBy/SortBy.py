import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from collections import OrderedDict
from typing import Any, List, Tuple


def demisto_get(obj: Any, path: Any) -> Any:
    r"""
    This is an extended function of demisto.get().
    The `path` argument parameter supports a syntax of path escaped with backslash
    in order to support a key icluding period charactors.

    e.g.
       xxx
        + x.y.z
         + zzz

       -> path: xxx.x\.y\.z.zzz

    :param obj: The root node.
    :param path: The path to get values in the node.
    :return: The value(s) specified with `path` in the node.
    """
    def split_context_path(path: str) -> List[str]:
        """
        Get keys in order from the path which supports a syntax of path escaped with backslash.

        :param path: The path.
        :return: The keys whose escape charactors are removed.
        """
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


class Key:
    """
    This is a class to provide you a key from an any types of values to sort it.
    That allows you to sort values even if them have different types of values.
    The key given by Key.get() can be used for list.sort().
    """
    def __init__(self, value: Any, path: Optional[str]) -> None:
        """
        Initialize the key.

        :param value: The value to set key, or the node from which to get the value if the `path` is given.
        :param path: The path to get values in the node.
        """
        self.__value = value if path is None else demisto_get(value, path)

    def __get_type_order(self) -> int:
        if self.__value is None:
            return 0
        elif isinstance(self.__value, bool):
            return 1
        elif isinstance(self.__value, (int, float)):
            return 2
        elif isinstance(self.__value, str):
            return 3
        else:
            return 4

    def __get_key(self) -> Any:
        def __get(value: Any) -> Any:
            if value is None:
                return 0
            elif isinstance(value, (bool, int, float, str)):
                return value
            elif isinstance(value, dict):
                return OrderedDict((k, __get(value[k])) for k in sorted(value.keys()))
            elif isinstance(value, list):
                return [__get(v) for v in value]
            else:
                return value

        v = __get(self.__value)
        if v is None or isinstance(v, (bool, int, float, str)):
            return v
        else:
            return json.dumps(v)

    def get(self) -> Tuple[int, Any]:
        """
        Get the key from the value.

        :return: The key which can be used for list.sort().
        """
        return self.__get_type_order(), self.__get_key()


def main():
    try:
        args = assign_params(**demisto.args())
        if value := args.get('value', []):
            descending_keys = argToList(args.get('descending_keys'))
            if paths := argToList(args.get('keys')):
                for path in reversed(paths):
                    value.sort(key=lambda x: Key(x, path).get(),
                               reverse=path in descending_keys)
            else:
                descending = len(descending_keys) == 1 and descending_keys[0] == '*'
                value.sort(key=lambda x: Key(x, None).get(), reverse=descending)

        return_results(value)
    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
