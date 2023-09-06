import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, List, Union


def demisto_get(obj: Any, path: Any) -> Any:
    """
    This is an extended function of demisto.get().
    The `path` argument parameter supports a syntax of path escaped with backslash
    in order to support a key including period characters.

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
        :return: The keys whose escape characters are removed.
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


class Key(object):
    """
    The custom key object class, which enables you to compare any types of data even in different types.
    This can be used for keys of dict.
    """
    def __init__(self, value: Any, path: Optional[str] = None) -> None:
        """
        Initialize the key.

        :param value: The value to set key, or the node from which to get the value if the `path` is given.
        :param path: The path to get values in the node.
        """
        self.__value = value if path is None else demisto_get(value, path)

    def __eq__(self, other: Any) -> bool:
        def __equals(obj1: Any, obj2: Any) -> bool:
            if type(obj1) != type(obj2):  # noqa: E721
                return False
            elif isinstance(obj1, dict):
                for k1, v1 in obj1.items():
                    if k1 not in obj2:
                        return False
                    if not __equals(v1, obj2[k1]):
                        return False
                return not (set(obj1.keys()) ^ set(obj2.keys()))
            elif isinstance(obj1, list):
                if len(obj1) != len(obj2):
                    return False
                return all(__equals(e1, e2) for e1, e2 in zip(obj1, obj2))
            else:
                return obj1 == obj2

        if not isinstance(other, Key):
            return False
        return __equals(self.__value, other.__value)

    def __hash__(self) -> int:
        def __get_hash_base(value: Any) -> Any:
            if value is None or isinstance(value, (bool, int, float, str)):
                return value
            elif isinstance(value, dict):
                return tuple((k, __get_hash_base(value[k])) for k in sorted(value.keys()))
            elif isinstance(value, list):
                return tuple(__get_hash_base(v) for v in value)
            else:
                return value

        v = __get_hash_base(self.__value)
        return hash((type(v), v))


def main():
    try:
        args = assign_params(**demisto.args())
        if value := args.get('value', []):
            temp = {}
            if paths := argToList(args.get('keys')):
                for v in value:
                    k: Union[tuple, Key] = tuple(Key(v, path) for path in paths)
                    if k not in temp:
                        temp[k] = v
            else:
                for v in value:
                    k = Key(v)  # noqa: F812
                    if k not in temp:
                        temp[k] = v
            value = list(temp.values())

        return_results(value)
    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
