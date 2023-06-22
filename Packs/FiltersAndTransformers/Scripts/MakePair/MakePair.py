import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from itertools import zip_longest
from typing import Any, List, Dict, Optional


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


def make_dict(element1: Any,
              element2: Any,
              output_name1: str,
              output_name2: str,
              method: Optional[str]) -> Dict[str, Any]:
    if method == 'array1':
        if isinstance(element1, dict):
            return dict(element1, **{output_name2: element2})
    elif method == 'array2':
        if isinstance(element2, dict):
            return dict(element2, **{output_name1: element1})
    elif method == 'array1<array2':
        if isinstance(element1, dict):
            if isinstance(element2, dict):
                return dict(element1, **element2)
            else:
                return dict(element1, **{output_name2: element2})
    elif method == 'array2<array1':
        if isinstance(element1, dict):
            if isinstance(element2, dict):
                return dict(element2, **element1)
            else:
                return dict(element2, **{output_name1: element1})
    elif method is not None:
        raise DemistoException(f'Invalid parameter was given to "merge_dict" - {method}')

    return {output_name1: element1, output_name2: element2}


def main():
    try:
        args = assign_params(**demisto.args())
        array1 = args.get('value', [])
        if array1_key := args.get('array1_key'):
            array1 = [demisto_get(x, array1_key) for x in array1]

        if not isinstance(array1, list):
            array1 = [array1]

        array2 = args.get('array2', [])
        if array2_key := args.get('array2_key'):
            array2 = [demisto_get(x, array2_key) for x in array2]

        if not isinstance(array2, list):
            array2 = [array2]

        determine_output_length_by = args.get('determine_output_length_by', 'shorter')
        if determine_output_length_by == 'array1':
            diff = len(array1) - len(array2)
            if diff > 0:
                array2 += [None] * diff
            determine_output_length_by = 'shorter'
        elif determine_output_length_by == 'array2':
            diff = len(array2) - len(array1)
            if diff > 0:
                array1 += [None] * diff
            determine_output_length_by = 'shorter'

        output_name1 = args.get('output_name1')
        output_name2 = args.get('output_name2')
        merge_dict = args.get('merge_dict')
        if determine_output_length_by == 'shorter':
            value = [make_dict(e1, e2, output_name1, output_name2, merge_dict) for e1, e2 in zip(array1, array2)]
        elif determine_output_length_by == 'longer':
            value = [make_dict(e1, e2, output_name1, output_name2, merge_dict) for e1, e2 in zip_longest(array1, array2)]
        else:
            raise DemistoException(f'Invalid parameter was given to "determine_output_length_by" - {determine_output_length_by}')

        return_results(value)
    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
