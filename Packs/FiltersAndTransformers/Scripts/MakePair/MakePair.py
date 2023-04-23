import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from itertools import zip_longest
from typing import Any, List, Dict, Optional


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
    elif method == 'array1<2':
        if isinstance(element1, dict):
            if isinstance(element2, dict):
                return dict(element1, **element2)
            else:
                return dict(element1, **{output_name2: element2})
    elif method == 'array2<1':
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

        array2 = args.get('array2', [])
        if array2_key := args.get('array2_key'):
            array2 = [demisto_get(x, array2_key) for x in array2]

        different_sized = args.get('different_sized', 'shorter')

        if different_sized == 'array1':
            diff = len(array1) - len(array2)
            if diff > 0:
                array2 += [None] * diff
            different_sized = 'shorter'
        elif different_sized == 'array2':
            diff = len(array2) - len(array1)
            if diff > 0:
                array1 += [None] * diff
            different_sized = 'shorter'

        output_name1 = args.get('output_name1')
        output_name2 = args.get('output_name2')
        merge_dict = args.get('merge_dict')
        if different_sized == 'shorter':
            value = [make_dict(e1, e2, output_name1, output_name2, merge_dict) for e1, e2 in zip(array1, array2)]
        elif different_sized == 'longer':
            value = [make_dict(e1, e2, output_name1, output_name2, merge_dict) for e1, e2 in zip_longest(array1, array2)]
        else:
            raise DemistoException(f'Invalid parameter was given to "different_sized" - {different_sized}')

        return_results(value)
    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
