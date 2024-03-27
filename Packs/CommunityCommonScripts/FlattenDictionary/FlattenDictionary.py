import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
from collections.abc import MutableMapping

def flatten_dict(d, parent_key='', sep='.') -> dict:
    """Uses recursion to flatten a nested dictionary.

    Args:
        d (dict): The dictionary object to be flattened.
        parent_key (str, optional): The parent of the key currently being processed. Defaults to ''.
        sep (str, optional): The delimiter for the flattened keys. Defaults to '.'.

    Returns:
        dict: a flattened dictionary.
    """
    
    items = []
    for k, v in d.items():
        n_key = parent_key + sep + k if parent_key else k
        if isinstance(v, MutableMapping):
            items.extend(flatten_dict(v, n_key, sep).items())
        else:
            items.append((n_key, v))
        
    return dict(items)
            
''' MAIN FUNCTION '''


def main():
    try:
        data = json.loads(demisto.args()["unflatten_dict"])
        return_results(flatten_dict(data))
    except Exception as ex:

        return_error(f'Failed to execute FlattenDictionary. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
