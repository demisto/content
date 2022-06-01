import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def count_dict(value):
    if not isinstance(value, str):
        return value
    categories = value.split(',')
    count_d = {
        'initialaccess': 0,
        'execution': 0,
        'persistence': 0,
        'privilegeescalation': 0,
        'defenseevasion': 0,
        'credentialaccess': 0,
        'discovery': 0,
        'lateralmovement': 0,
        'collection': 0,
        'commandandcontrol': 0,
        'exfiltration': 0,
        'other': 0
    }

    for category in categories:
        category = category.lower()
        category = category if category in count_d.keys() else 'other'
        count_d[category] += 1

    return count_d


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(count_dict(**demisto.args()))
