import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def count_dict(value):
    if not isinstance(value, str):
        return value
    users = value.split(',')

    return [{'User': user for user in users}]


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(count_dict(**demisto.args()))
