import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections import Counter


def count_dict(value):
    if not isinstance(value, str):
        return value
    categories = value.split(',')
    return [{'category': key, 'count': value} for key, value in dict(Counter(categories)).items()]


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(count_dict(**demisto.args()))
