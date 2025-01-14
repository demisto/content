import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections import Counter


def count_dict(value):
    """
    Count the number of occurrences of each category in the given string.
    :param value: The string containing the categories separated by commas.
    :return: A list of dictionaries containing the category and the number of occurrences.
    """
    if not isinstance(value, str):
        return value
    demisto.debug(f'Counting categories in string: {value}')
    categories = value.split(',')
    return [{'category': key, 'count': value} for key, value in dict(Counter(categories)).items()]


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(count_dict(**demisto.args()))
