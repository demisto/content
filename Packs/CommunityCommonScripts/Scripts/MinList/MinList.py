import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def min_value(value):
    if isinstance(value, float):
        return value

    if isinstance(value, str):
        try:
            value = [float(item) for item in value.split(',')]
        except ValueError:
            return 'error', 'error'

    elif isinstance(value, list):
        try:
            value = [float(item) for item in value]
        except ValueError:
            return 'error', 'error'

    result = min(value)
    return result, 'ok'


def main():
    value = demisto.args()['value']
    result, return_type = min_value(value)

    if return_type == 'error':
        return_error('This transformer applies only to list of numbers.')
    demisto.results(result)


# python2 uses __builtin__ python3 uses builtins
if __name__ in ['__builtin__', 'builtins']:
    main()
