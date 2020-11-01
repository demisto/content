from CommonServerPython import *


def sum_value(value):
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

    result = sum(value)
    return result, 'ok'


def main():
    value = demisto.args()['value']
    result, return_type = sum_value(value)

    if return_type == 'error':
        return_error('This transformer applies only to list of numbers.')
    demisto.results(result)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
