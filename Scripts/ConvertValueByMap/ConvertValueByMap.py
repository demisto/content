import demistomock as demisto
from CommonServerPython import *
import json


def convert_value(arg_value, arg_map, arg_default):
    try:
        arg_map = json.loads(arg_map)
    except ValueError:
        demisto.error(f'Failed to parse "map" argument as JSON.\nInvalid JSON: {arg_map}')
        raise ValueError('Failed to parse "map" argument as JSON.')

    if str(arg_value) in arg_map:
        return arg_map[str(arg_value)]
    elif arg_default:
        return arg_default
    else:
        # return the original value
        return arg_value


def main():
    arg_value = demisto.args().get('value')
    arg_map = demisto.args().get('map')
    arg_default = demisto.args().get('default')

    result = convert_value(arg_value, arg_map, arg_default)
    demisto.results(result)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
