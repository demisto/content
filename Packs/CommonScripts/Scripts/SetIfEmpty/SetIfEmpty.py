from CommonServerPython import *
import demistomock as demisto
from distutils.util import strtobool


def get_value_to_set(args):
    value = args.get('value')
    apply_if_empty = strtobool(args.get('applyIfEmpty', 'false'))

    if value is None or (apply_if_empty and is_value_empty(value)):
        value = args.get('defaultValue')

    if isinstance(value, list):
        for i, item in enumerate(value):
            value[i] = encode_string_results(item)

        return value
    else:
        return encode_string_results(value)


def is_value_empty(value):
    if hasattr(value, '__iter__') and len(value) == 1 and not isinstance(value, dict):
        value = value[0]

    value_is_string_null = isinstance(value, str) and value.lower() in ["none", "null", ""]  # type: ignore
    return value is None or (hasattr(value, '__iter__') and len(value) == 0) or value_is_string_null


def main(args):
    demisto.results(get_value_to_set(args))


if __name__ in ('builtins', '__builtin__'):
    main(demisto.args())
