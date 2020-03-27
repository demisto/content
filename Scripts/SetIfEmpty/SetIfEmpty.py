<<<<<<< HEAD
=======
from CommonServerPython import *
>>>>>>> upstream/master
import demistomock as demisto
from distutils.util import strtobool


def get_value_to_set(args):
    value = args.get('value')
<<<<<<< HEAD
    apply_if_empty =strtobool(args.get('applyIfEmpty', 'false'))
=======
    apply_if_empty = strtobool(args.get('applyIfEmpty', 'false'))
>>>>>>> upstream/master

    if value is None or (apply_if_empty and is_value_empty(value)):
        value = args.get('defaultValue')

<<<<<<< HEAD
    return value


def is_value_empty(value):
    if hasattr(value, '__iter__') and len(value) == 1:
        value = value[0]

    return value is None or \
           value is "" or \
           (hasattr(value, '__iter__') and len(value) == 0)
=======
    return encode_string_results(value)


def is_value_empty(value):
    if hasattr(value, '__iter__') and len(value) == 1 and not isinstance(value, dict):
        value = value[0]

    value_is_string_null = isinstance(value, basestring) and value.lower() in ["none", "null", ""]  # type: ignore
    return value is None or (hasattr(value, '__iter__') and len(value) == 0) or value_is_string_null
>>>>>>> upstream/master


def main(args):
    demisto.results(get_value_to_set(args))


if __name__ in ('builtins', '__builtin__'):
<<<<<<< HEAD
    main(demisto.args())
=======
    main(demisto.args())
>>>>>>> upstream/master
