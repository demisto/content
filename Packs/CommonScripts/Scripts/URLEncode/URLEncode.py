import demistomock as demisto
from CommonServerPython import *
from urllib.parse import quote, unquote

''' MAIN FUNCTION '''


def main(args):
    value = args.get('value')
    decoded_value = unquote(value)
    return quote(decoded_value)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main(demisto.args()))
    except Exception as exc:
        return_error(str(exc), error=exc)
