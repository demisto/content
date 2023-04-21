
from CommonServerPython import *  # noqa
import demistomock as demisto


def main(args):
    value = args.get('value')
    json_value = [value]
    return json.dumps(json_value)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main(demisto.args()))
    except Exception as exc:
        return_error(str(exc), error=exc)
