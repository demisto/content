import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def main(args):
    demisto.results(getValueToSet(args))

def getValueToSet(args):
    value = args.get('value')
    applyIfEmpty = True if args.get('applyIfEmpty', '').lower() == 'true' else False

    if value is None or (applyIfEmpty and len(value) < 1):
        value = args.get('defaultValue')

    return value


if __name__ in ('builtins', '__builtin__'):
    main(demisto.args())