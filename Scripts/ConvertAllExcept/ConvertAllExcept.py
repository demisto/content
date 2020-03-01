import demistomock as demisto
from CommonServerPython import *


def main(args):
    value = args.get('value')
    convert_to = args.get('convertTo')
    exceptions = argToList(args.get('except'))

    return value if value in exceptions else convert_to


if __name__ in ('builtins', '__builtin__'):
    result = main(demisto.args())
    demisto.results(result)
