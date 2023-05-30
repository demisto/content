import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from urllib.parse import unquote


def main():
    value = demisto.args()["value"]
    processed_value = unquote(value)

    eContext = {
        'DecodedURL': processed_value
    }

    entry = {'Type': entryTypes['note'],
             'Contents': eContext,
             'ContentsFormat': formats['json'],
             'HumanReadable': processed_value,
             'ReadableContentsFormat': formats['markdown'],
             'EntryContext': eContext}

    demisto.results(entry)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
