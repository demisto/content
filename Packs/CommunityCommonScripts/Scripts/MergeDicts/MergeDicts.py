import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *


def main():
    try:
        dict1 = demisto.args().get('value')
        dict2 = demisto.args().get('dictionary')

        if isinstance(dict1, str):
            dict1 = json.loads(dict1, strict=False)
        if isinstance(dict2, str):
            dict2 = json.loads(dict2, strict=False)

        if isinstance(dict1, dict) and isinstance(dict2, dict):
            if argToBoolean(demisto.args().get('overwrite', 'false')):
                result = {**dict1, **dict2}
            else:
                result = {**dict2, **dict1}
        else:
            result = dict1

        entry = {'Type': entryTypes['note'],
                 'ContentsFormat': formats['json'],
                 'Contents': result,
                 'HumanReadable': tableToMarkdown("Merged Dicts", result, headers=list(result.keys())),
                 'ReadableContentsFormat': formats['markdown'],
                 'EntryContext': {"MergedDicts": result}
                 }

        return_results(entry)

    except Exception as ex:
        return_error(f'Failed to execute MergeDicts. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
