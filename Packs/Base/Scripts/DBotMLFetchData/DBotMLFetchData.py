import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def return_json_entry(obj):
    entry = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": obj,
    }
    demisto.results(entry)


def main():
    return_json_entry({})


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
