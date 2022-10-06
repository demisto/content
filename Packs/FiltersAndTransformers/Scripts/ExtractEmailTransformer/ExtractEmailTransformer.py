import demistomock as demisto
from CommonServerPython import *


def main():
    try:
        return_results(extract(argToList(demisto.args().get('value'))))
    except Exception as error:
        return_error(str(error), error)


def extract(values: list[str]) -> list[str]:
    list_results = []
    for val in values:
        list_results.extend(re.findall(emailRegex, (val or '').lower()))
    return list_results


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
