import demistomock as demisto
from CommonServerPython import *


def main():
    try:
        list_results = []
        for val in argToList(demisto.args().get('value')):
            list_results.extend(list(re.findall(emailRegex, val)))
        return_results(list_results)
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
