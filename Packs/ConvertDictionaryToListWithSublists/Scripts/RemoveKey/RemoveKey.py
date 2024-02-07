import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any


def main():

    dict_list = demisto.args().get('ListData')

    list_of_lists = [list(d.values()) for d in dict_list]

    return_results(CommandResults(
        outputs_prefix='Entry',
        readable_output="Successfully Create a list under Entry",
        outputs=list_of_lists))


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
