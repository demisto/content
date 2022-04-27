import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback


def main():
    try:
        args = demisto.args()
        tir_id = args.get('id')
        if not tir_id:
            return_results(CommandResults(outputs={"tirexist": "false"}, outputs_prefix="SearchTIR"))
        else:
            response = execute_command('getThreatIntelReport', {"id": tir_id})
            if 'Failed to execute' in response:
                return_results(CommandResults(outputs={"tirexist": "false"}, outputs_prefix="SearchTIR"))
            else:
                return_results(CommandResults(outputs={"tirexist": "true"}, outputs_prefix="SearchTIR"))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
