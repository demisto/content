import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Script for Cortex XSOAR (aka Demisto)
This is an empty script with some basic structure according
to the code conventions.
MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"
Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


''' COMMAND FUNCTION '''


''' MAIN FUNCTION '''


def main():

    misp_fields = {'from': 'from', 'from-display-name': 'from_display_name', 'from-domain': 'from_domain',
                   'ip-src': 'ip_src', 'subject': 'subject', 'send-date': 'send_date', 'return-path': 'return_path'}

    try:
        args = dict(demisto.args())
        misp_value = {}

        for k, v in misp_fields.items():
            if v in args.keys():
                misp_value[k] = args[v]

        command_result = CommandResults(
            outputs_prefix='MispEmailAttribute',
            outputs=misp_value
        )

        return_results(command_result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
