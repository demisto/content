"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

import demistomock as demisto
from CommonServerPython import *

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''




''' COMMAND FUNCTION '''


# TODO: REMOVE the following dummy command function
def basescript_dummy_command(args: Dict[str, Any]) -> CommandResults:

    remediation_actions = demisto.get(demisto.context(), 'RemediationActions')
    res = {'Blocked IP Addresses': remediation_actions.get('BlockedIP').get('Addresses'),
           'Inactive Access keys': ','.join(remediation_actions.get('InactiveAccessKeys')),
           'Deleted Login Profiles': remediation_actions.get('DisabledLoginProfile').get('Username')}
    return CommandResults(readable_output=tableToMarkdown('Remediation Actions Information', res, headers=res.keys()))


''' MAIN FUNCTION '''


def main():
    try:
        # TODO: replace the invoked command function with yours
        return_results(basescript_dummy_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute RemediationActionsWidget. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
