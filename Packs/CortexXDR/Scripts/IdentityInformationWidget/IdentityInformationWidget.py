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

''' COMMAND FUNCTION '''


# TODO: REMOVE the following dummy command function
def basescript_dummy_command(args: Dict[str, Any]) -> CommandResults:

    alert_event = demisto.get(demisto.context(), 'PaloAltoNetworksXDR.OriginalAlert.event')
    res = {'Name': alert_event.get('identity_name'),
           'Type': alert_event.get('identity_type'),
           'Sub Type': alert_event.get('identity_sub_type'),
           'Uuid': alert_event.get('identity_uuid'),
           'Provider': alert_event.get('cloud_provider'),
           'Access Keys': alert_event.get('userIdentity').get('accessKeyId')}

    return CommandResults(readable_output=tableToMarkdown('Identity Information', res, headers=res.keys()))


''' MAIN FUNCTION '''


def main():
    try:
        # TODO: replace the invoked command function with yours
        return_results(basescript_dummy_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute IdentityInformationWidget. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
