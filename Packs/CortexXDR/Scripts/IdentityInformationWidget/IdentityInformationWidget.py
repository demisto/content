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
from itertools import chain

''' COMMAND FUNCTION '''


def get_identity_info() -> CommandResults:
    context = demisto.context()
    alerts = demisto.get(context, 'PaloAltoNetworksXDR.OriginalAlert')
    users = demisto.get(context, 'AWS.IAM.Users')
    if not isinstance(alerts, list):
        alerts = [alerts]
    results = []
    for alert in alerts:
        alert_event = alert.get('event')
        username = alert_event.get('identity_orig').get('userName')
        access_keys = chain(*[user.get('AccessKeys', {}) for user in users])
        access_keys = [access_key.get('AccessKeyId') for access_key in access_keys if
                       access_key.get('UserName') == username]
        res = {'Name': alert_event.get('identity_name'),
               'Type': alert_event.get('identity_type'),
               'Sub Type': alert_event.get('identity_sub_type'),
               'Uuid': alert_event.get('identity_uuid'),
               'Provider': alert_event.get('cloud_provider'),
               'Access Keys': access_keys}
        if res not in results:
            results.append(res)
    return CommandResults(
        readable_output=tableToMarkdown('Identity Information', results,
                                        headers=list(results[0].keys()) if results else None))


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_identity_info())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute IdentityInformationWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
