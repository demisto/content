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

import traceback


''' COMMAND FUNCTION '''


# TODO: REMOVE the following dummy command function
def get_additonal_info() -> CommandResults:
    alert = demisto.get(demisto.context(), 'PaloAltoNetworksXDR.OriginalAlert')
    res = {'Alert Full Description': alert.get('alert_full_description'),
           'Detection Module': alert.get('detection_modules'),
           'Vendor': alert.get('event').get('vendor'),
           'Provider': alert.get('event').get('cloud_provider'),
           'Log Name': alert.get('event').get('log_name'),
           'Event Type': alert.get('event').get('event_type'),
           'Caller IP': alert.get('event').get('caller_ip'),
           'Caller IP Geo Location': alert.get('event').get('caller_ip_geolocation'),
           'Resource Type': alert.get('event').get('resource_type'),
           'Identity Name': alert.get('event').get('identity_name'),
           'Operation Name': alert.get('event').get('operation_name'),
           'Operation Status': alert.get('event').get('operation_status'),
           'User Agent': alert.get('event').get('user_agent')}
    
    return CommandResults(readable_output=tableToMarkdown('Original Alert Additional Information', res, headers=res.keys()))


# TODO: ADD additional command functions that translate XSOAR inputs/outputs

''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_additonal_info())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute AdditionalAlertInformationWidget. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
