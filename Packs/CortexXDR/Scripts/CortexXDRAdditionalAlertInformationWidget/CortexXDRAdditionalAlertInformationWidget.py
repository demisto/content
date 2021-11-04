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


def indicator_to_clickable(indicator):
    res = demisto.executeCommand('GetIndicatorsByQuery', {'query': f'value:{indicator}'})
    if isError(res[0]):
        return_error('Query for get indicators is invalid')
    res_content = res[0].get('Contents')
    if not res_content:
        return_error(f'Indicator {indicator} was not found')
    indicator_id = res_content[0].get('id')
    incident_url = os.path.join('#', 'indicator', indicator_id)
    return f'[{indicator}]({incident_url})'


def get_additonal_info() -> CommandResults:
    alerts = demisto.get(demisto.context(), 'PaloAltoNetworksXDR.OriginalAlert')
    if not alerts:
        raise DemistoException('Original Alert is not configured in context')
    if not isinstance(alerts, list):
        alerts = [alerts]

    results = []
    for alert in alerts:
        alert_event = alert.get('event')
        res = {'Alert Full Description': alert.get('alert_full_description'),
               'Detection Module': alert.get('detection_modules'),
               'Vendor': alert_event.get('vendor'),
               'Provider': alert_event.get('cloud_provider'),
               'Log Name': alert_event.get('log_name'),
               'Event Type': alert_event.get('raw_log').get('eventType'),
               'Caller IP': indicator_to_clickable(alert_event.get('caller_ip')),
               'Caller IP Geo Location': alert_event.get('caller_ip_geolocation'),
               'Resource Type': alert_event.get('resource_type'),
               'Identity Name': alert_event.get('identity_name'),
               'Operation Name': alert_event.get('operation_name'),
               'Operation Status': alert_event.get('operation_status'),
               'User Agent': alert_event.get('user_agent')}
        results.append(res)

    return CommandResults(readable_output=tableToMarkdown('Original Alert Additional Information', results,
                                                          headers=list(results[0].keys()) if results else None))


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
