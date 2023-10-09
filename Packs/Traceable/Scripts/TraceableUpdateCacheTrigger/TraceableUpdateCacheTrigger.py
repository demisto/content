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
from CommonServerUserPython import *
import json


''' COMMAND FUNCTION '''


def get_additonal_info() -> List[dict]:
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
               'Event Type': demisto.get(alert_event, 'raw_log.eventType'),
               'Caller IP': alert_event.get('caller_ip'),
               'Caller IP Geo Location': alert_event.get('caller_ip_geolocation'),
               'Resource Type': alert_event.get('resource_type'),
               'Identity Name': alert_event.get('identity_name'),
               'Operation Name': alert_event.get('operation_name'),
               'Operation Status': alert_event.get('operation_status'),
               'User Agent': alert_event.get('user_agent')}
        results.append(res)
    indicators = [res.get('Caller IP') for res in results]
    indicators_callable = indicators_value_to_clickable(indicators)
    for res in results:
        res['Caller IP'] = indicators_callable.get(res.get('Caller IP'))
    return results


''' MAIN FUNCTION '''


def main():
    try:
        inc = demisto.incidents()[0]
        commands = [CommandRunner.Command('update_incident_cache', {'incident': json.dumps(inc)})
                    # CommandRunner.Command('command5', {}, instance='some_instance', brand='some_brand')
                    ]

        return_results(CommandRunner.run_commands_with_summary(commands))
    except Exception as ex:
        return_error(f'Failed to execute AdditionalAlertInformationWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
