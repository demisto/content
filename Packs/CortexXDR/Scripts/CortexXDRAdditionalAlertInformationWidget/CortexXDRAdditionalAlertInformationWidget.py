from CommonServerPython import *

import traceback

''' COMMAND FUNCTION '''


def get_additonal_info() -> List[Dict]:
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
        results = get_additonal_info()
        command_results = CommandResults(
            readable_output=tableToMarkdown('Original Alert Additional Information', results,
                                            headers=list(results[0].keys()) if results else None))
        return_results(command_results)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute AdditionalAlertInformationWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
