from CommonServerPython import *  # noqa: F401


''' COMMAND FUNCTION '''


def get_additonal_info() -> List[Dict]:
    alerts = demisto.context().get('Core', {}).get('OriginalAlert')
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


def verify_list_type(original_alert_data):
    if isinstance(original_alert_data, list):
        res = original_alert_data[0].get('EntryContext')
        res['OriginalAlert'] = res.pop('Core.OriginalAlert(val.internal_id && val.internal_id == obj.internal_id)')
        if isinstance(res['OriginalAlert'], list):
            res['OriginalAlert'] = res['OriginalAlert'][0]
        return res
    return None


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    try:
        alert_context = demisto.investigation()
        core_alert_context = demisto.context().get('Core', {})
        if not core_alert_context.get('OriginalAlert'):
            original_alert_data = demisto.executeCommand('core-get-cloud-original-alerts', {"alert_ids": alert_context.get('id')})
            if original_alert_data:
                res = verify_list_type(original_alert_data)
                demisto.executeCommand('SetByIncidentId', {"key": "Core", "value": res, "id": alert_context.get('id')})
        results = get_additonal_info()
        command_results = CommandResults(
            readable_output=tableToMarkdown('Original Alert Additional Information', results,
                                            headers=list(results[0].keys()) if results else None))
        return_results(command_results)
    except Exception as ex:
        return_error(f'Failed to execute AdditionalAlertInformationWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
