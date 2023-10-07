import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' COMMAND FUNCTION '''


def get_additonal_info() -> List[Dict]:
    alerts = demisto.context().get('foundIncidents')
    if alerts == "{}":
        raise DemistoException('No related alerts found')
    if not isinstance(alerts, list):
        alerts = [alerts]

    results = []
    for alert in alerts:
        if alert == {}:
            continue
        if isinstance(alert, list):
            alert = tuple(alert)
        alert_event = alert.get('CustomFields')
        res = {'Alert Full Description': alert.get('name'),
               'Action': alert_event.get('action'),
               'Category Name': alert_event.get('categoryname'),
               'Provider': alert_event.get('cloudprovider'),
               'Region': alert_event.get('region'),
               'Cloud Operation Type': demisto.get(alert_event, 'cloudoperationtype'),
               'Caller IP': alert_event.get('hostip'),
               'Caller IP Geo Location': alert_event.get('Country', 'N/A'),
               'Resource Type': alert_event.get('cloudresourcetype'),
               'Identity Name': alert_event.get('username'),
               'User Agent': alert_event.get('useragent')}
        results.append(res)
    return results


''' MAIN FUNCTION '''


def main():
    try:
        results = get_additonal_info()
        command_results = CommandResults(
            readable_output=tableToMarkdown('Related Alerts', results,
                                            headers=list(results[0].keys()) if results else None))
        return_results(command_results)
    except Exception as ex:
        return_error(f'Failed to execute XCloudRelatedAlertsWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
