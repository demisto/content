import demistomock as demisto  # noqa: F401  # pragma: no cover
from CommonServerPython import *  # noqa: F401  # pragma: no cover


''' COMMAND FUNCTION '''  # pragma: no cover


def get_additonal_info() -> List[Dict]:  # pragma: no cover
    alerts = demisto.context().get('Core', {}).get('OriginalAlert')
    if isinstance(alerts, list):
        alerts = alerts[0]
    if not alerts:
        raise DemistoException('Original Alert is not configured in context')
    if not isinstance(alerts, list):
        alerts = [alerts]
    results = []
    for alert in alerts:
        if alert == {}:
            continue
        if isinstance(alert, list):
            alert = tuple(alert)
        alert_event = alert.get('event')
        res = {'Identity Name': alert_event.get('identity_name'),
               'Identity Type': alert_event.get('identity_type'),
               'Access Key ID': alert_event.get('identity_invoked_by_uuid'),
               'Identity Invoke Type': alert_event.get('identity_invoked_by_type'),
               'Identity Invoke Sub Type': alert_event.get('identity_invoked_by_sub_type')}
        results.append(res)
    return results


''' MAIN FUNCTION '''  # pragma: no cover


def main():  # pragma: no cover
    try:
        results = get_additonal_info()
        command_results = CommandResults(
            readable_output=tableToMarkdown('Cloud Identity', results,
                                            headers=list(results[0].keys()) if results else None))
        return_results(command_results)
    except Exception as ex:
        return_error(f'Failed to execute XCloudIdentitiesWidget. Error: {str(ex)}')


''' ENTRY POINT '''  # pragma: no cover

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()  # pragma: no cover
