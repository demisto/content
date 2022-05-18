from CommonServerPython import *

import traceback

''' COMMAND FUNCTION '''


def get_identity_info() -> List[Dict]:
    context = demisto.context()
    alerts = demisto.get(context, 'PaloAltoNetworksXDR.OriginalAlert')
    if not alerts:
        raise DemistoException('PaloAltoNetworksXDR.OriginalAlert is not in the context')
    users = demisto.get(context, 'AWS.IAM.Users')
    if not users:
        raise DemistoException('AWS users are not in context')
    access_keys = users[0].get('AccessKeys', [])
    if not isinstance(alerts, list):
        alerts = [alerts]
    results = []
    for alert in alerts:
        alert_event = alert.get('event')
        username = demisto.get(alert_event, 'identity_orig.userName')
        access_keys_ids = list({access_key.get('AccessKeyId') for access_key in access_keys
                                if isinstance(access_key, dict) and access_key.get('UserName') == username})
        res = {'Name': alert_event.get('identity_name'),
               'Type': alert_event.get('identity_type'),
               'Sub Type': alert_event.get('identity_sub_type'),
               'Uuid': alert_event.get('identity_uuid'),
               'Provider': alert_event.get('cloud_provider'),
               'Access Keys': access_keys_ids}
        if res not in results:
            results.append(res)
    return results


''' MAIN FUNCTION '''


def main():
    try:
        results = get_identity_info()
        command_results = CommandResults(
            readable_output=tableToMarkdown('Identity Information', results,
                                            headers=list(results[0].keys()) if results else None))
        return_results(command_results)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute IdentityInformationWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
