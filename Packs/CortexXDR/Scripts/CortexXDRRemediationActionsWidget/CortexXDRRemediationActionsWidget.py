from CommonServerPython import *

import traceback

''' STANDALONE FUNCTION '''


def get_remediation_info() -> Dict:
    remediation_actions = demisto.get(demisto.context(), 'RemediationActions')
    if not remediation_actions:
        raise DemistoException('RemediationActions not in context')
    blocked_ip_addresses = demisto.get(remediation_actions, 'BlockedIP.Addresses')
    if blocked_ip_addresses is not None and not isinstance(blocked_ip_addresses, list):
        blocked_ip_addresses = [blocked_ip_addresses]
    inactive_access_keys = remediation_actions.get('InactiveAccessKeys')
    if inactive_access_keys is not None and not isinstance(inactive_access_keys, list):
        inactive_access_keys = [inactive_access_keys]
    deleted_login_profiles = demisto.get(remediation_actions, 'DisabledLoginProfile.Username')
    if deleted_login_profiles is not None and not isinstance(deleted_login_profiles, list):
        deleted_login_profiles = [deleted_login_profiles]

    res = {}
    if blocked_ip_addresses:
        res['Blocked IP Addresses'] = list(indicators_value_to_clickable(blocked_ip_addresses).values())
    if inactive_access_keys:
        res['Inactive Access keys'] = inactive_access_keys
    if deleted_login_profiles:
        res['Deleted Login Profiles'] = deleted_login_profiles
    return res


''' MAIN FUNCTION '''


def main():
    try:
        result = get_remediation_info()
        command_result = CommandResults(
            readable_output=tableToMarkdown('Remediation Actions Information', result, headers=list(result.keys())))
        return_results(command_result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute RemediationActionsWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
