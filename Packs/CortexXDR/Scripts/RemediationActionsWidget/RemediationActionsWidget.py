"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

from CommonServerPython import *

import traceback

''' STANDALONE FUNCTION '''

''' COMMAND FUNCTION '''


def get_remediation_info() -> CommandResults:
    remediation_actions = demisto.get(demisto.context(), 'RemediationActions')
    blocked_ip_addresses = remediation_actions.get('BlockedIP').get('Addresses')
    if not isinstance(blocked_ip_addresses, list):
        blocked_ip_addresses = [blocked_ip_addresses]
    inactive_access_keys = remediation_actions.get('InactiveAccessKeys')
    if not isinstance(inactive_access_keys, list):
        inactive_access_keys = [inactive_access_keys]
    deleted_login_profiles = remediation_actions.get('DisabledLoginProfile').get('Username')
    if not isinstance(deleted_login_profiles, list):
        deleted_login_profiles = [deleted_login_profiles]
    res = {'Blocked IP Addresses': ','.join(blocked_ip_addresses),
           'Inactive Access keys': ','.join(inactive_access_keys),
           'Deleted Login Profiles': ','.join(deleted_login_profiles)}
    return CommandResults(
        readable_output=tableToMarkdown('Remediation Actions Information', res, headers=list(res.keys())))


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_remediation_info())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute RemediationActionsWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
