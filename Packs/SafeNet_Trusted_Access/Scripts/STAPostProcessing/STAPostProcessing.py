import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback

''' STANDALONE FUNCTION '''


# Get Incident Details.
def get_incident_sta():
    return demisto.incidents()[0]


# Check if user is a member of Unusual Activity Group.
def check_user_exist_group_sta(field: Dict[str, Any]):
    return demisto.executeCommand('sta-user-exist-group', {
        "userName": field.get('safenettrustedaccessusername'),
        "groupName": field.get('safenettrustedaccessunusualactivitygroup'),
        "using": field.get('safenettrustedaccessinstancename'),
    })[0]['EntryContext'].get('STA.EXIST.USER.GROUP')


# Remove user from Unusual Activity Group if incident is closed manually.
def close_incident_sta(args: Dict[str, Any]):
    incident = get_incident_sta()
    sta_fields = incident.get('CustomFields')

    if "safenettrustedaccessremoveuserfromunusualactivitygroup" in sta_fields:
        if sta_fields.get('safenettrustedaccessremoveuserfromunusualactivitygroup') == 'Yes':
            if check_user_exist_group_sta(sta_fields) is True:
                demisto.executeCommand('sta-remove-user-group', {
                    "userName": sta_fields.get('safenettrustedaccessusername'),
                    "groupName": sta_fields.get('safenettrustedaccessunusualactivitygroup'),
                    "using": sta_fields.get('safenettrustedaccessinstancename'),
                })
        elif sta_fields.get('safenettrustedaccessremoveuserfromunusualactivitygroup') == 'No':
            if check_user_exist_group_sta(sta_fields) is False:
                raise Exception(f'User - {sta_fields.get("safenettrustedaccessusername")} is not a member of the '
                                f'group - {sta_fields.get("safenettrustedaccessunusualactivitygroup")}.')


''' MAIN FUNCTION '''


def main():

    try:
        # Check if incident is closed manually.
        if demisto.args().get('closingUserId') != "DBot":
            close_incident_sta(demisto.args())

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute STAPostProcessing script. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
