import demistomock as demisto
import STAPostProcessing
from STAPostProcessing import close_incident_sta

# Defining output of get_incident_sta function for mocker.
incident_fields = {
    'id': 100,
    'CustomFields': {
        'safenettrustedaccessremoveuserfromunusualactivitygroup': 'Yes',
        'safenettrustedaccessusername': 'demouser',
        'safenettrustedaccessunusualactivitygroup': 'TestUnusualActivityGroup',
        'safenettrustedaccessinstancename': 'SafeNet Trusted Access_instance_1',
    }
}

# Defining output of check_user_exist_group_sta function for mocker.
user_exist_group = True


# Tests close_incident_sta function.
def test_close_incident_sta(mocker):
    mocker.patch.object(STAPostProcessing, 'get_incident_sta', return_value=incident_fields)
    mocker.patch.object(STAPostProcessing, 'check_user_exist_group_sta', return_value=user_exist_group)
    execute_mocker = mocker.patch.object(demisto, 'executeCommand')
    expected_command = 'sta-remove-user-group'
    expected_args = {
        'userName': 'demouser',
        'groupName': 'TestUnusualActivityGroup',
        'using': 'SafeNet Trusted Access_instance_1',
    }

    close_incident_sta(demisto.args())
    execute_mocker.assert_called_with(expected_command, expected_args)
