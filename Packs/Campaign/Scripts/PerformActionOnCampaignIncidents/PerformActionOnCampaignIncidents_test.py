import pytest
from PerformActionOnCampaignIncidents import *


NUM_OF_INCIDENTS = 5
INCIDENT_IDS = [str(i) for i in range(NUM_OF_INCIDENTS)]
CUSTOM_FIELDS = {
    ACTION_ON_CAMPAIGN_FIELD_NAME: 'Close',
    SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME: INCIDENT_IDS
}
MOCKED_INCIDENT = {
    'id': '100',
    'CustomFields': CUSTOM_FIELDS
}

SUCCESS_REOPEN = 'The following incidents was successfully reopened {}.'
SUCCESS_CLOSE = 'The following incidents was successfully closed {}.'


def prepare(mocker):
    mocker.patch.object(demisto, 'incidents', return_value=[MOCKED_INCIDENT])
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch('PerformActionOnCampaignIncidents.get_campaign_incident_ids', return_value=INCIDENT_IDS)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'callingContext', return_value='admin')


@pytest.mark.parametrize('action', ACTIONS_MAPPER.keys())
def test_perform_action_happy_path(mocker, action):
    """
        Given -
            Perform action button was clicked and there is Selected incident ids

        When -
            Run the perform_action script

        Then -
            Validate the correct message is returned

    """
    prepare(mocker)
    CUSTOM_FIELDS[ACTION_ON_CAMPAIGN_FIELD_NAME] = action
    test_selected_ids = ['All', INCIDENT_IDS]
    for selected_ids in test_selected_ids:
        CUSTOM_FIELDS[SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME] = selected_ids
        # run
        main()

        # validate
        res = demisto.results.call_args[0][0]
        assert 'The following incidents was successfully' in res
        assert ','.join(INCIDENT_IDS) in res


def test_invalid_action(mocker):
    """
        Given -
             Invalid action in the perform action field

        When -
            Run the main of PerformActionOnCampaignIncidents

        Then -
            Validate error occurred
    """

    prepare(mocker)
    CUSTOM_FIELDS[ACTION_ON_CAMPAIGN_FIELD_NAME] = 'invalid_action'
    # run
    try:
        main()
        pytest.fail('SystemExit should occurred as the return_error was called')
    except SystemExit:
        # validate
        res = demisto.results.call_args[0][0]
        assert 'invalid_action' in res['Contents']


@pytest.mark.parametrize('action', ACTIONS_MAPPER.keys())
def test_error_in_execute_command(mocker, action):
    """
        Given -
            isError is return true to indicate there is error

        When -
            Run the main of PerformActionOnCampaignIncidents

        Then -
            Validate return_error was called
    """

    prepare(mocker)
    mocker.patch('PerformActionOnCampaignIncidents.isError', return_value=True)
    mocker.patch('PerformActionOnCampaignIncidents.get_error', return_value="Error message")

    CUSTOM_FIELDS[ACTION_ON_CAMPAIGN_FIELD_NAME] = action
    # run
    try:
        main()
        pytest.fail('SystemExit should occurred as the return_error was called')
    except SystemExit:
        # validate
        res = demisto.results.call_args[0][0]
        if action == 'link & close':
            action = 'link'  # command failed on link
        elif action == 'unlink & reopen':
            action = 'unlink'  # command failed on unlink
        assert res['Contents'] == COMMAND_ERROR_MSG.format(action=action, ids=','.join(INCIDENT_IDS),
                                                           error="Error message")


def test_no_incidents_in_context(mocker):
    """
        Given - there is no email campaign in context

        When - user click on perform action button

        Then - validate the return message about there is no campaign in context

    """

    prepare(mocker)
    CUSTOM_FIELDS[SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME] = []
    CUSTOM_FIELDS[SELECT_CAMPAIGN_LOWER_INCIDENTS_FIELD_NAME] = []

    # run
    main()

    # validate
    assert demisto.results.call_args[0][0] == NO_CAMPAIGN_INCIDENTS_MSG
