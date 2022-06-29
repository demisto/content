import pytest
from SendEmailToCampaignRecipients import *

CAMPAIGN_EMAIL_TO = 'campaignemailto'
CAMPAIGN_EMAIL_SUBJECT = 'campaignemailsubject'
CAMPAIGN_EMAIL_BODY = 'campaignemailbody'

NUM_OF_INCIDENTS = 5
INCIDENT_IDS = [str(i) for i in range(NUM_OF_INCIDENTS)]
CUSTOM_FIELDS = {
    CAMPAIGN_EMAIL_TO: 'a@a.com',
    CAMPAIGN_EMAIL_SUBJECT: 'Campaign Detected',
    CAMPAIGN_EMAIL_BODY: 'PLease check the email'
}
MOCKED_INCIDENT = {
    'id': 100,
    'CustomFields': CUSTOM_FIELDS
}


def test_send_email_happy_path(mocker):
    """
        Given -
            Mocked custom field for an incident

        When -
            Run the main of the command

        Then -
            Validate the expected args sent to demisto.executeCommand
    """

    # prepare
    mocker.patch.object(demisto, 'incidents', return_value=[MOCKED_INCIDENT])
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'results')
    # run
    main()

    # validate
    assert demisto.executeCommand.call_args[0][0] == 'send-mail'
    command_arg_dict = demisto.executeCommand.call_args[0][1]
    for custom_filed_key, command_key in zip(CUSTOM_FIELDS.keys(), ['to', 'subject', 'body']):
        assert command_arg_dict[command_key] == CUSTOM_FIELDS[custom_filed_key]


def test_no_email_to(mocker):
    """
        Given -
            Empty emailto in the incident

        When -
            Try to send email

        Then -
            Validate return_error was called

    """

    # prepare
    mocker.patch.object(demisto, 'incidents', return_value=[MOCKED_INCIDENT])
    mocker.patch.object(demisto, 'results')
    CUSTOM_FIELDS[CAMPAIGN_EMAIL_TO] = ''

    # run
    try:
        main()
        pytest.fail('SystemExit should occurred as return_error was called')
    except SystemExit:
        args = demisto.results.call_args[0][0]
        assert args['Contents'] == INVALID_EMAIL_TO_MSG
