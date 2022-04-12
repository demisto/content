import pytest
from CommonServerPython import *
import json
import demistomock as demisto


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


EMAIL_SIGNATURE_LIST = [{'Contents': 'Test email signature.'}]

EMAIL_SIGNATURE_APPENDED = '<html><body>Simple HTML message.\r\n\r\nTest email signature.\r\n</body></html>'


def test_append_email_signature(mocker):
    from SendEmailReply import append_email_signature
    mocker.patch.object(demisto, 'executeCommand', return_value=EMAIL_SIGNATURE_LIST)
    result = append_email_signature('<html><body>Simple HTML message.\r\n</body></html>')
    assert result == EMAIL_SIGNATURE_APPENDED


def test_send_reply(mocker):
    """Unit test
        Given
        - Raw response of an email reply.
        When
        - The result is a successful reply with email recipients and cc.
        Then
        - Validate that the successful message is returned.
        """
    from SendEmailReply import send_reply
    email_reply_response = util_load_json('test_data/email_reply.json')
    mocker.patch("SendEmailReply.append_email_signature")
    mocker.patch("SendEmailReply.send_mail_request", return_value=email_reply_response)
    result = send_reply('123', 'email_subject', 'test1@gmail.com,test2@gmail.com', 'reply_body', 'test.onmicrosoft.com',
                        'test3@gmail.com', 'test4@gmail.com', 'reply_html_body', {}, 'item_id', '12345678',
                        'EWS Mail Sender_instance_1')
    assert "Mail sent successfully. To: test1@gmail.com,test2@gmail.com Cc: test3@gmail.com" == result


GET_EMAIL_RECIPIENTS = [
    # Both service mail and mailbox are configured as different addresses, should remove only mailbox.
    ('["avishai@demistodev.onmicrosoft.com", "test test <\'test@test.com\'>"]',
     "test123@gmail.com",
     "avishai@demistodev.onmicrosoft.com",
     "test@test.com",
     {"test123@gmail.com", "avishai@demistodev.onmicrosoft.com"}),

    # Only mailbox is configured, should be removed.
    ('["avishai@demistodev.onmicrosoft.com", "test test <\'test@test.com\'>"]',
     "test123@gmail.com",
     "",
     "test@test.com",
     {"test123@gmail.com", "avishai@demistodev.onmicrosoft.com"}),

    # Only service mail is configured, should be removed.
    ('["avishai@demistodev.onmicrosoft.com", "test1@gmail.com"]',
     "test123@gmail.com",
     "avishai@demistodev.onmicrosoft.com",
     "",
     {"test123@gmail.com", "test1@gmail.com"}),

    # Neither service mail nor mailbox is configured, make sure nothing is removed.
    ('["avishai@demistodev.onmicrosoft.com", "test1@gmail.com"]',
     "test123@gmail.com",
     "",
     "",
     {"test123@gmail.com", "test1@gmail.com", "avishai@demistodev.onmicrosoft.com"}),
]


@pytest.mark.parametrize(
    "email_to, email_from, service_mail, mailbox, excepted", GET_EMAIL_RECIPIENTS
)
def test_get_email_recipients(email_to, email_from, service_mail, mailbox, excepted):
    """Unit test
        Given
        - Single email recipient, single email author, service mail and mailbox.
        - Multiple email recipients, single email author, service mail and mailbox.
        When
        - Getting the email recipients.
        Then
        - validate that the correct email recipients are returned.
    """
    from SendEmailReply import get_email_recipients

    result = set(get_email_recipients(email_to, email_from, service_mail, mailbox).split(','))
    assert result == excepted


@pytest.mark.parametrize(
    "notes, attachments, expected_results",
    [
        (
            [{'Metadata': {'user': 'DBot'}, 'Contents': 'note1'}, {'Metadata': {'user': 'DBot'}, 'Contents': 'note2'}],
            [{'name': 'attachment1.png'}, {'name': 'attachment2.png'}],
            "DBot: \nnote1\n\nDBot: \nnote2\n\nAttachments: ['attachment1.png', 'attachment2.png']\n\n"
        ),
        (
            [{'Metadata': {'user': 'DBot'}, 'Contents': 'note1'}, {'Metadata': {'user': 'DBot'}, 'Contents': 'note2'}],
            [],
            "DBot: \nnote1\n\nDBot: \nnote2\n\n"
        ),
        (
            [{'Metadata': {'user': 'DBot'}, 'Contents': 'note1'}, {'Metadata': {'user': 'DBot'}, 'Contents': 'note2'}],
            "[]",
            "DBot: \nnote1\n\nDBot: \nnote2\n\n"
        )
    ]
)
def test_get_reply_body(mocker, notes, attachments, expected_results):
    """Unit test
        Given
        - List of notes and list of attachments.
        When
        - Getting the email reply body.
        Then
        - validate that the correct reply is returned.
        """
    from SendEmailReply import get_reply_body
    import CommonServerPython
    mocker.patch.object(demisto, "executeCommand", return_value=[{'EntryContext': {'replyhtmlbody': ''}, 'Type': ''}])
    mocker.patch.object(CommonServerPython, "dict_safe_get", return_value=None)
    mocker.patch.object(CommonServerPython, "is_error", return_value=False)
    reply_body = get_reply_body(notes=notes, incident_id='1', attachments=attachments)[0]
    assert reply_body == expected_results


def test_create_file_data_json():
    """Unit test
        Given
        - Raw response of an attachment in email reply.
        When
        - There is an attachment in the email reply.
        Then
        - Validate that the file data is in the right json format.
        """
    from SendEmailReply import create_file_data_json
    attachment_response = util_load_json('test_data/attachment_example.json')
    expected_result = util_open_file('test_data/file_data.txt')
    result = create_file_data_json(attachment_response, 'attachment')
    assert result == expected_result


@pytest.mark.parametrize(
    "current_cc, additional_cc, excepted",
    [('test1@gmail.com, test2@gmail.com', 'test3@gmail.com,test4@gmail.com', 'test1@gmail.com,test2@gmail.com,'
                                                                             'test3@gmail.com,test4@gmail.com'),
     ('test1@gmail.com', '', 'test1@gmail.com'), ('', '', '')
     ])
def test_get_email_cc(current_cc, additional_cc, excepted):
    """Unit test
        Given
        - multiple current email cc and multiple additional email cc.
        - single current email cc and empty additional email cc.
        - empty current email cc and empty additional email cc.
        When
        - Getting email cc.
        Then
        - validate that the correct email cc are being returned.
        """
    from SendEmailReply import get_email_cc
    result = get_email_cc(current_cc, additional_cc)
    assert result == excepted


def test_create_thread_context(mocker):
    """Unit test
        Given:
        - all required function arguments are provided
        When:
        - creating new context entry to store email thread data
        Then
        - validate that function calls appendContext() with all arguments and data needed to properly create
          the required context entry
    """
    email_threads = util_load_json('test_data/email_threads.json')

    def side_effect_function(command, args):
        if command == "getContext":
            return email_threads

    from SendEmailReply import create_thread_context
    import SendEmailReply

    # Email data to use both for function input and function output validation
    test_email = email_threads[0]
    # Mock function to get current time string to match the expected result
    mocker.patch('SendEmailReply.get_utc_now',
                 return_value=datetime.strptime(test_email['MessageTime'], "%Y-%m-%dT%H:%M:%SUTC"))
    appendContext_mocker = mocker.patch.object(SendEmailReply, "appendContext", return_value=True)
    create_thread_context(test_email['EmailCommsThreadId'], test_email['EmailCC'], test_email['EmailBCC'],
                          test_email['EmailBody'], test_email['EmailFrom'], test_email['EmailHTML'],
                          test_email['MessageID'], test_email['EmailReceived'], test_email['EmailReplyTo'],
                          test_email['EmailSubject'], test_email['EmailTo'], '123', 'None')
    call_args = appendContext_mocker.call_args
    assert "EmailThreads" == call_args.args[0]
    assert test_email == call_args.args[1]


@pytest.mark.parametrize(
    "scenario",
    [
        'required_fields_missing',
        'no_codes_present',
        'codes_present'
    ]
)
def test_multi_thread_new(scenario, mocker):
    """
    Unit test scenario 1 - Required fields are missing
        Given
         - Script is called to send a new first-contact email message
        When
         - Required fields 'new_email_subject', 'new_email_recipients', and 'new_email_body' are not provided
        Then
         - Validate that the function returns a meaningful error message
    Unit test scenario 2 - No other email identifier codes are present
        Given
         - Script is called to send a new first-contact email message
        When
         - All required fields are provided
         - There are no prior email identifier codes present on the incident
        Then
         - Validate that the function sets 'emailgeneratedcodes' to the new identifier value
         - Validate that the function calls 'send_reply' with correct arguments set
         - Validate that 'reset_fields' is called
    Unit test scenario 3 - Incident already contains other unique identifier codes for other threads
        Given
         - Script is called to send a new first-contact email message
        When
         - All required fields are provided
         - There are at least one prior email identifier codes present on the incident
        Then
         - Validate that the function sets 'emailgeneratedcodes' with the new code appended to the prior one
         - Validate that the function calls 'send_reply' with correct arguments set
         - Validate that 'reset_fields' is called
    """
    from SendEmailReply import multi_thread_new
    import SendEmailReply
    return_error_mocker = mocker.patch.object(SendEmailReply, 'return_error', return_value=True)
    mocker.patch.object(SendEmailReply, 'get_unique_code', return_value='87654321')
    setIncident_mocker = mocker.patch.object(demisto, 'executeCommand', return_value=True)
    mocker.patch.object(SendEmailReply, 'get_entry_id_list', return_value=[])
    mocker.patch.object(SendEmailReply, 'format_body', return_value='<html>Some HTML</html>')
    send_new_email_mocker = mocker.patch.object(SendEmailReply, 'send_new_email', return_value=True)
    reset_fields_mocker = mocker.patch.object(SendEmailReply, 'reset_fields', return_value=True)
    if scenario == 'required_fields_missing':
        # Test Scenario 1
        expected = "The following required fields have not been set.  Please set them and try again. " \
                   "['New Email Subject', 'New Email Recipients', 'New Email Body']"
        multi_thread_new('', '', '', 1, '12345678', '', '', 'soc_sender@company.com', 'cc_user@company.com',
                         'bcc_user@company.com', 'soc_sender@company.com', '')
        call_args = return_error_mocker.call_args
        assert call_args.args[0] == expected
    if scenario == 'no_codes_present':
        # Test Scenario 2
        multi_thread_new('New Subject', 'end_user@company.com', 'Email Body', 1, '', '', '',
                         'soc_sender@company.com', 'cc_user@company.com', 'bcc_user@company.com',
                         'soc_sender@company.com', '')
        setIncident_call_args = setIncident_mocker.call_args
        send_new_email_mocker_args = send_new_email_mocker.call_args
        assert setIncident_call_args.args[1] == {'id': 1, 'customFields': {'emailgeneratedcodes': '87654321'}}
        valid_args = (1, 'New Subject', 'end_user@company.com', 'Email Body', 'soc_sender@company.com',
                      'cc_user@company.com', 'bcc_user@company.com', '<html>Some HTML</html>', [], '87654321',
                      'soc_sender@company.com', '')
        assert send_new_email_mocker_args.args == valid_args
        assert reset_fields_mocker.called is True
    if scenario == 'codes_present':
        # Test Scenario 3
        multi_thread_new('New Subject', 'end_user@company.com', 'Email Body', 1, '12345678', '', '',
                         'soc_sender@company.com', 'cc_user@company.com', 'bcc_user@company.com',
                         'soc_sender@company.com', '')
        setIncident_call_args = setIncident_mocker.call_args
        send_new_email_mocker_args = send_new_email_mocker.call_args
        assert setIncident_call_args.args[1] == {'id': 1, 'customFields': {'emailgeneratedcodes': '12345678,87654321'}}
        valid_args = (1, 'New Subject', 'end_user@company.com', 'Email Body', 'soc_sender@company.com',
                      'cc_user@company.com', 'bcc_user@company.com', '<html>Some HTML</html>', [], '87654321',
                      'soc_sender@company.com', '')
        assert send_new_email_mocker_args.args == valid_args
        assert reset_fields_mocker.called is True


def test_collect_thread_details(mocker):
    """
    Unit test scenario
        Given
         - Function is called to gather details from existing email thread
        When
         - Multiple emails are present on the thread
        Then
         - Validate that the function returns the correct email details for use in an email reply
    """
    from SendEmailReply import collect_thread_details
    expected = (True, 'AAMkAGRcOGZlZTEzLTkyZGDtNGJkNy1iOWMxLYM0NTAwODZhZjlxNABGAAAAAAAP2ksrJ8icRL4Zhadm7iVXBwAkkBJXBb0'
                      'sRJWC0zdXEMqsAAAAAAEMAAAkkBJFBb0fRJWC0zdXEMqsABApcWVYAAA=', False, '87692312',
                'Re: <87692312> Test Email 4', 'end_user@company.com, soc_sender@company.com',
                'soc_sender@company.com', '', '', 3)
    actual = collect_thread_details(util_load_json('test_data/email_threads.json'), '1')
    assert actual == expected


@pytest.mark.parametrize(
    "scenario",
    [
        'single_outbound',
        'multiple_outbound',
        'replies_present'
    ]
)
def test_multi_thread_reply(scenario, mocker):
    """
    Unit test scenario 1 - Resend First-Contact - Single Outbound
        Given
         - Function is called to send a reply to an existing email thread
        When
         - The selected thread contains only an outbound message (no replies from recipients)
        Then
         - Validate that the function calls 'resend_first_contact' to send the message as a new outbound email
         - Validate that 'first_contact_resent' is set to True
    Unit test scenario 2 - Resend First-Contact - Multiple Outbound
        Given
         - Function is called to send a reply to an existing email thread
        When
         - The selected thread contains multiple outbound messages (no replies from recipients)
        Then
         - Validate that the function calls 'resend_first_contact' to send the message as a new outbound email
         - Validate that 'first_contact_resent' is set to True
    Unit test scenario 3 - Replies Present
        Given
         - Function is called to send a reply to an existing email thread
        When
         - The selected thread contains both outbound and inbound messages (there are replies from recipients)
        Then
         - Validate that the function calls 'send_reply' to reply to existing email thread
         - Validate that the function calls 'create_thread_context' with correct arguments
         - Validate that 'first_contact_resent' is set to False
         - Validate that 'reset_fields' is called
    """
    from SendEmailReply import multi_thread_reply
    import SendEmailReply

    email_threads = util_load_json('test_data/email_threads.json')
    resend_first_contact_mocker = mocker.patch.object(SendEmailReply, 'resend_first_contact', return_value=True)
    reset_fields_mocker = mocker.patch.object(SendEmailReply, 'reset_fields', return_value=True)
    mocker.patch.object(SendEmailReply, 'return_results', return_value=True)
    mocker.patch.object(SendEmailReply, 'format_body', return_value='<html><body>Email body</body></html>')
    mocker.patch.object(SendEmailReply, 'append_email_signature',
                        return_value='<html><body>Email body+signature</body></html>')
    reset_fields_mocker = mocker.patch.object(SendEmailReply, 'reset_fields', return_value=True)
    send_reply_mocker = mocker.patch.object(SendEmailReply, 'send_reply', return_value=True)
    create_context_mocker = mocker.patch.object(SendEmailReply, 'create_thread_context', return_value=True)

    if scenario == 'single_outbound':
        # Return only a single email thread entry
        mocker.patch.object(SendEmailReply, 'get_email_threads', return_value=email_threads[0])
        multi_thread_reply('Email body', 1, 0, '', '', 'cc_user@company.com', 'bcc_user@company.com',
                           'soc_sender@company.com', 'soc_sender@company.com', '')
        expected = (0, {'EmailBCC': '', 'EmailBody': 'Outbound test message from XSOAR to User.', 'EmailCC': '',
                        'EmailCommsThreadId': '69433507', 'EmailCommsThreadNumber': '0',
                        'EmailFrom': 'soc_sender@company.com', 'EmailHTML': 'Outbound test message from XSOAR to User.',
                        'EmailReceived': '', 'EmailReplyTo': 'soc_sender@company.com',
                        'EmailSubject': '<69433507> Test Email 2', 'EmailTo': 'end_user@company.com',
                        'EmailAttachments': 'None', 'MessageDirection': 'outbound', 'MessageID': '',
                        'MessageTime': '2022-02-04T20:56:53UTC'}, 1, '', '', '<html><body>Email body</body></html>',
                    'cc_user@company.com', 'bcc_user@company.com', 'soc_sender@company.com',
                    'soc_sender@company.com', '')
        resend_first_contact_call_args = resend_first_contact_mocker.call_args
        assert resend_first_contact_call_args.args == expected
        assert reset_fields_mocker.called is True
    elif scenario == 'multiple_outbound':
        # Return all email thread entries
        mocker.patch.object(SendEmailReply, 'get_email_threads', return_value=email_threads)
        thread_details = (
            True, 'AAMkAGRcOGZlZTEzLTkyZGDtNGJkNy1iOWMxLYM0NTAwODZhZjlxNABGAAAAAAAP2ksrJ8icRL4Zhadm7iVXBwAkkBJXBb0'
                  'sRJWC0zdXEMqsAAAAAAEMAAAkkBJFBb0fRJWC0zdXEMqsABApcWVYAAA=', True, '69433507',
            'Re: <69433507> Test Email 2', 'end_user@company.com, soc_sender@company.com',
            'soc_sender@company.com', '', '', 2)
        mocker.patch.object(SendEmailReply, 'collect_thread_details', return_value=thread_details)

        # Execute the tested function
        multi_thread_reply('Email body', 1, 0, '', '', 'cc_user@company.com', 'bcc_user@company.com',
                           'soc_sender@company.com', 'soc_sender@company.com', '')

        expected = (0, {'EmailBCC': '', 'EmailBody': 'Outbound test message from XSOAR to User.', 'EmailCC': '',
                        'EmailCommsThreadId': '87692312', 'EmailCommsThreadNumber': '1',
                        'EmailFrom': 'soc_sender@company.com', 'EmailHTML': 'Outbound test message from XSOAR to User.',
                        'EmailReceived': '', 'EmailReplyTo': 'soc_sender@company.com',
                        'EmailSubject': '<87692312> Test Email 4', 'EmailTo': 'end_user@company.com',
                        'EmailAttachments': 'None', 'MessageDirection': 'outbound', 'MessageID': '',
                        'MessageTime': '2022-02-04T20:56:53UTC'}, 1, '', '', '<html><body>Email body</body></html>',
                    'cc_user@company.com', 'bcc_user@company.com', 'soc_sender@company.com',
                    'soc_sender@company.com', '')
        resend_first_contact_call_args = resend_first_contact_mocker.call_args
        assert resend_first_contact_call_args.args == expected
        assert reset_fields_mocker.called is True
    elif scenario == 'replies_present':
        thread_details = (
            True, 'AAMkAGRcOGZlZTEzLTkyZGDtNGJkNy1iOWMxLYM0NTAwODZhZjlxNABGAAAAAAAP2ksrJ8icRL4Zhadm7iVXBwAkkBJXBb0'
            'sRJWC0zdXEMqsAAAAAAEMAAAkkBJFBb0fRJWC0zdXEMqsABApcWVYAAA=', False, '87692312',
            'Re: <87692312> Test Email 4', 'end_user@company.com, soc_sender@company.com',
            'soc_sender@company.com', '', '', 2)
        mocker.patch.object(SendEmailReply, 'collect_thread_details', return_value=thread_details)
        # Return all email thread entries
        mocker.patch.object(SendEmailReply, 'get_email_threads', return_value=email_threads)
        send_reply_expected = (1, '<87692312> Test Email 4', 'end_user@company.com', 'Email body', 'soc_sender@company.com',
                    'cc_user@company.com', 'bcc_user@company.com', '<html><body>Email body</body></html>', [],
                    'AAMkAGRcOGZlZTEzLTkyZGDtNGJkNy1iOWMxLYM0NTAwODZhZjlxNABGAAAAAAAP2ksrJ8icRL4Zhadm7iVXBwAkkBJXBb0sR'
                    'JWC0zdXEMqsAAAAAAEMAAAkkBJFBb0fRJWC0zdXEMqsABApcWVYAAA=', '87692312', 'soc_sender@company.com')
        create_context_expected = ('87692312', 'cc_user@company.com', 'bcc_user@company.com', 'Email body',
                                   'soc_sender@company.com', '<html><body>Email body+signature</body></html>', '', '',
                                   'soc_sender@company.com', '<87692312> Test Email 4', 'end_user@company.com', 1, '')

        # Execute the tested function
        multi_thread_reply('Email body', 1, 1, '', '', 'cc_user@company.com', 'bcc_user@company.com',
                           'soc_sender@company.com', 'soc_sender@company.com', '')

        send_reply_call_args = send_reply_mocker.call_args
        create_context_call_args = create_context_mocker.call_args
        assert send_reply_call_args.args == send_reply_expected
        assert create_context_call_args.args == create_context_expected
        assert reset_fields_mocker.called is True
