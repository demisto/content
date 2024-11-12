import pytest
from freezegun import freeze_time

from CommonServerPython import *
import json
import demistomock as demisto
from SendEmailReply import get_unique_code


def util_open_file(path):
    with open(path) as f:
        return f.read()


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


EMAIL_SIGNATURE_APPENDED = '<html><body>Simple HTML message.\r\n\r\nTest email signature.\r\n</body></html>'


def test_append_email_signature(mocker):
    """
    Given
    - Email signature stored in XSOAR List
    When
    - List content is returned correctly
    Then
    - Validate that the returned message includes the appended signature content
    """
    from SendEmailReply import append_email_signature
    signature_list = util_load_json('test_data/getList_signature_success.json')
    mocker.patch.object(demisto, 'executeCommand', return_value=signature_list)
    result = append_email_signature('<html><body>Simple HTML message.\r\n</body></html>')
    assert result == EMAIL_SIGNATURE_APPENDED


def test_append_email_signature_fails(mocker):
    """
    Given
    - Email signature stored in XSOAR List
    When
    - List content results in error when fetched
    Then
    - Validate that the returned message remains unchanged
    - Validate that a debug message is saved indicating the list couldn't be fetched
    """
    from SendEmailReply import append_email_signature
    get_list_error_response = util_load_json('test_data/getList_signature_error.json')
    mocker.patch.object(demisto, 'executeCommand', return_value=get_list_error_response)
    debug_mocker = mocker.patch.object(demisto, 'debug')
    append_email_signature('<html><body>Simple HTML message.\r\n</body></html>')
    debug_mocker_call_args = debug_mocker.call_args
    assert debug_mocker_call_args.args[0] == 'Error occurred while trying to load the `XSOAR - Email Communication ' \
                                             'Signature` list. No signature added to email'


@pytest.mark.parametrize(
    "email_cc, email_bcc, expected_result",
    [
        ('', '', 'Mail sent successfully. To: test1@gmail.com,test2@gmail.com'),
        ('cc_user@company.com', '', 'Mail sent successfully. To: test1@gmail.com,test2@gmail.com '
                                    'Cc: cc_user@company.com'),
        ('cc_user@company.com', 'bcc_user@company.com', 'Mail sent successfully. '
                                                        'To: test1@gmail.com,test2@gmail.com Cc: '
                                                        'cc_user@company.com Bcc: bcc_user@company.com')
    ]
)
def test_validate_email_sent(email_cc, email_bcc, expected_result, mocker):
    """
    Given
    - Raw response of an email reply.
    When
    - The result is a successful reply with email recipients, cc, and bcc.
    Then
    - Validate that the successful message is returned.
    """
    from SendEmailReply import validate_email_sent
    email_reply_response = util_load_json('test_data/email_reply.json')
    mocker.patch("SendEmailReply.execute_reply_mail", return_value=email_reply_response)
    result = validate_email_sent(
        '123',
        'email_subject',
        False,
        'test1@gmail.com,test2@gmail.com',
        'reply_body',
        'html',
        'test.onmicrosoft.com',
        email_cc,
        email_bcc,
        'reply_html_body',
        {},
        'item_id',
        '12345678',
        'test.onmicrosoft.com'
    )
    assert result == expected_result


def test_validate_email_sent_fails(mocker):
    """
    Given -
        a random error message which is returned from reply-mail executed command.
    When -
        executing the 'send_reply' function
    Then -
        an error message would be returned.
    """
    from SendEmailReply import validate_email_sent
    reply_mail_error = util_load_json('test_data/reply_mail_error.json')
    mocker.patch('SendEmailReply.execute_reply_mail', return_value=reply_mail_error)

    return_error_mock = mocker.patch("SendEmailReply.return_error")
    validate_email_sent('', '', False, '', '', 'html', '', '', '', '', {}, '', '', '')
    assert return_error_mock.call_count == 1
    assert return_error_mock.call_args[0][
        0] == 'Error:\n Command reply-mail in module EWS Mail Sender requires argument inReplyTo that is missing (7)'


@pytest.mark.parametrize(
    "test_args, expected_response",
    [
        ((1, 'Email Subject', False, 'end_user@company.com', 'Reply body.', 'html', 'soc_sender@company.com',
          'cc_user@company.com', 'bcc_user@company.com', '<html><body>Reply body.</body></html',
          ['10', '12'], '5', '12345678', 'soc_sender@company.com'),
         {'to': 'end_user@company.com', 'inReplyTo': '5',
          'subject': '<12345678> Email Subject', 'cc': 'cc_user@company.com',
          'bcc': 'bcc_user@company.com',
          'htmlBody': '<html><body>Reply body.</body></html',
          'body': 'Reply body.', 'attachIDs': '10,12',
          'replyTo': 'soc_sender@company.com', 'using': 'soc_sender@company.com', 'bodyType': 'html'}
         ),
        ((1, 'Email Subject', False, 'end_user@company.com', 'Reply body.', 'html', 'soc_sender@company.com',
          'cc_user@company.com', 'bcc_user@company.com', '<html><body>Reply body.</body></html',
          ['10', '12'], '5', '12345678', ''),
         {'to': 'end_user@company.com', 'inReplyTo': '5',
          'subject': '<12345678> Email Subject', 'cc': 'cc_user@company.com',
          'bcc': 'bcc_user@company.com',
          'htmlBody': '<html><body>Reply body.</body></html',
          'body': 'Reply body.', 'attachIDs': '10,12',
          'replyTo': 'soc_sender@company.com', 'bodyType': 'html'}
         ),
        ((2, 'Email Subject', True, 'end_user@company.com', 'Reply body.', 'html', 'soc_sender@company.com',
          'cc_user@company.com', 'bcc_user@company.com', '<html><body>Reply body.</body></html',
          ['10', '12'], '5', '12345678', 'soc_sender@company.com'),
         {'to': 'end_user@company.com', 'inReplyTo': '5',
          'subject': '<12345678> [2] Email Subject', 'cc': 'cc_user@company.com',
          'bcc': 'bcc_user@company.com',
          'htmlBody': '<html><body>Reply body.</body></html',
          'body': 'Reply body.', 'attachIDs': '10,12',
          'replyTo': 'soc_sender@company.com', 'using': 'soc_sender@company.com', 'bodyType': 'html'}
         ),
        ((2, 'Email Subject', True, 'end_user@company.com', 'Reply body.', 'html', 'soc_sender@company.com',
          'cc_user@company.com', 'bcc_user@company.com', '<html><body>Reply body.</body></html',
          ['10', '12'], '5', '12345678', ''),
         {'to': 'end_user@company.com', 'inReplyTo': '5',
          'subject': '<12345678> [2] Email Subject', 'cc': 'cc_user@company.com',
          'bcc': 'bcc_user@company.com',
          'htmlBody': '<html><body>Reply body.</body></html',
          'body': 'Reply body.', 'attachIDs': '10,12',
          'replyTo': 'soc_sender@company.com', 'bodyType': 'html'}
         )
    ]
)
def test_execute_reply_mail(test_args, expected_response, mocker):
    """Unit Test
    Given
    - function is called to send an email reply
    When
    - All input arguments are correctly set
    Then
    - Validate that 'reply-mail' command is called and supplied with a correctly formatted set of mail content
    """
    from SendEmailReply import execute_reply_mail
    import SendEmailReply
    execute_command_mocker = mocker.patch.object(demisto, 'executeCommand', return_value=True)
    mocker.patch.object(SendEmailReply, 'return_error', return_value=True)
    execute_reply_mail(*test_args)
    execute_command_call_args = execute_command_mocker.call_args
    assert execute_command_call_args.args[1] == expected_response


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
    "list_response, expected_result",
    [
        (util_load_json('test_data/getList_querywindow_success.json'), 'success'),
        (util_load_json('test_data/getList_querywindow_error.json'), 'fail')
    ]
)
def test_get_query_window(list_response, expected_result, mocker):
    """
    Unit Test Scenario 1 - List exists
        Given
        - Query window value stored in XSOAR List
        When
        - List content is returned successfully
        Then
        - Validate that the function returns the correct window based on the list response
    Unit Test Scenario 2 - List retrieval fails
        Given
        - Query window value stored in XSOAR List
        When
        - List retrieval results in an error
        Then
        - Validate that the function returns the default '60 days' window
        - Validate that a debug message is saved indicating the list couldn't be fetched
    """
    from SendEmailReply import get_query_window
    mocker.patch.object(demisto, 'executeCommand', return_value=list_response)
    debug_mocker = mocker.patch.object(demisto, 'debug')
    result = get_query_window()
    debug_mocker_call_args = debug_mocker.call_args
    if expected_result == 'success':
        assert result == '90 days'
    elif expected_result == 'fail':
        assert result == '60 days'
        assert debug_mocker_call_args.args[0] == 'Error occurred while trying to load the `XSOAR - Email ' \
                                                 'Communication Days To Query` list. Using the default query time - ' \
                                                 '60 days'


@pytest.mark.parametrize(
    "notes, attachments, expected_results",
    [
        (
            [{'Metadata': {'user': 'DBot'}, 'Contents': 'note1'}, {'Metadata': {'user': 'DBot'}, 'Contents': 'note2'}],
            [{'name': 'attachment1.png'}, {'name': 'attachment2.png'}],
            "DBot: \n\nnote1\n\nDBot: \n\nnote2\n\nAttachments: ['attachment1.png', 'attachment2.png']\n\n"
        ),
        (
            [{'Metadata': {'user': 'DBot'}, 'Contents': 'note1'}, {'Metadata': {'user': 'DBot'}, 'Contents': 'note2'}],
            [],
            "DBot: \n\nnote1\n\nDBot: \n\nnote2\n\n"
        ),
        (
            [{'Metadata': {'user': 'DBot'}, 'Contents': 'note1'}, {'Metadata': {'user': 'DBot'}, 'Contents': 'note2'}],
            "[]",
            "DBot: \n\nnote1\n\nDBot: \n\nnote2\n\n"
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


def test_get_email_threads(mocker):
    """Unit Test
    Given
    - Function is called to fetch email threads from current incident
    When
    - Context contains email threads
    Then
    - Validate that function returns email thread data
    """
    from SendEmailReply import get_email_threads
    import SendEmailReply
    email_threads = util_load_json('test_data/email_threads.json')
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(SendEmailReply, 'dict_safe_get', return_value=email_threads)
    result = get_email_threads('1')
    assert result == email_threads


@pytest.mark.parametrize(
    "email_code, email_threads, scenario",
    [
        ('69433507', util_load_json('test_data/email_threads.json'), 'thread_found'),
        ('123', util_load_json('test_data/email_threads.json'), 'thread_notfound'),
        ('69433507',
         [{'EmailCommsThreadId': '69433507',
           'EmailCommsThreadNumber': '0',
           'EmailCC': 'cc_user@company.com',
           'EmailBCC': 'bcc_user@company.com',
           'EmailBody': 'Email body.',
           'EmailFrom': 'soc_sender@company.com',
           'EmailHTML': '<html><body>Email body.</body></html>',
           'MessageID': '5',
           'EmailReceived': 'soc_sender@company.com',
           'EmailReplyTo': 'soc_sender@company.com',
           'EmailSubject': 'Email Subject',
           'EmailTo': 'end_user@company.com',
           'EmailAttachments': 'None',
           'MessageDirection': 'outbound',
           'MessageTime': '2022-02-04T20:56:53UTC'}], 'thread_found')
    ]
)
def test_create_thread_context(email_code, email_threads, scenario, mocker):
    """Unit test
        Given:
        - all required function arguments are provided
        When:
        - creating new context entry to store email thread data
        Then
        - validate that function calls appendContext() with all arguments and data needed to properly create
          the required context entry
    """
    from SendEmailReply import create_thread_context
    import SendEmailReply

    # Mock function to get current time string to match the expected result
    mocker.patch('SendEmailReply.get_utc_now',
                 return_value=datetime.strptime('2022-02-04T20:58:20UTC', "%Y-%m-%dT%H:%M:%SUTC"))
    mocker.patch.object(SendEmailReply, 'get_email_threads', return_value=email_threads)
    append_context_mocker = mocker.patch.object(SendEmailReply, "appendContext", return_value=True)
    create_thread_context(email_code, 'cc_user@company.com', 'bcc_user@company.com',
                          'Email body.', 'soc_sender@company.com', '<html>body><Email body.</body></html>',
                          '10', 'soc_sender@company.com', 'soc_sender@company.com',
                          'Email Subject', 'end_user@company.com', '123', '')
    call_args = append_context_mocker.call_args
    if scenario == 'thread_found':
        expected = {'EmailCommsThreadId': '69433507', 'EmailCommsThreadNumber': '0',
                    'EmailCC': 'cc_user@company.com', 'EmailBCC': 'bcc_user@company.com',
                    'EmailBody': 'Email body.', 'EmailFrom': 'soc_sender@company.com',
                    'EmailHTML': '<html>body><Email body.</body></html>', 'MessageID': '10',
                    'EmailReceived': 'soc_sender@company.com', 'EmailReplyTo': 'soc_sender@company.com',
                    'EmailSubject': 'Email Subject', 'EmailTo': 'end_user@company.com', 'EmailAttachments': '',
                    'MessageDirection': 'outbound', 'MessageTime': '2022-02-04T20:58:20UTC'}

        assert call_args.args[1] == expected
    elif scenario == 'thread_notfound':
        expected = {'EmailCommsThreadId': '123', 'EmailCommsThreadNumber': '2',
                    'EmailCC': 'cc_user@company.com', 'EmailBCC': 'bcc_user@company.com',
                    'EmailBody': 'Email body.', 'EmailFrom': 'soc_sender@company.com',
                    'EmailHTML': '<html>body><Email body.</body></html>', 'MessageID': '10',
                    'EmailReceived': 'soc_sender@company.com', 'EmailReplyTo': 'soc_sender@company.com',
                    'EmailSubject': 'Email Subject', 'EmailTo': 'end_user@company.com', 'EmailAttachments': '',
                    'MessageDirection': 'outbound', 'MessageTime': '2022-02-04T20:58:20UTC'}
        assert call_args.args[1] == expected


@pytest.mark.parametrize(
    "test_args, expected_result, expected_message",
    [
        (
            (1, 'Email Subject', False, 'end_user@company.com', 'Email Body', 'soc_sender@company.com', '', '',
             '<html><body>Email Body</body></html>', 'html', [], '12345678', 'soc_sender@company.com', 'attachment.txt', ''),
            (1, 'Email Subject', False, 'end_user@company.com', 'Email Body', 'soc_sender@company.com', '', '',
             'Email Body + Signature', 'html', [], 'attachment.txt', '12345678', 'soc_sender@company.com', ''),
            'Mail sent successfully. To: end_user@company.com'),
        (
            (1, 'Email Subject', False, 'end_user@company.com', 'Email Body', 'soc_sender@company.com',
             'cc_user@company.com', '',
             '<html><body>Email Body</body></html>', 'html', [], '12345678', 'soc_sender@company.com', 'attachment.txt', ''),
            (1, 'Email Subject', False, 'end_user@company.com', 'Email Body', 'soc_sender@company.com',
             'cc_user@company.com', '',
             'Email Body + Signature', 'html', [], 'attachment.txt', '12345678', 'soc_sender@company.com', ''),
            'Mail sent successfully. To: end_user@company.com Cc: cc_user@company.com'),
        (
            (1, 'Email Subject', False, 'end_user@company.com', 'Email Body', 'soc_sender@company.com', '',
             'bcc_user@company.com', '<html><body>Email Body</body></html>', 'html', [], '12345678',
             'soc_sender@company.com',
             'attachment.txt', ''),
            (1, 'Email Subject', False, 'end_user@company.com', 'Email Body', 'soc_sender@company.com', '',
             'bcc_user@company.com',
             'Email Body + Signature', 'html', [], 'attachment.txt', '12345678', 'soc_sender@company.com', ''),
            'Mail sent successfully. To: end_user@company.com Bcc: bcc_user@company.com')
    ]
)
def test_send_new_email(test_args, expected_result, expected_message, mocker):
    """Unit test
        Given:
        - All required function arguments are provided
        When:
        - Appending email signature and calling send_new_mail_request function
        Then
        - Validate that the email signature is appended to 'email_html_body' and arguments are correctly
          passed to 'send_new_mail_request'
    """
    from SendEmailReply import send_new_email
    import SendEmailReply
    mocker.patch.object(SendEmailReply, 'append_email_signature', return_value='Email Body + Signature')
    send_new_mail_request_mocker = mocker.patch.object(SendEmailReply, 'send_new_mail_request',
                                                       return_value=[{'Contents': 'Success', 'Type': 1}])
    message = send_new_email(*test_args)
    send_new_mail_request_args = send_new_mail_request_mocker.call_args
    assert message == expected_message
    assert send_new_mail_request_args.args == expected_result


@pytest.mark.parametrize(
    "email_selected_thread, email_thread, expected_result",
    [
        ('0', util_load_json('test_data/email_threads.json')[0], 'success'),
        ('42', util_load_json('test_data/email_threads.json')[0], 'fail')
    ]
)
def test_resend_first_contact(email_selected_thread, email_thread, expected_result, mocker):
    """Unit Test
    Given
    - function is called to re-send a first-contact email message
    When
    - All input arguments are  set
    Then
    - Validate that 'send_new_email' is called if selected thread is found
    - Validate that an error is returned if selected thread is not found
    """
    from SendEmailReply import resend_first_contact
    import SendEmailReply
    mocker.patch.object(SendEmailReply, 'get_entry_id_list', return_value=['5', '10'])
    mocker.patch.object(SendEmailReply, 'format_body', return_value=('<html><body>Resending email.</body></html>',
                                                                     '<html><body>Resending email.</body></html>'))
    mocker.patch.object(SendEmailReply, 'get_email_cc', return_value='')
    send_new_email_mocker = mocker.patch.object(SendEmailReply, 'send_new_email', return_value=True)
    return_error_mocker = mocker.patch.object(SendEmailReply, 'return_error', return_value=True)
    result = resend_first_contact(email_selected_thread, email_thread, 1, '', '', 'Resending email.', 'html', '', '',
                                  'soc_sender@company.com', 'soc_sender@company.com', '', False)
    send_new_email_args = send_new_email_mocker.call_args
    return_error_args = return_error_mocker.call_args
    if expected_result == 'success':
        assert result is True
        assert send_new_email_args.args == (1, '<69433507> Test Email 2', False, 'end_user@company.com',
                                            'Resending email.', 'soc_sender@company.com', '', '',
                                            '<html><body>Resending email.</body></html>', 'html', ['5', '10'],
                                            '69433507', 'soc_sender@company.com', '',
                                            '<html><body>Resending email.</body></html>')
    if expected_result == 'fail':
        assert return_error_args.args[0] == ('The selected Thread Number to respond to (42) does not exist.  '
                                             'Please choose a valid Thread Number and re-try.')


@pytest.mark.parametrize(
    "email_code",
    [
        '12345678',
        ''
    ]
)
def test_single_thread_reply(email_code, mocker):
    """Unit Test
    Given
    - function is called to send a new email message
    When
    - All input arguments are correctly set
    Then
    - Validate that 'validate_email_sent' function is called and supplied with a correctly formatted set of mail content
    - Validate that if no email_code is provided, 'get_unique_code' is called to generate one
    """

    def get_reply_body_side_effect(notes, incident_id, attachments, reputation_calc_async):  # noqa
        return 'Email body.', '<html><body>Email body.</body></html>', '<html><body>Email body.</body></html>'

    from SendEmailReply import single_thread_reply
    import SendEmailReply
    mocker.patch.object(SendEmailReply, 'get_unique_code', return_value='12345678')
    execute_command_mocker = mocker.patch.object(demisto, 'executeCommand', return_value=True)
    mocker.patch.object(SendEmailReply, 'get_entry_id_list', return_value=['5', '10'])
    mocker.patch.object(SendEmailReply, 'get_email_cc', return_value='')
    mocker.patch.object(SendEmailReply, 'get_reply_body', side_effect=get_reply_body_side_effect)
    validate_email_sent_mocker = mocker.patch.object(SendEmailReply, 'validate_email_sent', return_value=True)
    single_thread_reply(email_code, 1, 'cc_user@company.com', '', ['5'], 'html', '', '', 'Email Subject', False,
                        'end_user@company.com', 'soc_sender@company.com', 10, 'soc_sender@company.com')
    validate_mail_sent_call_args = validate_email_sent_mocker.call_args
    execute_command_call_args = execute_command_mocker.call_args
    assert validate_mail_sent_call_args.args == (1, 'Email Subject', False, 'end_user@company.com', 'Email body.', 'html',
                                                 'soc_sender@company.com', '', '',
                                                 '<html><body>Email body.</body></html>', ['5', '10'], 10,
                                                 '12345678', 'soc_sender@company.com')
    if not email_code:
        assert execute_command_call_args.args == ('setIncident',
                                                  {'id': 1, 'customFields': {'emailgeneratedcode': '12345678'}})


@pytest.mark.parametrize(
    "test_args, expected_result",
    [
        ((1, 'Email Subject', False, 'end_user@company.com', 'Message body.', 'soc_sender@company.com',
          'cc_user@company.com', 'bcc_user@company.com', '<html><body>Reply body.</body></html', 'html', ['10', '12'], '',
          '12345678', 'soc_sender@company.com', ''),
         {'to': 'end_user@company.com', 'subject': '<12345678> Email Subject',
          'cc': 'cc_user@company.com', 'bcc': 'bcc_user@company.com',
          'htmlBody': '<html><body>Reply body.</body></html',
          'body': 'Message body.', 'bodyType': 'html', 'attachIDs': '10,12',
          'replyTo': 'soc_sender@company.com', 'using': 'soc_sender@company.com'}
         ),
        ((1, 'Email Subject', False, 'end_user@company.com', 'Message body.', 'soc_sender@company.com',
          'cc_user@company.com', 'bcc_user@company.com', '<html><body>Reply body.</body></html', 'html', ['10', '12'], '',
          '12345678', '', ''),
         {'to': 'end_user@company.com', 'subject': '<12345678> Email Subject',
          'cc': 'cc_user@company.com', 'bcc': 'bcc_user@company.com',
          'htmlBody': '<html><body>Reply body.</body></html',
          'body': 'Message body.', 'bodyType': 'html', 'attachIDs': '10,12',
          'replyTo': 'soc_sender@company.com'}
         )
    ]
)
def test_send_new_mail_request(test_args, expected_result, mocker):
    """Unit Test
    Given
    - function is called to send a new email message
    When
    - All input arguments are correctly set
    Then
    - Validate that 'send-mail' command is called and supplied with a correctly formatted set of mail content
    """
    from SendEmailReply import send_new_mail_request
    import SendEmailReply
    execute_command_mocker = mocker.patch.object(demisto, 'executeCommand', return_value='Success')
    mocker.patch.object(SendEmailReply, 'return_error', return_value=True)
    mocker.patch.object(SendEmailReply, 'create_thread_context', return_value=True)
    result = send_new_mail_request(*test_args)
    execute_command_call_args = execute_command_mocker.call_args
    assert execute_command_call_args.args[1] == expected_result
    assert result == 'Success'


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
    set_incident_mocker = mocker.patch.object(demisto, 'executeCommand', return_value=True)
    mocker.patch.object(SendEmailReply, 'get_entry_id_list', return_value=[])
    mocker.patch.object(SendEmailReply, 'format_body', return_value=('<html>Some HTML</html>', '<html>Some HTML</html>'))
    send_new_email_mocker = mocker.patch.object(SendEmailReply, 'send_new_email', return_value=True)
    reset_fields_mocker = mocker.patch.object(SendEmailReply, 'reset_fields', return_value=True)
    if scenario == 'required_fields_missing':
        # Test Scenario 1
        expected = "The following required fields have not been set. Please set them and try again. " \
                   "['New Email Subject', 'New Email Recipients', 'New Email Body']"
        multi_thread_new('', False, '', '', 'html', 1, '12345678', '', '', 'soc_sender@company.com', 'cc_user@company.com',
                         'bcc_user@company.com', 'soc_sender@company.com', '')
        call_args = return_error_mocker.call_args
        assert call_args.args[0] == expected
    if scenario == 'no_codes_present':
        # Test Scenario 2
        multi_thread_new('New Subject', False, 'end_user@company.com', 'Email Body', 'html', 1, '', '', '',
                         'soc_sender@company.com', 'cc_user@company.com', 'bcc_user@company.com',
                         'soc_sender@company.com', '')
        set_incident_call_args = set_incident_mocker.call_args
        send_new_email_mocker_args = send_new_email_mocker.call_args
        assert set_incident_call_args.args[1] == {'id': 1, 'customFields': {'emailgeneratedcodes': '87654321'}}
        valid_args = (1, 'New Subject', False, 'end_user@company.com', 'Email Body', 'soc_sender@company.com',
                      'cc_user@company.com', 'bcc_user@company.com', '<html>Some HTML</html>', 'html', [], '87654321',
                      'soc_sender@company.com', '', '<html>Some HTML</html>')
        assert send_new_email_mocker_args.args == valid_args
        assert reset_fields_mocker.called is True
    if scenario == 'codes_present':
        # Test Scenario 3
        multi_thread_new('New Subject', False, 'end_user@company.com', 'Email Body', 'html', 1, '12345678', '', '',
                         'soc_sender@company.com', 'cc_user@company.com', 'bcc_user@company.com',
                         'soc_sender@company.com', '')
        set_incident_call_args = set_incident_mocker.call_args
        send_new_email_mocker_args = send_new_email_mocker.call_args
        assert set_incident_call_args.args[1] == {'id': 1, 'customFields': {'emailgeneratedcodes': '12345678,87654321'}}
        valid_args = (1, 'New Subject', False, 'end_user@company.com', 'Email Body', 'soc_sender@company.com',
                      'cc_user@company.com', 'bcc_user@company.com', '<html>Some HTML</html>', 'html', [], '87654321',
                      'soc_sender@company.com', '', '<html>Some HTML</html>')
        assert send_new_email_mocker_args.args == valid_args
        assert reset_fields_mocker.called is True


def test_collect_thread_details():
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
    mocker.patch.object(SendEmailReply, 'reset_fields', return_value=True)
    mocker.patch.object(SendEmailReply, 'return_results', return_value=True)
    mocker.patch.object(SendEmailReply, 'format_body', return_value=(
        '<html><body>Email body</body></html>', '<html><body>Email body</body></html>'))
    mocker.patch.object(SendEmailReply, 'append_email_signature',
                        return_value='<html><body>Email body+signature</body></html>')
    reset_fields_mocker = mocker.patch.object(SendEmailReply, 'reset_fields', return_value=True)
    validate_email_sent_mocker = mocker.patch.object(SendEmailReply, 'validate_email_sent', return_value=True)
    create_context_mocker = mocker.patch.object(SendEmailReply, 'create_thread_context', return_value=True)

    if scenario == 'single_outbound':
        # Return only a single email thread entry
        mocker.patch.object(SendEmailReply, 'get_email_threads', return_value=email_threads[0])
        multi_thread_reply('Email body', 'html', 1, 0, '', '', 'cc_user@company.com', 'bcc_user@company.com',
                           'soc_sender@company.com', 'soc_sender@company.com', '', False)
        expected = (0, {'EmailBCC': '', 'EmailBody': 'Outbound test message from XSOAR to User.', 'EmailCC': '',
                        'EmailCommsThreadId': '69433507', 'EmailCommsThreadNumber': '0',
                        'EmailFrom': 'soc_sender@company.com', 'EmailHTML': 'Outbound test message from XSOAR to User.',
                        'EmailReceived': '', 'EmailReplyTo': 'soc_sender@company.com',
                        'EmailSubject': '<69433507> Test Email 2', 'EmailTo': 'end_user@company.com',
                        'EmailAttachments': 'None', 'MessageDirection': 'outbound', 'MessageID': '',
                        'MessageTime': '2022-02-04T20:56:53UTC'}, 1, '', '', 'Email body', 'html',
                    'cc_user@company.com', 'bcc_user@company.com', 'soc_sender@company.com',
                    'soc_sender@company.com', '', False)
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
        multi_thread_reply('Email body', 'html', 1, 0, '', '', 'cc_user@company.com', 'bcc_user@company.com',
                           'soc_sender@company.com', 'soc_sender@company.com', '', False)

        expected = (0, {'EmailBCC': '', 'EmailBody': 'Outbound test message from XSOAR to User.', 'EmailCC': '',
                        'EmailCommsThreadId': '87692312', 'EmailCommsThreadNumber': '1',
                        'EmailFrom': 'soc_sender@company.com', 'EmailHTML': 'Outbound test message from XSOAR to User.',
                        'EmailReceived': '', 'EmailReplyTo': 'soc_sender@company.com',
                        'EmailSubject': '<87692312> Test Email 4', 'EmailTo': 'end_user@company.com',
                        'EmailAttachments': 'None', 'MessageDirection': 'outbound', 'MessageID': '',
                        'MessageTime': '2022-02-04T20:56:53UTC'}, 1, '', '', 'Email body', 'html',
                    'cc_user@company.com', 'bcc_user@company.com', 'soc_sender@company.com',
                    'soc_sender@company.com', '', False)
        resend_first_contact_call_args = resend_first_contact_mocker.call_args
        assert resend_first_contact_call_args.args == expected
        assert reset_fields_mocker.called is True
    elif scenario == 'replies_present':
        thread_details = (
            True, 'AAMkAGRcOGZlZTEzLTkyZGDtNGJkNy1iOWMxLYM0NTAwODZhZjlxNABGAAAAAAAP2ksrJ8icRL4Zhadm7iVXBwAkkBJXBb0'
                  'sRJWC0zdXEMqsAAAAAAEMAAAkkBJFBb0fRJWC0zdXEMqsABApcWVYAAA=', False, '87692312',
            'RE: <87692312> Test Email 4', 'end_user@company.com, soc_sender@company.com',
            'soc_sender@company.com', '', '', 2)
        mocker.patch.object(SendEmailReply, 'collect_thread_details', return_value=thread_details)
        # Return all email thread entries
        mocker.patch.object(SendEmailReply, 'get_email_threads', return_value=email_threads)
        validate_email_sent_expected = (1, '<87692312> Test Email 4', False, 'end_user@company.com', 'Email body', 'html',
                                        'soc_sender@company.com', 'cc_user@company.com', 'bcc_user@company.com',
                                        '<html><body>Email body</body></html>', [],
                                        'AAMkAGRcOGZlZTEzLTkyZGDtNGJkNy1iOWMxLYM0NTAwODZhZjlxNABGAAAAAAAP2ksrJ8icRL4Zha'
                                        'dm7iVXBwAkkBJXBb0sRJWC0zdXEMqsAAAAAAEMAAAkkBJFBb0fRJWC0zdXEMqsABApcWVYAAA=',
                                        '87692312', 'soc_sender@company.com')
        create_context_expected = ('87692312', 'cc_user@company.com', 'bcc_user@company.com',
                                   'Email body', 'soc_sender@company.com',
                                   '<html><body>Email body+signature</body></html>', '', '', 'soc_sender@company.com',
                                   '<87692312> Test Email 4', 'end_user@company.com', 1, '')

        # Execute the tested function
        multi_thread_reply('Email body', 'html', 1, 1, '', '', 'cc_user@company.com', 'bcc_user@company.com',
                           'soc_sender@company.com', 'soc_sender@company.com', '', False)

        validate_email_sent_call_args = validate_email_sent_mocker.call_args
        create_context_call_args = create_context_mocker.call_args
        assert validate_email_sent_call_args.args == validate_email_sent_expected
        assert create_context_call_args.args == create_context_expected
        assert reset_fields_mocker.called is True


@pytest.mark.parametrize(
    "new_thread",
    [
        'n/a',
        'true',
        'false'
    ]
)
def test_main(new_thread, mocker):
    """
    Unit Test Scenario 1 new_thread = 'n/a'
        Given
         - Script is called to send an email message
        When
         - new_thread = 'n/a', indicating this script is being called from the Email Communication layout
        Then
         - Validate that function single_thread_reply is called with all correct arguments
    Unit Test Scenario 1 new_thread = 'true'
        Given
         - Script is called to send an email message
        When
         - new_thread = 'true', indicating this script is being called from the Email Threads layout and the message
           to be sent is a new first-contact email
        Then
         - Validate that function multi_thread_new is called with all correct arguments
    Unit Test Scenario 1 new_thread = 'false'
        Given
         - Script is called to send an email message
        When
         - new_thread = 'false', indicating this script is being called from the Email Threads layout and the message
           to be sent is a reply to an existing email chain
        Then
         - Validate that function multi_thread_reply is called with all correct arguments
    """
    from SendEmailReply import main
    import SendEmailReply
    incident = util_load_json('test_data/incident_data.json')
    input_args = {
        'service_mail': 'soc_sender@company.com',
        'files': {},
        'mail_sender_instance': 'mail-sender-instance-1',
        'new_thread': new_thread,
        'bodyType': 'html',
    }
    mocker.patch.object(demisto, 'args', return_value=input_args)
    mocker.patch.object(demisto, 'incident', return_value=incident)
    mocker.patch.object(SendEmailReply, 'get_mailbox_from_incident_labels', return_value='')
    mocker.patch.object(SendEmailReply, 'get_email_recipients', return_value='end_user@company.com')
    mocker.patch.object(demisto, 'executeCommand', return_value='')
    single_thread_reply_mocker = mocker.patch.object(SendEmailReply, 'single_thread_reply', return_value=True)
    multi_thread_new_mocker = mocker.patch.object(SendEmailReply, 'multi_thread_new', return_value=True)
    multi_thread_reply_mocker = mocker.patch.object(SendEmailReply, 'multi_thread_reply', return_value=True)
    main()
    if new_thread == 'n/a':
        single_thread_reply_args = single_thread_reply_mocker.call_args
        expected_args = ('87654321', '10', '', 'test_cc@example.com', '', 'html', [], {}, None, False, 'end_user@company.com',
                         'soc_sender@company.com', '123456', 'mail-sender-instance-1', False)
        assert single_thread_reply_args.args == expected_args
    elif new_thread == 'true':
        multi_thread_new_args = multi_thread_new_mocker.call_args
        expected_args = ('Test Email Subject.', False, 'test_recipient@example.com', 'This is a test email.', 'html', '10',
                         None, {}, {}, 'soc_sender@company.com', 'test_cc@example.com', 'test_bcc@example.com',
                         'mail-sender-instance-1', 'None')
        assert multi_thread_new_args.args == expected_args
    elif new_thread == 'false':
        multi_thread_reply_args = multi_thread_reply_mocker.call_args
        expected_args = ('This is a test email.', 'html', '10', 1, {}, {}, 'test_cc@example.com', 'test_bcc@example.com',
                         'soc_sender@company.com', 'mail-sender-instance-1', 'None', False)
        assert multi_thread_reply_args.args == expected_args


# Parametrized test for happy path scenarios with various realistic markdown inputs
@pytest.mark.parametrize("input_md, expected_html, test_id", [
    # Test ID: #1 - Simple text conversion
    ("Hello, World!", "<p>Hello, World!</p>", "simple_text"),

    # Test ID: #2 - Header conversion
    ("# Header 1", "<h1>Header 1</h1>", "header_conversion"),

    # Test ID: #3 - Table conversion
    ("| Header1 | Header2 |\n| ------- | ------- |\n| Cell1   | Cell2   |",
     "<table>\n<thead>\n<tr>\n<th>Header1</th>\n<th>Header2</th>\n</tr>\n</thead>\n<tbody>\n<tr>\n<td>Cell1</td>\n"
     "<td>Cell2</td>\n</tr>\n</tbody>\n</table>",
     "table_conversion"),

    # Test ID: #4 - Emphasis conversion using legacy syntax
    ("_italic_ **bold**",
     "<p><em>italic</em> <strong>bold</strong></p>",
     "emphasis_conversion"),

    # Test ID: #5 - List conversion
    ("- Item 1\n- Item 2",
     "<ul>\n<li>Item 1</li>\n<li>Item 2</li>\n</ul>",
     "list_conversion"),

    # Test ID: #6 - New lines to <br> conversion
    ("Line 1\nLine 2",
     "<p>Line 1<br />\nLine 2</p>",
     "newline_to_br_conversion"),
], ids=lambda test_id: test_id)
def test_format_body_happy_path(input_md, expected_html, test_id):
    # Act
    from SendEmailReply import format_body
    result = format_body(input_md)

    # Assert
    assert result[1] == expected_html, f"Test failed for {test_id}"


# Parametrized test for edge cases
@pytest.mark.parametrize("input_md, expected_html, test_id", [
    # Test ID: #1 - Empty string
    ("", ("", ""), "empty_string"),

    # Test ID: #2 - Markdown with only special characters
    ("# $%^&*()",
     ('<h1>$%^&amp;*()</h1>', '<h1>$%^&amp;*()</h1>'),
     "special_characters_only"),
], ids=lambda test_id: test_id)
def test_format_body_edge_cases(input_md, expected_html, test_id):
    # Act
    from SendEmailReply import format_body
    result = format_body(input_md)

    # Assert
    assert result == expected_html, f"Test failed for {test_id}"


# Parametrized test for edge cases
@pytest.mark.parametrize("input_md, expected_html, test_id", [
    # Test ID: #1 - Demisto custom markdown underline syntax.
    ("+underline+", ("<p><u>underline</u></p>", "<p><u>underline</u></p>"), "underline"),

    # Test ID: #2 - Demisto custom markdown strikethrough syntax.
    ("~~strikethrough~~", ("<p><s>strikethrough</s></p>", "<p><s>strikethrough</s></p>"), "strikethrough"),
], ids=lambda test_id: test_id)
def test_demisto_custom_markdown_syntax(input_md, expected_html, test_id):
    # Act
    from SendEmailReply import format_body
    result = format_body(input_md)

    # Assert
    assert result == expected_html, f"Test failed for {test_id}"


@freeze_time("2024-02-22 10:00:00 UTC")
def test_get_unique_code_happy_path(mocker):
    # Arrange
    incident_id = "123"
    max_tries = 1000
    expected_code = "1231708596000000"
    mocker.patch('SendEmailReply.demisto', return_value=None)
    mocker.patch('SendEmailReply.get_incident_by_query', return_value=None)

    # Act
    code = get_unique_code(incident_id, max_tries)

    # Assert
    assert code == expected_code


@freeze_time("2024-02-22 10:00:00 UTC")
def test_get_unique_code_edge_cases(mocker):
    # Arrange
    incident_id = "1"
    max_tries = 1000
    expected_code = "0011708596000000"
    mocker.patch('SendEmailReply.get_incident_by_query', return_value=None)

    # Act
    code = get_unique_code(incident_id, max_tries)

    # Assert
    assert code == expected_code


@freeze_time("2024-02-22 10:00:00 UTC")
def test_get_unique_code_error_case(mocker):
    # Arrange
    incident_id = "123"
    max_tries = 0
    mocker.patch('SendEmailReply.get_incident_by_query', return_value=[{"id": "existing_incident"}])
    mocked_return_error = mocker.patch('SendEmailReply.return_error', side_effect=Exception('Error'))

# Act and Assert
    with pytest.raises(Exception):
        get_unique_code(incident_id, max_tries)
    mocked_return_error.assert_called_once_with(
        f'Failed to generate unique code for incident {incident_id} after {max_tries} tries')


def test_format_body(mocker):
    from SendEmailReply import format_body
    html_body = '![image](/markdown/image/aljhgfghdjakldvygi)'
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'FileID': '111'}])
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1234'})
    open_mock = mocker.mock_open(read_data=b'some binary data')
    mocker.patch('builtins.open', open_mock)
    result = format_body(html_body)
    expected_result = ('<p><img alt="image" src="/markdown/image/aljhgfghdjakldvygi" /></p>',
                       '<p><img alt="image" src="data:image/png;base64,c29tZSBiaW5hcnkgZGF0YQ==" /></p>')
    assert result == expected_result
