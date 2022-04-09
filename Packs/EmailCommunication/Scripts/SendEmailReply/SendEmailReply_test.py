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
    "new_thread, thread_input_type",
    [('n/a', ''),
     ('true', ''),
     ('false', 'dict'),
     ('false', 'list')]
)
def test_main(new_thread, thread_input_type, mocker):
    """
    Unit test scenario - new_thread = 'n/a', thread_input_type = ''
        Given
         - Script is called to send an email message
        When
         - new_thread = 'n/a', indicating use by the generic 'Email Communication' layout workflow replying to message
        Then
         - validate that the new email is constructed and the send_reply function is called successfully
    Unit test scenario - new_thread = 'true', thread_input_type = ''
        Given
         - Script is called to send an email message
        When
         - new_thread = 'true', indicating use by incident types besides 'Email Communication' and sending a
         first-contact outbound email message
        Then
         - validate that the new email is constructed and the send_new_email function is called successfully
    Unit test scenario - new_thread = 'false', thread_input_type = 'dict'
        Given
         - Script is called to send an email message
        When
         - new_thread = 'false', indicating use by incident types besides 'Email Communication' and sending a
         reply to an existing email chain
         - 'EmailThreads' context key is type dict, indicating an attempt to reply to an email chain that has never
         received a reply from the end user and we must send a new email message rather than reply to one
        Then
         - validate that the new email is constructed and resend_first_contact is called successfully
    Unit test scenario - new_thread = 'false', thread_input_type = 'list'
        Given
         - Script is called to send an email message
        When
         - new_thread = 'false', indicating use by incident types besides 'Email Communication' and sending a
         reply to an existing email chain
         - 'EmailThreads' context key is type list, indicating there is at least one reply to the first-contact email
        Then
         - validate that the new email is constructed, re-using correct items from the existing email thread entries
         - validate that send_reply is called successfully
         - validate that create_thread_context is successfully called
    """
    def executeCommand_side_effects(command, args):
        if command == "setIncident":
            return True

    import SendEmailReply
    from SendEmailReply import main
    incident = util_load_json('test_data/incident_data.json')
    email_threads = util_load_json('test_data/email_threads.json')
    mocker.patch.object(demisto, 'incident', return_value=incident)
    input_args = {'service_mail': 'soc-sender@example.com', 'files': {}, 'attachment': {},
                  'mail_sender_instance': 'soc-sender@example.com', 'new_thread': new_thread}
    mocker.patch.object(demisto, 'args', return_value=input_args)
    mocker.patch.object(SendEmailReply, 'get_mailbox_from_incident_labels')
    mocker.patch.object(SendEmailReply, 'get_email_recipients', return_value='user@example.com')
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand_side_effects)
    mocker.patch.object(SendEmailReply, 'get_unique_code', return_value='12345678')
    mocker.patch.object(SendEmailReply, 'get_email_cc', return_value='')
    mocker.patch.object(SendEmailReply, 'get_reply_body', return_value=['Body text.', 'Body text.'])
    mocker.patch.object(SendEmailReply, 'get_entry_id_list', return_value=[])
    mocker.patch.object(SendEmailReply, 'append_email_signature', return_value='Body text.  Signature.')
    if thread_input_type == 'list' or '':
        mocker.patch.object(SendEmailReply, 'get_email_threads', return_value=email_threads)
    elif thread_input_type == 'dict':
        mocker.patch.object(SendEmailReply, 'get_email_threads', return_value=email_threads[0])
    send_reply_mocker = mocker.patch.object(SendEmailReply, 'send_reply',
                                            return_value='Mail sent successfully. To: user@example.com')
    mocker.patch.object(SendEmailReply, 'format_body', return_value='This is a test email.')
    send_new_email_mocker = mocker.patch.object(SendEmailReply, 'send_new_email',
                                                return_value='Mail sent successfully. To: user@example.com')
    mocker.patch.object(SendEmailReply, 'reset_fields', return_value=None)
    resend_first_contact_mocker = mocker.patch.object(SendEmailReply, 'resend_first_contact',
                                                      return_value='Mail sent successfully. To: user@example.com')
    create_thread_context_mocker = mocker.patch.object(SendEmailReply, 'create_thread_context')

    main()
    if new_thread == 'n/a':
        assert send_reply_mocker.called
    elif new_thread == 'true':
        assert send_new_email_mocker.called
    elif new_thread == 'false' and thread_input_type == 'dict':
        assert resend_first_contact_mocker.called
    elif new_thread == 'false' and thread_input_type == 'list':
        expected_reply = ('10', '<87692312> Test Email 4', 'user@example.com', 'This is a test email.',
                          'soc-sender@example.com', '', '', 'This is a test email.', [],
                          'AAMkAGRcOGZlZTEzLTkyZGDtNGJkNy1iOWMxLYM0NTAwODZhZjlxNABGAAAAAAAP2ksrJ8icRL4Zhadm7iVXBwA'
                          'kkBJXBb0sRJWC0zdXEMqsAAAAAAEMAAAkkBJFBb0fRJWC0zdXEMqsABApcWVYAAA=', '87692312',
                          'soc-sender@example.com')
        call_args = send_reply_mocker.call_args
        assert call_args.args == expected_reply
        assert send_reply_mocker.called
        assert create_thread_context_mocker.called
