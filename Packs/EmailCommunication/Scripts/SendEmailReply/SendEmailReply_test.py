import pytest
import json
import demistomock as demisto


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


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
    mocker.patch("SendEmailReply.send_mail_request", return_value=email_reply_response)
    result = send_reply('123', 'email_subject', 'test1@gmail.com,test2@gmail.com', 'reply_body', 'test.onmicrosoft.com',
                        'test3@gmail.com', 'reply_html_body', {}, 'item_id', '12345678')
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
    [([{'Metadata': {'user': 'DBot'}, 'Contents': 'note1'}, {'Metadata': {'user': 'DBot'}, 'Contents': 'note2'}],
      [{'name': 'attachment1.png'}, {'name': 'attachment2.png'}],
      "DBot: \nnote1\n\nDBot: \nnote2\n\nAttachments: ['attachment1.png', 'attachment2.png']\n\n"),
     ([{'Metadata': {'user': 'DBot'}, 'Contents': 'note1'}, {'Metadata': {'user': 'DBot'}, 'Contents': 'note2'}],
      [],
      "DBot: \nnote1\n\nDBot: \nnote2\n\n"),
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
    result = create_file_data_json(attachment_response)
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
