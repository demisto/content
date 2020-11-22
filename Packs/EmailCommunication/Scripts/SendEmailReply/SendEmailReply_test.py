import pytest
import json


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
                        'test3@gmail.com', 'reply_html_body', {}, 'item_id')
    assert "Mail sent successfully. To: test1@gmail.com,test2@gmail.com Cc: test3@gmail.com" == result


@pytest.mark.parametrize(
    "email_to, email_from, service_mail, excepted",
    [('["avishai@demistodev.onmicrosoft.com"]', "test123@gmail.com", "avishai@demistodev.onmicrosoft.com",
      {'test123@gmail.com'}),
     ('["avishai@demistodev.onmicrosoft.com", "test1@gmail.com"]', "test123@gmail.com",
      "avishai@demistodev.onmicrosoft.com", {'test123@gmail.com', 'test1@gmail.com'})])
def test_get_email_recipients(email_to, email_from, service_mail, excepted):
    """Unit test
        Given
        - Single email recipient, single email author, service mail.
        - Multiple email recipients, single email author, service mail.
        When
        - Getting the email recipients.
        Then
        - validate that the correct email recipients are returned.
        """
    from SendEmailReply import get_email_recipients

    result = set(get_email_recipients(email_to, email_from, service_mail).split(','))
    assert result == excepted


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
