import pytest
import json


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


def test_send_reply(mocker):
    from SendEmailReply import send_reply, SendEmailReply
    email_reply_response = util_load_json('test_data/email_reply.json')
    mocker.patch.object(SendEmailReply, "send_mail_request", return_value=email_reply_response)
    result = send_reply('123', 'email_subject', 'test1@gmail.com,test2@gmail.com', 'reply_body', 'test.onmicrosoft.com',
                        'test3@gmail.com', 'reply_html_body', {}, "additional_header")
    assert "Mail sent successfully. To: test1@gmail.com,test2@gmail.com Cc: test3@gmail.com" == result


@pytest.mark.parametrize(
    "email_to, email_from, service_mail, excepted",
    [('["avishai@demistodev.onmicrosoft.com"]', "test123@gmail.com", "avishai@demistodev.onmicrosoft.com",
      {'test123@gmail.com'}),
     ('["avishai@demistodev.onmicrosoft.com", "test1@gmail.com"]', "test123@gmail.com",
      "avishai@demistodev.onmicrosoft.com", {'test123@gmail.com', 'test1@gmail.com'})])
def test_get_email_recipients(email_to, email_from, service_mail, excepted):
    from SendEmailReply import get_email_recipients

    result = set(get_email_recipients(email_to, email_from, service_mail).split(','))
    assert result == excepted


def test_create_file_data_json():
    from SendEmailReply import create_file_data_json
    attachment_response = util_load_json('test_data/attachment_example.json')
    expected_result = util_open_file('test_data/file_data.txt')
    result = create_file_data_json(attachment_response)
    assert result == expected_result


@pytest.mark.parametrize(
    "current_cc, additional_cc, excepted",
    [('test1@gmail.com, test2@gmail.com', 'test3@gmail.com,test4@gmail.com', 'test1@gmail.com,test2@gmail.com,'
                                                                             'test3@gmail.com,test4@gmail.com'),
     ('test1@gmail.com', '', 'test1@gmail.com'), ('', 'test1@gmail.com', 'test1@gmail.com')
     ])
def test_get_email_cc(current_cc, additional_cc, excepted):
    from SendEmailReply import get_email_cc
    result = get_email_cc(current_cc, additional_cc)
    assert result == excepted
