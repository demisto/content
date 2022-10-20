import pytest
from test_data import input_data

MOCK_MAIL_NO_LABELS = {
    u'internalDate': u'1572251535000',
    u'historyId': u'249781',
    u'payload': {
        u'mimeType': u'multipart/mixed',
        u'body': {u'size': 0},
        u'partId': u'',
        u'filename': u'',
        u'headers': [
            {
                u'name': u'Received',
                u'value': u'from 1041831412594 named unknown by gmailapi.google.com with '
                          u'HTTPREST; Mon, 28 Oct 2019 04:32:15 -0400'
            }, {
                u'name': u'Content-Type',
                u'value': u'mixed; boundary="===============4922146810840031257=="'
            }, {
                u'name': u'MIME-Version',
                u'value': u'1.0'
            }, {
                u'name': u'to',
                u'value': u'<some_mail>'
            }, {
                u'name': u'cc',
                u'value': u''
            }, {
                u'name': u'bcc',
                u'value': u''
            }, {
                u'name': u'from',
                u'value': u'<some_mail>'
            }, {
                u'name': u'subject',
                u'value': u'a mail subject'
            }, {
                u'name': u'reply-to',
                u'value': u''
            }, {
                u'name': u'Date',
                u'value': u'Mon, 28 Oct 2019 04:32:15 -0400'
            }, {
                u'name': u'Message-Id',
                u'value': u'<some_id>'
            }
        ],
        u'parts': [
            {
                u'mimeType': u'text/plain',
                u'headers': [
                    {
                        u'name': u'Content-Type',
                        u'value': u'text/plain; charset="utf-8"'
                    }, {
                        u'name': u'MIME-Version',
                        u'value': u'1.0'
                    }, {
                        u'name': u'Content-Transfer-Encoding',
                        u'value': u'base64'
                    }
                ],
                u'body': {
                    u'data': u'<data>',
                    u'size': 9
                },
                u'partId': u'0',
                u'filename': u''
            }
        ]
    },
    u'snippet': u'some info',
    u'sizeEstimate': 637,
    u'threadId': u'<id>',
    u'id': u'<id>'
}

EXPECTED_GMAIL_CONTEXT = {
    'To': u'<some_mail>',
    'Body': u'',
    'From': u'<some_mail>',
    'Attachments': u'',
    'Format': u'mixed',
    'Cc': u'',
    'Labels': '',
    'Mailbox': 'some_mail',
    'Headers': [
        {
            'Name': u'Received',
            'Value': u'from 1041831412594 named '
                     u'unknown by gmailapi.google.com with HTTPREST; Mon, 28 Oct 2019 04:32:15 -0400'
        }, {
            'Name': u'Content-Type',
            'Value': u'mixed; boundary="===============4922146810840031257=="'
        }, {
            'Name': u'MIME-Version',
            'Value': u'1.0'
        }, {
            'Name': u'to',
            'Value': u'<some_mail>'
        }, {
            'Name': u'cc',
            'Value': u''
        }, {
            'Name': u'bcc', 'Value': u''
        }, {
            'Name': u'from', 'Value': u'<some_mail>'
        }, {
            'Name': u'subject',
            'Value': u'a mail subject'
        }, {
            'Name': u'reply-to',
            'Value': u''
        }, {
            'Name': u'Date',
            'Value': u'Mon, 28 Oct 2019 04:32:15 -0400'
        }, {
            'Name': u'Message-Id',
            'Value': u'<some_id>'
        }
    ],
    'Html': None,
    'RawData': None,
    'ThreadId': u'<id>',
    'Date': 'Mon, 28 Oct 2019 04:32:15 -0400',
    'Bcc': u'',
    'Type': 'Gmail',
    'ID': u'<id>',
    'Subject': u'a mail subject'
}


def test_timestamp_to_date():
    from Gmail import create_base_time
    valid_timestamp = '1566819604000'
    valid_header_date = "Mon, 26 Aug 2019 14:40:04 +0300"
    # this does contain the utc time change
    invalid_header_date = "25 Aug 2019 06:25:38"
    # this does contain the utc time change
    semi_valid_header_date = "26 Aug 2019 14:40:04 +0300"
    assert str(create_base_time(valid_timestamp, valid_header_date)) == "Mon, 26 Aug 2019 14:40:04 +0300"
    assert str(create_base_time(valid_timestamp, semi_valid_header_date)) == "Mon, 26 Aug 2019 14:40:04 +0300"
    assert str(create_base_time(valid_timestamp, invalid_header_date)) == "Mon, 26 Aug 2019 11:40:04 -0000"


def test_move_to_gmt():
    from Gmail import move_to_gmt
    valid_header_date = "Mon, 26 Aug 2019 14:40:04 +0300"
    no_utc_header_date = "Mon, 26 Aug 2019 14:40:04 -0000"
    assert str(move_to_gmt(valid_header_date)) == "2019-08-26T11:40:04Z"
    assert str(move_to_gmt(no_utc_header_date)) == "2019-08-26T14:40:04Z"


def test_no_label_mail_context_creation():
    from Gmail import get_email_context
    context_gmail, _, _ = get_email_context(MOCK_MAIL_NO_LABELS, "some_mail")
    assert context_gmail.get('Labels') == EXPECTED_GMAIL_CONTEXT.get('Labels')
    assert context_gmail.get('To') == EXPECTED_GMAIL_CONTEXT.get('To')
    assert context_gmail.get('From') == EXPECTED_GMAIL_CONTEXT.get('From')
    assert context_gmail.get('Subject') == EXPECTED_GMAIL_CONTEXT.get('Subject')


def test_parse_privileges():
    from Gmail import parse_privileges
    privileges = [{'serviceId': '', 'privilegeName': 'name_no_id'}, {'serviceId': '', 'privilegeName': ''},
                  {'serviceId': 'id', 'privilegeName': 'name'}]
    assert sorted(parse_privileges(privileges), key=lambda i: i['Name']) == sorted(
        [{'ServiceID': 'id', 'Name': 'name'}, {'Name': 'name_no_id'}], key=lambda i: i['Name'])


def test_dict_keys_snake_to_camelcase():
    """
    Tests dict_keys_snake_to_camelcase method works as expected.
    e.g. family_name -> familyName
    """
    from Gmail import dict_keys_snake_to_camelcase
    dictionary = {
        'user_name': 'user1',
        'user_id': '2'
    }
    assert dict_keys_snake_to_camelcase(dictionary) == {'userName': 'user1', 'userId': '2'}


def test_labels_to_entry():
    """
    Given:
        gmail label api response

    When:
        executing labels_to_entry function.

    Then:
        the context and human readable are valid
    """
    from Gmail import labels_to_entry
    labels = [
        {
            "id": "CHAT",
            "labelListVisibility": "labelHide",
            "messageListVisibility": "hide",
            "name": "CHAT",
            "type": "system"
        },
        {
            "id": "SENT",
            "labelListVisibility": "labelHide",
            "messageListVisibility": "hide",
            "name": "SENT",
            "type": "system"
        }
    ]
    expected_human_readable = '### test\n|Name|ID|Type|MessageListVisibility|LabelListVisibility|' \
                              '\n|---|---|---|---|---|\n| CHAT | CHAT | system | hide | labelHide ' \
                              '|\n| SENT | SENT | system | hide | labelHide |\n'
    expected_context_output = [
        {
            "ID": "CHAT",
            "LabelListVisibility": "labelHide",
            "MessageListVisibility": "hide",
            "Name": "CHAT",
            "Type": "system",
            "UserID": "me"
        },
        {
            "ID": "SENT",
            "LabelListVisibility": "labelHide",
            "MessageListVisibility": "hide",
            "Name": "SENT",
            "Type": "system",
            "UserID": "me"
        }
    ]

    result = labels_to_entry("test", labels, "me")
    assert result.outputs == expected_context_output
    assert result.readable_output == expected_human_readable


@pytest.mark.parametrize('params_str, expected_result', [
    ("{\"varname\" :{\"value\": \"some value\", \"key\": \"context key\"}}", {'varname': "some value"})
])
def test_template_params(params_str, expected_result):
    """
    Tests template_params function.
        Given:
            - values are in the form of a JSON document.
        When:
            - sending email.
        Then:
            - the output dictionary is valid.
    """

    from Gmail import template_params

    assert template_params(params_str) == expected_result


@pytest.mark.parametrize('title, response, expected_result', [
    ('User 000000000000000000000:', input_data.response_test_users_to_entry,
     input_data.expected_result_test_users_to_entry)
])
def test_users_to_entry(title, response, expected_result):
    """
    Tests users_to_entry function.
        Given:
            - gmail get list of users api response.
        When:
            - executing users_to_entry function.
        Then:
            -the outputs, raw response, and human readable are valid.
    """

    from Gmail import users_to_entry

    result = users_to_entry(title, response)
    assert result.readable_output == expected_result.get("expected_human_readable")
    assert result.outputs == expected_result.get("expected_outputs")
    assert result.raw_response == expected_result.get('expected_raw_response')


@pytest.mark.parametrize('title, response, user_id, expected_result', [
    ('User johndoe@test.com:', [input_data.get_auto_replay_result],
     'johndoe@test.com', input_data.expected_result_test_autoreply_to_entry)
])
def test_autoreply_to_entry(title, response, user_id, expected_result):
    """
    Tests autoreply_to_entry function.
        Given:
            -gmail get autoreply api response (from get_autoreply function).
        When:
            - executing autoreply_to_entry function.
        Then:
            -the outputs, raw response, and human readable are valid.
    """

    from Gmail import autoreply_to_entry

    result = autoreply_to_entry(title, response, user_id)
    assert result.readable_output == expected_result.get("expected_human_readable")
    assert result.outputs == expected_result.get("expected_outputs")
    assert result.raw_response == expected_result.get('expected_raw_response')


@pytest.mark.parametrize('title, role, expected_result', [
    ('Role 00000000000000000 details:', input_data.role_test_role_to_entry, input_data.expected_result_test_role_to_entry)
])
def test_role_to_entry(title, role, expected_result):
    """
    Tests role_to_entry function.
        Given:
            - gmail get role api response (from get_role function).
        When:
            - executing role_to_entry function.
        Then:
            -the outputs, raw response, and human readable are valid.
    """

    from Gmail import role_to_entry

    result = role_to_entry(title, role)
    assert result.readable_output == expected_result.get("expected_human_readable")
    assert result.outputs == expected_result.get("expected_outputs")
    assert result.raw_response == expected_result.get('expected_raw_response')


@pytest.mark.parametrize('title, response, expected_result', [
    ('User Roles of 222222222222222222222:', input_data.get_user_role_mock_result,
     input_data.expected_result_user_roles_to_entry)
])
def test_user_roles_to_entry(title, response, expected_result):
    """
    Tests user_roles_to_entry function.
        Given:
            - gmail get user role api response (from get_user_role function).
        When:
            - executing user_roles_to_entry function.
        Then:
            -the outputs, raw response, and human readable are valid.
    """

    from Gmail import user_roles_to_entry

    result = user_roles_to_entry(title, response)
    assert result.readable_output == expected_result.get("expected_human_readable")
    assert result.outputs == expected_result.get("expected_outputs")
    assert result.raw_response == expected_result.get('expected_raw_response')


@pytest.mark.parametrize('title, response, expected_result', [
    ('Tokens:', input_data.get_user_tokens_mock_result,
     input_data.expected_result_test_tokens_to_entry)
])
def test_tokens_to_entry(title, response, expected_result):
    """
    Tests tokens_to_entry function.
        Given:
            - gmail get user tokens api response (from get_user_tokens function).
        When:
            - executing tokens_to_entry function.
        Then:
            -the outputs, raw response, and human readable are valid.
    """

    from Gmail import tokens_to_entry

    result = tokens_to_entry(title, response)
    assert result.readable_output == expected_result.get("expected_human_readable")
    assert result.outputs == expected_result.get("expected_outputs")
    assert result.raw_response == expected_result.get('expected_raw_response')


@pytest.mark.parametrize('title, response, to, emailfrom, cc, bcc, body, subject, expected_result', [
    ('Email sent:', [input_data.send_mail_mock_result], ['helloworld@gmail.com'],
     'test@gmail.com', [], [], None,
     'ls', input_data.expected_result_test_sent_mail_to_entry)
])
def test_sent_mail_to_entry(title, response, to, emailfrom, cc, bcc, body, subject, expected_result):
    """
    Tests sent_mail_to_entry function.
        Given:
            - gmail send mail api response (from send_mail function).
        When:
            - executing sent_mail_to_entry function.
        Then:
            -the outputs, raw response, and human readable are valid.
    """

    from Gmail import sent_mail_to_entry

    result = sent_mail_to_entry(title, response, to, emailfrom, cc, bcc, body, subject)
    assert result.readable_output == expected_result.get("expected_human_readable")
    assert result.outputs == expected_result.get("expected_outputs")
    assert result.raw_response == expected_result.get('expected_raw_response')


@pytest.mark.parametrize('title, mailbox, response, expected_result', [
    ('filters:', '1111111',
     input_data.list_filters_mock_result, input_data.expected_result_test_filters_to_entry)
])
def test_filters_to_entry(title, mailbox, response, expected_result):
    """
    Tests filters_to_entry function.
        Given:
            - gmail get filters list api response (from list_filters function).
        When:
            - executing filters_to_entry function.
        Then:
            -the contents and human readable are valid.
    """

    from Gmail import filters_to_entry

    result = filters_to_entry(title, mailbox, response)
    assert result.get("Contents") == expected_result.get("except_contents")
    assert result.get("HumanReadable") == expected_result.get("expected_human_readable")


@pytest.mark.parametrize('mailboxes, expected_result', [
    (input_data.list_mailboxes, input_data.expected_result_test_mailboxes_to_entry)
])
def test_mailboxes_to_entry(mailboxes, expected_result):
    """
    Tests mailboxes_to_entry function.
        Given:
            - gmail get message list api response (from search_command function).
        When:
            - executing mailboxes_to_entry function.
        Then:
            -the contents and human readable are valid.
    """

    from Gmail import mailboxes_to_entry

    result = mailboxes_to_entry(mailboxes)
    assert result.get("Contents") == expected_result.get("except_contents")
    assert result.get("HumanReadable") == expected_result.get("expected_human_readable")


@pytest.mark.parametrize('title, raw_emails, format_data, mailbox, expected_result', [
    ('Search in 11111:\nquery: "subject:helloworld"', input_data.mails, 'full',
     '11111', input_data.expected_result_test_emails_to_entry)
])
def test_emails_to_entry(title, raw_emails, format_data, mailbox, expected_result):
    """
    Tests emails_to_entry function.
        Given:
             - gmail get message list api response (from search_command function).
        When:
            - executing emails_to_entry function.
        Then:
            -the contents and human readable are valid.
    """

    from Gmail import emails_to_entry

    result = emails_to_entry(title, raw_emails, format_data, mailbox)
    assert result.get("Contents") == expected_result.get("except_contents")
    assert result.get("HumanReadable") == expected_result.get("expected_human_readable")
