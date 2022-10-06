import pytest
from freezegun import freeze_time

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
            - get a dictionary.
    """

    from Gmail import template_params

    assert template_params(params_str) == expected_result


@freeze_time("2022-09-08 12:00:00 UTC")
@pytest.mark.parametrize('date, arg_name, expected_result', [
    ("2022-09-08", "", 1662595200000)
])
def test_get_millis_from_date(date, arg_name, expected_result):
    """
    Tests get_millis_from_date function.
        Given:
            - .
        When:
            - .
        Then:
            - .
    """

    from Gmail import get_millis_from_date

    assert get_millis_from_date(date, arg_name) == expected_result


RESPONSE = [
    {'kind': 'admin#directory#user',
        'id': '000000000000000000000',
        'etag': '“XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX”',
        'primaryEmail': 'johndoe@test.com',
        'name': {'givenName': 'john',
                        'familyName': 'doe',
                        'fullName': 'john doe'},
        'isAdmin': True,
        'isDelegatedAdmin': False,
        'lastLoginTime': '2021-09-21T08:52:17.000Z',
        'creationTime': '2019-12-30T14:32:18.000Z',
        'agreedToTerms': True,
        'suspended': False,
        'archived': False,
        'changePasswordAtNextLogin': False,
        'ipWhitelisted': False,
        'emails': [
                {'address': 'johndoe@test.com', 'primary': True}],
        'languages': [{'languageCode': 'en', 'preference': 'preferred'}],
        'nonEditableAliases': ['johndoe@test.com'],
        'customerId': 'Cxxxxxxxx',
        'orgUnitPath': '/',
        'isMailboxSetup': True,
        'isEnrolledIn2Sv': False,
        'isEnforcedIn2Sv': False,
        'includeInGlobalAddressList': True,
        'recoveryEmail': 'johndoe@test.com',
        'recoveryPhone': '+972500000000'}]
expected_outputs = [
    {
        'Type': 'Google',
        'ID': '000000000000000000000',
        'UserName': 'john',
        'Username': 'john',  # adding to fit the new context standard
        'DisplayName': 'john doe',
        'Email': {'Address': 'johndoe@test.com'},
        'Gmail': {'Address': 'johndoe@test.com'},
        'Group': 'admin#directory#user',
        'Groups': 'admin#directory#user',  # adding to fit the new context standard
        'CustomerId': 'Cxxxxxxxx',
        'Domain': 'test.com',
        'VisibleInDirectory': True,

    }
]

expected_human_readable = "### User 000000000000000000000:\n\
|Type|ID|Username|DisplayName|Groups|CustomerId|Domain|Email|VisibleInDirectory|\n\
|---|---|---|---|---|---|---|---|---|\n\
| Google | 000000000000000000000 | john | john doe |\
 admin#directory#user |\
 Cxxxxxxxx | test.com |\
 Address: johndoe@test.com | true |\n"
EXPECTED_RESULT_test_users_to_entry = {"expected_human_readable": expected_human_readable,
                                       "expected_outputs": expected_outputs,
                                       "expected_raw_response": RESPONSE}


@pytest.mark.parametrize('title, response, expected_result', [
    ('User 000000000000000000000:', RESPONSE, EXPECTED_RESULT_test_users_to_entry)
])
def test_users_to_entry(title, response, expected_result):
    """
    Tests get_millis_from_date function.
        Given:
            - .
        When:
            - .
        Then:
            - .
    """

    from Gmail import users_to_entry

    result = users_to_entry(title, response)
    assert result.readable_output == expected_result.get("expected_human_readable")
    assert result.outputs == expected_result.get("expected_outputs")
    assert result.raw_response == expected_result.get('expected_raw_response')


get_auto_replay_result = {'enableAutoReply': True, 'responseSubject': 'subject_test', 'responseBodyPlainText': 'body_test', 'restrictToContacts': False, 'restrictToDomain': False}

expected_raw_response_test_autoreply_to_entry = [{'EnableAutoReply': True, 'ResponseBody': 'body_test', 'ResponseSubject': 'subject_test', 'RestrictToContact': False, 'RestrictToDomain': False, 'StartTime': None, 'EndTime': None, 'ResponseBodyHtml': None}]

expected_human_readable_test_autoreply_to_entry = '### User johndoe@test.com:\n|EnableAutoReply|ResponseBody|ResponseSubject\
|RestrictToContact|RestrictToDomain|EnableAutoReply|\n|---|---|---|---|---|---|\n| true | body_test |\
 subject_test | false | false | true |\n'

expected_outputs_test_autoreply_to_entry = {"Address": "johndoe@test.com",
                                            "AutoReply": [{'EnableAutoReply': True,
                                                           'ResponseBody': 'body_test',
                                                           'ResponseSubject': 'subject_test',
                                                           'RestrictToContact': False,
                                                           'RestrictToDomain': False,
                                                           'StartTime': None, 'EndTime': None,
                                                           'ResponseBodyHtml': None}]
                                            }

expected_result_test_autoreply_to_entry = {"expected_human_readable": expected_human_readable_test_autoreply_to_entry,
                                           "expected_outputs": expected_outputs_test_autoreply_to_entry,
                                           "expected_raw_response": expected_raw_response_test_autoreply_to_entry}


@pytest.mark.parametrize('title, response, user_id, expected_result', [
    ('User johndoe@test.com:', [get_auto_replay_result], 'johndoe@test.com', expected_result_test_autoreply_to_entry)
])
def test_autoreply_to_entry(title, response, user_id, expected_result):
    """
    Tests get_millis_from_date function.
        Given:
            - .
        When:
            - .
        Then:
            - .
    """

    from Gmail import autoreply_to_entry

    result = autoreply_to_entry(title, response, user_id)
    assert result.readable_output == expected_result.get("expected_human_readable")
    assert result.outputs == expected_result.get("expected_outputs")
    assert result.raw_response == expected_result.get('expected_raw_response')
