import demistomock as demisto
import pytest
from test_data import input_data
import datetime

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
    context_gmail, _, _, _, _ = get_email_context(MOCK_MAIL_NO_LABELS, "some_mail")
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
    assert result[0].outputs == expected_result.get("except_contents")
    assert result[0].readable_output == expected_result.get("expected_human_readable")


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


def test_forwarding_address_list_command(mocker):
    """
    Tests forwarding_address_list function.
        Given:
             - demisto arg user_id.
        When:
            - executing forwarding_address_list function.
        Then:
            -the raw_response,outputs and readable_output are valid.
    """

    import Gmail
    from Gmail import forwarding_address_list_command
    mocker.patch.object(demisto, 'args', return_value={'user_id': '111', 'forwarding_email': 'test@gmail.com'})
    mocker.patch.object(Gmail, 'forwarding_address_list',
                        return_value={'forwardingAddresses': [{'forwardingEmail': 'test1@gmail.com',
                                                               'verificationStatus': 'accepted'},
                                                              {'forwardingEmail': 'test2@gmail.com',
                                                              'verificationStatus': 'accepted'}]})

    result = forwarding_address_list_command()
    assert result.raw_response == {'forwardingAddresses': [{'forwardingEmail': 'test1@gmail.com',
                                                            'userId': '111',
                                                            'verificationStatus': 'accepted'},
                                                           {'forwardingEmail': 'test2@gmail.com',
                                                            'userId': '111',
                                                           'verificationStatus': 'accepted'}]}
    assert result.outputs == [{'forwardingEmail': 'test1@gmail.com', 'userId': '111', 'verificationStatus': 'accepted'},
                              {'forwardingEmail': 'test2@gmail.com', 'userId': '111', 'verificationStatus': 'accepted'}]
    assert result.readable_output == '### Forwarding addresses list for: "111"\n|forwardingEmail|\
verificationStatus|\n|---|---|\n| test1@gmail.com | accepted |\n| test2@gmail.com | accepted |\n'


def test_forwarding_address_remove_command(mocker):
    """
    Tests forwarding_address_remove_command function.
        Given:
             - demisto arg user_id and forwarding_email.
        When:
            - executing forwarding_address_remove_command function.
        Then:
            -the raw_response,outputs and readable_output are valid.
    """

    import Gmail
    from Gmail import forwarding_address_remove_command
    mocker.patch.object(demisto, 'args', return_value={'user_id': '111', 'forwarding_email': 'test@gmail.com'})
    mocker.patch.object(Gmail, 'forwarding_address_remove', return_value='')

    result = forwarding_address_remove_command()
    assert result.readable_output == 'Forwarding address "test@gmail.com" for "111" was deleted successfully .'


@pytest.mark.parametrize('return_value_from_mocker_args, expected_result', [
    ({'user_id': '111', 'forwarding_email': 'test@gmail.com'},
     input_data.expected_result_forwarding_address_get_command_1),
    ({'user_id': '111'},
     input_data.expected_result_forwarding_address_get_command_2)
])
def test_forwarding_address_get_command(mocker, return_value_from_mocker_args, expected_result):
    """
    Tests forwarding_address_get_command function.
        Given:
             - demisto arg user_id.
        When:
            - executing forwarding_address_list function.
        Then:
            -the raw_response,outputs and readable_output are valid.
    """

    import Gmail
    from Gmail import forwarding_address_get_command
    mocker.patch.object(demisto, 'args', return_value=return_value_from_mocker_args)
    mocker.patch.object(Gmail, 'forwarding_address_get',
                        return_value={'forwardingEmail': 'test@gmail.com', 'verificationStatus': 'accepted'})
    mocker.patch.object(Gmail, 'forwarding_address_list',
                        return_value={'forwardingAddresses': [{'forwardingEmail': 'test1@gmail.com',
                                                               'verificationStatus': 'accepted'},
                                                              {'forwardingEmail': 'test2@gmail.com',
                                                              'verificationStatus': 'accepted'},
                                                              {'forwardingEmail': 'test3@gmail.com',
                                                               'verificationStatus': 'accepted'}]})

    result = forwarding_address_get_command()
    assert result.raw_response == expected_result.get("raw_response")
    assert result.outputs == expected_result.get("outputs")
    assert result.readable_output == expected_result.get("readable_output")


def test_forwarding_address_add(mocker):
    """
    Tests forwarding_address_get_command function.
        Given:
             - demisto arg user_id.
        When:
            - executing forwarding_address_list function.
        Then:
            -the raw_response,outputs and readable_output are valid.
    """

    import Gmail
    from Gmail import forwarding_address_add_command
    mocker.patch.object(Gmail, 'forwarding_address_add', return_value=({'forwardingEmail': 'test@gmail.com',
                                                                        'verificationStatus': 'accepted', 'userId': 'me'},
                                                                       False,
                                                                       {'forwardingEmail': 'test@gmail.com',
                                                                        'errorMessage': '', 'userId': 'me'}))
    mocker.patch.object(demisto, 'args', return_value={'user_id': 'me', 'forwarding_email': 'test@gmail.com'})
    result = forwarding_address_add_command()[0]
    assert result.outputs == [{'forwardingEmail': 'test@gmail.com', 'verificationStatus': 'accepted', 'userId': 'me'}]
    assert result.readable_output == '### Forwarding addresses results for "me":\n|forwardingEmail|userId|verificationStatus|\n|\
---|---|---|\n| test@gmail.com | me | accepted |\n'
    assert result.raw_response == [{'forwardingEmail': 'test@gmail.com', 'verificationStatus': 'accepted', 'userId': 'me'}]


def test_forwarding_address_update(mocker):
    """
    Tests forwarding_address_get_command function.
        Given:
             - demisto arg user_id.
        When:
            - executing forwarding_address_list function.
        Then:
            -the raw_response,outputs and readable_output are valid.
    """

    import Gmail
    from Gmail import forwarding_address_update_command
    mocker.patch.object(Gmail, 'forwarding_address_update', return_value=({'enabled': True, 'emailAddress': 'test@gmail.com',
                                                                           'disposition': 'markRead', 'userId': 'me'},
                                                                          None, {'emailAddress': 'test@gmail.com',
                                                                          'errorMessage': None, 'userId': 'me'}))
    mocker.patch.object(demisto, 'args', return_value={'user_id': 'me', 'forwarding_email': 'test@gmail.com',
                                                       'disposition': 'markRead'})
    result = forwarding_address_update_command()[0]
    assert result.outputs == [{'enabled': True, 'forwardingEmail': 'test@gmail.com', 'disposition': 'markRead', 'userId': 'me'}]
    assert result.readable_output == '### Forwarding addresses update results for "me":\n|forwardingEmail|userId|disposition|\
enabled|\n|---|---|---|---|\n| test@gmail.com | me | markRead | true |\n'
    assert result.raw_response == [{'enabled': True, 'forwardingEmail': 'test@gmail.com', 'disposition':
                                    'markRead', 'userId': 'me'}]


def test_no_date_mail():
    """
    Tests get_email_context function.
        Given:
             - An email without a valid date header.
        When:
            - executing get_email_context function.
        Then:
            -the 'Date' is valid.
    """
    from email.utils import parsedate_to_datetime

    from Gmail import get_email_context
    context_gmail, _, _, occurred, is_valid = get_email_context(input_data.email_without_date, "some_mail")
    # check that the x-received date was usd
    assert occurred.timestamp() == parsedate_to_datetime('Mon, 21 Dec 2020 12:11:57 -0800').timestamp()
    assert is_valid
    assert context_gmail.get('Date') == 'Mon, 21 Dec 2020 12:11:57 -0800'


class MockMessages:
    def messages(self):
        return MockListAndGet()


class MockExecuteMessagesList:
    def execute(self):
        return input_data.service_result


class MockExecute:

    def __init__(self, name, userId, pageToken, q, msgid):
        self.name = name
        self.user_id = userId
        self.pageToken = pageToken
        self.q = q
        self.msgid = msgid

    def message(self):
        if self.msgid == "1845fa4c3a5618cb":
            return input_data.first_message
        else:
            return input_data.second_message
        return 0

    def execute(self):
        if self.name == "list":
            if self.pageToken:
                return input_data.service_result_with_pageToken
            else:
                return input_data.service_result_without_pageToken
        if self.name == "get":
            return self.message()


class MockListAndGet:
    def list(self, userId, maxResults, pageToken, q):
        return MockExecute("list", 0, pageToken, q, 0)

    def get(self, id, userId):
        return MockExecute("get", userId, None, 0, id)


class MockService:
    def users(self):
        return MockMessages()


@pytest.mark.parametrize('return_value_get_last_run, expected_result', [
    ({'lastRun': '2018-10-24T14:13:20+00:00', 'gmt_time': '2017-10-24T14:13:20Z'}, input_data.first_incident_result),
    ({'lastRun': '2018-10-24T14:13:20+00:00', 'gmt_time': '2017-10-24T14:13:20Z', 'page_token': '02582292467408105606'},
     input_data.second_incident_result)
])
def test_fetch_incidents(mocker, return_value_get_last_run, expected_result):
    """
    Tests fetch_incidents function.
        Given:
             - lastRun object.
        When:
            - executing fetch_incidents function.
        Then:
            - the incidents are valid.
    """

    import Gmail
    from Gmail import fetch_incidents
    service = MockService()
    mocker.patch.object(Gmail, 'get_service', return_value=service)
    mocker.patch.object(demisto, 'params', return_value={'queryUserKey': '111', 'query': '', 'fetch_limit': '1'})
    mocker.patch.object(demisto, 'getLastRun', return_value=return_value_get_last_run)
    incidents = fetch_incidents()
    assert incidents == expected_result


def test_get_occurred_date():
    """
    Tests test_get_occurred_date function.
        Given:
             - an email message without date header.
        When:
            - executing test_get_occurred_date function.
        Then:
            - the occurred date is valid and corresponding to the date in the email.
    """
    from Gmail import get_occurred_date
    occurred, occurred_is_valid = get_occurred_date(input_data.email_without_date)
    assert str(occurred) == '2020-12-21 12:11:57-08:00'
    assert occurred == datetime.datetime(2020, 12, 21, 12, 11, 57,
                                         tzinfo=datetime.timezone(datetime.timedelta(days=-1, seconds=57600)))
    assert occurred_is_valid is True


def test_get_date_from_email_header():
    """
    Tests test_get_occurred_date function.
        Given:
             - an email header with a date.
        When:
            - executing get_date_from_email_header function.
        Then:
            - the date is valid and corresponding to the date in the header.
    """

    from Gmail import get_date_from_email_header
    result = get_date_from_email_header('by 2002:a9d:4b03:: with SMTP id q3mr13206164otf.88.1608581517297;\
            Mon, 21 Dec 2020 12:11:57 -0800 (PST)')
    assert str(result) == '2020-12-21 12:11:57-08:00'
    assert result == datetime.datetime(2020, 12, 21, 12, 11, 57,
                                       tzinfo=datetime.timezone(datetime.timedelta(days=-1, seconds=57600)))


def test_get_date_isoformat_server():
    """
    Tests test_get_occurred_date function.
        Given:
             - a datetime object.
        When:
            - executing test_get_date_isoformat_server function.
        Then:
            - the date string is valid.
    """
    from Gmail import get_date_isoformat_server
    date = get_date_isoformat_server(datetime.datetime(2022, 11, 9, 22, 45, 44,
                                                       tzinfo=datetime.timezone(datetime.timedelta(days=-1, seconds=68400))))
    assert date == '2022-11-10T03:45:44Z'


def test_parse_date_isoformat_server():
    """
    Tests parse_date_isoformat_server function.
        Given:
             - a string that represents a date.
        When:
            - executing parse_date_isoformat_server function.
        Then:
            - the datetime is valid.
    """
    from Gmail import parse_date_isoformat_server
    date = parse_date_isoformat_server('2017-10-24T14:13:20Z')
    assert date == datetime.datetime(2017, 10, 24, 14, 13, 20, tzinfo=datetime.timezone.utc)
    assert str(date) == '2017-10-24 14:13:20+00:00'


@pytest.mark.parametrize(
    "fields, expected_result",
    [
        (None, None),
        ("test", None),
        ("test,test", None),
        ("id", None),
        ("subject", ["Subject", "ID"]),
        ("subject,html", ["Subject", "Html", "ID"]),
    ],
)
def test_format_fields_argument(fields: str | None, expected_result: list[str] | None):
    """
    Given:
        - A string or None in fields argument.

    When:
        - `format_fields_argument` is called with the fields.

    Then:
        Ensure:
        - When given None returns None
        - When an invalid field is given, None is returned
        - When valid fields are given the list returned contains the given fields
        - When valid fields are given, the ID field will always be included in the list
    """
    from Gmail import format_fields_argument
    from CommonServerPython import argToList
    assert format_fields_argument(argToList(fields)) == expected_result


@pytest.mark.parametrize(
    "full_mail, filter_fields, expected_result",
    [
        (
            {
                "Type": "Gmail",
                "Mailbox": "test",
                "ID": "id",
                "ThreadId": "test",
                "Labels": "test",
                "Headers": "test",
                "Attachments": "test",
                "RawData": "test",
                "Format": "test",
                "Subject": "test",
                "From": "test",
                "To": "test",
                "Body": "test",
                "Cc": "test",
                "Bcc": "test",
                "Date": "test",
                "Html": "test",
            },
            ["ID", "Labels", "From"],
            {
                "ID": "id",
                "Labels": "test",
                "From": "test",
            },
        )
    ],
)
def test_filter_by_fields(
    full_mail: dict[str, str], filter_fields: list[str], expected_result: dict[str, str]
):
    """
    Given:
        - A full mail object, a list of filter fields.
    When:
        - `filter_by_fields` is called.
    Then:
        - Ensure the email is filtered by the fields that given.
    """
    from Gmail import filter_by_fields

    assert filter_by_fields(full_mail, filter_fields) == expected_result
