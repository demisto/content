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
    assert sorted(parse_privileges(privileges)) == sorted([{'ServiceID': 'id', 'Name': 'name'}, {'Name': 'name_no_id'}])


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
