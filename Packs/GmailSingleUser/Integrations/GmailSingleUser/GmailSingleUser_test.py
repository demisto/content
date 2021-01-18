from GmailSingleUser import Client
import json
from email.utils import parsedate_to_datetime

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


def test_header_to_date():
    valid_header_date = Client.get_date_from_email_header("Mon, 26 Aug 2019 14:40:04 +0300")
    semi_valid_header_date = Client.get_date_from_email_header("26 Aug 2019 14:40:04 +0300")
    header_date_no_tz = Client.get_date_from_email_header("26 Aug 2019 11:40:04")
    header_x_received = Client.get_date_from_email_header('by 2002:a17:90a:77cb:0:0:0:0 with SMTP id e11csp4670216pjs;        '
                                                          'Mon, 26 Aug 2019 03:40:04 -0800 (PST)')
    # all should be the same
    assert valid_header_date == semi_valid_header_date
    assert valid_header_date == header_date_no_tz
    assert header_x_received == valid_header_date


def test_no_label_mail_context_creation():
    client = Client()
    context_gmail, _, _, occurred, is_internal = client.get_email_context(MOCK_MAIL_NO_LABELS, "some_mail")
    assert int(occurred.timestamp()) == 1572251535
    assert is_internal
    assert context_gmail.get('Labels') == EXPECTED_GMAIL_CONTEXT.get('Labels')
    assert context_gmail.get('To') == EXPECTED_GMAIL_CONTEXT.get('To')
    assert context_gmail.get('From') == EXPECTED_GMAIL_CONTEXT.get('From')
    assert context_gmail.get('Subject') == EXPECTED_GMAIL_CONTEXT.get('Subject')


def test_extract_occurred_no_headers():
    occurred, is_valid = Client.get_occurred_date({
        'payload': {
            'headers': [{'name': 'stam', 'value': 'stam'}]
        },
        'internalDate': '1610642469000'
    })
    assert is_valid
    assert occurred.timestamp() == 1610642469


def test_no_date_mail():
    with open('test_data/email_no_date.json', 'r') as f:
        msg = json.load(f)
    client = Client()
    context_gmail, _, _, occurred, is_valid = client.get_email_context(msg, "some_mail")
    # check that the x-received date was usd
    assert occurred.timestamp() == parsedate_to_datetime('Mon, 21 Dec 2020 12:11:57 -0800').timestamp()
    assert is_valid
    assert context_gmail.get('Date') == 'Mon, 21 Dec 2020 12:11:57 -0800'


def test_generate_auth_link():
    client = Client()
    link, challange = client.generate_auth_link()
    assert link.startswith('https://accounts.google.com/o/oauth2/v2/auth?')
    assert challange in link
    assert 'code_challenge_method=S256' in link
