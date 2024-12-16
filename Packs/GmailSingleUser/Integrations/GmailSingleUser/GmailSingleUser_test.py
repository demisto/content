import json
import uuid
import pytest
from pytest_mock import MockerFixture
import demistomock as demisto

from GmailSingleUser import Client, send_mail_command, MIMEMultipart, execute_gmail_action
from email.utils import parsedate_to_datetime


@pytest.fixture
def gmail_client(mocker):
    client = Client()
    mocker.patch.object(client, 'get_access_token', return_value='token')
    return client


class MockAttachments:
    def get(self, **kwargs):
        return MockExecute()


class MockExecute:
    def execute(self):
        return {'attachmentId': '67890', 'size': 1024, 'data': 'mock_data'}


class MockSend:
    def execute(self):
        return {'id': '12345'}


class MockGet:
    def execute(self):
        return {'id': '12345', 'snippet': 'Test email content'}


class MockList:
    def execute(self):
        return {'messages': [{'id': '12345'}, {'id': '67890'}]}


class MockMessages:
    def send(self, **kwargs):
        return MockSend()

    def get(self, **kwargs):
        return MockGet()

    def attachments(self, **kwargs):
        return MockAttachments()

    def list(self, **kwargs):
        return MockList()


class MockUsers:
    def messages(self):
        return MockMessages()


class MockService:
    def users(self):
        return MockUsers()


@pytest.fixture
def mock_service():
    return MockService()


def test_execute_gmail_action_send(mock_service):
    result = execute_gmail_action(mock_service, "send", {})
    assert result == {'id': '12345'}


def test_execute_gmail_action_get(mock_service):
    result = execute_gmail_action(mock_service, "get", {})
    assert result == {'id': '12345', 'snippet': 'Test email content'}


def test_execute_gmail_action_get_attachments(mock_service):
    result = execute_gmail_action(mock_service, "get_attachments", {})
    assert result == {'attachmentId': '67890', 'size': 1024, 'data': 'mock_data'}


def test_execute_gmail_action_list(mock_service):
    result = execute_gmail_action(mock_service, "list", {})
    assert result == {'messages': [{'id': '12345'}, {'id': '67890'}]}


def test_execute_gmail_action_unsupported(mock_service):
    action_kwargs = {}
    with pytest.raises(ValueError, match="Unsupported action: unsupported_action"):
        execute_gmail_action(mock_service, "unsupported_action", action_kwargs)


MOCK_MAIL_NO_LABELS = {
    'internalDate': '1572251535000',
    'historyId': '249781',
    'payload': {
        'mimeType': 'multipart/mixed',
        'body': {'size': 0},
        'partId': '',
        'filename': '',
        'headers': [
            {
                'name': 'Received',
                'value': 'from 1041831412594 named unknown by gmailapi.google.com with '
                'HTTPREST; Mon, 28 Oct 2019 04:32:15 -0400'
            }, {
                'name': 'Content-Type',
                'value': 'mixed; boundary="===============4922146810840031257=="'
            }, {
                'name': 'MIME-Version',
                'value': '1.0'
            }, {
                'name': 'to',
                'value': '<some_mail>'
            }, {
                'name': 'cc',
                'value': ''
            }, {
                'name': 'bcc',
                'value': ''
            }, {
                'name': 'from',
                'value': '<some_mail>'
            }, {
                'name': 'subject',
                'value': 'a mail subject'
            }, {
                'name': 'reply-to',
                'value': ''
            }, {
                'name': 'Date',
                'value': 'Mon, 28 Oct 2019 04:32:15 -0400'
            }, {
                'name': 'Message-Id',
                'value': '<some_id>'
            }
        ],
        'parts': [
            {
                'mimeType': 'text/plain',
                'headers': [
                    {
                        'name': 'Content-Type',
                        'value': 'text/plain; charset="utf-8"'
                    }, {
                        'name': 'MIME-Version',
                        'value': '1.0'
                    }, {
                        'name': 'Content-Transfer-Encoding',
                        'value': 'base64'
                    }
                ],
                'body': {
                    'data': '<data>',
                    'size': 9
                },
                'partId': '0',
                'filename': ''
            }
        ]
    },
    'snippet': 'some info',
    'sizeEstimate': 637,
    'threadId': '<id>',
    'id': '<id>'
}


EXPECTED_GMAIL_CONTEXT = {
    'To': '<some_mail>',
    'Body': '',
    'From': '<some_mail>',
    'Attachments': '',
    'Format': 'mixed',
    'Cc': '',
    'Labels': '',
    'Mailbox': 'some_mail',
    'Headers': [
        {
            'Name': 'Received',
            'Value': 'from 1041831412594 named '
                     'unknown by gmailapi.google.com with HTTPREST; Mon, 28 Oct 2019 04:32:15 -0400'
        }, {
            'Name': 'Content-Type',
            'Value': 'mixed; boundary="===============4922146810840031257=="'
        }, {
            'Name': 'MIME-Version',
            'Value': '1.0'
        }, {
            'Name': 'to',
            'Value': '<some_mail>'
        }, {
            'Name': 'cc',
            'Value': ''
        }, {
            'Name': 'bcc', 'Value': ''
        }, {
            'Name': 'from', 'Value': '<some_mail>'
        }, {
            'Name': 'subject',
            'Value': 'a mail subject'
        }, {
            'Name': 'reply-to',
            'Value': ''
        }, {
            'Name': 'Date',
            'Value': 'Mon, 28 Oct 2019 04:32:15 -0400'
        }, {
            'Name': 'Message-Id',
            'Value': '<some_id>'
        }
    ],
    'Html': None,
    'RawData': None,
    'ThreadId': '<id>',
    'Date': 'Mon, 28 Oct 2019 04:32:15 -0400',
    'Bcc': '',
    'Type': 'Gmail',
    'ID': '<id>',
    'Subject': 'a mail subject'
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
    with open('test_data/email_no_date.json') as f:
        msg = json.load(f)
    client = Client()
    context_gmail, _, _, occurred, is_valid = client.get_email_context(msg, "some_mail")
    # check that the x-received date was usd
    assert occurred.timestamp() == parsedate_to_datetime('Mon, 21 Dec 2020 12:11:57 -0800').timestamp()
    assert is_valid
    assert context_gmail.get('Date') == 'Mon, 21 Dec 2020 12:11:57 -0800'


def test_generate_auth_link_oob():
    client = Client()
    link = client.generate_auth_link()
    assert link.startswith('https://accounts.google.com/o/oauth2/v2/auth?')
    assert 'code_challenge=' in link
    assert 'code_challenge_method=S256' in link


def test_generate_auth_link_web(mocker):
    mocker.patch('GmailSingleUser.CLIENT_SECRET', 'test')
    mocker.patch('GmailSingleUser.CLIENT_ID', 'test_id')
    mocker.patch('GmailSingleUser.REDIRECT_URI', 'http://localhost:9001')
    client = Client()
    link = client.generate_auth_link()
    assert link.startswith('https://accounts.google.com/o/oauth2/v2/auth?')
    assert 'code_challenge=' not in link
    assert 'code_challenge_method=S256' not in link
    assert 'access_type=offline' in link
    assert 'redirect_uri=http' in link
    assert 'client_id=test_id' in link


SEND_EMAIL_ARGS = [
    {"subject": "test", "to": "test@gmail.com", "body": "hello"},
    {"subject": "test", "to": "test@gmail.com", "htmlBody": "<h1>test</h1>"}
]


@pytest.mark.parametrize("command_args", SEND_EMAIL_ARGS)
def test_send_mail(gmail_client, mocker, command_args):
    """
    Given:
        - send mail command arguments

    When:
        - executing the send mail function

    Then:
        - a valid entry is returned
    """
    mocker.patch.object(
        gmail_client, 'send_email_request', return_value={'id': '123', 'threadId': '123', 'labelIds': ['SENT']}
    )
    mocker.patch.object(demisto, 'args', return_value=command_args)

    send_email_entry = send_mail_command(client=gmail_client)
    context_output = send_email_entry['EntryContext']
    assert 'Gmail.SentMail(val.ID && val.Type && val.ID == obj.ID && val.Type == obj.Type)' in context_output
    context_output = context_output['Gmail.SentMail(val.ID && val.Type && val.ID == obj.ID && val.Type == obj.Type)'][0]

    assert context_output.get('To') == command_args.get('to')
    assert context_output.get('Subject') == command_args.get('subject')
    assert context_output.get('Body') == command_args.get('body')
    assert context_output.get('BodyHTML') == command_args.get('htmlBody')
    assert context_output.get('Mailbox') == command_args.get("to")

    markdown_table = send_email_entry['HumanReadable']
    assert 'Gmail' in markdown_table
    assert command_args.get('to') in markdown_table
    assert command_args.get('subject') in markdown_table
    assert 'SENT' in markdown_table


def test_send_mail_with_reference(gmail_client: Client, mocker):
    """
    Given:
        - The references argument as a list type
        - The inReplyTo argument as a str type
    When:
        - run client.send_mail function
    Then:
        - Ensure the function expects to receive the type
          of the reference argument and the inReplyTo argument
    """
    mocker.patch.object(
        gmail_client, 'send_email_request', return_value=True
    )
    assert gmail_client.send_mail(
        emailto=None,
        emailfrom=None,
        send_as=None,
        cc=None,
        bcc=None,
        subject=None,
        body=None,
        htmlBody=None,
        entry_ids=None,
        replyTo=None,
        file_names=None,
        attach_cid=None,
        manualAttachObj=None,
        transientFile=None,
        transientFileContent=None,
        transientFileCID=None,
        additional_headers=None,
        templateParams=None,
        references=['test', 'test1'],
        inReplyTo='test test'
    )


def test_send_mail_MIMEMultipart_constructor(mocker: MockerFixture):
    """
    Given:
        - Client object
    When:
        - Client constructor called
    Then:
        - Ensure MIMEMultipart constructor called once without subtype
    """
    from GmailSingleUser import Client
    import GmailSingleUser

    gmail_single_user_client = Client()
    # Mock the chain of calls: service.users().messages().send().execute()
    mock_execute = mocker.Mock(return_value={'id': 'mock_message_id'})
    mock_send = mocker.Mock(return_value=mock_execute)
    mock_messages = mocker.Mock(send=mocker.Mock(return_value=mock_send))
    mock_users = mocker.Mock(messages=mocker.Mock(return_value=mock_messages))
    mock_service = mocker.Mock(users=mocker.Mock(return_value=mock_users))
    # Patch the service object in the Client class to use the mocked service
    mocker.patch.object(GmailSingleUser.Client, 'get_service', new=mock_service)
    # Replace MIMEMultipart with the mock object
    mocker_obj = mocker.patch.object(
        GmailSingleUser, "MIMEMultipart", return_value=MIMEMultipart()
    )

    gmail_single_user_client.send_mail(
        emailto="test@gmail.com",
        emailfrom="test@gmail.com",
        send_as="test@gmail.com",
        cc=None,
        bcc=None,
        subject="hello-world",
        body="body",
        htmlBody="<>",
        entry_ids=[],
        replyTo=None,
        file_names=[],
        attach_cid=[],
        manualAttachObj=[],
        transientFile=[],
        transientFileContent=[],
        transientFileCID=[],
        additional_headers=[],
        templateParams=None,
    )

    mocker_obj.assert_called_once()
    assert mocker_obj.call_args.args == ()


def test_handle_html(mocker):
    """
    Given:
        - html body of a message.
    When:
        - run handle_html function.
    Then:
        - Ensure attachments list contains 2 items with correct data, name and cid fields.
    """
    client = Client()
    mocker.patch.object(demisto, "uniqueFile", return_value="1234567")
    mocker.patch.object(demisto, "getFilePath", return_value={"path": "", "name": ""})
    mocker.patch.object(uuid, "uuid4", return_value="11111111")
    htmlBody = """<html>
                        <body>
                            <img src="data:image/png;base64,Aa=="/>
                            <img src="data:image/jpeg;base64,Bb=="/>
                        </body>
                      </html>"""

    expected_attachments = [
        {'maintype': 'image',
         'subtype': 'png',
         'data': b'\x01',
         'name': 'image0.png',
         'cid': 'image0.png@11111111_11111111',
         'ID': 'image0.png@11111111_11111111'
         },
        {'maintype': 'image',
         'subtype': 'jpeg',
         'data': b'\x05',
         'name': 'image1.jpeg',
         'cid': 'image1.jpeg@11111111_11111111',
         'ID': 'image1.jpeg@11111111_11111111'
         }
    ]
    expected_cleanBody = '<html>\n                        <body>\n                            <img src="cid:image0.png@11111111_11111111"/>\n                            <img src="cid:image1.jpeg@11111111_11111111"/>\n                        </body>\n                      </html>'  # noqa: E501
    cleanBody, attachments = client.handle_html(htmlBody)

    assert expected_cleanBody == cleanBody
    assert expected_attachments == attachments


def test_handle_html_image_with_new_line(mocker):
    """
    Given:
        - html body of a message with an attached base64 image.
    When:
        - run handle_html function.
    Then:
        - Ensure attachments list contains correct data, name and cid fields.
    """
    client = Client()
    mocker.patch.object(demisto, "uniqueFile", return_value="1234567")
    mocker.patch.object(demisto, "getFilePath", return_value={"path": "", "name": ""})
    mocker.patch.object(uuid, "uuid4", return_value="11111111")
    htmlBody = """
<html>
    <body>
        <img\n\t\t\t\t\t  src="data:image/png;base64,Aa=="/>
    </body>
</html>"""

    expected_attachments = [
        {'maintype': 'image',
         'subtype': 'png',
         'data': b'\x01',
         'name': 'image0.png',
         'cid': 'image0.png@11111111_11111111',
         'ID': 'image0.png@11111111_11111111'}
    ]
    expected_cleanBody = '\n<html>\n    <body>\n        <img\n\t\t\t\t\t  src="cid:image0.png@11111111_11111111"/>\n    </body>\n</html>'  # noqa: E501

    cleanBody, attachments = client.handle_html(htmlBody)

    assert expected_cleanBody == cleanBody
    assert expected_attachments == attachments


part_test1 = [{
    'filename': 'image-1.png',
    'headers': [{
        'name': 'Content-ID', 'value': '<5678>'},
        {'name': 'Content-Disposition', 'value': 'inline'}],
    'body': {
        'attachmentId': '1234'},
    'mimeType': ''
}]

part_test2 = [{
    'filename': 'image-1.png',
    'headers': [{
        'name': 'Content-ID', 'value': '5678'},
        {'name': 'Content-Disposition', 'value': 'attachment'}],
    'body': {
        'attachmentId': '1234'},
    'mimeType': ''
}]

part_test3 = [{
    'filename': 'image-1.png',
    'headers': [{
        'name': 'Content-ID', 'value': 'None'},
        {'name': 'Content-Disposition', 'value': 'attachment'}],
    'body': {
        'attachmentId': '1234'},
    'mimeType': ''
}]


@pytest.mark.parametrize(
    "part, expected_result",
    [
        (part_test1, ('', '', [{'ID': '1234', 'Name': '5678-attachmentName-image-1.png'}])),
        (part_test2, ('', '', [{'ID': '1234', 'Name': 'image-1.png'}])),
        (part_test3, ('', '', [{'ID': '1234', 'Name': 'image-1.png'}])),
    ],
)
def test_parse_mail_parts(part, expected_result):
    """
    Given:
        - Part of message from Gmail API response.
    When:
        - Run parse_mail_parts function with LEGACY_NAME is false.
    Then:
        - Ensure attachment's name was correctly constructed and parsing was correctly done.
    """
    client = Client()
    result = client.parse_mail_parts(part)
    assert result == expected_result


@pytest.mark.parametrize(
    "part, expected_result",
    [
        (part_test1, ('', '', [{'ID': '1234', 'Name': 'image-1.png'}])),
        (part_test2, ('', '', [{'ID': '1234', 'Name': 'image-1.png'}])),
        (part_test3, ('', '', [{'ID': '1234', 'Name': 'image-1.png'}])),
    ],
)
def test_parse_mail_parts_use_legacy_name(monkeypatch, part, expected_result):
    """
    Given:
        - Part of message from Gmail API response.
    When:
        - Run parse_mail_parts function LEGACY_NAME is true.
    Then:
        - Ensure attachment's name was correctly constructed and parsing was correctly done.
    """
    client = Client()
    monkeypatch.setattr('GmailSingleUser.LEGACY_NAME', True)
    result = client.parse_mail_parts(part)
    assert result == expected_result
