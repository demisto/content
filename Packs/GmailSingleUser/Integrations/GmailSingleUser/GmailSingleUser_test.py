import json
import uuid
import pytest
from pytest_mock import MockerFixture
import demistomock as demisto
from datetime import datetime, UTC
from freezegun import freeze_time


from GmailSingleUser import Client, send_mail_command, MIMEMultipart, execute_gmail_action
from email.utils import parsedate_to_datetime


@pytest.fixture
def gmail_client(mocker):
    client = Client()
    mocker.patch.object(client, "get_access_token", return_value="token")
    return client


class MockAttachments:
    def get(self, **kwargs):
        return MockExecute()


class MockExecute:
    def execute(self):
        return {"attachmentId": "67890", "size": 1024, "data": "mock_data"}


class MockSend:
    def execute(self):
        return {"id": "12345"}


class MockGet:
    def execute(self):
        return {"id": "12345", "snippet": "Test email content"}


class MockList:
    def execute(self):
        return {"messages": [{"id": "12345"}, {"id": "67890"}]}


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
    assert result == {"id": "12345"}


def test_execute_gmail_action_get(mock_service):
    result = execute_gmail_action(mock_service, "get", {})
    assert result == {"id": "12345", "snippet": "Test email content"}


def test_execute_gmail_action_get_attachments(mock_service):
    result = execute_gmail_action(mock_service, "get_attachments", {})
    assert result == {"attachmentId": "67890", "size": 1024, "data": "mock_data"}


def test_execute_gmail_action_list(mock_service):
    result = execute_gmail_action(mock_service, "list", {})
    assert result == {"messages": [{"id": "12345"}, {"id": "67890"}]}


def test_execute_gmail_action_unsupported(mock_service):
    action_kwargs = {}
    with pytest.raises(ValueError, match="Unsupported action: unsupported_action"):
        execute_gmail_action(mock_service, "unsupported_action", action_kwargs)


MOCK_MAIL_NO_LABELS = {
    "internalDate": "1572251535000",
    "historyId": "249781",
    "payload": {
        "mimeType": "multipart/mixed",
        "body": {"size": 0},
        "partId": "",
        "filename": "",
        "headers": [
            {
                "name": "Received",
                "value": "from 1041831412594 named unknown by gmailapi.google.com with "
                "HTTPREST; Mon, 28 Oct 2019 04:32:15 -0400",
            },
            {"name": "Content-Type", "value": 'mixed; boundary="===============4922146810840031257=="'},
            {"name": "MIME-Version", "value": "1.0"},
            {"name": "to", "value": "<some_mail>"},
            {"name": "cc", "value": ""},
            {"name": "bcc", "value": ""},
            {"name": "from", "value": "<some_mail>"},
            {"name": "subject", "value": "a mail subject"},
            {"name": "reply-to", "value": ""},
            {"name": "Date", "value": "Mon, 28 Oct 2019 04:32:15 -0400"},
            {"name": "Message-Id", "value": "<some_id>"},
        ],
        "parts": [
            {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "Content-Type", "value": 'text/plain; charset="utf-8"'},
                    {"name": "MIME-Version", "value": "1.0"},
                    {"name": "Content-Transfer-Encoding", "value": "base64"},
                ],
                "body": {"data": "<data>", "size": 9},
                "partId": "0",
                "filename": "",
            }
        ],
    },
    "snippet": "some info",
    "sizeEstimate": 637,
    "threadId": "<id>",
    "id": "<id>",
}


EXPECTED_GMAIL_CONTEXT = {
    "To": "<some_mail>",
    "Body": "",
    "From": "<some_mail>",
    "Attachments": "",
    "Format": "mixed",
    "Cc": "",
    "Labels": "",
    "Mailbox": "some_mail",
    "Headers": [
        {
            "Name": "Received",
            "Value": "from 1041831412594 named unknown by gmailapi.google.com with HTTPREST; Mon, 28 Oct 2019 04:32:15 -0400",
        },
        {"Name": "Content-Type", "Value": 'mixed; boundary="===============4922146810840031257=="'},
        {"Name": "MIME-Version", "Value": "1.0"},
        {"Name": "to", "Value": "<some_mail>"},
        {"Name": "cc", "Value": ""},
        {"Name": "bcc", "Value": ""},
        {"Name": "from", "Value": "<some_mail>"},
        {"Name": "subject", "Value": "a mail subject"},
        {"Name": "reply-to", "Value": ""},
        {"Name": "Date", "Value": "Mon, 28 Oct 2019 04:32:15 -0400"},
        {"Name": "Message-Id", "Value": "<some_id>"},
    ],
    "Html": None,
    "RawData": None,
    "ThreadId": "<id>",
    "Date": "Mon, 28 Oct 2019 04:32:15 -0400",
    "Bcc": "",
    "Type": "Gmail",
    "ID": "<id>",
    "Subject": "a mail subject",
}


def test_header_to_date():
    valid_header_date = Client.get_date_from_email_header("Mon, 26 Aug 2019 14:40:04 +0300")
    semi_valid_header_date = Client.get_date_from_email_header("26 Aug 2019 14:40:04 +0300")
    header_date_no_tz = Client.get_date_from_email_header("26 Aug 2019 11:40:04")
    header_x_received = Client.get_date_from_email_header(
        "by 2002:a17:90a:77cb:0:0:0:0 with SMTP id e11csp4670216pjs;        Mon, 26 Aug 2019 03:40:04 -0800 (PST)"
    )
    # all should be the same
    assert valid_header_date == semi_valid_header_date
    assert valid_header_date == header_date_no_tz
    assert header_x_received == valid_header_date


def test_no_label_mail_context_creation():
    client = Client()
    context_gmail, _, _, occurred, is_internal = client.get_email_context(MOCK_MAIL_NO_LABELS, "some_mail")
    assert int(occurred.timestamp()) == 1572251535
    assert is_internal
    assert context_gmail.get("Labels") == EXPECTED_GMAIL_CONTEXT.get("Labels")
    assert context_gmail.get("To") == EXPECTED_GMAIL_CONTEXT.get("To")
    assert context_gmail.get("From") == EXPECTED_GMAIL_CONTEXT.get("From")
    assert context_gmail.get("Subject") == EXPECTED_GMAIL_CONTEXT.get("Subject")


def test_extract_occurred_no_headers():
    occurred, is_valid = Client.get_occurred_date(
        {"payload": {"headers": [{"name": "stam", "value": "stam"}]}, "internalDate": "1610642469000"}
    )
    assert is_valid
    assert occurred.timestamp() == 1610642469


def test_no_date_mail():
    with open("test_data/email_no_date.json") as f:
        msg = json.load(f)
    client = Client()
    context_gmail, _, _, occurred, is_valid = client.get_email_context(msg, "some_mail")
    # check that the x-received date was usd
    assert occurred.timestamp() == parsedate_to_datetime("Mon, 21 Dec 2020 12:11:57 -0800").timestamp()
    assert is_valid
    assert context_gmail.get("Date") == "Mon, 21 Dec 2020 12:11:57 -0800"


def test_generate_auth_link_oob():
    client = Client()
    link = client.generate_auth_link()
    assert link.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "code_challenge=" in link
    assert "code_challenge_method=S256" in link


def test_generate_auth_link_web(mocker):
    mocker.patch("GmailSingleUser.CLIENT_SECRET", "test")
    mocker.patch("GmailSingleUser.CLIENT_ID", "test_id")
    mocker.patch("GmailSingleUser.REDIRECT_URI", "http://localhost:9001")
    client = Client()
    link = client.generate_auth_link()
    assert link.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "code_challenge=" not in link
    assert "code_challenge_method=S256" not in link
    assert "access_type=offline" in link
    assert "redirect_uri=http" in link
    assert "client_id=test_id" in link


SEND_EMAIL_ARGS = [
    {"subject": "test", "to": "test@gmail.com", "body": "hello"},
    {"subject": "test", "to": "test@gmail.com", "htmlBody": "<h1>test</h1>"},
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
    mocker.patch.object(gmail_client, "send_email_request", return_value={"id": "123", "threadId": "123", "labelIds": ["SENT"]})
    mocker.patch.object(demisto, "args", return_value=command_args)

    send_email_entry = send_mail_command(client=gmail_client)
    context_output = send_email_entry["EntryContext"]
    assert "Gmail.SentMail(val.ID && val.Type && val.ID == obj.ID && val.Type == obj.Type)" in context_output
    context_output = context_output["Gmail.SentMail(val.ID && val.Type && val.ID == obj.ID && val.Type == obj.Type)"][0]

    assert context_output.get("To") == command_args.get("to")
    assert context_output.get("Subject") == command_args.get("subject")
    assert context_output.get("Body") == command_args.get("body")
    assert context_output.get("BodyHTML") == command_args.get("htmlBody")
    assert context_output.get("Mailbox") == command_args.get("to")

    markdown_table = send_email_entry["HumanReadable"]
    assert "Gmail" in markdown_table
    assert command_args.get("to") in markdown_table
    assert command_args.get("subject") in markdown_table
    assert "SENT" in markdown_table


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
    mocker.patch.object(gmail_client, "send_email_request", return_value=True)
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
        references=["test", "test1"],
        inReplyTo="test test",
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
    mock_execute = mocker.Mock(return_value={"id": "mock_message_id"})
    mock_send = mocker.Mock(return_value=mock_execute)
    mock_messages = mocker.Mock(send=mocker.Mock(return_value=mock_send))
    mock_users = mocker.Mock(messages=mocker.Mock(return_value=mock_messages))
    mock_service = mocker.Mock(users=mocker.Mock(return_value=mock_users))
    # Patch the service object in the Client class to use the mocked service
    mocker.patch.object(GmailSingleUser.Client, "get_service", new=mock_service)
    # Replace MIMEMultipart with the mock object
    mocker_obj = mocker.patch.object(GmailSingleUser, "MIMEMultipart", return_value=MIMEMultipart())

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
        {
            "maintype": "image",
            "subtype": "png",
            "data": b"\x01",
            "name": "image0.png",
            "cid": "image0.png@11111111_11111111",
            "ID": "image0.png@11111111_11111111",
        },
        {
            "maintype": "image",
            "subtype": "jpeg",
            "data": b"\x05",
            "name": "image1.jpeg",
            "cid": "image1.jpeg@11111111_11111111",
            "ID": "image1.jpeg@11111111_11111111",
        },
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
        {
            "maintype": "image",
            "subtype": "png",
            "data": b"\x01",
            "name": "image0.png",
            "cid": "image0.png@11111111_11111111",
            "ID": "image0.png@11111111_11111111",
        }
    ]
    expected_cleanBody = (
        '\n<html>\n    <body>\n        <img\n\t\t\t\t\t  src="cid:image0.png@11111111_11111111"/>\n    </body>\n</html>'  # noqa: E501
    )

    cleanBody, attachments = client.handle_html(htmlBody)

    assert expected_cleanBody == cleanBody
    assert expected_attachments == attachments


part_test1 = [
    {
        "filename": "image-1.png",
        "headers": [{"name": "Content-ID", "value": "<5678>"}, {"name": "Content-Disposition", "value": "inline"}],
        "body": {"attachmentId": "1234"},
        "mimeType": "",
    }
]

part_test2 = [
    {
        "filename": "image-1.png",
        "headers": [{"name": "Content-ID", "value": "5678"}, {"name": "Content-Disposition", "value": "attachment"}],
        "body": {"attachmentId": "1234"},
        "mimeType": "",
    }
]

part_test3 = [
    {
        "filename": "image-1.png",
        "headers": [{"name": "Content-ID", "value": "None"}, {"name": "Content-Disposition", "value": "attachment"}],
        "body": {"attachmentId": "1234"},
        "mimeType": "",
    }
]


@pytest.mark.parametrize(
    "part, expected_result",
    [
        (part_test1, ("", "", [{"ID": "1234", "Name": "5678-attachmentName-image-1.png"}])),
        (part_test2, ("", "", [{"ID": "1234", "Name": "image-1.png"}])),
        (part_test3, ("", "", [{"ID": "1234", "Name": "image-1.png"}])),
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
        (part_test1, ("", "", [{"ID": "1234", "Name": "image-1.png"}])),
        (part_test2, ("", "", [{"ID": "1234", "Name": "image-1.png"}])),
        (part_test3, ("", "", [{"ID": "1234", "Name": "image-1.png"}])),
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
    monkeypatch.setattr("GmailSingleUser.LEGACY_NAME", True)
    result = client.parse_mail_parts(part)
    assert result == expected_result


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_incidents_command(mocker):
    from GmailSingleUser import Client, get_incidents_command

    client = Client()
    args = {
        "after": "24 Mar 2025 08:17:02 -0700",
        "before": "24 Mar 2025 08:18:02 -0700"
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(
        client,
        "search",
        return_value=(
            util_load_json("test_data/search_email_list.json"),
            "before:1742829482  after:1742829422",
        ),
    )
    result = get_incidents_command(client)
    emails: list = result.raw_response  # type: ignore
    assert emails[0].get("internalDate") == "1742829478000"
    assert len(emails) == 2
    assert "2025-03-24T15:17:58.000Z | SENT | 111 |\n| test@test.com | Test message 1234 | 2025-03-24T1" in result.readable_output


@pytest.mark.parametrize(
    "test_input, expected_output",
    [
        (("2023-01-01T12:00:00Z", "date"), datetime(2023, 1, 1, 12, 0, tzinfo=UTC)),
        ((datetime(2023, 1, 1, 12, 0), "date"), datetime(2023, 1, 1, 12, 0)),
        ((datetime(2023, 1, 1, 12, 0), "str"), "2023-01-01T12:00:00Z"),
        (("2023-01-01T12:00:00Z", "str"), "2023-01-01T12:00:00Z"),
    ],
    ids=["date_str_to_datetime", "date_datetime_pass", "datetime_to_iso_str", "iso_str_pass"]
)
def test_parse_date(test_input, expected_output):
    """
    Given:
        - A tuple input specifying the format type ('date' or 'isoformat') and the date value.
    When:
        - The parse_date function is invoked with the given format type and date.
    Then:
        - Confirm that the output matches the expected datetime object or ISO formatted string.
    """
    from GmailSingleUser import Client, parse_date
    client = Client()
    result = parse_date(client, *test_input)
    assert result == expected_output, f"Expected {expected_output} but got {result}"


@pytest.mark.parametrize(
    "input_args, expected",
    [
        ({"before": "now", "after": "1 day ago"},
         ('1672574400', '1672488000')),  # Unix timestamps for '2023-01-01 12:00:00', '2022-12-31 12:00:00'
        ({"before": "2023-01-01 12:00:00", "after": "2022-12-31 12:00:00"},
         ('1672574400', '1672488000')),  # Unix timestamps for the same fixed dates
        ({},
         ('1672574400', '1672488000')),  # Default case: 'now' and '1 day ago' will be the same as the first case
    ],
    ids=["default_dates", "specific_dates", "no_params"]
)
@freeze_time("2023-01-01 12:00:00 UTC")
def test_get_unix_date(input_args, expected):
    """
    Given:
        - Dictionary with 'before' and 'after' date parameters, or defaults.
    When:
        - Converting dates to Unix timestamps using get_unix_date.
    Then:
        - Validate that the conversions match expected Unix timestamps.
    """
    from GmailSingleUser import get_unix_date
    assert get_unix_date(input_args) == expected


def test_fetch_incidents_set_last_run_called_correctly(mocker):
    """
    Test the `fetch_incidents` function to ensure it correctly updates the 'setLastRun' after fetching incidents.

    Given:
    - A GmailSingleUser client with a mocked Gmail service and necessary method patches.
    - A patch on 'GmailSingleUser.execute_gmail_action' to simulate Gmail API responses for 'list' and 'get' actions based on the fetch count.
    - Initial 'getLastRun' returning a specific datetime indicating the last run time.
    - An external file 'test_data/a.json' to simulate fetched email details.

    When:
    - The `fetch_incidents` function is called twice, first with an initial fetch count of 0, then incremented to simulate a subsequent fetch.

    Then:
    - The function should update 'setLastRun' correctly after each call:
      - After the first call, 'setLastRun' should contain exactly two messages with IDs '1' and '3'.
      - After the second call, 'setLastRun' should contain exactly three messages with IDs '1', '2', and '3', reflecting the updated fetch.
      - The 'lookback_msg' field in the data sent to 'setLastRun' should reflect the correct IDs of the messages fetched in each incident fetch.
    """  # noqa: E501
    from GmailSingleUser import fetch_incidents
    import GmailSingleUser
    gmail_single_user_client = Client()
    # Mock the chain of calls: service.users().messages().send().execute()
    mock_execute = mocker.Mock(return_value={"id": "mock_message_id"})
    mock_send = mocker.Mock(return_value=mock_execute)
    mock_messages = mocker.Mock(send=mocker.Mock(return_value=mock_send))
    mock_users = mocker.Mock(messages=mocker.Mock(return_value=mock_messages))
    mock_service = mocker.Mock(users=mocker.Mock(return_value=mock_users))
    # Patch the service object in the Client class to use the mocked service
    mocker.patch.object(GmailSingleUser.Client, "get_service", new=mock_service)
    fetch_count = 0

    def execute_gmail_action_side_effect(service, action, args):
        nonlocal fetch_count
        if action == "list":
            if fetch_count == 0:
                return {'messages': [{'id': '1'}, {'id': '3'}]}
            return {'messages': [{'id': '1'}, {'id': '2'}, {'id': '3'}]}
        elif action == "get":
            message_id = args.get("id")
            for item in util_load_json("test_data/lookback_emails.json"):
                if item.get("id") == message_id:
                    return item
        return {}

    # Mocking external functions and globals
    mocker.patch('GmailSingleUser.execute_gmail_action', side_effect=execute_gmail_action_side_effect)
    mocker.patch('GmailSingleUser.demisto.getLastRun', return_value={"gmt_time": "2025-02-24T15:17:05Z"})
    mock_set_last_run = mocker.patch('GmailSingleUser.demisto.setLastRun')

    fetch_incidents(gmail_single_user_client)

    last_args = mock_set_last_run.call_args[0][0]
    assert len(last_args['lookback_msg']) == 2, "lookback_msg does not contain exactly three messages in the first fetch"

    fetch_count += 1
    fetch_incidents(gmail_single_user_client)

    # Check the last arguments sent to setLastRun
    last_args = mock_set_last_run.call_args[0][0]

    # Assert the lookback_msg contains the correct messages
    assert 'lookback_msg' in last_args, "lookback_msg key is missing in the arguments sent to setLastRun"
    assert len(last_args['lookback_msg']) == 3, "lookback_msg does not contain exactly three messages in the secund fetch"
    assert [id for id, _ in last_args['lookback_msg']] == ["1", "2", "3"], "lookback_msg do"
