import json
import unittest
import uuid
from unittest.mock import MagicMock, patch

import pytest
from EWSO365 import (
    SMTP,
    ExpandGroup,
    GetSearchableMailboxes,
    add_additional_headers,
    cast_mime_item_to_message,
    create_message,
    decode_email_data,
    email,
    fetch_emails_as_incidents,
    fetch_last_emails,
    find_folders,
    get_attachment_name,
    get_client_from_params,
    get_expanded_group,
    get_item_as_eml,
    get_searchable_mailboxes,
    handle_attached_email_with_incorrect_from_header,
    handle_attached_email_with_incorrect_message_id,
    handle_html,
    handle_incorrect_message_id,
    handle_transient_files,
    parse_incident_from_item,
    parse_item_as_dict,
)
from exchangelib import EWSDate, EWSDateTime, EWSTimeZone, FileAttachment
from exchangelib.attachments import AttachmentId, ItemAttachment
from exchangelib.items import Item, Message
from exchangelib.properties import MessageHeader
from freezegun import freeze_time

import demistomock as demisto

with open("test_data/commands_outputs.json") as f:
    COMMAND_OUTPUTS = json.load(f)
with open("test_data/raw_responses.json") as f:
    RAW_RESPONSES = json.load(f)


class TestNormalCommands:
    """
    The test class checks the following normal_commands:
        * ews-find-folders
        * ews-expand-group
        * ews-get-searchable-mailboxes
        * ews-expand-group
    """

    class MockClient:
        class MockAccount:
            DEFAULT_FOLDER_TRAVERSAL_DEPTH = 3

            def __init__(self):
                self.root = self
                self.walk_res = []
                self.all_res = ""
                self.contacts = self

            def walk(self):
                return self.walk_res

            def tree(self):
                return ""

            def all(self):
                return self.all_res

        def __init__(self):
            self.default_target_mailbox = ""
            self.client_id = ""
            self.client_secret = ""
            self.tenant_id = ""
            self.folder = ""
            self.is_public_folder = ""
            self.request_timeout = ""
            self.max_fetch = 50
            self.self_deployed = ""
            self.insecure = ""
            self.proxy = ""
            self.account = self.MockAccount()
            self.protocol = ""
            self.mark_as_read = False
            self.folder_name = ""
            self.version = 'O365'

        def get_account(self, target_mailbox=None, access_type=None):
            return self.account

        def get_protocol(self):
            return self.protocol

        def get_items_from_mailbox(self, account, item_ids):
            return ""

        def get_item_from_mailbox(self, account, item_id):
            return ""

        def get_attachments_for_item(self, item_id, account, attachment_ids=None):
            return ""

        def is_default_folder(self, folder_path, is_public):
            return ""

        def get_folder_by_path(self, path, account=None, is_public=False):
            return ""

    def test_ews_find_folders(self, mocker):
        """
        This test checks the following normal_command:
            * ews-find-folders
        Using this method:
        Given:
            - command name is ews-find-folders
            - client function name to mock
            - expected raw result
            - expected command result
        When:
            - we want to execute the command function
        Then:
            - the expected result will be the same as the entry context
        """
        command_name = "ews-find-folders"
        raw_response = RAW_RESPONSES[command_name]
        expected = COMMAND_OUTPUTS[command_name]
        client = self.MockClient()
        client.account.walk_res = raw_response
        res = find_folders(client)
        actual_ec = res[1]
        assert expected == actual_ec

    def test_get_searchable_mailboxes(self, mocker):
        """
        This test checks the following normal_command:
            * ews-get-searchable-mailboxes
        Using this method:
        Given:
            - command name is ews-get-searchable-mailboxes
            - client function name to mock
            - expected raw result
            - expected command result
        When:
            - we want to execute the command function
        Then:
            - the expected result will be the same as the entry context
        """
        command_name = "ews-get-searchable-mailboxes"
        expected = COMMAND_OUTPUTS[command_name]
        raw_response = RAW_RESPONSES["ews-get-searchable-mailboxes"]
        mocker.patch.object(GetSearchableMailboxes, "__init__", return_value=None)
        mocker.patch.object(GetSearchableMailboxes, "call", return_value=raw_response)
        client = self.MockClient()
        res = get_searchable_mailboxes(client)
        actual_ec = res.outputs
        assert expected.get(res.outputs_prefix) == actual_ec

    def test_expand_group(self, mocker):
        """
        This test checks the following normal_command:
            * ews-expand-group
        Using this method:
        Given:
            - command name is ews-expand-group
            - client function name to mock
            - expected raw result
            - expected command result
        When:
            - we want to execute the command function
        Then:
            - the expected result will be the same as the entry context
        """
        command_name = "ews-expand-group"
        expected = COMMAND_OUTPUTS[command_name]
        raw_response = RAW_RESPONSES[command_name]
        mocker.patch.object(ExpandGroup, "__init__", return_value=None)
        mocker.patch.object(ExpandGroup, "call", return_value=raw_response)
        client = self.MockClient()
        res = get_expanded_group(
            client, email_address="testgroup-1@demistodev.onmicrosoft.com"
        )
        actual_ec = res.outputs
        assert expected.get(res.outputs_prefix) == actual_ec


MESSAGES = [
    Message(subject='message1',
            message_id='message1',
            text_body='Hello World',
            body='message1',
            datetime_received=EWSDateTime(2021, 7, 14, 13, 00, 00, tzinfo=EWSTimeZone(key='UTC')),
            datetime_sent=EWSDateTime(2021, 7, 14, 13, 00, 00, tzinfo=EWSTimeZone(key='UTC')),
            datetime_created=EWSDateTime(2021, 7, 14, 13, 00, 00, tzinfo=EWSTimeZone(key='UTC'))
            ),
    Message(subject='message2',
            message_id='message2',
            text_body='Hello World',
            body='message2',
            datetime_received=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone(key='UTC')),
            datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone(key='UTC')),
            datetime_created=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone(key='UTC'))
            ),
    Message(subject='message3',
            message_id='message3',
            text_body='Hello World',
            body='message3',
            datetime_received=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone(key='UTC')),
            datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone(key='UTC')),
            datetime_created=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone(key='UTC'))
            ),

]
CASE_FIRST_RUN_NO_INCIDENT = (
    {},
    [],
    {'lastRunTime': None, 'folderName': 'Inbox', 'ids': [], 'errorCounter': 0}
)
CASE_FIRST_RUN_FOUND_INCIDENT = (
    {},
    MESSAGES[:1],
    {'lastRunTime': '2021-07-14T13:00:00Z', 'folderName': 'Inbox', 'ids': ['message1'], 'errorCounter': 0}
)
CASE_SECOND_RUN_FOUND_ONE_INCIDENT = (
    {'lastRunTime': '2021-07-14T12:59:17Z', 'folderName': 'Inbox', 'ids': []}, MESSAGES[:1],
    {'lastRunTime': '2021-07-14T13:00:00Z', 'folderName': 'Inbox', 'ids': ['message1'], 'errorCounter': 0})
CASE_SECOND_RUN_FOUND_MORE_THAN_ONE_FIRST_RUN = (
    {'lastRunTime': '2021-07-14T13:05:17Z', 'folderName': 'Inbox', 'ids': ['message1']}, MESSAGES,
    {'lastRunTime': '2021-07-14T13:09:00Z', 'folderName': 'Inbox', 'ids': ['message2'], 'errorCounter': 0})
CASE_SECOND_RUN_FOUND_MORE_THAN_ONE_NEXT_RUN = (
    {'lastRunTime': '2021-07-14T13:09:00Z', 'folderName': 'Inbox', 'ids': ['message2']}, MESSAGES[1:],
    {'lastRunTime': '2021-07-14T13:09:00Z', 'folderName': 'Inbox', 'ids': ['message2', 'message3'], 'errorCounter': 0})
CASE_SECOND_RUN_NO_INCIDENTS = (
    {'lastRunTime': '2021-07-14T12:59:17Z', 'folderName': 'Inbox', 'ids': ['message1']}, [],
    {'lastRunTime': '2021-07-14T12:59:17Z', 'folderName': 'Inbox', 'ids': ['message1'], 'errorCounter': 0})

CASES = [
    CASE_FIRST_RUN_NO_INCIDENT,
    CASE_FIRST_RUN_FOUND_INCIDENT,
    CASE_SECOND_RUN_FOUND_ONE_INCIDENT,
    CASE_SECOND_RUN_FOUND_MORE_THAN_ONE_FIRST_RUN,
    CASE_SECOND_RUN_FOUND_MORE_THAN_ONE_NEXT_RUN,
    CASE_SECOND_RUN_NO_INCIDENTS
]


@pytest.mark.parametrize('current_last_run, messages, expected_last_run', CASES)
def test_last_run(mocker, current_last_run, messages, expected_last_run):
    """Check the fetch command.

    Given:
        - Last Run data including time and ids to be excluded.
    When:
        - Running fetch command.
    Then:
        - Validates the new Last Run new excluded IDs and last run time.
    """

    class MockObject:
        def filter(self, last_modified_time__gte='', datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            # Return a list of emails
            class MockQuerySet:
                def __iter__(self):
                    return (t for t in messages)

            return MockQuerySet()

    def mock_get_folder_by_path(path, account=None, is_public=False):
        return MockObject()

    from EWSO365 import RECEIVED_FILTER
    client = TestNormalCommands.MockClient()
    client.max_fetch = 1
    client.get_folder_by_path = mock_get_folder_by_path
    client.folder_name = 'Inbox'
    last_run = mocker.patch.object(demisto, 'setLastRun')
    fetch_emails_as_incidents(client, current_last_run, RECEIVED_FILTER, False)
    assert last_run.call_args[0][0].get('lastRunTime') == expected_last_run.get('lastRunTime')
    assert set(last_run.call_args[0][0].get('ids')) == set(expected_last_run.get('ids'))


@pytest.mark.parametrize(
    "skip_unparsable_emails_param, exception_type, expected",
    [
        (True, IndexError("Unparsable email ignored"), "Unparsable email ignored"),
        (True, UnicodeError("Unparsable email ignored"), "Unparsable email ignored"),
        (True, Exception("Unparsable email not ignored"), "Unparsable email not ignored"),
        (False, Exception("Unparsable email not ignored"), "Unparsable email not ignored"),
        (False, IndexError("Unparsable email not ignored"), "Unparsable email not ignored"),
    ],
)
def test_skip_unparsable_emails(mocker, skip_unparsable_emails_param, exception_type, expected):
    """Check the fetch command in skip_unparsable_emails parameter use-cases.
    Given:
        - An exception has occurred while processing an email message.
    When:
        - Running fetch command.
    Then:
        - If skip_unparsable_emails parameter is True, and the Exception is a specific type we allow to fail due to parsing error:
            log the exception message and continue processing the next email (ignore unparsable email).
        - If skip_unparsable_emails parameter is False, raise the exception (crash the fetch command).
    """
    import EWSO365

    import demistomock as demisto

    class MockEmailObject:
        def __init__(self):
            self.message_id = "Value"

    last_run = {"lastRunTime": "2021-07-14T12:59:17Z", "folderName": "Inbox", "ids": ["message1"]}

    client = TestNormalCommands.MockClient()
    mocker.patch.object(
        demisto, "getLastRun", return_value={"lastRunTime": "2021-07-14T12:59:17Z", "folderName": "Inbox", "ids": []}
    )
    mocker.patch.object(EWSO365, "parse_incident_from_item", side_effect=exception_type)
    mocker.patch.object(EWSO365, "fetch_last_emails", return_value=[MockEmailObject()])
    mocker.patch.object(EWSO365, "get_last_run", return_value=last_run)

    with pytest.raises((Exception, UnicodeError, IndexError)) as e:
        fetch_emails_as_incidents(client, last_run, "received-time", skip_unparsable_emails_param)
        assert expected == str(e)


def test_fetch_and_mark_as_read(mocker):
    """
    Given:
        - Nothing.
    When:
        - Running fetch command.
    Then:
        - If the parameter "Mark fetched emails as read" is set to true, the function mark_item_as_read should be called.
    """

    class MockObject:
        def filter(self, last_modified_time__gte='', datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            # Return a list of emails
            class MockQuerySet:
                def __iter__(self):
                    return (t for t in [])

            return MockQuerySet()

    def mock_get_folder_by_path(path, account=None, is_public=False):
        return MockObject()

    from EWSO365 import RECEIVED_FILTER
    client = TestNormalCommands.MockClient()
    client.get_folder_by_path = mock_get_folder_by_path
    client.folder_name = 'Inbox'
    mark_item_as_read = mocker.patch('EWSO365.mark_item_as_read')

    fetch_emails_as_incidents(client, {}, RECEIVED_FILTER, False)
    assert mark_item_as_read.called is False

    client.mark_as_read = True
    fetch_emails_as_incidents(client, {}, RECEIVED_FILTER, False)
    assert mark_item_as_read.called is True


HEADERS_PACKAGE = [
    ('', {}),
    ('header=value', {'header': 'value'}),
    ('header1=value1, header2=value2', {'header1': 'value1', 'header2': 'value2'}),
    # Can register the same header more then once.
    ('header3=value3, header3=other_value', {'header3': 'other_value'})
]


@pytest.mark.parametrize('input_headers, expected_output', HEADERS_PACKAGE)
def test_additional_headers(input_headers, expected_output):
    """Check the registration of custom headers to the Message object.

    Given:
        - Custom headers and their values (as a string)
    When:
        - Adding custom headers to the Message object before sending it
    Then:
        - Register new headers to the Message object

    """
    assert add_additional_headers(input_headers) == expected_output


TRANSIENT_PACKAGE = [
    ('', '', '', []),
    (
        'file1, file2', 'content1, content2', 'cid1',
        [
            {
                'name': 'file1',
                'data': bytes('content1', 'utf-8'),
                'cid': 'cid1'
            },
            {
                'name': 'file2',
                'data': bytes('content2', 'utf-8'),
                'cid': ''
            },
        ]
    ),
    (
        'file1, file2', 'content1, content2', ',cid2',
        [
            {
                'name': 'file1',
                'data': bytes('content1', 'utf-8'),
                'cid': ''
            },
            {
                'name': 'file2',
                'data': bytes('content2', 'utf-8'),
                'cid': 'cid2'
            },
        ]
    )
]


@pytest.mark.parametrize('transient_files, transient_files_contents, transient_files_cids, expected_output',
                         TRANSIENT_PACKAGE)
def test_handle_transient_files(transient_files, transient_files_contents, transient_files_cids, expected_output):
    """Check the parsing of transient files

    Given:
        - Files names (as a string)
        - Files contents (as a string)
        - Files cids (as a string)
    When:
        - Parsing the data for transient files creation
    Then:
        - Create the dictionary for files creation

    """
    assert handle_transient_files(transient_files, transient_files_contents, transient_files_cids) == expected_output


HTML_PACKAGE = [
    ('<html><body>some text</body></html>', ('<html><body>some text</body></html>', [])),
    ('<html><body>some text <img src="data:image/abcd;base64,abcd"></body></html>',
     ('<html><body>some text <img src="cid:image0@abcd1234_abcd1234"></body></html>',
      [{'data': b'i\xb7\x1d', 'name': 'image0', 'cid': 'image0@abcd1234_abcd1234'}],
      )
     )
]


@pytest.mark.parametrize('html_input, expected_output', HTML_PACKAGE)
def test_handle_html(mocker, html_input, expected_output):
    """Check the parsing of the html_body

    Given:
        - String that represents the HTML body
    When:
        - Parsing the HTML string to incorporate the inline images
    Then:
        - Clean the HTML string and add the relevant references to image files

    """
    mocker.patch.object(uuid, 'uuid4', return_value='abcd1234')
    # mocker.patch.object(demisto, 'uniqueFile', return_value='12345678')
    clean_html, attachments = handle_html(html_input)
    assert clean_html == expected_output[0]
    assert len(attachments) == len(expected_output[1])
    for i, attachment in enumerate(attachments):
        attachment_params = {'data': attachment.content, 'name': attachment.name, 'cid': attachment.content_id}
        assert attachment_params == expected_output[1][i]


@freeze_time('2021-05-23 13:18:14.901293+00:00')
@pytest.mark.parametrize('since_datetime, filter_arg, expected_result',
                         [('', 'last_modified_time__gte', EWSDateTime.from_string('2021-05-23 13:08:14.901293+00:00')),
                          ('2021-05-23 21:28:14.901293+00:00', 'datetime_received__gte',
                           '2021-05-23 21:28:14.901293+00:00')
                          ])
def test_fetch_last_emails(mocker, since_datetime, filter_arg, expected_result):
    """
    Given:
        - First fetch timestamp - no last_run
        - Not the first time fetching - last_run with a date

    When:
        - Fetching last emails

    Then:
        - Verify last_modified_time__gte is ten minutes earlier
        - Verify datetime_received__gte according to the datetime received
    """

    class MockObject:
        def filter(self, last_modified_time__gte='', datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            class MockQuerySet:
                def __iter__(self):
                    return (t for t in [Message(), Message(), Message(), Message(), Message()])

            return MockQuerySet()

    def mock_get_folder_by_path(path, account=None, is_public=False):
        return MockObject()

    client = TestNormalCommands.MockClient()
    client.get_folder_by_path = mock_get_folder_by_path
    mocker.patch.object(MockObject, 'filter')

    fetch_last_emails(client, since_datetime=since_datetime)
    assert MockObject.filter.call_args[1].get(filter_arg) == expected_result


@freeze_time('2021-05-23 18:28:14.901293+00:00')
@pytest.mark.parametrize('max_fetch, expected_result',
                         [(6, 5),
                          (2, 2),
                          (5, 5)])
def test_fetch_last_emails_max_fetch(max_fetch, expected_result):
    """
    Given:
        - Max fetch is 6
        - Max fetch is 2
        - Max fetch is 5

    When:
        - Fetching last emails - need to make sure to return emails according to the max_fetch param.

    Then:
        - Return 5 emails (Cause we only have 5 emails)
        - Return 2 emails
        - Return 5 emails
    """

    class MockObject:
        def filter(self, last_modified_time__gte='', datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            # Return a list of emails
            class MockQuerySet:
                def __iter__(self):
                    return (t for t in [Message(), Message(), Message(), Message(), Message()])

            return MockQuerySet()

    def mock_get_folder_by_path(path, account=None, is_public=False):
        return MockObject()

    client = TestNormalCommands.MockClient()
    client.max_fetch = max_fetch
    client.get_folder_by_path = mock_get_folder_by_path

    emails = fetch_last_emails(client, since_datetime='')
    assert len(emails) == expected_result


@pytest.mark.parametrize("mime_content, expected_data, expected_attachmentSHA256", [
    (b'\xc400',
     '\r\nÄ00',
     '90daab88e6fac673e12acbbe28879d8d2b60fc2f524f1c2ff02fccb8e3e526a8'),
    ("Hello, this is a sample email with non-ASCII characters: é, ñ, ü.",
     "\r\nHello, this is a sample email with non-ASCII characters: é, ñ, ü.",
     "228d032fb728b3f86c49084b7d99ec37e913789415789084cd44fd94ea4647b7"),
    ("Hello, this is a sample email with ASCII characters",
     "\r\nHello, this is a sample email with ASCII characters",
     "84f8a0dec6732c2341eeb7b05ebdbe919e7092bcaf6505fbd6cda495d89b55d6")
])
def test_parse_incident_from_item(mocker, mime_content, expected_data, expected_attachmentSHA256):
    """
    Given:
        1. Message item with attachment that contains non UTF-8 encoded char
        2. Message item with attachment that contains non-ASCII characters
        3. Message item with attachment that contains only ASCII characters.

    When:
        - Parsing incident from item

    Verify:
        - Parsing runs successfully
        - Incident attachment is not empty
    """
    mock_file_result = mocker.patch('EWSO365.fileResult')
    message = Message(
        datetime_received=EWSDate(year=2021, month=1, day=25),
        datetime_created=EWSDate(year=2021, month=1, day=25),
        to_recipients=[],
        attachments=[
            ItemAttachment(
                item=Item(mime_content=mime_content),
                attachment_id=AttachmentId(),
                last_modified_time=EWSDate(year=2021, month=1, day=25),
            ),
        ],
    )
    incident = parse_incident_from_item(message)

    assert incident
    assert incident['attachment']
    assert incident["rawJSON"]
    raw_json = json.loads(incident["rawJSON"])
    assert raw_json['attachments'][0]['attachmentSHA256'] == expected_attachmentSHA256
    mock_file_result.assert_called_once_with("demisto_untitled_attachment.eml", expected_data)


def test_parse_incident_from_item_with_attachments(mocker):
    """
    Given:
        - Message item with attachment that contains email attachments

    When:
        - Parsing incident from item

    Verify:
        - Parsing runs successfully
    """
    content = b'ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901;' \
              b' d=microsoft.com; cv=none;b=ES/YXpFlV19rlN1iV+ORg5RzID8GPSQL' \
              b'nUT26MNdeTzcQSwK679doIz5Avpv8Ps2H/aBkBamwRNOCJBkl7iCHyy+04yRj3ghikw3u/ufIFHi0sQ7QG95mO1PVPLibv9A=='

    message = Message(
        datetime_received=EWSDate(year=2021, month=1, day=25),
        datetime_created=EWSDate(year=2021, month=1, day=25),
        to_recipients=[],
        attachments=[
            ItemAttachment(
                name='test_attachment.eml',
                item=Item(mime_content=content, headers=[]),
                attachment_id=AttachmentId(),
                last_modified_time=EWSDate(year=2021, month=1, day=25),
            ),
        ],
    )
    mocker.patch('EWSO365.fileResult')
    incident = parse_incident_from_item(message)

    assert incident['attachment']


def test_parse_incident_from_item_with_eml_attachment_header_integrity(mocker):
    """
    Given:
        1. Message with EML attachment
        2. Attachment Item Header Keys differ in case from mime content case

    When:
        - Parsing incident from item

    Verify:
        - Result EML attachment headers are intact

    """

    # raw mime data
    content = b'MIME-Version: 1.0\r\n' \
              b'Message-ID:\r\n' \
              b' <message-test-idRANDOMVALUES@testing.com>' \
              b'Content-Type: text/plain; charset="us-ascii"\r\n' \
              b'X-FAKE-Header: HVALue\r\n' \
              b'X-Who-header: whovALUE\r\n' \
              b'DATE: 2023-12-16T12:04:45\r\n' \
              b'\r\nHello'
    # headers set in the Item
    item_headers = [
        # these headers may have different casing than what exists in the raw content
        MessageHeader(name="Mime-Version", value="1.0"),
        MessageHeader(name="Content-Type", value="text/plain; charset=\"us-ascii\""),
        MessageHeader(name="X-Fake-Header", value="HVALue"),
        MessageHeader(name="X-WHO-header", value="whovALUE"),
        # this is a header whose value is different. The field is limited to 1 by RFC
        MessageHeader(name="Date", value="2023-12-16 12:04:45"),
        # This is an extra header logged by exchange in the item -> add to the output
        MessageHeader(name="X-EXTRA-Missed-Header", value="EXTRA")
    ]

    # sent to "fileResult", original headers from content with matched casing, with additional header
    expected_data = 'MIME-Version: 1.0\r\n' \
                    'Message-ID:  <message-test-idRANDOMVALUES@testing.com>\r\n' \
                    'X-FAKE-Header: HVALue\r\n' \
                    'X-Who-header: whovALUE\r\n' \
                    'DATE: 2023-12-16T12:04:45\r\n' \
                    'X-EXTRA-Missed-Header: EXTRA\r\n' \
                    '\r\nHello'

    message = Message(
        datetime_received=EWSDate(year=2021, month=1, day=25),
        datetime_created=EWSDate(year=2021, month=1, day=25),
        to_recipients=[],
        attachments=[
            ItemAttachment(
                item=Item(mime_content=content, headers=item_headers),
                attachment_id=AttachmentId(),
                last_modified_time=EWSDate(year=2021, month=1, day=25),
            ),
        ],
    )
    mock_file_result = mocker.patch('EWSO365.fileResult')
    parse_incident_from_item(message)
    # assert the fileResult is created with the expected results
    mock_file_result.assert_called_once_with("demisto_untitled_attachment.eml", expected_data)


@pytest.mark.parametrize('params, expected_result', [
    ({'_tenant_id': '_tenant_id', '_client_id': '_client_id', 'default_target_mailbox': 'default_target_mailbox'},
     'Key / Application Secret must be provided.'),
    ({'credentials': {'password': '1234'}, '_client_id': '_client_id',
      'default_target_mailbox': 'default_target_mailbox'}, 'Token / Tenant ID must be provided.'),
    ({'_tenant_id': '_tenant_id', 'credentials': {'password': '1234'},
      'default_target_mailbox': 'default_target_mailbox'}, 'ID / Application ID must be provided.')
])
def test_invalid_params(mocker, params, expected_result):
    """
    Given:
      - Configuration parameters
    When:
      - One of the required parameters are missed.
    Then:
      - Ensure the exception message as expected.
    """
    import EWSO365
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'error')
    EWSO365.sub_main()
    EWSO365.log_stream = None

    assert "Exception: " + expected_result in demisto.error.call_args[0][0]


@pytest.mark.parametrize(argnames='old_credentials, new_credentials, expected',
                         argvalues=[
                             ('old_client_secret', {'password': 'new_client_secret'}, 'new_client_secret'),
                             ('old_client_secret', None, 'old_client_secret')])
def test_credentials_with_old_secret(mocker, old_credentials, new_credentials, expected):
    """
    Given:
      - Configuration contained credentials and old client_secret
    When:
      - init the MS client.
    Then:
      - Ensure the new credentials is taken if exist and old if new doesn't exist.
    """
    mocker.patch('EWSO365.MicrosoftClient.get_access_token', return_value='test_token')
    params = {
        'credentials': new_credentials,
        'client_secret': old_credentials,
        '_client_id': 'new_client_id',
        '_tenant_id': 'new_tenant_id',
        'default_target_mailbox': 'test',
        'self_deployed': True,
    }
    client = get_client_from_params(params)
    assert client.ms_client.client_secret == expected


def test_categories_parse_item_as_dict():
    """
    Given -
        a Message with categories.

    When -
        running the parse_item_as_dict function.

    Then -
        verify that the categories were parsed correctly.
    """

    message = Message(subject='message4',
                      message_id='message4',
                      text_body='Hello World',
                      body='message4',
                      datetime_received=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone(key='UTC')),
                      datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone(key='UTC')),
                      datetime_created=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone(key='UTC')),
                      categories=['Purple category', 'Orange category']
                      )

    return_value = parse_item_as_dict(message)
    assert return_value.get("categories") == ['Purple category', 'Orange category']


@pytest.mark.parametrize("subject, expected_file_name", [
    ("test_subject", "test_subject.eml"),
    ("", "demisto_untitled_eml.eml"),
    ("another subject", "another subject.eml")
])
def test_get_item_as_eml(subject, expected_file_name, mocker):
    """
    Given
        1. An Item Exists in the Target Mailbox
        2. That Item Can be Retrieved By Item ID
    When
        - Requesting Item As EML

    Then
        - Item is converted to an EML with the correct filename and headers intact.

    """
    content = b'MIME-Version: 1.0\r\n' \
              b'Message-ID:\r\n' \
              b' <message-test-idRANDOMVALUES@testing.com>' \
              b'Content-Type: text/plain; charset="us-ascii"\r\n' \
              b'X-FAKE-Header: HVALue\r\n' \
              b'X-Who-header: whovALUE\r\n' \
              b'DATE: 2023-12-16T12:04:45\r\n' \
              b'\r\nHello'
    # headers set in the Item
    item_headers = [
        # these header keys may have different casing than what exists in the raw content
        MessageHeader(name="Mime-Version", value="1.0"),
        MessageHeader(name="Content-Type", value="text/plain; charset=\"us-ascii\""),
        MessageHeader(name="X-Fake-Header", value="HVALue"),
        MessageHeader(name="X-WHO-header", value="whovALUE"),
        # this is a header whose value is different. The field is limited to 1 by RFC
        MessageHeader(name="Date", value="2023-12-16 12:04:45"),
        # This is an extra header logged by exchange in the item -> add to the output
        MessageHeader(name="X-EXTRA-Missed-Header", value="EXTRA")
    ]
    expected_data = 'MIME-Version: 1.0\r\n' \
                    'Message-ID:  <message-test-idRANDOMVALUES@testing.com>\r\n' \
                    'X-FAKE-Header: HVALue\r\n' \
                    'X-Who-header: whovALUE\r\n' \
                    'DATE: 2023-12-16T12:04:45\r\n' \
                    'X-EXTRA-Missed-Header: EXTRA\r\n' \
                    '\r\nHello'

    class MockEWSClient:

        def __init__(self, *args, **kwargs):
            pass

        def get_account(self, target_mailbox):
            return "Account"

        def get_item_from_mailbox(self, account, item_id):
            return Item(mime_content=content, headers=item_headers, subject=subject)

    mock_file_result = mocker.patch('EWSO365.fileResult')

    get_item_as_eml(MockEWSClient(), "item", "account@test.com")

    mock_file_result.assert_called_once_with(expected_file_name, expected_data)


@pytest.mark.parametrize('message_content', ('Holá', 'À bientôt!', '今日は!'))
def test_decode_email_data(message_content):
    """
    Given a message containing characters in:
        a. Spanish
        b. French
        c. Japanese

    When: decoding the content

    Then make sure the content and characters are decoded correctly.
    """
    class MockMimeItem:
        mime_content: str = ''

        def __init__(self, message: str):
            self.mime_content = message

    mime_item = cast_mime_item_to_message(MockMimeItem(message_content))
    result = decode_email_data(mime_item)
    assert result == f'\r\n{message_content}'


class TestEmailModule(unittest.TestCase):

    @patch('EWSO365.FileAttachment.__new__')
    @patch('EWSO365.HTMLBody')
    @patch('EWSO365.Body')
    @patch('EWSO365.Message')
    def test_create_message_with_html_body(self, mock_message, mock_body, mock_html_body, mock_file_attachment):
        """
        Test create_message function with an HTML body.
        """
        # Setup
        to = ["recipient@example.com"]
        subject = "Test Subject"
        html_body = "<p>Test HTML Body</p>"
        attachments = [{"name": "file.txt", "data": "data", "cid": "12345"}]
        mock_message.return_value = MagicMock()
        mock_html_body.return_value = MagicMock()
        mock_file_attachment.return_value = MagicMock(spec=FileAttachment)

        # Call the function
        result = create_message(
            to, True, subject, html_body=html_body, attachments=attachments
        )

        # Assertions
        mock_html_body.assert_called_once_with(html_body)
        mock_file_attachment.assert_called_once_with(FileAttachment,
                                                     name="file.txt", content="data", is_inline=True, content_id="12345"
                                                     )
        mock_message.assert_called_once()
        assert isinstance(result[0], MagicMock)

    @patch('EWSO365.FileAttachment.__new__')
    @patch('EWSO365.HTMLBody')
    @patch('EWSO365.Body')
    @patch('EWSO365.Message')
    def test_create_message_with_html_body_inline_image_with_handle_html(
        self,
        mock_message,
        mock_body,
        mock_html_body,
        mock_file_attachment
    ):
        """
        Test create_message function with an HTML body.
        """
        import EWSO365
        # Setup
        to = ["recipient@example.com"]
        subject = "Test Subject"
        original_html_body = '<p><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA"/></p>'
        new_html_body = '<p><img src="cid:image0@11111111_11111111"/></p>'
        attachments = [{"name": "file.txt", "data": "data", "cid": "12345"}]

        mock_message.return_value = MagicMock()
        mock_html_body.return_value = MagicMock()
        mock_file_attachment.return_value = MagicMock(spec=FileAttachment)
        with patch.object(EWSO365.demisto, 'uniqueFile', return_value="1234567"), \
                patch.object(EWSO365.demisto, 'getFilePath', return_value={"path": "", "name": ""}), \
                patch.object(uuid, 'uuid4', return_value="111111111"):  # noqa: F821
            # Call the function
            result = create_message(
                to, True, subject, html_body=original_html_body, attachments=attachments
            )

            # Assertions
            mock_html_body.assert_called_once_with(new_html_body)
            mock_message.assert_called_once()
            assert isinstance(result[0], MagicMock)

    @patch('EWSO365.FileAttachment.__new__')
    @patch('EWSO365.HTMLBody')
    @patch('EWSO365.Body')
    @patch('EWSO365.Message')
    def test_create_message_with_html_body_inline_image_no_handle_html(
        self,
        mock_message,
        mock_body,
        mock_html_body,
        mock_file_attachment
    ):
        """
        Test create_message function with an HTML body.
        The handle_inline_image parameter is set to False, so the HTML body containing an inline image should be left as is.
        """
        import EWSO365
        # Setup
        to = ["recipient@example.com"]
        subject = "Test Subject"
        html_body = '<p><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA"/></p>'
        attachments = [{"name": "file.txt", "data": "data", "cid": "12345"}]

        mock_message.return_value = MagicMock()
        mock_html_body.return_value = MagicMock()
        mock_file_attachment.return_value = MagicMock(spec=FileAttachment)
        with patch.object(EWSO365.demisto, 'uniqueFile', return_value="1234567"), \
                patch.object(EWSO365.demisto, 'getFilePath', return_value={"path": "", "name": ""}), \
                patch.object(uuid, 'uuid4', return_value="111111111"):  # noqa: F821
            # Call the function
            result = create_message(
                to, False, subject, html_body=html_body, attachments=attachments
            )

            # Assertions
            mock_html_body.assert_called_once_with(html_body)
            mock_message.assert_called_once()
            assert isinstance(result[0], MagicMock)


@pytest.mark.parametrize("headers, expected_formatted_headers", [
    pytest.param([("Message-ID", '<valid_header>')], [("Message-ID", '<valid_header>')], id="valid header"),
    pytest.param([("Message-ID", '<[valid_header]>')], [("Message-ID", '<valid_header>')], id="invalid header"),
    pytest.param([("Message-ID", 'Other type of header format')], [("Message-ID", 'Other type of header format')],
                 id="untouched header format"),
])
def test_handle_attached_email_with_incorrect_id(mocker, headers, expected_formatted_headers):
    """
    Given:
        - case 1: valid Message-ID header value in attached email object
        - case 1: invalid Message-ID header value in attached email object
        - case 3: a Message-ID header value format which is not tested in the context of handle_attached_email_with_incorrect_id
    When:
        - fetching email which have an attached email with Message-ID header
    Then:
        - case 1: verify the header in the correct format
        - case 2: correct the invalid Message-ID header value
        - case 3: return the header value without further handling

    """
    mime_content = b'\xc400'
    email_policy = SMTP
    attached_email = email.message_from_bytes(mime_content, policy=email_policy)
    attached_email._headers = headers
    assert handle_attached_email_with_incorrect_message_id(attached_email)._headers == expected_formatted_headers


@pytest.mark.parametrize("message_id, expected_message_id_output", [
    pytest.param('<message_id>', '<message_id>', id="valid message_id 1"),
    pytest.param('<mess<[age_id>', '<mess<[age_id>', id="valid message_id 2"),
    pytest.param('<>]message_id>', '<>]message_id>', id="valid message_id 3"),
    pytest.param('<[message_id]>', '<message_id>', id="invalid message_id"),
    pytest.param('\r\n\t<message_id>', '\r\n\t<message_id>', id="valid message_id with escape chars"),
    pytest.param('\r\n\t<[message_id]>', '\r\n\t<message_id>', id="invalid message_id with escape chars"),
])
def test_handle_incorrect_message_id(message_id, expected_message_id_output):
    """
    Given:
        - case 1: valid Message-ID header value in attached email object
        - case 1: invalid Message-ID header value in attached email object
        - case 3: a Message-ID header value format which is not tested in the context of handle_attached_email_with_incorrect_id
    When:
        - fetching email which have an attached email with Message-ID header
    Then:
        - case 1: verify the header in the correct format
        - case 2: correct the invalid Message-ID header value
        - case 3: return the header value without further handling

    """
    assert handle_incorrect_message_id(message_id) == expected_message_id_output


@pytest.mark.parametrize("attachment_name, content_id, is_inline, expected_result", [
    pytest.param('image1.png', "", False, "image1.png"),
    pytest.param('image1.png', '123', True, "123-attachmentName-image1.png"),
    pytest.param('image1.png', None, False, "image1.png"),

])
def test_get_attachment_name(attachment_name, content_id, is_inline, expected_result):
    """
    Given:
        - case 1: attachment is not inline.
        - case 1: attachment is inline.
        - case 3: attachment is not inline.
    When:
        - get_attachment_name is called with LEGACY_NAME=FALSE
    Then:
        Only case 2 should add an ID to the attachment name.

    """
    assert get_attachment_name(attachment_name=attachment_name, content_id=content_id,
                               is_inline=is_inline) == expected_result


@pytest.mark.parametrize("attachment_name, content_id, is_inline, expected_result", [
    pytest.param('image1.png', "", False, "image1.png"),
    pytest.param('image1.png', '123', True, "image1.png"),
    pytest.param('image1.png', None, False, "image1.png"),

])
def test_get_attachment_name_legacy_name(monkeypatch, attachment_name, content_id, is_inline, expected_result):
    """
    Given:
        - case 1: attachment is not inline.
        - case 1: attachment is inline.
        - case 3: attachment is not inline.
    When:
        - get_attachment_name is called with LEGACY_NAME=FALSE
    Then:
        All cases should not add an ID to the attachment name.

    """
    monkeypatch.setattr('EWSO365.LEGACY_NAME', True)
    assert get_attachment_name(attachment_name=attachment_name, content_id=content_id,
                               is_inline=is_inline) == expected_result


def test_handle_attached_email_with_incorrect_from_header_fixes_malformed_header():
    """
    Given:
        An email message with a malformed From header.
    When:
        The handle_attached_email_with_incorrect_from_header function is called.
    Then:
        The From header is corrected and the email message object is updated.
    """
    message = email.message_from_bytes(b"From: =?UTF-8?Q?Task_One=0DTest?= <info@test.com>", policy=SMTP)

    result = handle_attached_email_with_incorrect_from_header(message)

    assert result['From'] == 'Task One Test <info@test.com>'
