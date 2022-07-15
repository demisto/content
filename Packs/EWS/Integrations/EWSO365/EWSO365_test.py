import base64
import json
import demistomock as demisto

import pytest
from exchangelib import EWSDate, EWSDateTime, EWSTimeZone
from exchangelib.attachments import AttachmentId, ItemAttachment
from exchangelib.items import Item, Message
from freezegun import freeze_time

from EWSO365 import (ExpandGroup, GetSearchableMailboxes, fetch_emails_as_incidents,
                     add_additional_headers, fetch_last_emails, find_folders,
                     get_expanded_group, get_searchable_mailboxes, handle_html,
                     handle_transient_files, parse_incident_from_item)

with open("test_data/commands_outputs.json", "r") as f:
    COMMAND_OUTPUTS = json.load(f)
with open("test_data/raw_responses.json", "r") as f:
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
            self.max_fetch = ""
            self.self_deployed = ""
            self.insecure = ""
            self.proxy = ""
            self.account = self.MockAccount()
            self.protocol = ""

        def get_account(self, target_mailbox=None, access_type=None):
            return self.account

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

    def test_ews_find_folders(self):
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
        actual_ec = res[1]
        assert expected == actual_ec

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
        actual_ec = res[1]
        assert expected == actual_ec


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
            return messages

    def mock_get_folder_by_path(path, account=None, is_public=False):
        return MockObject()

    client = TestNormalCommands.MockClient()
    client.max_fetch = 1
    client.get_folder_by_path = mock_get_folder_by_path
    client.folder_name = 'Inbox'
    last_run = mocker.patch.object(demisto, 'setLastRun')
    fetch_emails_as_incidents(client, current_last_run)
    assert last_run.call_args[0][0].get('lastRunTime') == expected_last_run.get('lastRunTime')
    assert set(last_run.call_args[0][0].get('ids')) == set(expected_last_run.get('ids'))


HEADERS_PACKAGE = [
    ('', {}),
    ('header=value', {'header': 'value'}),
    ('header1=value1, header2=value2', {'header1': 'value1', 'header2': 'value2'}),
    # Can not register the same header more then once.
    ('header3=value3, header3=other_value', {'header3': 'value3'})
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
     ('<html><body>some text <img src="cid:image0@abcd1234.abcd1234"></body></html>',
      [{'data': base64.b64decode('abcd'), 'name': 'image0', 'cid': 'image0@abcd1234.abcd1234'}]
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
    import EWSO365 as ewso365
    mocker.patch.object(ewso365, 'random_word_generator', return_value='abcd1234')
    assert handle_html(html_input) == expected_output


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
            return [Message(), Message(), Message(), Message(), Message()]

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
            return [Message(), Message(), Message(), Message(), Message()]

    def mock_get_folder_by_path(path, account=None, is_public=False):
        return MockObject()

    client = TestNormalCommands.MockClient()
    client.max_fetch = max_fetch
    client.get_folder_by_path = mock_get_folder_by_path

    emails = fetch_last_emails(client, since_datetime='')
    assert len(emails) == expected_result


def test_parse_incident_from_item():
    """
    Given:
        - Message item with attachment that contains non UTF-8 encoded char

    When:
        - Parsing incident from item

    Verify:
        - Parsing runs successfully
        - Incidnet attachment is not empty
    """
    message = Message(
        datetime_created=EWSDate(year=2021, month=1, day=25),
        to_recipients=[],
        attachments=[
            ItemAttachment(
                item=Item(mime_content=b'\xc400'),
                attachment_id=AttachmentId(),
                last_modified_time=EWSDate(year=2021, month=1, day=25),
            ),
        ],
    )
    incident = parse_incident_from_item(message)
    assert incident['attachment']


def test_parse_incident_from_item_with_attachments():
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
        datetime_created=EWSDate(year=2021, month=1, day=25),
        to_recipients=[],
        attachments=[
            ItemAttachment(
                item=Item(mime_content=content, headers=[]),
                attachment_id=AttachmentId(),
                last_modified_time=EWSDate(year=2021, month=1, day=25),
            ),
        ],
    )
    incident = parse_incident_from_item(message)
    assert incident['attachment']


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
