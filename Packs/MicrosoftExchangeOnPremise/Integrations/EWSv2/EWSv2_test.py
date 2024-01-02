import datetime

import EWSv2
import logging

import dateparser
import pytest
from exchangelib import Message
from EWSv2 import fetch_last_emails
from exchangelib.errors import UnauthorizedError
from exchangelib import EWSDateTime, EWSTimeZone
from exchangelib.errors import ErrorInvalidIdMalformed, ErrorItemNotFound
import demistomock as demisto


class TestNormalCommands:
    """

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
            self.inbox = self.MockInbox()

        class MockInbox:
            class parent:
                def __init__(self):
                    self.children = ""

            def __init__(self):
                self.parent = self.parent()

        def get_folder_by_path(self, path, account=None, is_public=False):
            return ""


def test_keys_to_camel_case():
    assert EWSv2.keys_to_camel_case('this_is_a_test') == 'thisIsATest'
    # assert keys_to_camel_case(('this_is_a_test', 'another_one')) == ('thisIsATest', 'anotherOne')
    obj = {}
    obj['this_is_a_value'] = 'the_value'
    obj['this_is_a_list'] = []
    obj['this_is_a_list'].append('list_value')
    res = EWSv2.keys_to_camel_case(obj)
    assert res['thisIsAValue'] == 'the_value'
    assert res['thisIsAList'][0] == 'listValue'


def test_start_logging():
    EWSv2.start_logging()
    logging.getLogger().debug("test this")
    assert "test this" in EWSv2.log_stream.getvalue()


@pytest.mark.parametrize('since_datetime, expected_result',
                         [('', EWSDateTime.from_string('2021-05-23 13:18:14.901293+00:00'))])
def test_fetch_last_emails_first_fetch(mocker, since_datetime, expected_result):
    """
    Given:
        - First fetch timestamp - no last_run
    When:
        - Fetching last emails

    Then:
        - Verify datetime_received__gte is ten minutes earlier
    """
    class MockObject:
        def filter(self, datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            return [Message(), Message(), Message(), Message(), Message()]

    client = TestNormalCommands.MockClient()
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2021, 5, 23, 13, 18, 14, 901293,
                                                                            datetime.timezone.utc))
    mocker.patch.object(EWSv2, 'get_folder_by_path', return_value=MockObject())

    mocker.patch.object(MockObject, 'filter')

    fetch_last_emails(client, since_datetime=since_datetime)
    assert MockObject.filter.call_args[1].get('datetime_received__gte') == expected_result


@pytest.mark.parametrize('since_datetime, expected_result',
                         [('2021-05-23 21:18:14.901293+00:00',
                           '2021-05-23 21:18:14.901293+00:00')])
def test_fetch_last_emails_last_run(mocker, since_datetime, expected_result):
    """
    Given:
        - Not the first time fetching - last_run with a date
    When:
        - Fetching last emails

    Then:
        - Verify datetime_received__gte according to the datetime received
    """
    class MockObject:
        def filter(self, datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            return [Message(), Message(), Message(), Message(), Message()]

    mocker.patch.object(EWSv2, 'get_folder_by_path', return_value=MockObject())
    mocker.patch.object(MockObject, 'filter')

    client = TestNormalCommands.MockClient()

    fetch_last_emails(client, since_datetime=since_datetime)
    assert MockObject.filter.call_args[1].get('datetime_received__gte') == expected_result


@pytest.mark.parametrize('limit, expected_result',
                         [(6, 5),
                          (2, 2),
                          (5, 5)])
def test_fetch_last_emails_limit(mocker, limit, expected_result):
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
        def filter(self, datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            return [Message(), Message(), Message(), Message(), Message()]

    mocker.patch.object(EWSv2, 'get_folder_by_path', return_value=MockObject())
    EWSv2.MAX_FETCH = limit
    client = TestNormalCommands.MockClient()

    x = fetch_last_emails(client, since_datetime='since_datetime')
    assert len(x) == expected_result


def test_fetch_last_emails_fail(mocker):
    """
    This UT is added due to the following issue: XSUP-28730
    where an ErrorMimeContentConversionFailed exception is raised if there was a corrupt object in the stream of
    results returned from the fetch process (exchangelib module behavior).
    If such exception is encountered, it would be handled internally so that the integration would not crash.

    Given:
        - First exception raised is ErrorMimeContentConversionFailed
        - Second exception raised is ValueError

    When:
        - Iterating over mail objects when fetching last emails

    Then:
        - Catch ErrorMimeContentConversionFailed, print relevant debug message
          for encountered corrupt object and continue iteration to next object
        - Catch ValueError, and raise it forward
    """
    from EWSv2 import ErrorMimeContentConversionFailed

    class MockObject:
        def filter(self, datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            return [Message(), Message(), Message(), Message(), Message()]

    mocker.patch.object(EWSv2, 'get_folder_by_path', return_value=MockObject())
    EWSv2.MAX_FETCH = 1
    client = TestNormalCommands.MockClient()

    mocker.patch('EWSv2.isinstance', side_effect=[ErrorMimeContentConversionFailed(AttributeError()), ValueError()])

    with pytest.raises(ValueError) as e:
        fetch_last_emails(client, since_datetime='since_datetime')
        assert str(e) == 'Got an error when pulling incidents. You might be using the wrong exchange version.'


def test_fetch_last_emails_object_stream_behavior(mocker):
    """
    This UT is added due to the following issue: XSUP-28730
    where an ErrorMimeContentConversionFailed exception is raised if there was a corrupt object in the stream of
    results returned from the fetch process (exchangelib module behavior).
    If such exception is encountered, it would be handled internally so that the integration would not crash

    Given:
        - A stream of 3 fetched objects, where objects in indexes 0,2 are valid message objects
          and the object in index 1 is an exception object (corrupt object)

    When:
        - Iterating over mail objects when fetching last emails

    Then:
        - Iterate over the fetched objects
        - Catch the corrupt object object, print relevant debug message
          and continue iteration to next object
        - Assert only valid objects are in the result
    """
    from EWSv2 import ErrorMimeContentConversionFailed

    class MockObject:
        def filter(self, datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            return [Message(), Message(), Message()]

    mocker.patch.object(EWSv2, 'get_folder_by_path', return_value=MockObject())
    EWSv2.MAX_FETCH = 3
    client = TestNormalCommands.MockClient()

    mocker.patch('EWSv2.isinstance', side_effect=[True, ErrorMimeContentConversionFailed(AttributeError()), True])

    x = fetch_last_emails(client, since_datetime='since_datetime')
    assert len(x) == 2


def test_dateparser():
    """Test that dateparser works fine. See: https://github.com/demisto/etc/issues/39240 """
    now = datetime.datetime.now()
    res = dateparser.parse(EWSv2.FETCH_TIME)
    assert res is not None
    assert res < now


MESSAGES = [
    Message(subject='message1',
            message_id='message1',
            text_body='Hello World',
            body='message1',
            datetime_received=EWSDateTime(2021, 7, 14, 13, 00, 00, tzinfo=EWSTimeZone('UTC')),
            datetime_sent=EWSDateTime(2021, 7, 14, 13, 00, 00, tzinfo=EWSTimeZone('UTC')),
            datetime_created=EWSDateTime(2021, 7, 14, 13, 00, 00, tzinfo=EWSTimeZone('UTC'))
            ),
    Message(subject='message2',
            message_id='message2',
            text_body='Hello World',
            body='message2',
            datetime_received=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC')),
            datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC')),
            datetime_created=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC'))
            ),
    Message(subject='message3',
            message_id='message3',
            text_body='Hello World',
            body='message3',
            datetime_received=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC')),
            datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC')),
            datetime_created=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC'))
            ),
    Message(subject='message4',
            message_id='message4',
            text_body='Hello World',
            body='message4',
            datetime_received=EWSDateTime(2021, 7, 14, 13, 10, 00, tzinfo=EWSTimeZone('UTC')),
            datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC')),
            datetime_created=EWSDateTime(2021, 7, 14, 13, 11, 00, tzinfo=EWSTimeZone('UTC'))
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
    {'lastRunTime': '2021-07-14T13:05:17Z', 'folderName': 'Inbox', 'ids': ['message1']}, MESSAGES[0:3],
    {'lastRunTime': '2021-07-14T13:09:00Z', 'folderName': 'Inbox', 'ids': ['message2'], 'errorCounter': 0})
CASE_SECOND_RUN_FOUND_MORE_THAN_ONE_NEXT_RUN = (
    {'lastRunTime': '2021-07-14T13:09:00Z', 'folderName': 'Inbox', 'ids': ['message2']}, MESSAGES[1:3],
    {'lastRunTime': '2021-07-14T13:09:00Z', 'folderName': 'Inbox', 'ids': ['message2', 'message3'], 'errorCounter': 0})
CASE_SECOND_RUN_NO_INCIDENTS = (
    {'lastRunTime': '2021-07-14T12:59:17Z', 'folderName': 'Inbox', 'ids': ['message1']}, [],
    {'lastRunTime': '2021-07-14T12:59:17Z', 'folderName': 'Inbox', 'ids': ['message1'], 'errorCounter': 0})
CASE_SECOND_RUN_DIFFERENT_CREATED_RECEIVED_TIME = (
    {'lastRunTime': '2021-07-14T13:09:00Z', 'folderName': 'Inbox', 'ids': []}, MESSAGES[3:],
    {'lastRunTime': '2021-07-14T13:10:00Z', 'folderName': 'Inbox', 'ids': ['message4'], 'errorCounter': 0})
CASES = [
    CASE_FIRST_RUN_NO_INCIDENT,
    CASE_FIRST_RUN_FOUND_INCIDENT,
    CASE_SECOND_RUN_FOUND_ONE_INCIDENT,
    CASE_SECOND_RUN_FOUND_MORE_THAN_ONE_FIRST_RUN,
    CASE_SECOND_RUN_FOUND_MORE_THAN_ONE_NEXT_RUN,
    CASE_SECOND_RUN_NO_INCIDENTS,
    CASE_SECOND_RUN_DIFFERENT_CREATED_RECEIVED_TIME,
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
    from EWSv2 import fetch_emails_as_incidents
    import demistomock as demisto

    class MockObject:
        def filter(self, datetime_received__gte=''):
            return MockObject2()

    class MockObject2:
        def filter(self):
            return MockObject2()

        def only(self, *args):
            return self

        def order_by(self, *args):
            return messages

    client = TestNormalCommands.MockClient()
    mocker.patch.object(EWSv2, 'get_folder_by_path', return_value=MockObject())
    mocker.patch.object(EWSv2, 'get_account', return_value='test_account')
    EWSv2.MAX_FETCH = 1
    last_run = mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'getLastRun', return_value=current_last_run)
    fetch_emails_as_incidents(client, 'Inbox')
    assert last_run.call_args[0][0].get('lastRunTime') == expected_last_run.get('lastRunTime')
    assert set(last_run.call_args[0][0].get('ids')) == set(expected_last_run.get('ids'))


class MockItem:
    def __init__(self, item_id):
        self.id = item_id


class MockAccount:
    def __init__(self, primary_smtp_address="", error=401):
        self.primary_smtp_address = primary_smtp_address
        self.error = error

    @property
    def root(self):
        if self.error == 401:
            raise UnauthorizedError('Wrong username or password')
        if self.error == 404:
            raise Exception('Page not found')

    def fetch(self, ids):
        if isinstance(ids, type(map)):
            ids = list(ids)

        result = []

        for item in ids:
            item_id = item.id
            if item_id == '3':
                result.append(ErrorInvalidIdMalformed(value="malformed ID 3"))
            elif item_id == '4':
                result.append(ErrorItemNotFound(value="ID 4 was not found"))
            else:
                result.append(item_id)
        return result


def test_send_mail(mocker):
    """
    Given -
        to, subject and replyTo arguments to send an email.

    When -
        trying to send an email

    Then -
        verify the context output is returned correctly and that the 'to' and 'replyTo' arguments were sent
        as a list of strings.
    """
    from EWSv2 import send_email
    mocker.patch.object(EWSv2, 'Account', return_value=MockAccount(primary_smtp_address="test@gmail.com"))
    send_email_mocker = mocker.patch.object(EWSv2, 'send_email_to_mailbox')
    results = send_email({'to': "test@gmail.com", 'subject': "test", 'replyTo': "test1@gmail.com"})
    assert send_email_mocker.call_args.kwargs.get('to') == ['test@gmail.com']
    assert send_email_mocker.call_args.kwargs.get('reply_to') == ['test1@gmail.com']
    assert results[0].get('Contents') == {
        'from': 'test@gmail.com', 'to': ['test@gmail.com'], 'subject': 'test', 'attachments': []
    }


def test_send_mail_with_from_arg(mocker):
    """
    Given -
        to, subject and replyTo arguments to send an email.

    When -
        trying to send an email

    Then -
        verify the context output is returned correctly and that the 'to' and 'replyTo' arguments were sent
        as a list of strings.
    """
    from EWSv2 import send_email
    mocker.patch.object(EWSv2, 'Account', return_value=MockAccount(primary_smtp_address="test@gmail.com"))
    send_email_mocker = mocker.patch.object(EWSv2, 'send_email_to_mailbox')
    results = send_email({'to': "test@gmail.com", 'subject': "test", 'replyTo': "test1@gmail.com", "from": "somemail@what.ever"})
    assert send_email_mocker.call_args.kwargs.get('to') == ['test@gmail.com']
    assert send_email_mocker.call_args.kwargs.get('reply_to') == ['test1@gmail.com']
    assert results[0].get('Contents') == {
        'from': 'somemail@what.ever', 'to': ['test@gmail.com'], 'subject': 'test', 'attachments': []
    }


def test_send_mail_with_trailing_comma(mocker):
    """
    Given -
        a 'subject' which is 'test' and 'to' which is 'test@gmail.com,' (ending with a comma),

    When -
        trying to send an email

    Then -
        verify that the 'to' field was extracted correctly and that the trailing comma was handled.
    """
    from EWSv2 import send_email
    mocker.patch.object(EWSv2, 'Account', return_value=MockAccount(primary_smtp_address="test@gmail.com"))
    send_email_mocker = mocker.patch.object(EWSv2, 'send_email_to_mailbox')
    results = send_email({'to': "test@gmail.com,", 'subject': "test"})
    assert send_email_mocker.call_args.kwargs.get('to') == ['test@gmail.com']
    assert results[0].get('Contents') == {
        'from': 'test@gmail.com', 'to': ['test@gmail.com'], 'subject': 'test', 'attachments': []
    }


@pytest.mark.parametrize(
    'item_ids, should_throw_exception', [
        (
            ['1'],
            False
        ),
        (
            ['1', '2'],
            False
        ),
        (
            ['1', '2', '3'],
            True
        ),
        (
            ['1', '2', '3', '4'],
            True
        ),
    ]
)
def test_get_items_from_mailbox(mocker, item_ids, should_throw_exception):
    """
    Given -
        Case A: single ID which is valid
        Case B: two IDs which are valid
        Case C: two ids which are valid and one id == 3 which cannot be found
        Case D: two ids which are valid and one id == 3 which cannot be found and one id == 4 which is malformed

    When -
        executing get_items_from_mailbox function

    Then -
        Case A: make sure the ID is returned successfully
        Case B: make sure that IDs are returned successfully
        Case C: make sure an exception is raised
        Case D: make sure an exception is raised
    """
    from EWSv2 import get_items_from_mailbox

    mocker.patch('EWSv2.Item', side_effect=[MockItem(item_id=item_id) for item_id in item_ids])

    if should_throw_exception:
        with pytest.raises(Exception):
            get_items_from_mailbox(MockAccount(), item_ids=item_ids)
    else:
        assert get_items_from_mailbox(MockAccount(), item_ids=item_ids) == item_ids


def test_categories_parse_item_as_dict():
    """
    Given -
        a Message with categories.

    When -
        running the parse_item_as_dict function.

    Then -
        verify that the categories were parsed correctly.
    """
    from EWSv2 import parse_item_as_dict

    message = Message(subject='message4',
                      message_id='message4',
                      text_body='Hello World',
                      body='message4',
                      datetime_received=EWSDateTime(2021, 7, 14, 13, 10, 00, tzinfo=EWSTimeZone('UTC')),
                      datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC')),
                      datetime_created=EWSDateTime(2021, 7, 14, 13, 11, 00, tzinfo=EWSTimeZone('UTC')),
                      categories=['Purple category', 'Orange category']
                      )

    return_value = parse_item_as_dict(message, False)
    assert return_value.get("categories") == ['Purple category', 'Orange category']


def test_list_parse_item_as_dict():
    """
    Given -
        a Message where effective rights is a list.

    When -
        running the parse_item_as_dict function.

    Then -
        verify that the object is parsed correctly.
    """
    from EWSv2 import parse_item_as_dict
    from exchangelib.properties import EffectiveRights

    message = Message(subject='message4',
                      message_id='message4',
                      text_body='Hello World',
                      body='message4',
                      datetime_received=EWSDateTime(2021, 7, 14, 13, 10, 00, tzinfo=EWSTimeZone('UTC')),
                      datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC')),
                      datetime_created=EWSDateTime(2021, 7, 14, 13, 11, 00, tzinfo=EWSTimeZone('UTC')),
                      effective_rights=[EffectiveRights(), EffectiveRights()]
                      )

    return_value = parse_item_as_dict(message, False)
    effetive_right_res = return_value.get("effective_rights")
    assert type(effetive_right_res) is list
    assert len(effetive_right_res) == 2


def test_parse_item_as_dict_with_empty_field():
    """
    Given -
        a Message where effective rights is None and other fields are false\empty strings.

    When -
        running the parse_item_as_dict function.

    Then -
        effective rights field was removed from response other empty\negative fields aren't.
    """
    from EWSv2 import parse_item_as_dict

    message = Message(subject='message4',
                      message_id='message4',
                      text_body='Hello World',
                      body='',
                      datetime_received=EWSDateTime(2021, 7, 14, 13, 10, 00, tzinfo=EWSTimeZone('UTC')),
                      datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC')),
                      datetime_created=EWSDateTime(2021, 7, 14, 13, 11, 00, tzinfo=EWSTimeZone('UTC')),
                      effective_rights=None,
                      is_read=False
                      )

    return_value = parse_item_as_dict(message, False)
    assert 'effective_rights' not in return_value
    assert return_value['body'] == ''
    assert return_value['is_read'] is False


def test_get_entry_for_object_empty():
    from EWSv2 import get_entry_for_object
    obj = {}
    assert get_entry_for_object("test", "keyTest", obj) == "There is no output results"


def test_get_entry_for_object():
    from EWSv2 import get_entry_for_object
    obj = {"a": 1, "b": 2}
    assert get_entry_for_object("test", "keyTest", obj)['HumanReadable'] == '### test\n|a|b|\n|---|---|\n| 1 | 2 |\n'


def test_get_time_zone(mocker):
    """
    When -
        trying to send/reply an email we check the XOSAR user time zone

    Then -
        verify that info returns
    """
    from EWSv2 import get_time_zone
    mocker.patch.object(demisto, 'callingContext', new={'context': {'User': {'timeZone': 'Asia/Jerusalem'}}})
    results = get_time_zone()
    assert results.key == 'Asia/Jerusalem'


def test_get_item_as_eml(mocker):
    """
    Given:
        - A quoted-printable encoded email returns.
    When:
        - The "ews-get-items-as-eml" command is called.
    Then:
        - The output contains the expected file name and content
    """
    from EWSv2 import get_item_as_eml
    from exchangelib import ItemId, Mailbox
    from exchangelib.items import Message, ReplyToItem, ForwardItem, ReplyAllToItem
    from exchangelib.properties import ParentFolderId, ResponseObjects, EffectiveRights, ConversationId, MessageHeader

    mocker.patch('EWSv2.get_account', return_value='account')
    mime_content = b'Received: from A by\r\n B\r\n (version=A, cipher=B) id\r\n  Fri, 24 Nov 2023\r\nReceived: from C\r\n D\r\n' \
                   b' (version=A, cipher=B) id\r\n Fri, 24 Nov 2023\r\nReceived: from E\r\n F\r\n Fri, 24 Nov 2023\r\nFrom: ' \
                   b'"Test User" <foo@test.com>\r\nTo: "Test User" <foo@test.com>\r\nSubject: Test pobierania ' \
                   b'emla\r\nThread-Topic: Test pobierania emla\r\nThread-Index: aa\r\nDate: Fri, 24 Nov 2023 11:38:02 ' \
                   b'+0000\r\nMessage-ID: <34>\r\nAccept-Language: pl-PL, en-US\r\nContent-Language: ' \
                   b'pl-PL\r\nX-MS-Exchange-Organization-AuthAs: Internal\r\nX-MS-Exchange-Organization-AuthMechanism: ' \
                   b'04\r\nX-MS-Exchange-Organization-AuthSource: ' \
                   b'pl\r\nX-MS-Has-Attach:\r\nX-MS-Exchange-Organization-Network-Message-Id:\r\n\tbb\r\nX-MS-Exchange' \
                   b'-Organization-SCL: -1\r\nX-MS-TNEF-Correlator:\r\nX-MS-Exchange-Organization-RecordReviewCfmType: ' \
                   b'0\r\nx-greenmod-classification: PropertyRoot=m;CATEGORY=NEW\r\nx-greenmod-classificationdate: ' \
                   b'2023-11-24T12:36:56.8950031+01:00\r\nx-greenmod-classifiedby:\r\n\taabb\r\nx-greenmod-grnitemid: ' \
                   b'ccdd\r\nx-greenmod-classifiedbysid:\r\n\teeff\r\nx-greenmod-flags:\r\ndlp-product: ' \
                   b'dlpe-windows\r\ndlp-version: 1.2.3\r\ndlp-reaction: no-action\r\nContent-Type: ' \
                   b'multipart/alternative;\r\n\tboundary="_012_"\r\nMIME-Version: 1.0\r\n\r\n--_012_\r\nContent-Type: ' \
                   b'text/plain; charset="iso-8859-2"\r\nContent-Transfer-Encoding: ' \
                   b'quoted-printable\r\n\r\nNEWn=EAtrzne\r\n=A1=B3=BF=F3=E6\r\n\r\nLorem ipsum dolor sit amet, consectetur ' \
                   b'adipiscing elit, sed do eiusmod tem=\r\npor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ' \
                   b'veniam, q=\r\nuis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo cons=\r\nequat. Duis ' \
                   b'aute irure dolor in reprehenderit in voluptate velit esse cillu=\r\nm dolore eu fugiat nulla pariatur. ' \
                   b'Excepteur sint occaecat cupidatat non pr=\r\noident, sunt in culpa qui officia deserunt mollit anim id est' \
                   b' laborum.\r\n\r\n--_012_\r\nContent-Type: text/html; charset="iso-8859-2"\r\nContent-Transfer-Encoding: ' \
                   b'quoted-printable\r\n\r\n<html>\r\n<head>\r\n<meta http-equiv=3D"Content-Type" content=3D"text/html; ' \
                   b'charset=3Diso-8859-=\r\n2">\r\n<meta name=3D"Generator" content=3D"Microsoft Word 15 (filtered ' \
                   b'medium)">\r\n<style><!--\r\n/* Font Definitions */\r\n@font-face\r\n\t{font-family:"Cambria ' \
                   b'Math";\r\n\tpanose-1:2 4 5 3 5 4 6 3 2 4;}\r\n@font-face\r\n\t{font-family:Calibri;\r\n\tpanose-1:2 15 5 2' \
                   b' 2 2 4 3 2 4;}\r\n/* Style Definitions */\r\np.MsoNormal, li.MsoNormal, div.MsoNormal\r\n\t{' \
                   b'margin:0cm;\r\n\tmargin-bottom:.0001pt;\r\n\tfont-size:11.0pt;\r\n\tfont-family:"Calibri",' \
                   b'sans-serif;\r\n\tmso-fareast-language:EN-US;}\r\na:link, span.MsoHyperlink\r\n\t{' \
                   b'mso-style-priority:99;\r\n\tcolor:#0563C1;\r\n\ttext-decoration:underline;}\r\na:visited, ' \
                   b'span.MsoHyperlinkFollowed\r\n\t{' \
                   b'mso-style-priority:99;\r\n\tcolor:#954F72;\r\n\ttext-decoration:underline;}\r\nspan.Stylwiadomocie-mail17' \
                   b'\r\n\t{mso-style-type:personal-compose;\r\n\tfont-family:"Calibri",' \
                   b'sans-serif;\r\n\tcolor:windowtext;}\r\n.MsoChpDefault\r\n\t{' \
                   b'mso-style-type:export-only;\r\n\tmso-fareast-language:EN-US;}\r\n@page WordSection1\r\n\t{size:612.0pt ' \
                   b'792.0pt;\r\n\tmargin:70.85pt 70.85pt 70.85pt 70.85pt;}\r\ndiv.WordSection1\r\n\t{' \
                   b'page:WordSection1;}\r\n--></style><!--[if gte mso 9]><xml>\r\n<o:shapedefaults v:ext=3D"edit" ' \
                   b'spidmax=3D"1026" />\r\n</xml><![endif]--><!--[if gte mso 9]><xml>\r\n<o:shapelayout ' \
                   b'v:ext=3D"edit">\r\n<o:idmap v:ext=3D"edit" data=3D"1" />\r\n</o:shapelayout></xml><![' \
                   b'endif]-->\r\n</head>\r\n<body lang=3D"PL" link=3D"#0563C1" vlink=3D"#954F72">\r\n<div ' \
                   b'id=3D"BodyTopText">\r\n<p style=3D"font-family:PKO Bank ' \
                   b'Polski;font-size:15px;color:#0098d4">NEWn=\r\n=EAtrzne</p>\r\n</div>\r\n<div class=3D"WordSection1">\r\n<p' \
                   b' class=3D"MsoNormal">=A1=B3=BF=F3=E6<o:p></o:p></p>\r\n<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>\r\n<p ' \
                   b'class=3D"MsoNormal">Lorem ipsum dolor sit amet, consectetur adipiscing e=\r\nlit, sed do eiusmod tempor ' \
                   b'incididunt ut labore et dolore magna aliqua. Ut =\r\nenim ad minim veniam, quis nostrud exercitation ' \
                   b'ullamco laboris nisi ut ali=\r\nquip ex ea commodo consequat. Duis\r\n aute irure dolor in reprehenderit ' \
                   b'in voluptate velit esse cillum dolore eu=\r\n fugiat nulla pariatur. Excepteur sint occaecat cupidatat non' \
                   b' proident, sun=\r\nt in culpa qui officia deserunt mollit anim id est ' \
                   b'laborum.<o:p></o:p></p>\r\n</div>\r\n</body>\r\n</html>\r\n\r\n--_012_--\r\n '
    text_body = 'NEWnÄ™trzne\r\nÄ„Å‚Å¼Ã³Ä‡\r\n\r\nLorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod ' \
                'tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco' \
                ' laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit ' \
                'esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui' \
                ' officia deserunt mollit anim id est laborum.\r\n '
    body = '<html>\r\n<head>\r\n<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\r\n<meta name="Generator" ' \
           'content="Microsoft Word 15 (filtered medium)">\r\n<style><!--\r\n/* Font Definitions */\r\n@font-face\r\n\t{' \
           'font-family:"Cambria Math";\r\n\tpanose-1:2 4 5 3 5 4 6 3 2 4;}\r\n@font-face\r\n\t{' \
           'font-family:Calibri;\r\n\tpanose-1:2 15 5 2 2 2 4 3 2 4;}\r\n/* Style Definitions */\r\np.MsoNormal, li.MsoNormal, ' \
           'div.MsoNormal\r\n\t{margin:0cm;\r\n\tmargin-bottom:.0001pt;\r\n\tfont-size:11.0pt;\r\n\tfont-family:"Calibri",' \
           'sans-serif;\r\n\tmso-fareast-language:EN-US;}\r\na:link, span.MsoHyperlink\r\n\t{' \
           'mso-style-priority:99;\r\n\tcolor:#0563C1;\r\n\ttext-decoration:underline;}\r\na:visited, ' \
           'span.MsoHyperlinkFollowed\r\n\t{mso-style-priority:99;\r\n\tcolor:#954F72;\r\n\ttext-decoration:underline;}\r\nspan' \
           '.Stylwiadomocie-mail17\r\n\t{mso-style-type:personal-compose;\r\n\tfont-family:"Calibri",' \
           'sans-serif;\r\n\tcolor:windowtext;}\r\n.MsoChpDefault\r\n\t{' \
           'mso-style-type:export-only;\r\n\tmso-fareast-language:EN-US;}\r\n@page WordSection1\r\n\t{size:612.0pt ' \
           '792.0pt;\r\n\tmargin:70.85pt 70.85pt 70.85pt 70.85pt;}\r\ndiv.WordSection1\r\n\t{' \
           'page:WordSection1;}\r\n--></style><!--[if gte mso 9]><xml>\r\n<o:shapedefaults v:ext="edit" spidmax="1026" ' \
           '/>\r\n</xml><![endif]--><!--[if gte mso 9]><xml>\r\n<o:shapelayout v:ext="edit">\r\n<o:idmap v:ext="edit" data="1" ' \
           '/>\r\n</o:shapelayout></xml><![endif]-->\r\n</head>\r\n<body lang="PL" link="#0563C1" vlink="#954F72">\r\n<div ' \
           'id="BodyTopText">\r\n<p style="font-family:PKO Bank ' \
           'Polski;font-size:15px;color:#0098d4">NEWnÄ™trzne</p>\r\n</div>\r\n<div class="WordSection1">\r\n<p ' \
           'class="MsoNormal">Ä„Å‚Å¼Ã³Ä‡<o:p></o:p></p>\r\n<p class="MsoNormal"><o:p>&nbsp;</o:p></p>\r\n<p ' \
           'class="MsoNormal">Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut ' \
           'labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ' \
           'ex ea commodo consequat. Duis\r\n aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat' \
           ' nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id ' \
           'est laborum.<o:p></o:p></p>\r\n</div>\r\n</body>\r\n</html>\r\n '
    unique_body = '<html><body><div>\r\n<div><span lang="pl">\r\n<div id="BodyTopText">\r\n<div ' \
                  'style="margin-top:14pt;margin-bottom:14pt;"><font face="PKO Bank Polski" size="2" color="#0098D4"><span ' \
                  'style="font-size:15px;">NEWnÄ™trzne</span></font></div>\r\n</div>\r\n<div>\r\n<div style="margin:0;"><font ' \
                  'face="Calibri,sans-serif" size="2"><span style="font-size:11pt;">Ä„Å‚Å¼Ã³Ä‡</span></font></div>\r\n<div ' \
                  'style="margin:0;"><font face="Calibri,sans-serif" size="2"><span ' \
                  'style="font-size:11pt;">&nbsp;</span></font></div>\r\n<div style="margin:0;"><font face="Calibri,' \
                  'sans-serif" size="2"><span style="font-size:11pt;">Lorem ipsum dolor sit amet, consectetur adipiscing elit, ' \
                  'sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud ' \
                  'exercitation\r\nullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in ' \
                  'reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat ' \
                  'cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id\r\nest ' \
                  'laborum.</span></font></div>\r\n</div>\r\n</span></div>\r\n</div>\r\n</body></html> '
    item = Message(
        mime_content=mime_content, _id=ItemId(id='abc', changekey='cde'),
        parent_folder_id=ParentFolderId(id='efg', changekey='AQAAAA=='), item_class='IPM.Note', subject='Test pobierania emla',
        sensitivity='Normal', text_body=text_body, body=body, attachments=[],
        datetime_received=EWSDateTime(2023, 11, 24, 11, 38, 3, tzinfo=EWSTimeZone(key='UTC')), size=13318, categories=None,
        importance='Normal', in_reply_to=None, is_submitted=False, is_draft=False, is_from_me=True, is_resend=False,
        is_unmodified=True,
        headers=[MessageHeader(name='Received', value='from A by B (version=A, cipher=B) id  Fri, 24 Nov 2023'),
                 MessageHeader(name='Received', value='from C D (version=A, cipher=B) id Fri, 24 Nov 2023'),
                 MessageHeader(name='Received', value='from E F Fri, 24 Nov 2023'),
                 MessageHeader(name='Content-Type', value='application/ms-tnef'),
                 MessageHeader(name='Content-Transfer-Encoding', value='binary'),
                 MessageHeader(name='Subject', value='Test pobierania emla'),
                 MessageHeader(name='Thread-Topic', value='Test pobierania emla'),
                 MessageHeader(name='Thread-Index', value='aa'),
                 MessageHeader(name='Date', value='Fri, 24 Nov 2023 12:38:02 +0100'),
                 MessageHeader(name='Message-ID', value='<34>'),
                 MessageHeader(name='Accept-Language', value='pl-PL, en-US'),
                 MessageHeader(name='Content-Language', value='pl-PL'),
                 MessageHeader(name='X-MS-Exchange-Organization-SCL', value='-1'),
                 MessageHeader(name='X-MS-TNEF-Correlator', value='<34>'),
                 MessageHeader(name='x-greenmod-classification', value='PropertyRoot=m;CATEGORY=NEW'),
                 MessageHeader(name='x-greenmod-classificationdate', value='2023-11-24T12:36:56.8950031+01:00'),
                 MessageHeader(name='x-greenmod-classifiedby', value='aabb'),
                 MessageHeader(name='x-greenmod-grnitemid', value='ccdd'),
                 MessageHeader(name='x-greenmod-classifiedbysid', value='eeff'),
                 MessageHeader(name='dlp-product', value='dlpe-windows'),
                 MessageHeader(name='dlp-version', value='1.2.3'),
                 MessageHeader(name='dlp-reaction', value='no-action'),
                 MessageHeader(name='MIME-Version', value='1.0'),
                 MessageHeader(name='X-MS-Exchange-Organization-MessageDirectionality', value='Originating'),
                 MessageHeader(name='X-MS-Exchange-Organization-AuthSource', value='pl'),
                 MessageHeader(name='X-MS-Exchange-Organization-AuthAs', value='Internal'),
                 MessageHeader(name='X-MS-Exchange-Organization-AuthMechanism', value='04'),
                 MessageHeader(name='X-Originating-IP', value='[1.2.3.4]'),
                 MessageHeader(name='X-MS-Exchange-Organization-Network-Message-Id', value='bb'),
                 MessageHeader(name='Return-Path', value='foo@test.com'),
                 MessageHeader(name='X-MS-Exchange-Organization-AVStamp-Mailbox', value='SYMANTEC;1;0;info'),
                 MessageHeader(name='X-MS-Exchange-Transport-EndToEndLatency', value='00:00:00.5164136'),
                 MessageHeader(name='X-MS-Exchange-Processed-By-BccFoldering', value='1.2.3.4')],
        datetime_sent=EWSDateTime(2023, 11, 24, 11, 38, 2, tzinfo=EWSTimeZone(key='UTC')),
        datetime_created=EWSDateTime(2023, 11, 24, 11, 38, 3, tzinfo=EWSTimeZone(key='UTC')),
        response_objects=ResponseObjects(accept_item=None, tentatively_accept_item=None, decline_item=None,
                                         reply_to_item=ReplyToItem(subject=None, body=None, to_recipients=None,
                                                                   cc_recipients=None, bcc_recipients=None,
                                                                   is_read_receipt_requested=None,
                                                                   is_delivery_receipt_requested=None, author=None,
                                                                   reference_item_id=None, new_body=None, received_by=None,
                                                                   received_representing=None),
                                         forward_item=ForwardItem(subject=None, body=None, to_recipients=None, cc_recipients=None,
                                                                  bcc_recipients=None, is_read_receipt_requested=None,
                                                                  is_delivery_receipt_requested=None, author=None,
                                                                  reference_item_id=None, new_body=None, received_by=None,
                                                                  received_representing=None),
                                         reply_all_to_item=ReplyAllToItem(subject=None, body=None, to_recipients=None,
                                                                          cc_recipients=None, bcc_recipients=None,
                                                                          is_read_receipt_requested=None,
                                                                          is_delivery_receipt_requested=None, author=None,
                                                                          reference_item_id=None, new_body=None, received_by=None,
                                                                          received_representing=None), cancel_calendar_item=None,
                                         remove_item=None, post_reply_item=None, success_read_receipt=None,
                                         accept_sharing_invitation=None), reminder_due_by=None, reminder_is_set=False,
        reminder_minutes_before_start=0, display_cc=None, display_to='Test User', has_attachments=False,
        culture='pl-PL',
        effective_rights=EffectiveRights(create_associated=False, create_contents=False, create_hierarchy=False, delete=True,
                                         modify=True, read=True, view_private_items=True),
        last_modified_name='Test User',
        last_modified_time=EWSDateTime(2023, 11, 24, 11, 38, 3, tzinfo=EWSTimeZone(key='UTC')), is_associated=False,
        web_client_read_form_query_string='https://test.com',
        web_client_edit_form_query_string=None,
        conversation_id=ConversationId(id='aabc',
                                       changekey=None),
        unique_body=unique_body,
        sender=Mailbox(name='Test User', email_address='foo@test.com', routing_type='SMTP',
                       mailbox_type='Mailbox', item_id=None), to_recipients=[
            Mailbox(name='Test User', email_address='foo@test.com', routing_type='SMTP',
                    mailbox_type='Mailbox', item_id=None)], cc_recipients=None, bcc_recipients=None,
        is_read_receipt_requested=False, is_delivery_receipt_requested=False,
        conversation_index=b"1", conversation_topic='Test pobierania emla',
        author=Mailbox(name='Test User', email_address='foo@test.com', routing_type='SMTP',
                       mailbox_type='Mailbox', item_id=None), message_id='<34>',
        is_read=False, is_response_requested=False, references=None, reply_to=None,
        received_by=Mailbox(name='Test User', email_address='foo@test.com',
                            routing_type='SMTP', mailbox_type='Mailbox', item_id=None),
        received_representing=Mailbox(name='Test User', email_address='foo@test.com',
                                      routing_type='SMTP', mailbox_type='Mailbox', item_id=None), reminder_message_data=None)
    mocker.patch('EWSv2.get_item_from_mailbox', return_value=item)

    mocked = mocker.patch('EWSv2.fileResult', side_effect=[''])
    get_item_as_eml(item_id='item_id', target_mailbox='Inbox')
    file_expected_data = 'Received: from A by\n B\n (version=A, cipher=B) id\n  Fri, 24 Nov 2023\nReceived: from C\n D\n (' \
                         'version=A, cipher=B) id\n Fri, 24 Nov 2023\nReceived: from E\n F\n Fri, 24 Nov 2023\nFrom: "Test ' \
                         'User" <foo@test.com>\nTo: "Test User" <foo@test.com>\nSubject: Test pobierania emla\nThread-Topic: ' \
                         'Test pobierania emla\nThread-Index: aa\nDate: Fri, 24 Nov 2023 11:38:02 +0000\nMessage-ID: ' \
                         '<34>\nAccept-Language: pl-PL, en-US\nContent-Language: pl-PL\nX-MS-Exchange-Organization-AuthAs: ' \
                         'Internal\nX-MS-Exchange-Organization-AuthMechanism: 04\nX-MS-Exchange-Organization-AuthSource: ' \
                         'pl\nX-MS-Has-Attach: \nX-MS-Exchange-Organization-Network-Message-Id: ' \
                         '\n\tbb\nX-MS-Exchange-Organization-SCL: -1\nX-MS-TNEF-Correlator: ' \
                         '\nX-MS-Exchange-Organization-RecordReviewCfmType: 0\nx-greenmod-classification: ' \
                         'PropertyRoot=m;CATEGORY=NEW\nx-greenmod-classificationdate: ' \
                         '2023-11-24T12:36:56.8950031+01:00\nx-greenmod-classifiedby: \n\taabb\nx-greenmod-grnitemid: ' \
                         'ccdd\nx-greenmod-classifiedbysid: \n\teeff\nx-greenmod-flags: \ndlp-product: ' \
                         'dlpe-windows\ndlp-version: 1.2.3\ndlp-reaction: no-action\nContent-Type: ' \
                         'multipart/alternative;\n\tboundary="_012_"\nMIME-Version: 1.0\nReceived: from A by B (version=A, ' \
                         'cipher=B) id  Fri, 24 Nov 2023\nContent-Transfer-Encoding: binary\nDate: Fri, 24 Nov 2023 12:38:02 ' \
                         '+0100\nX-MS-TNEF-Correlator: <34>\nx-greenmod-classifiedby: aabb\nx-greenmod-classifiedbysid: ' \
                         'eeff\nX-MS-Exchange-Organization-MessageDirectionality: Originating\nX-Originating-IP: [' \
                         '1.2.3.4]\nX-MS-Exchange-Organization-Network-Message-Id: bb\nReturn-Path: ' \
                         'foo@test.com\nX-MS-Exchange-Organization-AVStamp-Mailbox: ' \
                         'SYMANTEC;1;0;info\nX-MS-Exchange-Transport-EndToEndLatency: ' \
                         '00:00:00.5164136\nX-MS-Exchange-Processed-By-BccFoldering: 1.2.3.4\n\n--_012_\nContent-Type: ' \
                         'text/plain; charset="iso-8859-2"\nContent-Transfer-Encoding: ' \
                         'quoted-printable\n\nNEWnętrzne\nĄłżóć\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit, ' \
                         'sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, ' \
                         'quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure ' \
                         'dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint' \
                         ' occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est ' \
                         'laborum.\n\n--_012_\nContent-Type: text/html; charset="iso-8859-2"\nContent-Transfer-Encoding: ' \
                         'quoted-printable\n\n<html>\n<head>\n<meta http-equiv="Content-Type" content="text/html; ' \
                         'charset=iso-8859-2">\n<meta name="Generator" content="Microsoft Word 15 (filtered ' \
                         'medium)">\n<style><!--\n/* Font Definitions */\n@font-face\n\t{font-family:"Cambria ' \
                         'Math";\n\tpanose-1:2 4 5 3 5 4 6 3 2 4;}\n@font-face\n\t{font-family:Calibri;\n\tpanose-1:2 15 5 2 2 ' \
                         '2 4 3 2 4;}\n/* Style Definitions */\np.MsoNormal, li.MsoNormal, div.MsoNormal\n\t{' \
                         'margin:0cm;\n\tmargin-bottom:.0001pt;\n\tfont-size:11.0pt;\n\tfont-family:"Calibri",' \
                         'sans-serif;\n\tmso-fareast-language:EN-US;}\na:link, span.MsoHyperlink\n\t{' \
                         'mso-style-priority:99;\n\tcolor:#0563C1;\n\ttext-decoration:underline;}\na:visited, ' \
                         'span.MsoHyperlinkFollowed\n\t{' \
                         'mso-style-priority:99;\n\tcolor:#954F72;\n\ttext-decoration:underline;}\nspan.Stylwiadomocie-mail17\n' \
                         '\t{mso-style-type:personal-compose;\n\tfont-family:"Calibri",' \
                         'sans-serif;\n\tcolor:windowtext;}\n.MsoChpDefault\n\t{' \
                         'mso-style-type:export-only;\n\tmso-fareast-language:EN-US;}\n@page WordSection1\n\t{size:612.0pt ' \
                         '792.0pt;\n\tmargin:70.85pt 70.85pt 70.85pt 70.85pt;}\ndiv.WordSection1\n\t{' \
                         'page:WordSection1;}\n--></style><!--[if gte mso 9]><xml>\n<o:shapedefaults v:ext="edit" ' \
                         'spidmax="1026" />\n</xml><![endif]--><!--[if gte mso 9]><xml>\n<o:shapelayout v:ext="edit">\n<o:idmap' \
                         ' v:ext="edit" data="1" />\n</o:shapelayout></xml><![endif]-->\n</head>\n<body lang="PL" ' \
                         'link="#0563C1" vlink="#954F72">\n<div id="BodyTopText">\n<p style="font-family:PKO Bank ' \
                         'Polski;font-size:15px;color:#0098d4">NEWnętrzne</p>\n</div>\n<div class="WordSection1">\n<p ' \
                         'class="MsoNormal">Ąłżóć<o:p></o:p></p>\n<p class="MsoNormal"><o:p>&nbsp;</o:p></p>\n<p ' \
                         'class="MsoNormal">Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor ' \
                         'incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ' \
                         'ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis\n aute irure dolor in reprehenderit in ' \
                         'voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non ' \
                         'proident, sunt in culpa qui officia deserunt mollit anim id est ' \
                         'laborum.<o:p></o:p></p>\n</div>\n</body>\n</html>\n\n--_012_--\n '
    mocked.assert_called_with('Test pobierania emla.eml', file_expected_data)


def test_parse_quoted_printable():
    """
    Given:
        - A quoted-printable encoded email as a string.
    When:
        - The "ews-get-items-as-eml" command is called and parses email content.
    Then:
        - A string returns with the right parsed content
    """
    from EWSv2 import parse_quoted_printable

    email_content = '\n--_012_\nContent-Type: text/plain; charset="iso-8859-2"\nContent-Transfer-Encoding: quoted-printable\n\n' \
                    'NEWn=EAtrzne\n=A1=B3=BF=F3=E6\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod ' \
                    'tem=\npor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, q=\nuis nostrud ' \
                    'exercitation ullamco laboris nisi ut aliquip ex ea commodo cons=\nequat. Duis aute irure dolor in ' \
                    'reprehenderit in voluptate velit esse cillu=\nm dolore eu fugiat nulla pariatur. Excepteur sint occaecat ' \
                    'cupidatat non pr=\noident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n\n--_012_\n' \
                    'Content-Type: text/html; charset="iso-8859-2"\nContent-Transfer-Encoding: quoted-printable\n\n' \
                    '<html>\n</html>\n\n--_012_--\n '
    parsed_email_content = '\n--_012_\nContent-Type: text/plain; charset="utf-8"\n\nNEWnętrzne\nĄłżóć\n\nLorem ipsum dolor ' \
                           'sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ' \
                           'aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea ' \
                           'commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu ' \
                           'fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia ' \
                           'deserunt mollit anim id est laborum.\n\n--_012_\nContent-Type: text/html; charset="utf-8"\n\n' \
                           '<html>\n</html>\n\n--_012_--\n '

    assert parse_quoted_printable(email_content) == parsed_email_content
