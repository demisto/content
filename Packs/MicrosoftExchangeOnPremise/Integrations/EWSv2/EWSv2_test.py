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
