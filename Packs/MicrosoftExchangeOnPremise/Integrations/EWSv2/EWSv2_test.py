import datetime
import json
import uuid

from exchangelib.indexed_properties import PhoneNumber, PhysicalAddress

import EWSv2
import logging

import dateparser
import pytest
from exchangelib import Message, Mailbox, Contact, HTMLBody, Body
from EWSv2 import fetch_last_emails, get_message_for_body_type, parse_item_as_dict, parse_physical_address, get_attachment_name
from exchangelib.errors import UnauthorizedError, ErrorNameResolutionNoResults
from exchangelib import EWSDateTime, EWSTimeZone, EWSDate
from exchangelib.errors import ErrorInvalidIdMalformed, ErrorItemNotFound
import demistomock as demisto
from exchangelib.properties import ItemId
from exchangelib.items import Item


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
                                                                            datetime.UTC))
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
    fetch_emails_as_incidents(client, 'Inbox', False)
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
    from EWSv2 import fetch_emails_as_incidents

    import demistomock as demisto

    class MockEmailObject:
        def __init__(self):
            self.message_id = "Value"

    client = TestNormalCommands.MockClient()
    mocker.patch.object(
        demisto, "getLastRun", return_value={"lastRunTime": "2021-07-14T12:59:17Z", "folderName": "Inbox", "ids": []}
    )
    mocker.patch.object(EWSv2, "parse_incident_from_item", side_effect=exception_type)
    mocker.patch.object(EWSv2, "fetch_last_emails", return_value=[MockEmailObject()])
    mocker.patch.object(EWSv2, "get_account", return_value=[{}])
    with pytest.raises((Exception, UnicodeError, IndexError)) as e:
        fetch_emails_as_incidents(client, "Inbox", skip_unparsable_emails_param)
        assert expected == str(e)


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
    send_email_mocker = mocker.patch.object(EWSv2, 'send_email_to_mailbox', return_value=(''))
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
    send_email_mocker = mocker.patch.object(EWSv2, 'send_email_to_mailbox', return_value=('', [
        {'Contents': '', 'ContentsFormat': 'text', 'Type': 'png', 'File': 'image.png', 'FileID': '12345'}]))
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
    send_email_mocker = mocker.patch.object(EWSv2, 'send_email_to_mailbox', return_value=('', [
        {'Contents': '', 'ContentsFormat': 'text', 'Type': 'png', 'File': 'image.png', 'FileID': '12345'}]))
    results = send_email({'to': "test@gmail.com,", 'subject': "test"})
    assert send_email_mocker.call_args.kwargs.get('to') == ['test@gmail.com']
    assert results[0].get('Contents') == {
        'from': 'test@gmail.com', 'to': ['test@gmail.com'], 'subject': 'test', 'attachments': []
    }


PALO_LOGO_BASE64 = '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'
PALO_LOGO_DECODED = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x05L\x00\x00\x00\xf8\x08\x03\x00\x00\x00\x00E\\8\x00\x00\x00 cHRM\x00\x00z&\x00\x00\x80\x84\x00\x00\xfa\x00\x00\x00\x80\xe8\x00\x00u0\x00\x00\xea`\x00\x00:\x98\x00\x00\x17p\x9c\xbaQ<\x00\x00\x00\x8dPLTE\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf7X(\xffP \xfaX/\xfaY-\xf4U*\xfaX-\xfaX-\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfaY,\xfbW-\xf9Y-\xf7X0\xffP0\xfaW.\xf9X,\x00\x00\x00\x00\x00\x00\xfbX.\xf7X-\xf9V-\xfbY-\x00\x00\x00\xf4Z0\xfaX-\x00\x00\x00\xfaX-\xff\xff\xff*o\x82)\x00\x00\x00,tRNS\x00\xa0\x1f\x80` \x10\x9f\xef0\xdf\x9f\x10 Pp\x9f\xcf\x8f\xaf\xdf0\xef\xbf@\x7fo\x90\xcf\xafP \x10\xcf\x80\xb0_\x7f`P\x8f\xc00`\x93\xd1\xc1b\x00\x00\x00\x01bKGD.T\xd3\x10\x87\x00\x00\'\x8cIDATx\xda\xed\xddic\xdb<\x8e\x00`\xb9\xe2\xec\xce\xbcC]\x16E2\xd5\xee\x1cm\xb7\xb3\x87\xfa\xff\xff\xde\xdaI\x93H\xb6\x0e\x90\x04\xa8\x0b\xf8\xd64\xb1%\x9ax\x08\x92\xb2\x94$\x1c\x1c\xdb\x8aK\x07\x8b/\xdcT\x1e\x91\x02[WpSm>\xfeD\xf5\xc2\xff\xc6m\xcb\x98r0\xa6\xe7\x89\x7f\xff\xf3_\x88\x90\xfe\xe3\xaf\xdc\xba\x8c)\x07cz\x1aK\x7f\xfd\xa2\xd1\xf4O\x7f\xfc\xfa\xc5\x9a2\xa6\x1c\x8c\xe9y,\xa5\xd1\xf4n)k\xca\x98r0\xa6g\xb2\x94B\xd37KYS\xc6\x94\x831=\x93\xa5\xf8\x9a\xbe[\xca\x9a2\xa6\x1c\x8c\xe9\x99,\xc5\xd6\xf4\xd3R\xd6\x941\xe5`L\xcfd)\xae\xa6}KYS\xc6\x94\x831=\x93\xa5\x98\x9a\x0e-eM\x19S\x0e\xc6\xf4L\x96\xe2i\xfah)k\xca\x98r0\xa6g\xb2\x14K\xd3gKYS\xc6\x94\x831=\x93\xa58\x9a\x8eY\xca\x9a2\xa6\x1c\x8c\xe9\x99,\xc5\xd0t\xdcR\xd6\x941\xe5`L\xcfdi\xb8\xa6S\x96\xb2\xa6\x8c)\x07cz&KC5\x9d\xb6\x945eL9\x18\xd33Y\x1a\xa6\xe9\x9c\xa5\xac)c\xca\xc1\x98\x9e\xc9\xd2\x10M\xe7-eM\x19S\x8e50\x95Y^\x94U\xc5\r\x1d\xddR\x7fM\x97,eM\x19S\x8e\xa8\x98\xde\x14\xbd\xd6\xea\xed\xaf\x157t|K}5]\xb6\x945eL9\xa2`*\x1bqST\xf7\xff\x9a1]\xc3R?M!\x96\xb2\xa6\x8c)\x07)\xa67E\xd3\xb2\xd2#\x7f\xcd\x98\xaeb\xa9\x8f\xa60KYS\xc6\x94\x83\x06\xd3\xfb\xc2\xa8Q\xd3\x7f\xcd\x98\xaec\xa9\xbb\xa6PKYS\xc6\x94\x03\x17\xd3\xfe\xc2h\xc7\x98n\xceRWM\xe1\x96\xb2\xa6\x8c)\x07*\xa6\xc0\xbffL\xd7\xb2\xd4MS\x17KYS\xc6\x94\x831=\x93\xa5.\x9a\xbaY\xca\x9a2\xa6\x1c\x8c\xe9\x99,\x85k\xeaj)k\xca\x98r0\xa6g\xb2\x14\xaa\xa9\xbb\xa5\xac)c\xca\xc1\x98\x9e\xc9R\x98\xa6>\x96\xb2\xa6\x8c)\x07cz&K!\x9a\xfaY\xca\x9a2\xa6\x1c\x8c\xe9\x99,]\xd6\xd4\xd7R\xd6\x941\xe5`L\xcfd\xe9\x92\xa6\xfe\x96\xb2\xa6\x8c)\x07cz&K\xe75\r\xb1\x945eL9\x18\xd33Y:\xa7i\x98\xa5\xac)c\xca\xc1\x98\x9e\xc9\xd2iMC-eM\x19S\x0e\xc6\xf4L\x96Ni\x1an)k\xca\x98r0\xa6a!mQ\xd6\xc6\x98\xfaZ\xd8\xed[:\xae)\x86\xa5\xac)c\xca\xc1\x98\x06HZ\x98\xfe\xbd[u\x99o\xdd\xd21Mq,eM\x19S\x0e\xc6\xd4\x97\xd2\x97\xe7\xbb`+\xb2\xc7\x0e"Y\xfa\xac)\x96\xa5\xac)c\xca\x982\xa6^\xf1\xf5\x8dR\xd3\n\xdbd\xd6\x16\xady;Q\x9a\xd9>\x9a\xa5\x8f\x9a\xe2Y\xca\x9a2\xa6\x8c)c\xeaQ\x96\xd6\xaf\x92\x16\xb2\xf7\xb3L\xbc\xde$\xfbe\xdb\x96\x0e5\xc5\xb4\x945eL\x19S\xc6\xd45\xb2;\x9b\xe6\xb9\x08}\xe5\xb4\x92\x9b\xb6\xb4\xaf)\xae\xa5\xac)c\xca\x982\xa6\x1e\x96\x16\xa3\x15k{?YdM\x91-\xfd\xd4\x14\xdbR\xd6\x941eL\x19SWK\xf5\xd4\xdah\x81^\x9b\xa2[\xfa\xae)\xbe\xa5\xac)c\xca\x982\xa6\x0eQ\xdd\xce\'\x9b\xfc_q;\xdd\xeb\xb6-}\xd3\x94\xc2R\xd6\x941eL\x19Sp\xbc\xdc\xce\xa7\x99\xf9\xff{m\x8aw\xc5)\x89\xa5wMi,=\x84\xa6\x99\x15"}\x0b\x91[\x19\xfb\xdd\x9b\xcf\xb7\xbf\x1f\x81\xb06\xdb9\xa6Y\x93\x7f\x9eRqk\xd3l\xbd\xcf\xf6\xfe\xe1\x16D\xad{XL\xe5\xa0\xd5\xf0\x1a-\xbb\x9dN:\xfb\x1bm\xd7i\xb9mK\x7f\xfd\xfa\x8f\xff\xa4z\xe5\xbf\xed\x98Q\x99\x8f<\xb8\\\x9b\xabhb\xe4\xb9H\xcbj\xe2\xb1\xe9\xda\xd4i\xde\xec\x0e\xd3\xd7o\x08*\xca\x13\x82\xb7n>u(\xb7\x83\xa9\xea\xab@\x185\x0f\x88i&\xaee\xa5\xc7\x0e\xa32\xd7"\xb4\xcd\xca\xdb\xcb\xbc\xd7\xa8\xe5{\x0c\xbeM*\xd5\x12\xb7\xeb[\xfa\xc7\xdf\xff\xf1O\x9aW\xfe\xb6\xa2\x85v9\xe6\xfe\xfaZM\xf7`]\x0b\xc2r\xaa)&z\xecC\x98k\x9e\xed\x05\xd3\xdb9\xa9\xa5\xb7\xd1&\xb5Q@0\x90\xd6\xad\xea\xa2\xd9\x03\xa6\xd6)\xbcO\xe9VY,7[U\x06\x14\x1a\xf7\xc2\xf4\xbd?\x9b\x89o?\t\xac\xd2\x94\xd0\xd2$\xa1\xd1tMK3@O\x9c\x96t9\xdd\x8c\xa0\x98\xf2\xdb\x02\x94\xe9\x9f\x1d-\xe4k\xcb\x910\x95\xa2\x84\x9f\x93)\x08\x87\xa9\xac(\x9dZ7h\xd0\x8c\x83\xa9c\x94~\xbd\xf2\xc5\xb8\xf4H\xbf\xc4\xb8\x15\xa6&\x19\xc3\xb4\xbf\xed\xa4qJSRKi4]\xd3R\x10\xa6\xa3J\xc8\x97\n\xda3q\xf3\xde\t\x9d^\xd4b\xc3\x98\xca\xc2\xb8\x9eOE\xe2\xa9\xb4W\xe5\xd3\xba\xc6\xd7\xd3\xa3`\n\xa9,0z\xa4\xee\xed.=\xf6\x99\xb4\xd7\xa8f\xf3\x96Rh\xba\xaa\xa5 L\xc5\x18\xa5.]\xc7\xa0\xcdK3wt\xfa\xd5@\xb6ML\xad\xf1\x1a\x1e\xd0\xcb~Yx\x1e\xc8\x9b@\xf6\xb4\x98\xc2+\x8b\x87\x9a\xde\xb9\xcd\xf2\xdb\x1f%}L/o\x0b\x13\x97\xfb\x07\xf71\xb7\x97\x18\xabN\xe4\x96\xe2k\xba\xae\xa5 L\xd30J\xd18\x95/&4K\x8c\xd8\x1c\xa6\xee\x8d9\xc8\xc6\x0cQ\xd2\xd0\xd6\xf5\xb9i\xd1\x010\xb5u\xc0[Unm\xd6v\xdd\xf7\x01\xa6\xef\xc9i\x07\x8d\xa4&\x1blK\x96bk\xba\xb2\xa5 L\x1f\xbbV\xee3\x11\x0c\xcdz\x84\\\xf7LxRL\x83(E\\E\xb1\xb5^\xa7uw\x8f\xa95\xc1m\xe6\xf0\t\x9a\xfe\xf7H\xfb\x98\xde\xfd\xfc\xfc\xc7\xc5w\xdd7\xae\xa5\xb8\x9a\xaem)\x08\xd3\xe1u%\x99o\xe7\t\xb9\x9d\x8d\xc7\x8a\xd4\xf4\xe94\x9b\xc14\x9cR\x14Nq\x0e\xc3\x8f\xd3\x9dcj1\x86xU\xb8,\x99Z\x00\xa6\xc5\xe7\xf5S\x9b\xb6\x14S\xd3\xd5-\x05a:\xd8\xce\xcf\xfd\xf3Ny&=VQ\xea\xa9\x0f\x19\xa6x\x86\x05qj\x91[\xd7\xedc\xde5\xa6hM\x07\x1d\x82\x86\x8b\xa1\x03L\xef}\xa9\xe8-\xad\xaa]X\x8a\xa7\xe9\xfa\x96\xc20\xed1q\r\xea3/+\x97M^\xe5\x13\x15\xa6V!\x9e\x91o\xd9/_\x14\xbeE/\xe7\xc0T^\xa3\x0fA\xd9\xa0\xb4\xe9a*\xcb\xfb\x8b|\xcc\xb9\xec\xcc\x15\x8d\xdb\xb2\x14K\xd3\rX\n\xc3\xf4\xa3#\xcb\xd0\x91\xb8r-\xa1\x82\x16\xf7qj9\x1aL3\xecz\xb0\xd9\xc8@\xe5X\x9c\xee\x17\xd3\x1c\xb9\xed\xae\xd2\x07\xd3\xea\xf5\x1bPo+\xde\xf5\xc4\xefm\xdaR\x1cM\xb7`)\x0c\xd3\xf7\xa9D\xa6"\xe7<\xf6\x0c\xd4+\xdfI0\xfd\x8a\xaf\x98\xf3\xad\x82lI\xd6\xbaZ\x1c\x1dS\x89?\xca\x03\x1e9\xf2\x8c\xe9x\x97nB0\x8dl)\x86\xa6\x9b\xb0\x14\x86i\x89fi7qS\xdb\xd8\x94\xde\xf3\xfd\xc7z\x98\xcaz\xdd\xf1\x81\xbeu\xc1S\xfd\x9dbj\xd5*\x8dvOW9\x8e\xa9N{\x95\xad\xed_\x8e\xbauK\xc35\xdd\x86\xa50L\x15\xa2\xa5\xe04#Nv\xf8\x81\xe0c\xda(\xa23\xda\xca@\xe5P(\xef\x13\xd3+Q\xa3-\x8e\x87O\x1bPO\xd3\xc7\xf7\r\xa8j?\x96\x86j\xba\x11Ka\x98v\x98\x96\xc2\x10\xa3Ov\xb0\xa6\xe8\x98~\xd5k\x0b\x16\xa5u\xcb\xc3b*\tW\x9f\x16\xa6\xfa\xaa\x7f\xaf\xd2\x8fo@\xdd\x1fV\xa2\xb3a\xab\x9a\x1dY\x1a\xa6\xe9V,\x05bzw\xa2\x8a\x88X\x94d\x87j\x8a\x8d\xe9\x95\xf2\x8c ;|Y\xa4\xd6-\x0f\x8ai\xa6\xd6\xeb\x93u\xd7\xb5\xcf\xbb\xf9R?\x1c\xf4\xe0\xd7v`i\x88\xa6\x9b\xb1\x14\x88\xa9@&`\x011\xd1\xc5\x8a\x97\xe8\x98\xca\x92\xf6\x8c\x96\x17N\x9bh\xad[\x1e\x12\xd3F\xaf\xd8\'\x8b~\xc9\xf9yi\xd4k+\xf6\x8aZ\xedy\xb3\xfd\xd5,\xf5\xd7t;\x96\x021M\x93\xaf1\x11\x93:Z\xbe\xff\x88\x8c\xa9\xac\xa8\xcfhYS\xb3\xa5\xb1jw\x98\xfe \xef\x9csk5\xb6\xbf\x03\xf5\x89\xe9k\xc6\x98\xf1\xdf\xda\x87\xa5\xbe\x9an\xc8R \xa6e\x86\xdd\x83\xe6\xb7J\xdah\xe9\xae\x9b\xa8\x98f\xd5\x06N)\x8f\xd6\xba\x80\x1d\xb1\xbda\xfac\xe5\x8a\xbe\x7f\x17\xfd\xdeE\xfb\xc3\xd2\xb4\xec\xdf\x0ee\'\x96\xfai\xba%K\x81\x98*\xfcU\xa2\xd9\x85v\x1b/\xdd\x97\x1f2\x8e\x88\xa9T[\x18 "\x16\xfe\xcbc\xd5\xce0\xfd\x11\xa5\xd9\xca\xd9\xf6\xd2#\x98\x0eJ\xd3{R\xe7\xbb\xb3\xd4G\xd3MY\n\xc4\x94"\xcd\xb2m\xccD{_\x1b!\xc7TV[h[8`1\xc6\xaa}a\xfa#R\xb3\x95\xb3#a\xf1\x8c\xe9\xa04-\xbd\xbe\x99\xbf\xba\xa5\xee\x9an\xcb\xd2\xf50\xed*9\xbf\xce\xbe\x99\xa9(\x1e\xa6\xd1\x86\x88\x85u\xd3&b\xeb^\x8f\x84i\x13\xad\xa6\x7f\x99-M\x7f\xa7Nc?\x1fy*\xed\xc7?\xb2\xce\xe7n\xa6\x1b\xb0\xf4\xa6\xe9\x1fT\x96\xfe\xdb\xa11\x9dM\xb3\x883\xd1\xc5g\x8f\xa1az\x8dwN\x0b\x05a\xc4\xc2\xbf\xb3\xc7\xc14S\xf1\x9a\xeden\xa9\xc8,\xad%\x99}Z\x9a\xfc\x17\x95\xa5\x7f\xfa\xe3\xaf\x87\xc6tvY\xa7\x8dx\x1cu\x1cL_b\xb6\xad\xd9\xca\x16\xd4\x92\xeb;\xc24\xa6\xa53\xd9a\xbb\xf9\xcb$\xea\xe5u\x9e\x13Z\xfa\xeb\xd7_\x0f\x8d\xe9\xdcGnc\x1e\x88\x8d\x81i\x1e\xb7q\xe7\xa7\xd7\x11\x0b\xff\x85\xe7d\xee\x08\xd3z#\xd9\x91\xcejZ\xfaL\xf2O`i\x04M\xd7\xc4t\xb6|2\x1b9\x0e,L\xe3\x965K\xdb\xb9iL\x15\xe410}\x89\xfc\x01N\x97\xf4\x97\xe9\xc1R\x9a\xce\xe31\xcf\xa7\xb0\x94^\xd3U1\x9dK\xf8\xa8\x85\x9c\xa5\xc7\xb4\x8a\xdd\xb6\xb3S=\x19\xf3H\xd2C`j\xa3g\xc7u\xb6K\x8en2Z\xc5\x96NZJ\xae\xe9\xba\x98\xce\xac\xa7\xc5\xdc\x82\x9a/MQ0}\x89\xdf\xb8f+[P\xb3\xa5\xe9^0\x8d>\xb3\x98\xad5^[\xed\xe9\x06\xe7o\xb7\xb4(\xd8\xd2\tK\xa95]\x17\xd3\xb9A4\xe6Lt\xb64\xc5\xc0t\x95f.\xb6\xf1\xb5\x88\xf9Ri/\x98\x96+|\x803\xa3\x90x\xb5\xdd\xf4\x1el\xda\xbc=\x08]Y\xb6t\xd2RbMW\xc6tf.\x1a\xf3b\xc8\xd9*\x0e\x03S\xb5\xb1\xc6\x8d\xbb\x055W\x9a\xee\x04S\xb1Jz\x943\x89\xfb\xbb[jS^\xd3\xb2\xac\xde>\xcf\xc1\x1d\xa2\xd9\xd2\'Ki5]\x19\xd3\xb9\xee\x12s&:w[\x08\x04L\xbf\xae\xd3\xb8f#[Psk\xe3;\xc1T\xad\xf3\t\xce\x95\x99\xd9S\xc7\xf4\xa0\xf4l\x96\x92j\xba6\xa63\xdd\xc5u&\xaaLY\xa6\xf7(k\xe3\xdc\xf7SJL\xb3\x95Rq\x0e1\xd7-(U\xd5e{o\xdd\xb64\x15\xa2\xea\xfb\xc0\xf4e\xa5\x0fp\xfe[\xa1R\\>{\x96j\xad\xc7\x8d\xa2Ng)\xa5\xa6a\x98\xaa\xbaL\x0b!n~\x19\xdfi\xa3A\x98\x89\xaa\xb2\xc8\x1f\xa6\xb4\xd2\x16N\x95\xad\xa6\xc4\xd4s\xbdMW\xb7\xc1A\x88"m}[w\xee\x82yp\xf3\xe8\xba\x15\xcd\xc3\x0b5\xa2v:$\xb92\xa6Z8\x85E\xca\x12U\xb7o\xf9Q\xfbN\xb3\x16w\xe6\xa5\xcd\xefG\xdcH\xaf\xf4?\xa1\xa5\x84\x9a\xfac\xaaK\x91=\xe4\x97\xd7\xebdayV\xb5\xf9T?\xca\x84CEh\xe90\xf5jcS\x0c\x1a&\xcb/\n7\x17-l\x98\x12\x93\x9f\x8fp\x00\xa2X\x19S\x15\x96%>\xa3\xa1~\xa8\x14\x9b\xc2\x07T-\x13\xc28\xa5\xa5t\x9a\xfabj\n\x19\xa8\xd7{\xb4\xfe3Q]\x8b\x85\xbe\x06?\xa0\x96\x0eS\xf7T\x1c_\xfc\x12\x065\x17\xb5\xa3\xe7#\xd7\x02\x83[\xd7\xec\x1aS\x8f$1vt\x95Sa\x0e\x87l\xa9\x9f\xa5d\x9a\xfaaZ\xd9p\xbd\x00\xf9n\xe6+c\xc8\x1a\x11\xf8n\xcc\x8a\x0cS\xe7&\xd6\x93u\x9c\xc5\\\x0b\x9eeL\x1b\x01\xa9\x89\xc0\xb7P\x90{\xc6\xb4D\xa1\xf4\xb5/\xa4\x1aq8dK\xfd,\xa5\xd2\xd4\x07S=w\x01\xa3L\xf1\xf2\xdd\xce\xe4:t\xb5\x1d|\x0f\xd1/T\x98\xba\xa6b;{oB\x8d\x96\x8b\xd2q\xdeAa\xe1.0u\xcd\x11\xe5\xb6\x07\xbfVizbK\x894\xf5\xc0t\xe9!C\xae\xe5\x93v\x9e\x89\xc2s=\x81\xdf\xdd\xbe \xc2\xd4\xb1\x85\xf5\xc2E\xd7\xaeW\x06\xa4\xce[Pn\x17\xd8\x00\x97\x1e\xca\x1dc\xea8\x1a\xd6\x0b\xcdWl\xa34=\xb5\xa54\x9a\xbaczY\xfcp]\xf3\xdd:\xd5=\xbau\xfc\x8e\x87\rL\xf7@LK\xd4\x91*q\xbd;\xa1rl\x18\xe3\xd8\xba\xc0\xa7\x83\xa9\xfdb\x9aaW\x92\x8d[~\x14l)\xbe\xa5$\x9a:cz\xc1\x9cZ/062\x13\xf5\xb9.\xd9\x84\xe5[\x18\xa6n\x8f"\xac g\x97"\rU\xcf\x85\xbfN\x9do\x84\t\xb5]\xee\x16S\x81l\xa9k\xb5Q\xb1\xa5\x04\x96Rh\x9a\x11X\xea\xaa)|\x0b\xca\x08\x9fsL\xc3\xd2=\x0cS\xa7TT\x12\xd3\xaf\xa5\x8d\xf4\xc7\x86\xf1\x19\xa8\xc0\x85\x7f\xbe[L\x15\xb6\xa5\xae\x9aZ\xb6\x94\xc0R\x02M\x1d1\x85>\x0e\xc1\xed1\x9c\x02\x96\xa9\xc6\xb3W\xe5a\xe9\x1e\x86\xa9\xcb\xb0\xa2\xa0u\xa1\xd3\x15\xbd\xc0;s)\xe1\xd7\xba\x12v\x14\xed^1\xb5\xf8\x96:>L\xaaeK),\xc5\xd7\xd4\rSp\xb6\xbb\xcdnK\xc8L\xd4x\x0f\xd0\xc0[\xa6\x14\x14\x98:\xb5/\xb8u\x9d\xc6\xaa\x02\x82\xb2\x7f\xeb\x02=\xfb\xbeWL]\xd6\xbck\xf0\xab\xbaLX\xd0\xb7\xa0\xd8R\x1aM\xdd0uXQs\xd9\xb3\xd4\xcb3\xd1\x80d\x87\x9ecI\x81iKP\xd6$n\xb7\xd42\xcbUWH\xeb&a\x9cm\x1eSMQk\xb8u\x0c\xc1\x96\x92X\x8a\xadi\xd6\xd1d\xbb\xdbM\x9f\xec\xc2$2(\xd9\xa1\x13\xb5\x8a\x02\xd3\n\x05\xbd\xb0M\xa8\x99\xdbYU!\x13|7\xcfv\x8aiN\x84\x9e\xcb\xe4\xe2;[Jc)\xb2\xa6.\x98\xba\xf5H\x97\x89~;k\xb2\t\\\x81/\xc2\xea\xe3\x10L]\x9a\xd7m#\xdd!\x17\x8bY\x93u\xe0\xa576\x8c\xf4\xadc\xea0\xcb/\xa9\xd6bQ\xe7\xf9l)\x99\xa6\x19\xddl#E)\xca\xac\n\x9e\xe4@\xdd\x91\xf8\x98\x16T\xa9\xe8\x92\x8bf\xae>JC\x13\x15\xaaM\xbeOL\x15\xd5h\xe82u\xb3l)\x91\xa5\xa8\x9afT\x85\xa9\xdbS\x9cf2:xT\x06\xdf\x8b\xf2\x0b>\xa6\x86,\x15\x1d^\x9a\xf4\xceCy\xe0P\xbcqL\x1b\xb2\xd1\xd0e8l\xd9R*K15\xcd\xc8\nS\xa7\xd2\xd4\xd2e\xfb5\xf4 B0\xd5d\xa9\xe8\x92\x8b\x84\xad\xfb\x15|\x86\xe9.1-\xe8FC\x87\xe1\xb0bK\xc9,E\xd44#+L\x9dJ\xd3\x82(\xd7\xa5\xcb]\xac\x04:\xa6\x960\x15\x1d\xf6\xb6Z*J\xad\t\xae\xae6\x8eiM7\x1a\xba\xf4\x0e\xc9\x96\x92Y\x8a\xa7iF\xe9\x1d\xbc\'~\xa7H\xf5L\x94N\xdf\xe5\xc4\xc7\xb4\xa0l\x00\xf8\x8b\x1b\x92q*\xbf:\xb5n\xb9KL5e\xf9\x0f\x7f\xf1\x9c-\xa5\xb3\x14M\xd3\x8c\xb0tr\x18z\x15*\xa2M.\xd2\xf7\xe75\x86_\xf9\x15\x80i\x1d\n\xf9\xacf\x18\xd7\xf1\xfa\xb6n\xed|g\xd5\xef{\xc4\xb4!\xed\xc1ihY\xcf\x96\xa2X\x8a\xa5iFZ\xdd\xe8\x88\xf3\x18\x99\xbd&y\xe5\xff\xf0:|L+R\xee\xe0s\xec/\x08\xadkEq-\x03Z\xd7\xec\x11\xd3\x9c\x94\xbb,t$bKq,E\xd2\x14\xfcyz\xadj\xc2o\x84\xdb\xf8\xa7ys3\xd4`<\xff\x13\x1dSI\x9b,\x05e\xdd\xdbo\xddZ\xe9\xf0\xd6\xdd%\xa6\xf0\xda\xd1k\x93Ou\xc4\xc7\xcf\x96\xc6\xd44#\xd5N\x90\xa6\xbbl\x8ak\x85\x90\xe6\x0b\xabz\xfe\x98ZZ\xed2\xd2\xb2)\xc9\xc4\xb5F|Fu\xb5GL\xc1\xeb4~+)\xf0\xef\x94J\xb6\x94\xd4R\x14M3\xd2\xde(\xc9\xd2]\x8ak\xd5!\x07:\xa6\xf0\xb1$KH\x0b\x1b\xd7\x9df\x99_\x8dFn]\xb5GL\xc1}\xcco\x1e\x0e_Eh\xd8RZK14\xcdH;\x0bM\xbaK{U\x1dA\xa0c\x9av\xb4\xb9~\t\xac\n\'\xb6\r\xaf\x86\xa2uw\x89)\xf1\xb5}\xf0bC\xb0\xa5\xc4\x96"h\x9a\x91v\x16x\xba\x83\xf7\xb7d\x81^3\x91aZ\xd3\xd65\xf0ES\r\x1f\xa7J\xaa\xd6\xdd#\xa6\xf0\x85\x14K\\l\xa4l)\xb5\xa5\xe1\x9af\xb4\x9d\xa5\xc0\xad\xcd\xa40\x1d]\xa0cj\x88S\x05~\xe1\x0el\xc9\x8dN\xd2\x9dbj\x91\x1b\xd8\xbf\xd8(\xd9RrK\x835\xcdh;K\x8eY;5W\xc2\\\xa7\xc0\x14\\wx^\x93\r\x9f%\x02\xae\x8d\x92/\xb4\xad\xbbGL\xf3\x8e\xf6\xf5\xe1\x0bA\xdf\xd9RzKC5\x85bJ}\xb1\xc0\xf2\x1bX\xd3\x11\x07:\xa6`\x9d|\xb7\x17\xc0o`\xd7\x1e\xa8\xf6\x89)x\x07\xd1\xf7;f\xe4o\xc0\x96F\xd4\x14\xa8\x9d\xf7\x9d\x16\xb0j\'zJ\t0%\xbf\xf0\x05\xbc\xd9\x9c\xaf\xdf\xba{\xc44\r\xec:x\xeb\x08\x8a-\x8dai\x98\xa6\x19\xf1\xc0\xa8P0\x8d\x91\xec\xf8\x98\xc2g\xe1\xbe\xad\x0b\xde\xe1\x9a\xdd\x0c\xce\xca\x18\xad{hLS\xda\xf4\x0b\xc0\x94-\x8d\xa7)\xf0\xd3\xfc\xbe&\xa6\xf2\xdau{\xc4\x94>S.\x18\x98\xbe\xe8\x8e1\rl_\xdf\xbb\x9e\x81\xc7[\xcd\x96\xc6\xb14D\xd3\xc0\x87\xcd-\x06\xb8\xa4\x9c^\xd5\xcb\xe3$\xfb\x8a\x98z/\xa2\xa4\xe1\xc9nU\xa4\xd6=4\xa6\xde\x97\x81\x12O^\xd8\xd2\x98\x9a\x02\x13>]\rSYw\xdd\xd115\xe4\x98N~~_\xa3\xb5\xee\xa11\xf5\xbeE\x9e&\xc5\x94-\x8d\xaa)5\xa6\x97@L\x1b\xd51\xa6d\x98f\xa6cL\t{/\xe22\x18[\x1a\xcd\xd2_\xbf\xfevHL\x7f\xe8\x8e1%\xc34\xe6H\xc5\x98\xc6\xc7\xf4\'[\xea\x15\xdf\x92#b\xfa\xd2u\x8c)\x19\xa6y\xcc\x91\x8a1\x8d\x8f)\x91\xa6l\xe9\x1e1\x8dk\xe9\xd90\xfd\x11\xb7u\x19\xd3\xf8\x98\x92h\xca\x96\xee\x11\xd3\xc8\x96\x9e\x0c\xd3\xc8\x962\xa6k`J\xa0)[\xba\xc7\xdd\xfc\xd8\x96\x9e\x0bS\xdb1\xa6\'\xc0\x14]S\xb64\x18\xd36>\xa6_;\xc6\x94\x0e\xd3L3\xa6\'\xb8\xce\x14]S\xb64\x1c\xd32:\xa6\xf1\xb3}\x87\xdf\x80\x02?\xf6\xe2\xf1\xa2}\xa9:\xc6\xf4\x1c\x98\xa2j\xca\x96"`\x1a\xff\xeb\xa4x\xd9n\xeca1\xf5N\xf62~\xeb\xee\x11S\xef\xc1\n9\xfd\xc2\x9e\xd6\xfd\x93-\x8db)\xf9]\xa3\xb4\'\xa6W\xbcd\x07\xf7XlL%y\xd9a<1\x15h\xad\x9b\x87zv\x8c\x1b\x9d\xf8.\x835\xe4\xe3-\xa6\xa6l)\n\xa6\xbe\x9f%\xdc\x13\xe97b/\x8c\xe7\xadux1lL\xd1\xee?8\x19\xe0[\xf0\r\x17Q2\x9c\xb2_\xd76\xdc\xb3Mc\n~P\x84\xef2\x18x\x1b\xb0J\xd6\xd7\x94-E\x9agH\xe2\x91\xb7\xc3\x9f\xe4\xbfI\xba&\xa6\xd4w\xda\x87km\xd1\'\xf9\xba\x16\x12\xc3\xb3c\xdc\x1c\xda\xd7:\xb0\xd6&Y]S\xb6\x14\x0bS\xcf{\xc1{>\xb6$x\x1a\xaa\xca\xa2q>GtL\xc1\x85\xa3\xa0\x1e\xaa\xbe\xa0\x96\xfd\xba.,\x96g\xc7xl\x89\xef\x92&xQ\xf6{\xb2\xb6\xa6l)\x1a\xa6\x9e\xe9\x9e\xfa\r\xed\x01\x85\xa9\xaa\xdb\xc2\xfa\xad\x19\xa0c\n\xbe\xe1UK\x9c\xeb\x1dVa\xaa\xab\xb2\xc83L\xcf\x0e\xf2tR\xcf\x85\x1a\xeaG.\xe2i\xca\x96\xe2u\x97\x96\xb8\xb3\x98\xe0\xc2\xf4-\xcfe\xc09\xa2c\x8a\xff\xa0k\xcf\xa1J\x05\x17\xa6\xb7\xd6ME#\xf1=\xdb4\xa6\xf0%\x7f\xcf\x85\x1a\xf0\xfel\x91\xac\xab)[\x8a\x88\xa9!\xee,\xad\x17\xc1\xbdi\xa7\x0c?GtL\xe1\xcf\xb5\x97\x11\x87*\xd7\xc2T\x9b\xf6\xb1\x18=\x0b\xa6\x9e\xfd\x97`\x9d\xc6&\xabj\xca\x96\xa2Nd$mg)\xbcK\'\x95Z\xa4sD\xc74\'\xce\x15\xbfTwZC\xd1\xad]\xfa\xe4\x8f\x8ci\xd5\x91\x16\x1b\xf0)X\x93\xac\xa9)[\x8a\x8b\xa9W\xba\x83K\xb3\xc14\xa9uHvc\xf1\xce\x11\x1dS\xf8\xa8\xe0\xb5$f\xbd\x86*\x8b\xdc\xba\x87\xc6\x14\xbcP\xe3Wl\xc0\x9f"\x81\x92\xec?\xd9RJK\xe1\xf9\xee5\x8f1^#\xaf\xc2M\xf6\xf50\x85\x97\x8e^\x85\r|\xd0\xb1^\xb3|\x05\x1b@\x8f\x8c)\xbc\x1a\xf0\xda\xa1\x05\xf7\x8f*YQS\xb6\x14\x1bSM\xf9\xe2\x83\x917\xf3*\xb8\x10*8|L\xc1\xb3D\xaf\xdd`\xe5U6\x81\xff\xaa\x05\x16[G\xc6\x14^\xc6\xfb\x0c\x87\xf0e\xa02YOS\xb6\x14\xdf;\x8fy>|I\xa8\xf2\xf9+\x91l\x1dSx\xed\x98R&z\xe5\xb3\x8c\r>\xa2#c\n\xdf\xce\xf7\xd9C,\xb1\xcb\x06\nM\xd9R\x02L=\x86^\xe55\xf2\xd6\xd8\x1d,_\rS\xf8h\xa2)S\xf1\xbb\xc7\xc4\xb5\xc5\xeeA\xbb\xc4\xd4an\x91\x12\xe6\x1e\xca\xfe\x93\x9f\xa6l)\xc9\x07\xea<\xf4:lu\x08\xf7\xfe\x0b\x9f\xf9\xa4\xaba\xea\xd0\xba\x96\xf0\x93\x13\xeeC\x95\x92\xd8\x9f\xf2>1\x85\xcf-\xdc\xdf\xa2\xa0\x1cj\x914eKiR\xd2y\xe85^#/tf\x95\xa1\xef\x99\xe2c\xea\xb2\x97\xe6\xda\xba/~uM\x15dW\x00\t\xfb\xc44\'\x1c\x0e\xe1\x9d\xe3{\xb2\x92\xa6l)\x11\xa6\xae\xabBM\xe75\xf2\x02+\x1d\x87\xfd\xcdj=L[\xb2\\t\xb8\xf3\x93\xf2\xd0\x07\xfeY\x97{\xc0\xd4\xbb\xb4\x83/\x9a:\x0f\x87\x0e\xdf\xf3\x13\xc9:\x9a\xb2\xa5T\x98vW\xaa\xe5\xa6\xc1\xc8\x0b\xac\x05Z\xfc| \xc0\xd4\x92\xe5\xa2\xc3\r_K\xf7\xcf\xdb\xe0\x7f\xcc\xabb\xea{\xd73\xa7\xe9\x95\xa0\x1a\r\x1dfa\xa8\x9a\xb2\xa5t\x98\xba\x15O._\xb0\x17\xee\xd3F\xf8\x97\xa1\xf3\x151\x95\x0e\x0f_)\xa8>\xb7\xdc]\xf7\x16\xff@h0U\x01\x1f\x0e\xea\x82\xbb\xf3\xd4\xcd\xe1[\xbd\n9\xe9\x81\x9a\xb2\xa5\x94\x98VD\x03\xef`\xe4M\xb1a/W\xc4\xd4\xa5\xb0\xd1.\xf5\x87C\xebj\x8fR9\xc5\x1f3\xd7\xc54\x8f\x91 .S7\x97/\xa2\xb5\xc9\x1a\x9a\xb2\xa5\xa4\x98\xba\xf4\x96\xd2\x17i\xa0]\r\xfe\x19R`\xeaR\x9f;\xcc\xad]\x1e\x83]z\x1c\x8f\xc0W}]L\xfd=r\xb9\xebNNSk4\xc9\n\x9a\xb2\xa5\xc4\x98\xc2{\x8b\xd3C\xef[JL\xc5\xaa\x98\xba\xcc\xf3\xbb\x17\x8a\xb2f\xf8\x99ac\n?\x92u1\xf5\xbfS\xbd\xc3<\xdfarQ;\xbc\xaaJ\x92\xf8\x9a\xb2\xa5\xe4\x98j\xa0a?\x9c^\xb5\xf1\xb0\x0b:\xcd\x97jUL\x9d\xee\xda\xd2\xfd (k\x86\xa9\x08\\\x91\x06O\xf3\xcd\xca\x98\x82\xdf\xdf{\x07J\xba|\x80\xd0\xcbs\x9dj\r\x91\xc4\xd7\x94-\xa5\xc7\xb4S\xa0\xb1\xb7q{M\x1f\xbb\xa0=\xcc\xa1\xdb\x92`\xeaTD\xc24u{\x1e^\xe9cW\x89\xbf\xcbH\x83)\xb8\xc2\xf3\xbfU\xbd\xd3\xddu+\x89n)\xf6^>DS\xb64\x06\xa6 M\xdd\xea\xd2\x87<\xb9\xa0\xa6{\xd6\xad\x8c\xa9\xe3\x9d\xae\x0blK\x1fR1\r\x92/\xe4Ph0\x05\xdf#\x0f\xb4\xd5._FJK\x8b\x9e\x1fn\x96\x96I\x12[S\xb64\x0e\xa6\x9d\x16\xb8}\xe51\xdd/\x88\xc9\xe12\xc9\xa7\xc2\xb4pk\x8c\xc5uS\xabCR\x11z4\xb0U\x14\x97]F\x1aL\xe1+\x9a)\x80R=:\x9aU\xb8\x9aJ\xc7G\x1d\xd8$\xb6\xa6li,L\x97\xf2]\xd6\x8e/\xf7\xdd\xcf.\xd0\xbc\xad\xeeV\xc7T\xba\xe1\xd7\xd5\xf3\xc9x\xed\x82RQ`\x96CN\xa3&\r\xa6\x02\r%[O\xedT9\x0e\x87z~v\xd18>-\xd2$IdM\xd9\xd2\x88\x98vj\xa68\xfd\xaa\xbb\xb0t\x87\xda\x05)M\xcbn}L\x9d\xb6\x83\x97Z\xd7\xba>\xb7\xd5\xf8\xe2c\x91-%\xc2\xd4\xe1\xbb\xf3s\x9b\xa7\xd9\x8b\x9e>q\xd7\xe1\xb03\xd9L\xf5\xeb\x9a\x1e"\x89\xac)[\x1a\x15\xd3\xe9[\xdc[\xe3.\xb3\xaf=\x8bC\xb6t<\x18"L\x9dsq\x92S\x8f\xd6\xb5\xbe\x0b\x80\xcbk\x7f\xd7n\x03\x98\xba\xf4\xdf\xa9\x92\xd1\xbe\xf4\xdb\xb5\r\x1f\x0eo])\x9b^H@i6:M\xd9\xd2\xd8\x98\xde\x13>\x9b\x19\xde\x03F^\xf8\xc4\xad\x9e\xafM\x9d\xab8"L=r\xb1S\xd7\xa72J\x16\xc6c\xd0\xf3\xff\xbc\x174\xcdL\xb7\x05L\x13\xa7.W=\xd5\x00\x99(\xf5\xe2\x8cG*\x8f\x96\x17O\xafc\xaf:<=\xa85eKW\xc0\xf4\xde5\xaf\xf9\xfb\x93\xd4e#\xae\xca\x0f\xe5\x80\xcd\xd3\xb9|\x97W\xf7r\x82\x08S\xe9\xd52\xaa\x14\xef\x0f\x06\x95\x99\xb8\x1a\xaf\xd6}j \x89\xb3\xdc\x80Wb\x85bZ\xb9\xb6j\xde\xbc7j^\x94\nvA\x85\xf0j|\x93\xbe\xbfW\x92\xd9\xa2\xd4^\xaf\x91$Q5eKW\xc2\xf4w\xf7\xbcE\xc0\x9f\x8b\x80t\x9f\x9cN\xf9$;\x1d\xa6\x9e\xb9\xf8\xd1\xba\xda\xfb\xafG\xce\xc8\xe5\xb3\x9aZ\xcc\xf1j]"L[\x8ff\xd1\xb3\x8dj\x82\xafo{|\xaf\x80\xfc\xc8\x92\xa8\x9a\xb2\xa5\xebb\x1aHq\xe0\xc4\xed6\x9dz^n(\x0c\x16=8\x98\x06\xe4bP\x8c}\xbb\xf1\xe2\xf6\xf1\x14\xcf\xcb\r\xc2h\xa4O\x1a\x03S\x81\xdfl#C\x88])=\xca$\x89\xa9)[\xbakLE\xe0\xe5L\xafiZ\xa7\xc2\xda&\xcb\xb2&\x17\xd7Z!\xf7\\\x04L\x9bu\x1a7\r\xbf\xec\xf5&\xb2\xb9\x16\xf9[\xebZ\x91\x96\xde\xadK\x84)A\x07n\x91\n`\x84R#Kbj\xca\x96\xee\x1aS\x85\x91\xee\xc4e\x00\x02\xa6>{P4\x8d\xbbZ\x8dE\x85i\xa2\xd0\x8ft\xec\xa2;\xa9\xd7h3\x91$\x115eK\xf7\x8di\xbe\xa5C"\xc4T\xaa\x15\xce\'\x0b\xdf\xfe\xde\x01\xa6\x045c\x1avA\xeb\xbe&\xf9\x1f\x9a\xb2\xa5\xfb\xc6\xb4\x8cTk\xac\x8e\xe9\x1a\x13\xfd4\xect\xf6\x82)A\xa9]EB{\x1b\x93\xfc\xdf\x9a\xb2\xa5\xfb\xc6t\xa2\xb7\xa4\x07\xc44\xfe\xe2\x85\x89\x87\xcf\xaa\x98RL\xc0\xed&&\x17y\x121\xfeEf\xe9\x7f\x9f\xc5\xd2u1\x15\xdb:&RL\xdd\xf7\xd5\xa8\xca\x1a},L)J\xc6ztr\x11\xb9\xe1\xd2d\xab\xe1d\xe9\xaf?\xff\xe5$\x96\xae\x8ai\xb9\xb1+\x89h1\x8d\\\xd94\xdb\xda\x0c#\xc4\x94\xa0\xd4\x1e\xbf\xefC\xdc\xc9\x859\x88\xa5\x0e\x9a\xee\xdc\xd251\x9d\xae\x9d\xec\x111M\xb2\x98\x95\xcd\xcc\x9d\x8b\xd6\xd9\x98\xa6\xc3\x94b\xecMW\x1f\x86b.\x98\xd2Z\n\xd6t\xef\x96\xae\x89\xa9\xdd\xdaE\xee\xc4\x98\xc6\x1c#f\xa7\x88\xed\xc10%\xa8\x18\xab\xb57\xef\x8ed)P\xd3\xdd[\xba"\xa6\xe96\xd8\x89\x88)\xc5\xb7u\xc6\xa3\xddN\x89\x1c\x01\xd3X[P\xb7w\xaa"5\x96n\x8ed)H\xd3\xfd[\xba\x1e\xa6\xf5\xeca\x99Cb\x1ak\x9ex\xd9\xc6a\xc4\xc2\x94\xe2|&V,ciz0K\x01\x9a\x1e\xc0\xd2\xd50]x\x8c#\xf2e\x99f#\x98\xc6al\xc9R\xec\xbd0\xb56\xa6\x14W&O\xf4\xcf,\xca6\xa28\x9a\xa5\x8b\x9a\x1e\xc1R0\xa6\xff\x83;\x95Z\\\x12B]\xd7S\xcdV0\x8d\xa1\xe9e\xf9(P\x97Q4\x0c\x18JL\t\x96\x85\xa6V\xa12\xfa\xdaT\xdb\xe3Y\xba\xa0\xe9!,\x05cZ\x8a\xa8\x96\xa2\xce\xa7t\x06\xbb\xb62\x06\xa6\xf4\xeb\xa6-\xe4(0\xc7*\x01\xbb\x84\x96\x12S\x82\x8bxu\x8c\x9ey\x8a\xf5R\x80\xa6\xc7\xb0\x14\x8e)f\xfeA\xb6*\x11wIr\xe0-\x84\xa3`\xea\xfatQ\xcc}=\x92\x89~\n\xa4\x99\x14S\x82=(\xbb\xd2\xd5\x10\xc7\xda\xc7\x07iz\x10K\x1d0M\xaa\xb8\xdd\x05\xad\x84+\xa0 \xc6\xc1\x94t\xd9MCW\xdb\xd0\xc6\xaa\x16\xfaQ\x91bJ0\xd17\xeb\xac\xd5T\x87\xb5tR\xd3\xa3X\xea\x82)\x16\x02\xd0\xa1\x17\xa9\xcb\xa6\xe0K\x11#a\x9add\xdf,U\xf0\x19"\x92>\x17\xf0v!-\xa6\x04\xc0\xcdl\x91\xe6d\xe3a\x9b\x1c\xd7\xd2\tM\x0fc\xa9\x0b\xa6H\x9a\xc2\xa71)\x9a\xa5\xb0\x1b\xa8\xc5\xc2\x94\xac\xb41\xd2\xe1\x93\x17h\x96\xc2\x9e4C\x8c)\xfe\x05\xf5i\xfc\xd9\x85.\x0em\xe9\xa8\xa6\xc7\xb1\xd4\tS\x94.\xe4\x92\xf0-ZFd\xdb\xc24i\xd4\xfa\x99\x98bY\n\xbb4\x89\x1aS\xf4M(\x1d}<4\xd9\xc1-\x1d\xd1\xf4@\x96\xbaa\x8a\xa0i\x1b5\xdf?\x97\x10\xf5\xb60Md\xbb~&\x16H#\x15\xcc1rL%\xae\xa6K\xcb\xcf\xe8\xe3\xa1\xde\xeem\xa2\xd0,}\xd2\xf4H\x96:b\xea\xfe\xb4\xf4\x87\xfe\xe2z\x8b\xc60M{K\x88\xd5\xc60\xc5NF\xaf\tb\xae\x91\xb4i\xb7\x80)\xea6\xbbN%\xf9P\xbf\x9b\xb2\x14\xd1\xd2\x07M\x0fe\xa9+\xa6a=\xc8\xa3\xbf\x84\xe4{\x7fE\xe1\xb29Lo\x95!\x1e\xa7\xa5\xf4\xfb\xf4\x03\x8e\xa0\xbf\xf6-\xb6\x81)\x1ao\x10J\xef\xcd\x87\xb7N\xabDr\x0eK\x07\x9a\x1e\xcbRwL\xfdw2\xfdV\xd73\x9c\xb7+6\x88)Z2\x1a\xef\xaf\xccH\xef#h\xfb\xdc4\x1b\xc1\x14g\x9b]\x15\xe0\xa1I\xa8\x98x\x1f\xc2\xd2\x9e\xa6\x07\xb3\xd4\x03S_\x02j\xdfi\x8c_\xb9\xf1P\x05\xe7[\xc4\x14\x87S\x13\xf4\xedC?\x0e\xd4\xf0=\xe5V0EhP\xc7\xe6D\xe0t\xdb\x94\xa2[\xfa\xa1\xe9\xd1,\xf5\xc1\xd4k\xfc\x0f\xc9x\x8f\xeb2\x95\xf58\xcf\x150\xbdg\xbfZ\x91R?~\x9e\xb7J\xd4V0\r\xd4M\xa7\xee\xdf\xe5\x14\xe6\xc8\x94\x12X\xfa[\xd3\xc3Y\xea\x87\xa9s\x8f\r\xcdx\xc7\xb7\x1b[P\xd0\x1b\xc5\xf4V\xd6\xf9\xa7\xbfN1v-\x1c\x07\xab\xb1\xec\xaf\xb7\x83\xa9?\xa7\xba\xb6\xd1\xc6\xa3\x8f\xcc\xc8\xb7M)\x89\xa5\xaf\x9a\x1e\xcfR_L\x9dz\xacA\xb8\x0b\x8e\xcb\xdb\x89\xb1\xfeYm\x16\xd3[X\xaf\xf2\xd4X\xacD\xb4u`!\xd5n\tS/N\xf5x\xb7\x01\x0f\x88&R\x1d|\x08Ko\x9a\xfe\xebx\x96\xfacz\x17 j\x87\x01\xbe\xddTuq\xd92\xa6\xee\x9ejS\xa0\x964\xc0\xd5\x86\xa9BJl\x0b\xd3{s\xba\\\x06\xa2\xda\xf0q)s\xf4\xf4\xf6\x9e\xc9\xf6\xe3\'\x91x\x7f\xfc\xef?\x0fgi\x08\xa6\x80\xfe\xa3Q;\xcc\xf2\xdb\xcdT\x17B-\xc6\xc4\x17\nZ\x05\x8b/\xa1\xe7\xd7\x14\x06&@\xd5Z\x82\xc9a\xbe\xe4\xcf\x8c\xdf\xcdr\xf3L\xdc8\xa4\x00\xb6n\xeeq>\xb0\xfb\xac\x96\x02\xeb\nO\x99_`w\x03\xd2u\x91%\xfb\x08\x1aM\xff\xf8{\xf2\x8f\x7f\x1e\xcd\xd20L\xef\xfd\xc7\xb6f\xb2\xc3\xe0\x0f\xbd\xd3\xddU\x1b\x12ab\x87-\xea\xd9|T\xb7V\xa5;\xcd\xc9\x0f\xf3\xe6w\xbe\xc3\xd6m\xc4\xacn\xb7\xc6D?+\x99\xa7\xb3C\xa2\xaeZ\x91\xed\xa9\r\x7f\xd2X\x9a\xd0h\xba\xa6\xa5\xc1\x98\xbe\xf5\xd9<\xad\x8dz\xefBZ\x99\xb2\xc8\xe9:\x8c\xb4E{{\xbb\xae\xf7v\xe9\xbe\xfa\xe7\xa2\x01\xafgX\xf5\n+\xad\xaa\xba,D\x13\x01\xb4\xb7\x0f\xb3\xf7\xc6e\x1b\xe5})O\xa85\x9f\xdd\xf3\xad1[\xd2\xc6\x946O\xcb\xc1{v\xb7\xd2\xfc\xd6\x90\xf9\x0e\xfb\xe9O\x1aKI4]\xd5R\x1cL?_-\x8b\xd9Yd\xdc\xb7[#\xee\xa7\xb8\xd2I\xde\xdfZ\x1e\xb05c\'X\xb6\xfbv\xfcIc)\x81\xa6\xebZ\x8a\x8c)\x07\x07\xc7\xe1\xe2\'\x8d\xa5\xe8\x9a\xael)c\xca\xc1\xc1\x11Q\xd3\x9e\xa5\xc8\x9a\xaem)c\xca\xc1\xc1\x11O\xd3\x81\xa5\xa8\x9a\xaen)c\xca\xc1\xc1\x11M\xd3\x07K\x115]\xdfR\xc6\x94\x83\x83#\x96\xa6O\x96\xa2i\xba\x01K\x19S\x0e\x0e\x8eH\x9a\x8eX\x8a\xa4\xe9\x16,eL988\xe2h:j)\x8a\xa6\x9b\xb0\x941\xe5\xe0\xe0\x88\xa2\xe9\x84\xa5\x08\x9an\xc3R\xc6\x94\x83\x83#\x86\xa6\x93\x96\x06k\xba\x11K\x19S\x0e\x0e\x8e\x08\x9a\xceX\x1a\xa8\xe9V,eL988\xe85\x9d\xb54H\xd3\xcdX\xca\x98rpp\x90k\xba`i\x80\xa6\xdb\xb1\x941\xe5\xe0\xe0\xa0\xd6t\xd1RoM7d)c\xca\xc1\xc1A\xac)\xc0ROM\xb7d)c\xca\xc1\xc1A\xab)\xc8R/M7e)c\xca\xc1\xc1A\xaa)\xd0R\x0fM\xb7e)c\xca\xc1\xc1A\xa9)\xd8RgM7f)c\xca\xc1\xc1A\xa8\xa9\x83\xa5\x8e\x9an\xcdR\xc6\x94\x83\x83\x83NS\'K\x9d4\xdd\x9c\xa5\x8c)\x07\x07\x07\x99\xa6\x8e\x96:h\xba=K\x19S\x0e\x0e\x0e*M\x9d-\x05k\xbaAK\x19S\x0e\x0e\x0e"M=,\x05j\xbaEK\x19S\x0e\x0e\x0e\x1aM\xbd,\x05i\xbaIK\x19S\x0e\x0e\x0e\x12M=-\x05h\xbaMK\x19S\x0e\x0e\x0e\nM\xbd-]\xd4t\xa3\x962\xa6\x1c\x1c\x1c\x04\x9a\x06X\xba\xa0\xe9V-eL988\xf05\r\xb2tV\xd3\xcdZ\xca\x98rpp\xa0k\x1ah\xe9\x8c\xa6\xdb\xb5\x941\xe5\xe0\xf8\x1dR\\\xebJ\xdd\xa22\xd7<[\xe9\x18lQ\xd6\xe6~\x08\xf5\xb5\xb0r\xaf\x9a\x06[:\xa9\xe9\x86-eL90\xfbP1\xf8\x8f\xcbh\xefQ3\xdd\xcc|\xfcV\xba\xd0!\xd3w}>\x7f$F\x8f\xc9\xf4\xdf\xfb\xf3\x97\x9f\x14+\xcc\xf0\r*1\xe6\xa9\x199\x94W|\xc7\xdc\xfb8S5x\xa7^\x03\xd8\xe1\x1fX\xa3\x1f\x0e\xe2j\xf7\xa8)\x82\xa5\x13\x9a~\xdbI"0\xa6\x1c\xc1}\xc8bazY\xe8\x90\xed\xf3\xcb\xb5\xbd7\x11\x1f?\xd5=\xe6\xec8\xb17\xe0^\xf4\x08\x92/0L\x7f\x9fc\x06\xc4\xf4\xfa<"\xfc>\xba\xd1\x96Q/\x1b\xafO\x7f\xd2X:\xaa\xe9\xb7\xdd$\x02c\xca\x11\xda\x87\x94\x0c\xc2T\x811\xfdx\xc9\xf6\xb3\x8c\x1bG\xaf\xe7{1QB7\x13\xc7\xa428\xa6]\xf7\x02\xc2\xf4\xa5\x1b\xd5?\x91\xd7\xa9\xd7\xfd\xb2\xb3\xda\x14\xc9\xd2\x11M\xbf\xed\'\x11\x18S\x8e\xe0>dbc\x9a\x7f\xfe\xec\x13r\xd9\x8d\x92U\x7f\xfc\xb0\xe9\x1f\xd1\xd7\xe9\xb7)\x1c0}\xd2t\x0cS;1\xf0\xc8\xaa\xdb+\xa6\x0f\x9a\xa2Y\xfa\xa4\xe9\xb7=%\x02c\xca\x11\xdc\x87^B0\xd50\xb5n\xf1}\xc4M;2\xcb\xef\xbff\xa2G~6\xa8\x15\x175\x9d?\xacb\x11\xd3LM\x94\xbd\xd7n\xbf\x98\x0e4E\xb4\xf4A\xd3o\xfbJ\x04\xc6\x94#\xb8\x0f\xd9\x00L;0\xa6f\xe47\xdb\x91\x12\xb4\x7f@\xcd3\xc5\xc3Zq,\xac\x03\xa6Z.a:\xb5\xf9$\xba=c\xda\xd3\x14\xd5\xd2\x81\xa6\xdf\xf6\x96\x08\x8c)Gh\x1f\xfa\xac\xb8\xe2`\xda\x8e\xfcL\x8fm\xfc\xf7\xc4\xeam\xfcgj\xfe\x8d\x06\x93\xf1\xa5\xc3*\x160\x9d\xdc|2\xfb\xc6\xf4CSdK{\x9a~\xdb]"0\xa6\x1c\xc1}\xc8\x04`\xfa\x05\xf4[\x83b\xcf>O\xe8\xed\xf8\xf1\x94cK\xa6\xe5\xa0\xb4,S!\xd2Z\x8dZ\x0c\xc0\xd4\xccc:\xb5\xf9\xd4o\xc2\xaah2\x99e6o\xcd\x8e0\xfd\xad)\xba\xa5\x1f\x9a~\xdba"0\xa6\x1c\xc1}\xe8\n\xc3T\xcd\xbdh\x91~\xc4\xe7\x9c\xbd\xfe\xfc\xe1g\r(\xf5\xd3\xcc\xb9\x1c\x1e\xcf{mY\x8d\xbc\xf3\xe0R\x84\x8f\x99\xb7P\x13sw\xf3\xcc~\xd6\xffe9w\xa6\xcdT\xbd\xdb\xd3\xbf\xff\x1f2\xbf\xe8\xbd`\xfa\xaa)\x81\xa5\xbf5\xfd\xb6\xcbD`L9\x82\xfb\x90\r\xc7\xb4\x17\xa3\xb3\xf3Q\xe0\x8a\xf1\xb2\xf6\xf7\x8f\xe5Xo\xee}9\xe0\xd2w\xec2^\x9a\x9a\xb1\xc9w\x0f\xc9f\xe6L\'7\x9f\xfa\xa78\xacX\x13y\x93z\x1f\x98\xde4%\xb1\xf4U\xd3o;M\x04\xc6\x94#\xb4\x0f\xe9,&\xa6\xc5\xe3\xbeR3>\xf9\xce\xc7^\xa7\xea&\x0eg\xfc?F1\xed\xfd\xd4\xce\x9ci5\xf9\xcd\xa7\xde)>_\xda*\xe4N\xfa\xc1\xbf\xfeN\xf4\xc2\xff\xf8\xbf\xbd&\x02c\xca\x11\xdc\x87\xaa\x98\x98>-\x9a\x16\xe3\x9b\xec\x9f;U\xd9\xd8\xb1gS\xaf\xdaws\x1c\xd3t\xfc\x08\x87g:\xb9\xf94p\xfe\xd6X\xa2\xe1>u\x94D`L9\x82\xfb\xd0\x15\x80\xa9N\x87\xe1\x8bio\xef\xfe\xcb\x83x\x83B\xd0\x8c|U*\x9f\xfa\x82i\xffU\x04\x1c\xd3|\xf4L\xbb\xfb\xedS\xa66\x9f\xc6\x9a\xb0\xaa\xd3\xb5n\xb5\xc2\xe1\x1d\xd2\xc2\x82?Y\x8eeL{W$\xe5\x89\xf3n\xbe7\xa6\xf5\xf0\x17>\x8e\'\x1d\xea5\x86Y:\xfd\xda\xc5X!9\x8ei\xb90\xcd\x9f\xbb\xd8*\x19\xf7\xff\xfe{\xb5\xe0\xb4\xe3\xe08\'\xa6\xbd}\xed\xfb\xb2i,L\x8b\xe1\x04J|L\xfau\x7f\xfao\xc7\xca\xc7\xcb\xe42fo\xe5\xb5\\\xc2T-\xec\xe6/|\xe1?\x99\xfe\xe6@\xc9\x9crp\x9c\x11S\xdb3\xa1\x92\xd10\xcd\x86{E\xf5\xc7\xbb\xb6})\x8b1\xf1\xea\xe9K\xe33(\xa6\xb2\x9c\xd8\xc4\x1a?\xd3|\xf4\x1c\xda\xc9\x056\xc9=\x8c\x83\xe3|\x98\xf6\xaf4\xbaF\xc3tX\x19\xcaO\xb5l\x7f\xa2^\x8f\xad\x8e\x1a\x08\xa6f\xec\xf7\xdb\xf7\xa5\xdeROm-\x8c\x9f\xe95q\xd3Tqq\xca\xc1qBL\xfb\x8b\x7f?\xa2az\xe9\xffF\xfe\t\xeb\xc7\xf5\xfc\xa6\xff\xbe\xed\xe8_\xbaV\xa6\xa3\x91\x010}\xba\x13\xd5\xfbi*\xd0\xd7\xaa888\xce\x81i\xef>\xf2\xda\xc4\xc2tp\xcd{\xd93\xa8\xfe\x84\xb5\x19]\x1d\xbd\x8c_n\x7f\x0f\xeb\x8ei\x99@0\xed\xa6.}\x12\xc6I_\x0e\x0e\x8e#c:\xba\x952\x81\xa9\x19\x86?\xa6\xb2\x7f\x81\xab\xea\xfd\xb2\xf8\xfcK1\x8av1-\xd6\xc2n>`\x9b^u\xf0\xed\xfc\xdf\'\x92\xb7FO\\\xb5\xcb\xc1\xc1q.L\x9f.\x99\'\xbfh?\xe9\x7f\xb9H\xda\xfe\x94[~~7\xaa\x1c\x9d5\xcf\\gZ\x8dm\x19\xcdaZ=.n~^Q{\xbf\xbaPA\'\xee\x8d-\xeajw\xf7\x8d\xe2\xe0\xe0\xc0\xc6t\x04\x1crL?wol;\x00\xcb||\t\xaa\x1a-A\xe5\xe4W<\xf3\xd1\x95\xd0iLu\xfaTo\x0e\xcf4\xd3\xd3\xf7\xe4\x97\xd9s\x8dzY\xba\x00\x80\x83\x83\xe3\xe0\x98J\x15\x1d\xd3\xcf\xb5\x85\xab\x1a\x98\xf9Q&\x17\x8bw{\x1eN\xbe{w%\x99x\xb6\xd4\xecM\xa4\xc7\xceTL_\x1fe\xd5\xc8\x05\xa5\x97\xe5\xf3\xe6\xe0\xe082\xa6O7\x1a\xa1\xc7TN\xed\xf2d3OFI\x1e\x16%\xfa\xd3\xf4\xfe-\xa3\x05\x08\xd3\x91\x85\xd0\xc73m\x9fn\x05\xd3\x1f\x0c\xea\xc7\xfa3\xe5\xca\x94\x83\xe3\xe4\x98>-\x9bN`\x9a=\x87\xf4\xc3\xf4\x199\xf5\xf8ncO,I\x06wC\xedT\xf1\x9b\xb8\xc1\x93\x9f\x07\xd7y\xf6\xee\x0f\xf5z\xbc\xf9\xdc\xf5\xa3O\xc3\x86\x19|\xa7\xe1\xa9\xb2\xd6\xa5\x18\xf7\xdcr\'\xe3\xe08\'\xa6\xc3g0\xb9\xdci\xbf\xf4\xc44\x9dz\xa1\xa7k\xe1\xc5\xec_V\xf5\xb5,\x87\xbb?\x13w\xda\xff\xf2\xf4\xe7?\x161\xed/\x80\\\xc7\x97)T\x9d\nkm.\xaez\xe2\x96\xd3\x1c\x1c\x1c\'\xc2\xf4a\xd9\x14\x8ei\xeb\x89\xa9\x9dZ\xc2\xb4K\x17y\xca\xa5g@%\xb3\x98\xf6~\xa2\xb3%L\x93F\x8f_=jaOb\xe5\xe0\xe08\x1b\xa6\x035\\0M=1M\xf4\x14\x81z\xce\xc6\xd7\xc3\xd7\xb3\x0f\x1c\xcd\x160\xed\xfdy%\x970\x1d,\x804PL\xf9\xfe\xa6\x1c\x1c\xe7\xc5t\xb8l\x1a\x01S3\xb5\\pY\\Ghf4\xd5M\xb2\x80i\xffL\xaf\x8b\x98\xf6\x97\x1dz[V\xd6\xb5Z\xe7\xe0\xe08\x0b\xa6\x03\xc4\xe0\x98\x16\xbe\x98\x16S\xb7f\x12\xf3K\xa6\xaf\x9a*\xa8\xa5\xa37F\xa9\xa7\xaex\x1a\xbdn\xa1\x1a\xbbv\x7f\x0eS\xfe\xfe\x13\x07\xc7\xb91\xed\xafE\xc21\x15\xbe\x986\xe3\x0f$\x1dn\xd7??\x9c\xe4\xf7\x19L\\\xf1d\xb2\x04\x80\xa9T\x13\x8b\x02\xa3\x98fc\x9bP\x99\xe2\xba\x94\x83\x83c\x1c\xd3\xfebb\x04L\x87k\xa3fj\x01`\xaa\xcc\x1b\xbbeS\x95\xcf\xad&\xf4\xbe\xe2i\'\xbe(:~E\xad\x1d-\xa0\xede\xb4]\x0c_\x15\xc5\xc1q"L?nU2\x9c\x14\x17\x1f?\x1fL\xdek3\x13c{-\xf9\xc7\xff\xce\xc9\x92\xf6_\xa6\xcf\xa0\xe8\xff\xc7\xe4\x83\xa6\x1e5\xd3\xe5\xe8\x9b\xb5\x1f\xaf$\xc7\xdf;\x1f;\xd3r\xa2]L=8\x82\xf4\xe1&\'\xbaeJ988v\x18M\x9e\x96\xaf\xf6\xb5\xab= \xb4\xb1EZ\xde\xa3-\x82\x9f\xa8\xf7\xff\x06q\xf9-\xe3\xdf\xe6\x1c\x00\x00\x00\x00IEND\xaeB`\x82'
CASE_NO_PADDING = (PALO_LOGO_BASE64, PALO_LOGO_DECODED)
CASE_LESS_PADDING = (PALO_LOGO_BASE64 + '=', PALO_LOGO_DECODED)
CASE_WITH_PADDING = (PALO_LOGO_BASE64 + '==', PALO_LOGO_DECODED)
CASE_TOO_MUCH_PADDING = (PALO_LOGO_BASE64 + '===', PALO_LOGO_DECODED)


@pytest.mark.parametrize('str_to_decode, expected_encoded', (CASE_NO_PADDING, CASE_WITH_PADDING, CASE_LESS_PADDING, CASE_TOO_MUCH_PADDING))
def test_base_64_decode(str_to_decode, expected_encoded):
    from EWSv2 import base_64_decode

    encoded = base_64_decode(str_to_decode)
    assert encoded == expected_encoded


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


def test_parse_incident_from_item():
    """
    Given -
        a Message with attachments contains non-ASCII characters.

    When -
        running the parse_incident_from_item function.

    Then -
        verify that the attachments were parsed correctly.
    """
    from EWSv2 import parse_incident_from_item
    from exchangelib.attachments import AttachmentId, ItemAttachment

    message = Message(subject='message4',
                      message_id='message4',
                      text_body='Hello World',
                      body='message4',
                      datetime_received=EWSDateTime(2021, 7, 14, 13, 10, 00, tzinfo=EWSTimeZone('UTC')),
                      datetime_sent=EWSDateTime(2021, 7, 14, 13, 9, 00, tzinfo=EWSTimeZone('UTC')),
                      datetime_created=EWSDateTime(2021, 7, 14, 13, 11, 00, tzinfo=EWSTimeZone('UTC')),
                      id='message4',
                      attachments=[
                          ItemAttachment(
                              item=Item(mime_content=b'\x80\x81\x82'),
                              attachment_id=AttachmentId(),
                              last_modified_time=EWSDate(year=2021, month=1, day=25),
                          ),
                      ],
                      )

    return_value = parse_incident_from_item(message, is_fetch=False)
    assert return_value.get("attachment")


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
        a Message where effective rights is None and other fields are false/empty strings.

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


def test_resolve_names_command_no_contact(mocker):
    """
        Given:
            Calling resolve_name_command
        When:
            Only a Mailbox is returned
        Then:
            The results are displayed correctly without FullContactInfo
    """
    from EWSv2 import resolve_name_command
    protocol = mocker.Mock()
    email = '1234@demisto.com'
    protocol.resolve_names.return_value = [Mailbox(email_address=email)]
    result = resolve_name_command({'identifier': 'someIdentifier'}, protocol)
    assert email in result.get('HumanReadable')
    assert email == list(result.get('EntryContext').values())[0][0].get('email_address')
    assert not list(result.get('EntryContext').values())[0][0].get('FullContactInfo')


def test_resolve_names_command_with_contact(mocker):
    """
        Given:
            Calling resolve_name_command
        When:
            A Mailbox, Contact tuple is returned
        Then:
            The results are displayed correctly with FullContactInfo
    """
    from EWSv2 import resolve_name_command
    protocol = mocker.Mock()
    email = '1234@demisto.com'
    number_label = 'Bussiness2'
    phone_numbers = [PhoneNumber(label=number_label, phone_number='+972 058 000 0000'),
                     PhoneNumber(label='Bussiness', phone_number='+972 058 000 0000')]
    protocol.resolve_names.return_value = [(Mailbox(email_address=email), Contact(phone_numbers=phone_numbers))]
    result = resolve_name_command({'identifier': 'someIdentifier'}, protocol)
    assert email in result.get('HumanReadable')
    context_output = list(result.get('EntryContext').values())[0][0]
    assert email == context_output.get('email_address')

    assert any(number.get('label') == number_label for number in context_output.get('FullContactInfo').get('phoneNumbers'))


def test_resolve_names_command_no_result(mocker):
    """
        Given:
            Calling resolve_name_command
        When:
            ErrorNameResolutionNoResults is returned
        Then:
            A human readable string is returned
    """
    from EWSv2 import resolve_name_command
    protocol = mocker.Mock()
    protocol.resolve_names.return_value = [ErrorNameResolutionNoResults(value='No results')]
    result = resolve_name_command({'identifier': 'someIdentifier'}, protocol)
    assert result == 'No results were found.'


def test_parse_phone_number():
    """
        Given: A filled phone number and a Phonenumber with no backing number
        When: Calling parse_phone_number
        Then: Only get the context object when the phpone_number is populated
    """
    good_number = EWSv2.parse_phone_number(PhoneNumber(label='123', phone_number='123123123'))
    assert good_number.get('label')
    assert good_number.get('phone_number')
    assert not EWSv2.parse_phone_number(PhoneNumber(label='123'))


def test_switch_hr_headers():
    """
           Given: A context object
           When: switching headers using a given header switch dict
           Then: The keys that are present are switched
       """
    assert (EWSv2.switch_hr_headers(
        {'willswitch': '1234', 'wontswitch': '111', 'alsoswitch': 5555},
        {'willswitch': 'newkey', 'alsoswitch': 'annothernewkey', 'doesnt_exiest': 'doesnt break'})
        == {'annothernewkey': 5555, 'newkey': '1234', 'wontswitch': '111'})


@pytest.mark.parametrize('input, output', [
    ('John Smith', 'John Smith'),
    ('SomeName', 'SomeName'),
    ('sip:test@test.com', 'sip:test@test.com'),
    ('hello@test.com', 'smtp:hello@test.com')
])
def test_format_identifier(input, output):
    """
           Given: several inputs with and without prefixes, that are or arent mails
           When: calling format_identifier
           Then: Only mails without a prefix have smtp appended
       """
    assert EWSv2.format_identifier(input) == output


def test_get_message_for_body_type_no_body_type_with_html_body():
    body = "This is a plain text body"
    html_body = "<p>This is an HTML body</p>"
    result = get_message_for_body_type(body, None, html_body)
    assert isinstance(result[0], HTMLBody)
    assert result[0] == HTMLBody(html_body)


def test_get_message_for_body_type_no_body_type_with_html_body_and_image(mocker):
    from exchangelib import FileAttachment
    mocker.patch.object(uuid, 'uuid4', return_value='123456')
    body = "This is a plain text body"
    html_body = '<p>This is an HTML body</p><p><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA"/></p>'
    result = get_message_for_body_type(body, None, html_body)
    assert isinstance(result[0], HTMLBody)
    assert isinstance(result[1][0], FileAttachment)
    assert result[0] == HTMLBody('<p>This is an HTML body</p><p><img src="cid:image0_123456_123456"/></p>')


def test_get_message_for_body_type_no_body_type_with_no_html_body():
    body = "This is a plain text body"
    result = get_message_for_body_type(body, None, None)
    assert isinstance(result[0], Body)
    assert result[0] == Body(body)


def test_get_message_for_body_type_html_body_type_with_html_body():
    body = "This is a plain text body"
    html_body = "<p>This is an HTML body</p>"
    result = get_message_for_body_type(body, 'html', html_body)
    assert isinstance(result[0], HTMLBody)
    assert result[0] == HTMLBody(html_body)


def test_get_message_for_body_type_text_body_type_with_html_body():
    body = "This is a plain text body"
    html_body = "<p>This is an HTML body</p>"
    result = get_message_for_body_type(body, 'text', html_body)
    assert isinstance(result[0], Body)
    assert result[0] == Body(body)


def test_get_message_for_body_type_html_body_type_with_no_html_body():
    body = "This is a plain text body"
    result = get_message_for_body_type(body, 'html', None)
    assert isinstance(result[0], Body)
    assert result[0] == Body(body)


def test_get_message_for_body_type_text_body_type_with_no_html_body():
    body = "This is a plain text body"
    result = get_message_for_body_type(body, 'text', None)
    assert isinstance(result[0], Body)
    assert result[0] == Body(body)


def test_get_message_for_body_type_text_body_type_with_html_body_no_body():
    """
    Given: html_body, no body, the default 'text' as body_type.
    When: Constructing the message body.
    Then: Assert that the result is an html body.
    """
    html_body = "<p>This is an HTML body</p>"
    result = get_message_for_body_type('', 'text', html_body)
    assert isinstance(result[0], HTMLBody)
    assert result[0] == HTMLBody(html_body)


def test_parse_physical_address():
    assert parse_physical_address(PhysicalAddress(city='New York',
                                                  country='USA',
                                                  label='SomeLabel',
                                                  state='NY',
                                                  street='Broadway Ave.',
                                                  zipcode=10001)) == {'city': 'New York',
                                                                      'country': 'USA',
                                                                      'label': 'SomeLabel',
                                                                      'state': 'NY',
                                                                      'street': 'Broadway Ave.',
                                                                      'zipcode': 10001}


def test_parse_item_as_dict_return_json_serializable():
    """
    Given:
        - A message with cc_recipients with an object that includes a non-serializable object (ItemId).
    When:
        - Calling parse_item_as_dict

    Then:
        - Verify that the received dict is json serializable,
        and that the ItemId appears both in the received dict and the json serialized object.
    """
    item = Message(cc_recipients=[Mailbox(item_id=ItemId(id='id123', changekey='change'))])
    item_as_dict = parse_item_as_dict(item, None)
    item_as_json = json.dumps(item_as_dict, ensure_ascii=False)
    assert isinstance((item_as_dict.get("cc_recipients", [])[0]).get("item_id"), dict)
    assert '"item_id": {"id": "id123", "changekey": "change"}' in item_as_json


@pytest.mark.parametrize("attachment_name, content_id, is_inline, attachment_subject, expected_result", [
    pytest.param('image1.png', "", False, None, "image1.png"),
    pytest.param('image1.png', '123', True, None, "123-attachmentName-image1.png"),
    pytest.param('image1.png', None, False, None, "image1.png"),
    pytest.param(None, None, False, "Re: test", "Re: test"),

])
def test_get_attachment_name(attachment_name, content_id, is_inline, attachment_subject, expected_result):
    """
    Given:
        - case 1: attachment is not inline.
        - case 2: attachment is inline.
        - case 3: attachment is not inline.
        - case 4: attachment with no name, only subject.
    When:
        - get_attachment_name is called with LEGACY_NAME=FALSE
    Then:
        Only case 2 should add an ID to the attachment name.

    """
    assert get_attachment_name(attachment_name=attachment_name, content_id=content_id,
                               is_inline=is_inline, attachment_subject=attachment_subject) == expected_result


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
    monkeypatch.setattr('EWSv2.LEGACY_NAME', True)
    assert get_attachment_name(attachment_name=attachment_name, content_id=content_id,
                               is_inline=is_inline) == expected_result


def test_parse_mime_content_with_quoted_printable():
    """
    Given:
        - A MIME item with quoted-printable encoded subject and UTF-8 encoded body.

    When:
        - The MIME item is cast to a message object.

    Then:
        - The subject should be correctly decoded.
        - The body of the email should be correctly parsed.
    """

    from EWSv2 import cast_mime_item_to_message

    class MockMimeItem:
        mime_content: str = ''

        def __init__(self, message: str):
            self.mime_content = message

    mime_content = "Subject: =?UTF-8?Q?Prueba_de_correo?=\n\nEste es un correo de prueba."
    mime_item = cast_mime_item_to_message(MockMimeItem(mime_content))
    expected_subject = "Prueba de correo"
    expected_body = "Este es un correo de prueba."

    assert mime_item['Subject'] == expected_subject, f"Expected subject '{expected_subject}', got '{mime_item['Subject']}'"
    assert mime_item.get_payload() == expected_body, f"Expected body '{expected_body}', got '{mime_item.get_payload()}'"


def test_get_item_as_eml(mocker):
    """
    Given
        - A quoted-printable encoded email returns.
    When
        - The "ews-get-items-as-eml" command is called.
    Then
        - The output contains the expected file name and content
    """
    from EWSv2 import get_item_as_eml
    from exchangelib.properties import MessageHeader
    from exchangelib.items import Item

    content = b'MIME-Version: 1.0\n' \
              b'Message-ID:\r\n' \
              b' <message-test-idRANDOMVALUES@testing.com>\r\n' \
              b'Content-Type: text/plain; charset="iso-8859-2"\r\n' \
              b'Content-Transfer-Encoding: quoted-printable\r\n' \
              b'X-FAKE-Header: HVALue\r\n' \
              b'X-Who-header: whovALUE\n' \
              b'DATE: 2023-12-16T12:04:45\r\n' \
              b'\r\nHello'

    item_headers = [
        MessageHeader(name="Mime-Version", value="1.0"),
        MessageHeader(name="Content-Type", value='application/ms-tnef'),
        MessageHeader(name="X-Fake-Header", value="HVALue"),
        MessageHeader(name="X-WHO-header", value="whovALUE"),
        # this is a header whose value is different. The field is limited to 1 by RFC
        MessageHeader(name="Date", value="2023-12-16 12:04:45"),
        MessageHeader(name="X-EXTRA-Missed-Header", value="EXTRA")
    ]
    expected_data = 'MIME-Version: 1.0\r\n' \
                    'Message-ID: \r\n' \
                    ' <message-test-idRANDOMVALUES@testing.com>\r\n' \
                    'Content-Type: text/plain; charset="iso-8859-2"\r\n' \
                    'Content-Transfer-Encoding: quoted-printable\r\n' \
                    'X-FAKE-Header: HVALue\r\n' \
                    'X-Who-header: whovALUE\r\n' \
                    'DATE: 2023-12-16T12:04:45\r\n' \
                    'X-EXTRA-Missed-Header: EXTRA\r\n' \
                    '\r\nHello'
    mock_file_result = mocker.patch('EWSv2.fileResult')
    mocker.patch.object(EWSv2, 'get_item_from_mailbox', return_value=Item(mime_content=content, headers=item_headers))
    mocker.patch.object(EWSv2, 'Account', return_value=MockAccount(primary_smtp_address="test@gmail.com"))

    get_item_as_eml("Inbox", "test@gmail.com")
    mock_file_result.assert_called_once_with("demisto_untitled_eml.eml", expected_data)
