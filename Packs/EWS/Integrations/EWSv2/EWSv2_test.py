import datetime

import EWSv2
import logging

import dateparser
import pytest
from exchangelib import Message
from EWSv2 import fetch_last_emails

from exchangelib import EWSDateTime


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
    mocker.patch.object(dateparser, 'parse', return_value=datetime.datetime(2021, 5, 23, 13, 18, 14, 901293))
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
