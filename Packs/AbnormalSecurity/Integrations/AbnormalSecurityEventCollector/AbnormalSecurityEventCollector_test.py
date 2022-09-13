import pytest
import demistomock as demisto
import io
from AbnormalSecurityEventCollector import get_threats
from CommonServerPython import *
from Packs.AbnormalSecurity.Integrations.AbnormalSecurityEventCollector.AbnormalSecurityEventCollector import Client


class MockResponse:
    def __init__(self, data, status_code):
        self.data = data
        self.text = str(data)
        self.status_code = status_code


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


class Client(BaseClient):
    def get_threats(self, params):
        return util_load_json('test_data/test_get_list_threats.json')

    def get_threat(self, threat):
        return util_load_json('test_data/test_get_threat.json').get(threat)

"""
    Command Unit Tests
"""


def test_get_a_list_of_threats_command():
    """
        When:
            - Retrieving list of cases identified
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = Client(base_url="url")
    messages, last_run = get_threats(client, '2022-04-02T18:44:38Z')

    assert messages == [{'abxMessageId': 3,
                         'receivedTime': '2022-06-01T18:44:38Z',
                         'threatId': '123456789-1'},
                        {'abxMessageId': 3,
                         'receivedTime': '2022-06-02T18:44:38Z',
                         'threatId': '123456789-2'},
                        {'abxMessageId': 3,
                         'receivedTime': '2022-06-03T18:44:38Z',
                         'threatId': '123456789-3'},
                        {'abxMessageId': 2,
                         'receivedTime': '2022-08-01T18:44:38Z',
                         'threatId': '123456789-1'},
                        {'abxMessageId': 2,
                         'receivedTime': '2022-08-02T18:44:38Z',
                         'threatId': '123456789-2'},
                        {'abxMessageId': 2,
                         'receivedTime': '2022-08-03T18:44:38Z',
                         'threatId': '123456789-3'}]
