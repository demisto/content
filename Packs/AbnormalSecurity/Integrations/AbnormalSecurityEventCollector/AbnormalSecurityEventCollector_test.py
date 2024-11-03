from AbnormalSecurityEventCollector import get_events
from CommonServerPython import *
from freezegun import freeze_time


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


class Client(BaseClient):
    def list_threats(self, params):
        return util_load_json('test_data/test_get_list_threats.json')

    def get_threat(self, threat):
        return util_load_json('test_data/test_get_threat.json').get(threat)


"""
    Command Unit Tests
"""


@freeze_time("2022-09-14")
def test_get_events():
    """
        When:
            - running the get_events function
        Then
            - Assert the returned messages contains only messages in the specific time range (.
            - Assert the returned messages are ordered by datetime.
            - Assert the returned "toAddresses" field in the messages returned as a list.

    """
    client = Client(base_url="url")
    messages, last_run = get_events(client, after='2022-05-02T18:44:38Z')

    assert messages == [{'abxMessageId': 3,
                         'receivedTime': '2022-06-01T18:44:38Z',
                         'threatId': '123456789-1',
                         "toAddresses": []},
                        {'abxMessageId': 3,
                         'receivedTime': '2022-06-02T18:44:38Z',
                         'threatId': '123456789-2'},
                        {'abxMessageId': 3,
                         'receivedTime': '2022-06-03T18:44:38Z',
                         'threatId': '123456789-3'},
                        {'abxMessageId': 2,
                         'receivedTime': '2022-08-01T18:44:38Z',
                         'threatId': '123456789-1',
                         "toAddresses": ["test1", "test2"]},
                        {'abxMessageId': 2,
                         'receivedTime': '2022-08-02T18:44:38Z',
                         'threatId': '123456789-2',
                         "toAddresses": ["test1", "test2"]},
                        {'abxMessageId': 2,
                         'receivedTime': '2022-08-03T18:44:38Z',
                         'threatId': '123456789-3'}]
