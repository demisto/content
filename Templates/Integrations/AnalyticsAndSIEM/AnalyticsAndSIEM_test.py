""" HELPER FUNCTIONS """
from pytest import raises
from AnalyticsAndSIEM import Client

CONTEXT_PREFIX = 'AnalyticsAndSIEM.Event(val.ID && val.ID === obj.ID)'
BASE_URL = 'http://api.service.com/v1/'


def event_dict_input(*args, **kwargs):
    return {'event': {'eventId': 'ab123',
                      'description': 'Phishing email',
                      'createdAt': '2010-01-01T00:00:00Z',
                      'isActive': True,
                      'assignee': [{'name': 'DBot Demisto', 'id': '11'},
                                   {'name': 'Demisto DBot', 'id': '12'}]}}


def event_dict_output(*args, **kwargs):
    return {'Event': {'Assignee': [{'ID': '11', 'Name': 'DBot Demisto'},
                                   {'ID': '12', 'Name': 'Demisto DBot'}],
                      'Created': '2010-01-01T00:00:00Z',
                      'Description': 'Phishing email',
                      'ID': 'ab123',
                      'IsActive': True}}


def event_list_input(*args, **kwargs):
    return {'event': [{'eventId': 'ab123',
                       'description': 'Phishing email',
                       'createdAt': '2010-01-01T00:00:00Z',
                       'isActive': True,
                       'assignee': [{'name': 'DBot Demisto', 'id': '11'},
                                    {'name': 'Demisto DBot', 'id': '12'}]},
                      {'eventId': 'ab123',
                       'description': 'Phishing email',
                       'createdAt': '2010-01-01T00:00:00Z',
                       'isActive': True,
                       'assignee': [{'name': 'DBot Demisto', 'id': '11'},
                                    {'name': 'Demisto DBot', 'id': '12'}]}]}


def event_list_output(*args, **kwargs):
    return {'Event': [{'Assignee': [{'ID': '11', 'Name': 'DBot Demisto'},
                                    {'ID': '12', 'Name': 'Demisto DBot'}],
                       'Created': '2010-01-01T00:00:00Z',
                       'Description': 'Phishing email',
                       'ID': 'ab123',
                       'IsActive': True},
                      {'Assignee': [{'ID': '11', 'Name': 'DBot Demisto'},
                                    {'ID': '12', 'Name': 'Demisto DBot'}],
                       'Created': '2010-01-01T00:00:00Z',
                       'Description': 'Phishing email',
                       'ID': 'ab123',
                       'IsActive': True}]}


def mock_client() -> Client:
    return Client(
        'Analytics And SIEM',
        'analytics-and-siem',
        'AnalyticsAndSIEM',
        BASE_URL,
        '/',
        False,
        False
    )


""" TESTS FUNCTION """


class TestBuildContext:
    def test_build_context_dict(self):
        from AnalyticsAndSIEM import build_context
        res = build_context(event_dict_input()['event'])
        assert res == event_dict_output()['Event']

    def test_build_context_list(self):
        from AnalyticsAndSIEM import build_context
        res = build_context(event_list_input()['event'])
        assert res == event_list_output()['Event']


class TestTestModule:
    client = mock_client()

    def test_test_module(self, requests_mock):
        from AnalyticsAndSIEM import test_module
        requests_mock.get(BASE_URL + 'version', json={'version': '1.0.0'})
        assert test_module(self.client) == ('ok', {}, {})

    def test_test_module_negative(self, requests_mock):
        from AnalyticsAndSIEM import test_module, DemistoException
        requests_mock.get(BASE_URL + 'version', json={})
        with raises(DemistoException, match='Test module failed'):
            test_module(self.client)


class TestListEvents:
    client = mock_client()

    def test_list_events(self, requests_mock):
        from AnalyticsAndSIEM import list_events
        requests_mock.get(BASE_URL + 'event', json=event_list_input())
        _, context, _ = list_events(self.client, dict())
        context = context['AnalyticsAndSIEM.Event(val.ID && val.ID === obj.ID)']
        assert context == event_list_output()['Event']
