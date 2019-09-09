""" HELPER FUNCTIONS """
from pytest import raises
from AnalyticsAndSIEM import Client

CONTEXT_PREFIX = 'AnalyticsAndSIEM.Event(val.ID && val.ID === obj.ID)'


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
        'http://api.service.com',
        'v1',
        'Analytics And SIEM',
        'analytics-and-siem',
        'AnalyticsAndSIEM',
        False,
        False
    )


def raise_exception(*args, **kwargs):
    from AnalyticsAndSIEM import DemistoException
    raise DemistoException('error')


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
    def test_test_module(self, monkeypatch):
        from AnalyticsAndSIEM import test_module
        client = mock_client()
        monkeypatch.setattr(client, 'test_module_request', lambda: {'version': '1.0.0'})
        assert test_module(client)

    def test_test_module_negative(self, monkeypatch):
        from AnalyticsAndSIEM import test_module, DemistoException
        client = mock_client()
        monkeypatch.setattr(client, '_http_request', raise_exception)
        with raises(DemistoException) as e:
            test_module(client)
            assert str(e) == 'error'


class TestListEvents:
    def test_list_events(self, monkeypatch):
        from AnalyticsAndSIEM import list_events
        client = mock_client()
        monkeypatch.setattr(client, 'list_events_request', event_list_input)
        _, context, _ = list_events(client, dict())
        context = context['AnalyticsAndSIEM.Event(val.ID && val.ID === obj.ID)']
        assert context == event_list_output()['Event']
