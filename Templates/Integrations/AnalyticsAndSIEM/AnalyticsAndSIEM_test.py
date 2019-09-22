""" HELPER FUNCTIONS """
from pytest import raises
from AnalyticsAndSIEM import Client
from CommonServerPython import DemistoException

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
    return Client(BASE_URL)


""" TESTS FUNCTION """


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


class TestBuildContext:
    def test_build_context_dict(self):
        from AnalyticsAndSIEM import build_context
        res = build_context(event_dict_input()['event'])
        assert res == event_dict_output()['Event']

    def test_build_context_list(self):
        from AnalyticsAndSIEM import build_context
        res = build_context(event_list_input()['event'])
        assert res == event_list_output()['Event']


class TestEvents:
    client = mock_client()

    def test_list_events(self, requests_mock):
        from AnalyticsAndSIEM import list_events
        requests_mock.get(BASE_URL + 'event', json=event_list_input())
        _, context, _ = list_events(self.client, dict())
        context = context[CONTEXT_PREFIX]
        assert context == event_list_output()['Event']

    def test_list_events_empty(self, requests_mock):
        from AnalyticsAndSIEM import list_events
        requests_mock.get(BASE_URL + 'event', json={'event': []})
        human_readable, context, _ = list_events(self.client, {})
        assert 'Could not find any events' in human_readable
        assert isinstance(context, dict)
        assert not context  # Context is empty

    def test_get_event(self, requests_mock):
        from AnalyticsAndSIEM import get_event
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': True, 'assignee': [{'name': 'user1', 'id': '142'}]}]}
        requests_mock.get(BASE_URL + 'event', json=request_json)
        human_readable, context, _ = get_event(self.client, {'event_id': '111'})
        assert 'Event `111`' in human_readable
        assert context[CONTEXT_PREFIX]  # Context is not empty

    def test_get_event_empty(self, requests_mock):
        from AnalyticsAndSIEM import get_event
        requests_mock.get(BASE_URL + 'event', json={})
        human_readable, context, _ = get_event(self.client, {'event_id': '111'})
        assert 'not find' in human_readable
        assert isinstance(context, dict) and not context  # Context is empty

    def test_close_event(self, requests_mock):
        from AnalyticsAndSIEM import close_event
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': False, 'assignee': [{'name': 'user1', 'id': '142'}]}]}
        requests_mock.delete(BASE_URL + 'event', json=request_json)
        human_readable, context, _ = close_event(self.client, {'event_id': '111'})
        assert 'Event `111`' in human_readable
        assert context[CONTEXT_PREFIX]  # Context is not empty

    def test_close_event_fail(self, requests_mock):
        from AnalyticsAndSIEM import close_event
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': True, 'assignee': [{'name': 'user1', 'id': '142'}]}]}
        requests_mock.delete(BASE_URL + 'event', json=request_json)
        with raises(DemistoException, match='Could not delete event `111`'):
            close_event(self.client, {'event_id': '111'})

    def test_update_event(self, requests_mock):
        from AnalyticsAndSIEM import update_event
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': False, 'assignee': [{'name': 'user1', 'id': '142'}]}]}
        requests_mock.post(BASE_URL + 'event', json=request_json)
        human_readable, context, _ = update_event(self.client, {'event_id': '111'})
        assert 'Event `111` has been updated.' in human_readable
        assert context[CONTEXT_PREFIX]  # Context is not empty

    def test_update_event_fail(self, requests_mock):
        from AnalyticsAndSIEM import update_event
        requests_mock.post(BASE_URL + 'event', json={'event': []})
        with raises(DemistoException, match='Could not update event `111`'):
            update_event(self.client, {'event_id': '111', 'assignee': '142,143'})

    def test_create_event(self, requests_mock):
        from AnalyticsAndSIEM import create_event
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': False,
            'assignee': [
                {'name': 'user1', 'id': '123'},
                {'name': 'user2', 'id': '124'}
            ]}]}
        requests_mock.post(BASE_URL + 'event', json=request_json)
        human_readable, context, raw_response = create_event(self.client,
                                                             {'description': 'Test event', 'assignee': '123,124'}
                                                             )
        assert 'Event `111` has been created' in human_readable
        assert len(context[CONTEXT_PREFIX]['Assignee']) == 2  # Context is not empty

    def test_create_event_fail(self, requests_mock):
        from AnalyticsAndSIEM import create_event
        requests_mock.post(BASE_URL + 'event', json={'event': []})
        with raises(DemistoException, match='Could not update event `111`'):
            create_event(self.client, {'event_id': '111', 'assignee': '142,143'})

    def test_query(self, requests_mock):
        from AnalyticsAndSIEM import query
        event__to_query = {'events': [
            {'eventId': '1', 'assignee': [{'id': 123}]}
        ]
                           }
        requests_mock.get(BASE_URL + 'query', json={'event': []})
        query(self.client, {
            'event_id': '1,2,3',
            'assignee': '123'
        })
