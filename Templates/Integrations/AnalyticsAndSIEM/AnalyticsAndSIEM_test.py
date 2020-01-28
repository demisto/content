from CommonServerPython import *

from pytest import raises
from AnalyticsAndSIEM import Client

CONTEXT_PREFIX = 'AnalyticsAndSIEM.Event(val.ID && val.ID === obj.ID)'
BASE_URL = 'http://api.example.com/v1/'

EVENT_LIST_INPUT = {'event': [{'eventId': 'ab123',
                               'description': 'Phishing email',
                               'createdAt': '2010-01-01T00:00:00',
                               'isActive': True,
                               'assignee': [{'name': 'DBot Demisto', 'id': '11'},
                                            {'name': 'Demisto DBot', 'id': '12'}]},
                              {'eventId': 'ab123',
                               'description': 'Phishing email',
                               'createdAt': '2010-02-01T00:00:00',
                               'isActive': True,
                               'assignee': [{'name': 'DBot Demisto', 'id': '11'},
                                            {'name': 'Demisto DBot', 'id': '12'}]}]}

EVENT_LIST_OUTPUT = {'Event': [{'Assignee': [{'ID': '11', 'Name': 'DBot Demisto'},
                                             {'ID': '12', 'Name': 'Demisto DBot'}],
                                'Created': '2010-01-01T00:00:00',
                                'Description': 'Phishing email',
                                'ID': 'ab123',
                                'IsActive': True},
                               {'Assignee': [{'ID': '11', 'Name': 'DBot Demisto'},
                                             {'ID': '12', 'Name': 'Demisto DBot'}],
                                'Created': '2010-02-01T00:00:00',
                                'Description': 'Phishing email',
                                'ID': 'ab123',
                                'IsActive': True}]}

client = Client(BASE_URL)

""" TESTS FUNCTION """


class TestBuildContext:
    def test_raw_response_to_context_dict(self):
        from AnalyticsAndSIEM import raw_response_to_context
        res = raw_response_to_context(EVENT_LIST_INPUT['event'][0])
        assert res == EVENT_LIST_OUTPUT['Event'][0]

    def test_raw_response_to_context_list(self):
        from AnalyticsAndSIEM import raw_response_to_context
        res = raw_response_to_context(EVENT_LIST_INPUT['event'])
        assert res == EVENT_LIST_OUTPUT['Event']


class TestTestModule:
    def test_test_module(self, requests_mock):
        from AnalyticsAndSIEM import test_module_command
        requests_mock.get(BASE_URL + 'version', json={'version': '1.0.0'})
        assert test_module_command(client) == ('ok', None, None)

    def test_test_module_negative(self, requests_mock):
        from AnalyticsAndSIEM import test_module_command, DemistoException
        requests_mock.get(BASE_URL + 'version', json={})
        with raises(DemistoException, match='Test module failed'):
            test_module_command(client)


class TestFetchIncidends:
    time_format = '%Y-%m-%dT%H:%M:%SZ'
    last_fetch = '2010-01-01T00:00:00Z'
    new_last_fetch = '2010-02-01T00:00:00Z'

    def test_fetch_incidents(self, requests_mock):
        from AnalyticsAndSIEM import fetch_incidents_command
        requests_mock.get(BASE_URL + 'event?sinceTime=2010-01-01+00%3A00%3A00', json=EVENT_LIST_INPUT)
        incidents, last_run = fetch_incidents_command(client, fetch_time='3 days', last_run=self.last_fetch)
        assert len(incidents) == 2
        assert last_run == self.new_last_fetch

    def test_fetch_incidents_first_time(self, requests_mock, mocker):
        from AnalyticsAndSIEM import fetch_incidents_command
        requests_mock.get(BASE_URL + 'event?sinceTime=2010-01-01+00%3A00%3A00', json=EVENT_LIST_INPUT)
        mocker.patch('AnalyticsAndSIEM.parse_date_range',
                     return_value=(datetime.strptime(self.last_fetch, self.time_format), None)
                     )
        incidents, last_run = fetch_incidents_command(client, fetch_time='3 days')
        assert len(incidents) == 2
        assert last_run == self.new_last_fetch

    def test_fetch_incidents_empty(self, requests_mock):
        from AnalyticsAndSIEM import fetch_incidents_command
        requests_mock.get(BASE_URL + 'event?sinceTime=2010-01-01+00%3A00%3A00', json={'event': []})
        incidents, last_run = fetch_incidents_command(client, fetch_time='3 days', last_run=self.last_fetch)
        assert not incidents
        assert last_run == self.last_fetch


class TestEvents:
    def test_list_events(self, requests_mock):
        from AnalyticsAndSIEM import list_events_command
        requests_mock.get(BASE_URL + 'event', json=EVENT_LIST_INPUT)
        _, context, _ = list_events_command(client, dict())
        context = context[CONTEXT_PREFIX]
        assert context == EVENT_LIST_OUTPUT['Event']

    def test_list_events_empty(self, requests_mock):
        from AnalyticsAndSIEM import list_events_command
        requests_mock.get(BASE_URL + 'event', json={'event': []})
        human_readable, context, _ = list_events_command(client, {})
        assert 'Could not find any events' in human_readable
        assert isinstance(context, dict)
        assert not context  # Context is empty

    def test_get_event(self, requests_mock):
        from AnalyticsAndSIEM import get_event_command
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': True, 'assignee': [{'name': 'user1', 'id': '142'}]}]}
        requests_mock.get(BASE_URL + 'event', json=request_json)
        human_readable, context, _ = get_event_command(client, {'event_id': '111'})
        assert 'Event `111`' in human_readable
        assert context[CONTEXT_PREFIX]  # Context is not empty

    def test_get_event_empty(self, requests_mock):
        from AnalyticsAndSIEM import get_event_command
        requests_mock.get(BASE_URL + 'event?eventId=111', json={})
        human_readable, context, _ = get_event_command(client, {'event_id': '111'})
        assert 'not find' in human_readable
        assert isinstance(context, dict) and not context  # Context is empty

    def test_close_event(self, requests_mock):
        from AnalyticsAndSIEM import close_event_command
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': False, 'assignee': [{'name': 'user1', 'id': '142'}]}]}
        requests_mock.delete(BASE_URL + 'event', json=request_json)
        human_readable, context, _ = close_event_command(client, {'event_id': '111'})
        assert 'Event `111`' in human_readable
        assert context[CONTEXT_PREFIX]  # Context is not empty

    def test_close_event_fail(self, requests_mock):
        from AnalyticsAndSIEM import close_event_command
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': True, 'assignee': [{'name': 'user1', 'id': '142'}]}]}
        requests_mock.delete(BASE_URL + 'event', json=request_json)
        with raises(DemistoException, match='Could not close event `111`'):
            close_event_command(client, {'event_id': '111'})

    def test_update_event(self, requests_mock):
        from AnalyticsAndSIEM import update_event_command
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': False, 'assignee': [{'name': 'user1', 'id': '142'}]}]}
        requests_mock.post(BASE_URL + 'event', json=request_json)
        human_readable, context, _ = update_event_command(client, {'event_id': '111'})
        assert 'Event `111` has been updated.' in human_readable
        assert context[CONTEXT_PREFIX]  # Context is not empty

    def test_update_event_fail(self, requests_mock):
        from AnalyticsAndSIEM import update_event_command
        requests_mock.post(BASE_URL + 'event', json={'event': []})
        with raises(DemistoException, match='Could not update event `111`'):
            update_event_command(client, {'event_id': '111', 'assignee': '142,143'})

    def test_create_event(self, requests_mock):
        from AnalyticsAndSIEM import create_event_command
        request_json = {'event': [{
            'eventId': '111', 'description': 'event description', 'createdAt':
                '2019-09-09T08:30:07.959533', 'isActive': False,
            'assignee': [
                {'name': 'user1', 'id': '123'},
                {'name': 'user2', 'id': '124'}
            ]}]}
        requests_mock.post(BASE_URL + 'event', json=request_json)
        human_readable, context, raw_response = create_event_command(client,
                                                                     {'description': 'Test event',
                                                                      'assignee': '123,124'}
                                                                     )
        assert 'Event `111` has been created' in human_readable
        assert len(context[CONTEXT_PREFIX]['Assignee']) == 2  # Context is not empty
        assert raw_response == request_json

    def test_create_event_fail(self, requests_mock):
        from AnalyticsAndSIEM import create_event_command
        requests_mock.post(BASE_URL + 'event', json={'event': []})
        with raises(DemistoException, match='Could not create new event.'):
            create_event_command(client, {'event_id': '111', 'assignee': '142,143'})

    def test_query(self, requests_mock):
        from AnalyticsAndSIEM import query_command
        event__to_query = {'event': [
            {'eventId': '1', 'assignee': [{'id': 123}]},
            {'eventId': '2', 'assignee': [{'id': 123}]}
        ]}
        requests_mock.get(BASE_URL + 'query?eventId=1&eventId=2&eventId=3&assignee=123', json=event__to_query)
        human_readable, context, _ = query_command(client, {
            'event_id': '1,2,3',
            'assignee': '123'
        })
        assert 'Results for given query' in human_readable
        assert context[CONTEXT_PREFIX][0]['Assignee'][0]['ID'] == 123

    def test_query_empty(self, requests_mock):
        from AnalyticsAndSIEM import query_command
        requests_mock.get(BASE_URL + 'query', json={'event': []})
        human_readable, _, _ = query_command(client, {
            'event_id': '1,2,3',
            'assignee': '123'
        })
        assert 'Could not find any results for given query' in human_readable
