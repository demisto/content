from typing import Any
from SiemApiModule import (
    IntegrationEventsClient,
    IntegrationHTTPRequest,
    IntegrationOptions,
    IntegrationGetEvents,
    Method,
)
import json


class MyIntegrationEventsClient(IntegrationEventsClient):
    def set_request_filter(self, after: Any):
        """Implement the next call run

        Example:
        >>> from datetime import datetime
        >>> set_request_filter(datetime(year=2022, month=4, day=16))
        """
        self.request.headers['after'] = after


class MyIntegrationGetEvents(IntegrationGetEvents):
    @staticmethod
    def get_last_run(events: list) -> dict:
        """Implement how to get the last run.

        Example:
        >>> get_last_run([{'created': '2022-4-16'}])
        """
        return {'after': events[-1]['created']}

    def _iter_events(self):
        """Create an iterator on the events.
        If need extra authorisation, do that in the beggining of the command.
        Example:
        >>> for event in _iter_events():
        ...
        """
        response = self.call()
        while True:
            events = response.json()
            yield events
            self.client.set_request_filter(events[-1]['created'])
            self.call()


class TestSiemAPIModule:
    def test_flow(self, requests_mock):
        created = '2022-04-16'
        requests_mock.post('https://example.com', json=[{'created': created}])
        request = IntegrationHTTPRequest(
            method=Method.POST, url='https://example.com'
        )
        options = IntegrationOptions(limit=1)
        client = MyIntegrationEventsClient(request, options)
        get_events = MyIntegrationGetEvents(client, options)
        events = get_events.run()
        assert events[0]['created'] == '2022-04-16'

    def test_created(self, requests_mock):
        created = '2022-04-16'
        requests_mock.post('https://example.com', json=[{'created': created}])
        request = IntegrationHTTPRequest(
            method=Method.POST, url='https://example.com'
        )
        options = IntegrationOptions(limit=2)
        client = MyIntegrationEventsClient(request, options)
        get_events = MyIntegrationGetEvents(client, options)
        get_events.run()
        assert client.request.headers['after'] == '2022-04-16'

    def test_headers_parsed(self):
        request = IntegrationHTTPRequest(
            method=Method.GET,
            url='https://example.com',
            headers=json.dumps({'Authorization': 'Bearer Token'}),
        )
        assert request.headers['Authorization']
