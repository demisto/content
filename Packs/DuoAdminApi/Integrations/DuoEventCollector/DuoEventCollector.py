from collections import deque
from enum import Enum

import duo_client
from pydantic import BaseModel
from CommonServerPython import *

HOST = demisto.getParam('host')
INTEGRATION_KEY = demisto.getParam('integration_key')
SECRET_KEY = demisto.getParam('secret_key')
USE_PROXY = demisto.params().get('proxy', False)


class LogType(str, Enum):
    """
    A list that represent the types of log collecting
    """
    AUTHENTICATION = 'AUTHENTICATION'
    ADMINISTRATION = 'ADMINISTRATION'
    TELEPHONY = 'TELEPHONY'
    OFFLINE_ENROLLMENT = 'OFFLINE_ENROLLMENT'


class Params(BaseModel):
    """
    A class that stores the request params
    """
    mintime: dict
    limit: str = 1000
    retries: int = 5

    def set_mintime_value(self, mintime: list, log_type: LogType) -> None:
        self.mintime[log_type] = mintime


class Client:
    """
    A class for the client request handling
    """

    def __init__(self, params: Params):
        self.params = params
        self.admin_api = create_api_call()

    def call(self, request_order) -> dict:
        retries = self.params.retries
        while retries != 0:
            try:
                if request_order[0] == LogType.AUTHENTICATION:
                    response = self.admin_api.get_authentication_log(
                        mintime=self.params.mintime[LogType.AUTHENTICATION])
                elif request_order[0] == LogType.ADMINISTRATION:
                    response = self.admin_api.get_administrator_log(
                        mintime=self.params.mintime[LogType.ADMINISTRATION])
                elif request_order[0] == LogType.TELEPHONY:
                    response = self.admin_api.get_telephony_log(
                        mintime=self.params.mintime[LogType.TELEPHONY])
                return response
            except Exception as exc:
                msg = f'something went wrong with the sdk call {exc}'
                LOG(msg)
                if str(exc) == 'Received 429 Too Many Requests':
                    retries -= 1
        return []

    def set_next_run_filter(self, mintime: int, log_type: LogType):
        self.params.set_mintime_value(mintime, log_type)


class GetEvents:
    """
    A class to handle the flow of the integration
    """

    def __init__(self, client: Client, request_order=[]) -> None:
        self.client = client
        self.request_order = request_order

    def rotate_request_order(self) -> list:
        temp = deque(self.request_order)
        temp.rotate(-1)
        self.request_order = list(temp)

    def make_sdk_call(self, last_object_ids: list):
        events: list = self.client.call(self.request_order)
        if last_object_ids:
            events = GetEvents.remove_duplicates(events, last_object_ids)
        events = sorted(events, key=lambda e: e['timestamp'])
        events = events[: int(self.client.params.limit)]
        self.rotate_request_order()
        return events

    def _iter_events(self, last_object_ids: list) -> None:
        """
        Function that responsible for the iteration over the events returned from the Duo api
        """
        events: list = self.make_sdk_call(last_object_ids)
        while True:
            yield events
            self.client.set_next_run_filter(events[-1]['timestamp'], self.request_order[-1])
            events: list = self.make_sdk_call(last_object_ids)
            try:
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    def aggregated_results(self, last_object_ids: list = None) -> List[dict]:
        """
        Function to group the events returned from the api
        """

        stored_events = []
        for events in self._iter_events(last_object_ids):
            stored_events.extend(events)
            if len(stored_events) >= int(self.client.params.limit) or not events:
                return stored_events
            self.client.params.limit = int(self.client.params.limit) - len(stored_events)
        return stored_events

    def get_last_run(self, events: List[dict]) -> dict:
        """
        Get the info from the last run, it returns the time to query from and a list of ids to prevent duplications
        """

        ids = []
        # gets the last event time
        last_time = events[-1].get('timestamp')
        for event in events:
            if event.get('timestamp') == last_time:
                event_id = f'{event.get("username")}{event.get("eventtype")}{event.get("timestamp")}'
                ids.append(event_id)
        return {'mintime': last_time, 'ids': ids, 'request_order': self.request_order}

    @staticmethod
    def remove_duplicates(events: list, ids: list) -> list:
        """
        Remove object duplicates by the uuid of the object
        """

        return [event for event in events if
                event[f'{event.get("username")}{event.get("eventtype")}{event.get("timestamp")}'] not in ids]


def override_make_request(self, method, uri, body, headers):
    """

    This function is an override function to the original
    duo_client.client.Client._make_request function in API version 4.1.0

    The reason for it is that the API creates a bad uri address for the GET requests.

    """

    conn = self._connect()
    conn.request(method, uri, body, headers)
    response = conn.getresponse()
    data = response.read()
    self._disconnect(conn)
    return response, data


def create_api_call():
    client = duo_client.Admin(
        ikey=INTEGRATION_KEY,
        skey=SECRET_KEY,
        host=HOST,
        ca_certs='DISABLE'
    )
    try:
        client._make_request = lambda method, uri, body, headers: override_make_request(client, method, uri, body,
                                                                                        headers)

    except Exception as e:
        demisto.error("Error making request - failed to create client: {}".format(e))
        raise Exception

    return client


def main():
    try:
        demisto_params = demisto.params()  # | demisto.args()
        after = dateparser.parse(demisto_params['after'].strip())
        last_run = demisto.getLastRun()
        last_object_ids = last_run.get('ids')
        if 'after' not in last_run:
            after = (datetime.today() - after)
            after = after.total_seconds()
            last_run = int(time.time()) - after
            last_run = {LogType[LogType.AUTHENTICATION]: last_run,
                        LogType[LogType.ADMINISTRATION]: last_run,
                        LogType[LogType.TELEPHONY]: last_run,
                        LogType[LogType.OFFLINE_ENROLLMENT]: last_run}

        else:
            last_run = last_run['after']
        request_order = last_run.get('request_order',
                                     [LogType.AUTHENTICATION, LogType.ADMINISTRATION, LogType.TELEPHONY])
        demisto_params['params'] = Params(**demisto_params, mintime=last_run)

        client = Client(demisto_params['params'])

        get_events = GetEvents(client, request_order)

        command = demisto.command()

        if command == 'test-module':
            get_events.aggregated_results()
            demisto.results('ok')
        elif command == 'duo-get-events' or command == 'fetch-events':
            events = get_events.aggregated_results(last_object_ids=last_object_ids)
            if events:
                demisto.setLastRun(get_events.get_last_run(events))
                if command == 'duo-get-events':
                    command_results = CommandResults(
                        readable_output=tableToMarkdown('Duo Logs', events, headerTransform=pascalToSpace),
                        outputs_prefix='Duo.Logs',
                        outputs_key_field='timestamp',
                        outputs=events,
                        raw_response=events,
                    )
                    return_results(command_results)
            send_events_to_xsiam(events, 'duo', 'duo')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
