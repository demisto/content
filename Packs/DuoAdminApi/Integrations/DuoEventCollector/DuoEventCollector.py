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


OPTIONS_TO_TIME = {

    '1 minute': 60,
    '1 hour': 3600,
    '1 day': 86400,
    '3 days': 259200,
    '5 days': 432000,
    '1 week': 604800,
    '1 month': 2628288,
    '1 year': 31536000

}


class Params(BaseModel):
    """
    A class that stores the request params
    """
    mintime: dict
    limit: str = 100
    method: LogType

    def set_mintime_value(self, mintime: 'epoch time') -> None:
        self.mintime = mintime


class Client:
    """
    A class for the client request handling
    """

    def __init__(self, params: Params):
        self.params = params
        self.admin_api = create_api_call()

    def call(self) -> dict:
        try:
            # if self.params.method == LogType.AUTHENTICATION:
            #     response = self.admin_api.get_authentication_log(mintime=int(self.params.mintime))
            # elif self.params.method == LogType.ADMINISTRATION:
            #     response = self.admin_api.get_administrator_log(mintime=int(self.params.mintime))
            # elif self.params.method == LogType.TELEPHONY:
            #     response = self.admin_api.get_telephony_log(mintime=int(self.params.mintime))
            # elif self.params.method == LogType.OFFLINE_ENROLLMENT:
            #     response = self.admin_api.get_administrator_log()
            response = self.admin_api.get_authentication_log(mintime=int(self.params.mintime))
            response.extend(self.admin_api.get_administrator_log(mintime=int(self.params.mintime)))
            response.extend(self.admin_api.get_telephony_log(mintime=int(self.params.mintime)))
            # elif self.params.method == LogType.OFFLINE_ENROLLMENT:
            #     response = self.admin_api.get_administrator_log()
            return response
        except Exception as exc:
            msg = f'something went wrong with the sdk call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    def set_next_run_filter(self, mintime: str):
        self.params.set_mintime_value(mintime)


class GetEvents:
    """
    A class to handle the flow of the integration
    """
    def __init__(self, client: Client) -> None:
        self.client = client

    def _iter_events(self, last_object_ids: list) -> None:
        """
        Function that responsible for the iteration over the events returned from the Okta api
        """
        events: list = self.client.call()
        if len(events) == 0:
            return []
        events = sorted(events, key=lambda e: e['timestamp'])
        if last_object_ids:
            events = GetEvents.remove_duplicates(events, last_object_ids)
        while True:
            yield events
            last = events.pop()
            self.client.set_next_run_filter(last['timestamp'])
            events: list = self.client.call()
            try:
                events.pop(0)
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    def aggregated_results(self, last_object_ids: list = None) -> List[dict]:
        """
        Function to group the events returned from the api
        """
        # events: list = self.client.call()
        # if len(events) == 0:
        #     return []
        # events = sorted(events, key=lambda e: e['timestamp'])
        # if last_object_ids:
        #     events = GetEvents.remove_duplicates(events, last_object_ids)
        # self.client.set_next_run_filter(events[-1]['timestamp'])
        # return events

        stored_events = []
        for events in self._iter_events(last_object_ids):
            stored_events.extend(events)
        return stored_events

    @staticmethod
    def get_last_run(events: List[dict]) -> dict:
        """
        Get the info from the last run, it returns the time to query from and a list of ids to prevent duplications
        """

        ids = []
        # gets the last event time
        last_time = events[-1].get('timestamp')
        for event in events:
            if event.get('timestamp') == last_time:
                ids.append(event.get('username') + event.get('eventtype') + event.get('timestamp'))
        return {'mintime': last_time, 'ids': ids}

    @staticmethod
    def remove_duplicates(events: list, ids: list) -> list:
        """
        Remove object duplicates by the uuid of the object
        """

        duplicates_indexes = []
        for i in range(len(events)):
            event_id = events[i]['uuid']
            if event_id in ids:
                duplicates_indexes.append(i)
        if len(duplicates_indexes) > 0:
            for i in duplicates_indexes:
                del events[i]
        return events

def override_make_request(self, method, uri, body, headers):
    """

    This function is an override function to the original
    duo_client.client.Client._make_request function in API version 4.1.0

    The reason for it is that the API creates a bad uri address for the GET requests.

    """

    conn = self._connect()

    # Ignored original code #
    # --------------------- #
    # if self.proxy_type == 'CONNECT':
    #     # Ensure the request uses the correct protocol and Host.
    #     if self.ca_certs == 'HTTP':
    #         api_proto = 'http'
    #     else:
    #         api_proto = 'https'
    #     uri = ''.join((api_proto, '://', self.host, uri))
    # ------------------- #
    # End of ignored code #

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
        client._make_request = lambda method, uri, body, headers: override_make_request(client, method, uri, body, headers)

    except Exception as e:
        demisto.error("Error making request - failed to create client: {}".format(e))
        raise Exception

    return client


def main():
    demisto_params = demisto.params() #| demisto.args()

    after = OPTIONS_TO_TIME[demisto_params['after']]
    last_run = demisto.getLastRun()
    last_object_ids = last_run.get('ids')
    if 'after' not in last_run:
        last_run = int(time.time()) - after
        last_run = {LogType[LogType.AUTHENTICATION]: last_run,
                    LogType[LogType.ADMINISTRATION]: last_run,
                    LogType[LogType.TELEPHONY]: last_run,
                    LogType[LogType.OFFLINE_ENROLLMENT]: last_run}

    else:
        last_run = last_run['after']

    demisto_params['params'] = Params(**demisto_params, mintime=last_run)

    client = Client(demisto_params['params'])

    get_events = GetEvents(client)

    command = demisto.command()

    if command == 'test-module':
        get_events.aggregated_results()
        demisto.results('ok')
    elif command == 'duo-get-events' or command == 'fetch-events':
        events = get_events.aggregated_results(last_object_ids=last_object_ids)
        if events:
            demisto.setLastRun(GetEvents.get_last_run(events))
            if command == 'fetch-events':
                events_to_add_per_request = demisto_params.get('events_to_add_per_request', 2000)
                try:
                    events_to_add_per_request = int(events_to_add_per_request)
                except ValueError:
                    events_to_add_per_request = 2000
                while len(events) > 0:
                    send_events_to_xsiam(events[:events_to_add_per_request], 'Duo', 'Duo')
                    events = events[events_to_add_per_request:]
            elif command == 'okta-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('Duo Logs', events, headerTransform=pascalToSpace),
                    outputs_prefix='Duo.Logs',
                    outputs_key_field='timestamp',
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
