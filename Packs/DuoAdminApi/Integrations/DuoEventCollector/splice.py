from enum import Enum

import duo_client
from pydantic import BaseModel, AnyUrl, Json
from CommonServerPython import *

HOST = 'api-a1fdb00d.duosecurity.com'#demisto.getParam('hostname')
INTEGRATION_KEY = 'DI47E4733YUXJZUWRYV2'#demisto.getParam('integration_key')
SECRET_KEY = 'YK6mtSzO5qTdeVjqvEqs7rmnc40Zw8fTsEw3heft'#demisto.getParam('secret_key')
USE_PROXY = demisto.params().get('proxy', False)


class Method(str, Enum):
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
    mintime: str
    limit: str = 1000
    method: Method

    def set_since_value(self, mintime: 'dateTime as ISO string') -> None:
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
            if self.params.method == Method.AUTHENTICATION:
                response = self.admin_api.get_authentication_log(api_version=2, mintime=self.params.mintime)
            elif self.params.method == Method.ADMINISTRATION:
                response = self.admin_api.get_administrator_log()
            elif self.params.method == Method.TELEPHONY:
                response = self.admin_api.get_telephony_log()
            elif self.params.method == Method.OFFLINE_ENROLLMENT:
                response = self.admin_api.get_administrator_log()
            return response
        except Exception as exc:
            msg = f'something went wrong with the sdk call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    def set_next_run_filter(self, after: str):
        self.params.set_since_value(after)


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
        response = self.client.call()
        events: list = response['authlogs']
        if last_object_ids:
            events = GetEvents.remove_duplicates(events, last_object_ids)
        if len(events) == 0:
            return []
        while True:
            yield events
            last = events.pop()
            self.client.set_next_run_filter(last['published'])
            response = self.client.call()
            events: list = response.json()
            try:
                events.pop(0)
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    def aggregated_results(self, last_object_ids: List[str] = None) -> List[dict]:
        """
        Function to group the events returned from the api
        """
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
        last_time = events[-1].get('published')
        for event in events:
            if event.get('published') == last_time:
                ids.append(event.get('uuid'))
        last_time = datetime. strptime(str(last_time).lower().replace('z', ''), '%Y-%m-%dt%H:%M:%S.%f')
        return {'after': last_time.isoformat(), 'ids': ids}

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
    # events_to_add_per_request = demisto_params.get('events_to_add_per_request', 2000)
    # admin_api = create_api_call()
    # try:
    #     events_to_add_per_request = int(events_to_add_per_request)
    # except ValueError:
    #     events_to_add_per_request = 2000
    # after = int(demisto_params['after'])
    # headers = json.loads(demisto_params['headers'])
    # encrypted_headers = json.loads(demisto_params['encrypted_headers'])
    # demisto_params['headers'] = dict(encrypted_headers.items() | headers.items())
    # del demisto_params['encrypted_headers']
    # last_run = demisto.getLastRun()
    # last_object_ids = last_run.get('ids')
    # # If we do not have an after in the last run than we calculate after according to now - after param from integration settings.
    # if 'after' not in last_run:
    #     delta = datetime.today() - timedelta(days=after)
    #     last_run = delta.isoformat()
    # else:
    #     last_run = last_run['after']
    demisto_params['params'] = Params(**demisto_params)

    client = Client(demisto_params['params'])

    get_events = GetEvents(client)

    command = demisto.command()
    if command == 'test-module':
        get_events.aggregated_results()
        demisto.results('ok')
    # elif command == 'okta-get-events' or command == 'fetch-events':
    #     events = get_events.aggregated_results(last_object_ids=last_object_ids)
    #     if events:
    #         demisto.setLastRun(GetEvents.get_last_run(events))
    #         if command == 'fetch-events':
    #             while len(events) > 0:
    #                 send_events_to_xsiam(events[:events_to_add_per_request], 'okta', 'okta')
    #                 events = events[events_to_add_per_request:]
    #         elif command == 'okta-get-events':
    #             command_results = CommandResults(
    #                 readable_output=tableToMarkdown('Okta Logs', events, headerTransform=pascalToSpace),
    #                 outputs_prefix='Okta.Logs',
    #                 outputs_key_field='published',
    #                 outputs=events,
    #                 raw_response=events,
    #             )
    #             return_results(command_results)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
