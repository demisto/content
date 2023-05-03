from collections import deque
from enum import Enum
import duo_client
from pydantic import BaseModel  # pylint: disable=E0611
from CommonServerPython import *

VENDOR = "duo_test"
PRODUCT = "duo_test"
# This variable is used to convert the meantime for the v2 API for auth to milliseconds while the others use seconds
AUTH_API_V2_TIME_MODIFIER = 1000


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
    limit: str = '1000'
    retries: Optional[str] = '5'
    auth_api_version: Optional[str] = '1'

    def set_mintime_value(self, mintime: list, log_type: LogType) -> None:  # pragma: no cover
        self.mintime[log_type] = mintime

class Client:
    """
    A class for the client request handling
    """

    def __init__(self, params: Params):  # pragma: no cover type: ignore
        self.params = params.get('params')  # type: ignore[attr-defined]
        self.admin_api = create_api_call(params.get('host'),  # type: ignore[attr-defined]
                                         params.get('integration_key'),  # type: ignore[attr-defined]
                                         (params.get('secret_key')).get('password'))  # type: ignore[attr-defined]

    def call(self, request_order: list) -> tuple:  # pragma: no cover
        retries = int(self.params.retries)
        auth_api_version = int(self.params.auth_api_version)
        response_metadata = None
        while retries != 0:
            try:
                if request_order[0] == LogType.AUTHENTICATION:
                    if auth_api_version == 2:
                        if not self.params.mintime[LogType.AUTHENTICATION].get('next_offset'):
                            response = self.admin_api.get_authentication_log(
                                min_time=self.params.mintime[LogType.AUTHENTICATION].get('min_time'),
                                api_version=2, limit=str(min(int(self.params.limit), int('1000'))), sort='ts:asc')
                        else:
                            response = self.admin_api.get_authentication_log(
                                next_offset=self.params.mintime[LogType.AUTHENTICATION].get('next_offset'),
                                api_version=2, limit=str(min(int(self.params.limit), int('1000'))), sort='ts:asc')
                        # The v2 API returns a different object, so we do this to normalize it
                        response_metadata = response.get('metadata')
                        response = response.get('authlogs', [])

                elif request_order[0] == LogType.ADMINISTRATION:
                    response = self.admin_api.get_administrator_log(
                        mintime=self.params.mintime[LogType.ADMINISTRATION])

                elif request_order[0] == LogType.TELEPHONY:
                    response = self.admin_api.get_telephony_log(
                        mintime=self.params.mintime[LogType.TELEPHONY])
                return response, response_metadata
            except Exception as exc:
                msg = f'something went wrong with the sdk call {exc}'
                demisto.debug(msg)
                if str(exc) == 'Received 429 Too Many Requests':
                    retries -= 1
                else:
                    raise exc

        return ([], [])

    def set_next_run_filter(self, mintime: int, log_type: LogType, metadata=None): #pragma: no cover
        if metadata:
            self.params.set_mintime_value({'min_time': mintime, 'next_offset': metadata.get('next_offset')}, log_type)
        else:
            self.params.set_mintime_value(mintime + 1, log_type)


class GetEvents:
    """
    A class to handle the flow of the integration
    """

    def __init__(self, client: Client, request_order=[]) -> None:  # pragma: no cover
        self.client = client
        self.request_order = request_order

    def rotate_request_order(self) -> None:
        temp = deque(self.request_order)
        temp.rotate(-1)
        self.request_order = list(temp)

    def make_sdk_call(self) -> tuple:  # pragma: no cover
        events, metadata = self.client.call(self.request_order)  # type: ignore
        events = sorted(events, key=lambda e: e['timestamp'])
        events = events[: int(self.client.params.limit)]
        return events, metadata

    def _iter_events(self) -> None:  # type: ignore  # pragma: no cover
        """
        Function that responsible for the iteration over the events returned from the Duo api
        """
        events, metadata = self.make_sdk_call()
        while True:
            if events:
                self.client.set_next_run_filter(events[-1]['timestamp'], self.request_order[0], metadata=metadata)
            yield events
            events, metadata = self.make_sdk_call()
            try:
                assert events
            except (IndexError, AssertionError):
                demisto.debug('empty list, breaking')
                break

    def aggregated_results(self) -> List[dict]:  # pragma: no cover
        """
        Function to group the events returned from the api
        """

        stored_events = []
        for events in self._iter_events():  # type: ignore
            demisto.debug(f'Got {len(events)}, events for {self.request_order[0]} logs')
            stored_events.extend(events)
            if len(stored_events) >= int(self.client.params.limit) or not events:
                return stored_events
            self.client.params.limit = int(self.client.params.limit) - len(stored_events)
        return stored_events

    def get_last_run(self):  # pragma: no cover
        """
        Get the info from the last run, it returns the time to query from
        """
        self.rotate_request_order()
        last_run = {'after': self.client.params.mintime,
                    'request_order': self.request_order}
        return last_run


def override_make_request(self, method: str, uri: str, body: dict, headers: dict):  # pragma: no cover
    """

    This function is an override function to the original
    duo_client.client.Client._make_request function in API version 4.1.0

    The reason for it is that the API creates a bad uri address for the GET requests.

    """
    try:
        conn = self._connect()
        conn.request(method, uri, body, headers)
        response = conn.getresponse()
        data = response.read()
        return response, data
    finally:
        self._disconnect(conn)


def create_api_call(host: str, integration_key: str, secrete_key: str):  # pragma: no cover
    client = duo_client.Admin(
        ikey=integration_key,
        skey=secrete_key,
        host=host,
        ca_certs='DISABLE'
    )

    client._make_request = lambda method, uri, body, headers: override_make_request(client, method, uri, body,
                                                                                    headers)
    return client


def main():  # pragma: no cover
    try:
        demisto_params = demisto.params() | demisto.args()

        last_run = demisto.getLastRun()

        logs_type_array = demisto_params.get('logs_type_array',
                                             f'{LogType.AUTHENTICATION},{LogType.ADMINISTRATION},{LogType.TELEPHONY}')
        request_order = last_run.get('request_order', logs_type_array.split(','))
        demisto.debug(f'The request order is : {request_order}')
        if 'after' not in last_run:
            after = dateparser.parse(demisto_params['after'].strip())
            last_run = after.timestamp()  # type: ignore
            last_run = {LogType.AUTHENTICATION.value: {'min_time': last_run, 'next_offset': []},
                        LogType.ADMINISTRATION.value: last_run,
                        LogType.TELEPHONY.value: last_run}

        else:
            last_run = last_run['after']
        demisto.debug(f'The last run is : {last_run}')
        demisto_params['params'] = Params(**demisto_params, mintime=last_run)
        client = Client(demisto_params)

        get_events = GetEvents(client, request_order)

        command = demisto.command()

        if command == 'test-module':
            get_events.aggregated_results()
            return_results('ok')
        elif command in ('duo-get-events', 'fetch-events'):
            events = get_events.aggregated_results()
            if command == 'duo-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('Duo Logs', events, headerTransform=pascalToSpace),
                    raw_response=events,
                )
                return_results(command_results)
                if argToBoolean(demisto_params.get('push_events', 'false')):
                    demisto.debug(f'Sending {len(events)} events to XSIAM')
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            else:
                # fetch-events
                demisto.debug(f'Sending {len(events)} events to XSIAM')
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(get_events.get_last_run())

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
