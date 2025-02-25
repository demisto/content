from datetime import datetime, timedelta
from collections import deque
from enum import Enum

import duo_client
from pydantic import BaseModel, Field  # pylint: disable=E0611

from CommonServerPython import *
from typing import Any
from collections.abc import Generator

VENDOR = "duo"
PRODUCT = "duo"


class LogType(str, Enum):
    """
    A list that represent the types of log collecting
    """
    AUTHENTICATION = 'AUTHENTICATION'
    ADMINISTRATION = 'ADMINISTRATION'
    TELEPHONY = 'TELEPHONY'


class Params(BaseModel):
    """
    A class that stores the request params
    """
    mintime: dict
    limit: str = '1000'
    retries: str = Field(default='5')
    host: str
    integration_key: str
    secret_key: dict
    fetch_delay: str = '0'
    end_window: datetime

    def set_next_offset_value(self, mintime: Any, log_type: LogType) -> None:
        demisto.debug(f'in set_next_offset_value {mintime=} {log_type=}')
        self.mintime[log_type] = mintime


class Client:
    """
    A class for the client request handling
    """

    def __init__(self, params: Params):
        self.params = params
        self.admin_api = create_api_call(self.params.host,
                                         self.params.integration_key,
                                         str(self.params.secret_key.get('password')))

    def call(self, request_order: list) -> tuple:
        """
        returns a tuple (events:list, metadata:dict|None) the metadata part is relevant only to the V2 endpoints,
        And should be None for the V1 end points.
        """
        retries = int(self.params.retries)
        response_metadata = None
        while retries != 0:
            try:
                if request_order[0] == LogType.AUTHENTICATION:
                    events, response_metadata = self.handle_authentication_logs()

                elif request_order[0] == LogType.TELEPHONY:
                    events = self.handle_telephony_logs_v1()

                else:  # request_order[0] == LogType.ADMINISTRATION:
                    demisto.debug(f"{request_order[0]=} should be LogType.ADMINISTRATION")
                    events = self.handle_administration_logs()

                return events, response_metadata

            except Exception as exc:
                msg = f'something went wrong with the sdk call {exc}'
                demisto.debug(msg)
                if str(exc) == 'Received 429 Too Many Requests':
                    retries -= 1
                else:
                    raise exc

        return ([], [])

    def check_window_before_call(self, mintime: int | float) -> bool:
        """ Check if the API call should be performed. If not return false, else return true.
            If the fetch_delay != 0 (we want a delayed fetch) and end_window <= mintime -> we don't want to perform the fetch
            at the moment.

        Args:
            mintime (int | float): The wanted fetch time in a timestamp.

        Returns:
            bool: False - don't perform the API call, True - perform the API call
        """
        demisto.debug(f'check_window_before_call {mintime=}')
        mintime_dt = datetime.fromtimestamp(mintime)
        if self.params.fetch_delay != '0' and self.params.end_window - timedelta(seconds=5) <= mintime_dt:
            demisto.debug(f"check_window_before_call, don't perform API call {self.params.fetch_delay=} and "
                          f"{(self.params.end_window - timedelta(seconds=5))=} <= {mintime_dt=}")
            return False
        demisto.debug('check_window_before_call, perform API call')
        return True

    def handle_authentication_logs(self) -> tuple:
        """
        Uses the V2 version of the API.
        For the first time the logs are retreived will work with mintime parameter.
        All other calls will be made with the next_offset parameter returned from the last fetch.
        get_authentication_log: If not provided takes mintime to 24 hours and maxtime to time.now - 2 min.

        NOTE: In case there is a fetch_delay, we want to perform the API call only in case that min_time is before the end of the
        fetch window.
        """
        maxtime = str(int(self.params.end_window.timestamp() * 1000))

        if not self.params.mintime[LogType.AUTHENTICATION].get('next_offset'):
            mintime = self.params.mintime[LogType.AUTHENTICATION].get('min_time')
            if not self.check_window_before_call(int(mintime) / 1000):
                return [], {}
            demisto.debug(f'handle_authentication_logs, no next_offset {mintime=} {maxtime=}')
            response = self.admin_api.get_authentication_log(
                mintime=mintime, api_version=2, limit=str(min(int(self.params.limit), int('1000'))), sort='ts:asc',
                maxtime=maxtime)

        else:
            next_offset = self.params.mintime[LogType.AUTHENTICATION].get('next_offset')
            mintime = next_offset[0]  # The mintime in the next_offset object is a string according to the API
            if not self.check_window_before_call(int(mintime) / 1000):
                return [], {}
            demisto.debug(f'handle_authentication_logs {next_offset=} {maxtime=}')
            response = self.admin_api.get_authentication_log(
                next_offset=next_offset, mintime=mintime,
                api_version=2, limit=str(min(int(self.params.limit), int('1000'))), sort='ts:asc', maxtime=maxtime)

        # The v2 API works with a metadata dictionary - (next token mechanism).
        response_metadata = response.get('metadata')
        events = response.get('authlogs', [])
        return events, response_metadata

    def handle_telephony_logs_v2(self) -> tuple:
        """
        *** This method uses the api_version=2 this endpoint is still not availabe for GA.
            The api version 1 is about to get deprecated  then this method will replace the
            handle_telephony_logs with some additional code changes. look at the handeling of
            authentication logs for reference.

        Uses the V2 version of the API.
        For the first time the logs are retreived will work with mintime parameter.
        All other calls will be made with the next_offset parameter returned from the last fetch.
        get_telephony_log: If not provided takes mintime to 180 days and maxtime to time.now - 2 min.

        NOTE: In case there is a fetch_delay, we want to perform the API call only in case that min_time is before the end of the
        fetch window.
        """
        maxtime = str(int(self.params.end_window.timestamp() * 1000))

        if not self.params.mintime[LogType.TELEPHONY].get('next_offset'):
            mintime = self.params.mintime[LogType.TELEPHONY].get('min_time')
            if not self.check_window_before_call(int(mintime) / 1000):
                return [], {}
            demisto.debug(f'handle_telephony_logs_v2, no next_offset {mintime=} {maxtime=}')
            response = self.admin_api.get_telephony_log(
                mintime=mintime,
                api_version=2, limit=str(min(int(self.params.limit), 1000)), sort='ts:asc', maxtime=maxtime)

        else:
            next_offset = self.params.mintime[LogType.TELEPHONY].get('next_offset', '')
            mintime = next_offset.split(',')[0]  # "next_offset": "1666714065304,5bf1a860-fe39-49e3-be29-217659663a74"
            if not self.check_window_before_call(int(mintime) / 1000):
                return [], {}
            demisto.debug(f'handle_telephony_logs_v2 {next_offset=} {maxtime=}')
            response = self.admin_api.get_telephony_log(
                next_offset=next_offset, mintime=mintime,
                api_version=2, limit=str(min(int(self.params.limit), 1000)), sort='ts:asc', maxtime=maxtime)

        response_metadata = response.get('metadata', {})
        events = response.get('items')

        return events, response_metadata

    def handle_telephony_logs_v1(self) -> list:
        # TELEPHONY end point uses the V1 api endpoint.
        # In case there is a fetch_delay, we want to perform the API call only in case that min_time is before the end of the
        # fetch window.
        mintime = int(self.params.mintime[LogType.TELEPHONY])
        if not self.check_window_before_call(mintime):
            return []
        demisto.debug(f'handle_telephony_logs_v1 mintime={mintime}')
        events = self.admin_api.get_telephony_log(mintime=self.params.mintime[LogType.TELEPHONY])
        events = sorted(events, key=lambda e: e['timestamp'])
        return events

    def handle_administration_logs(self) -> list:
        # ADMINISTRATION end point uses the V1 api endpoint.
        # In case there is a fetch_delay, we want to perform the API call only in case that min_time is before the end of the
        # fetch window.
        mintime = int(self.params.mintime[LogType.ADMINISTRATION])
        if not self.check_window_before_call(mintime):
            return []
        demisto.debug(f'handle_administration_logs mintime={mintime}')
        events = self.admin_api.get_administrator_log(mintime=self.params.mintime[LogType.ADMINISTRATION])
        events = sorted(events, key=lambda e: e['timestamp'])
        return events

    def set_next_run_filter_v1(self, log_type: LogType, mintime: int):
        """Set the next_run for the v1 api. works with mintime parameter"""
        self.params.set_next_offset_value(mintime + 1, log_type)

    def set_next_run_filter_v2(self, log_type: LogType, metadata: dict, mintime: int = 0):
        """Set the next_run for the v2 api, works with the next_offset parameter"""
        self.params.set_next_offset_value({'next_offset': metadata.get('next_offset')}, log_type)


class GetEvents:
    """
    A class to handle the flow of the integration
    """

    def __init__(self, client: Client, request_order: list) -> None:
        self.client = client
        self.request_order = request_order

    def rotate_request_order(self) -> None:
        temp = deque(self.request_order)
        temp.rotate(-1)
        self.request_order = list(temp)

    def make_sdk_call(self) -> tuple:
        events, metadata = self.client.call(self.request_order)
        demisto.debug(f'make_sdk_call {len(events)=}')
        events = events[: int(self.client.params.limit)]
        demisto.debug(f'make_sdk_call after update {len(events)=}')
        return events, metadata

    def events_in_window(self, events: list) -> tuple[list, bool]:
        """ Binary search on the list of events to find the event closest to the end of the fetch window.
            cases:
            a. There is no need to run this function fetch_delay = 0 (if 1).
            b. No events are in the fetch_window (if 2).
            c. Some of the events in the fetch window.

            Args:
                events (list[dict]): List of events from the current fetch response.

            Returns:
                tuple[list[dict], bool]: The list of events, bool represents whether we reached the end of the fetch window.
            """
        # if 1
        if (self.client.params.fetch_delay == '0'
                or datetime.fromtimestamp(events[-1]['timestamp']) < self.client.params.end_window):
            demisto.debug(f"events_in_window, all events in the fetch window {events[-1]['timestamp']=} < "
                          f"{self.client.params.end_window.timestamp()=}")
            return events, False
        # if 2
        if datetime.fromtimestamp(events[0]['timestamp']) >= self.client.params.end_window:
            demisto.debug(f"events_in_window, no events are in the fetch window {events[0]['timestamp']=} >= "
                          f"{self.client.params.end_window.timestamp()=}")
            return [], True

        i = 0
        for i in range(len(events)):
            if datetime.fromtimestamp(events[i]['timestamp']) >= self.client.params.end_window:
                demisto.debug(f'events_in_window, the {i} event occurred date is {events[i]["isotimestamp"]=}, after the end of '
                              f'the fetch_window. Returning the events up to and include event {i-1} with occurred date of'
                              f'{events[i-1]["isotimestamp"]=} {events[i-1]["timestamp"]=}.')
                break
        return events[:i], True

    def _iter_events(self) -> Generator:
        """
        Function that responsible for the iteration over the events returned from the Duo api
        """
        events, metadata = self.make_sdk_call()
        reached_end_window = False
        while True:
            if events:
                # The diffrent filters set are driven from duo-api admin documentation.
                # V1 is filtered with the timespamp parameter and V2 is filtered by the metadata dictionary.
                if self.request_order[0] in [
                    LogType.ADMINISTRATION,
                    LogType.TELEPHONY,
                ]:
                    events, reached_end_window = self.events_in_window(events)
                    if events:  # if there aren't events in the fetch window events will return empty
                        self.client.set_next_run_filter_v1(self.request_order[0], events[-1]['timestamp'])
                else:
                    self.client.set_next_run_filter_v2(self.request_order[0], metadata)
                events = parse_events(events)  # If there are events left in events, add _time
            yield events
            if reached_end_window:
                demisto.debug('reached the end_window, breaking')
                break
            events, metadata = self.make_sdk_call()
            try:
                assert events
            except (IndexError, AssertionError):
                demisto.debug('empty list, breaking')
                break

    def aggregated_results(self) -> List[dict]:
        """
        Function to group the events returned from the api
        """

        stored_events = []
        for events in self._iter_events():
            demisto.debug(f'Got {len(events)}, events for {self.request_order[0]} logs')
            stored_events.extend(events)
            if len(stored_events) >= int(self.client.params.limit) or not events:
                return stored_events
            demisto.debug(f'updating the limit current value is {self.client.params.limit} the new value will be '
                          f'{int(self.client.params.limit) - len(stored_events)}')
            self.client.params.limit = str(int(self.client.params.limit) - len(stored_events))
        return stored_events

    def get_last_run(self):
        """
        Get the info from the last run, it returns the time to query from
        """
        self.rotate_request_order()
        return {
            'after': self.client.params.mintime,
            'request_order': self.request_order,
        }


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


def parse_events(authentication_evetns: list):
    """
    Adds the parsing rule of the _time to each of duo events
    """
    for event in authentication_evetns:
        event["_time"] = event.get("isotimestamp")

    return authentication_evetns


def parse_mintime(last_run: float) -> tuple:
    """Returns the last run precision of 10 digits(seconds) for v1 and 13 digits(milliseconds) for v2"""
    last_run_v1 = int(last_run)
    last_run_v2 = int(last_run * 1000)
    demisto.debug(f'in parse_mintime {last_run=} {last_run_v1=} {last_run_v2=}')
    return last_run_v1, last_run_v2


def validate_request_order_array(logs_type_array: list) -> Any:
    """Validates that all the inputs of the log_type_array are valid."""
    wrong_values = []
    for value in logs_type_array:
        if value not in [LogType.ADMINISTRATION, LogType.AUTHENTICATION, LogType.TELEPHONY]:
            wrong_values.append(value)

    if not wrong_values:
        return True
    else:
        return ','.join(wrong_values)


def calculate_window(params: dict):
    fetch_delay = arg_to_number(params.get('fetch_delay')) or 0
    end_window = datetime.utcnow() - timedelta(minutes=fetch_delay)
    demisto.debug(f'{fetch_delay=} {end_window=}')
    params['end_window'] = end_window


def main():
    try:
        demisto_params = demisto.params() | demisto.args()

        last_run = demisto.getLastRun()

        logs_type_array = demisto_params.get('logs_type_array',
                                             f'{LogType.AUTHENTICATION},{LogType.ADMINISTRATION},{LogType.TELEPHONY}')

        request_order = last_run.get('request_order', logs_type_array.split(','))
        request_order = [log_type.upper() for log_type in request_order]
        if unvalid_log_type := validate_request_order_array(request_order) is not True:
            DemistoException(f'We found invalid values for logs_type_array, the values are {unvalid_log_type}')

        demisto.debug(f'The request order is : {request_order}')

        if 'after' not in last_run:
            after = dateparser.parse(demisto_params['after'].strip())
            if after is not None:
                last_run = after.timestamp()
            else:
                DemistoException('Please check your "after" parameter is valid')

            v1_mintime, v2_mintime = parse_mintime(last_run)
            last_run = {LogType.AUTHENTICATION.value: {'min_time': v2_mintime, 'next_offset': []},
                        LogType.ADMINISTRATION.value: v1_mintime,
                        LogType.TELEPHONY.value: v1_mintime}
        else:
            last_run = last_run['after']

        demisto.debug(f'The last run is : {last_run}')

        calculate_window(demisto_params)
        client = Client(Params(**demisto_params, mintime=last_run))

        get_events = GetEvents(client, request_order)

        command = demisto.command()

        if command == 'test-module':
            get_events.aggregated_results()
            return_results('ok')
        elif command in ('duo-get-events', 'fetch-events'):
            events = get_events.aggregated_results()
            if command == 'duo-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown(f'Duo Logs - {len(events)} events', events, headerTransform=pascalToSpace),
                    raw_response=events,
                )
                return_results(command_results)
                if argToBoolean(demisto_params.get('should_push_events', 'false')):
                    demisto.debug(f'Sending {len(events)} events to XSIAM')
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            else:
                # fetch-events
                demisto.debug(f'Sending {len(events)} events to XSIAM')
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(get_events.get_last_run())
        else:
            raise NotImplementedError(f'The command {command} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
