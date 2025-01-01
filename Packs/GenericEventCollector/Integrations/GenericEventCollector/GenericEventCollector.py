from CommonServerPython import *
import demistomock as demisto
from typing import Any, cast  # noqa: UP035
from base64 import b64encode
from datetime import datetime

import json
import urllib3
import requests
import re

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 10000
DEFAULT_INDICATORS_THRESHOLD = 65
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
VENDOR = 'generic'
PRODUCT = 'collector'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes are defined
    """

    def search_events(self, endpoint: str, method: str, request_data: dict[Any, Any], request_json: dict[Any, Any],
                      query_params: dict[Any, Any]) -> list[dict[str, Any]]:
        """
        Searches for events using the API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            endpoint: API endpoint to send the request to.
            method: HTTP method to use in the request.
            request_data: data to send in the body of the request.
            request_json: JSON data to send in the body of the request.
            query_params: query parameters to send in the request.
        Returns:
            list: list of events as dicts.
        """
        return self._http_request(  # type: ignore
            method=method,
            url_suffix=endpoint,
            json_data=request_json,
            data=request_data,
            params=query_params,
        )
        # return self._http_request(
        #     method=method,
        #     url_suffix=endpoint,
        #     data=request_data,
        #     params=query_params,
        # )

        # else:
        #     return self._http_request(
        #         method=method,
        #         url_suffix=endpoint,
        #         json_data=request_json,
        #         data=request_data,
        #         params=query_params,
        #     )


def organize_events_to_xsiam_format(events):

    raw_events = events
    events_to_xsiam = []
    events_list: Dict[Any, Any]

    if isinstance(raw_events, dict):
        for event in raw_events:
            if isinstance(raw_events[event], list):
                full_event_list = raw_events[event]
                for full_event in full_event_list:
                    events_list = {}
                    for key, value in full_event.items():

                        if isinstance(value, int | str):
                            events_list[key] = value

                        elif isinstance(value, dict):

                            dict_values_to_extract_back_to_list = value
                            new_value: Any = {key: value}
                            events_list.update(new_value)

                            for item in dict_values_to_extract_back_to_list:
                                key = item
                                value = dict_values_to_extract_back_to_list[item]
                                new_value = {key: value}
                                events_list.update(new_value)

                    events_to_xsiam.append(events_list)

    elif isinstance(raw_events, list):
        full_event_list = raw_events
        for event in full_event_list:
            events_list = {}
            for key, value in event.items():

                if isinstance(value, int | str):
                    events_list[key] = value

                elif isinstance(value, dict):

                    dict_values_to_extract_back_to_list = value
                    events_list[key] = value

                    for item in dict_values_to_extract_back_to_list:
                        key = item
                        value = dict_values_to_extract_back_to_list[item]
                        new_value = {key: value}
                        events_list.update(new_value)

            events_to_xsiam.append(events_list)

    return events_to_xsiam


def get_log_timestamp(log):
    possible_fields = [
        'created',
        'time_created',
        'raised',
        'timestamp',
        'time',
        'date',
        'datetime',
        'log_time',
        'event_time',
        'event_timestamp',
        'generated',
        'logged',
        'log_timestamp',
        'entry_time',
        'entry_timestamp',
        'created_at',
        'raised_at',
        'time_logged',
        'start_time',
        'EventFirstSeen',
        'launchTime',
        'creation_date',
        'creation_time',
        'creationtime',
        'published',
        'generated_time',
        'raised_at',
        'event_created',
        'event_logged',
        'log_entry_time',
        'eventdate',
        'recorded_at',
        'recorded_time',
        'recorded',
        'event_datetime',
        'reported',
        'report_time',
        'report_timestamp',
        'logdate',
        'log_datetime',
        'time_raised',
        'eventtime',
        'eventime',
        'eventdate',
        'insert_at',
        'insert_time',

    ]

    for field in possible_fields:
        if field in log:
            return field

    raise ValueError("No valid timestamp field found in the log")


KNOWN_TIME_FORMATS = [
    "%d/%b/%Y:%H:%M:%S",
    "%a %b %d %H:%M:%S.%f %Y",
    "%y:%m:%d %H:%M:%S",
    "%Y %H:%M:%S",
    "%a %b %d %H:%M:%S.%f %Y",
    "%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.Z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d-%b-%Y %H:%M:%S",
    "%d/%b/%Y %H:%M:%S",
    "%b %d, %Y %H:%M:%S",
    "%Y.%m.%d %H:%M:%S",
    "%Y%m%dT%H%M%S",
    "%Y-%m-%d",
    "%d/%m/%Y",
    "%m/%d/%Y",
    "%b %d %Y",
    "%d %b %Y",
    "%Y%m%d"
]


def identify_time_format(log_source_time):

    # In case the time format is ISO 8601 - ISO supports 7 digits while datetime in python supports only 6,
    # so we need to reduce 1 number from the nanoseconds.
    if '.' in log_source_time:
        full_timestamp = re.split(".", log_source_time)

        timestamp_without_nanoseconds = full_timestamp[0]
        nanoseconds = full_timestamp[1]

        fractional = nanoseconds.rstrip('Z')[:6]  # Keep only the first 6 digits
        log_source_time = f"{timestamp_without_nanoseconds}.{fractional}Z"

    for fmt in KNOWN_TIME_FORMATS:
        try:
            datetime.strptime(log_source_time, fmt)
            return fmt
        except ValueError:
            pass
    return None


def get_time_field_from_event(events_list):
    event_time_field = None

    if len(events_list) > 0:
        event_sample = events_list[0]
    else:
        event_sample = None

    if event_sample is not None:
        for key in event_sample:
            if isinstance(event_sample[key], str):
                field_time_format = identify_time_format(events_list[0][key])
                if field_time_format:
                    event_time_field = key
                    break

    return event_time_field


def is_pagination_needed(events, pagination_logic):
    next_page_value = None
    pagination_needed = pagination_logic['pagination_needed']

    if pagination_needed == 'True':
        pagination_flag = pagination_logic['pagination_flag']
        if events[pagination_flag]:
            pagination_field = pagination_logic['pagination_field_name']
            next_page_value = events[pagination_field]
        else:
            pagination_needed = 'False'

    return pagination_needed, next_page_value


def fetch_events(client: Client, last_run, first_fetch_time, endpoint, method, request_data, request_json, query_params,
                 pagination_logic):
    # region Gets Last Time
    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
        first_fetch_for_this_integration = True
    else:
        # otherwise, use the stored last fetch
        last_fetch = int(last_fetch)
        first_fetch_for_this_integration = False

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of events to return
    # Each event is a dict with a string as a key
    event_list: list[dict[str, Any]] = []
    # endregion

    # region Gets events & Searches for pagination
    events = client.search_events(endpoint=endpoint, method=method, request_data=request_data, request_json=request_json,
                                  query_params=query_params)
    pagination_needed, next_page_value = is_pagination_needed(events, pagination_logic)
    raw_events_list = organize_events_to_xsiam_format(events)
    demisto.debug(f"{len(raw_events_list)} events fetched")

    while pagination_needed == 'True':
        request_json = {pagination_logic['pagination_field_name']: next_page_value}

        events = client.search_events(endpoint=endpoint, method=method, request_data=request_data, request_json=request_json,
                                      query_params=query_params)
        events_list = organize_events_to_xsiam_format(events)
        raw_events_list.extend(events_list)
        demisto.debug(f"{len(raw_events_list)} events fetched")
        pagination_needed, next_page_value = is_pagination_needed(events, pagination_logic)

    # endregion

    # region Collect all events based on their last fetch time.
    event_time_field = get_time_field_from_event(raw_events_list)

    if event_time_field:
        for event in raw_events_list:

            incident_created_time = event.get(event_time_field, '0')

            # In case the time format is ISO 8601 - ISO supports 7 digits while datetime in python supports only 6,
            # so we need to reduce 1 number from the nanoseconds
            if '.' in incident_created_time:
                full_timestamp = re.split(".", incident_created_time)
                timestamp_without_nanoseconds = full_timestamp[0]
                nanoseconds = full_timestamp[1]
                fractional = nanoseconds.rstrip('Z')[:6]  # Keep only the first 6 digits
                incident_created_time = f"{timestamp_without_nanoseconds}.{fractional}Z"

            log_source_time_format = identify_time_format(incident_created_time)
            incident_created_time_dt = datetime.strptime(incident_created_time, log_source_time_format)  # type: ignore
            unix_timestamp = int(incident_created_time_dt.timestamp())
            incident_created_time = unix_timestamp

            # to prevent duplicates, we are only adding events with creation_time > last fetched incident
            if incident_created_time > last_fetch:  # type: ignore
                demisto.debug(f'Pulling event.. {event}')
                event_list.append(event)
            else:
                demisto.debug('This event is to old to pull..')
                demisto.debug(f'Incident start time: {incident_created_time}..')

            if first_fetch_for_this_integration and incident_created_time > latest_created_time:
                demisto.debug(f'Pulling event.. {event}')
                event_list.append(event)

            # Update last run and add event if the event is newer than the last fetch
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

            demisto.debug('')
    else:
        demisto.debug('did not find any time field')
    # endregion

    # region Saves important parameters here to Integration context / last run
    demisto.debug(f'next_run.. {latest_created_time}')
    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    # endregion

    return next_run, event_list


def test_module(client,
                params,  # noqa
                first_fetch_time,  # noqa
                endpoint, method, request_data, request_json, query_params):
    try:
        events = client.search_events(endpoint=endpoint, method=method, request_data=request_data, request_json=request_json,
                                      query_params=query_params)

        demisto.debug(events)

    except DemistoException as e:

        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok', events


def format_header(params):
    headers = {}
    request_data = {}
    request_json = {}
    query_params = {}

    request_data_fields_to_add: Any = params.get('request_data')
    request_data_fields_to_add = str(request_data_fields_to_add)

    request_json_fields_to_add = params.get('request_json')
    request_json_fields_to_add = str(request_json_fields_to_add)

    query_params_fields_to_add = params.get('query_params')
    query_params_fields_to_add = str(query_params_fields_to_add)

    authentication = params.get('authentication')
    add_fields_to_header = params.get('add_fields_to_header')
    add_fields_to_header = str(add_fields_to_header)

    if authentication == 'Basic':
        username = params.get('username')
        password = params.get('password')

        # encode username and password in a basic authentication method
        auth_credentials = f'{username}:{password}'
        encoded_credentials = b64encode(auth_credentials.encode()).decode('utf-8')

        headers = {
            'Authorization': f'Basic {encoded_credentials}',
        }

    elif authentication == 'Bearer':
        token = params.get('token')
        headers = {
            'Authorization': f'Bearer {token}',
        }

    elif authentication == 'Token':
        token = params.get('token')
        headers = {
            'Authorization': f'Token {token}',
        }

    elif authentication == 'Api-Key':
        token = params.get('token')
        headers = {
            'api-key': f'{token}',
        }

    elif authentication == 'No Authorization':

        token = params.get('token')
        headers = {
            'Authorization': f'{token}',
        }

    if add_fields_to_header and add_fields_to_header != 'None':

        try:
            if add_fields_to_header[-2] == '\'' and add_fields_to_header[1] == '\'':
                add_fields_to_header = add_fields_to_header.replace("'", '"')

            add_fields = json.loads(add_fields_to_header)
            headers.update(add_fields)

        except requests.exceptions.ConnectionError as exception:
            err_msg = 'Please insert the data in a valid dictionary format'
            raise DemistoException(err_msg, exception) from exception

    if request_data_fields_to_add and request_data_fields_to_add != 'None':
        try:
            if request_data_fields_to_add[-2] == '\'' and request_data_fields_to_add[1] == '\'':
                request_data_fields_to_add = request_data_fields_to_add.replace("'", '"')

            add_params = json.loads(request_data_fields_to_add)
            request_data.update(add_params)

        except requests.exceptions.ConnectionError as exception:
            err_msg = 'Please insert the data in a valid dictionary format'
            raise DemistoException(err_msg, exception) from exception

    if request_json_fields_to_add and request_json_fields_to_add != 'None':
        try:
            if request_json_fields_to_add[-2] == '\'' and request_json_fields_to_add[1] == '\'':
                request_json_fields_to_add = request_json_fields_to_add.replace("'", '"')

            add_params = json.loads(request_json_fields_to_add)
            request_json.update(add_params)

        except requests.exceptions.ConnectionError as exception:
            err_msg = 'Please insert the data in a valid dictionary format'
            raise DemistoException(err_msg, exception) from exception

    if query_params_fields_to_add and query_params_fields_to_add != 'None':
        try:
            demisto.debug('3')
            if query_params_fields_to_add[-2] == '\'' and query_params_fields_to_add[1] == '\'':
                query_params_fields_to_add = query_params_fields_to_add.replace("'", '"')

            add_query_params = json.loads(query_params_fields_to_add)
            query_params.update(add_query_params)

        except requests.exceptions.ConnectionError as exception:
            err_msg = 'Please insert the data in a valid dictionary format'
            raise DemistoException(err_msg, exception) from exception

    return headers, request_data, request_json, query_params


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    # Create Base Classes
    params = demisto.params()
    # FIXME! revert before merging: `command = demisto.command()`

    # region Gets the service API url endpoint and method.
    base_url = params.get('base_url')
    endpoint = params.get('endpoint')
    http_method = params.get('http_method')

    pagination_needed = params.get('pagination_needed')
    pagination_field_name = params.get('pagination_field_name')
    pagination_flag = params.get('pagination_flag')
    pagination_logic = {'pagination_needed': pagination_needed,
                        'pagination_field_name': pagination_field_name,
                        'pagination_flag': pagination_flag
                        }
    # endregion

    # Collect headers & request queries
    headers, request_data, request_json, query_params = format_header(params)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )

    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # # Using `assert` as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    # Create a client object.
    client = Client(
        base_url=base_url,
        verify=False,
        headers=headers,
        proxy=proxy
    )
    command = 'fetch-events'

    if command == 'test-module':

        # This is the call made when pressing the integration Test button.
        test_type = params.get('test_type')

        result, events = test_module(
            client=client,
            params=params,
            first_fetch_time=first_fetch_timestamp,
            endpoint=endpoint,
            method=http_method,
            request_data=request_data,
            request_json=request_json,
            query_params=query_params
        )

        if test_type == 'push_to_dataset':
            # Fix The JSON Format to send to XSIAM dataset
            vendor = params.get('vendor').lower()
            product = params.get('product').lower()
            events_to_xsiam = organize_events_to_xsiam_format(events)
            send_events_to_xsiam(events_to_xsiam, vendor=vendor, product=product)  # noqa

        return_results(result)

    elif command == 'fetch-events':

        # # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
        # max_results = arg_to_number(
        #     arg=params.get('max_fetch'),
        #     arg_name='max_fetch',
        #     required=False
        # )
        #
        # if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
        #     max_results = MAX_INCIDENTS_TO_FETCH

        next_run, events = fetch_events(
            client=client,
            last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
            first_fetch_time=first_fetch_timestamp,
            endpoint=endpoint,
            method=http_method,
            request_data=request_data,
            request_json=request_json,
            query_params=query_params,
            pagination_logic=pagination_logic
        )

        # saves next_run for the time fetch-incidents are invoked
        demisto.setLastRun(next_run)

        # Fix The JSON Format to send to XSIAM dataset

        vendor = params.get('vendor').lower()
        product = params.get('product').lower()

        events_to_xsiam = organize_events_to_xsiam_format(events)
        send_events_to_xsiam(events_to_xsiam, vendor=vendor, product=product)  # noqa


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
