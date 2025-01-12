import contextlib

from CommonServerPython import *
import demistomock as demisto
from typing import Any, cast, Tuple  # noqa: UP035
from base64 import b64encode
from datetime import datetime
from distutils.util import strtobool

import json
import urllib3
import requests
import re

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 10_000
POSSIBLE_TIMESTAMP_FIELDS = [
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
VENDOR = 'generic'
PRODUCT = 'collector'


def str2bool(s: str) -> bool:
    return bool(strtobool(s))


class Client(BaseClient):
    """
    Client class to interact with the service API

    This Client implements API calls and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServerPython.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def search_events(self,
                      endpoint: str,
                      method: str,
                      request_data: dict[Any, Any],
                      request_json: dict[Any, Any],
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
    field = next((field for field in POSSIBLE_TIMESTAMP_FIELDS if field in log), None)
    if field:
        return field
    raise ValueError("No valid timestamp field found in the log")


def identify_time_format(log_source_time):
    log_source_time = iso8601_to_datetime_str(log_source_time)
    for fmt in KNOWN_TIME_FORMATS:
        with contextlib.suppress(ValueError):
            datetime.strptime(log_source_time, fmt)
            return fmt
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

    if pagination_needed:
        pagination_flag = pagination_logic['pagination_flag']
        if events[pagination_flag]:
            pagination_field = pagination_logic['pagination_field_name']
            next_page_value = str2bool(events[pagination_field])
        else:
            pagination_needed = False

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

    while pagination_needed:
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

            incident_created_time = iso8601_to_datetime_str(incident_created_time)

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
    else:
        demisto.debug('did not find any time field')
    # endregion

    # region Saves important parameters here to Integration context / last run
    demisto.debug(f'next_run.. {latest_created_time}')
    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    # endregion

    return next_run, event_list


def iso8601_to_datetime_str(iso8601_time: str) -> str:
    # In case the time format is ISO 8601 - ISO supports 7 digits while datetime in python supports only 6,
    # so we need to reduce 1 number from the nanoseconds
    if '.' in iso8601_time:
        timestamp_without_nanoseconds, nanoseconds = re.split("[.]", iso8601_time, maxsplit=1)
        fractional = nanoseconds.rstrip('Z')[:6]  # Keep only the first 6 digits.
        iso8601_time = f"{timestamp_without_nanoseconds}.{fractional}Z"
    return iso8601_time


def test_module(client: Client,
                params: dict,  # noqa
                first_fetch_time,  # noqa
                endpoint,
                method,
                request_data,
                request_json,
                query_params) -> Tuple[str, list[dict[str, Any]]]:
    try:
        events = client.search_events(endpoint=endpoint, method=method, request_data=request_data, request_json=request_json,
                                      query_params=query_params)
        demisto.debug(f"{events!s}")
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set', []
        else:
            raise e

    return 'ok', events


def try_load_json(json_str: str) -> dict:
    if json_str[-2] == '\'' and json_str[1] == '\'':
        json_str = json_str.replace("'", '"')
    return json.loads(json_str)


def format_header(params):
    request_data = {}
    request_json = {}
    query_params = {}

    request_data_fields_to_add: Any = params.get('request_data')
    request_data_fields_to_add = str(request_data_fields_to_add)

    request_json_fields_to_add = params.get('request_json')
    request_json_fields_to_add = str(request_json_fields_to_add)

    query_params_fields_to_add = params.get('query_params')
    query_params_fields_to_add = str(query_params_fields_to_add)

    add_fields_to_header = params.get('add_fields_to_header')
    add_fields_to_header = str(add_fields_to_header)

    headers = generate_authentication_headers(params)

    if add_fields_to_header and add_fields_to_header != 'None':
        try:
            demisto.debug("adding fields to header")
            headers.update(try_load_json(add_fields_to_header))
        except requests.exceptions.ConnectionError as exception:
            err_msg = 'Please insert the data in a valid dictionary format'
            demisto.error(err_msg)
            raise DemistoException(err_msg, exception) from exception

    if request_data_fields_to_add and request_data_fields_to_add != 'None':
        try:
            demisto.debug("adding request data")
            request_data.update(try_load_json(request_data_fields_to_add))
        except requests.exceptions.ConnectionError as exception:
            err_msg = 'Please insert the data in a valid dictionary format'
            demisto.error(err_msg)
            raise DemistoException(err_msg, exception) from exception

    if request_json_fields_to_add and request_json_fields_to_add != 'None':
        try:
            demisto.debug("adding request json")
            request_json.update(try_load_json(request_json_fields_to_add))
        except requests.exceptions.ConnectionError as exception:
            err_msg = 'Please insert the data in a valid dictionary format'
            demisto.error(err_msg)
            raise DemistoException(err_msg, exception) from exception

    if query_params_fields_to_add and query_params_fields_to_add != 'None':
        try:
            demisto.debug("adding query params")
            query_params.update(try_load_json(query_params_fields_to_add))
        except requests.exceptions.ConnectionError as exception:
            err_msg = 'Please insert the data in a valid dictionary format'
            demisto.error(err_msg)
            raise DemistoException(err_msg, exception) from exception

    return headers, request_data, request_json, query_params


def generate_authentication_headers(params: dict) -> dict:
    authentication = params.get('authentication')
    if authentication == 'Basic':
        username = params.get('username')
        password = params.get('password')
        add_sensitive_log_strs(password)
        demisto.debug("fAuthenticating with Basic Authentication, username: {username}")
        # encode username and password in a basic authentication method
        auth_credentials = f'{username}:{password}'
        encoded_credentials = b64encode(auth_credentials.encode()).decode('utf-8')
        headers = {
            'Authorization': f'Basic {encoded_credentials}',
        }
    elif authentication == 'Bearer':
        demisto.debug("fAuthenticating with Bearer Authentication")
        token = params.get('token')
        add_sensitive_log_strs(token)
        headers = {
            'Authorization': f'Bearer {token}',
        }
    elif authentication == 'Token':
        demisto.debug("fAuthenticating with Token Authentication")
        token = params.get('token')
        add_sensitive_log_strs(token)
        headers = {
            'Authorization': f'Token {token}',
        }
    elif authentication == 'Api-Key':
        demisto.debug("fAuthenticating with Api-Key Authentication")
        token = params.get('token')
        add_sensitive_log_strs(token)
        headers = {
            'api-key': f'{token}',
        }
    elif authentication == 'No Authorization':
        demisto.debug("fAuthenticating with No Authorization, just with token")
        token = params.get('token')
        add_sensitive_log_strs(token)
        headers = {
            'Authorization': f'{token}',
        }
    else:
        err_msg = (f"Please insert a valid authentication method, options are: Basic, Bearer, Token, Api-Key, "
                   f"No Authorization, got: {authentication}")
        demisto.error(err_msg)
        raise DemistoException(err_msg)
    return headers


def main() -> None:
    """
    main function, parses params and runs command functions.
    """
    # Create Base Classes
    params = demisto.params()

    # region Gets the service API url endpoint and method.
    base_url = params.get('base_url')
    endpoint = params.get('endpoint')
    http_method = params.get('http_method')
    demisto.debug(f"base url: {base_url}, endpoint: {endpoint}, http method: {http_method}")
    if not base_url:
        raise DemistoException('Base URL is missing')
    if not endpoint:
        raise DemistoException('Endpoint is missing')
    if not http_method:
        raise DemistoException('HTTP method is missing')
    if http_method not in ['GET', 'POST']:
        raise DemistoException('HTTP method is not valid, please choose between GET and POST')
    # endregion

    # region Pagination logic
    pagination_needed = str2bool(params.get('pagination_needed'))
    pagination_field_name = params.get('pagination_field_name')
    pagination_flag = params.get('pagination_flag')
    pagination_logic = {
        'pagination_needed': pagination_needed,
        'pagination_field_name': pagination_field_name,
        'pagination_flag': pagination_flag
    }
    demisto.debug(f"Pagination logic - pagination_needed: {pagination_needed}, "
                  f"pagination_field_name: {pagination_field_name}, pagination_flag: {pagination_flag}")
    if pagination_needed:
        if not pagination_field_name:
            raise DemistoException('Pagination field name is missing')
        if not pagination_flag:
            raise DemistoException('Pagination flag is missing')
    # endregion

    # Collect headers & request queries.
    headers, request_data, request_json, query_params = format_header(params)

    # How much time before the first fetch to retrieve incidents.
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )

    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    if not isinstance(first_fetch_timestamp, int):
        raise DemistoException(f"First fetch time is not an integer: {first_fetch_timestamp}")

    # if your Client class inherits from BaseClient, it handles system proxy
    # out of the box, pass ``proxy`` to the Client constructor.
    proxy = params.get('proxy', False)

    # Create a client object.
    client = Client(
        base_url=base_url,
        verify=False,
        headers=headers,
        proxy=proxy
    )
    # FIXME! revert before merging: `command = demisto.command()`
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
            demisto.debug(f"Vendor: {vendor}, Product: {product}")
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
            last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict.
            first_fetch_time=first_fetch_timestamp,
            endpoint=endpoint,
            method=http_method,
            request_data=request_data,
            request_json=request_json,
            query_params=query_params,
            pagination_logic=pagination_logic
        )

        # saves next_run for the time fetch-incidents are invoked.
        demisto.setLastRun(next_run)
        vendor = params.get('vendor').lower()
        product = params.get('product').lower()
        demisto.debug(f"Vendor: {vendor}, Product: {product}")

        # Fix The JSON Format to send to XSIAM dataset.
        events_to_xsiam = organize_events_to_xsiam_format(events)
        send_events_to_xsiam(events_to_xsiam, vendor=vendor, product=product)  # noqa


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
