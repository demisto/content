import contextlib
import copy
import enum
from json import JSONDecodeError
from CommonServerPython import *
import demistomock as demisto
from typing import Any  # noqa: UP035
from base64 import b64encode
from datetime import datetime
# from distutils.util import strtobool

import json
import urllib3
import re
from collections import namedtuple

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEFAULT_LIMIT = "1000"
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
PaginationLogic = namedtuple(
    "PaginationLogic",
    (
        "pagination_needed",
        "pagination_field_name",
        "pagination_flag",
    ),
    defaults=(False, '', ''),
)
TimestampFieldConfig = namedtuple(
    "TimestampFieldConfig",
    (
        "timestamp_field_name",
        "timestamp_format",
    ),
    defaults=("", DATE_FORMAT),
)


class PlaceHolders(enum.Enum):
    LAST_FETCHED_ID = "@last_fetched_id"
    LAST_FETCHED_DATETIME = "@last_fetched_datetime"
    FIRST_FETCH_DATETIME = "@first_fetch_datetime"


# def str2bool(s: str | bool) -> bool:
#     if isinstance(s, bool):
#         return s
#     return bool(strtobool(s))


def recursive_replace(org_dict: dict[Any, Any], substitutions: list[tuple[Any, Any]]) -> dict[Any, Any]:
    # Create a deep copy of the dictionary to avoid modifying the original
    copy_dict = copy.deepcopy(org_dict)

    for key, value in copy_dict.items():
        if isinstance(value, dict):
            # If value is a dictionary, recursively call this function
            copy_dict[key] = recursive_replace(value, substitutions)
        elif isinstance(value, str):
            # If value is a string, perform substitutions
            for old, new in substitutions:
                value = value.replace(old, new)
            copy_dict[key] = value

    return copy_dict


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
                      http_method: str,
                      request_data: dict[Any, Any],
                      request_json: dict[Any, Any],
                      query_params: dict[Any, Any]) -> dict[Any, Any]:
        """
        Searches for events using the API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            endpoint: API endpoint to send the request to.
            http_method: HTTP method to use in the request.
            request_data: data to send in the body of the request.
            request_json: JSON data to send in the body of the request.
            query_params: query parameters to send in the request.
        Returns:
            list: list of events as dicts.
        """
        return self._http_request(  # type: ignore
            method=http_method,
            url_suffix=endpoint,
            json_data=request_json,
            data=request_data,
            params=query_params,
        )


def organize_events_to_xsiam_format(raw_events: Any, events_keys: list[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = dict_safe_get(raw_events, events_keys, [], list, True)  # type: ignore
    return events


# region Auto-detection functionality
def detect_where_is_the_events_to_xsiam_format(events):
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


# endregion


def get_time_field_from_event_to_dt(event: dict[str, Any], timestamp_field_config: TimestampFieldConfig) -> datetime:
    timestamp: str | None = dict_safe_get(event, timestamp_field_config.timestamp_field_name, return_type=str)  # noqa
    if timestamp is None:
        raise DemistoException(f"Timestamp field: {timestamp_field_config.timestamp_field_name} not found in event")
    timestamp_str: str = iso8601_to_datetime_str(timestamp)
    # Convert the timestamp to the desired format.
    return datetime.strptime(timestamp_str, timestamp_field_config.timestamp_format)


def is_pagination_needed(events: dict[Any, Any], pagination_logic: PaginationLogic) -> tuple[bool, Any]:
    next_page_value = None
    if pagination_needed := pagination_logic.pagination_needed:
        if events[pagination_logic.pagination_flag]:
            pagination_needed = True
            next_page_value = events[pagination_logic.pagination_field_name]
        else:
            pagination_needed = False

    return pagination_needed, next_page_value


def fetch_events(client: Client,
                 params: dict[str, Any],
                 last_run: dict[Any, Any],
                 first_fetch_datetime: datetime,
                 endpoint: str,
                 http_method: str,
                 pagination_logic: PaginationLogic,
                 events_keys: list[str],
                 timestamp_field_config: TimestampFieldConfig) -> tuple[dict[Any, Any], list[dict[Any, Any]]]:
    # region Gets first fetch time.
    if PlaceHolders.FIRST_FETCH_DATETIME.value not in last_run:
        last_run[PlaceHolders.FIRST_FETCH_DATETIME.value] = first_fetch_datetime.strftime(timestamp_field_config.timestamp_format)
    # endregion

    # region Handle first fetch time
    last_fetched_datetime_str: str | None = last_run.get(PlaceHolders.LAST_FETCHED_DATETIME.value)
    if last_fetched_datetime_str is None:
        # if missing, use what provided via first_fetch_timestamp
        last_fetched_datetime: datetime = first_fetch_datetime
        first_fetch_for_this_integration: bool = True
    else:
        # otherwise, use the stored last fetch
        last_fetched_datetime = datetime.fromisoformat(last_fetched_datetime_str)
        first_fetch_for_this_integration = False
    # endregion

    # region load request arguments
    request_data: dict[Any, Any] = parse_json_param(params.get('request_data'), 'request_data')
    request_json: dict[Any, Any] = parse_json_param(params.get('request_json'), 'request_json')
    query_params: dict[Any, Any] = parse_json_param(params.get('query_params'), 'query_params')

    # If we've an initial query argument, we try with it.
    if first_fetch_for_this_integration:
        if params.get('initial_query_params'):
            query_params = parse_json_param(params.get('initial_query_params'), 'initial_query_params')
        if params.get('initial_pagination_params'):
            pagination_logic = extract_pagination_params(params.get('initial_pagination_params'))

    latest_created_datetime: datetime = last_fetched_datetime
    last_fetched_id: str | None = None
    # endregion

    # region Handle substitutions
    substitutions: list[tuple[str, str]] = [
        (place_holder.value, last_run.get(place_holder.value)) for place_holder in PlaceHolders  # type: ignore[misc]
        if last_run.get(place_holder.value) is not None
    ]
    substitutions_query_params: dict[Any, Any] = recursive_replace(query_params, substitutions)
    substitutions_request_json: dict[Any, Any] = recursive_replace(request_json, substitutions)
    substitutions_request_data: dict[Any, Any] = recursive_replace(request_data, substitutions)
    # endregion

    # region Gets events & Searches for pagination

    all_events_list: list[dict[str, Any]] = []
    pagination_needed: bool = True
    id_keys: list[str] = argToList(params.get('id_keys', '.'))
    while pagination_needed:

        raw_events = client.search_events(endpoint=endpoint,
                                          http_method=http_method,
                                          request_data=substitutions_request_data,
                                          request_json=substitutions_request_json,
                                          query_params=substitutions_query_params)
        events_list = organize_events_to_xsiam_format(raw_events, events_keys)
        all_events_list.extend(events_list)
        demisto.debug(f"{len(all_events_list)} events fetched")
        pagination_needed, next_page_value = is_pagination_needed(raw_events, pagination_logic)
        if pagination_needed:
            request_json[pagination_logic.pagination_field_name] = next_page_value

    # endregion

    # region Collect all events based on their last fetch time.
    returned_event_list: list[dict[str, Any]] = []
    for event in all_events_list:

        incident_created_dt = get_time_field_from_event_to_dt(event, timestamp_field_config)
        event['_time'] = incident_created_dt.isoformat()

        # to prevent duplicates, we are only adding events with creation_time > last fetched incident
        if incident_created_dt > last_fetched_datetime:
            demisto.debug(f'Pulling event.. {event}')
            returned_event_list.append(event)
            latest_created_datetime = max(latest_created_datetime, incident_created_dt)
        else:
            demisto.debug(f'This event is to old to pull, creation time: {incident_created_dt}')

        # Handle the last event id.
        if id_keys:
            current_id: str = dict_safe_get(event, id_keys)  # noqa
            if last_fetched_id is None:
                last_fetched_id = current_id
            else:
                last_fetched_id = max(last_fetched_id, current_id)

    # region Saves important parameters here to Integration context / last run
    demisto.debug(f'next run:{latest_created_datetime}')
    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {
        PlaceHolders.LAST_FETCHED_DATETIME.value: latest_created_datetime.isoformat(),
        PlaceHolders.LAST_FETCHED_ID.value: str(last_fetched_id),
        PlaceHolders.FIRST_FETCH_DATETIME.value: last_run[PlaceHolders.FIRST_FETCH_DATETIME.value],
    }
    # endregion

    return next_run, returned_event_list


def iso8601_to_datetime_str(iso8601_time: str) -> str:
    # In case the time format is ISO 8601 - ISO supports 7 digits while datetime in python supports only 6,
    # so we need to reduce 1 number from the nanoseconds
    if '.' in iso8601_time:
        timestamp_without_nanoseconds, nanoseconds = re.split("[.]", iso8601_time, maxsplit=1)
        fractional = nanoseconds.rstrip('Z')[:6]  # Keep only the first 6 digits.
        iso8601_time = f"{timestamp_without_nanoseconds}.{fractional}Z"
    return iso8601_time


def test_module(client: Client,
                endpoint: str,
                http_method: str,
                request_data: dict[Any, Any],
                request_json: dict[Any, Any],
                query_params: dict[Any, Any]):
    try:
        events = client.search_events(endpoint=endpoint,
                                      http_method=http_method,
                                      request_data=request_data,
                                      request_json=request_json,
                                      query_params=query_params)
        demisto.debug(f"{events!s}")
    except DemistoException as e:
        error = str(e)
        if 'Forbidden' in error or 'Unauthorized' in error:
            return_error('Authorization Error: make sure Username/Password/Token is correctly set')
        else:
            raise e

    return_results("ok")


def try_load_json(json_str: str) -> dict:
    if isinstance(json_str, dict):
        return json_str
    if isinstance(json_str, str) and json_str[-2] == '\'' and json_str[1] == '\'':
        json_str = json_str.replace("'", '"')
    return json.loads(json_str)


def parse_json_param(json_param_value: Any, json_param_name) -> dict[Any, Any]:
    if json_param_value and json_param_value != 'None':
        try:
            demisto.debug(f"parsing argument: {json_param_name}")
            return try_load_json(json_param_value)
        except JSONDecodeError as exception:
            err_msg = f"Argument {json_param_name} could not be parsed as a valid JSON: {exception}"
            demisto.error(err_msg)
            raise DemistoException(err_msg, exception) from exception
        except KeyError as exception:
            err_msg = f"Argument {json_param_name} could not be parsed: {exception}"
            demisto.error(err_msg)
            raise DemistoException(err_msg, exception) from exception
    return {}


def generate_headers(params: dict[str, Any]) -> dict[Any, Any]:

    headers = generate_authentication_headers(params)
    if add_fields_to_header := str(params.get('add_fields_to_header')):
        headers.update(parse_json_param(add_fields_to_header, 'add_fields_to_header'))
    return headers


def generate_authentication_headers(params: dict[Any, Any]) -> dict[Any, Any]:
    authentication = params.get('authentication')
    if authentication == 'Basic':
        username = params.get("credentials", {}).get("identifier")
        password = params.get("credentials", {}).get("password")
        if password:
            add_sensitive_log_strs(password)
        demisto.debug(f"Authenticating with Basic Authentication, username: {username}")
        # encode username and password in a basic authentication method
        auth_credentials = f'{username}:{password}'
        encoded_credentials = b64encode(auth_credentials.encode()).decode('utf-8')
        add_sensitive_log_strs(encoded_credentials)
        headers = {
            'Authorization': f'Basic {encoded_credentials}',
        }
    elif authentication == 'Bearer':
        demisto.debug("Authenticating with Bearer Authentication")
        token = params.get('token')
        if token:
            add_sensitive_log_strs(token)
        headers = {
            'Authorization': f'Bearer {token}',
        }
    elif authentication == 'Token':
        demisto.debug("Authenticating with Token Authentication")
        token = params.get('token')
        if token:
            add_sensitive_log_strs(token)
        headers = {
            'Authorization': f'Token {token}',
        }
    elif authentication == 'Api-Key':
        demisto.debug("Authenticating with Api-Key Authentication")
        token = params.get('token')
        if token:
            add_sensitive_log_strs(token)
        headers = {
            'api-key': f'{token}',
        }
    elif authentication == 'RawToken':
        demisto.debug("Authenticating with raw token")
        token = params.get('token')
        if token:
            add_sensitive_log_strs(token)
        headers = {
            'Authorization': f'{token}',
        }
    elif authentication == 'No Authorization':
        demisto.debug("Connecting without Authorization")
        headers = {}
    else:
        err_msg = ("Please insert a valid authentication method, options are: Basic, Bearer, Token, Api-Key, RawToken"
                   f"No Authorization, got: {authentication}")
        demisto.error(err_msg)
        raise DemistoException(err_msg)
    return headers


def get_events_command(client: Client,
                       endpoint: str,
                       http_method: str,
                       request_data: dict[Any, Any],
                       request_json: dict[Any, Any],
                       query_params: dict[Any, Any],
                       limit: int) -> tuple[Dict[str, Any], CommandResults]:
    """
    Fetch events from AWS Security Hub.

    Args:
        query_params:
        request_json:
        request_data:
        http_method:
        endpoint:
        client (Client):
        limit (int, optional): Maximum number of events to fetch, Defaults to 0 (no limit).

    Returns:
        CommandResults: CommandResults containing the events.
    """
    events = client.search_events(endpoint=endpoint,
                                  http_method=http_method,
                                  request_data=request_data,
                                  request_json=request_json,
                                  query_params=query_params)
    return events, CommandResults(
        readable_output=tableToMarkdown('Generic Events', events[:limit], sort_headers=False),
    )


def main() -> None:
    """
    main function, parses params and runs command functions.
    """
    try:
        params = demisto.params()

        # region Gets the service API url endpoint and method.
        base_url: str = params.get('base_url')
        endpoint: str = params.get('endpoint')
        http_method: str | None = params.get('http_method')
        demisto.debug(f"base url: {base_url}, endpoint: {endpoint}, http method: {http_method}")
        if not base_url:
            raise DemistoException('Base URL is missing')
        if not endpoint:
            raise DemistoException('Endpoint is missing')
        if not http_method:
            raise DemistoException('HTTP method is missing')
        if not http_method or http_method.upper() not in ['GET', 'POST']:
            raise DemistoException('HTTP method is not valid, please choose between GET and POST')
        # endregion

        # region Gets the timestamp field configuration
        if not (timestamp_field_name_param := params.get('timestamp_field_name')):
            raise DemistoException('Timestamp field is missing')
        timestamp_field_name: list[str] = argToList(timestamp_field_name_param, '.')
        timestamp_field_config = TimestampFieldConfig(timestamp_field_name, params.get('timestamp_format', DATE_FORMAT))
        demisto.debug(f"Timestamp field configuration - field_name: {timestamp_field_config.timestamp_field_name}, "
                      f"format: {timestamp_field_config.timestamp_format}")
        # endregion

        # region Pagination logic
        pagination_logic = extract_pagination_params(params)
        # endregion

        # region Gets the events keys
        events_keys: list[str] = argToList(params.get('events_keys'), '.')
        demisto.debug(f"Events keys: {events_keys}")
        # endregion

        # How much time before the first fetch to retrieve incidents.
        first_fetch_datetime: datetime = arg_to_datetime(  # type: ignore[assignment]
            arg=params.get('first_fetch', '3 days'),
            arg_name='First fetch time',
            required=True
        )

        # if your Client class inherits from BaseClient, it handles system proxy
        # out of the box, pass ``proxy`` to the Client constructor.
        proxy: bool = argToBoolean(params.get('proxy', False))
        verify: bool = not argToBoolean(params.get('insecure', False))

        # Create a client object.
        client = Client(
            base_url=base_url,
            verify=verify,
            headers=generate_headers(params),
            proxy=proxy
        )
        vendor: str = params.get('vendor').lower()
        raw_product: str = params.get('product').lower()
        product: str = f"{raw_product}_generic"
        demisto.debug(f"Vendor: {vendor}, Raw Product: {raw_product}, Product: {product}")

        command: str = demisto.command()
        demisto.debug(f"Command being called is {command}")
        if command == 'test-module':
            test_module(
                client=client,
                endpoint=endpoint,
                http_method=http_method,
                request_data=parse_json_param(params.get('request_data'), 'request_data'),
                request_json=parse_json_param(params.get('request_json'), 'request_json'),
                query_params=parse_json_param(params.get('query_params'), 'query_params'),
            )

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
                params=params,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict.
                first_fetch_datetime=first_fetch_datetime,
                endpoint=endpoint,
                http_method=http_method,
                pagination_logic=pagination_logic,
                events_keys=events_keys,
                timestamp_field_config=timestamp_field_config,
            )

            # saves next_run for the time fetch-incidents are invoked.
            demisto.setLastRun(next_run)

            # Fix The JSON Format to send to XSIAM dataset.
            events_to_xsiam = organize_events_to_xsiam_format(events, events_keys)
            send_events_to_xsiam(events_to_xsiam, vendor=vendor, product=product)  # noqa
        elif command == "generic-event-collector-get-events":
            args: dict[Any, Any] = demisto.args()
            should_push_events: bool = argToBoolean(args.get("should_push_events"))
            limit: int = arg_to_number(args.get("limit", DEFAULT_LIMIT), "limit", True)  # type: ignore[assignment]
            raw_events, results = get_events_command(client, endpoint, http_method,
                                                     request_data=parse_json_param(params.get('request_data'), 'request_data'),
                                                     request_json=parse_json_param(params.get('request_json'), 'request_json'),
                                                     query_params=parse_json_param(params.get('query_params'), 'query_params'),
                                                     limit=limit)

            return_results(results)

            if should_push_events:
                events = organize_events_to_xsiam_format(raw_events, events_keys)
                send_events_to_xsiam(events, vendor=vendor, product=product)  # noqa
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


def extract_pagination_params(params):
    pagination_needed: bool = argToBoolean(params.get('pagination_needed', False))
    pagination_field_name: str | None = params.get('pagination_field_name')
    pagination_flag: str | None = params.get('pagination_flag')
    pagination_logic = PaginationLogic(pagination_needed, pagination_field_name, pagination_flag)
    demisto.debug(f"Pagination logic - pagination_needed: {pagination_logic.pagination_needed}, "
                  f"pagination_field_name: {pagination_logic.pagination_field_name}, "
                  f"pagination_flag: {pagination_logic.pagination_flag}")
    if pagination_logic.pagination_needed:
        if not pagination_logic.pagination_field_name:
            raise DemistoException('Pagination field name is missing')
        if not pagination_logic.pagination_flag:
            raise DemistoException('Pagination flag is missing')
    return pagination_logic


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
