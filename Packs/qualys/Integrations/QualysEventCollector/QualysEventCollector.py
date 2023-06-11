import copy
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Optional, Any
import urllib3
import csv
import io

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_SUFFIX = "/api/2.0/fo/"
VENDOR = 'qualys'
PRODUCT = 'qualys'
BEGIN_RESPONSE_LOGS_CSV = "----BEGIN_RESPONSE_BODY_CSV"
END_RESPONSE_LOGS_CSV = "----END_RESPONSE_BODY_CSV"
BEGIN_RESPONSE_FOOTER_CSV = "----BEGIN_RESPONSE_FOOTER_CSV"
END_RESPONSE_FOOTER_CSV = "----END_RESPONSE_FOOTER_CSV"

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url, username, password, verify=True, proxy=False, headers=None):
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers, auth=(username, password))

    @staticmethod
    def error_handler(res):
        """ Handles error on API request to Qyalys """
        err_msg = f"Error in API call [{res.status_code}] - {res.reason}"
        try:
            simple_response = get_simple_response_from_raw(parse_raw_response(res.text))
            err_msg = f'{err_msg}\nError Code: {simple_response.get("CODE")}\nError Message: {simple_response.get("TEXT")}'
        except Exception:
            raise DemistoException(err_msg, res=res)

    def get_user_activity_logs(self, since_datetime: str, max_fetch: int = 0) -> Union[str, bytes]:
        """
        Make a http request to Qualys API to get user activities logs
        Args:
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        self._headers.update({"Content-Type": 'application/json'})
        params: Dict[str, Any] = {
            "truncation_limit": max_fetch
        }
        if since_datetime:
            params["since_datetime"] = since_datetime

        response = self._http_request(
            method='GET',
            url_suffix=urljoin(API_SUFFIX, 'activity_log/?action=list'),
            resp_type='text/csv',
            params=params,
            timeout=60,
            error_handler=self.error_handler,
        )

        return response.text

    def get_host_list_detection(self, since_datetime: str, max_fetch: int = 0) -> Union[str, bytes]:
        """
        Make a http request to Qualys API to get user activities logs
        Args:
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        self._headers.update({"Content-Type": 'application/json'})
        params: Dict[str, Any] = {
            "truncation_limit": max_fetch
        }
        if since_datetime:
            params["vm_scan_date_after"] = since_datetime

        response = self._http_request(
            method='GET',
            url_suffix=urljoin(API_SUFFIX, 'asset/host/vm/detection/?action=list'),
            resp_type='text',
            params=params,
            timeout=60,
            error_handler=self.error_handler,
        )

        return response


def get_partial_response(response: str, start: str, end: str):
    """ Cut response string from start to end tokens.
    """
    if start not in response or end not in response:
        return response
    start_index = response.index(start) + len(start)
    end_index = response.index(end)
    result = response[start_index:end_index].strip()
    return result


def csv2json(csv_data: str):
    """ Converts data from csv to json
    Args:
        csv_data: data in csv format
    Returns:
        the same data in json formal
    """
    reader = csv.DictReader(io.StringIO(csv_data))
    json_data = list(reader)
    return json_data


def handle_host_list_detection_result(raw_response: requests.Response) -> Optional[List]:
    """
    Handles Host list detection response - parses xml to json and gets the list
    Args:
        raw_response (requests.Response): the raw result received from Qualys API command
    Returns:
        List with data generated for the result given
    """
    formatted_response = parse_raw_response(raw_response)
    simple_response = get_simple_response_from_raw(formatted_response)
    if simple_response and simple_response.get("CODE"):
        raise DemistoException(f"\n{simple_response.get('TEXT')} \nCode: {simple_response.get('CODE')}")

    response_requested_value = dict_safe_get(formatted_response,
                                             ["HOST_LIST_VM_DETECTION_OUTPUT", "RESPONSE", "HOST_LIST", "HOST"])
    if isinstance(response_requested_value, dict):
        response_requested_value = [response_requested_value]

    return response_requested_value


def parse_raw_response(response: Union[bytes, requests.Response]) -> Dict:
    """
    Parses raw response from Qualys.
    Tries to load as JSON. If fails to do so, tries to load as XML.
    If both fails, returns an empty dict.
    Args:
        response (Union[bytes, requests.Response]): Response from Qualys service.

    Returns:
        (Dict): Dict representing the data returned by Qualys service.
    """
    return json.loads(xml2json(response))


def get_simple_response_from_raw(raw_response: Any) -> Union[Any, Dict]:
    """
    Gets the simple response from a given JSON dict structure returned by Qualys service
    If object is not a dict, returns the response as is.
    Args:
        raw_response (Any): Raw response from Qualys service.

    Returns:
        (Union[Any, Dict]): Simple response path if object is a dict, else response as is.
    """
    simple_response = None
    if raw_response and isinstance(raw_response, dict):
        simple_response = raw_response.get("SIMPLE_RETURN", {}).get("RESPONSE", {})
    return simple_response


def remove_events_before_last_scan(events, last_run):
    try:
        edited_events = []
        for event in events:
            if first_found := event.get('DETECTION', {}).get('FIRST_FOUND_DATETIME'):
                if datetime.strptime(first_found, DATE_FORMAT) < datetime.strptime(last_run, DATE_FORMAT):
                    demisto.debug(
                        f'Removed event with time: {first_found}, qid: {event.get("DETECTION", {}).get("ID")}')
                else:
                    edited_events.append(event)
        return edited_events
    except Exception as e:
        raise Exception(f'Failed to remove previous events. Error:{str(e)}')


def remove_last_events(events, time_to_remove, time_field):
    """ Removes events with certain time.
        Args:
            events: list of events to remove the time from
            time_to_remove: remove events with this time
            time_field: the field name where the time is
    """
    new_events = []
    for event in events:
        if event.get(time_field) == time_to_remove:
            demisto.debug(f'Removed activity log event with time: {time_to_remove}, log: {event}')
        else:
            new_events.append(event)
    return new_events


def add_fields_to_events(events, time_field_path, event_type_field):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
        time_field_path: the list of fields to get _time from
        event_type_field: type field in order to distinguish between the API's
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            event['_time'] = dict_safe_get(event, time_field_path)
            event['event_type'] = event_type_field


def get_detections_from_hosts(hosts):
    """
    Parses detections from hosts.
    Each host contains list of detections:
    {'ID':1,
    'IP': '1.1.1.1',
    'LAST_VM_SCANNED_DATE': '01-01-2020',
    'DETECTION_LIST': {'DETECTION': [first_detection_data, second_detection, ...]}
    'additional_fields': ...
    }

    The function parses the data in the following way:
    {''ID':1,
    'IP': '1.1.1.1',
    'LAST_VM_SCANNED_DATE': '01-01-2020',
    'DETECTION': first_detection_data
    'additional_fields': ...
    },
    {'ID':1,
    'IP': '1.1.1.1',
    'LAST_VM_SCANNED_DATE': '01-01-2020',
    'DETECTION': second_detection_data
    'additional_fields': ...
    }
    ....

    :param hosts: list of hosts that contains detections.
    :return: parsed events.
    """
    fetched_events = []
    for host in hosts:
        if detections_list := host.get('DETECTION_LIST', {}).get('DETECTION'):
            if isinstance(detections_list, list):
                for detection in detections_list:
                    new_detection = copy.deepcopy(host)
                    del new_detection['DETECTION_LIST']
                    new_detection['DETECTION'] = detection
                    fetched_events.append(new_detection)
            elif isinstance(detections_list, dict):
                new_detection = copy.deepcopy(host)
                new_detection['DETECTION'] = detections_list
                fetched_events.append(new_detection)
        else:
            del host['DETECTION_LIST']
            host['DETECTION'] = {}
            fetched_events.append(host)
    return fetched_events


def get_activity_logs_events(client, last_run, max_fetch) -> tuple[Optional[list], dict]:
    """ Get logs activity from qualys
    Args:
        client: Qualys client
        last_run: datetime to get events from
        max_fetch: max number of events to return
    Returns:
        Logs activity events, Next run datetime
    """
    demisto.debug(f'Starting to fetch activity logs events: {last_run=}')

    activity_logs = client.get_user_activity_logs(since_datetime=last_run, max_fetch=max_fetch)
    activity_logs_events = csv2json(get_partial_response(activity_logs, BEGIN_RESPONSE_LOGS_CSV,
                                                         END_RESPONSE_LOGS_CSV)) or []
    demisto.debug(f'Got activity logs events from server: {len(activity_logs_events)=}.')

    next_run = activity_logs_events[0].get('Date') if activity_logs_events else last_run
    activity_logs_events = remove_last_events(activity_logs_events, next_run, 'Date')
    add_fields_to_events(activity_logs_events, ['Date'], 'activity_log')

    next_run_dict = {'activity_logs': next_run}
    demisto.debug(f'Done to fetch activity logs events: {next_run_dict=}, sending {len(activity_logs_events)} events.')
    return activity_logs_events, next_run_dict


def get_host_list_detections_events(client, last_run, max_fetch) -> tuple[Optional[list], dict]:
    """ Get host list detections from qualys
    Args:
        client: Qualys client
        last_run: datetime to get events from
        max_fetch: max number of events to return
    Returns:
        Host list detections events, Next run datetime
    """
    demisto.debug(f'Starting to fetch host list events: {last_run=}')

    host_list_detections = client.get_host_list_detection(since_datetime=last_run, max_fetch=max_fetch)
    host_list_events = handle_host_list_detection_result(host_list_detections) or {}
    next_run = host_list_events[0].get('LAST_VM_SCANNED_DATE') if host_list_events else last_run

    edited_host_detections = get_detections_from_hosts(host_list_events)
    demisto.debug(f'Parsed detections from hosts, got {len(edited_host_detections)=} events.')

    edited_host_detections = remove_events_before_last_scan(edited_host_detections, last_run)

    add_fields_to_events(edited_host_detections, ['DETECTION', 'FIRST_FOUND_DATETIME'], 'host_list_detection')

    next_run_dict = {
        'host_list_detection': next_run,
        'host_last_fetch': datetime.now().strftime(DATE_FORMAT)
    }
    demisto.debug(f'Done to fetch host list events: {next_run_dict=}, sending {len(edited_host_detections)} events.')

    return edited_host_detections, next_run_dict


def fetch_events(client, last_run, last_run_field, first_fetch_time, fetch_function, max_fetch: int = 0):
    """ Fetches activity logs and host list detections
    Args:
        client: command client
        last_run: last fetch time
        last_run_field: last run field in last run dictionary
        first_fetch_time: when start to fetch from
        fetch_function: function that gets the events
        max_fetch: max number of items to return (0 to return all)

    Return:
        next_last_run: where to fetch from next time
        event: events to push to xsiam
    """
    last_run_time = last_run.get(last_run_field) if last_run else None

    if not last_run_time:
        last_run_time = first_fetch_time

    events, next_run = fetch_function(client, last_run_time, max_fetch)
    return next_run, events


def get_activity_logs_events_command(client, args, first_fetch_time):
    """
    Args:
        client: command client
        args: Demisto args for this command: limit and since_datetime
    Retuns:
        Command results with activity logs

    """
    limit = arg_to_number(args.get('limit', 50))
    offset = arg_to_number(args.get('offset', 0))
    since_datetime = arg_to_datetime(args.get('since_datetime'))
    last_run = since_datetime.strftime(DATE_FORMAT) if since_datetime else first_fetch_time
    activity_logs_events, _ = get_activity_logs_events(
        client=client,
        last_run=last_run,
        max_fetch=0,
    )
    limited_activity_logs_events = activity_logs_events[offset:limit + offset]
    activity_logs_hr = tableToMarkdown(name='Activity Logs', t=limited_activity_logs_events)
    results = CommandResults(
        readable_output=activity_logs_hr,
        raw_response=limited_activity_logs_events,
    )

    return limited_activity_logs_events, results


def get_host_list_detections_events_command(client, args, first_fetch_time):
    """
    Args:
        client: command client
        args: Demisto args for this command: limit and since_datetime
    Retuns:
        Command results with host list detections

    """
    limit = arg_to_number(args.get('limit', 50))
    offset = arg_to_number(args.get('offset', 0))
    since_datetime = arg_to_datetime(args.get('vm_scan_date_after'))
    last_run = since_datetime.strftime(DATE_FORMAT) if since_datetime else first_fetch_time

    host_list_detection_events, _ = get_host_list_detections_events(
        client=client,
        last_run=last_run,
        max_fetch=0,
    )
    limited_host_list_detection_events = host_list_detection_events[offset:limit + offset]
    host_list_detection_hr = tableToMarkdown(name='Host List Detection', t=limited_host_list_detection_events)
    results = CommandResults(
        readable_output=host_list_detection_hr,
        raw_response=limited_host_list_detection_events,
    )

    return limited_host_list_detection_events, results


def test_module(client: Client, params: Dict[str, Any], first_fetch_time: str) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    fetch_events(
        client=client,
        last_run={},
        first_fetch_time=first_fetch_time,
        max_fetch=1,
        fetch_function=get_activity_logs_events,
        last_run_field='activity_logs',
    )
    fetch_events(
        client=client,
        last_run={},
        first_fetch_time=first_fetch_time,
        max_fetch=1,
        fetch_function=get_host_list_detections_events,
        last_run_field='host_list_detection',
    )

    return 'ok'


def should_run_host_detections_fetch(last_run, host_detections_fetch_interval: timedelta, datatime_now: datetime):
    """

    Args:
        last_run: last run object.
        host_detections_fetch_interval: host detection fetch interval.

    Returns: True if fetch host detections interval time has passed since last time that fetch run.

    """
    if last_fetch_time := last_run.get('host_last_fetch'):
        last_check_time = datetime.strptime(last_fetch_time, DATE_FORMAT)
    else:
        # never run host detections fetch before
        return True
    demisto.debug(f'Should run host detections? {last_check_time=}, {host_detections_fetch_interval=}')
    return datatime_now - last_check_time > host_detections_fetch_interval


""" MAIN FUNCTION """


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get('url')
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")

    # How much time before the first fetch to retrieve events
    first_fetch_datetime: datetime = arg_to_datetime(  # type: ignore[assignment]
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    host_detections_fetch_interval: timedelta = (datetime.now() - dateparser.parse(  # type: ignore[operator]
        params.get('host_detections_fetch_interval', '12 hours')))
    first_fetch_str = first_fetch_datetime.strftime(DATE_FORMAT)

    demisto.debug(f'Command being called is {command}')

    try:
        headers: Dict = {"X-Requested-With": "Cortex XSIAM"}

        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_str)
            return_results(result)

        elif command == "qualys-get-activity-logs":
            should_push_events = argToBoolean(args.get('should_push_events', False))
            events, results = get_activity_logs_events_command(client, args, first_fetch_str)
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "qualys-get-host-detections":
            should_push_events = argToBoolean(args.get('should_push_events', False))
            events, results = get_host_list_detections_events_command(client, args, first_fetch_str)
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            host_list_detection_events = []
            host_next_run = {}
            if should_run_host_detections_fetch(last_run=last_run,
                                                host_detections_fetch_interval=host_detections_fetch_interval,
                                                datatime_now=datetime.now()):
                host_next_run, host_list_detection_events = fetch_events(
                    client=client,
                    last_run=last_run,
                    last_run_field='host_list_detection',
                    fetch_function=get_host_list_detections_events,
                    first_fetch_time=first_fetch_str,
                )
            logs_next_run, activity_logs_events = fetch_events(
                client=client,
                last_run=last_run,
                last_run_field='activity_logs',
                fetch_function=get_activity_logs_events,
                first_fetch_time=first_fetch_str,
            )
            send_events_to_xsiam(activity_logs_events + host_list_detection_events, vendor=VENDOR, product=PRODUCT)

            # saves next_run for the time fetch-events is invoked
            last_run.update(logs_next_run)
            last_run.update(host_next_run)
            demisto.setLastRun(last_run)

            # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
