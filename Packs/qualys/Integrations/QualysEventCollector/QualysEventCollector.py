import copy
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import urllib3
import csv
import io

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
ASSETS_DATE_FORMAT = '%Y-%m-%d'

API_SUFFIX = "/api/2.0/fo/"
VENDOR = 'qualys'
PRODUCT = 'qualys'
BEGIN_RESPONSE_LOGS_CSV = "----BEGIN_RESPONSE_BODY_CSV"
END_RESPONSE_LOGS_CSV = "----END_RESPONSE_BODY_CSV"
BEGIN_RESPONSE_FOOTER_CSV = "----BEGIN_RESPONSE_FOOTER_CSV"
END_RESPONSE_FOOTER_CSV = "----END_RESPONSE_FOOTER_CSV"
WARNING = 'WARNING'
ACTIVITY_LOGS_NEWEST_EVENT_DATETIME = 'activity_logs_newest_event_datetime'
ACTIVITY_LOGS_NEXT_PAGE = 'activity_logs_next_page'
ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN = 'activity_logs_since_datetime_prev_run'
HOST_DETECTIONS_NEWEST_EVENT_DATETIME = 'host_detections_newest_event_datetime'
HOST_DETECTIONS_NEXT_PAGE = 'host_detections_next_page'
HOST_DETECTIONS_SINCE_DATETIME_PREV_RUN = 'host_detections_since_datetime_prev_run'
HOST_LAST_FETCH = 'host_last_fetch'
ASSETS_FETCH_FROM = '90 days'
MIN_ASSETS_INTERVAL = 59

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

    def get_user_activity_logs(self, since_datetime: str, max_fetch: int = 0, next_page=None) -> Union[str, bytes]:
        """
        Make a http request to Qualys API to get user activities logs
        Args:
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        self._headers.update({"Content-Type": 'application/json'})
        params: dict[str, Any] = {
            "truncation_limit": max_fetch
        }
        if since_datetime:
            params["since_datetime"] = since_datetime
        if next_page:
            params["id_max"] = next_page

        response = self._http_request(
            method='GET',
            url_suffix=urljoin(API_SUFFIX, 'activity_log/?action=list'),
            resp_type='text/csv',
            params=params,
            timeout=60,
            error_handler=self.error_handler,
        )

        return response.text

    def get_host_list_detection(self, since_datetime, next_page=None) -> Union[str, bytes]:
        """
        Make a http request to Qualys API to get assets
        Args:
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        self._headers.update({"Content-Type": 'application/json'})
        params: dict[str, Any] = {
            "truncation_limit": 3,
            "vm_scan_date_after": since_datetime
        }
        if next_page:
            params["id_min"] = next_page

        response = self._http_request(
            method='GET',
            url_suffix=urljoin(API_SUFFIX, 'asset/host/vm/detection/?action=list'),
            resp_type='text',
            params=params,
            timeout=60,
            error_handler=self.error_handler,
        )
        return response

    def get_vulnerabilities(self, since_datetime) -> Union[str, bytes]:
        """
        Make a http request to Qualys API to get vulnerabilities
        Args:
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        self._headers.update({"Content-Type": 'application/json'})
        params: dict[str, Any] = {"last_modified_after": since_datetime}

        response = self._http_request(
            method='POST',
            url_suffix=urljoin(API_SUFFIX, 'knowledge_base/vuln/?action=list'),
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
        return None
    start_index = response.index(start) + len(start)
    end_index = response.index(end)
    result = response[start_index:end_index].strip()
    if result.startswith(WARNING):
        result = result.replace(WARNING, '').strip()
    return result


def skip_fetch_assets(last_run):
    """ Checks if enough time has passed since the previous run.
    Args:
        last_run: Last run time.
    Returns:
        Returns true or false if enough time has passed since the previous run.
    """
    time_to_check = last_run.get("assets_last_fetch")
    if not time_to_check:
        return False
    passed_minutes = (time.time() - time_to_check) / 60
    if passed_minutes < MIN_ASSETS_INTERVAL:
        demisto.info(f"Skipping fetch-assets command. Only {passed_minutes} minutes have passed since the last fetch. "
                     f"It should be a minimum of 1 hour.")
        return True
    return False


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


def get_next_page_from_url(url, field):
    """
    Get the next page field from url.
    """
    match = re.search(rf"{field}=(\d+)", url)
    res = match.group(1) if match else None
    return res


def get_next_page_activity_logs(footer):
    """
    Extracts the next token from activity logs response.
    """
    if isinstance(footer, list):
        footer = footer[0]
    next_url = footer.get('URL', '')
    max_id = get_next_page_from_url(next_url, 'id_max')
    return max_id


def handle_host_list_detection_result(raw_response: requests.Response) -> tuple[Optional[list], Optional[str]]:
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
    response_next_url = dict_safe_get(formatted_response,
                                      ["HOST_LIST_VM_DETECTION_OUTPUT", "RESPONSE", "WARNING", "URL"], default_return_value='')
    if isinstance(response_requested_value, dict):
        response_requested_value = [response_requested_value]

    return response_requested_value, response_next_url


def handle_vulnerabilities_result(raw_response: requests.Response) -> tuple[Optional[list], Optional[str]]:
    """
    Handles vulnerabilities response - parses xml to json and gets the list
    Args:
        raw_response (requests.Response): the raw result received from Qualys API command
    Returns:
        List with data generated for the result given
    """
    formatted_response = parse_raw_response(raw_response)

    vulnerabilities = dict_safe_get(formatted_response, ['KNOWLEDGE_BASE_VULN_LIST_OUTPUT', 'RESPONSE', 'VULN_LIST', 'VULN'])
    if isinstance(vulnerabilities, dict):
        vulnerabilities = [vulnerabilities]

    return vulnerabilities


def parse_raw_response(response: Union[bytes, requests.Response]) -> dict:
    """
    Parses raw response from Qualys.
    Load xml as JSON.
    Args:
        response (Union[bytes, requests.Response]): Response from Qualys service.

    Returns:
        (Dict): Dict representing the data returned by Qualys service.
    """
    return json.loads(xml2json(response))


def get_simple_response_from_raw(raw_response: Any) -> Union[Any, dict]:
    """
    Gets the simple response from a given JSON dict structure returned by Qualys service
    If object is not a dict, returns None.
    Args:
        raw_response (Any): Raw response from Qualys service.

    Returns:
        (Union[Any, Dict]): Simple response path if object is a dict, else response as is.
    """
    simple_response = None
    if raw_response and isinstance(raw_response, dict):
        simple_response = raw_response.get("SIMPLE_RETURN", {}).get("RESPONSE", {})
    return simple_response


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
                del new_detection['DETECTION_LIST']
                fetched_events.append(new_detection)
        else:
            del host['DETECTION_LIST']
            host['DETECTION'] = {}
            fetched_events.append(host)
    return fetched_events


def get_activity_logs_events(client, since_datetime, max_fetch, next_page=None) -> tuple[Optional[list], dict]:
    """ Get logs activity from qualys
    API response returns events sorted in descending order. We are saving the next_page param and
    sending next request with next_page arg if needed. Saving the newest event fetched.
    We are deleting the newest event each time to avoid duplication.
    Args:
        client: Qualys client
        since_datetime: datetime to get events from
        max_fetch: max number of events to return
        next_page: pagination marking
    Returns:
        Logs activity events, Next run datetime
    """
    demisto.debug(f'Starting to fetch activity logs events: since_datetime={since_datetime}, next_page={next_page}')
    activity_logs = client.get_user_activity_logs(since_datetime=since_datetime, max_fetch=max_fetch, next_page=next_page)
    activity_logs_events = csv2json(get_partial_response(activity_logs, BEGIN_RESPONSE_LOGS_CSV,
                                                         END_RESPONSE_LOGS_CSV) or activity_logs) or []
    footer_json = csv2json(get_partial_response(activity_logs, BEGIN_RESPONSE_FOOTER_CSV,
                                                END_RESPONSE_FOOTER_CSV)) or {}
    new_next_page = get_next_page_activity_logs(footer_json)
    demisto.debug(f'Got activity logs events from server: {len(activity_logs_events)=}.')

    newest_event_time = activity_logs_events[0].get('Date') if activity_logs_events else since_datetime

    if not next_page:
        activity_logs_events = remove_last_events(activity_logs_events, newest_event_time, 'Date')
    add_fields_to_events(activity_logs_events, ['Date'], 'activity_log')

    next_run_dict = {
        ACTIVITY_LOGS_NEWEST_EVENT_DATETIME: newest_event_time,
        ACTIVITY_LOGS_NEXT_PAGE: new_next_page,
        ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN: since_datetime,
    }
    demisto.debug(f'Done to fetch activity logs events: {next_run_dict=}, sending {len(activity_logs_events)} events.')
    return activity_logs_events, next_run_dict


def get_host_list_detections_events(client, since_datetime) -> list:
    """ Get host list detections from qualys
    Args:
        client: Qualys client
        since_datetime: The start fetch date.
    Returns:
        Host list detections assets
    """
    demisto.debug(f'Starting to fetch assets')
    assets = []
    next_page = ''

    while True:
        host_list_detections = client.get_host_list_detection(since_datetime, next_page=next_page)
        host_list_assets, next_url = handle_host_list_detection_result(host_list_detections) or []
        assets += host_list_assets
        next_page = get_next_page_from_url(next_url, 'id_min')
        if not next_page:
            break

    edited_host_detections = get_detections_from_hosts(assets)
    demisto.debug(f'Parsed detections from hosts, got {len(edited_host_detections)=} assets.')

    add_fields_to_events(edited_host_detections, ['DETECTION', 'FIRST_FOUND_DATETIME'], 'host_list_detection')

    return edited_host_detections


def get_vulnerabilities(client, since_datetime) -> list:
    """ Get vulnerabilities list from qualys
    Args:
        client: Qualys client
        since_datetime: The start fetch date.
    Returns:
        list vulnerabilities
    """
    demisto.debug('Starting to fetch vulnerabilities')
    host_list_detections = client.get_vulnerabilities(since_datetime)
    vulnerabilities = handle_vulnerabilities_result(host_list_detections) or []

    demisto.debug(f'Parsed detections from hosts, got {len(vulnerabilities)=} vulnerabilities.')
    return vulnerabilities


def fetch_assets(client):
    """ Fetches host list detections
    Args:
        client: command client
    Return:
        event: events to push to xsiam
    """
    demisto.debug(f'Starting fetch for assets')
    since_datetime = arg_to_datetime(ASSETS_FETCH_FROM).strftime(ASSETS_DATE_FORMAT)

    assets = get_host_list_detections_events(client, since_datetime)
    vulnerabilities = get_vulnerabilities(client, since_datetime)

    demisto.info(f"Pulled {len(assets)} assets, and {len(vulnerabilities)} vulnerabilities from API, sending them to XSIAM")
    return assets, vulnerabilities


def fetch_events(client, last_run, first_fetch_time, fetch_function, newest_event_field, next_page_field,
                 previous_run_time_field, max_fetch: Optional[int] = 0):
    """ Fetches activity logs and host list detections
    Args:
        client: command client
        last_run: last fetch time
        first_fetch_time: when start to fetch from
        fetch_function: function that gets the events
        max_fetch: max number of items to return (0 to return all)
        newest_event_field
        next_page_field
        previous_run_time_field
    Return:
        next_last_run: where to fetch from next time
        event: events to push to xsiam
    """
    demisto.debug(f'Starting fetch for {fetch_function.__name__}, last run: {last_run}')
    newest_event_time = last_run.get(newest_event_field) if last_run else None
    next_page = last_run.get(next_page_field)
    previous_time_field = last_run.get(previous_run_time_field)

    if not newest_event_time:
        newest_event_time = first_fetch_time

    time_to_fetch = newest_event_time if not next_page else previous_time_field

    events, new_next_run = fetch_function(client, time_to_fetch, max_fetch, next_page)

    updated_next_run = {previous_run_time_field: time_to_fetch}
    new_next_page = new_next_run.get(next_page_field)

    # if the fetch is not during the pagination (fetched without next_page)
    if not next_page:
        # update the newest event
        updated_next_run[newest_event_field] = new_next_run.get(newest_event_field)

    # update if there is next page and this fetch is not over
    updated_next_run[next_page_field] = new_next_page

    if last_fetch_time := new_next_run.get(HOST_LAST_FETCH):
        updated_next_run[HOST_LAST_FETCH] = last_fetch_time

    demisto.info(f"Sending len{len(events)} to XSIAM. updated_next_run={updated_next_run}.")
    return updated_next_run, events


def get_activity_logs_events_command(client, args, first_fetch_time):
    """
    Args:
        client: command client
        args: Demisto args for this command: limit and since_datetime
        first_fetch_time: first fetch time
    Retuns:
        Command results with activity logs

    """
    limit = arg_to_number(args.get('limit', 50))
    offset = arg_to_number(args.get('offset', 0))
    since_datetime = arg_to_datetime(args.get('since_datetime'))
    since_datetime = since_datetime.strftime(DATE_FORMAT) if since_datetime else first_fetch_time
    activity_logs_events, _ = get_activity_logs_events(
        client=client,
        since_datetime=since_datetime,
        max_fetch=0,
    )
    limited_activity_logs_events = activity_logs_events[offset:limit + offset]  # type: ignore[index,operator]
    activity_logs_hr = tableToMarkdown(name='Activity Logs', t=limited_activity_logs_events)
    results = CommandResults(
        readable_output=activity_logs_hr,
        raw_response=limited_activity_logs_events,
    )

    return limited_activity_logs_events, results


def test_module(client: Client, params: dict[str, Any], first_fetch_time: str) -> str:
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
        newest_event_field=ACTIVITY_LOGS_NEWEST_EVENT_DATETIME,
        next_page_field=ACTIVITY_LOGS_NEXT_PAGE,
        previous_run_time_field=ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN,
    )

    fetch_assets(client=client)

    return 'ok'


""" MAIN FUNCTION """


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get('url')
    verify_certificate = not params.get("insecure", True)
    proxy = params.get("proxy", False)
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")

    # How much time before the first fetch to retrieve events
    first_fetch_datetime: datetime = arg_to_datetime(  # type: ignore[assignment]
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_str = first_fetch_datetime.strftime(DATE_FORMAT)

    demisto.info(f'Command being called is {command}')

    try:
        headers: dict = {"X-Requested-With": "Cortex"}
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

        elif command == "qualys-get-events":
            should_push_events = argToBoolean(args.get('should_push_events', False))
            events, results = get_activity_logs_events_command(client, args, first_fetch_str)
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            max_fetch_activity_logs = arg_to_number(params.get("max_fetch_activity_logs", 0))
            logs_next_run, activity_logs_events = fetch_events(
                client=client,
                last_run=last_run,
                newest_event_field=ACTIVITY_LOGS_NEWEST_EVENT_DATETIME,
                next_page_field=ACTIVITY_LOGS_NEXT_PAGE,
                previous_run_time_field=ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN,
                fetch_function=get_activity_logs_events,
                first_fetch_time=first_fetch_str,
                max_fetch=max_fetch_activity_logs,
            )
            send_events_to_xsiam(activity_logs_events, vendor=VENDOR, product=PRODUCT)

            # saves next_run for the time fetch-events is invoked
            demisto.setLastRun(logs_next_run)

        elif command == 'fetch-assets':
            assets_last_run = demisto.getAssetsLastRun()
            demisto.debug(f'saved lastrun assets: {assets_last_run}')
            if skip_fetch_assets(assets_last_run):
                return
            execution_start_time = time.time()
            assets, vulnerabilities = fetch_assets(client=client)
            send_data_to_xsiam(data=assets, vendor=VENDOR, product='host_detections', data_type='assets')
            send_data_to_xsiam(data=vulnerabilities, vendor=VENDOR, product='vulnerabilities')
            demisto.setAssetsLastRun({'assets_last_fetch': execution_start_time})

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
