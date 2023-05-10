import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Tuple, Optional, Any
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
        params = {
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
        params = {
            "truncation_limit": max_fetch
        }
        # todo:
        # if since_datetime:
        #     params["since_datetime"] = since_datetime

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
    try:
        return json.loads(xml2json(response))
    except Exception:
        return {}


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


def remove_last_events(events, time_to_remove, time_field):
    """ Removes events with certain time.
        Args:
            events: list of events to remove the time from
            time_to_remove: remove events with this time
            time_field: the field name where the time is
    """
    for event in events:
        if event.get(time_field) == time_to_remove:
            events.remove(event)


def add_time_to_events(events, time_field):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
        time_field: the field to get _time from
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get(time_field))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


def get_activity_logs_events(client, last_run, max_fetch) -> tuple[Optional[list], str]:
    """ Get logs activity from qualys
    Args:
        client: Qualys client
        last_run: datetime to get events from
        max_fetch: max number of events to return
    Returns:
        Logs activity events, Next run datetime
    """
    activity_logs = client.get_user_activity_logs(since_datetime=last_run, max_fetch=max_fetch)
    activity_logs_events = csv2json(get_partial_response(activity_logs, BEGIN_RESPONSE_LOGS_CSV, END_RESPONSE_LOGS_CSV))
    next_run = activity_logs_events[0].get('Date') if activity_logs_events else last_run
    remove_last_events(activity_logs_events, next_run, 'Date')
    add_time_to_events(activity_logs_events, 'Date')

    return activity_logs_events, next_run


def get_host_list_detections_events(client, last_run, max_fetch) -> tuple[Optional[list], str]:
    """ Get host list detections from qualys
    Args:
        client: Qualys client
        last_run: datetime to get events from
        max_fetch: max number of events to return
    Returns:
        Host list detections events, Next run datetime
    """
    host_list_detections = client.get_host_list_detection(since_datetime=last_run, max_fetch=max_fetch)
    host_list_events = handle_host_list_detection_result(host_list_detections)
    next_run = host_list_events[0].get('LAST_UPDATE_DATETIME') if host_list_events else last_run
    # remove_last_events(host_list_events, next_run, 'LAST_UPDATE_DATETIME')
    add_time_to_events(host_list_events, 'LAST_UPDATE_DATETIME')

    return host_list_events, next_run


def fetch_events(client, last_run, first_fetch_time, max_fetch: int = 0):
    """ Fetches activity logs and host list detections
    Args:
        client: command client
        last_run: last fetch time
        first_fetch_time: when start to fetch from
        max_fetch: max number of items to return (0 to return all)

    Return:
        next_last_run: where to fetch from next time
        event: events to push to xsiam
    """
    activity_logs_last_run = last_run.get('activity_logs')
    host_list_detection_last_run = last_run.get('host_list_detection')

    if not last_run:
        activity_logs_last_run = first_fetch_time
        host_list_detection_last_run = first_fetch_time

    # activity_logs_events, next_run_activity_log = get_activity_logs_events(client, activity_logs_last_run, max_fetch)

    host_list_detection_events, next_run_host_list = get_host_list_detections_events(client,
                                                                                     host_list_detection_last_run,
                                                                                     max_fetch)
    next_run_activity_log = "TODO"
    activity_logs_events = []
    next_run = {'activity_logs': next_run_activity_log, 'host_list_detection': next_run_host_list}
    return next_run, activity_logs_events + host_list_detection_events


def get_events(client, args):
    """
    Args:
        client: command client
        args: Demisto args for this command: limit and since_datetime
    Retuns:
        Command results with activity logs and host list detections

    """
    limit = arg_to_number(args.get('limit', 50))
    since_datetime = arg_to_datetime(args.get('since_datetime'))
    last_run = since_datetime.strftime(DATE_FORMAT) if since_datetime else ''
    activity_logs_events, _ = get_activity_logs_events(
        client=client,
        last_run=last_run,
        max_fetch=limit,
    )

    host_list_detection_events, _ = get_host_list_detections_events(
        client=client,
        last_run=last_run,
        max_fetch=limit,
    )

    activity_logs_hr = tableToMarkdown(name='Activity Logs', t=activity_logs_events)
    host_list_detection_hr = tableToMarkdown(name='Host List Detection', t=host_list_detection_events)
    results = CommandResults(
        readable_output=activity_logs_hr + host_list_detection_hr,
        raw_response=activity_logs_events + host_list_detection_events,
    )

    return activity_logs_events + host_list_detection_events, results


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
        max_fetch=1
    )

    return 'ok'


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
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '6 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = first_fetch_time.strftime(DATE_FORMAT)

    demisto.debug(f'Command being called is {command}')

    try:
        headers: Dict = {"X-Requested-With": "Demisto"}

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
            result = test_module(client, params, first_fetch_timestamp)
            return_results(result)

        elif command == 'qualys-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events'))
            events, results = get_events(client, args)
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT,
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_timestamp,
            )
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT,
            )
            # saves next_run for the time fetch-events is invoked
            demisto.setLastRun(next_run)

            # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
