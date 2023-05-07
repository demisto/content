import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict
import urllib3
import csv
import io

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
API_SUFFIX = "/api/2.0/fo/"
TAG_API_SUFFIX = "/qps/rest/2.0/"
VENDOR = 'qualys'
PRODUCT = 'qualys'
BEGIN_RESPONSE_LOGS_CSV = "----BEGIN_RESPONSE_BODY_CSV"
END_RESPONSE_LOGS_CSV = "----END_RESPONSE_BODY_CSV"
BEGIN_RESPONSE_FOOTER_CSV = "----BEGIN_RESPONSE_FOOTER_CSV"
END_RESPONSE_FOOTER_CSV = "----END_RESPONSE_FOOTER_CSV"

qualys_host_list_detection = {
    "api_route": API_SUFFIX + "asset/host/vm/detection/?action=list",
    "call_method": "GET",
    "resp_type": "text",
}


def get_partial_response(response: str, start: str, end: str):
    start_index = response.index(start) + len(start)
    end_index = response.index(end)
    result = response[start_index:end_index].strip()
    return result


def csv2json(csv_data: str):
    reader = csv.DictReader(io.StringIO(csv_data))
    json_data = json.dumps(list(reader))
    return json_data


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url, username, password, verify=True, proxy=False, headers=None):
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers, auth=(username, password))

    @staticmethod
    def error_handler(res):
        err_msg = f"Error in API call [{res.status_code}] - {res.reason}"
        try:
            simple_response = get_simple_response_from_raw(parse_raw_response(res.text))
            err_msg = f'{err_msg}\nError Code: {simple_response.get("CODE")}\nError Message: {simple_response.get("TEXT")}'
        except Exception:
            try:
                # Try to parse json error response
                error_entry = res.json()
                err_msg += "\n{}".format(json.dumps(error_entry))
                raise DemistoException(err_msg, res=res)
            except (ValueError, TypeError):
                err_msg += "\n{}".format(res.text)
                raise DemistoException(err_msg, res=res)
        raise DemistoException(err_msg, res=res)

    @logger
    def get_user_activity_logs(self, since_datetime) -> Union[str, bytes]:
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
            "since_datetime": since_datetime,
            "truncation_limit": 0
        }

        response = self._http_request(
            method='GET',
            url_suffix=urljoin(API_SUFFIX, 'activity_log/?action=list'),
            resp_type='text/csv',
            params=params,
            timeout=60,
            error_handler=self.error_handler,
        )

        return response.text


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
        return json.loads(str(response))
    except Exception:
        try:
            return json.loads(xml2json(response))
        except Exception:
            return {}


@logger
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


def test_module(client: Client, params: Dict[str, Any], first_fetch_time: int) -> str:
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

    try:
        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            max_fetch=1
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def add_time_to_events(events, time_field):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
        time_field:
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get(time_field))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


""" MAIN FUNCTION """


def fetch_events(client, last_run, first_fetch_time, max_fetch):
    events = []
    activity_logs_last_run = last_run.get('activity_logs')
    host_list_detection_last_run = last_run.get('host_list_detection')

    if not last_run:
        activity_logs_last_run = first_fetch_time
        host_list_detection_last_run = first_fetch_time

    # todo: call user activity log
    activity_logs = client.get_user_activity_logs(since_datetime=activity_logs_last_run)
    activity_logs_events = csv2json(get_partial_response(activity_logs, BEGIN_RESPONSE_LOGS_CSV, END_RESPONSE_LOGS_CSV))

    add_time_to_events(activity_logs_events, 'Date')

    # todo: call host list detection

    add_time_to_events(events, "TODO")

    next_run = {'activity_logs': '', 'host_list_detection': ''}
    return {}, events


def get_events(client):
    events = []
    # todo: call user activity log

    # todo: call host list detection

    add_time_to_events(events)
    return {}, events


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get('url')
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")

    max_fetch = params.get('max_fetch')
    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    # todo: 2023-05-04T12:36:59Z
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None

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
            events, results = get_events(client)
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
                max_fetch=max_fetch,
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
