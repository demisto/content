import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
API_SUFFIX = "/api/2.0/fo/"
TAG_API_SUFFIX = "/qps/rest/2.0/"
VENDOR = 'qualys'
PRODUCT = 'qualys'


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
    def command_http_request(self, command_api_data: Dict[str, str]) -> Union[str, bytes]:
        """
        Make a http request to Qualys API
        Args:
            command_api_data: Information about the API request of the requested command
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        if content_type := command_api_data.get("Content-Type"):
            self._headers.update({"Content-Type": content_type})

        return self._http_request(
            method=command_api_data["call_method"],
            url_suffix=command_api_data["api_route"],
            params=args_values,
            resp_type=command_api_data["resp_type"],
            timeout=60,
            data=command_api_data.get("request_body", None),
            error_handler=self.error_handler,
        )


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
        alert_status = params.get('alert_status', None)

        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            alert_status=alert_status,
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def add_time_to_events(events):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('created_time'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


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

    max_fetch = params.get('max_fetch')
    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    assert isinstance(first_fetch_timestamp, int)

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

        elif command == 'hello-world-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events'))
            events, results = get_events(client)
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
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
            add_time_to_events(events)
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
