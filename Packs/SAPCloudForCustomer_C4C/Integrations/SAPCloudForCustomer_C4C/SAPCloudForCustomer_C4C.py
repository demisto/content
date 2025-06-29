import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

SAP_CLOUD = "SAP CLOUD FOR CUSTOMER"
STRFTIME_FORMAT = "%d-%m-%Y %H:%M:%S"
ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
VENDOR = "SAP CLOUD"
PRODUCT = "C4C"
FIRST_FETCH = "one minute ago"
URL_SUFFIX = "/sap/c4c/odata/ana_businessanalytics_analytics.svc/"
INIT_SKIP = 0
DEFAULT_TOP = 1000

""" CLIENT CLASS """

class Client(BaseClient):
    """
    Client to use in the Anomali ThreatStream Feed integration. Overrides BaseClient
    """

    def __init__(self, base_url, base64String, verify):
        super().__init__(base_url=base_url, verify=verify, ok_codes=(200, 201, 202))
        self.credentials = {
             "Authorization": "Basic " + base64String, "Content-Type": "application/json"
        }

    def http_request(
        self,
        method,
        url_suffix,
        params=None,
        data=None,
        headers=None,
        files=None,
        json=None,
        without_credentials=False,
        resp_type="json",
    ):
        """
        A wrapper for requests lib to send our requests and handle requests and responses better.
        """
        headers = headers or {}
        if not without_credentials:
            headers.update(self.credentials)
        res = super()._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            params=params,
            data=data,
            json_data=json,
            files=files,
            resp_type=resp_type,
            error_handler=self.error_handler,
            retries=2,
        )
        return res

    def error_handler(self, res: requests.Response):  # pragma: no cover
        """
        Error handler to call by super()._http_request in case an error was occurred.
        Handles specific HTTP status codes and raises a DemistoException.
        Args:
            res (requests.Response): The HTTP response object.
        """
        # Handle error responses gracefully
        if res.status_code == 401:
            raise DemistoException(f"{SAP_CLOUD} - Got unauthorized from the server. Check the credentials. {res.text}")
        elif res.status_code == 204:
            return
        elif res.status_code == 404:
            raise DemistoException(f"{SAP_CLOUD} - The resource was not found. {res.text}")
        raise DemistoException(f"{SAP_CLOUD} - Error in API call {res.status_code} - {res.text}")
    

""" COMMAND FUNCTIONS """

def encode_to_base64(input_string):
  """
  Encodes a given string into its Base64 representation.

  Args:
    input_string: The string to be encoded.

  Returns:
    The Base64 encoded string.
  """
  bytes_string = input_string.encode('utf-8')
  encoded_bytes = base64.b64encode(bytes_string)
  encoded_string = encoded_bytes.decode('utf-8')
  return encoded_string


def test_module(client: Client, report_id: str) -> str:
    """
    Tests API connectivity and authentication.
    Args:
        client (Client): The client object to use for API requests.
        report_id (str): The ID of the report to use for testing.
    Returns:
        str: 'ok' if the test passed, otherwise raises an exception.
    """
    if not report_id:
        raise DemistoException("Report ID is a mandatory parameter for test-module. Please provide a Report ID.")
    
    url_suffix = f"{URL_SUFFIX}{report_id}?"
    client.http_request("GET", url_suffix=f"{url_suffix}", params={"$inlinecount": "allpages", "$filter": "CUSER eq 'ASAHAYA'",
                                                            "$top": 2, "$format": "json"})
    return "ok"
    
    
def get_current_utc_time():
    """
    Returns the current UTC time as an aware datetime object.

    Returns:
        datetime: The current time in UTC with timezone information.
    """
    return datetime.now(timezone.utc)

def get_events(client: Client, report_id: str, start_date: str, skip: int, top: int) -> dict[str, Any]:
    """
    Get a list of events from the SAP Cloud for Customer API.

    Args:
        client (Client): The client object to use for API requests.
        report_id (str): The ID of the report to fetch events from.
        start_date (str): Fetch events that are newer than or equal to this time (formatted as DD-MM-YYYY HH:MM:SS).
        skip (int): Number of items to skip for pagination.
        top (int): Maximum number of events to return in this request.

    Returns:
        Dict[str, Any]: A list of events.
    """
    params = {
            "$filter": f"CTIMESTAMP ge '{start_date} INDIA'", #TODO will be fixes once the client returns a response
            "$skip": skip,
            "$top": top,
            "$format": "json"
        }

    
    res =  client.http_request(
        method="GET",
        url_suffix=f"{URL_SUFFIX}{report_id}?",
        params=params,
    )
    
    return res.get('d', {}).get('results', [])


def fetch_events(client: Client, params: dict, last_run: dict):
    """
    Fetches events from SAP Cloud API.
    Args:
        client (Client): The client object to use for API requests.
        params (dict): Integration parameters.
        last_run (dict): The last run object from Demisto.

    Returns:
        tuple: A tuple containing (next_run_timestamp_str, all_fetched_events_list).
    """
    max_events_per_fetch = arg_to_number(params.get("max_fetch")) or 10000
    report_id = params.get("report_id")
    all_events = []
    skip_count = INIT_SKIP
    top_count = DEFAULT_TOP
    now = get_current_utc_time()
    
    demisto.debug(f"{last_run=}")
    
    # Get last_fetch time from last_run or set to FIRST_FETCH (e.g., "one minute ago")
    start_date_str = last_run.get("lastRun")
    
    if start_date_str: # last_fetch will be in ISO format
        # Parse and format to DD-MM-YYYY HH:MM:SS for the SAP API filter
        parsed_start_date = dateparser.parse(start_date_str)
        if parsed_start_date:
            start_date_for_filter = parsed_start_date.strftime(STRFTIME_FORMAT)
        else:
            # Fallback if parsing fails for some reason
            demisto.info(f"Could not parse last_fetch: {start_date_str}. Falling back to {FIRST_FETCH}.")
            start_date_for_filter = dateparser.parse(FIRST_FETCH).strftime(STRFTIME_FORMAT)
    else:
        # For the very first fetch or if last_run is empty
        start_date_for_filter = dateparser.parse(FIRST_FETCH).strftime(STRFTIME_FORMAT)
    
    
    demisto.debug(f"Getting events from: {start_date_for_filter}")

    while max_events_per_fetch > 0:
        top = min(top_count, max_events_per_fetch)
        response = get_events(client, report_id, start_date=start_date_for_filter, skip=skip_count, top=top)
        if response:
            all_events.extend(response)
            skip_count += DEFAULT_TOP
            max_events_per_fetch -= len(response)
        else:
            demisto.debug("No more events exist or no response received, breaking...")
            break

    demisto.debug(f"Fetched {len(all_events)} events.")
    # next_run will be the current time when the fetch started, in ISO format for Demisto's last_run
    next_run = now.strftime(ISO_8601_FORMAT),
    return next_run, all_events


def main():
    """
    Initiate integration command
    """
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    params = demisto.params()

    # init credentials
    user_name = demisto.get(params, "username.identifier")
    password = demisto.get(params, "username.password")
    server_url = params.get("url", "").strip("/")
    try:
        
        base64String = encode_to_base64(user_name + ":" + password) # type: ignore
        client = Client(
            base_url=f"{server_url}",
            base64String = base64String,
            verify=not params.get("insecure", False),
        )

        if command == "test-module":
            # This call is made when clicking the integration 'Test' button.
            report_id = params.get("report_id")
            if report_id:
                return_results(test_module(client, report_id))
            else:
                demisto.info(f"Invalid Report ID:{report_id}")

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            next_run, events = fetch_events(client, params, last_run)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Successfully saved last_run= {demisto.getLastRun()}")
            
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
