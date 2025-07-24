import uuid
import demistomock as demisto # noqa: F401
from CommonServerPython import *
import urllib3

from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "Monday"
PRODUCT = "Monday"

# Event type string as appears in the yml file
AUDIT_LOGS_TYPE = "Audit Logs"
ACTIVITY_LOGS_TYPE = "Activity Logs"

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

SCOPE = "boards:read"
REDIRECT_URI = "https://localhost"
AUTH_URL = "https://auth.monday.com/oauth2/token"
MAX_PER_PAGE = 1000

PARAMS = demisto.params()
PROXY = PARAMS.get("proxy", False)
USE_SSL = not PARAMS.get("insecure", False)

FETCH_TIME = "now" # check id i need this

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}

""" CLIENT CLASS """
# TODO: add function comments
# TODO: edit debug logs prints

# TODO: I dont think this app need to inherit from BaseClient, it is a basic client.
# change the request logic to use requests library and handle exception alone.
class ActivityLogsClient(BaseClient):
    def __init__(
        self,
        client_id: str,
        secret: str,
        max_logs_per_fetch: int,
        url: str,
        auth_code: str = "",
        verify: bool = True,
        proxy: bool = False,
        # I think proxy is redundant, TODO: check how to use it on Monday. (I read: No, Monday.com does not use or expose a centralized OAuth proxy service like Microsoft’s OProxy.)
        *args, # ???
        **kwargs, # ???
    ):
        demisto.debug("Initializing ActivityLogsClient with:")
        super().__init__(*args, verify=verify, **kwargs)  # type: ignore[misc]

        self.client_id = client_id
        self.secret = secret
        self.auth_code = auth_code
        self.verify = verify
        self.proxy = proxy
        self.max_logs_per_fetch = max_logs_per_fetch
        self.url = url
        self.board_ids = board_ids
        self.scope = SCOPE  # TODO: check if this is relevant and in used
        self.redirect_uri = REDIRECT_URI


    # TODO: Should I save the access_token in the integration context? if so, take reference from this implementation
    # def reference_get_access_token(self, resource: str = "", scope: str | None = None) -> str:
    #     """
    #     Obtains access and refresh token from oproxy server or just a token from a self deployed app.
    #     Access token is used and stored in the integration context
    #     until expiration time. After expiration, new refresh token and access token are obtained and stored in the
    #     integration context.
 
    #     Args:
    #         resource: The resource identifier for which the generated token will have access to.
    #         scope: A scope to get instead of the default on the API.

    #     Returns:
    #         str: Access token that will be added to authorization header.
    #     """
    #     integration_context = get_integration_context()
    #     refresh_token = integration_context.get("current_refresh_token", "")
    #     # Set keywords. Default without the scope prefix.
    #     access_token_keyword = f"{scope}_access_token" if scope else "access_token"
    #     valid_until_keyword = f"{scope}_valid_until" if scope else "valid_until"

    #     access_token = integration_context.get(resource) if self.multi_resource else integration_context.get(access_token_keyword)

    #     valid_until = integration_context.get(valid_until_keyword)

    #     if access_token and valid_until and self.epoch_seconds() < valid_until:
    #         return access_token

    #     if self.auth_type == OPROXY_AUTH_TYPE:
    #         if self.multi_resource:
    #             expires_in = None
    #             for resource_str in self.resources:
    #                 access_token, current_expires_in, refresh_token = self._oproxy_authorize(resource_str)
    #                 self.resource_to_access_token[resource_str] = access_token
    #                 self.refresh_token = refresh_token
    #                 expires_in = current_expires_in if expires_in is None else min(expires_in, current_expires_in)  # type: ignore[call-overload]
    #             if expires_in is None:
    #                 raise DemistoException("No resource was provided to get access token from")
    #         else:
    #             access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

    #     else:
    #         access_token, expires_in, refresh_token = self._get_self_deployed_token(refresh_token, scope, integration_context)
    #     time_now = self.epoch_seconds()
    #     time_buffer = 5  # seconds by which to shorten the validity period
    #     if expires_in - time_buffer > 0:
    #         # err on the side of caution with a slightly shorter access token validity period
    #         expires_in = expires_in - time_buffer
    #     valid_until = time_now + expires_in
    #     integration_context.update(
    #         {access_token_keyword: access_token, valid_until_keyword: valid_until, "current_refresh_token": refresh_token}
    #     )

    #     # Add resource access token mapping
    #     if self.multi_resource:
    #         integration_context.update(self.resource_to_access_token)

    #     set_integration_context(integration_context)
    #     demisto.debug("Set integration context successfully.")

    #     if self.multi_resource:
    #         return self.resource_to_access_token[resource]

    #     return access_token


def test_module(client: ActivityLogsClient, params: dict[str, Any], first_fetch_time: str) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        alert_status = params.get("alert_status", None)

        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            alert_status=alert_status,
            max_events_per_fetch=1,
        )

    except Exception as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e

    return "ok"


def get_events(client: ActivityLogsClient, alert_status: str, args: dict) -> tuple[List[Dict], CommandResults]:
    """Gets events from API

    Args:
        client (Client): The client
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        args (dict): Additional arguments

    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    limit = args.get("limit", 50)
    from_date = args.get("from_date")
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name="Test Event", t=events)
    return events, CommandResults(readable_output=hr)



# TODO: add comments that the auth flow is necessary for activity logs
def generate_login_url(client_id: str) -> CommandResults:
    if not client_id:
        raise DemistoException("Please make sure you entered the Client ID correctly.")
    
    login_url = f'https://auth.monday.com/oauth2/authorize?client_id={client_id}'

    result_msg = f"""Click on the [login URL]({login_url}) to sign in and grant Cortex XSOAR the permissions.
    You will be automatically redirected to a link with the following structure:
    ```REDIRECT_URI?code=AUTH_CODE&region=REGION&scope=boards%3Aread&state=```
    Copy the `AUTH_CODE` (without the `code=` prefix)
    and paste it in your instance configuration under the **Authorization code** parameter.
    """
    return CommandResults(readable_output=result_msg)


def get_access_token(client_id: str, secret: str, auth_code: str) -> str:
    """
    Exchange authorization code for access token from Monday.com
    """
    payload = {
        "client_id": client_id,
        "client_secret": secret,
        "code": auth_code,
        "redirect_uri": REDIRECT_URI
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        # response = requests.post(url=AUTH_URL, data=payload, headers=headers)
        # TODO: if i am using requests.lib i need to handle the code success and exception
        response = http_request("POST", AUTH_URL, headers=headers, data=payload)
        access_token = response.json().get("access_token")
        
        if not access_token:
            demisto.debug("Response missing access_token field")
            raise DemistoException("Response missing access_token field")
        
        demisto.debug("Access token received successfully")
        return access_token

    except Exception as e:
        demisto.debug(f"Error retrieving access token: {str(e)}")
        raise DemistoException(f"Error retrieving access token: {str(e)}")

    
def test_connection(client_id: str, secret: str, auth_code: str) -> CommandResults:
    """
    Test connectivity in the Authorization Code flow mode for activity logs.
    """
    access_token = get_access_token(client_id, secret, auth_code)  # If fails, get_access_token returns an error
    return CommandResults(readable_output=f"✅ Success!\nAccess token: {access_token}")


# TODO: delete after integration is deployed
# maybe it will be easier to use generic_http_request (CommonServerPython)
'''
Status codes - source: https://support.monday.com/hc/en-us/articles/4406042650002-Audit-Log-API
The following status codes will be returned for each request:
    200 - retrieving the audit logs succeeded
    400 - client errors (e.g. invalid filter)
    401 - unauthorized (e.g. requests without a token/invalid token)
    429 - rate limit error
    500 - internal server error
'''

def run_retry_on_rate_limit(args_for_next_run: dict):
    return CommandResults(
        readable_output="Rate limit reached, rerunning the command in 1 min",
        scheduled_command=ScheduledCommand(
            command=demisto.command(), next_run_in_seconds=60, args=args_for_next_run, timeout_in_seconds=900
        ),
    )

# TODO: maybe it better to use request from library instead of implement this one with generic_http_request, the request is basic.
def http_request(
        method: str,
        url: str,
        url_suffix=None,
        params=None,
        data=None,
        headers=HEADERS,
        json=None,
        token=None,
        timeout=None,
        ok_codes=[200],
    ):
        # TODO: add comments
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        int_timeout = int(timeout) if timeout else 60  # 60 is the default in generic_http_request
        
        try:
            response = generic_http_request(
                method=method,
                server_url=url,
                headers=headers,
                url_suffix=url_suffix,
                data=data,
                params=params,
                proxy=PROXY,
                verify=USE_SSL,
                json_data=json,
                timeout=int_timeout,
                ok_codes=ok_codes
            )
            demisto.debug(f"In http_request {response=} {response.status_code=}")
        except requests.exceptions.RequestException as e:
            return_error(f"Error in connection to the server. Please make sure you entered the URL correctly. Exception is {e!s}.")


        # Audit log fetch - The rate limit is up to 50 requests per minute.
        if response.status_code == 429:
            command_args = demisto.args()
            ran_once_flag = command_args.get("ran_once_flag")
            if ran_once_flag:
                try:
                    error_message = response.json()
                except Exception:
                    error_message = "Rate limit reached on retry - 429 Response"
                demisto.debug(f"Error in retry for Monday.com rate limit - {error_message}")
                raise DemistoException(error_message)

            else:
                demisto.debug(f"Scheduling command {demisto.command()}")
                command_args["ran_once_flag"] = True
                return_results(run_retry_on_rate_limit(command_args))
                sys.exit(0)
        
        elif response.status_code not in ok_codes:
            raise DemistoException(f"Failed to send http request. Status code: {response.status_code}")
        
        return response

# TODO: check that this mechanism is correct, and i fetched exactly the amount of logs that i want
# TODO: what should I save in last_run that helps me to fetch the next batch of logs from the last one that i fetched
# TODO: I think I should store: page: int, last_fetched_log_index: int
def get_audit_logs(filter: str, limit: int) -> dict:
    
    params = demisto.params()
    audit_logs_url = params.get("audit_logs_url", "")
    audit_token = params.get("audit_token", "")
    
    # TODO: should i validate the audit_token? (not empty)
    headers = {
        "Authorization": f"Bearer {audit_token}",
        "Content-Type": "application/json"
    }
            
    fetched_logs = []
    page = 1
    per_page = min(MAX_PER_PAGE, limit)
        
    while len(fetched_logs) < limit:
        params = {
            "filters": filter,
            "page": page,
            "per_page": per_page
        }
        url = urljoin(audit_logs_url, "audit-api/get-logs") # TODO: check that this endpoint correct

        try:
            response = requests.get(url, headers=headers, params=params, verify=USE_SSL)
        except Exception as e:
            return_error(f"Error in connection to the server. Please make sure you entered the URL correctly. Exception is {e!s}.")
        
        if response.status_code == 429:
            demisto.debug(f"Rate limit reached for audit logs. Status code: {response.status_code}\n{response.text}")
            return fetched_logs
        if response.status_code != 200:
            raise DemistoException(f"Failed to get audit logs. Status code: {response.status_code}\n{response.text}")
        
        logs = response.json().get("data", [])
        fetched_logs.extend(logs)
        
        if not response.json().get("next_page"):
            demisto.debug("No more Audit Logs, reached the last page.")
            return fetched_logs
        
        page += 1
        per_page = min(MAX_PER_PAGE, limit - len(fetched_logs))
        
    return fetched_logs

# TODO: Add comments
def fetch_audit_logs(last_run: dict) -> tuple[dict, list]:
    
    params = demisto.params()
    now_ms = int(time.time() * 1000)
    first_fetch = 3 * 365 * 24 * 60 * 60 * 1000     # TODO: change it to  (60 * 1000)-one minutes, now its 3 days
    
    end_time = timestamp_to_datestring(now_ms, date_format=DATE_FORMAT)
    start_time = last_run.get("last_timestamp") or timestamp_to_datestring(now_ms - first_fetch, date_format=DATE_FORMAT)

    
    demisto.debug(f"Fetching Audit Logs from: {start_time} to {end_time}")
    
    audit_logs = []
    fetch_limit = int(params.get("max_audit_logs_per_fetch", 50000))
    
    # TODO: I dont think that the time filter params is with the correct format for Monday api, check it.
    time_filter = f'{{"start_time":"{start_time}","end_time":"{end_time}"}}'
    
    try:
        audit_logs = get_audit_logs(filter=time_filter, limit=fetch_limit)
    except Exception as e:
        return_error(f"Error in connection to the server. Please make sure you entered the URL correctly. Exception is {e!s}.")
    
    
    
    audit_logs = add_time_field_to_logs(audit_logs)
    demisto.debug(f"Fetched {len(audit_logs)} audit logs before deduplication.")
    
    # Remove duplicates based on previous fetch
    audit_logs = remove_duplicate_logs(audit_logs, last_run)    #  TODO: check the logic of this function when last_timestamp!=None
    demisto.debug(f"Fetched {len(audit_logs)} audit logs after deduplication.")
    
    # Update last_run for next fetch
    next_last_run = update_last_run_state(audit_logs, last_run, now_ms)
    
    return next_last_run, audit_logs

def add_time_field_to_logs(logs: list) -> list:
    """Add _time field to logs for XSOAR ingestion."""
    for log in logs:
        timestamp_str = log.get("timestamp")
        if timestamp_str:
            # Parse the timestamp with milliseconds and reformat without milliseconds
            dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            log["_time"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            log["_time"] = None
    return logs


def remove_duplicate_logs(logs: list, last_run: dict) -> list:
    """
    Remove duplicate logs based on previous fetch state.
    
    Args:
        logs: List of audit logs from current fetch
        last_run: Previous fetch state containing last_timestamp and processed_ids
    
    Returns:
        List of deduplicated logs
    """
    if not logs:
        return logs
    
    last_timestamp = last_run.get("last_timestamp")
    processed_ids = set(last_run.get("processed_ids", []))
    
    if not last_timestamp:
        return logs  # First run, no deduplication needed
    
    deduplicated_logs = []
    
    for log in logs:
        # Create composite unique identifier since Monday logs don't have a single "id" field
        composite_id = f"{log.get('timestamp')}_{log.get('user_id')}_{log.get('event')}_{log.get('account_id')}"
        log_timestamp = log.get("timestamp")
        
        # Skip if we've already processed this event
        if composite_id in processed_ids:
            demisto.debug(f"Skipping duplicate log ID: {composite_id}")
            continue
            
        # Skip events older than our last processed timestamp
        if log_timestamp and log_timestamp < last_timestamp:
            demisto.debug(f"Skipping older log: {log_timestamp} < {last_timestamp}")
            continue
            
        deduplicated_logs.append(log)
    
    return deduplicated_logs


def update_last_run_state(logs: list, current_last_run: dict, current_time_ms: int) -> dict:
    """
    Update last_run state for next fetch cycle.
    
    Args:
        logs: List of processed logs from current fetch
        current_last_run: Current last_run state
        current_time_ms: Current time in milliseconds
    
    Returns:
        Updated last_run dictionary
    """
    if not logs:
        # No new logs, reset processed_ids since future events will have different timestamps
        return {
            "last_timestamp": timestamp_to_datestring(current_time_ms, date_format=DATE_FORMAT),
            "processed_ids": []
        }
    
    # TODO: check, I dont think is necessary, the logs are already sorted by timestamp when fetched from the API
    # index 0: the newest log, index -1: the oldest log (we need to store the newest log timestamp to avoid fetching the same logs again)
        # sorted_logs = sorted(logs, key=lambda x: x.get("timestamp", ""))
        # latest_log = sorted_logs[-1]
    latest_log = logs[0]
    latest_timestamp = latest_log.get("timestamp")
    
    # Find all logs with the same timestamp as the latest (optimized for sorted logs)
    same_timestamp_logs = []
    for log in logs:
        if log.get("timestamp") == latest_timestamp:
            same_timestamp_logs.append(log)
        else:
            # Since logs are sorted by timestamp (newest first), we can stop when timestamp changes
            break
    
    same_timestamp_ids = []
    for log in same_timestamp_logs:
        # Create composite unique identifier since Monday logs don't have a single "id" field
        # Combine timestamp + user_id + event + account_id for uniqueness
        composite_id = f"{log.get('timestamp')}_{log.get('user_id')}_{log.get('event')}_{log.get('account_id')}"
        same_timestamp_ids.append(composite_id)
    
    # Convert time to the correct format to use it as start_time params of Monday Audit Logs API
    dt = datetime.strptime(latest_timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    latest_timestamp = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    return {
        "last_timestamp": latest_timestamp,
        "processed_ids": same_timestamp_ids
        }

def fetch_activity_logs(last_run: dict) -> tuple[dict, list]:
    activity_logs = []
    params = demisto.params()
    
    fetch_limit = int(params.get("max_activity_logs_per_fetch", 50000))
    activity_logs_url = params.get("activity_logs_url", "https://api.monday.com")
    board_ids = argToList(params.get("board_ids", ""))
    auth_code = params.get("auth_code", "")
    
    return last_run, activity_logs

def fetch_events() -> tuple[dict, list]:
    """
    Fetch events from Monday based on configuration. (Activity Logs and Audit Logs)

    Returns:
        tuple: (last_run, events) where last_run is the updated state and events are the fetched logs.
    """
    events = []
    params = demisto.params()
    last_run = demisto.getLastRun()
    if not last_run:
        last_run = {AUDIT_LOGS_TYPE: {}, ACTIVITY_LOGS_TYPE: {}}
    
    last_run_audit_logs = last_run.get(AUDIT_LOGS_TYPE, {})
    last_run_activity_logs = last_run.get(ACTIVITY_LOGS_TYPE, {})
    
    selected_event_types = params.get("selected_event_types", "")
    demisto.debug(f"Selected event types: {selected_event_types}")
    
    if AUDIT_LOGS_TYPE in selected_event_types:
        demisto.debug("Monday: Start fetch Audit Logs")
        demisto.debug(f"Monday: Current Audit Logs last_run object: {last_run_audit_logs}")

        last_run_audit_logs, fetched_audit_logs = fetch_audit_logs(last_run_audit_logs)
        events.extend(fetched_audit_logs)
        
    if ACTIVITY_LOGS_TYPE in selected_event_types:
        demisto.debug("Monday: Start fetch Activity Logs")
        demisto.debug(f"Monday: Current Activity Logs last_run object: {last_run_activity_logs}")
        
        last_run_activity_logs, fetched_activity_logs = fetch_activity_logs(last_run_activity_logs)
        events.extend(fetched_activity_logs)
    
    last_run = {
        AUDIT_LOGS_TYPE: last_run_audit_logs,
        ACTIVITY_LOGS_TYPE: last_run_activity_logs
    }
    return last_run, events


""" MAIN FUNCTION """

def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    
    params = demisto.params()
    command = demisto.command()
            
    # TODO: move the unnecessary/unused parameters here, to the right function they in use.
    client_id = params.get("client_id", "")
    secret = params.get("secret",  "")
    auth_code = params.get("auth_code", "")
    proxy = bool(params.get("proxy", False))
    verify_certificate = not bool(params.get("insecure", False))    # TODO: use this at the correct place
    
        
    # TODO: move it to the fetch logic
    # How much time before the first fetch to retrieve events
    first_fetch_time = datetime.now().isoformat()

    demisto.debug(f"Command being called is {command}")
    try:
        # TODO: Ask what the test module command should test
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            # result = test_module(params, first_fetch_time)
            return_results(result)
        elif command == "monday-generate-login-url":
            return_results(generate_login_url(client_id))
        elif command == "monday-auth-test":
            return_results(test_connection(client_id, secret, auth_code))
            
        # TODO: implement this command
        elif command == "fetch-events":
            last_run, events = fetch_events()
            
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            
            demisto.setLastRun(last_run)
            demisto.debug(f"Monday: Updated last_run object after fetch: {last_run}")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
