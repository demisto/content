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

day_ms = 365 * 24 * 60 * 60 * 1000
FETCH_TIME = 3 * day_ms             # TODO: change it to  (60 * 1000)-one minutes, now its 3 days

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}

""" CLIENT CLASS """
# TODO: add function comments
# TODO: edit debug logs prints

# def test_module(client: BaseClient, params: dict[str, Any], first_fetch_time: str) -> str:
#     """
#     Tests API connectivity and authentication
#     When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
#     successful.
#     Raises exceptions if something goes wrong.

#     Args:
#         client (Client): HelloWorld client to use.
#         params (Dict): Integration parameters.
#         first_fetch_time(str): The first fetch time as configured in the integration params.

#     Returns:
#         str: 'ok' if test passed, anything else will raise an exception and will fail the test.
#     """

#     try:
#         alert_status = params.get("alert_status", None)

#         fetch_events(
#             client=client,
#             last_run={},
#             first_fetch_time=first_fetch_time,
#             alert_status=alert_status,
#             max_events_per_fetch=1,
#         )

#     except Exception as e:
#         if "Forbidden" in str(e):
#             return "Authorization Error: make sure API Key is correctly set"
#         else:
#             raise e

#     return "ok"


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
        # NOTE: if I am using requests.lib i need to handle the code success and exception, add error handling
        # response = http_request("POST", AUTH_URL, headers=headers, data=payload)
        response = requests.post(url=AUTH_URL, headers=headers, data=payload, verify=USE_SSL)
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


def get_audit_logs(last_run: dict, now_ms: int) -> tuple[dict, list]:
    
    demisto_params = demisto.params()
    # TODO: Validate audit_token is not empty before starting the fetch
    audit_logs_url = demisto_params.get("audit_logs_url", "")
    audit_token = demisto_params.get("audit_token", "")
    limit = int(demisto_params.get("max_audit_logs_per_fetch", 50000))

    # NOTE: if last_run.get("continuing_fetch_info") - this fetch is part of a previous fetch, fetch from the next page at the same time window.
    if last_run.get("continuing_fetch_info"):
        is_continuing_fetch = True
        continuing_fetch_info = last_run.get("continuing_fetch_info")
        
        page = continuing_fetch_info.get("next_page")
        start_time = continuing_fetch_info.get("start_time")
        end_time = continuing_fetch_info.get("end_time")
        demisto.debug(f"Continuing fetch for Audit Logs from: {start_time} to {end_time}\nPage: {page}")
    else:
        is_continuing_fetch = False
        end_time = timestamp_to_datestring(now_ms, date_format=DATE_FORMAT)
        start_time = last_run.get("last_timestamp") or timestamp_to_datestring(now_ms - FETCH_TIME, date_format=DATE_FORMAT)
        page = 1
        demisto.debug(f"Statring new fetch for Audit Logs from: {start_time} to {end_time}\nPage: {page}")
        

    time_filter = f'{{"start_time":"{start_time}","end_time":"{end_time}"}}'
    headers = {
        "Authorization": f"Bearer {audit_token}",
        "Content-Type": "application/json"
    }

    fetched_logs = []
    per_page = min(MAX_PER_PAGE, limit)
    newest_log_timestamp = ""
    
    # NOTE:I fetch the minimum of limit and MAX_PER_PAGE
    # the only case that this condition can be false is when the fetch exactly the limit logs.
    # I need to check if I need to continue fetching from this current time window or start a new fetch
    # (exception case, when the limit is exactly the amount of logs that fetched from monday.com api from start_time to end_time)
    while len(fetched_logs) < limit:
        params = {
            "filters": time_filter,
            "page": page,
            "per_page": per_page
        }
        url = urljoin(audit_logs_url, "audit-api/get-logs")

        try:
            response = requests.get(url, headers=headers, params=params, verify=USE_SSL)
        except Exception as e:
            return_error(f"Error in connection to the server. Please make sure you entered the URL correctly. Exception is {e!s}")
        
        # TODO: add comments, possible codes: 200, 400, 401, 429, 500
        if response.status_code == 429:
            demisto.debug(f"Rate limit reached for audit logs. Status code: {response.status_code}\n{response.text}")
            
            continuing_fetch_info = {"next_page": page, "start_time": start_time, "end_time": end_time}
            if is_continuing_fetch:
                previous_last_timestamp = last_run.get("last_timestamp")
                return fetched_logs, {"last_timestamp": previous_last_timestamp, "continuing_fetch_info": continuing_fetch_info}
            else:
                # TODO:add comment: newest_log_timestamp is the timestamp of the newest log in the current fetch - it saved for the next fetch when finishing this current fetch.
                return fetched_logs, {"last_timestamp": newest_log_timestamp, "continuing_fetch_info": continuing_fetch_info}

        if response.status_code != 200:
            # TODO: should I also return the fetched logs so far + last_run which support continuing fetch? or should I raise only exception?
            raise DemistoException(f"Failed to get audit logs. Status code: {response.status_code}\n{response.text}")
        
        # status code 200
        logs = response.json().get("data", [])
        fetched_logs.extend(logs)
        
        if page == 1:
            if logs:
                newest_log_timestamp = logs[0].get("timestamp")
            else:
                newest_log_timestamp = ""

        if not response.json().get("next_page"):
            demisto.debug("No more Audit Logs.")
            if is_continuing_fetch:
                previous_last_timestamp = last_run.get("last_timestamp")
                return fetched_logs, {"last_timestamp": previous_last_timestamp}
            else:
                return fetched_logs, {"last_timestamp": newest_log_timestamp}
        
        page += 1
        per_page = min(MAX_PER_PAGE, limit - len(fetched_logs))
    
    demisto.debug(f"Fetch Audit Logs finished, Fetch max limit: {limit}")
    continuing_fetch_info = {"next_page": page, "start_time": start_time, "end_time": end_time}
    if is_continuing_fetch:
        previous_last_timestamp = last_run.get("last_timestamp")
        last_timestamp = previous_last_timestamp
    else:
        last_timestamp = newest_log_timestamp
    return fetched_logs, {"last_timestamp": last_timestamp, "continuing_fetch_info": continuing_fetch_info}

# TODO: Add comments
def fetch_audit_logs(last_run: dict) -> tuple[dict, list]:
    
    now_ms = int(time.time() * 1000)
    audit_logs = []
    
    try:
        audit_logs, last_run = get_audit_logs(last_run=last_run, now_ms=now_ms)
    except Exception as e:
        return_error(f"Error in connection to the server. Please make sure you entered the URL correctly. Exception is {e!s}.")
    
    audit_logs = add_time_field_to_logs(audit_logs)
    demisto.debug(f"Fetched {len(audit_logs)} audit logs before deduplication.")
    
    # Remove duplicates based on previous fetch
    audit_logs = remove_duplicate_logs(audit_logs, last_run)    # TODO: check the logic of this function when last_timestamp!=None
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
        # TODO: change it to Hash function
        # Create composite unique identifier since Monday logs don't have a single "id" field
        # Combine timestamp + user_id + event + account_id for uniqueness
        composite_id = f"{log.get('timestamp')}_{log.get('user_id')}_{log.get('event')}_{log.get('account_id')}"
        same_timestamp_ids.append(composite_id)
    
    # Convert time to the correct format to use it as start_time params of Monday Audit Logs API
    dt = datetime.strptime(latest_timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    latest_timestamp = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    current_last_run["processed_ids"] = same_timestamp_ids
    return {
        "last_timestamp": latest_timestamp,
        "processed_ids": same_timestamp_ids
        }

def fetch_activity_logs(last_run: dict) -> tuple[dict, list]:
    activity_logs = []
    params = demisto.params()
    
    fetch_limit = int(params.get("max_activity_logs_per_fetch", 50000))
    activity_logs_url = params.get("activity_logs_url", "https://api.monday.com")
    access_token = params.get("access_token", "")
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
            
    client_id = params.get("client_id", "")
    secret = params.get("secret",  "")
    auth_code = params.get("auth_code", "")
    proxy = bool(params.get("proxy", False))

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
            
        elif command == "fetch-events":
            last_run, events = fetch_events()
            
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            
            demisto.setLastRun(last_run)
            demisto.debug(f"Monday: Updated last_run object after fetch: {last_run}")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
