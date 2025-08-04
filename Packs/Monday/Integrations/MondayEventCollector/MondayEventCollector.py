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
AUDIT_LOGS_LIMIT = int(PARAMS.get("max_audit_logs_per_fetch", 50000))
AUDIT_LOGS_PER_PAGE = min(MAX_PER_PAGE, AUDIT_LOGS_LIMIT) # must stay the same during all the fetch audit logs runs.

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


# it is possible to use this function only id audit logs limit is bigger the 1,000 (AUDIT_LOGS_PER_PAGE must be 1,000)
def get_remaining_audit_logs(last_run: dict) -> tuple[list, dict]:
    excess_logs_info = last_run.get("excess_logs_info")
    offset = excess_logs_info.get("offset")
    page = excess_logs_info.get("page")
    start_time = excess_logs_info.get("start_time")
    end_time = excess_logs_info.get("end_time")
    
    demisto_params = demisto.params()
    audit_logs_url = demisto_params.get("audit_logs_url", "")
    audit_token = demisto_params.get("audit_token", "")
    
    time_filter = f'{{"start_time":"{start_time}","end_time":"{end_time}"}}'
    params = {
        "filters": time_filter,
        "page": page,
        "per_page": AUDIT_LOGS_PER_PAGE
    }
    headers = {
        "Authorization": f"Bearer {audit_token}",
        "Content-Type": "application/json"
    }
    
    url = urljoin(audit_logs_url, "audit-api/get-logs")

    try:
        response = requests.get(url, headers=headers, params=params, verify=USE_SSL)
        
        if response.status_code != 200:
            raise DemistoException(f"Failed to get audit logs. Status code: {response.status_code}\n{response.text}")
    
        fetched_logs = response.json().get("data", [])
        last_run["excess_logs_info"] = None
        return fetched_logs[offset:], last_run
    except Exception as e:
        return_error(f"Error in connection to the server. Please make sure you entered the URL correctly. Exception is {e!s}") # TODO: change it to raise exception
    

def get_newest_log_id_with_same_timestamp(logs: list):
    if not logs:
        return []
    
    newest_log_timestamp = logs[0].get("timestamp")
    same_timestamp_ids = []
    
    for log in logs:
        if log.get("timestamp") == newest_log_timestamp:
            # TODO: change id to hash function
            composite_id = f"{log.get('timestamp')}_{log.get('user_id')}_{log.get('event')}_{log.get('account_id')}"
            same_timestamp_ids.append(composite_id)
        else:
            return same_timestamp_ids
    
    return same_timestamp_ids


def remove_duplicate_logs(logs: list, lower_bound_log_id: list) -> list:
    """
    Remove duplicate logs based on previous fetch.
    
    Args:
        logs: List of fetched logs
        current_last_run: Current last_run state
    
    Returns:
        List of logs without duplicates
    """
    if not logs:
        return logs
    
    # It is happening in the first fetch-events run or when it is the next non-empty fetch after empty fetch run.
    # In this case, there is no lower bound log id.
    if not lower_bound_log_id:
        return logs
    
    # Remove duplicates logs that already fetched in the previous run.
    # (start from the end of the list to compare the oldest log to the lower bounds ids from the previous run)
    logs_without_duplicates = logs.copy()
    for log in logs[-1::-1]:
        if log.get("id") in lower_bound_log_id:    # TODO: change to hash function
            logs_without_duplicates.remove(log)
            break
    
    return logs_without_duplicates


# When calling this function, last_run does not contain the "excess_logs_info" key.
# We are handling the case where we have remaining logs to fetch from the previous fetch before calling this function.
def get_audit_logs(last_run: dict, now_ms: int, limit: int) -> tuple[dict, list]:
    """
    Fetch audit logs from Monday based on configuration.

    Args:
        last_run: Previous fetch state containing last_timestamp and fetched_ids
        now_ms: Current time in milliseconds

    Returns:
        tuple: (last_run, logs) where last_run is the updated state and logs are the fetched logs.
    """
    
    # TODO: Validate audit_token is not empty before starting the fetch
    demisto_params = demisto.params()
    audit_logs_url = demisto_params.get("audit_logs_url", "")
    audit_token = demisto_params.get("audit_token", "")
    remaining_logs = 0
    
    newest_log_timestamp = ""
    total_logs = []

    # Not all logs were fetched in the previous fetch between start_time and end_time.
    if last_run.get("continuing_fetch_info"):
        is_continuing_fetch = True
        continuing_fetch_info = last_run.get("continuing_fetch_info")
        page = continuing_fetch_info.get("page")
        start_time = continuing_fetch_info.get("start_time")
        end_time = continuing_fetch_info.get("end_time")
        demisto.debug(f"Continuing fetch for Audit Logs from: {start_time} to {end_time}\nPage: {page}")
    
    # First fetch in the current time range.
    else:
        is_continuing_fetch = False
        end_time = timestamp_to_datestring(now_ms, date_format=DATE_FORMAT)

        if last_run.get("last_timestamp"):
            dt = datetime.strptime(last_run.get("last_timestamp"), "%Y-%m-%dT%H:%M:%S.%fZ")
            start_time = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            start_time = timestamp_to_datestring(now_ms - FETCH_TIME, date_format=DATE_FORMAT)

        page = 1
        demisto.debug(f"Starting new fetch for Audit Logs from: {start_time} to {end_time}\nPage: {page}")

    time_filter = f'{{"start_time":"{start_time}","end_time":"{end_time}"}}'
    headers = {
        "Authorization": f"Bearer {audit_token}",
        "Content-Type": "application/json"
    }

    '''
        The first condition that reached will exit the loop:
        1. len(total_logs) >= limit
        2. next_page = None
    '''
    while len(total_logs) < limit:
        
        params = {
            "filters": time_filter,
            "page": page,
            "per_page": AUDIT_LOGS_PER_PAGE
        }
        
        url = urljoin(audit_logs_url, "audit-api/get-logs")
        remaining_logs = limit - len(total_logs)
        
        try:
            # Monday API possible response codes: 200, 400, 401, 429, 500
            response = requests.get(url, headers=headers, params=params, verify=USE_SSL)
        except Exception as e:
            return_error(f"Error in connection to the server. Please make sure you entered the URL correctly. Exception is {e!s}") # TODO: change it to raise exception
        
        '''
            Rate limit reached - up to 50 requests per minute.
            Can be reached only if the user configured limit equal to 50,000.
            The maximum logs can be fetched per request is 1,000 so the maximum logs can be fetched per minute is 50*1,000=50,000
            TODO: I dont think this part will be reached because the limit the user can set is 50,000.
        '''
        if response.status_code == 429:
            demisto.debug(f"Rate limit reached for audit logs. Status code: {response.status_code}\n{response.text}")
            
            # Next run, starts fetching from this current page with the same time filter, resend the same request.
            last_run["continuing_fetch_info"] = {"page": page, "start_time": start_time, "end_time": end_time}
            
            if not is_continuing_fetch:
                last_run["last_timestamp"] = newest_log_timestamp
            
            return total_logs, last_run

        if response.status_code != 200:
            # TODO: check, should I also return the fetched logs so far + last_run which support continuing fetch? or should I raise only exception?
            raise DemistoException(f"Failed to get audit logs. Status code: {response.status_code}\n{response.text}")
        

        # Status code 200
        fetched_logs = response.json().get("data", [])
        total_logs.extend(fetched_logs)
        
        if page == 1:
            if fetched_logs:
                # Handle duplicate.
                # There is no need to save all logs ids, only the newest log id with the same timestamp (upper bound) which will check in the next fetch with the oldest log timestamp (lower bound)
                last_run["upper_bound_log_id"] = get_newest_log_id_with_same_timestamp(fetched_logs)
                newest_log_timestamp = fetched_logs[0].get("timestamp")
            else:
                newest_log_timestamp = ""
                last_run["upper_bound_log_id"] = None
                last_run["lower_bound_log_id"] = None

        # last page reached, next_page = None, meaning there are no more logs to fetch.
        # We can remove duplicate logs based on the lower bound logs set on the previous fetch.
        if not response.json().get("next_page"):
            
            lower_bound_log_id = last_run.get("lower_bound_log_id")
            fetched_logs = remove_duplicate_logs(fetched_logs, lower_bound_log_id)
            last_run["lower_bound_log_id"] = last_run.get("upper_bound_log_id") # The upper bound log id is the lower bound in the next fetch
            
            # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
            if not is_continuing_fetch:
                last_run["last_timestamp"] = newest_log_timestamp
            
            if len(fetched_logs) > remaining_logs:
                last_run["excess_logs_info"] = {"page": page, "start_time": start_time, "end_time": end_time, "offset": remaining_logs}
                total_logs = total_logs[:limit]
            
            last_run["continuing_fetch_info"] = None
                
            return total_logs, last_run
        
        page += 1

    # At this point, limit is reached so we need to continue fetching (next_page = None is not reached)
    last_run["continuing_fetch_info"] = {"page": page, "start_time": start_time, "end_time": end_time}
    
    # Only partial logs were fetched from the last page when limit is reached.
    if remaining_logs:
        last_run["excess_logs_info"] = {"page": page - 1, "start_time": start_time, "end_time": end_time, "offset": remaining_logs}
    
    # The first fetch in the current run, set the last_timestamp to the time of the newest log.
    # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
    if not is_continuing_fetch:
        last_run["last_timestamp"] = newest_log_timestamp
        
    return total_logs[:limit], last_run

# TODO: Add comments
def fetch_audit_logs(last_run: dict) -> tuple[dict, list]:
    # TODO: IMPORTANT!!!! notice that last_timestamp saved in the original time foramt, and also start_time and end_time.
    # The only value that will convert before stored is the _time column key we add.
    # this is important because when removing duplicates we need to compare times, check that all at the same format.
    # !!!!! ONLT BEFIRE creting the filter for the API call we need to convert the times to the matching format.
    
    now_ms = int(time.time() * 1000)
    audit_logs = []
    limit = int(demisto.params().get("max_audit_logs_per_fetch", 50000))
    try:
        # Handle fetching remaining logs from previous fetch
        if last_run.get("excess_logs_info"):
            excess_logs, last_run = get_remaining_audit_logs(last_run)
            audit_logs.extend(excess_logs)
            limit -= len(excess_logs)

        audit_logs, last_run = get_audit_logs(last_run=last_run, now_ms=now_ms, limit=limit)
    
    except Exception as e:
        return_error(f"Failed to fetch audit logs. Exception: {e}") # TODO: check when to use return_error and when to raise exception

    audit_logs = add_time_field_to_logs(audit_logs)
    
    # Update last_run for next fetch
    next_last_run = update_last_run_state(audit_logs, last_run, now_ms, is_first_fetch_on_current_time_range)
    
    return next_last_run, audit_logs

def add_time_field_to_logs(logs: list) -> list:
    for log in logs:
        timestamp_str = log.get("timestamp")
        if timestamp_str:
            # Parse the timestamp with milliseconds and reformat without milliseconds
            dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            log["_time"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            log["_time"] = None
    return logs


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
