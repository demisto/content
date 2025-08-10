import uuid
import hashlib
import json
import demistomock as demisto # noqa: F401
from CommonServerPython import *
import urllib3
import pandas as pd

from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "Monday"
PRODUCT = "Monday"

# Event type string as appears in the yml file
AUDIT_LOGS_TYPE = "Audit Logs"
ACTIVITY_LOGS_TYPE = "Activity Logs"

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO 8601 format TODO: check that this is the correct format in anyplace used.

SCOPE = "boards:read"
REDIRECT_URI = "https://localhost"
AUTH_URL = "https://auth.monday.com/oauth2/token"

# API limit
MAX_AUDIT_LOGS_PER_PAGE = 1000
MAX_ACTIVITY_LOGS_PER_PAGE = 10000

PARAMS = demisto.params()
PROXY = PARAMS.get("proxy", False)
USE_SSL = not PARAMS.get("insecure", False)

day_ms = 365 * 24 * 60 * 60 * 1000
FETCH_TIME = 3 * day_ms             # TODO: change it to  (60 * 1000)-one minutes, now its 3 days

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}

AUDIT_LOGS_LIMIT = int(PARAMS.get("max_audit_logs_per_fetch", 5000))
AUDIT_LOGS_PER_PAGE = min(MAX_AUDIT_LOGS_PER_PAGE, AUDIT_LOGS_LIMIT) # must stay the same during all the fetch audit logs runs.

ACTIVITY_LOGS_LIMIT = int(PARAMS.get("max_activity_logs_per_fetch", 10000))
ACTIVITY_LOGS_PER_PAGE = min(MAX_ACTIVITY_LOGS_PER_PAGE, ACTIVITY_LOGS_LIMIT) # must stay the same during all the fetch activity logs runs.

# Debug prefixes - used for logging
AUDIT_LOG_DEBUG_PREFIX = "Audit Logs- MondayEventCollector Debug Message:\n"
ACTIVITY_LOG_DEBUG_PREFIX = "Activity Logs- MondayEventCollector Debug Message:\n"
DEBUG_PREFIX = "MondayEventCollector Debug Message:\n"


""" CLIENT CLASS """
# TODO: add function comments

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
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Client ID parameter is missing.")
        raise DemistoException("Please provide Client ID in the integration parameters before running monday-generate-login-url.")
    
    login_url = f'https://auth.monday.com/oauth2/authorize?client_id={client_id}'

    result_msg = f"""Click on the [login URL]({login_url}) to sign in and grant Cortex XSOAR the permissions.
    You will be automatically redirected to a link with the following structure:
    ```REDIRECT_URI?code=AUTH_CODE&region=REGION&scope=boards%3Aread&state=```
    Copy the `AUTH_CODE` (without the `code=` prefix)
    and paste it in your instance configuration under the **Authorization code** parameter.
    """
    return CommandResults(readable_output=result_msg)


def get_access_token() -> str:
    """
    Exchange authorization code for access token from Monday.com
    """
    integration_context = get_integration_context()
    access_token = integration_context.get("access_token", "")
    if access_token:
        demisto.debug(f"{DEBUG_PREFIX}Access token already exists in integration context")
        return access_token
    
    params = demisto.params()
    client_id = params.get("client_id", "")
    secret = params.get("secret", "")
    auth_code = params.get("auth_code", "")
    
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
        # NOTE: if I am using requests.lib i need to handle the code success and exception, add error handling
        # response = http_request("POST", AUTH_URL, headers=headers, data=payload)
        response = requests.post(url=AUTH_URL, headers=headers, data=payload, verify=USE_SSL)

        if response.status_code != 200:
            demisto.debug(f"{DEBUG_PREFIX}Failed to get access token. response status code: {response.status_code}\n{response.text}")
            raise DemistoException(f"Failed to get access token. Status code: {response.status_code}")

        access_token = response.json().get("access_token")

        if not access_token:
            demisto.debug(f"{DEBUG_PREFIX}Response missing access_token")
            raise DemistoException("Response missing access_token")

        integration_context.update({"access_token": access_token})
        set_integration_context(integration_context)
        demisto.debug(f"{DEBUG_PREFIX}Access token received successfully and set to integration context")
        
        return access_token

    except Exception as e:
        demisto.debug(f"{DEBUG_PREFIX}Error retrieving access token: {str(e)}")
        raise DemistoException(f"Error retrieving access token: {str(e)}")

    
def test_connection() -> CommandResults:
    """
    Test connectivity in the Authorization Code flow mode for activity logs.
    """
    get_access_token() # exception on failure
    return CommandResults(readable_output='✅ Success!')


def get_remaining_audit_logs(last_run: dict) -> tuple[list, dict]:
    """
    Fetch remaining audit logs from Monday based on configuration.
    Called only if the user set the audit logs limit to be bigger than 1,000,
    and there are remaining logs to fetch from the last fetch run.
    
    Args:
        last_run (dict): The last run of the fetch.
    
    Returns:
        tuple[list, dict]: The remaining audit logs and the updated last run.
    """
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
    
    demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Requesting remaining audit logs from previous fetch.\nURL: {url}, Params: {params}, Offset: {offset}")
    
    try:
        response = requests.get(url, headers=headers, params=params, verify=USE_SSL)
        
        if response.status_code != 200:
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Failed to get remaining audit logs. response status code: {response.status_code}\n{response.text}")
            raise DemistoException(f"Failed to get remaining audit logs. response status code: {response.status_code}\n{response.text}")
    
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Response: {response.text}, Status code: {response.status_code}")
        fetched_logs = response.json().get("data", [])
        last_run["excess_logs_info"] = None
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Total remaining audit logs fetched: {len(fetched_logs[offset:])} logs")
        
        return fetched_logs[offset:], last_run
    
    except Exception as e:
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Exception during get remaining audit logs. Exception is {e!s}")
        raise DemistoException(f"Exception during get remaining audit logs. Exception is {e!s}")


def generate_log_hash(log: dict) -> str:
    """
    Generate a unique hash for a log entry based on the entire log object.
    
    Args:
        log: Log dictionary containing event data
        
    Returns:
        str: SHA-256 hash of the entire log object
    """
    # Create a consistent string formatting representation of the entire log for hashing. (sorted and without spaces)
    hash_string = json.dumps(log, sort_keys=True, separators=(',', ':'))
    
    # Generate SHA-256 hash
    return hashlib.sha256(hash_string.encode('utf-8')).hexdigest()


def get_newest_log_id_with_same_timestamp(logs: list, time_key: str, is_id_field_exists: bool):
    if not logs:
        return []
    
    newest_log_timestamp = logs[0].get(time_key)
    same_timestamp_ids = []
    
    for log in logs:
        if log.get(time_key) == newest_log_timestamp:
            if not is_id_field_exists:
                log_id = generate_log_hash(log)
            else:
                log_id = log.get("id")
            same_timestamp_ids.append(log_id)
        else:
            return same_timestamp_ids
    
    return same_timestamp_ids


def convert_17_digit_unix_time_to_ISO8601(ts):
    ts_int = int(ts)
    seconds = ts_int / 10_000_000      # convert to seconds
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    dt = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return dt

def remove_duplicate_logs(logs: list, lower_bound_log_id: list, is_id_field_exists: bool) -> list:
    """
    Remove duplicate logs based on previous fetch.
    
    Args:
        logs: List of fetched logs
        current_last_run: Current last_run state
        is_id_field_exists: Whether the id field exists in the logs
    
    Returns:
        List of logs without duplicates
    """
    if not logs:
        demisto.debug(f"{DEBUG_PREFIX}No logs to remove duplicates from.")
        return logs
    
    # It is happening in the first fetch-events run or when it is the next non-empty fetch after empty fetch run.
    # In this case, there is no lower bound log id.
    if not lower_bound_log_id:
        demisto.debug(f"{DEBUG_PREFIX}No lower bound log id to remove duplicates from.")
        return logs
    
    # Remove duplicates logs that already fetched in the previous run.
    # (start from the end of the list to compare the oldest log to the lower bounds ids from the previous run)
    logs_without_duplicates = logs.copy()
    for log in logs[-1::-1]:
        if not is_id_field_exists:
            log_id = generate_log_hash(log)
        else:
            log_id = log.get("id")
        if log_id in lower_bound_log_id:
            demisto.debug(f"{DEBUG_PREFIX}Removing duplicate log: {log_id}")
            logs_without_duplicates.remove(log)
            break

    return logs_without_duplicates


def is_empty_page(query: str, url: str, headers: dict) -> bool:
    """
    Check if the page is empty based on the response.
    Args:
        query: Query to fetch logs.
        url: URL to fetch logs from.
        headers: Headers to fetch logs with.
    Returns:
        bool: True if the page is empty, False otherwise.
    """
    
    try:
        response = requests.post(url, headers=headers, json={"query": query}, verify=USE_SSL)
        
        if response.status_code != 200:
            demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Failed to check if page is empty. response status code: {response.status_code}\n{response.text}")
            raise DemistoException(f"Failed to check if page is empty. response status code: {response.status_code}\n{response.text}")

        fetched_logs = response.json()["data"]["boards"][0]["activity_logs"]
        return not fetched_logs
    
    except Exception as e:
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Exception during check if page is empty. Exception is {e!s}")
        raise DemistoException(f"Exception during check if page is empty. Exception is {e!s}")


def get_activity_logs(last_run: dict, now_ms: int, limit: int) -> tuple[dict, list]:
    """
    Fetch activity logs from Monday based on configuration.

    Args:
        last_run: Previous fetch state containing last_timestamp and fetched_ids
        now_ms: Current time in milliseconds

    Returns:
        tuple: (last_run, logs) where last_run is the updated state and logs are the fetched logs.
    """
    
    demisto_params = demisto.params()
    activity_logs_url = demisto_params.get("activity_logs_url", "")
    board_ids = demisto_params.get("board_ids", "") # TODO: ask about it, how to fetch from multiple boards in one request with limit of logs to fetch??? (the current logic is to fetch from one board at a time)
    
    access_token = get_access_token()
    
    if not activity_logs_url:
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}activity logs url is missing.")
        raise DemistoException("Please provide Activity logs Server URL in the integration parameters before starting to fetch activity logs.")
    
    if not board_ids:
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}board ids is missing.")
        raise DemistoException("Please provide board ids in the integration parameters before starting to fetch activity logs.")
    
    remaining_logs = 0
    fetched_logs = []
    
    newest_log_timestamp = ""
    total_logs = []

    # Not all logs were fetched in the previous fetch between start_time and end_time.
    if last_run.get("continuing_fetch_info"):
        is_continuing_fetch = True
        continuing_fetch_info = last_run.get("continuing_fetch_info")
        page = continuing_fetch_info.get("page")
        start_time = continuing_fetch_info.get("start_time")
        end_time = continuing_fetch_info.get("end_time")
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Continuing fetch for Activity Logs from: {start_time} to {end_time}\nPage: {page}")
    
    # TODO: Check this time format and change . to %E2 if needed.
    # First fetch in the current time range.
    else:
        is_continuing_fetch = False
        end_time = timestamp_to_datestring(now_ms, date_format="%Y-%m-%dT%H:%M:%S.%fZ")

        if last_run.get("last_timestamp"):
            start_time = last_run.get("last_timestamp")
        else:
            start_time = timestamp_to_datestring(now_ms - FETCH_TIME, date_format="%Y-%m-%dT%H:%M:%S.%fZ")

        page = 1
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Starting new fetch range for Activity Logs from: {start_time} to {end_time}\nPage: {page}")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    url = urljoin(activity_logs_url, "v2")

    '''
        The first condition that reached will exit the loop:
        1. len(total_logs) >= limit
        2. next_page = None
    '''
    while len(total_logs) < limit:
        
        # Create parameterized GraphQL query for activity logs
        query = f'''
        query {{
        boards (ids: {board_ids}) {{
            activity_logs (from: "{start_time}", to: "{end_time}", limit: {ACTIVITY_LOGS_PER_PAGE}, page: {page}) {{
                created_at,
                data,
                id,
                event
            }}
        }}
        }}
        '''
        
        remaining_logs = limit - len(total_logs)
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Starting to fetch new page of activity logs.\nRemaining logs to fetch: {remaining_logs}")
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Requesting activity logs\nURL: {url}, Query: {query}")
        
        try:
            response = requests.post(url, headers=headers, json={"query": query}, verify=USE_SSL)
        except Exception as e:
            demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Exception during get activity logs. Exception is {e!s}")
            raise DemistoException(f"Exception during get activity logs. Exception is {e!s}")
        
        if response.status_code != 200:
            demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Failed to get activity logs. response status code: {response.status_code}\n{response.text}")
            raise DemistoException(f"Failed to get activity logs. Status code: {response.status_code}\n{response.text}")
        
        # Status code 200
        fetched_logs = response.json()["data"]["boards"][0]["activity_logs"]
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Successfully fetched {len(fetched_logs)} activity logs.")
        total_logs.extend(fetched_logs)
        
        if page == 1:
            if fetched_logs:
                # Saved for Handle duplicate.
                # There is no need to save all logs ids, only the newest log id with the same timestamp (upper bound) which will check in the next fetch with the oldest log timestamp (lower bound)
                last_run["upper_bound_log_id"] = get_newest_log_id_with_same_timestamp(fetched_logs, "created_at", is_id_field_exists=True)
                
                newest_log_timestamp = fetched_logs[0].get("created_at")
                newest_log_timestamp = convert_17_digit_unix_time_to_ISO8601(newest_log_timestamp)
                
                demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}page=1, newest log timestamp: {newest_log_timestamp}, set upper_bound_log_id: {last_run['upper_bound_log_id']}")

            else:
                newest_log_timestamp = ""
                last_run["upper_bound_log_id"] = None
                last_run["lower_bound_log_id"] = None
                demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}page=1, no logs available for this time range, set upper_bound_log_id and lower_bound_log_id to None")


        # last page reached when the response contains no activity logs.
        next_page = page + 1
        next_query = query.replace(f"page: {page}", f"page: {next_page}")
        
        if is_empty_page(next_query, url, headers):
            demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}page={page} is the last page, page={next_page} is empty.")

            lower_bound_log_id = last_run.get("lower_bound_log_id")
            fetched_logs = remove_duplicate_logs(fetched_logs, lower_bound_log_id, is_id_field_exists=True)
            last_run["lower_bound_log_id"] = last_run.get("upper_bound_log_id") # The upper bound log id is the lower bound in the next fetch
            
            demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}set lower_bound_log_id to be upper_bound_log_id: {last_run['lower_bound_log_id']}")
            
            # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
            if not is_continuing_fetch:
                last_run["last_timestamp"] = newest_log_timestamp
                demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}This is the first fetch in the current time range, set last_timestamp to be newest_log_timestamp: {last_run['last_timestamp']}")
            
            if len(fetched_logs) > remaining_logs:
                demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX} page={page} has more logs than remaining logs to fetch.\nremaining_logs: {remaining_logs}, Total logs fetched from page {page}: {len(fetched_logs)}")
                last_run["excess_logs_info"] = {"page": page, "start_time": start_time, "end_time": end_time, "offset": remaining_logs}
                demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX} Setting excess_logs_info for next fetch: {last_run['excess_logs_info']}")
                total_logs = total_logs[:limit]
                demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX} Truncated total_logs from {len(total_logs)} to limit: {limit}")
            
            last_run["continuing_fetch_info"] = None
            demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX} Setting continuing_fetch_info to None")
            
            return total_logs, last_run
        
        page += 1

    # At this point, limit is reached so we need to continue fetching (next_page = None is not reached)
    last_run["continuing_fetch_info"] = {"page": page, "start_time": start_time, "end_time": end_time}
    demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Limit is reached and there are more pages to fetch. Setting continuing_fetch_info: {last_run['continuing_fetch_info']}")

    # Only partial logs were fetched from the last page when limit is reached.
    if len(fetched_logs) > remaining_logs:
        last_run["excess_logs_info"] = {"page": page - 1, "start_time": start_time, "end_time": end_time, "offset": remaining_logs}
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Limit is reached and Only partial logs were fetched from the last page. Setting excess_logs_info: {last_run['excess_logs_info']}")

        total_logs = total_logs[:limit]
    
    # The first fetch in the current run, set the last_timestamp to the time of the newest log.
    # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
    if not is_continuing_fetch:
        last_run["last_timestamp"] = newest_log_timestamp
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}This is the first fetch in the current time range, setting last_timestamp: {last_run['last_timestamp']}")
        
    return total_logs[:limit], last_run


def get_audit_logs(last_run: dict, now_ms: int, limit: int) -> tuple[dict, list]:
    """
    Fetch audit logs from Monday based on configuration.
    
    Remaining logs fetched before calling this function, this function starts to fetch always from new page.
    (last_run does not contain the "excess_logs_info" key)
    Args:
        last_run: Previous fetch state containing last_timestamp and fetched_ids
        now_ms: Current time in milliseconds

    Returns:
        tuple: (last_run, logs) where last_run is the updated state and logs are the fetched logs.
    """
    
    demisto_params = demisto.params()
    
    audit_logs_url = demisto_params.get("audit_logs_url", "")
    audit_token = demisto_params.get("audit_token", "")
    
    if not audit_token or not audit_logs_url:
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Audit API token or Audit Server URL parameters are missing.")
        raise DemistoException("Please provide Audit API token and Audit Server URL in the integration parameters for fetch audit logs.")
    
    remaining_logs = 0
    fetched_logs = []
    
    newest_log_timestamp = ""
    total_logs = []

    # Not all logs were fetched in the previous fetch between start_time and end_time.
    if last_run.get("continuing_fetch_info"):
        is_continuing_fetch = True
        continuing_fetch_info = last_run.get("continuing_fetch_info")
        page = continuing_fetch_info.get("page")
        start_time = continuing_fetch_info.get("start_time")
        end_time = continuing_fetch_info.get("end_time")
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Continuing fetch for Audit Logs from: {start_time} to {end_time}\nPage: {page}")
    
    # TODO: Check this time format and change . to %E2 if needed.
    # First fetch in the current time range.
    else:
        is_continuing_fetch = False
        end_time = timestamp_to_datestring(now_ms, date_format="%Y-%m-%dT%H:%M:%S.%fZ")

        if last_run.get("last_timestamp"):
            start_time = last_run.get("last_timestamp")
        else:
            start_time = timestamp_to_datestring(now_ms - FETCH_TIME, date_format="%Y-%m-%dT%H:%M:%S.%fZ")

        page = 1
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Starting new fetch range for Audit Logs from: {start_time} to {end_time}\nPage: {page}")

    time_filter = f'{{"start_time":"{start_time}","end_time":"{end_time}"}}'
    headers = {
        "Authorization": f"Bearer {audit_token}",
        "Content-Type": "application/json"
    }
    url = urljoin(audit_logs_url, "audit-api/get-logs")

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
        
        remaining_logs = limit - len(total_logs)
        
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Starting to fetch new page of audit logs.\nRemaining logs to fetch: {remaining_logs}")
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Requesting audit logs\nURL: {url}, Params: {params}")
        
        try:
            # Monday API possible response codes: 200, 400, 401, 429, 500
            response = requests.get(url, headers=headers, params=params, verify=USE_SSL)
        except Exception as e:
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Exception during get audit logs. Exception is {e!s}")
            raise DemistoException(f"Exception during get audit logs. Exception is {e!s}")
        
        '''
            Rate limit reached - up to 50 requests per minute.
            Rate limit can be reached only if the user configured limit *equal* to 50,000 - max limit.
            NOTE: This code path is likely unreachable since limit=len(fetched_logs)=5000 logs per minute and the loop will exit before it can be reached.
        '''
        if response.status_code == 429:
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Rate limit reached for audit logs. Status code: {response.status_code}\n{response.text}")
            
            # NOTE: In case this code path is reached, I should save more things here, like limit and remaining logs.
            # Next run, starts fetching from this current page with the same time filter, resend the same request.
            last_run["continuing_fetch_info"] = {"page": page, "start_time": start_time, "end_time": end_time}
            
            if not is_continuing_fetch:
                last_run["last_timestamp"] = newest_log_timestamp
            
            return total_logs, last_run

        if response.status_code != 200:
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Failed to get audit logs. response status code: {response.status_code}\n{response.text}")
            raise DemistoException(f"Failed to get audit logs. Status code: {response.status_code}\n{response.text}")
        
        # Status code 200
        fetched_logs = response.json().get("data", [])
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Successfully fetched {len(fetched_logs)} audit logs.")
        total_logs.extend(fetched_logs)
        
        if page == 1:
            if fetched_logs:
                # Saved for Handle duplicate.
                # There is no need to save all logs ids, only the newest log id with the same timestamp (upper bound) which will check in the next fetch with the oldest log timestamp (lower bound)
                last_run["upper_bound_log_id"] = get_newest_log_id_with_same_timestamp(fetched_logs, "timestamp", is_id_field_exists=False)
                newest_log_timestamp = fetched_logs[0].get("timestamp")
                
                demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}page=1, newest log timestamp: {newest_log_timestamp}, set upper_bound_log_id: {last_run['upper_bound_log_id']}")

            else:
                newest_log_timestamp = ""
                last_run["upper_bound_log_id"] = None
                last_run["lower_bound_log_id"] = None
                demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}page=1, no logs available for this time range, set upper_bound_log_id and lower_bound_log_id to None")


        # last page reached, next_page = None, meaning there are no more logs to fetch.
        # We can remove duplicate logs based on the lower bound logs set on the previous fetch.
        if not response.json().get("next_page"):
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}page={page} is the last page.")

            lower_bound_log_id = last_run.get("lower_bound_log_id")
            fetched_logs = remove_duplicate_logs(fetched_logs, lower_bound_log_id, is_id_field_exists=False)
            last_run["lower_bound_log_id"] = last_run.get("upper_bound_log_id") # The upper bound log id is the lower bound in the next fetch
            
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}set lower_bound_log_id to be upper_bound_log_id: {last_run['lower_bound_log_id']}")
            
            # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
            if not is_continuing_fetch:
                last_run["last_timestamp"] = newest_log_timestamp
                demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}This is the first fetch in the current time range, set last_timestamp to be newest_log_timestamp: {last_run['last_timestamp']}")
            
            if len(fetched_logs) > remaining_logs:
                demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX} page={page} has more logs than remaining logs to fetch.\nremaining_logs: {remaining_logs}, Fetched logs from page {page}: {len(fetched_logs)}")
                last_run["excess_logs_info"] = {"page": page, "start_time": start_time, "end_time": end_time, "offset": remaining_logs}
                demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX} Setting excess_logs_info for next fetch: {last_run['excess_logs_info']}")
                total_logs = total_logs[:limit]
                demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX} Truncated total_logs from {len(total_logs)} to limit: {limit}")
            
            last_run["continuing_fetch_info"] = None
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX} Setting continuing_fetch_info to None")
            
            return total_logs, last_run
        
        page += 1

    # At this point, limit is reached so we need to continue fetching (next_page = None is not reached)
    last_run["continuing_fetch_info"] = {"page": page, "start_time": start_time, "end_time": end_time}
    demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Limit is reached and there are more pages to fetch. Setting continuing_fetch_info: {last_run['continuing_fetch_info']}")

    # Only partial logs were fetched from the last page when limit is reached.
    if len(fetched_logs) > remaining_logs:
        last_run["excess_logs_info"] = {"page": page - 1, "start_time": start_time, "end_time": end_time, "offset": remaining_logs}
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Limit is reached and Only partial logs were fetched from the last page. Setting excess_logs_info: {last_run['excess_logs_info']}")

        total_logs = total_logs[:limit]
    
    # The first fetch in the current run, set the last_timestamp to the time of the newest log.
    # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
    if not is_continuing_fetch:
        last_run["last_timestamp"] = newest_log_timestamp
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}This is the first fetch in the current time range, setting last_timestamp: {last_run['last_timestamp']}")
        
    return total_logs[:limit], last_run


def fetch_audit_logs(last_run: dict) -> tuple[dict, list]:
    
    now_ms = int(time.time() * 1000)
    audit_logs = []
    limit = AUDIT_LOGS_LIMIT
    try:
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}last_run before fetching audit logs: {last_run}")
        
        # Handle fetching remaining logs from previous fetch
        if last_run.get("excess_logs_info"):
            excess_logs, last_run = get_remaining_audit_logs(last_run)
            audit_logs.extend(excess_logs)
            limit -= len(excess_logs)
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Fetched {len(excess_logs)} excess audit logs, limit changes from {AUDIT_LOGS_LIMIT} to {limit}")
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}last_run after fetching remaining audit logs: {last_run}")

        fetched_logs, last_run = get_audit_logs(last_run=last_run, now_ms=now_ms, limit=limit)
        audit_logs.extend(fetched_logs)
    
    except Exception as e:
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Exception during fetch audit logs. Exception is {e!s}")
        raise DemistoException(f"{AUDIT_LOG_DEBUG_PREFIX}Exception during fetch audit logs. Exception is {e!s}")

    audit_logs = add_time_field_to_audit_logs(audit_logs)
    
    return last_run, audit_logs


def add_time_field_to_audit_logs(logs: list) -> list:
    for log in logs:
        timestamp_str = log.get("timestamp")
        if timestamp_str:
            # Parse the timestamp with milliseconds and reformat without milliseconds
            dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            log["_time"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")    # TODO: Verify the format is correct regarding the api response and correct for XSIAM
        else:
            log["_time"] = None
    return logs

def add_time_field_to_activity_logs(logs: list) -> list:
    for log in logs:
        timestamp_str = log.get("created_at")
        if timestamp_str:
            log["_time"] = convert_17_digit_unix_time_to_ISO8601(timestamp_str) # TODO: Verify the format is correct for XSIAM
        else:
            log["_time"] = None
    return logs


def fetch_activity_logs(last_run: dict) -> tuple[dict, list]:
    
    now_ms = int(time.time() * 1000)
    activity_logs = []
    limit = ACTIVITY_LOGS_LIMIT
    try:
    # NOTE: Activity logs don't require a remaining logs mechanism from previous fetches.
    #       The limit parameter equals the maximum logs per page (10,000), so we fetch
    #       exactly the limit number of logs per page when available. If fewer logs exist
    #       on the last page, we fetch them all and next_page becomes None. If more logs
    #       exist than the limit, we continue to the next page without remaining logs.
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}last_run before fetching activity logs: {last_run}")
        fetched_logs, last_run = get_activity_logs(last_run=last_run, now_ms=now_ms, limit=limit)
        activity_logs.extend(fetched_logs)

    except Exception as e:
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Exception during fetch activity logs. Exception is {e!s}")
        raise DemistoException(f"{ACTIVITY_LOG_DEBUG_PREFIX}Exception during fetch activity logs. Exception is {e!s}")

    activity_logs = add_time_field_to_activity_logs(activity_logs)
    
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
        demisto.debug("Empty last run object, initializing new last run object: {last_run}")

    last_run_audit_logs = last_run.get(AUDIT_LOGS_TYPE, {})
    last_run_activity_logs = last_run.get(ACTIVITY_LOGS_TYPE, {})

    selected_event_types = params.get("selected_event_types", "")
    demisto.debug(f"{DEBUG_PREFIX}Selected event types: {selected_event_types}")

    if AUDIT_LOGS_TYPE in selected_event_types:
        demisto.debug(f"{DEBUG_PREFIX}Start fetch Audit Logs, Current Audit Logs last_run object:\n{last_run_audit_logs}")
        last_run_audit_logs, fetched_audit_logs = fetch_audit_logs(last_run_audit_logs)
        events.extend(fetched_audit_logs)
        demisto.debug(f"{DEBUG_PREFIX}Total fetched audit logs: {len(fetched_audit_logs)}")


    if ACTIVITY_LOGS_TYPE in selected_event_types:
        demisto.debug(f"{DEBUG_PREFIX}Start fetch Activity Logs, Current Activity Logs last_run object:\n{last_run_activity_logs}")
        last_run_activity_logs, fetched_activity_logs = fetch_activity_logs(last_run_activity_logs)
        events.extend(fetched_activity_logs)
        demisto.debug(f"{DEBUG_PREFIX}Total fetched activity logs: {len(fetched_activity_logs)}")
    
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

    demisto.debug(f"{DEBUG_PREFIX}Command being called is {command}")
    try:
        # TODO: Ask what the test module command should test
        if command == "test-module":
            # result = test_module(params, first_fetch_time)
            return_results(result)
        elif command == "monday-generate-login-url":
            return_results(generate_login_url(client_id))
        elif command == "monday-auth-test":
            return_results(test_connection())
        elif command == "fetch-events":
            
            last_run, events = fetch_events()
            
            demisto.debug(f"{DEBUG_PREFIX}Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"{DEBUG_PREFIX}Sent events to XSIAM successfully")
            
            demisto.setLastRun(last_run)
            demisto.debug(f"{DEBUG_PREFIX}Updated last_run object after fetch: {last_run}")

    except Exception as e:
        return_error(f"{AUDIT_LOG_DEBUG_PREFIX}Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
