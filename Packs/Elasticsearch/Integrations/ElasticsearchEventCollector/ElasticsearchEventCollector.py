import re
import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *

"""IMPORTS"""
import json
import warnings
from datetime import datetime, UTC

import requests
import urllib3
from dateutil.parser import parse

# Disable insecure warnings
urllib3.disable_warnings()
warnings.filterwarnings(action="ignore", message=".*using SSL with verify_certs=False is insecure.")

VENDOR = "Elasticsearch"
PRODUCT = "Elasticsearch"

PARAMS = demisto.params()

# .ymla values
BASIC_AUTH = "Basic auth"
BEARER_AUTH = "Bearer auth"
API_KEY_AUTH = "API key auth"

API_KEY_PREFIX = "_api_key_id:"

AUTH_TYPE = PARAMS.get("auth_type", "Basic auth")
USERNAME: str = PARAMS.get("credentials", {}).get("identifier")
PASSWORD: str = PARAMS.get("credentials", {}).get("password")
API_KEY_ID: str = PARAMS.get("api_key_auth_credentials", {}).get("identifier")
API_KEY_SECRET: str = PARAMS.get("api_key_auth_credentials", {}).get("password")
API_KEY = None

# Using API key auth by username and password fields for backward compatibility.
if AUTH_TYPE == BASIC_AUTH:
    if USERNAME and USERNAME.startswith(API_KEY_PREFIX):
        AUTH_TYPE = API_KEY_AUTH
        API_KEY_ID = USERNAME[len(API_KEY_PREFIX) :]
        API_KEY = (API_KEY_ID, PASSWORD)

elif AUTH_TYPE == API_KEY_AUTH:
    API_KEY = (API_KEY_ID, API_KEY_SECRET)

ELASTICSEARCH_V8 = "Elasticsearch_v8"
ELASTICSEARCH_V9 = "Elasticsearch_v9"
OPEN_SEARCH = "OpenSearch"
ELASTIC_SEARCH_CLIENT = PARAMS.get("client_type")
if ELASTIC_SEARCH_CLIENT == OPEN_SEARCH:
    from opensearch_dsl import Search
    from opensearch_dsl.query import QueryString
    from opensearchpy import RequestsHttpConnection
    from opensearchpy import OpenSearch as Elasticsearch
elif ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, ELASTICSEARCH_V9]:
    from elastic_transport import RequestsHttpNode
    from elasticsearch import Elasticsearch  # type: ignore[assignment]
    from elasticsearch.dsl import Search
    from elasticsearch.dsl.query import QueryString
else:  # Elasticsearch (<= v7)
    from elasticsearch7 import Elasticsearch, RequestsHttpConnection  # type: ignore[assignment,misc]
    from elasticsearch.dsl import Search
    from elasticsearch.dsl.query import QueryString


ES_DEFAULT_DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss.SSSSSS"
PYTHON_DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
SERVER = PARAMS.get("url", "").rstrip("/")

TIME_FIELD = PARAMS.get("fetch_time_field", "")
FETCH_INDEX = PARAMS.get("fetch_index", "")
FETCH_QUERY_PARM = PARAMS.get("fetch_query", "")
RAW_QUERY = PARAMS.get("raw_query", "")
FETCH_TIME = "now"
FETCH_SIZE = int(PARAMS.get("fetch_size", 5000))
INSECURE = not PARAMS.get("insecure", False)
TIME_METHOD = PARAMS.get("time_method", "Simple-Date")
TIMEOUT = int(PARAMS.get("timeout") or 60)
MAP_LABELS = PARAMS.get("map_labels", True)

FETCH_QUERY = RAW_QUERY or FETCH_QUERY_PARM


def get_value_by_dot_notation(dictionary, key):
    """
    Get dictionary value by key using dot notation.

    Args:
        dictionary (dict): The dictionary to search within.
        key (str): The key in dot notation.

    Returns:
        The value corresponding to the key if found, otherwise None.
    """
    value = dictionary
    demisto.debug("Trying to get value by dot notation")
    for k in key.split("."):
        if isinstance(value, dict):
            value = value.get(k)
        else:
            demisto.debug(f"Last value is not a dict, returning None. {value=}")
            return None
    return value


def convert_date_to_timestamp(date, time_method):
    """converts datetime to the relevant timestamp format.

    Args:
        date(datetime): A datetime object setting up the last fetch time
        time_method (str): The method of timestamp conversion (e.g., 'Simple-Date', 'Timestamp-Seconds', 'Timestamp-Milliseconds')

    Returns:
        (num | str): The formatted timestamp
    """
    demisto.debug(f"Converting date to timestamp: {date}")

    if str(date).isdigit():
        return int(date)

    if time_method == "Timestamp-Seconds":
        return int(date.timestamp())

    if time_method == "Timestamp-Milliseconds":
        return int(date.timestamp() * 1000)

    # In case of 'Simple-Date'.
    return datetime.strftime(date, PYTHON_DEFAULT_DATETIME_FORMAT)


def timestamp_to_date(timestamp_string):
    """Converts a timestamp string to a datetime object.

    Args:
        timestamp_string(string): A string with a timestamp in it.

    Returns:
        (datetime).represented by the timestamp in the format '%Y-%m-%d %H:%M:%S.%f'
    """
    timestamp_number: float
    # find timestamp in form of more than seconds since epoch: 1572164838000
    if TIME_METHOD == "Timestamp-Milliseconds":
        timestamp_number = float(int(timestamp_string) / 1000)

    # find timestamp in form of seconds since epoch: 1572164838
    else:  # TIME_METHOD == 'Timestamp-Seconds':
        demisto.debug(f"{TIME_METHOD=}. Should be Timestamp-Seconds.")
        timestamp_number = float(timestamp_string)

    # convert timestamp (a floating point number representing time since epoch) to datetime
    return datetime.fromtimestamp(timestamp_number, tz=UTC).replace(tzinfo=None)


def get_api_key_header_val(api_key):
    """
    Check the type of the passed api_key and return the correct header value
    for the `API Key authentication
    <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html>`
    :arg api_key, either a tuple or a base64 encoded string
    """
    if isinstance(api_key, tuple | list):
        s = f"{api_key[0]}:{api_key[1]}".encode()
        return "ApiKey " + base64.b64encode(s).decode("utf-8")
    return "ApiKey " + api_key


def is_access_token_expired(expires_in: str) -> bool:
    """Check if access token is expired.

    Args:
        expires_in: ISO format datetime string representing when the token expires (UTC)

    Returns:
        bool: True if token is expired or will expire within 1 minute, False otherwise
    """
    try:
        # Parse the expires_in string to a UTC datetime object
        expiration_time = datetime.strptime(expires_in, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)

        # Subtract 1 min to refresh slightly early and avoid expiration issues.
        current_time_with_buffer = datetime.now(UTC) + timedelta(minutes=1)

        is_not_expired = expiration_time > current_time_with_buffer
        if is_not_expired:
            demisto.debug(
                f"is_access_token_expired - using existing Access token from integration context (expires in {expires_in})."
            )
            return False
        else:
            demisto.debug("is_access_token_expired - Access token expired.")
            return True
    except (ValueError, TypeError) as e:
        demisto.debug(f"is_access_token_expired - Error parsing expiration time: {e}. Treating as expired.")
        return True


def get_elastic_token():
    """
    Authenticates and retrieves an OAuth 2.0 access token from Elasticsearch.

    Returns an access token either by refreshing an existing token or performing a new token request.
        1. Check if existing access token is valid (with 1min buffer).
        2. If not, try to use refresh token if it exists and is valid.
        3. If not, perform a full password grant authentication for receiving initial access token.
    """
    try:
        url = urljoin(SERVER, "_security/oauth2/token")
        headers = {"Content-Type": "application/json"}

        integration_context = get_integration_context()
        access_token = integration_context.get("access_token", "")
        access_token_expires_in = integration_context.get("access_token_expires_in", "")
        refresh_token = integration_context.get("refresh_token", "")
        refresh_token_expires_in = integration_context.get("refresh_token_expires_in", "")

        # 1. Check if token exists and if it is still valid
        if access_token and not is_access_token_expired(access_token_expires_in):
            demisto.debug("get_elastic_token - Using existing access token from integration context.")
            return access_token

        if not USERNAME or not PASSWORD:
            demisto.debug("get_elastic_token - username or password fields are missing.")
            raise DemistoException("username or password fields are missing.")

        # 2. Token exists but expired, and refresh token is valid
        if refresh_token and not is_access_token_expired(refresh_token_expires_in):
            demisto.debug(
                "get_elastic_token - Access token expired, but Refresh token valid. Attempting to get token using refresh token"
            )

            payload = {"grant_type": "refresh_token", "refresh_token": refresh_token}
            response = requests.post(url, headers=headers, json=payload, verify=INSECURE, auth=(USERNAME, PASSWORD))

            if response.status_code == 200:
                now = datetime.now(UTC)
                token_data = response.json()
                access_token_expires_in = (now + timedelta(seconds=token_data.get("expires_in"))).strftime("%Y-%m-%dT%H:%M:%SZ")
                refresh_token_expires_in = (now + timedelta(hours=24)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )  # refresh token has a lifetime of 24 hours

                integration_context.update(
                    {
                        "access_token": token_data.get("access_token"),
                        "refresh_token": token_data.get("refresh_token"),
                        "access_token_expires_in": access_token_expires_in,
                        "refresh_token_expires_in": refresh_token_expires_in,
                    }
                )
                set_integration_context(integration_context)
                demisto.debug(
                    "get_elastic_token - Access token received successfully by refresh token and set to integration context."
                )
                return integration_context["access_token"]

            # If refresh fails, clear the refresh token to force generating of new token
            demisto.debug("get_elastic_token - refresh fails, a new token will be generated via password grant.")
            integration_context.update({"refresh_token": None, "refresh_token_expires_in": None})
            set_integration_context(integration_context)

        # Generate a new access vi password grant
        demisto.debug("get_elastic_token - Attempting to get token using grant_type:password")

        payload = {"grant_type": "password", "username": USERNAME, "password": PASSWORD}
        response = requests.post(url, headers=headers, auth=(USERNAME, PASSWORD), json=payload, verify=INSECURE)
        if response.status_code == 200:
            now = datetime.now(UTC)
            token_data = response.json()
            access_token_expires_in = (now + timedelta(seconds=token_data.get("expires_in"))).strftime("%Y-%m-%dT%H:%M:%SZ")
            refresh_token_expires_in = (now + timedelta(hours=24)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )  # refresh token has a lifetime of 24 hours

            integration_context.update(
                {
                    "access_token": token_data.get("access_token"),
                    "refresh_token": token_data.get("refresh_token"),
                    "access_token_expires_in": access_token_expires_in,
                    "refresh_token_expires_in": refresh_token_expires_in,
                }
            )
            set_integration_context(integration_context)
            demisto.debug(
                "get_elastic_token - Access token received successfully via password grant and set to integration context."
            )
            return integration_context["access_token"]

        demisto.debug(f"Failed to authenticate: {response.status_code}\n{response.text}")
        try:
            reason = json.loads(response.text).get("error", {}).get("reason")
        except Exception:
            reason = response.reason or response.text
        raise DemistoException(f"{response.status_code}, {reason}")

    except Exception as e:
        demisto.debug(f"get_elastic_token error: \n{str(e)}")
        raise DemistoException(f"{str(e)}")


def elasticsearch_builder(proxies):
    """Builds an Elasticsearch obj with the necessary credentials, proxy settings and secure connection."""

    connection_args: Dict[str, Union[bool, int, str, list, tuple[str, str], RequestsHttpConnection]] = {
        "hosts": [SERVER],
        "verify_certs": INSECURE,
        "timeout": TIMEOUT,
    }
    demisto.debug(f"Building Elasticsearch client with args: {connection_args}")
    if ELASTIC_SEARCH_CLIENT not in [ELASTICSEARCH_V9, ELASTICSEARCH_V8]:
        # Adding the proxy related parameters to the Elasticsearch client v7 and below or OpenSearch (BC)
        connection_args["connection_class"] = RequestsHttpConnection  # type: ignore[assignment]
        connection_args["proxies"] = proxies

    else:
        # Adding the proxy related parameter to the Elasticsearch client v8
        # Reference- https://github.com/elastic/elastic-transport-python/issues/53#issuecomment-1447903214
        class CustomHttpNode(RequestsHttpNode):  # pylint: disable=E0601
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.session.proxies = proxies

        connection_args["node_class"] = CustomHttpNode  # type: ignore[assignment]

    if AUTH_TYPE == API_KEY_AUTH and API_KEY:
        connection_args["api_key"] = API_KEY

    elif AUTH_TYPE == BASIC_AUTH and USERNAME and PASSWORD:
        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8]:
            connection_args["basic_auth"] = (USERNAME, PASSWORD)
        else:  # Elasticsearch version v7 and below or OpenSearch (BC)
            connection_args["http_auth"] = (USERNAME, PASSWORD)

    elif AUTH_TYPE == BEARER_AUTH:
        connection_args["bearer_auth"] = get_elastic_token()

    es = Elasticsearch(**connection_args)  # type: ignore[arg-type]

    # Ensuring api_key will be set correctly in case the authentication type is API key auth.
    # this should be passed as api_key via Elasticsearch init, but this code ensures it'll be set correctly
    # In some versions of the ES library, the transport object does not have a get_session func
    if AUTH_TYPE == API_KEY_AUTH and hasattr(es, "transport") and hasattr(es.transport, "get_connection"):
        es.transport.get_connection().session.headers["authorization"] = get_api_key_header_val(  # type: ignore[attr-defined]
            API_KEY
        )

    return es


def get_total_results(response_dict):
    """Creates a dictionary with all for the number of total results found

    Args:
        response_dict(dict): the raw response from elastic search.

    Returns:
        (dict).The total results info for the context.
        (num).The number of total results.
    """
    total_results = response_dict.get("hits", {}).get("total")
    if not str(total_results).isdigit():
        # if in version 7 - total number of hits has value field
        total_results = total_results.get("value")
        total_dict = response_dict.get("hits").get("total")

    else:
        total_dict = {
            "value": total_results,
        }

    return total_dict, total_results


def fetch_params_check():
    """If is_fetch is ticked, this function checks that all the necessary parameters for the fetch are entered."""
    str_error = []  # type:List
    if (TIME_FIELD == "" or TIME_FIELD is None) and not RAW_QUERY:
        str_error.append("Index time field is not configured.")

    if not FETCH_QUERY:
        str_error.append("Query by which to fetch events is not configured.")

    if RAW_QUERY and FETCH_QUERY_PARM:
        str_error.append("Both Query and Raw Query are configured. Please choose between Query or Raw Query.")

    demisto.debug(f"fetch_params_check errors:\n{str_error}")

    if len(str_error) > 0:
        return "Got the following errors in test:\nFetches events is enabled.\n" + "\n".join(str_error)
    else:
        return ""


def test_connectivity_auth(proxies) -> tuple[bool, str]:
    """
    Test connectivity and authentication with Elasticsearch server
    Args:
        proxies (dict): Dictionary of proxy settings

    Returns:
        tuple[bool, str]: (success status, message)
    """

    demisto.debug("test_connectivity_auth started")
    headers = {"Content-Type": "application/json"}
    res = None

    try:
        if AUTH_TYPE == BASIC_AUTH:
            demisto.debug("test_connectivity_auth - Basic auth setting authorization header and sending request")
            res = requests.get(SERVER, auth=(USERNAME, PASSWORD), verify=INSECURE, headers=headers)

        elif AUTH_TYPE == API_KEY_AUTH:
            demisto.debug("test_connectivity_auth - API key auth setting authorization header and sending request")
            headers["authorization"] = get_api_key_header_val(API_KEY)
            res = requests.get(SERVER, verify=INSECURE, headers=headers)

        elif AUTH_TYPE == BEARER_AUTH:
            demisto.debug("test_connectivity_auth - Bearer auth setting authorization header and sending request")
            headers["Authorization"] = f"Bearer {get_elastic_token()}"
            res = requests.get(SERVER, verify=INSECURE, headers=headers)

        if res is not None:
            if res.status_code >= 400:
                demisto.debug(f"test_connectivity_auth - Failed to connect.\n{res.status_code=}, {res.text=}")
                return False, f"Failed to connect.\nStatus:{res.status_code}, {res.reason}"

            elif res.status_code == 200:
                demisto.debug("test_connectivity_auth - Connectivity test successful")
                verify_es_server_version(res.json())
                return True, "Connectivity test successful"

        return False, "No response received from server"

    except Exception as e:
        demisto.debug(f"test_connectivity_auth - Failed to connect.\nError message: {e}")
        return False, f"Failed to connect.\n{e}"


def verify_es_server_version(res):
    """
    Gets the requests.get raw response, extracts the elasticsearch server version,
    and verifies that the client type parameter is configured accordingly.
    Raises exceptions for server version miss configuration issues.

    Args:
        res(dict): requests.models.Response object including information regarding the elasticsearch server.
    """
    es_server_version = res.get("version", {}).get("number", "")
    demisto.debug(f"Elasticsearch server version is: {es_server_version}")
    if es_server_version:
        major_version = es_server_version.split(".")[0]
        if major_version:
            if int(major_version) >= 8 and ELASTIC_SEARCH_CLIENT not in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
                raise ValueError(
                    f"Configuration Error: Your Elasticsearch server is version {es_server_version}. "
                    f"Please ensure that the client type is set to {ELASTICSEARCH_V9}, {ELASTICSEARCH_V8} or {OPEN_SEARCH}. "
                    f"For more information please see the integration documentation."
                )
            elif int(major_version) <= 7 and ELASTIC_SEARCH_CLIENT not in [OPEN_SEARCH, "Elasticsearch"]:
                raise ValueError(
                    f"Configuration Error: Your Elasticsearch server is version {es_server_version}. "
                    f"Please ensure that the client type is set to Elasticsearch or {OPEN_SEARCH}. "
                    f"For more information please see the integration documentation."
                )


def test_func(proxies):
    """
    Tests API connectivity to the Elasticsearch server.
    Tests the existence of all necessary fields for fetch.

    Due to load considerations, the test module doesn't check the validity of the fetch-events - to test that the fetch works
    as excepted the user should run the es-integration-health-check command.

    """
    success, message = test_connectivity_auth(proxies)
    if not success:
        return message

    if demisto.params().get("isFetchEvents", False):
        # check the existence of all necessary fields for fetch
        failed_message = fetch_params_check()
        if failed_message:
            return failed_message

        get_events(proxies, is_test=True)
    return "ok"


def event_label_maker(source):
    """Creates labels for the created event.

    Args:
        source(dict): the _source fields of a hit.

    Returns:
        (list).The labels.
    """
    labels = []
    for field, value in source.items():
        encoded_value = value if isinstance(value, str) else json.dumps(value)
        labels.append({"type": str(field), "value": encoded_value})

    return labels


def results_to_events_timestamp(response, last_fetch, seen_event_ids=None):
    """Converts the current results into events.

    Args:
        response(dict): the raw search results from Elasticsearch.
        last_fetch(num): the date or timestamp of the last fetch before this fetch
        - this will hold the last date of the event brought by this fetch.
        seen_event_ids(set): set of event IDs already processed at the current timestamp

    Returns:
        (list).The events.
        (num).The date of the last event brought by this fetch.
        (set).The set of event IDs at the last fetch timestamp.
    """
    current_fetch = last_fetch
    seen_event_ids = seen_event_ids or set()
    new_seen_ids = set()
    events = []

    for hit in response.get("hits", {}).get("hits"):
        source = hit.get("_source")
        if source is not None:
            time_field_value = get_value_by_dot_notation(source, str(TIME_FIELD))

            if time_field_value is not None:
                # if timestamp convert to iso format date and save the timestamp
                hit_date = timestamp_to_date(str(time_field_value))
                hit_timestamp = int(time_field_value)
                hit_id = hit.get("_id")

                if hit_timestamp > last_fetch:
                    last_fetch = hit_timestamp
                    new_seen_ids = {hit_id}  # Reset seen ids for new latest timestamp
                elif hit_timestamp == last_fetch:
                    new_seen_ids.add(hit_id)

                # avoid duplication: skip if timestamp equals current_fetch and id was already seen
                if hit_timestamp > current_fetch or (hit_timestamp == current_fetch and hit_id not in seen_event_ids):
                    inc = {
                        "name": "Elasticsearch: Index: " + str(hit.get("_index")) + ", ID: " + str(hit_id),
                        "rawJSON": json.dumps(hit),
                        "occurred": hit_date.isoformat() + "Z",
                    }
                    if hit_id:
                        inc["dbotMirrorId"] = hit_id

                    if MAP_LABELS:
                        inc["labels"] = event_label_maker(hit.get("_source"))

                    inc["_time"] = hit_date.isoformat() + "Z"

                    events.append(inc)

    return events, last_fetch, new_seen_ids


def results_to_events_datetime(response, last_fetch, seen_event_ids=None):
    """Converts the current results into events.

    Args:
        response(dict): the raw search results from Elasticsearch.
        last_fetch(datetime): the date or timestamp of the last fetch before this fetch or parameter default fetch time
        - this will hold the last date of the event brought by this fetch.
        seen_event_ids(set): set of event IDs already processed at the current timestamp

    Returns:
        (list).The events.
        (datetime).The date of the last event brought by this fetch.
        (set).The set of event IDs at the last fetch timestamp.
    """
    last_fetch = dateparser.parse(last_fetch)
    last_fetch_timestamp = int(last_fetch.timestamp() * 1000)  # type:ignore[union-attr]
    current_fetch = last_fetch_timestamp
    seen_event_ids = seen_event_ids or set()
    new_seen_ids = set()
    events = []
    hits = response.get("hits", {}).get("hits")
    demisto.debug(f"results_to_events_datetime - total hits to scan: {len(hits)}")

    for hit in hits:
        source = hit.get("_source")
        if source is not None:
            time_field_value = get_value_by_dot_notation(source, str(TIME_FIELD))
            if time_field_value is not None:
                hit_date = parse(str(time_field_value))
                hit_timestamp = int(hit_date.timestamp() * 1000)
                hit_id = hit.get("_id")

                if hit_timestamp > last_fetch_timestamp:
                    last_fetch = hit_date
                    last_fetch_timestamp = hit_timestamp
                    new_seen_ids = {hit_id}  # Reset seen ids for new latest timestamp
                elif hit_timestamp == last_fetch_timestamp:
                    new_seen_ids.add(hit_id)

                # avoid duplication: skip if timestamp equals current_fetch and id was already seen
                if hit_timestamp > current_fetch or (hit_timestamp == current_fetch and hit_id not in seen_event_ids):
                    inc = {
                        "name": "Elasticsearch: Index: " + str(hit.get("_index")) + ", ID: " + str(hit_id),
                        "rawJSON": json.dumps(hit),
                        # parse function returns iso format sometimes as YYYY-MM-DDThh:mm:ss+00:00
                        # and sometimes as YYYY-MM-DDThh:mm:ss
                        # we want to return format: YYYY-MM-DDThh:mm:ssZ in our events
                        "occurred": format_to_iso(hit_date.isoformat()),
                    }
                    if hit_id:
                        inc["dbotMirrorId"] = hit_id

                    if MAP_LABELS:
                        inc["labels"] = event_label_maker(hit.get("_source"))

                    inc["_time"] = format_to_iso(hit_date.isoformat())

                    events.append(inc)
                else:
                    demisto.debug(
                        f"Skipping hit ID: {hit_id} since {hit_timestamp=} is earlier than the {current_fetch=}"
                        f"or this event was already processed"
                    )

    return events, last_fetch.isoformat(), new_seen_ids  # type:ignore[union-attr]


def format_to_iso(date_string):
    """Formatting function to make sure the date string is in YYYY-MM-DDThh:mm:ssZ format.

    Args:
        date_string(str): a date string in ISO format could be like: YYYY-MM-DDThh:mm:ss+00:00 or: YYYY-MM-DDThh:mm:ss

    Returns:
        str. A date string in the format: YYYY-MM-DDThh:mm:ssZ
    """
    if "." in date_string:
        date_string = date_string.split(".")[0]

    if len(date_string) > 19 and not date_string.endswith("Z"):
        date_string = date_string[:-6]

    if not date_string.endswith("Z"):
        date_string = date_string + "Z"

    return date_string


def get_time_range(
    last_fetch: Union[str, None] = None,
    time_range_start=FETCH_TIME,
    time_range_end=None,
    time_field=TIME_FIELD,
    time_method=TIME_METHOD,
) -> Dict:
    """
    Creates the time range filter's dictionary based on the last fetch and given params.
    The filter is using timestamps with the following logic:
        start date (gte) - if this is the first fetch: use time_range_start param if provided, else use fetch time param.
                           if this is not the fetch: use the last fetch provided
        end date (lt) - use the given time range end param.
        When the `time_method` parameter is set to `Simple-Date` in order to avoid being related to the field datetime format,
            we add the format key to the query dict.
    Args:

        last_fetch (str): last fetch time stamp
        time_range_start (str): start of time range
        time_range_end (str): end of time range
        time_field (str): The field on which the filter the results
        time_method (str): The method of timestamp conversion (e.g., 'Simple-Date', 'Timestamp-Seconds', 'Timestamp-Milliseconds')

    Returns:
        dictionary (Ex. {"range":{'gte': 1000 'lt': 1001}})
    """
    range_dict = {}
    if not last_fetch and time_range_start:  # this is the first fetch
        start_date = dateparser.parse(time_range_start)

        start_time = convert_date_to_timestamp(start_date, time_method)
    else:
        start_time = last_fetch

    demisto.debug(f"Time range start time: {start_time}")
    if start_time:
        range_dict["gte"] = start_time  # Use gte (>=) instead of gt (>) to include events at exact timestamp

    if time_range_end:
        end_date = dateparser.parse(time_range_end)
        end_time = convert_date_to_timestamp(end_date, time_method)
        range_dict["lt"] = end_time

    if time_method == "Simple-Date":
        range_dict["format"] = ES_DEFAULT_DATETIME_FORMAT

    if utc_offset := re.search(r"([+-]\d{2}:\d{2})$", time_range_start):
        range_dict["time_zone"] = utc_offset.group(1)

    demisto.debug(f"Time range dictionary created: {range_dict}")
    return {"range": {time_field: range_dict}}


def query_string_to_dict(raw_query) -> Dict:
    """Parses a query_dsl string or bytearray into a Dict to make its fields accessible"""
    try:
        if not isinstance(raw_query, Dict):
            raw_query = json.loads(raw_query)
        if raw_query.get("query"):
            demisto.debug("Query provided already has a query field. Sending as is.")
            body = raw_query
        else:
            body = {"query": raw_query}
    except (ValueError, TypeError) as e:
        body = {"query": raw_query}
        demisto.info(f"unable to convert raw query to dictionary, use it as a string\n{e}")
    return body


def execute_raw_query(es, raw_query, index, size=None, page=None):
    body = query_string_to_dict(raw_query)

    # update parameters if given
    if isinstance(size, int):
        body["size"] = size
    if isinstance(page, int):
        body["from"] = page

    search = Search(using=es, index=index).update_from_dict(body)

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
        response = search.execute().to_dict()
    else:  # Elasticsearch v7 and below
        # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
        response = es.search(index=search._index, body=search.to_dict(), **search._params)

    demisto.debug(f"Raw query response: {response}")
    return response


def fetch_events(proxies):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get("time") or FETCH_TIME
    seen_event_ids = set(last_run.get("event_ids", []))
    demisto.debug(f"fetch_events - last_run before fetch:\n{last_fetch}, seen_event_ids: {len(seen_event_ids)}")
    es = elasticsearch_builder(proxies)
    time_range_dict = get_time_range(time_range_start=last_fetch)

    if RAW_QUERY:
        demisto.debug(f"fetch_events - search events using raw_query configured param:\n{RAW_QUERY}")
        response = execute_raw_query(es, raw_query=RAW_QUERY, index=FETCH_INDEX)
    else:
        query = QueryString(query="(" + FETCH_QUERY + ") AND " + TIME_FIELD + ":*")
        demisto.debug(
            f"fetch_events - raw_query param is empty, search events using fetch_query and fetch_time_field param:\n{query}"
        )
        # Elastic search can use epoch timestamps (in milliseconds) as date representation regardless of date format.
        search = Search(using=es, index=FETCH_INDEX).filter(time_range_dict)
        search = search.sort({TIME_FIELD: {"order": "asc"}})[0:FETCH_SIZE].query(query)

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

    _, total_results = get_total_results(response)
    demisto.debug(f"fetch_events - total fetched: {total_results}, response:\n{response}.")

    events = []  # type: List
    updated_last_run = last_run
    new_seen_ids = set()

    if total_results > 0:
        if "Timestamp" in TIME_METHOD:
            demisto.debug("fetch_events - calling results_to_events_timestamp")
            events, last_fetch, new_seen_ids = results_to_events_timestamp(response, last_fetch, seen_event_ids)
            updated_last_run = {"time": last_fetch, "event_ids": list(new_seen_ids)}

        else:
            demisto.debug("fetch_events - calling results_to_events_datetime")
            events, last_fetch, new_seen_ids = results_to_events_datetime(response, last_fetch or FETCH_TIME, seen_event_ids)
            updated_last_run = {"time": str(last_fetch), "event_ids": list(new_seen_ids)}

    demisto.info(f"fetch_events - total events extracted: {len(events)}")
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.info("fetch_events - send_events_to_xsiam completed successfully")

    if total_results > 0:
        demisto.setLastRun(updated_last_run)
        demisto.debug(f"fetch_events - Updated last_run object after successful fetch:\n{updated_last_run}")
    else:
        demisto.results("No events were found, last_run not updated.")


def get_events(proxies, is_test=False):
    if is_test:
        demisto.debug("get_events - Running get_events as test mode")
        raw_query = '{"query": {"match_all": {}}}'
        fetch_query = ""
        fetch_index = ""
        fetch_time_field = "timestamp"
        fetch_size = 1
        time_method = "Simple-Date"
        start_time = "1 days"
        end_time = "now"
    else:
        args = demisto.args()
        raw_query = args.get("raw_query", "")
        fetch_query = args.get("fetch_query", "")
        fetch_time_field = args.get("fetch_time_field", "")
        fetch_index = args.get("fetch_index", "")
        fetch_size = int(args.get("fetch_size", 10))
        time_method = args.get("time_method", "Simple-Date")
        start_time = args.get("start_time", "")
        end_time = args.get("end_time")

    if raw_query and fetch_query:
        demisto.debug("get_events - Only one of raw_query or fetch_query should be provided.")
        raise DemistoException("Only one of raw_query or fetch_query should be provided.")

    es = elasticsearch_builder(proxies)
    time_range_dict = get_time_range(
        time_range_start=start_time, time_range_end=end_time, time_field=fetch_time_field, time_method=time_method
    )

    if raw_query:
        demisto.debug(f"get_events - search events using raw_query:\n{raw_query}")
        response = execute_raw_query(es, raw_query=raw_query, index=fetch_index)
    elif fetch_query:
        query = QueryString(query="(" + fetch_query + ") AND " + fetch_time_field + ":*")
        demisto.debug(f"get_events - search events using fetch_query and fetch_time_field param:\n{query}")
        # Elastic search can use epoch timestamps (in milliseconds) as date representation regardless of date format.
        search = Search(using=es, index=fetch_index).filter(time_range_dict)
        search = search.sort({fetch_time_field: {"order": "asc"}})[0:fetch_size].query(query)

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)
    else:
        demisto.debug("get_events - Either raw_query or fetch_query must be provided.")
        raise DemistoException("Either raw_query or fetch_query must be provided.")

    _, total_results = get_total_results(response)
    demisto.debug(f"get_events - total fetched: {total_results}, response:\n{response}.")

    events = []  # type: List

    if total_results > 0:
        if "Timestamp" in time_method:
            demisto.debug("get_events - calling results_to_events_timestamp")
            events, _, _ = results_to_events_timestamp(response, start_time)

        else:
            demisto.debug("get_events - calling results_to_events_datetime")
            events, _, _ = results_to_events_datetime(response, start_time)

        demisto.info(f"get_events - total events extracted: {len(events)}")
        return CommandResults(readable_output=tableToMarkdown(name="Get Events", t=events))
    return CommandResults(readable_output=tableToMarkdown(name="No Events", t=events))


def main():  # pragma: no cover
    proxies = handle_proxy()
    proxies = proxies if proxies else None
    command = demisto.command()
    try:
        LOG(f"command is {command}")
        if command == "test-module":
            return_results(test_func(proxies))
        elif command == "fetch-events":
            fetch_events(proxies)
        elif command == "es-get-events":
            results = get_events(proxies)
            return_results(results)
    except Exception as e:
        error_msg = f"Failed executing {command}.\nError message: {e}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg, error=str(e))


if __name__ in ("__main__", "builtin", "builtins"):
    main()
