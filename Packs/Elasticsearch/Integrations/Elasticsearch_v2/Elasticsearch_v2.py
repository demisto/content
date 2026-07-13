import re

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
    from opensearchpy import NotFoundError, RequestsHttpConnection
    from opensearchpy import OpenSearch as Elasticsearch
elif ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, ELASTICSEARCH_V9]:
    from elastic_transport import RequestsHttpNode
    from elasticsearch import Elasticsearch, NotFoundError  # type: ignore[assignment]
    from elasticsearch.dsl import Search
    from elasticsearch.dsl.query import QueryString
else:  # Elasticsearch (<= v7)
    from elasticsearch7 import Elasticsearch, NotFoundError, RequestsHttpConnection  # type: ignore[assignment,misc]
    from elasticsearch.dsl import Search
    from elasticsearch.dsl.query import QueryString


ES_DEFAULT_DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss.SSSSSS"
PYTHON_DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
SERVER = PARAMS.get("url", "").rstrip("/")
PROXY = PARAMS.get("proxy")
HTTP_ERRORS = {
    400: "400 Bad Request - Incorrect or invalid parameters",
    401: "401 Unauthorized - Incorrect or invalid username or password",
    403: "403 Forbidden - The account does not support performing this task",
    404: "404 Not Found - Elasticsearch server was not found",
    408: "408 Timeout - Check port number or Elasticsearch server credentials",
    410: "410 Gone - Elasticsearch server no longer exists in the service",
    500: "500 Internal Server Error - Internal error",
    503: "503 Service Unavailable",
}

"""VARIABLES FOR FETCH INCIDENTS"""
TIME_FIELD = PARAMS.get("fetch_time_field", "")
FETCH_INDEX = PARAMS.get("fetch_index", "")
FETCH_QUERY_PARM = PARAMS.get("fetch_query", "")
RAW_QUERY = PARAMS.get("raw_query", "")
FETCH_TIME = PARAMS.get("fetch_time", "3 days")
FETCH_SIZE = int(PARAMS.get("fetch_size", 50))
INSECURE = not PARAMS.get("insecure", False)
TIME_METHOD = PARAMS.get("time_method", "Simple-Date")
TIMEOUT = int(PARAMS.get("timeout") or 60)
MAP_LABELS = PARAMS.get("map_labels", True)
FIELDS_LIST = argToList(PARAMS.get("fetch_fields", ""))

FETCH_QUERY = RAW_QUERY or FETCH_QUERY_PARM

"""VARIABLES FOR KIBANA COMMANDS (es-kibana-*)"""
DEFAULT_SPACE_ID = PARAMS.get("space_id", "")
KIBANA_XSRF_HEADER = {"kbn-xsrf": "true"}
# Kibana write operations (POST/PUT/PATCH/DELETE) require the kbn-xsrf header.
KIBANA_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


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


def convert_date_to_timestamp(date):
    """converts datetime to the relevant timestamp format.

    Args:
        date(datetime): A datetime object setting up the last fetch time

    Returns:
        (num | str): The formatted timestamp
    """
    demisto.debug(f"Converting date to timestamp: {date}")
    # this theoretically shouldn't happen but just in case
    if str(date).isdigit():
        return int(date)

    if TIME_METHOD == "Timestamp-Seconds":
        return int(date.timestamp())

    if TIME_METHOD == "Timestamp-Milliseconds":
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
    return datetime.utcfromtimestamp(timestamp_number)


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


def get_kibana_base_url() -> str:
    """
    Derives the Kibana base URL from the configured Elasticsearch Server URL.

    Elastic Cloud deployments expose Elasticsearch and Kibana on the same domain,
    differentiated only by the ".es." / ".kb." subdomain prefix, e.g.:
        https://my-deployment-af38b6.es.us-central1.gcp.cloud.es.io
        https://my-deployment-af38b6.kb.us-central1.gcp.cloud.es.io

    Returns:
        str: The derived Kibana base URL (no trailing slash).

    Raises:
        DemistoException: If the Server URL does not contain the expected ".es." segment,
            so a Kibana URL cannot be derived from it.
    """
    if ".es." not in SERVER:
        raise DemistoException(
            "Could not derive the Kibana URL from the configured Server URL. "
            'The Server URL is expected to contain ".es." (e.g. "https://my-deployment.es.us-central1.gcp.cloud.es.io"). '
            f"Configured Server URL: {SERVER}"
        )
    return SERVER.replace(".es.", ".kb.", 1)


def get_kibana_auth_headers() -> Dict[str, str]:
    """
    Builds the Authorization header for Kibana REST API requests, reusing the
    integration's configured authentication (Basic auth, Bearer auth or API key auth).

    Returns:
        Dict[str, str]: A dict containing the "Authorization" header value.
    """
    if AUTH_TYPE == API_KEY_AUTH and API_KEY:
        return {"Authorization": get_api_key_header_val(API_KEY)}

    if AUTH_TYPE == BEARER_AUTH:
        return {"Authorization": f"Bearer {get_elastic_token()}"}

    if AUTH_TYPE == BASIC_AUTH and USERNAME and PASSWORD:
        basic_token = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode("utf-8")
        return {"Authorization": f"Basic {basic_token}"}

    raise DemistoException(f"Missing or unsupported credentials for authentication type: {AUTH_TYPE}")


def build_kibana_path(path: str, space_id: Optional[str] = None) -> str:
    """
    Prefixes a Kibana API path with the space, if a space_id is provided.

    Args:
        path: The Kibana API path, e.g. "/api/cases".
        space_id: Optional Kibana space ID.

    Returns:
        str: The (optionally space-prefixed) path, e.g. "/s/my-space/api/cases".
    """
    path = path if path.startswith("/") else f"/{path}"
    if space_id:
        return f"/s/{space_id}{path}"
    return path


def kibana_http_request(
    method: str,
    path: str,
    space_id: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
    json_data: Optional[Any] = None,
    files: Optional[Dict[str, Any]] = None,
    proxies: Optional[Dict[str, str]] = None,
    ok_codes: Optional[tuple] = None,
    allow_not_found: bool = False,
) -> Any:
    """
    Performs an HTTP request against the Kibana REST API.

    Reuses the integration's Elasticsearch authentication configuration and automatically:
      - Derives the Kibana base URL from the Server URL.
      - Prefixes the path with the space ID, when provided.
      - Adds the "kbn-xsrf" header required by Kibana for write operations (POST/PUT/PATCH/DELETE).

    Args:
        method: HTTP method, e.g. "GET", "POST", "PUT", "DELETE".
        path: The Kibana API path, e.g. "/api/cases".
        space_id: Optional Kibana space ID. Falls back to the "Space ID" configuration parameter when not provided.
        params: Optional query-string parameters.
        json_data: Optional JSON request body.
        files: Optional dict of files for multipart/form-data requests (e.g. file attachments).
        proxies: Optional proxies dict, as returned by handle_proxy().
        ok_codes: Optional tuple of HTTP status codes considered successful. Defaults to (200, 201, 204).
        allow_not_found: When True, a 404 response is treated as "no entries found" and None is
            returned instead of raising a DemistoException. Intended for read (GET) commands where
            a missing resource should be surfaced to the user as an empty result rather than an error.

    Returns:
        Any: The parsed JSON response, an empty dict for empty (e.g. 204) responses, or None when
            allow_not_found is True and the response status code is 404.

    Raises:
        DemistoException: If the request fails or returns an unexpected status code.
    """
    ok_codes = ok_codes or (200, 201, 204)
    space_id = space_id or DEFAULT_SPACE_ID
    method = method.upper()

    url = urljoin(get_kibana_base_url(), build_kibana_path(path, space_id))
    headers = get_kibana_auth_headers()
    if method in KIBANA_WRITE_METHODS:
        headers.update(KIBANA_XSRF_HEADER)

    demisto.debug(f"Sending Kibana {method} request to {url}")
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=json_data if not files else None,
            data=json_data if files else None,
            files=files,
            verify=INSECURE,
            proxies=proxies,
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        raise DemistoException(f"Failed connecting to Kibana at {url}: {e}")

    if allow_not_found and response.status_code == 404:
        demisto.debug(f"Kibana API request to {url} returned 404, treating as no entries found.")
        return None

    if response.status_code not in ok_codes:
        error_message = response.text
        try:
            error_json = response.json()
            error_message = error_json.get("message") or error_json.get("error") or error_message
        except ValueError:
            pass
        raise DemistoException(f"Kibana API request to {url} failed with status {response.status_code}: {error_message}")

    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError:
        return response.text


def get_json_body_from_entry_id(entry_id: str) -> Any:
    """
    Reads a war-room file attachment referenced by entry_id and parses its content as JSON.

    Used by es-kibana-* commands that support an "entry_id" argument allowing the full
    request body to be supplied as an uploaded JSON file, overriding individual arguments.

    Args:
        entry_id: The war-room file entry ID.

    Returns:
        Any: The parsed JSON content of the file.

    Raises:
        DemistoException: If the file cannot be found, read, or parsed as JSON.
    """
    try:
        file_info = demisto.getFilePath(entry_id)
    except Exception as e:
        raise DemistoException(f"Failed to retrieve file info for entry_id={entry_id}: {e}")

    file_path = file_info.get("path") if file_info else None
    if not file_path:
        raise DemistoException(f"Could not resolve file path for entry_id={entry_id}")

    try:
        with open(file_path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise DemistoException(f"The file for entry_id={entry_id} does not contain valid JSON: {e}")
    except OSError as e:
        raise DemistoException(f"Failed reading file for entry_id={entry_id}: {e}")


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


def get_hit_table(hit):
    """Create context for a single hit in the search.

    Args:
        hit(Dict): a dictionary representing a single hit in the search.

    Returns:
        (dict).The hit context.
        (list).the headers of the hit.
    """
    table_context = {
        "_index": hit.get("_index"),
        "_id": hit.get("_id"),
        "_type": hit.get("_type"),
        "_score": hit.get("_score"),
    }
    headers = ["_index", "_id", "_type", "_score"]

    if hit.get("_source") is not None:
        for source_field in hit.get("_source"):
            table_context[str(source_field)] = hit.get("_source").get(str(source_field))
            headers.append(source_field)

    # Add normalized Elasticsearch fields to the table context
    if hit.get("fields") is not None:
        for field_name, field_value in hit.get("fields").items():
            normalized_key = f"fields.{field_name}"
            # Elasticsearch always returns field values as lists,
            # we unwrap single-element lists for readability
            if isinstance(field_value, list):
                table_context[normalized_key] = field_value[0] if len(field_value) == 1 else field_value
            else:
                table_context[normalized_key] = field_value
            headers.append(normalized_key)

    return table_context, headers


def results_to_context(index, query, base_page, size, total_dict, response, event=False):
    """Creates context for the full results of a search.

    Args:
        index(str): the index in which the search was made.
        query(str): the query of the search.
        base_page(int): the base page from which the search is made.
        size(int): the amount of results to return.
        total_dict(dict): a dictionary containing the info about thenumber of total results found
        response(Dict): the raw response of the results.

    Returns:
        (dict).The full context for the search results.
        (list).The metadata headers of the search.
        (list).the context for the hits.
        (list).the headers of the hits.
    """
    search_context = {
        "Server": SERVER,
        "Index": index,
        "Query": query,
        "Page": base_page,
        "Size": size,
        "total": total_dict,
        "max_score": response.get("hits").get("max_score"),
        "took": response.get("took"),
        "timed_out": response.get("timed_out"),
    }

    if aggregations := response.get("aggregations"):
        search_context["aggregations"] = aggregations

    hit_headers = []  # type: List
    hit_tables = []
    if total_dict.get("value") > 0:
        if not event:
            results = response.get("hits").get("hits", [])
        else:
            results = response.get("hits").get("events", [])

        for hit in results:
            single_hit_table, single_header = get_hit_table(hit)
            hit_tables.append(single_hit_table)
            hit_headers = list(set(single_header + hit_headers) - {"_id", "_type", "_index", "_score"})
        hit_headers = ["_id", "_index", "_type", "_score"] + hit_headers

    search_context["Results"] = response.get("hits").get("hits")
    meta_headers = ["Query", "took", "timed_out", "total", "max_score", "Server", "Page", "Size", "aggregations"]
    return search_context, meta_headers, hit_tables, hit_headers


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


def search_command(proxies):
    """Performs a search in Elasticsearch."""
    index = demisto.args().get("index")
    query = demisto.args().get("query")
    fields = demisto.args().get("fields")  # fields to display
    explain = demisto.args().get("explain", "false").lower() == "true"
    base_page = int(demisto.args().get("page"))
    size = int(demisto.args().get("size"))
    sort_field = demisto.args().get("sort-field")
    sort_order = demisto.args().get("sort-order")
    query_dsl = demisto.args().get("query_dsl")
    timestamp_field = demisto.args().get("timestamp_field")
    timestamp_range_start = demisto.args().get("timestamp_range_start")
    timestamp_range_end = demisto.args().get("timestamp_range_end")

    if query and query_dsl:
        return_error("Both query and query_dsl are configured. Please choose between query or query_dsl.")

    es = elasticsearch_builder(proxies)
    time_range_dict = None
    if timestamp_range_end or timestamp_range_start:
        time_range_dict = get_time_range(
            time_range_start=timestamp_range_start,
            time_range_end=timestamp_range_end,
            time_field=timestamp_field,
        )
    demisto.debug(f"Executing search with index={index}, query={query}, query_dsl={query_dsl}")

    if query_dsl:
        query_dsl = query_string_to_dict(query_dsl)
        if query_dsl.get("size", False) or query_dsl.get("page", False):
            response = execute_raw_query(es, query_dsl, index)
        else:
            response = execute_raw_query(es, query_dsl, index, size, base_page)

    else:
        que = QueryString(query=query)
        search = Search(using=es, index=index).query(que)[base_page : base_page + size]
        if explain:
            # if 'explain parameter is set to 'true' - adds explanation section to search results
            search = search.extra(explain=True)

        if time_range_dict:
            search = search.filter(time_range_dict)

        if fields is not None:
            fields = fields.split(",")
            search = search.source(fields)

        if sort_field is not None:
            search = search.sort({sort_field: {"order": sort_order}})

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

    demisto.debug(f"Search response: {response}")
    total_dict, total_results = get_total_results(response)
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(
        index, query_dsl or query, base_page, size, total_dict, response
    )
    search_human_readable = tableToMarkdown("Search Metadata:", search_context, meta_headers, removeNull=True)
    hits_human_readable = tableToMarkdown("Hits:", hit_tables, hit_headers, removeNull=True)
    total_human_readable = search_human_readable + "\n" + hits_human_readable
    full_context = {
        "Elasticsearch.Search(val.Query == obj.Query && val.Index == obj.Index "
        "&& val.Server == obj.Server && val.Page == obj.Page && val.Size == obj.Size)": search_context
    }

    return_outputs(total_human_readable, full_context, response)


def fetch_params_check():
    """If is_fetch is ticked, this function checks that all the necessary parameters for the fetch are entered."""
    str_error = []  # type:List
    if (TIME_FIELD == "" or TIME_FIELD is None) and not RAW_QUERY:
        str_error.append("Index time field is not configured.")

    if not FETCH_QUERY:
        str_error.append("Query by which to fetch incidents is not configured.")

    if RAW_QUERY and FETCH_QUERY_PARM:
        str_error.append("Both Query and Raw Query are configured. Please choose between Query or Raw Query.")

    if len(str_error) > 0:
        return_error("Got the following errors in test:\nFetches incidents is enabled.\n" + "\n".join(str_error))


def test_query_to_fetch_incident_index(es):
    """Test executing query in fetch index.

    Notes:
        if is_fetch it ticked, this function runs a general query to Elasticsearch just to make sure we get a response
        from the FETCH_INDEX.

    Args:
        es(Elasticsearch): an Elasticsearch object to which we run the test.
    """
    try:
        query = QueryString(query="*")
        search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8]:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below or OpenSearch
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

        demisto.debug(f"Test query to fetch incident index response: {response}")
        _, total_results = get_total_results(response)

    except NotFoundError as e:
        return_error("Fetch incidents test failed.\nError message: {}.".format(str(e).split(",")[2][2:-1]))


def test_general_query(es):
    """Test executing query to all available indexes.

    Args:
        es(Elasticsearch): an Elasticsearch object to which we run the test.
    """
    try:
        query = QueryString(query="*")
        search = Search(using=es, index="*").query(query)[0:1]

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

        demisto.debug(f"Test general query response: {response}")
        get_total_results(response)

    except NotFoundError as e:
        return_error(
            f"Failed executing general search command - please check the Server URL and port number "
            f"and the supplied credentials.\nError message: {e!s}."
        )


def test_time_field_query(es):
    """Test executing query of fetch time field.

    Notes:
        if is_fetch is ticked, this function checks if the entered TIME_FIELD returns results.

    Args:
        es(Elasticsearch): an Elasticsearch object to which we run the test.

    Returns:
        (dict).The results of the query if they are returned.
    """
    query = QueryString(query=TIME_FIELD + ":*")
    search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
        response = search.execute().to_dict()

    else:  # Elasticsearch v7 and below
        # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
        response = es.search(index=search._index, body=search.to_dict(), **search._params)

    demisto.debug(f"Test time field query response: {response}")
    _, total_results = get_total_results(response)

    if total_results == 0:
        # failed in getting the TIME_FIELD
        raise Exception(f"Fetch incidents test failed.\nDate field value incorrect [{TIME_FIELD}].")

    else:
        return response


def test_fetch_query(es):
    """Test executing fetch query.

    Notes:
        if is_fetch is ticked, this function checks if the FETCH_QUERY returns results.

    Args:
        es(Elasticsearch): an Elasticsearch object to which we run the test.

    Returns:
        (dict).The results of the query if they are returned.
    """
    query = QueryString(query=str(TIME_FIELD) + ":* AND " + FETCH_QUERY)
    search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
        response = search.execute().to_dict()

    else:  # Elasticsearch v7 and below
        # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
        response = es.search(index=search._index, body=search.to_dict(), **search._params)

    demisto.debug(f"Test fetch query response: {response}")
    return response


def test_timestamp_format(timestamp):
    """if is_fetch is ticked and the TIME_METHOD chosen is a type of timestamp - this function checks that
        the timestamp is in the correct format.

    Args:
        timestamp(sting): a timestamp string.
    """
    timestamp_in_seconds_len = len(str(int(time.time())))

    if TIME_METHOD == "Timestamp-Seconds":
        if not timestamp.isdigit():
            return_error(f"The time field does not contain a standard timestamp.\nFetched: {timestamp}")

        elif len(timestamp) > timestamp_in_seconds_len:
            return_error(f"Fetched timestamp is not in seconds since epoch.\nFetched: {timestamp}")

    elif TIME_METHOD == "Timestamp-Milliseconds":
        if not timestamp.isdigit():
            return_error(f"The timestamp fetched is not in milliseconds.\nFetched: {timestamp}")

        elif len(timestamp) <= timestamp_in_seconds_len:
            return_error(f"Fetched timestamp is not in milliseconds since epoch.\nFetched: {timestamp}")


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

    Due to load considerations, the test module doesn't check the validity of the fetch-incident - to test that the fetch works
    as excepted the user should run the es-integration-health-check command.

    """
    success, message = test_connectivity_auth(proxies)
    if not success:
        return message
    if demisto.params().get("isFetch"):
        # check the existence of all necessary fields for fetch
        fetch_params_check()
    return "ok"


def integration_health_check(proxies):
    success, message = test_connectivity_auth(proxies)
    if not success:
        raise DemistoException(message)
    # build general Elasticsearch class
    es = elasticsearch_builder(proxies)

    if demisto.params().get("isFetch"):
        # check the existence of all necessary fields for fetch
        fetch_params_check()

        try:
            # test if FETCH_INDEX exists
            test_query_to_fetch_incident_index(es)

            # test if TIME_FIELD in index exists
            response = test_time_field_query(es)

            # get the value in the time field
            source = response.get("hits", {}).get("hits")[0].get("_source", {})
            hit_date = str(get_value_by_dot_notation(source, str(TIME_FIELD)))

            demisto.debug(f"Hit date received: {hit_date}")
            # if not a timestamp test the conversion to datetime object
            if "Timestamp" not in TIME_METHOD:
                parse(str(hit_date))

            # test timestamp format and conversion to date
            else:
                test_timestamp_format(hit_date)
                timestamp_to_date(hit_date)

        except ValueError as e:
            return_error("Inserted time format is incorrect.\n" + str(e) + "\n" + TIME_FIELD + " fetched: " + hit_date)

        # try to get response from FETCH_QUERY or RAW_QUERY
        try:
            if RAW_QUERY:
                fetch_result = execute_raw_query(es, RAW_QUERY)
            else:
                fetch_result = test_fetch_query(es)

            # validate that the response actually returned results and did not time out
            if fetch_result and isinstance(fetch_result.get("timed_out"), bool):
                if fetch_result.get("timed_out"):
                    return_error(f"Elasticsearch fetching has timed out. Fetching response was:\n{str(fetch_result)}")
                _, total_results = get_total_results(fetch_result)
                if total_results == 0:
                    demisto.info("Elasticsearch fetching test returned 0 hits, but this might be expected.")
            else:
                return_error(
                    "Elasticsearch fetching was unsuccessful. Fetching returned the following invalid object:\n"
                    + str(fetch_result)
                )
        except Exception as ex:
            return_error(f"An exception has been thrown trying to test Elasticsearch fetching:\n{str(ex)}", error=str(ex))

    else:
        # check that we can reach any indexes in the supplied server URL
        test_general_query(es)
    return "Testing was successful."


def normalize_es_value(value):
    if isinstance(value, list):
        value = value[0] if len(value) == 1 else value

    if isinstance(value, dict | list):
        return json.dumps(value)

    return str(value)


def incident_label_maker(source, fields=None):
    """Creates labels for the created incident.

    Args:
        source(dict): the _source fields of a hit.
        fields (dict): the normalized fields returned by Elasticsearch.

    Returns:
        (list).The labels.
    """
    labels = []

    for field, value in source.items():
        labels.append({"type": str(field), "value": normalize_es_value(value)})

    if fields:
        for field, value in fields.items():
            labels.append({"type": f"fields.{field}", "value": normalize_es_value(value)})

    return labels


def results_to_incidents_timestamp(response, last_fetch):
    """Converts the current results into incidents.

    Args:
        response(dict): the raw search results from Elasticsearch.
        last_fetch(num): the date or timestamp of the last fetch before this fetch
        - this will hold the last date of the incident brought by this fetch.

    Returns:
        (list).The incidents.
        (num).The date of the last incident brought by this fetch.
    """
    current_fetch = last_fetch
    incidents = []
    for hit in response.get("hits", {}).get("hits"):
        source = hit.get("_source")

        # Retrieve normalized fields returned by Elasticsearch.
        # These may contain runtime fields or normalized date values
        # not present in _source.
        fields = hit.get("fields")

        if source is not None:
            time_field_value = get_value_by_dot_notation(source, str(TIME_FIELD))

            # Fallback: if TIME_FIELD is not found in _source,
            # try to retrieve it from normalized fields.
            # This handles cases where TIME_FIELD is a runtime field.
            if time_field_value is None and fields:
                field_value = fields.get(TIME_FIELD)

                if isinstance(field_value, list):
                    field_value = field_value[0] if field_value else None

                if field_value is not None:
                    time_field_value = field_value

            if time_field_value is not None:
                # if timestamp convert to iso format date and save the timestamp
                hit_date = timestamp_to_date(str(time_field_value))
                hit_timestamp = int(time_field_value)

                if hit_timestamp > last_fetch:
                    last_fetch = hit_timestamp

                # avoid duplication due to weak time query
                if hit_timestamp > current_fetch:
                    inc = {
                        "name": "Elasticsearch: Index: " + str(hit.get("_index")) + ", ID: " + str(hit.get("_id")),
                        "rawJSON": json.dumps(hit),
                        "occurred": hit_date.isoformat() + "Z",
                    }
                    if hit.get("_id"):
                        inc["dbotMirrorId"] = hit.get("_id")

                    if MAP_LABELS:
                        inc["labels"] = incident_label_maker(hit.get("_source"))

                    incidents.append(inc)

    return incidents, last_fetch


def results_to_incidents_datetime(response, last_fetch):
    """Converts the current results into incidents.

    Args:
        response(dict): the raw search results from Elasticsearch.
        last_fetch(datetime): the date or timestamp of the last fetch before this fetch or parameter default fetch time
        - this will hold the last date of the incident brought by this fetch.

    Returns:
        (list).The incidents.
        (datetime).The date of the last incident brought by this fetch.
    """
    last_fetch = dateparser.parse(last_fetch)
    last_fetch_timestamp = int(last_fetch.timestamp() * 1000)  # type:ignore[union-attr]
    current_fetch = last_fetch_timestamp
    incidents = []

    for hit in response.get("hits", {}).get("hits"):
        source = hit.get("_source")

        # Retrieve normalized fields returned by Elasticsearch.
        # These may contain runtime fields or normalized date values
        # not present in _source.
        fields = hit.get("fields")

        if source is not None:
            time_field_value = get_value_by_dot_notation(source, str(TIME_FIELD))

            # Fallback: if TIME_FIELD is not found in _source,
            # try to retrieve it from normalized fields.
            # This handles cases where TIME_FIELD is a runtime field.
            if time_field_value is None and fields:
                field_value = fields.get(TIME_FIELD)

                if isinstance(field_value, list):
                    field_value = field_value[0] if field_value else None

                if field_value is not None:
                    time_field_value = field_value

            if time_field_value is not None:
                hit_date = parse(str(time_field_value))
                hit_timestamp = int(hit_date.timestamp() * 1000)

                if hit_timestamp > last_fetch_timestamp:
                    last_fetch = hit_date
                    last_fetch_timestamp = hit_timestamp

                if hit_timestamp > current_fetch:
                    inc = {
                        "name": "Elasticsearch: Index: " + str(hit.get("_index")) + ", ID: " + str(hit.get("_id")),
                        "rawJSON": json.dumps(hit),
                        # parse function returns iso format sometimes as YYYY-MM-DDThh:mm:ss+00:00
                        # and sometimes as YYYY-MM-DDThh:mm:ss
                        # we want to return format: YYYY-MM-DDThh:mm:ssZ in our incidents
                        "occurred": format_to_iso(hit_date.isoformat()),
                    }
                    if hit.get("_id"):
                        inc["dbotMirrorId"] = hit.get("_id")

                    if MAP_LABELS:
                        # Pass both _source and normalized fields to label maker
                        inc["labels"] = incident_label_maker(hit.get("_source"), fields=fields)

                    incidents.append(inc)
                else:
                    demisto.debug(
                        f"Skipping hit ID: {hit.get('_id')} since {hit_timestamp=} is earlier than the {current_fetch=}"
                    )

    return incidents, last_fetch.isoformat()  # type:ignore[union-attr]


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
    last_fetch: Union[str, None] = None, time_range_start=FETCH_TIME, time_range_end=None, time_field=TIME_FIELD
) -> Dict:
    """
    Creates the time range filter's dictionary based on the last fetch and given params.
    The filter is using timestamps with the following logic:
        start date (gt) - if this is the first fetch: use time_range_start param if provided, else use fetch time param.
                          if this is not the fetch: use the last fetch provided
        end date (lt) - use the given time range end param.
        When the `time_method` parameter is set to `Simple-Date` in order to avoid being related to the field datetime format,
            we add the format key to the query dict.
    Args:

        last_fetch (str): last fetch time stamp
        time_range_start (str): start of time range
        time_range_end (str): end of time range
        time_field (str): The field on which the filter the results


    Returns:
        dictionary (Ex. {"range":{'gt': 1000 'lt': 1001}})
    """
    range_dict = {}
    if not last_fetch and time_range_start:  # this is the first fetch
        start_date = dateparser.parse(time_range_start)

        start_time = convert_date_to_timestamp(start_date)
    else:
        start_time = last_fetch

    demisto.debug(f"Time range start time: {start_time}")
    if start_time:
        range_dict["gt"] = start_time

    if time_range_end:
        end_date = dateparser.parse(time_range_end)
        end_time = convert_date_to_timestamp(end_date)
        range_dict["lt"] = end_time

    if TIME_METHOD == "Simple-Date":
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


def execute_raw_query(es, raw_query, index=None, size=None, page=None):
    body = query_string_to_dict(raw_query)

    requested_index = index or FETCH_INDEX

    # update parameters if given
    if isinstance(size, int):
        body["size"] = size
    if isinstance(page, int):
        body["from"] = page

    search = Search(using=es, index=requested_index).update_from_dict(body)

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
        response = search.execute().to_dict()
    else:  # Elasticsearch v7 and below
        # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
        response = es.search(index=search._index, body=search.to_dict(), **search._params)

    demisto.debug(f"Raw query response: {response}")
    return response


def fetch_incidents(proxies):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get("time") or FETCH_TIME

    es = elasticsearch_builder(proxies)
    time_range_dict = get_time_range(time_range_start=last_fetch)

    if RAW_QUERY:
        response = execute_raw_query(es, RAW_QUERY)
    else:
        query = QueryString(query="(" + FETCH_QUERY + ") AND " + TIME_FIELD + ":*")
        # Elastic search can use epoch timestamps (in milliseconds) as date representation regardless of date format.
        search = Search(using=es, index=FETCH_INDEX).filter(time_range_dict)
        search = search.sort({TIME_FIELD: {"order": "asc"}})[0:FETCH_SIZE].query(query)
        search = search.extra(fields=FIELDS_LIST, _source=True)

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

    demisto.debug(f"Fetch incidents response: {response}")
    _, total_results = get_total_results(response)

    incidents = []  # type: List

    if total_results > 0:
        if "Timestamp" in TIME_METHOD:
            incidents, last_fetch = results_to_incidents_timestamp(response, last_fetch)
            demisto.setLastRun({"time": last_fetch})

        else:
            incidents, last_fetch = results_to_incidents_datetime(response, last_fetch or FETCH_TIME)
            demisto.setLastRun({"time": str(last_fetch)})

        demisto.info(f"Extracted {len(incidents)} incidents.")
    demisto.incidents(incidents)


def parse_subtree(my_map):
    """
    param: my_map - tree element for the schema
    return: tree elements under each branch
    """
    # Recursive search in order to retrieve the elements under the branches in the schema
    res = {}
    for k in my_map:
        if "properties" in my_map[k]:
            res[k] = parse_subtree(my_map[k]["properties"])
        else:
            res[k] = "type: " + my_map[k].get("type", "")
    return res


def update_elastic_mapping(res_json, elastic_mapping, key):
    """
    A helper function for get_mapping_fields_command, updates the elastic mapping.
    """
    my_map = res_json[key]["mappings"]["properties"]
    elastic_mapping[key] = {"_id": "doc_id", "_index": key}
    elastic_mapping[key]["_source"] = parse_subtree(my_map)


def get_mapping_fields_command():
    """
    Maps a schema from a given index
    return: Elasticsearch schema structure
    """
    indexes = FETCH_INDEX.split(",")
    elastic_mapping = {}  # type:ignore[var-annotated]
    for index in indexes:
        if index == "":
            res = requests.get(SERVER + "/_mapping", auth=(USERNAME, PASSWORD), verify=INSECURE)
        else:
            res = requests.get(SERVER + "/" + index + "/_mapping", auth=(USERNAME, PASSWORD), verify=INSECURE)
        res_json = res.json()

        # To get mappings for all data streams and indices in a cluster,
        # use _all or * for <target> or omit the <target> parameter - from Elastic API
        if index in ["*", "_all", ""]:
            for key in res_json:
                if "mappings" in res_json[key] and "properties" in res_json[key]["mappings"]:
                    update_elastic_mapping(res_json, elastic_mapping, key)

        elif index.endswith("*"):
            prefix_index = re.compile(index.rstrip("*"))
            for key in res_json:
                if prefix_index.match(key):
                    update_elastic_mapping(res_json, elastic_mapping, key)

        else:
            update_elastic_mapping(res_json, elastic_mapping, index)

    return elastic_mapping


def build_eql_body(query, fields, size, tiebreaker_field, timestamp_field, event_category_field, filter):
    body = {}
    if query is not None:
        body["query"] = query
    if event_category_field is not None:
        body["event_category_field"] = event_category_field
    if fields is not None:
        body["fields"] = fields
    if filter is not None:
        body["filter"] = filter
    if size is not None:
        body["size"] = size
    if tiebreaker_field is not None:
        body["tiebreaker_field"] = tiebreaker_field
    if timestamp_field is not None:
        body["timestamp_field"] = timestamp_field
    return body


def search_eql_command(args, proxies):
    index = args.get("index")
    query = args.get("query")
    fields = args.get("fields")  # fields to display
    size = int(args.get("size", "10"))
    timestamp_field = args.get("timestamp_field")
    event_category_field = args.get("event_category_field")
    sort_tiebreaker = args.get("sort_tiebreaker")
    query_filter = args.get("filter")

    es = elasticsearch_builder(proxies)
    body = build_eql_body(
        query=query,
        fields=fields,
        size=size,
        tiebreaker_field=sort_tiebreaker,
        timestamp_field=timestamp_field,
        event_category_field=event_category_field,
        filter=query_filter,
    )

    demisto.debug(f"EQL search body: {body}")
    response = es.eql.search(index=index, body=body)

    total_dict, _ = get_total_results(response)
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(
        index, query, 0, size, total_dict, response, event=True
    )
    search_human_readable = tableToMarkdown("Search Metadata:", search_context, meta_headers, removeNull=True)
    hits_human_readable = tableToMarkdown("Hits:", hit_tables, hit_headers, removeNull=True)
    total_human_readable = search_human_readable + "\n" + hits_human_readable

    return CommandResults(readable_output=total_human_readable, outputs_prefix="Elasticsearch.Search", outputs=search_context)


def search_esql_command(args, proxies):
    query = args.get("query")
    limit = args.get("limit")

    es = elasticsearch_builder(proxies)

    if limit:
        query = {"query": query + f"| LIMIT {limit}"}
    else:
        query = {"query": query}

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, ELASTICSEARCH_V9]:
        compatible_with = 8 if ELASTIC_SEARCH_CLIENT == ELASTICSEARCH_V8 else 9
        headers = {
            "Content-Type": f"application/vnd.elasticsearch+json; compatible-with={compatible_with}",
            "Accept": f"application/vnd.elasticsearch+json; compatible-with={compatible_with}",
        }
    else:
        return_error("ES|QL Search is only supported in Elasticsearch 8.11 and above.")
        return None

    demisto.debug(f"ES|QL search body: {query}")
    res = es.perform_request(method="POST", path="/_query?format=json", headers=headers, body=query)

    human_output_columns = [col["name"] for col in res["columns"]]
    human_output_rows = res["values"]
    human_output = []

    for row in human_output_rows:
        row_dict = {}
        for i in range(len(human_output_columns)):
            row_dict[human_output_columns[i]] = row[i]
        human_output.append(row_dict)

    search_human_readable = tableToMarkdown(
        "Search query:", [{"Query": query.get("query"), "Total": str(len(human_output_rows))}], removeNull=True
    )
    hits_human_readable = tableToMarkdown("Results:", human_output, removeNull=True)
    total_human_readable = search_human_readable + "\n" + hits_human_readable

    return CommandResults(
        readable_output=total_human_readable,
        outputs_prefix="Elasticsearch.ESQLSearch",
        outputs=human_output,
        raw_response=res.body,
    )


def index_document(args, proxies):
    """
    Indexes a given document into an Elasticsearch index.
    return: Result returned from elasticsearch lib
    """
    index = args.get("index_name")
    doc = args.get("document")
    doc_id = args.get("id", "")
    es = elasticsearch_builder(proxies)

    demisto.debug(f"Indexing document in index {index} with ID {doc_id}")
    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8]:
        if doc_id:
            response = es.index(index=index, id=doc_id, document=doc)  # pylint: disable=E1123,E1120,E1125
        else:
            response = es.index(index=index, document=doc)  # pylint: disable=E1123,E1120,E1125

    else:  # Elasticsearch version v7 or below, OpenSearch (BC)
        # In elasticsearch lib <8 'document' param is called 'body'
        if doc_id:
            response = es.index(index=index, id=doc_id, body=doc)
        else:
            response = es.index(index=index, body=doc)

    demisto.debug(f"Index document response: {response}")
    return response


def index_document_command(args, proxies):
    resp = index_document(args, proxies)
    index_context = {
        "id": resp.get("_id", ""),
        "index": resp.get("_index", ""),
        "version": resp.get("_version", ""),
        "result": resp.get("result", ""),
    }
    human_readable = {
        "ID": index_context.get("id"),
        "Index name": index_context.get("index"),
        "Version": index_context.get("version"),
        "Result": index_context.get("result"),
    }
    headers = [str(k) for k in human_readable]
    readable_output = tableToMarkdown(name="Indexed document", t=human_readable, removeNull=True, headers=headers)

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8]:
        resp = resp.body

    result = CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Index",
        outputs=index_context,
        raw_response=resp,
        outputs_key_field="id",
    )
    return result


def get_indices_statistics(client):
    """
    Returns raw statistics and information of all the Elasticsearch indices.
    Args:
        client : The Elasticsearch client

    Returns:
        dict: raw statistics and information of all the Elasticsearch indices.
    """
    stats = client.indices.stats()
    raw_indices_data = stats.get("indices")

    return raw_indices_data


def get_indices_statistics_command(args, proxies):
    """
    Returns statistics and information of the Elasticsearch indices.

    return: A List with Elasticsearch indices info and statistics.
    API reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-stats.html
    """
    limit = arg_to_number(args.get("limit", 50))
    all_results = argToBoolean(args.get("all_results", False))
    indices = []
    es = elasticsearch_builder(proxies)

    demisto.debug("Retrieving indices statistics")
    # Fetch the statistics for all indices
    raw_indices_data = get_indices_statistics(es)
    for index, index_data in raw_indices_data.items():
        index_stats = {
            "Name": index,
            "Status": index_data.get("status", ""),
            "Health": index_data.get("health", ""),
            "UUID": index_data.get("uuid", ""),
            "Documents Count": index_data.get("total", {}).get("docs", {}).get("count", ""),
            "Documents Deleted": index_data.get("total", {}).get("docs", {}).get("deleted", ""),
        }
        indices.append(index_stats)

    if not all_results:
        indices = indices[:limit]

    readable_output = tableToMarkdown(
        name="Indices Statistics:", t=indices, removeNull=True, headers=[str(k) for k in indices[0]]
    )

    result = CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.IndexStatistics",
        outputs=indices,
        outputs_key_field="UUID",
        raw_response=raw_indices_data,
    )
    return result


"""KIBANA CASE MANAGEMENT COMMANDS (es-kibana-case-*)"""

CONNECTOR_FIELD_ARG_MAP = {
    "connector_fields_issue_type_jira": "issueType",
    "connector_fields_parent_jira": "parent",
    "connector_fields_priority_jira": "priority",
    "connector_fields_severity_code_resilient": "severityCode",
    "connector_fields_category_servicenow": "category",
    "connector_fields_impact_servicenow": "impact",
    "connector_fields_severity_servicenow": "severity",
    "connector_fields_subcategory_servicenow": "subcategory",
    "connector_fields_urgency_servicenow": "urgency",
    "connector_fields_priority_servicenow": "priority",
    "connector_fields_case_id_swimlane": "caseId",
}
CONNECTOR_FIELD_BOOLEAN_ARG_MAP = {
    "connector_fields_dest_ip_servicenow": "destIp",
    "connector_fields_malware_hash_servicenow": "malwareHash",
    "connector_fields_malware_url_servicenow": "malwareUrl",
    "connector_fields_source_ip_servicenow": "sourceIp",
}


def build_case_connector_fields(args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Builds the Kibana case connector "fields" object from the flattened connector_fields_* arguments.

    If the raw "connector_fields" argument is provided, it takes precedence and is used as-is
    (parsed as JSON if given as a string).
    """
    raw_connector_fields = args.get("connector_fields")
    if raw_connector_fields:
        return json.loads(raw_connector_fields) if isinstance(raw_connector_fields, str) else raw_connector_fields

    fields: Dict[str, Any] = {}
    for arg_name, field_name in CONNECTOR_FIELD_ARG_MAP.items():
        if args.get(arg_name):
            fields[field_name] = args[arg_name]
    for arg_name, field_name in CONNECTOR_FIELD_BOOLEAN_ARG_MAP.items():
        if arg_name in args:
            fields[field_name] = argToBoolean(args[arg_name])
    if args.get("connector_fields_issue_types_resilient"):
        fields["incidentTypes"] = argToList(args["connector_fields_issue_types_resilient"])

    return fields or None


def build_case_connector(args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Builds the Kibana case "connector" object from the case command arguments."""
    connector_id = args.get("connector_id")
    connector_name = args.get("connector_name")
    connector_type = args.get("connector_type")
    fields = build_case_connector_fields(args)

    if not any([connector_id, connector_name, connector_type, fields]):
        return None

    connector: Dict[str, Any] = {"fields": fields}
    if connector_id:
        connector["id"] = connector_id
    if connector_name:
        connector["name"] = connector_name
    if connector_type:
        connector["type"] = connector_type
    return connector


def build_case_custom_fields(args: Dict[str, Any]) -> Optional[list]:
    """Builds the Kibana case "customFields" array from the custom_key/custom_type/custom_value arguments."""
    key = args.get("custom_key")
    if not key:
        return None
    custom_type = args.get("custom_type")
    value = args.get("custom_value")
    if custom_type == "toggle":
        value = argToBoolean(value)
    return [{"key": key, "type": custom_type, "value": value}]


def build_case_body(args: Dict[str, Any], require_owner: bool = False) -> Dict[str, Any]:
    """
    Builds a Kibana case request body from the command arguments shared by
    es-kibana-case-create and es-kibana-case-update.
    """
    body: Dict[str, Any] = {}
    if args.get("title"):
        body["title"] = args["title"]
    if args.get("description"):
        body["description"] = args["description"]
    if args.get("tags") is not None:
        body["tags"] = argToList(args.get("tags"))
    if args.get("category"):
        body["category"] = args["category"]
    if args.get("severity"):
        body["severity"] = args["severity"]

    owner = args.get("owner")
    if owner:
        body["owner"] = owner
    elif require_owner:
        raise DemistoException('The "owner" argument is required.')

    assignee_uids = argToList(args.get("assignee_uid"))
    if assignee_uids:
        body["assignees"] = [{"uid": uid} for uid in assignee_uids]

    connector = build_case_connector(args)
    if connector:
        body["connector"] = connector

    settings: Dict[str, Any] = {}
    if "sync_alerts" in args:
        settings["syncAlerts"] = argToBoolean(args["sync_alerts"])
    if "extract_observables" in args:
        settings["extractObservables"] = argToBoolean(args["extract_observables"])
    if settings:
        body["settings"] = settings

    custom_fields = build_case_custom_fields(args)
    if custom_fields:
        body["customFields"] = custom_fields

    return body


def case_to_hr(case: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the human-readable row for a single Kibana case."""
    return {
        "Title": case.get("title"),
        "Case id": case.get("id"),
        "Description": case.get("description"),
        "Owner": case.get("owner"),
        "Severity": case.get("severity"),
        "Status": case.get("status"),
        "Creation date": case.get("created_at"),
        "Type": get_value_by_dot_notation(case, "connector.type"),
    }


def es_kibana_case_create_command(args: Dict[str, Any], proxies) -> CommandResults:
    entry_id = args.get("entry_id")
    body = get_json_body_from_entry_id(entry_id) if entry_id else build_case_body(args, require_owner=True)
    space_id = args.get("space_id")

    response = kibana_http_request("POST", "/api/cases", space_id=space_id, json_data=body, proxies=proxies)

    hr = case_to_hr(response)
    readable_output = tableToMarkdown("Kibana Case", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.Case",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_case_update_command(args: Dict[str, Any], proxies) -> CommandResults:
    entry_id = args.get("entry_id")
    if entry_id:
        payload = get_json_body_from_entry_id(entry_id)
    else:
        case_id = args.get("case_id")
        version = args.get("version")
        if not case_id:
            raise DemistoException('The "case_id" argument is required.')
        if not version:
            raise DemistoException('The "version" argument is required.')

        case_fields = build_case_body(args)
        case_fields["id"] = case_id
        case_fields["version"] = version
        if args.get("status"):
            case_fields["status"] = args["status"]
        if args.get("close_reason"):
            case_fields["closeReason"] = args["close_reason"]
        payload = {"cases": [case_fields]}

    space_id = args.get("space_id")
    response = kibana_http_request("PATCH", "/api/cases", space_id=space_id, json_data=payload, proxies=proxies)

    cases = response if isinstance(response, list) else [response]
    hr_rows = [case_to_hr(case) for case in cases]
    readable_output = tableToMarkdown(
        "Kibana Case(s) Updated", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    outputs = cases[0] if len(cases) == 1 else cases
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.Case",
        outputs=outputs,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_case_delete_command(args: Dict[str, Any], proxies) -> CommandResults:
    case_ids = argToList(args.get("case_id"))
    if not case_ids:
        raise DemistoException('The "case_id" argument is required.')
    space_id = args.get("space_id")

    kibana_http_request("DELETE", "/api/cases", space_id=space_id, params={"ids": json.dumps(case_ids)}, proxies=proxies)

    ids_str = ", ".join(case_ids)
    return CommandResults(readable_output=f"The cases {ids_str} have been successfully deleted.")


def es_kibana_case_list_command(args: Dict[str, Any], proxies) -> CommandResults:
    space_id = args.get("space_id")
    case_id = args.get("case_id")

    if case_id:
        response = kibana_http_request(
            "GET", f"/api/cases/{case_id}", space_id=space_id, proxies=proxies, allow_not_found=True
        )
        cases = [response] if response else []
    else:
        params: Dict[str, Any] = {}
        param_arg_map = {
            "assignees": "assignees",
            "category": "category",
            "default_search_operator": "defaultSearchOperator",
            "search": "search",
            "from": "from",
            "to": "to",
            "owner": "owner",
            "reporters": "reporters",
            "search_fields": "searchFields",
            "severity": "severity",
            "sort_field": "sortField",
            "sort_order": "sortOrder",
            "status": "status",
            "tags": "tags",
            "page": "page",
            "size": "perPage",
        }
        for arg_name, param_name in param_arg_map.items():
            if args.get(arg_name) is not None:
                params[param_name] = args[arg_name]

        response = kibana_http_request("GET", "/api/cases/_find", space_id=space_id, params=params, proxies=proxies)
        cases = response.get("cases", []) if isinstance(response, dict) else response

    hr_rows = [case_to_hr(case) for case in cases]
    readable_output = tableToMarkdown(
        "Kibana Cases", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.Case",
        outputs=cases,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_case_alerts_list_command(args: Dict[str, Any], proxies) -> CommandResults:
    case_id = args.get("case_id")
    if not case_id:
        raise DemistoException('The "case_id" argument is required.')
    space_id = args.get("space_id")

    params = {}
    if args.get("limit") is not None:
        params["limit"] = args["limit"]
    if args.get("offset") is not None:
        params["offset"] = args["offset"]

    response = kibana_http_request(
        "GET", f"/api/cases/{case_id}/alerts", space_id=space_id, params=params, proxies=proxies, allow_not_found=True
    )
    alerts = response if isinstance(response, list) else []

    hr_rows = [
        {
            "Case id": case_id,
            "Attached at": alert.get("attached_at"),
            "Alert id": alert.get("id"),
            "Index": alert.get("index"),
        }
        for alert in alerts
    ]
    readable_output = tableToMarkdown(
        f"Alerts for Case {case_id}", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"Elasticsearch.Kibana.Case.{case_id}.Alert",
        outputs=alerts,
        outputs_key_field="id",
        raw_response=response,
    )


def build_case_comment_body(args: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the Kibana case comment/alert request body shared by comment-add and comment-update."""
    comment_type = args.get("type")
    if not comment_type:
        raise DemistoException('The "type" argument is required.')
    owner = args.get("owner")
    if not owner:
        raise DemistoException('The "owner" argument is required.')

    body: Dict[str, Any] = {"type": comment_type, "owner": owner}

    if comment_type == "alert":
        alert_ids = argToList(args.get("alert_id"))
        indices = argToList(args.get("index"))
        body["alertId"] = alert_ids if len(alert_ids) > 1 else (alert_ids[0] if alert_ids else None)
        body["index"] = indices if len(indices) > 1 else (indices[0] if indices else None)
        if args.get("rule_id") or args.get("rule_name"):
            body["rule"] = {"id": args.get("rule_id"), "name": args.get("rule_name")}
    else:
        body["comment"] = args.get("comment")

    return body


def es_kibana_case_comment_add_command(args: Dict[str, Any], proxies) -> CommandResults:
    case_id = args.get("case_id")
    if not case_id:
        raise DemistoException('The "case_id" argument is required.')
    space_id = args.get("space_id")

    body = build_case_comment_body(args)
    response = kibana_http_request(
        "POST", f"/api/cases/{case_id}/comments", space_id=space_id, json_data=body, proxies=proxies
    )

    comments = response.get("comments", [])
    last_comment = comments[-1] if comments else {}
    hr = {
        "Case id": response.get("id"),
        "Comment": last_comment.get("comment"),
        "Created by": get_value_by_dot_notation(last_comment, "created_by.username"),
    }
    readable_output = tableToMarkdown("Kibana Case Comment Added", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.Case",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_case_comment_update_command(args: Dict[str, Any], proxies) -> CommandResults:
    case_id = args.get("case_id")
    if not case_id:
        raise DemistoException('The "case_id" argument is required.')
    space_id = args.get("space_id")

    body = build_case_comment_body(args)
    if args.get("comment_id"):
        body["id"] = args["comment_id"]
    if args.get("version"):
        body["version"] = args["version"]

    response = kibana_http_request(
        "PATCH", f"/api/cases/{case_id}/comments", space_id=space_id, json_data=body, proxies=proxies
    )

    comments = response.get("comments", [])
    updated_comment = next((c for c in comments if c.get("id") == args.get("comment_id")), comments[-1] if comments else {})
    hr = {
        "Case id": response.get("id"),
        "Comment": updated_comment.get("comment"),
        "Updated by": get_value_by_dot_notation(updated_comment, "updated_by.username"),
        "Updated at": updated_comment.get("updated_at"),
    }
    readable_output = tableToMarkdown("Kibana Case Comment Updated", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.Case",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_case_comment_delete_command(args: Dict[str, Any], proxies) -> CommandResults:
    case_id = args.get("case_id")
    if not case_id:
        raise DemistoException('The "case_id" argument is required.')
    space_id = args.get("space_id")

    kibana_http_request("DELETE", f"/api/cases/{case_id}/comments", space_id=space_id, proxies=proxies)

    return CommandResults(
        readable_output=f"The comments and alerts for the case {case_id} have been successfully deleted."
    )


def es_kibana_case_file_attach_command(args: Dict[str, Any], proxies) -> CommandResults:
    case_id = args.get("case_id")
    entry_id = args.get("entry_id")
    if not case_id:
        raise DemistoException('The "case_id" argument is required.')
    if not entry_id:
        raise DemistoException('The "entry_id" argument is required.')
    space_id = args.get("space_id")

    try:
        file_info = demisto.getFilePath(entry_id)
    except Exception as e:
        raise DemistoException(f"Failed to retrieve file info for entry_id={entry_id}: {e}")
    file_path = file_info.get("path") if file_info else None
    if not file_path:
        raise DemistoException(f"Could not resolve file path for entry_id={entry_id}")

    file_name = args.get("file_name") or file_info.get("name")

    with open(file_path, "rb") as f:
        files = {"file": (file_name, f)}
        response = kibana_http_request(
            "POST", f"/api/cases/{case_id}/files", space_id=space_id, files=files, proxies=proxies
        )

    comments = response.get("comments", []) if isinstance(response, dict) else []
    last_comment = comments[-1] if comments else {}
    hr = {
        "Case id": response.get("id") if isinstance(response, dict) else case_id,
        "Updated by": get_value_by_dot_notation(last_comment, "updated_by.username"),
    }
    readable_output = tableToMarkdown("Kibana Case File Attached", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.Case",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


"""KIBANA ALERTING / RULES FRAMEWORK COMMANDS (es-kibana-alerting-*, es-kibana-rule-*, es-kibana-detection-*)"""


def es_kibana_alerting_health_get_command(args: Dict[str, Any], proxies) -> CommandResults:
    space_id = args.get("space_id")
    response = kibana_http_request("GET", "/api/alerting/_health", space_id=space_id, proxies=proxies)

    hr = {
        "Is sufficiently secure": response.get("is_sufficiently_secure"),
        "Has permanent encryption key": response.get("has_permanent_encryption_key"),
        "Decryption status": get_value_by_dot_notation(response, "alerting_framework_health.decryption_health.status"),
        "Execution status": get_value_by_dot_notation(response, "alerting_framework_health.execution_health.status"),
        "Read status": get_value_by_dot_notation(response, "alerting_framework_health.read_health.status"),
    }
    readable_output = tableToMarkdown("Kibana Alerting Framework Health", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.AlertingHealth",
        outputs=response,
        raw_response=response,
    )


def es_kibana_rule_types_list_command(args: Dict[str, Any], proxies) -> CommandResults:
    space_id = args.get("space_id")
    response = kibana_http_request("GET", "/api/alerting/rule_types", space_id=space_id, proxies=proxies)
    rule_types = response if isinstance(response, list) else []

    hr_rows = [
        {
            "Rule type ID": rule_type.get("id"),
            "Name": rule_type.get("name"),
            "Category": rule_type.get("category"),
            "Producer": rule_type.get("producer"),
            "Action Group Id": [ag.get("id") for ag in rule_type.get("action_groups", [])],
        }
        for rule_type in rule_types
    ]
    readable_output = tableToMarkdown(
        "Kibana Rule Types", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.RuleTypes",
        outputs=rule_types,
        outputs_key_field="id",
        raw_response=response,
    )


def rule_to_hr(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the human-readable row for a single Kibana rule."""
    return {
        "Rule ID": rule.get("id"),
        "Enabled": rule.get("enabled"),
        "Name": rule.get("name"),
        "Type ID": rule.get("rule_type_id"),
        "Creation date": rule.get("created_at"),
    }


def es_kibana_rule_list_command(args: Dict[str, Any], proxies) -> CommandResults:
    space_id = args.get("space_id")
    rule_id = args.get("rule_id")

    if rule_id:
        response = kibana_http_request(
            "GET", f"/api/alerting/rule/{rule_id}", space_id=space_id, proxies=proxies, allow_not_found=True
        )
        rules = [response] if response else []
    else:
        params: Dict[str, Any] = {}
        param_arg_map = {
            "search": "search",
            "default_search_operator": "default_search_operator",
            "search_fields": "search_fields",
            "sort_field": "sort_field",
            "sort_order": "sort_order",
            "has_reference_id": "has_reference",
            "has_reference_type": "has_reference",
            "fields": "fields",
            "filter": "filter",
            "filter_consumers": "filter_consumers",
            "page": "page",
            "size": "per_page",
        }
        for arg_name, param_name in param_arg_map.items():
            if args.get(arg_name) is not None:
                params[param_name] = args[arg_name]

        response = kibana_http_request("GET", "/api/alerting/rules/_find", space_id=space_id, params=params, proxies=proxies)
        rules = response.get("data", []) if isinstance(response, dict) else response

    hr_rows = [rule_to_hr(rule) for rule in rules]
    readable_output = tableToMarkdown(
        "Kibana Rules", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.Rule",
        outputs=rules,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_rule_enable_command(args: Dict[str, Any], proxies) -> CommandResults:
    rule_id = args.get("rule_id")
    if not rule_id:
        raise DemistoException('The "rule_id" argument is required.')
    space_id = args.get("space_id")

    kibana_http_request("POST", f"/api/alerting/rule/{rule_id}/_enable", space_id=space_id, proxies=proxies)

    return CommandResults(readable_output=f"The rule {rule_id} has been successfully enabled.")


def es_kibana_rule_disable_command(args: Dict[str, Any], proxies) -> CommandResults:
    rule_id = args.get("rule_id")
    if not rule_id:
        raise DemistoException('The "rule_id" argument is required.')
    space_id = args.get("space_id")

    kibana_http_request("POST", f"/api/alerting/rule/{rule_id}/_disable", space_id=space_id, proxies=proxies)

    return CommandResults(readable_output=f"The rule {rule_id} has been successfully disabled.")


def build_rule_update_body(args: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the Kibana rule update request body from es-kibana-rule-update arguments."""
    body: Dict[str, Any] = {}

    if args.get("name"):
        body["name"] = args["name"]
    if args.get("schedule_interval"):
        body["schedule"] = {"interval": args["schedule_interval"]}
    if args.get("consumer"):
        body["consumer"] = args["consumer"]
    if args.get("notify_when"):
        body["notifyWhen"] = args["notify_when"]
    if args.get("tags") is not None:
        body["tags"] = argToList(args.get("tags"))
    if args.get("alert_delay_active") is not None:
        body["alertDelay"] = {"active": arg_to_number(args["alert_delay_active"])}

    flapping_enabled = args.get("flapping_enabled")
    flapping_look_back_window = args.get("flapping_look_back_window")
    flapping_status_change_threshold = args.get("flapping_status_change_threshold")

    if flapping_enabled is not None:
        # When the flapping object is provided, look_back_window and status_change_threshold are required by the API.
        if flapping_look_back_window is None:
            raise DemistoException(
                '"flapping_look_back_window" is required when configuring flapping settings.'
            )
        if flapping_status_change_threshold is None:
            raise DemistoException(
                '"flapping_status_change_threshold" is required when configuring flapping settings.'
            )
        flapping: Dict[str, Any] = {
            "look_back_window": arg_to_number(flapping_look_back_window),
            "status_change_threshold": arg_to_number(flapping_status_change_threshold),
        }
        flapping["enabled"] = argToBoolean(flapping_enabled)
        body["flapping"] = flapping

    artifacts: Dict[str, Any] = {}
    if args.get("artifacts_dashboards_id"):
        artifacts["dashboards"] = [{"id": dashboard_id} for dashboard_id in argToList(args["artifacts_dashboards_id"])]
    if args.get("artifacts_investigation_guide_blob"):
        artifacts["investigation_guide"] = {"blob": args["artifacts_investigation_guide_blob"]}
    if artifacts:
        body["artifacts"] = artifacts

    return body


def es_kibana_rule_update_command(args: Dict[str, Any], proxies) -> CommandResults:
    rule_id = args.get("rule_id")
    if not rule_id:
        raise DemistoException('The "rule_id" argument is required.')
    space_id = args.get("space_id")

    entry_id = args.get("entry_id")
    body = get_json_body_from_entry_id(entry_id) if entry_id else build_rule_update_body(args)

    response = kibana_http_request(
        "PUT", f"/api/alerting/rule/{rule_id}", space_id=space_id, json_data=body, proxies=proxies
    )

    hr = {"Rule ID": response.get("id"), "Changed fields": list(body.keys())}
    readable_output = f"The rule {rule_id} has been successfully changed.\n" + tableToMarkdown(
        "", hr, removeNull=True, headers=list(hr.keys())
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.Rule",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_rule_alert_mute_command(args: Dict[str, Any], proxies) -> CommandResults:
    rule_id = args.get("rule_id")
    if not rule_id:
        raise DemistoException('The "rule_id" argument is required.')
    space_id = args.get("space_id")
    alert_id = args.get("alert_id")
    mute_all = argToBoolean(args.get("mute_all", False))

    if mute_all:
        kibana_http_request("POST", f"/api/alerting/rule/{rule_id}/_mute_all", space_id=space_id, proxies=proxies)
        return CommandResults(readable_output="The alerts have been successfully muted.")

    if not alert_id:
        raise DemistoException('The "alert_id" argument is required when "mute_all" is not true.')

    params = {}
    if "validate_alerts_existence" in args:
        params["validate_alerts_existence"] = argToBoolean(args["validate_alerts_existence"])

    kibana_http_request(
        "POST",
        f"/api/alerting/rule/{rule_id}/alert/{alert_id}/_mute",
        space_id=space_id,
        params=params,
        proxies=proxies,
    )
    return CommandResults(readable_output=f"The alerts {alert_id}s have been successfully muted.")


def es_kibana_rule_alert_unmute_command(args: Dict[str, Any], proxies) -> CommandResults:
    rule_id = args.get("rule_id")
    if not rule_id:
        raise DemistoException('The "rule_id" argument is required.')
    space_id = args.get("space_id")
    alert_id = args.get("alert_id")
    unmute_all = argToBoolean(args.get("unmute_all", False))

    if unmute_all:
        kibana_http_request("POST", f"/api/alerting/rule/{rule_id}/_unmute_all", space_id=space_id, proxies=proxies)
        return CommandResults(readable_output="The alerts have been successfully unmuted.")

    if not alert_id:
        raise DemistoException('The "alert_id" argument is required when "unmute_all" is not true.')

    kibana_http_request(
        "POST", f"/api/alerting/rule/{rule_id}/alert/{alert_id}/_unmute", space_id=space_id, proxies=proxies
    )
    return CommandResults(readable_output=f"The alerts {alert_id}s have been successfully unmuted.")


def es_kibana_detection_alert_status_set_command(args: Dict[str, Any], proxies) -> CommandResults:
    status = args.get("status")
    if not status:
        raise DemistoException('The "status" argument is required.')
    space_id = args.get("space_id")

    body: Dict[str, Any] = {"status": status}
    signal_ids = argToList(args.get("signal_ids"))
    if signal_ids:
        body["signal_ids"] = signal_ids
    if args.get("query"):
        body["query"] = args["query"]
    if args.get("reason"):
        body["reason"] = args["reason"]
    if args.get("conflicts"):
        body["conflicts"] = args["conflicts"]

    response = kibana_http_request(
        "POST", "/api/detection_engine/signals/status", space_id=space_id, json_data=body, proxies=proxies
    )

    hr = {"Total": response.get("total"), "Updated": response.get("updated")}
    readable_output = tableToMarkdown(
        "Kibana Detection Alert Status Update", hr, removeNull=True, headers=list(hr.keys())
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.SecurityAlertSetStatus",
        outputs=response,
        raw_response=response,
    )


"""SHARED EXCEPTION ENTRY HELPERS (used by endpoint exception list items and exception list items)"""


def build_exception_entry(args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Builds a single Kibana exception list item "entry" object from the flattened entries_* arguments.

    Returns:
        Optional[Dict[str, Any]]: The entry object, or None if no entries_* arguments were provided.
    """
    field = args.get("entries_field")
    entry_type = args.get("entries_type")
    if not field and not entry_type:
        return None

    entry: Dict[str, Any] = {}
    if field:
        entry["field"] = field
    if entry_type:
        entry["type"] = entry_type
    if args.get("entries_operator"):
        entry["operator"] = args["entries_operator"]

    if entry_type == "list":
        entry["list"] = {"id": args.get("entries_list_id"), "type": args.get("entries_list_type")}
    elif args.get("entries_value") is not None:
        entry["value"] = args["entries_value"]

    return entry


def exception_list_item_to_hr(item: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the human-readable row for a single exception list item (endpoint or regular)."""
    return {
        "ID": item.get("id"),
        "Item ID": item.get("item_id"),
        "List ID": item.get("list_id"),
        "Name": item.get("name"),
        "Description": item.get("description"),
        "Creation date": item.get("created_at"),
    }


"""KIBANA SECURITY ELASTIC ENDPOINT EXCEPTIONS COMMANDS (es-kibana-endpoint-exception-list-item-*)"""


def build_endpoint_exception_item_body(args: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the Kibana endpoint exception list item request body shared by create and update."""
    body: Dict[str, Any] = {"type": "simple"}

    for arg_name, field_name in {
        "description": "description",
        "item_id": "item_id",
        "meta": "meta",
        "name": "name",
    }.items():
        if args.get(arg_name):
            body[field_name] = args[arg_name]

    if args.get("os_types"):
        body["os_types"] = argToList(args.get("os_types"))
    if args.get("tags") is not None:
        body["tags"] = argToList(args.get("tags"))

    entry = build_exception_entry(args)
    if entry:
        body["entries"] = [entry]

    return body


def es_kibana_endpoint_exception_list_item_create_command(args: Dict[str, Any], proxies) -> CommandResults:
    entry_id = args.get("entry_id")
    body = get_json_body_from_entry_id(entry_id) if entry_id else build_endpoint_exception_item_body(args)
    space_id = args.get("space_id")

    response = kibana_http_request("POST", "/api/endpoint_list/items", space_id=space_id, json_data=body, proxies=proxies)

    hr = exception_list_item_to_hr(response)
    readable_output = tableToMarkdown("Kibana Endpoint Exception List Item", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.EndpointExceptionListItem",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_endpoint_exception_list_item_update_command(args: Dict[str, Any], proxies) -> CommandResults:
    entry_id = args.get("entry_id")
    if entry_id:
        body = get_json_body_from_entry_id(entry_id)
    else:
        body = build_endpoint_exception_item_body(args)
        if args.get("exception_list_item_id"):
            body["id"] = args["exception_list_item_id"]
        if args.get("_version"):
            body["_version"] = args["_version"]
        if args.get("entries_value") is not None and "entries" in body:
            body["entries"][0]["value"] = args["entries_value"]
    space_id = args.get("space_id")

    response = kibana_http_request("PUT", "/api/endpoint_list/items", space_id=space_id, json_data=body, proxies=proxies)

    hr = exception_list_item_to_hr(response)
    readable_output = tableToMarkdown("Kibana Endpoint Exception List Item", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.EndpointExceptionListItem",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_endpoint_exception_list_item_delete_command(args: Dict[str, Any], proxies) -> CommandResults:
    item_id = args.get("item_id")
    if not item_id:
        raise DemistoException('Either "id" or "item_id" must be specified.')
    space_id = args.get("space_id")

    kibana_http_request(
        "DELETE", "/api/endpoint_list/items", space_id=space_id, params={"item_id": item_id}, proxies=proxies
    )

    return CommandResults(readable_output=f"The item {item_id} has been successfully deleted.")


def es_kibana_endpoint_exception_list_item_list_command(args: Dict[str, Any], proxies) -> CommandResults:
    space_id = args.get("space_id")
    item_id = args.get("item_id")

    if item_id:
        response = kibana_http_request(
            "GET",
            "/api/endpoint_list/items",
            space_id=space_id,
            params={"item_id": item_id},
            proxies=proxies,
            allow_not_found=True,
        )
        items = [response] if response else []
    else:
        params: Dict[str, Any] = {}
        param_arg_map = {"filter": "filter", "sort_field": "sort_field", "sort_order": "sort_order", "page": "page", "size": "per_page"}
        for arg_name, param_name in param_arg_map.items():
            if args.get(arg_name) is not None:
                params[param_name] = args[arg_name]

        response = kibana_http_request(
            "GET", "/api/endpoint_list/items/_find", space_id=space_id, params=params, proxies=proxies
        )
        items = response.get("data", []) if isinstance(response, dict) else response

    hr_rows = [exception_list_item_to_hr(item) for item in items]
    readable_output = tableToMarkdown(
        "Kibana Endpoint Exception List Items", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.EndpointExceptionListItem",
        outputs=items,
        outputs_key_field="id",
        raw_response=response,
    )


"""KIBANA SECURITY EXCEPTION LISTS COMMANDS (es-kibana-exception-list-*, es-kibana-exception-list-item-*)"""


def exception_list_to_hr(exception_list: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the human-readable row for a single exception list container."""
    return {
        "Exception list ID": exception_list.get("id"),
        "List ID": exception_list.get("list_id"),
        "Name": exception_list.get("name"),
        "Description": exception_list.get("description"),
        "Creation date": exception_list.get("created_at"),
    }


def es_kibana_exception_list_list_command(args: Dict[str, Any], proxies) -> CommandResults:
    space_id = args.get("space_id")
    exception_list_id = args.get("exception_list_id")
    list_id = args.get("list_id")

    if exception_list_id or list_id:
        params = {}
        if exception_list_id:
            params["id"] = exception_list_id
        if list_id:
            params["list_id"] = list_id
        response = kibana_http_request(
            "GET", "/api/exception_lists", space_id=space_id, params=params, proxies=proxies, allow_not_found=True
        )
        lists_ = [response] if response else []
    else:
        params = {}
        param_arg_map = {
            "filter": "filter",
            "namespace_type": "namespace_type",
            "sort_field": "sort_field",
            "sort_order": "sort_order",
            "page": "page",
            "size": "per_page",
        }
        for arg_name, param_name in param_arg_map.items():
            if args.get(arg_name) is not None:
                params[param_name] = args[arg_name]

        response = kibana_http_request(
            "GET", "/api/exception_lists/_find", space_id=space_id, params=params, proxies=proxies
        )
        lists_ = response.get("data", []) if isinstance(response, dict) else response

    hr_rows = [exception_list_to_hr(exc_list) for exc_list in lists_]
    readable_output = tableToMarkdown(
        "Kibana Exception Lists", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ExceptionList",
        outputs=lists_,
        outputs_key_field="id",
        raw_response=response,
    )


def build_exception_list_body(args: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the Kibana exception list container request body shared by create and update."""
    body: Dict[str, Any] = {}

    for arg_name in ("description", "list_id", "meta", "name"):
        if args.get(arg_name):
            body[arg_name] = args[arg_name]

    if args.get("os_types"):
        body["os_types"] = argToList(args.get("os_types"))
    if args.get("tags") is not None:
        body["tags"] = argToList(args.get("tags"))
    if args.get("namespace_type"):
        body["namespace_type"] = args["namespace_type"]
    if args.get("type"):
        body["type"] = args["type"]
    if args.get("version") is not None:
        body["version"] = arg_to_number(args["version"])

    return body


def es_kibana_exception_list_create_command(args: Dict[str, Any], proxies) -> CommandResults:
    entry_id = args.get("entry_id")
    if entry_id:
        body = get_json_body_from_entry_id(entry_id)
    else:
        exc_type = args.get("type")
        if not exc_type:
            raise DemistoException('The "type" argument is required.')
        body = build_exception_list_body(args)
    space_id = args.get("space_id")

    response = kibana_http_request("POST", "/api/exception_lists", space_id=space_id, json_data=body, proxies=proxies)

    hr = exception_list_to_hr(response)
    readable_output = tableToMarkdown("Kibana Exception List", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ExceptionList",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_exception_list_update_command(args: Dict[str, Any], proxies) -> CommandResults:
    if not args.get("description"):
        raise DemistoException('The "description" argument is required.')
    if not args.get("name"):
        raise DemistoException('The "name" argument is required.')
    if not args.get("type"):
        raise DemistoException('The "type" argument is required.')
    space_id = args.get("space_id")

    body = build_exception_list_body(args)
    if args.get("exception_list_id"):
        body["id"] = args["exception_list_id"]
    if args.get("_version"):
        body["_version"] = args["_version"]

    response = kibana_http_request("PUT", "/api/exception_lists", space_id=space_id, json_data=body, proxies=proxies)

    hr = exception_list_to_hr(response)
    readable_output = tableToMarkdown("Kibana Exception List", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ExceptionList",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_exception_list_delete_command(args: Dict[str, Any], proxies) -> CommandResults:
    exception_list_id = args.get("exception_list_id")
    list_id = args.get("list_id")
    if not exception_list_id and not list_id:
        raise DemistoException('Either "exception_list_id" or "list_id" must be specified.')
    space_id = args.get("space_id")

    params = {}
    if exception_list_id:
        params["id"] = exception_list_id
    if list_id:
        params["list_id"] = list_id
    if args.get("namespace_type"):
        params["namespace_type"] = args["namespace_type"]

    kibana_http_request("DELETE", "/api/exception_lists", space_id=space_id, params=params, proxies=proxies)

    identifier = exception_list_id or list_id
    return CommandResults(readable_output=f"The exception list {identifier} has been successfully deleted.")


def es_kibana_exception_list_item_list_command(args: Dict[str, Any], proxies) -> CommandResults:
    space_id = args.get("space_id")
    exception_list_item_id = args.get("exception_list_item_id")
    item_id = args.get("item_id")

    if exception_list_item_id or item_id:
        params = {}
        if exception_list_item_id:
            params["id"] = exception_list_item_id
        if item_id:
            params["item_id"] = item_id
        response = kibana_http_request(
            "GET", "/api/exception_lists/items", space_id=space_id, params=params, proxies=proxies, allow_not_found=True
        )
        items = [response] if response else []
    else:
        params = {}
        param_arg_map = {
            "exception_list_id": "list_id",
            "filter": "filter",
            "namespace_type": "namespace_type",
            "search": "search",
            "sort_field": "sort_field",
            "sort_order": "sort_order",
            "page": "page",
            "size": "per_page",
        }
        for arg_name, param_name in param_arg_map.items():
            if args.get(arg_name) is not None:
                params[param_name] = args[arg_name]

        response = kibana_http_request(
            "GET", "/api/exception_lists/items/_find", space_id=space_id, params=params, proxies=proxies
        )
        items = response.get("data", []) if isinstance(response, dict) else response

    hr_rows = [exception_list_item_to_hr(item) for item in items]
    readable_output = tableToMarkdown(
        "Kibana Exception List Items", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ExceptionListItem",
        outputs=items,
        outputs_key_field="id",
        raw_response=response,
    )


def build_exception_list_item_body(args: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the Kibana exception list item request body shared by create and update."""
    body: Dict[str, Any] = {}

    for arg_name in ("comment", "description", "expire_time", "item_id", "meta", "name", "list_id"):
        if args.get(arg_name):
            body[arg_name] = args[arg_name]

    if args.get("namespace_type"):
        body["namespace_type"] = args["namespace_type"]
    if args.get("type"):
        body["type"] = args["type"]
    if args.get("os_types"):
        body["os_types"] = argToList(args.get("os_types"))
    if args.get("tags") is not None:
        body["tags"] = argToList(args.get("tags"))

    entry = build_exception_entry(args)
    if entry:
        body["entries"] = [entry]

    return body


def es_kibana_exception_list_item_create_command(args: Dict[str, Any], proxies) -> CommandResults:
    entry_id = args.get("entry_id")
    body = get_json_body_from_entry_id(entry_id) if entry_id else build_exception_list_item_body(args)
    space_id = args.get("space_id")

    response = kibana_http_request("POST", "/api/exception_lists/items", space_id=space_id, json_data=body, proxies=proxies)

    hr = exception_list_item_to_hr(response)
    readable_output = tableToMarkdown("Kibana Exception List Item", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ExceptionListItem",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_exception_item_list_update_command(args: Dict[str, Any], proxies) -> CommandResults:
    entry_id = args.get("entry_id")
    if entry_id:
        body = get_json_body_from_entry_id(entry_id)
    else:
        body = build_exception_list_item_body(args)
        if args.get("exception_list_item_id"):
            body["id"] = args["exception_list_item_id"]
        if args.get("_version"):
            body["_version"] = args["_version"]
        if args.get("comment_id"):
            body["comment_id"] = args["comment_id"]
    space_id = args.get("space_id")

    response = kibana_http_request("PUT", "/api/exception_lists/items", space_id=space_id, json_data=body, proxies=proxies)

    hr = {
        "Exception list item ID": response.get("id"),
        "Item Id": response.get("item_id"),
        "List ID": response.get("list_id"),
        "Name": response.get("name"),
        "Description": response.get("description"),
        "Update date": response.get("updated_at"),
    }
    readable_output = tableToMarkdown("Kibana Exception List Item Updated", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ExceptionListItem",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_exception_list_item_delete_command(args: Dict[str, Any], proxies) -> CommandResults:
    exception_list_item_id = args.get("exception_list_item_id")
    item_id = args.get("item_id")
    if not exception_list_item_id and not item_id:
        raise DemistoException('Either "exception_list_item_id" or "item_id" must be specified.')
    space_id = args.get("space_id")

    params = {}
    if exception_list_item_id:
        params["id"] = exception_list_item_id
    if item_id:
        params["item_id"] = item_id
    if args.get("namespace_type"):
        params["namespace_type"] = args["namespace_type"]

    kibana_http_request("DELETE", "/api/exception_lists/items", space_id=space_id, params=params, proxies=proxies)

    identifier = exception_list_item_id or item_id
    return CommandResults(readable_output=f"The exception list item {identifier} has been successfully deleted.")


"""KIBANA VALUE LISTS COMMANDS (es-kibana-value-list*)"""


def value_list_to_hr(value_list: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the human-readable row for a single value list container."""
    return {
        "Value list ID": value_list.get("id"),
        "Name": value_list.get("name"),
        "Description": value_list.get("description"),
        "Creation date": value_list.get("created_at"),
    }


def value_list_item_to_hr(item: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the human-readable row for a single value list item."""
    return {
        "Value list item ID": item.get("id"),
        "Value list ID": item.get("list_id"),
        "Name": item.get("name"),
        "Description": item.get("description"),
        "Creation date": item.get("created_at"),
    }


def es_kibana_value_lists_list_command(args: Dict[str, Any], proxies) -> CommandResults:
    space_id = args.get("space_id")
    value_list_id = args.get("value_list_id")

    if value_list_id:
        response = kibana_http_request(
            "GET", "/api/lists", space_id=space_id, params={"id": value_list_id}, proxies=proxies, allow_not_found=True
        )
        lists_ = [response] if response else []
    else:
        params: Dict[str, Any] = {}
        param_arg_map = {
            "filter": "filter",
            "cursor": "cursor",
            "sort_field": "sort_field",
            "sort_order": "sort_order",
            "page": "page",
            "size": "per_page",
        }
        for arg_name, param_name in param_arg_map.items():
            if args.get(arg_name) is not None:
                params[param_name] = args[arg_name]

        response = kibana_http_request("GET", "/api/lists/_find", space_id=space_id, params=params, proxies=proxies)
        lists_ = response.get("data", []) if isinstance(response, dict) else response

    hr_rows = [value_list_to_hr(value_list) for value_list in lists_]
    readable_output = tableToMarkdown(
        "Kibana Value Lists", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ValueList",
        outputs=lists_,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_value_list_item_get_command(args: Dict[str, Any], proxies) -> CommandResults:
    space_id = args.get("space_id")
    value_list_item_id = args.get("value_list_item_id")
    value = args.get("value")
    value_list_id = args.get("value_list_id")

    if value_list_item_id or (value and not value_list_id):
        params = {}
        if value_list_item_id:
            params["id"] = value_list_item_id
        if value:
            params["value"] = value
        response = kibana_http_request(
            "GET", "/api/lists/items", space_id=space_id, params=params, proxies=proxies, allow_not_found=True
        )
        items = [response] if response else []
    else:
        params = {}
        param_arg_map = {
            "value_list_id": "list_id",
            "value": "value",
            "filter": "filter",
            "cursor": "cursor",
            "sort_field": "sort_field",
            "sort_order": "sort_order",
            "page": "page",
            "size": "per_page",
        }
        for arg_name, param_name in param_arg_map.items():
            if args.get(arg_name) is not None:
                params[param_name] = args[arg_name]

        response = kibana_http_request("GET", "/api/lists/items/_find", space_id=space_id, params=params, proxies=proxies)
        items = response.get("data", []) if isinstance(response, dict) else response

    hr_rows = [value_list_item_to_hr(item) for item in items]
    readable_output = tableToMarkdown(
        "Kibana Value List Items", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ValueListItem",
        outputs=items,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_value_list_item_create_command(args: Dict[str, Any], proxies) -> CommandResults:
    value_list_id = args.get("value_list_id")
    value = args.get("value")
    if not value_list_id:
        raise DemistoException('The "value_list_id" argument is required.')
    if not value:
        raise DemistoException('The "value" argument is required.')
    space_id = args.get("space_id")

    body: Dict[str, Any] = {"list_id": value_list_id, "value": value}
    if args.get("meta"):
        body["meta"] = json.loads(args["meta"]) if isinstance(args["meta"], str) else args["meta"]

    params = {}
    if args.get("refresh") is not None:
        params["refresh"] = args["refresh"]

    response = kibana_http_request(
        "POST", "/api/lists/items", space_id=space_id, json_data=body, params=params, proxies=proxies
    )

    hr = value_list_item_to_hr(response)
    readable_output = tableToMarkdown("Kibana Value List Item", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ValueListItem",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_value_list_item_update_command(args: Dict[str, Any], proxies) -> CommandResults:
    value_list_item_id = args.get("value_list_item_id")
    value = args.get("value")
    if not value_list_item_id:
        raise DemistoException('The "value_list_item_id" argument is required.')
    if not value:
        raise DemistoException('The "value" argument is required.')
    space_id = args.get("space_id")

    body: Dict[str, Any] = {"id": value_list_item_id, "value": value}
    if args.get("meta"):
        body["meta"] = json.loads(args["meta"]) if isinstance(args["meta"], str) else args["meta"]
    if args.get("_version"):
        body["_version"] = args["_version"]

    response = kibana_http_request("PUT", "/api/lists/items", space_id=space_id, json_data=body, proxies=proxies)

    hr = value_list_item_to_hr(response)
    readable_output = tableToMarkdown("Kibana Value List Item", hr, removeNull=True, headers=list(hr.keys()))
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ValueListItem",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def es_kibana_value_list_item_delete_command(args: Dict[str, Any], proxies) -> CommandResults:
    value_list_item_id = args.get("value_list_item_id")
    value_list_id = args.get("value_list_id")
    value = args.get("value")
    if not value_list_item_id and not (value_list_id and value):
        raise DemistoException(
            'Either "value_list_item_id" or both "value_list_id" and "value" must be specified.'
        )
    space_id = args.get("space_id")

    params = {}
    if value_list_item_id:
        params["id"] = value_list_item_id
    if value_list_id:
        params["list_id"] = value_list_id
    if value:
        params["value"] = value
    if args.get("refresh") is not None:
        params["refresh"] = args["refresh"]

    kibana_http_request("DELETE", "/api/lists/items", space_id=space_id, params=params, proxies=proxies)

    identifier = value_list_item_id or value
    return CommandResults(readable_output=f"The value list item {identifier} has been successfully deleted.")


def es_kibana_value_list_item_export_command(args: Dict[str, Any], proxies) -> list:
    value_list_id = args.get("value_list_id")
    space_id = args.get("space_id")

    params = {}
    if value_list_id:
        params["list_id"] = value_list_id

    response = kibana_http_request(
        "POST", "/api/lists/items/_export", space_id=space_id, params=params, proxies=proxies
    )

    file_content = response if isinstance(response, str) else json.dumps(response)
    file_name = f"{value_list_id or 'value-list'}-items.txt"
    file_result = fileResult(file_name, file_content)
    return [CommandResults(readable_output="Successful response", raw_response=response), file_result]


def es_kibana_value_list_item_import_command(args: Dict[str, Any], proxies) -> CommandResults:
    entry_id = args.get("entry_id")
    if not entry_id:
        raise DemistoException('The "entry_id" argument is required.')
    space_id = args.get("space_id")

    try:
        file_info = demisto.getFilePath(entry_id)
    except Exception as e:
        raise DemistoException(f"Failed to retrieve file info for entry_id={entry_id}: {e}")
    file_path = file_info.get("path") if file_info else None
    if not file_path:
        raise DemistoException(f"Could not resolve file path for entry_id={entry_id}")

    params: Dict[str, Any] = {}
    if args.get("value_list_id"):
        params["list_id"] = args["value_list_id"]
    if args.get("type"):
        params["type"] = args["type"]
    if args.get("refresh") is not None:
        params["refresh"] = args["refresh"]

    with open(file_path, "rb") as f:
        files = {"file": (file_info.get("name"), f)}
        response = kibana_http_request(
            "POST", "/api/lists/items/_import", space_id=space_id, params=params, files=files, proxies=proxies
        )

    items = response if isinstance(response, list) else [response]
    hr_rows = [value_list_item_to_hr(item) for item in items]
    readable_output = tableToMarkdown(
        "Kibana Value List Items Imported", hr_rows, removeNull=True, headers=list(hr_rows[0].keys()) if hr_rows else None
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Elasticsearch.Kibana.ValueListItem",
        outputs=items,
        outputs_key_field="id",
        raw_response=response,
    )


def main():  # pragma: no cover
    proxies = handle_proxy()
    proxies = proxies if proxies else None
    args = demisto.args()
    try:
        LOG(f"command is {demisto.command()}")
        if demisto.command() == "test-module":
            return_results(test_func(proxies))
        elif demisto.command() == "fetch-incidents":
            fetch_incidents(proxies)
        elif demisto.command() in ["search", "es-search"]:
            search_command(proxies)
        elif demisto.command() == "get-mapping-fields":
            return_results(get_mapping_fields_command())
        elif demisto.command() == "es-eql-search":
            return_results(search_eql_command(args, proxies))
        elif demisto.command() == "es-esql-search":
            return_results(search_esql_command(args, proxies))
        elif demisto.command() == "es-index":
            return_results(index_document_command(args, proxies))
        elif demisto.command() == "es-integration-health-check":
            return_results(integration_health_check(proxies))
        elif demisto.command() == "es-get-indices-statistics":
            return_results(get_indices_statistics_command(args, proxies))
        elif demisto.command() == "es-kibana-case-create":
            return_results(es_kibana_case_create_command(args, proxies))
        elif demisto.command() == "es-kibana-case-update":
            return_results(es_kibana_case_update_command(args, proxies))
        elif demisto.command() == "es-kibana-case-delete":
            return_results(es_kibana_case_delete_command(args, proxies))
        elif demisto.command() == "es-kibana-case-list":
            return_results(es_kibana_case_list_command(args, proxies))
        elif demisto.command() == "es-kibana-case-alerts-list":
            return_results(es_kibana_case_alerts_list_command(args, proxies))
        elif demisto.command() == "es-kibana-case-comment-add":
            return_results(es_kibana_case_comment_add_command(args, proxies))
        elif demisto.command() == "es-kibana-case-comment-update":
            return_results(es_kibana_case_comment_update_command(args, proxies))
        elif demisto.command() == "es-kibana-case-comment-delete":
            return_results(es_kibana_case_comment_delete_command(args, proxies))
        elif demisto.command() == "es-kibana-case-file-attach":
            return_results(es_kibana_case_file_attach_command(args, proxies))
        elif demisto.command() == "es-kibana-alerting-health-get":
            return_results(es_kibana_alerting_health_get_command(args, proxies))
        elif demisto.command() == "es-kibana-rule-types-list":
            return_results(es_kibana_rule_types_list_command(args, proxies))
        elif demisto.command() == "es-kibana-rule-list":
            return_results(es_kibana_rule_list_command(args, proxies))
        elif demisto.command() == "es-kibana-rule-enable":
            return_results(es_kibana_rule_enable_command(args, proxies))
        elif demisto.command() == "es-kibana-rule-disable":
            return_results(es_kibana_rule_disable_command(args, proxies))
        elif demisto.command() == "es-kibana-rule-update":
            return_results(es_kibana_rule_update_command(args, proxies))
        elif demisto.command() == "es-kibana-rule-alert-mute":
            return_results(es_kibana_rule_alert_mute_command(args, proxies))
        elif demisto.command() == "es-kibana-rule-alert-unmute":
            return_results(es_kibana_rule_alert_unmute_command(args, proxies))
        elif demisto.command() == "es-kibana-detection-alert-status-set":
            return_results(es_kibana_detection_alert_status_set_command(args, proxies))
        elif demisto.command() == "es-kibana-endpoint-exception-list-item-create":
            return_results(es_kibana_endpoint_exception_list_item_create_command(args, proxies))
        elif demisto.command() == "es-kibana-endpoint-exception-list-item-update":
            return_results(es_kibana_endpoint_exception_list_item_update_command(args, proxies))
        elif demisto.command() == "es-kibana-endpoint-exception-list-item-delete":
            return_results(es_kibana_endpoint_exception_list_item_delete_command(args, proxies))
        elif demisto.command() == "es-kibana-endpoint-exception-list-item-list":
            return_results(es_kibana_endpoint_exception_list_item_list_command(args, proxies))
        elif demisto.command() == "es-kibana-exception-list-list":
            return_results(es_kibana_exception_list_list_command(args, proxies))
        elif demisto.command() == "es-kibana-exception-list-create":
            return_results(es_kibana_exception_list_create_command(args, proxies))
        elif demisto.command() == "es-kibana-exception-list-update":
            return_results(es_kibana_exception_list_update_command(args, proxies))
        elif demisto.command() == "es-kibana-exception-list-delete":
            return_results(es_kibana_exception_list_delete_command(args, proxies))
        elif demisto.command() == "es-kibana-exception-list-item-list":
            return_results(es_kibana_exception_list_item_list_command(args, proxies))
        elif demisto.command() == "es-kibana-exception-list-item-create":
            return_results(es_kibana_exception_list_item_create_command(args, proxies))
        elif demisto.command() == "es-kibana-exception-item-list-update":
            return_results(es_kibana_exception_item_list_update_command(args, proxies))
        elif demisto.command() == "es-kibana-exception-list-item-delete":
            return_results(es_kibana_exception_list_item_delete_command(args, proxies))
        elif demisto.command() == "es-kibana-value-lists-list":
            return_results(es_kibana_value_lists_list_command(args, proxies))
        elif demisto.command() == "es-kibana-value-list-item-get":
            return_results(es_kibana_value_list_item_get_command(args, proxies))
        elif demisto.command() == "es-kibana-value-list-item-create":
            return_results(es_kibana_value_list_item_create_command(args, proxies))
        elif demisto.command() == "es-kibana-value-list-item-update":
            return_results(es_kibana_value_list_item_update_command(args, proxies))
        elif demisto.command() == "es-kibana-value-list-item-delete":
            return_results(es_kibana_value_list_item_delete_command(args, proxies))
        elif demisto.command() == "es-kibana-value-list-item-export":
            return_results(es_kibana_value_list_item_export_command(args, proxies))
        elif demisto.command() == "es-kibana-value-list-item-import":
            return_results(es_kibana_value_list_item_import_command(args, proxies))

    except Exception as e:
        if "The client noticed that the server is not a supported distribution of Elasticsearch" in str(e):
            return_error(
                f"Failed executing {demisto.command()}. Seems that the client does not support the server's "
                f"distribution, Please try using the Open Search client in the instance configuration."
                f"\nError message: {e!s}",
                error=str(e),
            )
        if "failed to parse date field" in str(e):
            return_error(
                f"Failed to execute the {demisto.command()} command. Make sure the `Time field type` is correctly set.",
                error=str(e),
            )
        return_error(f"Failed executing {demisto.command()}.\nError message: {e}", error=str(e))


if __name__ in ("__main__", "builtin", "builtins"):
    main()
