import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""IMPORTS"""
import re
import requests
import json
import warnings
from datetime import datetime
from requests.auth import HTTPBasicAuth
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
        API_KEY_ID = USERNAME[len(API_KEY_PREFIX):]
        API_KEY = (API_KEY_ID, PASSWORD)

elif AUTH_TYPE == API_KEY_AUTH:
    API_KEY = (API_KEY_ID, API_KEY_SECRET)

ELASTICSEARCH_V8 = "Elasticsearch_v8"
ELASTICSEARCH_V9 = "Elasticsearch_v9"
OPEN_SEARCH = "OpenSearch"
ELASTIC_SEARCH_CLIENT = demisto.params().get("client_type")
if ELASTIC_SEARCH_CLIENT == OPEN_SEARCH:
    from opensearch_dsl import Search
    from opensearch_dsl.query import QueryString
    from opensearchpy import NotFoundError, RequestsHttpConnection
    from opensearchpy import OpenSearch as Elasticsearch
elif ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, ELASTICSEARCH_V9]:
    from elastic_transport import RequestsHttpNode
    from elasticsearch import Elasticsearch, NotFoundError  # type: ignore[assignment]
    from elasticsearch_dsl import Search
    from elasticsearch_dsl.query import QueryString
else:  # Elasticsearch (<= v7)
    from elasticsearch7 import Elasticsearch, NotFoundError, RequestsHttpConnection  # type: ignore[assignment,misc]
    from elasticsearch_dsl import Search
    from elasticsearch_dsl.query import QueryString

ES_DEFAULT_DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss.SSSSSS"
PYTHON_DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
SERVER = PARAMS.get("url", "").rstrip("/")
PROXY = PARAMS.get("proxy")
KIBANA_SERVER = PARAMS.get("kibana_url", "").rstrip("/")

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
        search = Search(using=es, index=index).query(que)[base_page: base_page + size]
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


def incident_label_maker(source):
    """Creates labels for the created incident.

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
        if source is not None:
            time_field_value = get_value_by_dot_notation(source, str(TIME_FIELD))

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
        if source is not None:
            time_field_value = get_value_by_dot_notation(source, str(TIME_FIELD))
            if time_field_value is not None:
                hit_date = parse(str(time_field_value))
                hit_timestamp = int(hit_date.timestamp() * 1000)

                if hit_timestamp > last_fetch_timestamp:
                    last_fetch = hit_date
                    last_fetch_timestamp = hit_timestamp

                # avoid duplication due to weak time query
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
                        inc["labels"] = incident_label_maker(hit.get("_source"))

                    incidents.append(inc)

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
        query = QueryString(query=FETCH_QUERY + " AND " + TIME_FIELD + ":*")
        # Elastic search can use epoch timestamps (in milliseconds) as date representation regardless of date format.
        search = Search(using=es, index=FETCH_INDEX).filter(time_range_dict)
        search = search.sort({TIME_FIELD: {"order": "asc"}})[0:FETCH_SIZE].query(query)

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
            response = es.index(index=index, id=doc_id, document=doc)  # pylint: disable=E1123,E1120
        else:
            response = es.index(index=index, document=doc)  # pylint: disable=E1123,E1120

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


def kibana_find_cases(args, proxies):
    '''
    Returns information on the cases in Kibana.
    API reference: https://www.elastic.co/docs/api/doc/kibana/operation/operation-findcasesdefaultspace
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    status = demisto.args().get("status")
    severity = demisto.args().get("severity")
    from_time = demisto.args().get("from_time")

    url = f"{KIBANA_SERVER}/api/cases/_find"

    query_params = {
        'status': status,
        'severity': severity,
        'from': from_time
    }

    try:
        response = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD), params=query_params, headers=headers, verify=False)
        json_data = response.json()["cases"]

        # output results to markdown table
        md = tableToMarkdown("Kibana Cases", json_data, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Cases",
            outputs=json_data)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error finding cases: {e}"


def kibana_get_case_information(args, proxies):
    '''
    Retrieve information for a specific case in Kibana.
    API reference: https://www.elastic.co/docs/api/doc/kibana/operation/operation-getcasedefaultspace
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    case_id = demisto.args().get("case_id")

    url = f"{KIBANA_SERVER}/api/cases/{case_id}"

    try:
        response = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD), headers=headers, verify=False)
        json_data = response.json()

        # output results to markdown table
        md = tableToMarkdown("Kibana Case Info", json_data, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Case.Info",
            outputs=json_data)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error finding case information: {e}"


def kibana_find_alerts_for_case(args, proxies):
    '''
    Returns information on the alerts of a case in Kibana.
    API reference: https://www.elastic.co/docs/api/doc/kibana/operation/operation-getcasealertsdefaultspace
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    case_id = demisto.args().get("case_id")

    url = f"{KIBANA_SERVER}/api/cases/{case_id}/alerts"

    query_params = {
        'caseId': case_id,
    }

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        json_data = response.json()

        # output results to markdown table
        md = tableToMarkdown("Kibana Alerts For Case", json_data, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Alerts.For.Case",
            outputs=json_data)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error finding alerts for case {case_id}: {e}"


def kibana_find_case_comments(args, proxies):
    '''
    Get list of comments for a case in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-findcasecommentsdefaultspace
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    case_id = demisto.args().get("case_id")

    url = f"{KIBANA_SERVER}/api/cases/{case_id}/comments/_find"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        response = response.json()["comments"]

        # output results to markdown table
        md = tableToMarkdown("Kibana Case Comments", response, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Case.Comments",
            outputs=response)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error locating case comments: {e}"


def kibana_find_user_spaces(args, proxies):
    '''
    Get list of user spaces in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-spaces-space
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    url = f"{KIBANA_SERVER}/api/spaces/space"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        response = response.json()

        # output results to markdown table
        md = tableToMarkdown("Kibana User Spaces", response, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.User.Spaces",
            outputs=response)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error finding Kibana user spaces: {e}"


def kibana_search_rule_details(args, proxies):
    '''
    Retrieve details about detection rule in Kibana based on input KQL filter.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-alerting-rules-find
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    kql_query = demisto.args().get("kql_query")

    params = {
        'filter': kql_query
    }

    url = f"{KIBANA_SERVER}/api/alerting/rules/_find"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), params=params, headers=headers, verify=False)
        json_data = response.json()["data"]

        # output results to markdown table
        md = tableToMarkdown("Kibana Rule Details", json_data, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Rule.Details",
            outputs=json_data)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error searching rule details: {e}"


def kibana_delete_rule(args, proxies):
    '''
    Delete rule in Kibana based on input rule ID.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-delete-alerting-rule-id
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    rule_id = demisto.args().get("rule_id")

    url = f"{KIBANA_SERVER}/api/alerting/rule/{rule_id}"

    try:
        response = requests.delete(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        return f"Successfully deleted rule with ID of {rule_id}"

    except requests.exceptions.RequestException as e:
        return f"Error deleting detection rule: {e}"


def kibana_delete_case(args, proxies):
    '''
    Delete case in Kibana based on input case ID.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-deletecasedefaultspace
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    case_id = demisto.args().get("case_id")
    case_id = "[\"" + case_id + "\"]"
    case_list = []
    case_list.append(case_id)

    params = {
        'ids': case_list
    }

    url = f"{KIBANA_SERVER}/api/cases"

    try:
        response = requests.delete(url, auth=(USERNAME, PASSWORD), headers=headers, params=params, verify=False)
        return f"Successfully deleted case with ID of {case_id}"

    except requests.exceptions.RequestException as e:
        return f"Error deleting case in Kibana: {e}"


def kibana_update_case_status(args, proxies):
    '''
    Update status of input case in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-updatecasedefaultspace
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    case_id = demisto.args().get("case_id")
    status = demisto.args().get("status")
    version = demisto.args().get("version_id")

    url = f"{KIBANA_SERVER}/api/cases"

    body = {
        'cases': [{
            'id': case_id,
            'status': status,
            'version': version
        }]
    }

    try:
        response = requests.patch(url, auth=(USERNAME, PASSWORD), headers=headers, json=body, verify=False)
        response = response.json()

        # output results to markdown table
        md = tableToMarkdown("Kibana Updated Case Status", response, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Updated.Case.Status",
            outputs=response)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error updating case status: {e}"


def kibana_update_alert_status(args, proxies):
    '''
    Update status of input alert in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-setalertsstatus
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    alert_id = demisto.args().get("alert_id")
    status = demisto.args().get("status")

    url = f"{KIBANA_SERVER}/api/detection_engine/signals/status"

    data_params = {
        'status': status,
        'signal_ids': [
            alert_id,
        ],
    }

    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, json=data_params, verify=False)
        return f"Updated alert ID {alert_id} to status of {status}"

    except requests.exceptions.RequestException as e:
        return f"Error updating alert status: {e}"


def kibana_get_user_list(args, proxies):
    '''
    Search for a list of all users and UIDs in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-query-user
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    es = elasticsearch_builder(proxies)

    try:
        all_users = es.security.query_user(
            with_profile_uid=True, size=100)
        all_users = all_users.body['users']

        # output results to markdown table
        md = tableToMarkdown("Kibana User List", all_users, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.User.List",
            outputs=all_users)

        return result

    except Exception as e:
        return f"Error querying all users: {e}"


def kibana_get_user_by_email(args, proxies):
    '''
    Search for a single user's UID in Kibana by email address filter.
    Reference - https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-query-user
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    email_wildcard = demisto.args().get("email_wildcard")

    es = elasticsearch_builder(proxies)

    query_body = {
        "query": {
            "wildcard": {
                "email": {
                    "value": email_wildcard,
                    "case_insensitive": True
                }
            }
        }
    }

    try:
        user_data = es.security.query_user(with_profile_uid=True, body=query_body)

        user_data = user_data['users']

        # output results to markdown table
        md = tableToMarkdown("Kibana User Data", user_data, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.User.Data",
            outputs=user_data)

        return result

    except Exception as e:
        return f"Error querying all users: {e}"


def kibana_assign_alert_user(args, proxies):
    '''
    Assign user to input alert in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-setalertassignees
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    alert_id = demisto.args().get("alert_id")
    user_id = demisto.args().get("user_id")

    url = f"{KIBANA_SERVER}/api/detection_engine/signals/assignees"

    json_data = {
        'ids': [
            alert_id,
        ],
        'assignees': {
            'add': [
                user_id,
            ],
            'remove': [],
        },
    }

    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, json=json_data, verify=False)
        return f"Assigned user ID {user_id} to alert {alert_id}"

    except requests.exceptions.RequestException as e:
        return f"Error assigning alert to user: {e}"


def kibana_list_detection_alerts(args, proxies):
    '''
    List detection alerts in Kibana matching a status filter.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-searchalerts
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    alert_status = demisto.args().get("alert_status")

    url = f"{KIBANA_SERVER}/api/detection_engine/signals/search"

    json_data = {
        'query': {
            'bool': {
                'filter': [
                    {
                        'bool': {
                            'must': [],
                            'filter': [
                                {
                                    'match_phrase': {
                                        'kibana.alert.workflow_status': alert_status,
                                    },
                                },
                            ],
                        },
                    },
                ],
            },
        },
        'runtime_mappings': {},
    }

    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, json=json_data, verify=False)
        result_json = response.json()
        result_json = result_json.get('hits')  # dict
        result_list = result_json.get('hits')  # list
        result_list_final = []

        # append each _source dict in list of dicts to a final results list
        for item in result_list:
            result_list_final.append(item.get('_source'))

        # output results to markdown table
        md = tableToMarkdown("Kibana Detection Alerts", result_list_final, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Detection.Alerts",
            outputs=result_list_final)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error listing detection alerts: {e}"


def kibana_add_alert_note(args, proxies):
    '''
    Add note to detection alerts in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-persistnoteroute
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    event_id = demisto.args().get("alert_id")
    note = demisto.args().get("note")

    url = f"{KIBANA_SERVER}/api/note"

    json_data = {
        'note': {
            'eventId': event_id,
            'note': note,
            'timelineId': '',
        },
    }

    try:
        response = requests.patch(url, auth=(USERNAME, PASSWORD), headers=headers, json=json_data, verify=False)
        return f"Added note {note} to alert {event_id}"

    except requests.exceptions.RequestException as e:
        return f"Error adding note to alert: {e}"


def kibana_add_case_comment(args, proxies):
    '''
    Add comment to case in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-addcasecommentdefaultspace
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    case_id = demisto.args().get("case_id")
    case_owner = demisto.args().get("case_owner")
    comment = demisto.args().get("comment")

    url = f"{KIBANA_SERVER}/api/cases/{case_id}/comments"

    json_data = {
        'type': 'user',
        'owner': case_owner,
        'comment': comment,
    }

    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, json=json_data, verify=False)
        updated_at = response.json()["updated_at"]
        return f"Case comment updated at {updated_at}"

    except requests.exceptions.RequestException as e:
        return f"Error adding comment to case: {e}"


def kibana_get_alerting_health(args, proxies):
    '''
    Get alerting framework health in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-getalertinghealth
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    url = f"{KIBANA_SERVER}/api/alerting/_health"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        result_json = response.json()

        # output results to markdown table
        md = tableToMarkdown("Alerting Framework Health", result_json, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Alerting.Framework.Health",
            outputs=result_json)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error checking alerting framework health: {e}"


def kibana_disable_alert_rule(args, proxies):
    '''
    Used to disable a rule used for detection alerting. Clears all associated alerts from active alerts page.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-alerting-rule-id-disable
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    rule_id = demisto.args().get("rule_id")

    url = f"{KIBANA_SERVER}/api/alerting/rule/{rule_id}/_disable"

    json_data = {
        'untrack': True,
    }

    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, json=json_data, verify=False)
        print("Successfully disabled rule with ID of " + rule_id)

    except requests.exceptions.RequestException as e:
        return f"Error disabling alert rule: {e}"


def kibana_enable_alert_rule(args, proxies):
    '''
    Used to enable a rule used for detection alerting.
    Reference -https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-alerting-rule-id-enable
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    rule_id = demisto.args().get("rule_id")

    url = f"{KIBANA_SERVER}/api/alerting/rule/{rule_id}/_enable"

    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        print("Successfully enabled rule with ID of " + rule_id)

    except requests.exceptions.RequestException as e:
        return f"Error enabling alert rule: {e}"


def kibana_get_exception_lists(args, proxies):
    '''
    Used to get a list of all exception list containers.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-findexceptionlists
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    url = f"{KIBANA_SERVER}/api/exception_lists/_find"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        response = response.json()["data"]

        # output results to markdown table
        md = tableToMarkdown("Kibana Exception Lists", response, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Exception.Lists",
            outputs=response)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error retrieving exception lists: {e}"


def kibana_create_value_list(args, proxies):
    '''
    Used to create a value list in Kibana Detection Rules menu.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-createlist
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    description = demisto.args().get("description")
    list_id = demisto.args().get("list_id")
    name = demisto.args().get("name")
    data_type = demisto.args().get("data_type")

    json_data = {
        'id': list_id,
        'name': name,
        'type': data_type,
        'description': description,
    }

    url = f"{KIBANA_SERVER}/api/lists"

    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, json=json_data, verify=False)
        return response.json()

    except requests.exceptions.RequestException as e:
        return f"Error creating value list in Kibana: {e}"


def kibana_get_value_lists(args, proxies):
    '''
    Used to find all value lists in Kibana Detection Rules menu.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-findlists
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    url = f"{KIBANA_SERVER}/api/lists/_find"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        result_json = response.json()["data"]

        # output results to markdown table
        md = tableToMarkdown("Alerting Value Lists", result_json, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Alerting.Value.Lists",
            outputs=result_json)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error retrieving Kibana value lists: {e}"


def kibana_import_value_list_items(args, proxies):
    '''
    Used to import value list items from a TXT file.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-importlistitems
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    list_id = demisto.args().get("list_id")
    file_content = demisto.args().get("file_content")

    json_data = {
        'list_id': list_id,
    }

    files = {
        'file': ("value_list.txt", file_content, "text/plain")
    }

    url = f"{KIBANA_SERVER}/api/lists/items/_import"

    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, params=json_data, files=files, verify=False)
        return response.json()

    except requests.exceptions.RequestException as e:
        return f"Error connecting to Kibana: {e}"


def kibana_create_value_list_item(args, proxies):
    '''
    Used to create a value list item and associate it with the specified value list.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-createlistitem
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    list_id = demisto.args().get("list_id")
    new_item = demisto.args().get("new_value_list_item")

    json_data = {
        'value': new_item,
        'list_id': list_id
    }

    url = f"{KIBANA_SERVER}/api/lists/items"

    try:
        response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, json=json_data, verify=False)
        return response.json()

    except requests.exceptions.RequestException as e:
        return f"Error creating new value list item: {e}"


def kibana_get_value_list_items(args, proxies):
    '''
    Used to display entries in an input value list.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-findlistitems
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    list_id = demisto.args().get("list_id")
    result_size = demisto.args().get("result_size")

    params = {
        'list_id': list_id,
        'sort_field': 'created_at',
        'sort_order': 'asc',
        'per_page': result_size
    }

    url = f"{KIBANA_SERVER}/api/lists/items/_find"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, params=params, verify=False)
        result_output = (response.json())["data"]

        # output results to markdown table
        md = tableToMarkdown("Value List Items", result_output, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Value.List.Items",
            outputs=result_output)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error connecting to Kibana: {e}"


def kibana_delete_value_list_item(args, proxies):
    '''
    Used to delete a value list item given the item ID as input.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-deletelistitem
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
        'Content-Type': 'application/json'
    }

    item_id = demisto.args().get("item_id")

    json_data = {
        'id': item_id
    }

    url = f"{KIBANA_SERVER}/api/lists/items"

    try:
        response = requests.delete(url, auth=(USERNAME, PASSWORD), headers=headers, params=json_data, verify=False)
        return response.json()

    except requests.exceptions.RequestException as e:
        return f"Error deleting value list item: {e}"


def kibana_delete_value_list(args, proxies):
    '''
    Used to delete a value list given the list ID as input.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-deletelist
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
        'Content-Type': 'application/json'
    }

    list_id = demisto.args().get("list_id")

    params = {
        'id': list_id
    }

    url = f"{KIBANA_SERVER}/api/lists"

    try:
        response = requests.delete(url, auth=(USERNAME, PASSWORD), headers=headers, params=params, verify=False)
        return response.json()

    except requests.exceptions.RequestException as e:
        return f"Error connecting to Kibana: {e}"


def kibana_get_status(args, proxies):
    '''
    Used to check Kibana's operational status.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-status
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    url = f"{KIBANA_SERVER}/api/status"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        response = response.json()["status"]

        # output results to markdown table
        md = tableToMarkdown("Kibana Operational Status", response, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Operational.Status",
            outputs=response)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error checking Kibana operational status: {e}"


def kibana_get_task_manager_health(args, proxies):
    '''
    Get the health status of the Kibana task manager.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-task-manager-health
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    url = f"{KIBANA_SERVER}/api/task_manager/_health"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        response = response.json()["stats"]

        # output results to markdown table
        md = tableToMarkdown("Kibana Task Manager Health", response, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Task.Manager.Health",
            outputs=response)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error checking Kibana task manager health: {e}"


def kibana_get_upgrade_readiness_status(args, proxies):
    '''
    Check the upgrade readiness status of your cluster.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-upgrade-status
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    url = f"{KIBANA_SERVER}/api/upgrade_assistant/status"

    try:
        response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        response = response.json()

        # output results to markdown table
        md = tableToMarkdown("Kibana Upgrade Readiness Status", response, headers=[])

        result = CommandResults(
            readable_output=md,
            outputs_prefix="Kibana.Upgrade.Readiness.Status",
            outputs=response)

        return result

    except requests.exceptions.RequestException as e:
        return f"Error checking Kibana readiness status: {e}"


def kibana_delete_case_comment(args, proxies):
    '''
    Delete a case comment.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-deletecasecommentdefaultspace
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    case_id = demisto.args().get("case_id")
    comment_id = demisto.args().get("comment_id")

    url = f"{KIBANA_SERVER}/api/cases/{case_id}/comments/{comment_id}"

    try:
        response = requests.delete(url, auth=(USERNAME, PASSWORD), headers=headers, verify=False)
        return f"Deleted comment with ID {comment_id} from case {case_id}"

    except requests.exceptions.RequestException as e:
        return f"Error deleting case comment: {e}"


def kibana_add_file_to_case(args, proxies):
    '''
    Attach a file to a case.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-addcasefiledefaultspace
    '''
    headers = {
        'kbn-xsrf': 'true',  # Required for Kibana API requests
    }

    case_id = demisto.args().get("case_id")
    file_id = demisto.args().get("file_id")

    file_path_dict = demisto.getFilePath(file_id)
    file_path = file_path_dict['path']
    file_name = file_path_dict['name']

    url = f"{KIBANA_SERVER}/api/cases/{case_id}/files"

    try:
        with open(file_path, 'rb') as f:
            files = {
                'file': (file_name, f)
            }

            response = requests.post(url, auth=(USERNAME, PASSWORD), headers=headers, files=files, verify=False)
            return f"Successfully added file {file_name} to case {case_id}"

    except requests.exceptions.RequestException as e:
        return f"Error sending file to case: {e}"


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
        elif demisto.command() == "kibana-find-cases":
            return_results(kibana_find_cases(args, proxies))
        elif demisto.command() == "kibana-find-alerts-for-case":
            return_results(kibana_find_alerts_for_case(args, proxies))
        elif demisto.command() == "kibana-update-alert-status":
            return_results(kibana_update_alert_status(args, proxies))
        elif demisto.command() == "kibana-update-case-status":
            return_results(kibana_update_case_status(args, proxies))
        elif demisto.command() == "kibana-find-user-spaces":
            return_results(kibana_find_user_spaces(args, proxies))
        elif demisto.command() == "kibana-find-case-comments":
            return_results(kibana_find_case_comments(args, proxies))
        elif demisto.command() == "kibana-delete-case":
            return_results(kibana_delete_case(args, proxies))
        elif demisto.command() == "kibana-delete-rule":
            return_results(kibana_delete_rule(args, proxies))
        elif demisto.command() == "kibana-search-rule-details":
            return_results(kibana_search_rule_details(args, proxies))
        elif demisto.command() == "kibana-add-case-comment":
            return_results(kibana_add_case_comment(args, proxies))
        elif demisto.command() == "kibana-get-user-list":
            return_results(kibana_get_user_list(args, proxies))
        elif demisto.command() == "kibana-assign-alert":
            return_results(kibana_assign_alert_user(args, proxies))
        elif demisto.command() == "kibana-list-detection-alerts":
            return_results(kibana_list_detection_alerts(args, proxies))
        elif demisto.command() == "kibana-add-alert-note":
            return_results(kibana_add_alert_note(args, proxies))
        elif demisto.command() == "kibana-get-alerting-health":
            return_results(kibana_get_alerting_health(args, proxies))
        elif demisto.command() == "kibana-disable-alert-rule":
            return_results(kibana_disable_alert_rule(args, proxies))
        elif demisto.command() == "kibana-enable-alert-rule":
            return_results(kibana_enable_alert_rule(args, proxies))
        elif demisto.command() == "kibana-get-exception-lists":
            return_results(kibana_get_exception_lists(args, proxies))
        elif demisto.command() == "kibana-create-value-list":
            return_results(kibana_create_value_list(args, proxies))
        elif demisto.command() == "kibana-get-value-lists":
            return_results(kibana_get_value_lists(args, proxies))
        elif demisto.command() == "kibana-import-value-list-items":
            return_results(kibana_import_value_list_items(args, proxies))
        elif demisto.command() == "kibana-create-value-list-item":
            return_results(kibana_create_value_list_item(args, proxies))
        elif demisto.command() == "kibana-get-value-list-items":
            return_results(kibana_get_value_list_items(args, proxies))
        elif demisto.command() == "kibana-delete-value-list-item":
            return_results(kibana_delete_value_list_item(args, proxies))
        elif demisto.command() == "kibana-delete-value-list":
            return_results(kibana_delete_value_list(args, proxies))
        elif demisto.command() == "kibana-get-status":
            return_results(kibana_get_status(args, proxies))
        elif demisto.command() == "kibana-get-task-manager-health":
            return_results(kibana_get_task_manager_health(args, proxies))
        elif demisto.command() == "kibana-get-upgrade-readiness-status":
            return_results(kibana_get_upgrade_readiness_status(args, proxies))
        elif demisto.command() == "kibana-delete-case-comment":
            return_results(kibana_delete_case_comment(args, proxies))
        elif demisto.command() == "kibana-add-file-to-case":
            return_results(kibana_add_file_to_case(args, proxies))
        elif demisto.command() == "kibana-get-user-by-email":
            return_results(kibana_get_user_by_email(args, proxies))
        elif demisto.command() == "kibana-get-case-information":
            return_results(kibana_get_case_information(args, proxies))

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
