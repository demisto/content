import re

import demistomock as demisto  # noqa: F401

from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *

"""IMPORTS"""
import json
import mimetypes
import traceback
import warnings
from datetime import datetime, timedelta, UTC

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

"""VARIABLES FOR MIRRORING"""
MIRROR_LOG_PREFIX = "[ES-MIRROR]"


def _with_active_traceback(message: str) -> str:
    """Appends the traceback of the exception currently being handled, when there is one."""
    tb = traceback.format_exc()
    # format_exc() returns "NoneType: None\n" when no exception is being handled.
    if tb and not tb.startswith("NoneType: None"):
        return f"{message}\n{tb}"
    return message


def mirror_debug(message: str) -> None:
    demisto.debug(f"{MIRROR_LOG_PREFIX} {message}")


def mirror_error(message: str) -> None:
    demisto.error(f"{MIRROR_LOG_PREFIX} {_with_active_traceback(message)}")


def get_incident_type() -> str:
    """Returns the current incident's type, or "" when the incident context is unavailable."""
    try:
        incident = demisto.incident()
    except Exception as e:
        mirror_debug(f"Incident context unavailable ({e}); resolving type from the remote system.")
        return ""

    if not isinstance(incident, dict):
        return ""

    return incident.get("type") or ""


MIRROR_DIRECTION = PARAMS.get("mirror_direction", "None")
FETCH_SEVERITY = argToList(PARAMS.get("fetch_severity", ""))
FETCH_STATUS = argToList(PARAMS.get("fetch_status", "open,in-progress"))
FETCH_ALERTS_FOR_CASE = PARAMS.get("fetch_alerts_for_case", False)
CLOSE_INCIDENT = PARAMS.get("close_incident", False)
CLOSE_ELASTIC_INCIDENT = PARAMS.get("close_elastic_incident", False)

MIRROR_DIRECTION_MAP = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

INCIDENT_TYPE_SECURITY_ALERT = "Elasticsearch Security Alert"
INCIDENT_TYPE_CASE = "Elasticsearch Case"

ELASTIC_ENTITY_KIND_FIELD = "elastic_entity_kind"
ENTITY_KIND_SECURITY_ALERT = "signal"
ENTITY_KIND_CASE = "securitySolution"

# The only detection-alert fields Kibana can update; severity/risk/rule cannot be mirrored out.
MIRRORABLE_ALERT_FIELDS = ("status", "reason", "tags")

ELASTIC_CLOSE_REASON_TO_XSOAR: Dict[str, str] = {
    "false_positive": "false_positive",
    "duplicate": "duplicate",
    "true_positive": "resolved",
    "benign_positive": "resolved",
    "automated_closure": "resolved",
    "other": "other",
}

# Not the inverse of the map above: several Elastic reasons collapse onto "resolved", and Kibana
# rejects values outside its own enum, so unknown reasons fall back to "other".
XSOAR_CLOSE_REASON_TO_ELASTIC: Dict[str, str] = {
    "False Positive": "false_positive",
    "false_positive": "false_positive",
    "Duplicate": "duplicate",
    "duplicate": "duplicate",
    "Resolved": "true_positive",
    "resolved": "true_positive",
    "Other": "other",
    "other": "other",
}

# Keys XSOAR adds to the delta on close; used to detect closures when inc_status is still Active.
XSOAR_CLOSE_DELTA_KEYS = {"closeReason", "closeNotes", "closingUserId"}


def is_incident_closing(inc_status: Optional[int], delta: Optional[Dict[str, Any]]) -> bool:
    """Returns True when the local incident is being closed (by status or close-only delta keys)."""
    if inc_status == IncidentStatus.DONE:
        return True
    return bool((delta or {}).keys() & XSOAR_CLOSE_DELTA_KEYS)


"""VARIABLES FOR KIBANA COMMANDS (es-kibana-*)"""
KIBANA_LOG_PREFIX = "[ES-KIBANA]"
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


def get_alert_source_value(source: Any, key: str) -> Any:
    """Reads a field from an alert ``_source``, supporting both flat-dotted and nested key layouts.

    Alerts-as-data indices store keys flat (``{"kibana.alert.uuid": ...}``) while older
    ``.siem-signals-*`` documents use a nested layout. The flat key is checked first, then the
    nested walk via ``get_value_by_dot_notation``.
    """
    if not isinstance(source, dict):
        return None
    if key in source:
        return source[key]
    return get_value_by_dot_notation(source, key)


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
    Resolves the Kibana base URL.

    The explicitly configured "Kibana Server URL" parameter always wins. It is the only option that
    works for on-premises (self-managed) deployments, where Kibana is typically hosted separately
    from Elasticsearch (for example, https://kibana.example.com:5601).

    When that parameter is empty, the URL is derived from the Elasticsearch Server URL. Elastic Cloud
    deployments expose Elasticsearch and Kibana on the same domain, differentiated only by the
    ".es." / ".kb." subdomain segment, e.g.:
        https://my-deployment-af38b6.es.us-central1.gcp.cloud.es.io
        https://my-deployment-af38b6.kb.us-central1.gcp.cloud.es.io

    Returns:
        str: The Kibana base URL (no trailing slash).

    Raises:
        DemistoException: If no Kibana Server URL is configured and the Server URL does not contain
            the ".es." segment, so a Kibana URL cannot be derived from it.
    """
    kibana_server = (PARAMS.get("kibana_url") or "").rstrip("/")
    if kibana_server:
        demisto.debug(f"{KIBANA_LOG_PREFIX} Using the configured Kibana Server URL: {kibana_server}")
        return kibana_server

    if ".es." in SERVER:
        derived_url = SERVER.replace(".es.", ".kb.", 1)
        demisto.debug(f"{KIBANA_LOG_PREFIX} Derived the Kibana URL from the Elastic Cloud Server URL: {derived_url}")
        return derived_url

    raise DemistoException(
        "Could not determine the Kibana URL. "
        'Set the "Kibana Server URL" parameter in the integration instance configuration '
        '(for example, "https://kibana.example.com:5601"). '
        'It can be omitted only for Elastic Cloud deployments, whose Server URL contains ".es." '
        '(e.g. "https://my-deployment.es.us-central1.gcp.cloud.es.io") and is therefore used to derive it. '
        f"Configured Server URL: {SERVER}"
    )


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


def results_to_incidents_timestamp(response, last_fetch, last_fetch_ids=None):
    """Converts the current results into incidents.

    To avoid silently dropping documents that share an identical timestamp with the
    high-water-mark (last_fetch) - which happens when several documents have the same
    timestamp down to the sub-second and span a fetch boundary - the time query uses an
    inclusive lower bound (gte) and de-duplication is done by document ``_id`` rather than
    by discarding every hit that equals the boundary timestamp. Only the ``_id``s that were
    already ingested at the boundary timestamp are skipped; all other hits are ingested.

    Args:
        response(dict): the raw search results from Elasticsearch.
        last_fetch(num): the date or timestamp of the last fetch before this fetch
        - this will hold the last date of the incident brought by this fetch.
        last_fetch_ids(list): the ``_id``s of the documents already ingested at the
        ``last_fetch`` boundary timestamp in the previous fetch.

    Returns:
        (list).The incidents.
        (num).The date of the last incident brought by this fetch.
        (list).The ``_id``s of the documents ingested at the new boundary timestamp.
    """
    current_fetch = last_fetch
    already_fetched_ids = set(last_fetch_ids or [])
    incidents = []
    # tracks the _ids seen at the maximum timestamp so far in this fetch.
    # seeded with the previously-persisted boundary ids so that ids already ingested at the
    # boundary are carried forward and not re-ingested on the next fetch. It is reset whenever
    # a strictly newer timestamp is encountered.
    new_fetch_ids: list = list(dict.fromkeys(last_fetch_ids or []))
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
                hit_id = hit.get("_id")

                if hit_timestamp > last_fetch:
                    # a strictly newer timestamp resets the boundary id tracking
                    last_fetch = hit_timestamp
                    new_fetch_ids = []

                # remember every id seen at the current maximum timestamp - including ids
                # that are skipped below because they were already ingested - so the boundary
                # id set is preserved across fetches and does not drift.
                if hit_timestamp == last_fetch and hit_id and hit_id not in new_fetch_ids:
                    new_fetch_ids.append(hit_id)

                # Skip only documents already ingested at the boundary timestamp,
                # instead of dropping every hit that equals the boundary timestamp.
                if hit_timestamp < current_fetch or (hit_id and hit_id in already_fetched_ids):
                    demisto.debug(f"Skipping already-fetched hit ID: {hit_id} with {hit_timestamp=}.")
                    continue

                inc = {
                    "name": "Elasticsearch: Index: " + str(hit.get("_index")) + ", ID: " + str(hit_id),
                    "rawJSON": json.dumps(hit),
                    "occurred": hit_date.isoformat() + "Z",
                }
                if hit_id:
                    inc["dbotMirrorId"] = hit_id

                if MAP_LABELS:
                    inc["labels"] = incident_label_maker(hit.get("_source"))

                incidents.append(inc)

    return incidents, last_fetch, new_fetch_ids


def results_to_incidents_datetime(response, last_fetch, last_fetch_ids=None):
    """Converts the current results into incidents.

    To avoid silently dropping documents that share an identical timestamp with the
    high-water-mark (last_fetch) - which happens when several documents have the same
    timestamp down to the sub-second and span a fetch boundary - the time query uses an
    inclusive lower bound (gte) and de-duplication is done by document ``_id`` rather than
    by discarding every hit that equals the boundary timestamp. Only the ``_id``s that were
    already ingested at the boundary timestamp are skipped; all other hits are ingested.

    Args:
        response(dict): the raw search results from Elasticsearch.
        last_fetch(datetime): the date or timestamp of the last fetch before this fetch or parameter default fetch time
        - this will hold the last date of the incident brought by this fetch.
        last_fetch_ids(list): the ``_id``s of the documents already ingested at the
        ``last_fetch`` boundary timestamp in the previous fetch.

    Returns:
        (list).The incidents.
        (datetime).The date of the last incident brought by this fetch.
        (list).The ``_id``s of the documents ingested at the new boundary timestamp.
    """
    last_fetch = dateparser.parse(last_fetch)
    last_fetch_timestamp = int(last_fetch.timestamp() * 1000)  # type:ignore[union-attr]
    current_fetch = last_fetch_timestamp
    already_fetched_ids = set(last_fetch_ids or [])
    incidents = []
    # tracks the _ids seen at the maximum timestamp so far in this fetch.
    # seeded with the previously-persisted boundary ids so that ids already ingested at the
    # boundary are carried forward and not re-ingested on the next fetch. It is reset whenever
    # a strictly newer timestamp is encountered.
    new_fetch_ids: list = list(dict.fromkeys(last_fetch_ids or []))

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
                hit_id = hit.get("_id")

                if hit_timestamp > last_fetch_timestamp:
                    # a strictly newer timestamp resets the boundary id tracking
                    last_fetch = hit_date
                    last_fetch_timestamp = hit_timestamp
                    new_fetch_ids = []

                # remember every id seen at the current maximum timestamp - including ids
                # that are skipped below because they were already ingested - so the boundary
                # id set is preserved across fetches and does not drift.
                if hit_timestamp == last_fetch_timestamp and hit_id and hit_id not in new_fetch_ids:
                    new_fetch_ids.append(hit_id)

                # Skip only documents already ingested at the boundary timestamp,
                # instead of dropping every hit that equals the boundary timestamp.
                if hit_timestamp < current_fetch or (hit_id and hit_id in already_fetched_ids):
                    demisto.debug(
                        f"Skipping hit ID: {hit_id} since {hit_timestamp=} was already fetched (id previously ingested)"
                    )
                    continue

                inc = {
                    "name": "Elasticsearch: Index: " + str(hit.get("_index")) + ", ID: " + str(hit_id),
                    "rawJSON": json.dumps(hit),
                    # parse function returns iso format sometimes as YYYY-MM-DDThh:mm:ss+00:00
                    # and sometimes as YYYY-MM-DDThh:mm:ss
                    # we want to return format: YYYY-MM-DDThh:mm:ssZ in our incidents
                    "occurred": format_to_iso(hit_date.isoformat()),
                }
                if hit_id:
                    inc["dbotMirrorId"] = hit_id

                if MAP_LABELS:
                    # Pass both _source and normalized fields to label maker
                    inc["labels"] = incident_label_maker(hit.get("_source"), fields=fields)

                incidents.append(inc)

    return incidents, last_fetch.isoformat(), new_fetch_ids  # type:ignore[union-attr]


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
        start date (gte) - if this is the first fetch: use time_range_start param if provided, else use fetch time param.
                          if this is not the fetch: use the last fetch provided.
                          Note: an inclusive lower bound (gte) is used so documents that share the exact
                          high-water-mark timestamp are not permanently skipped by the query. De-duplication
                          of documents already ingested at the boundary timestamp is handled by _id in
                          results_to_incidents_datetime / results_to_incidents_timestamp.
        end date (lt) - use the given time range end param.
        When the `time_method` parameter is set to `Simple-Date` in order to avoid being related to the field datetime format,
            we add the format key to the query dict.
    Args:

        last_fetch (str): last fetch time stamp
        time_range_start (str): start of time range
        time_range_end (str): end of time range
        time_field (str): The field on which the filter the results


    Returns:
        dictionary (Ex. {"range":{'gte': 1000 'lt': 1001}})
    """
    range_dict = {}
    if not last_fetch and time_range_start:  # this is the first fetch
        start_date = dateparser.parse(time_range_start)

        start_time = convert_date_to_timestamp(start_date)
    else:
        start_time = last_fetch

    demisto.debug(f"Time range start time: {start_time}")
    if start_time:
        range_dict["gte"] = start_time

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


def build_fetch_extra_params(fields_list: list) -> dict:
    """Builds the extra request-body parameters for the fetch Search request.

    The "Fields to Fetch" parameter is optional. When it is left blank,
    ``fields_list`` is an empty list and the "fields" key must be omitted from the
    request body entirely. Sending ``"fields": []`` causes Elasticsearch to fail with:
    ``ParsingException 400 'Unknown key for a START_ARRAY in [fields]'``.

    Args:
        fields_list (list): The list of fields to fetch (may be empty).

    Returns:
        dict: The kwargs to pass to ``Search.extra``. Always requests ``_source``,
            and includes ``fields`` only when ``fields_list`` is non-empty.
    """
    extra_params: dict = {"_source": True}
    if fields_list:
        extra_params["fields"] = fields_list
    return extra_params


def fetch_incidents(proxies):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get("time") or FETCH_TIME
    # _ids of documents already ingested at the last_fetch boundary timestamp,
    # used to de-duplicate hits that share an identical timestamp across fetches.
    last_fetch_ids = last_run.get("last_fetch_ids") or []

    es = elasticsearch_builder(proxies)
    time_range_dict = get_time_range(time_range_start=last_fetch)

    if RAW_QUERY:
        response = execute_raw_query(es, RAW_QUERY)
    else:
        query = QueryString(query="(" + FETCH_QUERY + ") AND " + TIME_FIELD + ":*")
        # Elastic search can use epoch timestamps (in milliseconds) as date representation regardless of date format.
        search = Search(using=es, index=FETCH_INDEX).filter(time_range_dict)
        search = search.sort({TIME_FIELD: {"order": "asc"}})[0:FETCH_SIZE].query(query)
        # Only add the "fields" key to the request body when there are fields to fetch.
        # Passing an empty list results in "fields": [] in the body, which Elasticsearch
        # rejects with: ParsingException 400 'Unknown key for a START_ARRAY in [fields]'.
        search = search.extra(**build_fetch_extra_params(FIELDS_LIST))

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
            incidents, last_fetch, last_fetch_ids = results_to_incidents_timestamp(response, last_fetch, last_fetch_ids)
            demisto.setLastRun({"time": last_fetch, "last_fetch_ids": last_fetch_ids})

        else:
            incidents, last_fetch, last_fetch_ids = results_to_incidents_datetime(
                response, last_fetch or FETCH_TIME, last_fetch_ids
            )
            demisto.setLastRun({"time": str(last_fetch), "last_fetch_ids": last_fetch_ids})

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
    else:
        # The Kibana Cases API requires "connector" on create; default to the no-op connector.
        body["connector"] = {"fields": None, "id": "none", "name": "none", "type": ".none"}

    settings: Dict[str, Any] = {}
    if "sync_alerts" in args:
        settings["syncAlerts"] = argToBoolean(args["sync_alerts"])
    if "extract_observables" in args:
        settings["extractObservables"] = argToBoolean(args["extract_observables"])
    if settings:
        body["settings"] = settings
    else:
        # The Kibana Cases API requires "settings" on create; default to syncing alerts.
        body["settings"] = {"syncAlerts": True}

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
        response = kibana_http_request("GET", f"/api/cases/{case_id}", space_id=space_id, proxies=proxies, allow_not_found=True)
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
    response = kibana_http_request("POST", f"/api/cases/{case_id}/comments", space_id=space_id, json_data=body, proxies=proxies)

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

    response = kibana_http_request("PATCH", f"/api/cases/{case_id}/comments", space_id=space_id, json_data=body, proxies=proxies)

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

    return CommandResults(readable_output=f"The comments and alerts for the case {case_id} have been successfully deleted.")


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

    mime_type, _ = mimetypes.guess_type(file_name or file_path)
    if not mime_type:
        demisto.debug(f"Could not determine MIME type for file {file_name or file_path}, defaulting to text/plain")
        mime_type = "text/plain"  # Default to text/plain if MIME type cannot be determined

    root, ext = os.path.splitext(file_name)
    if not ext:
        guessed_ext = mimetypes.guess_extension(mime_type)
        if guessed_ext:
            demisto.debug(f"File {file_name} has no extension, but MIME type {mime_type} suggests extension {guessed_ext}")
            file_name += guessed_ext
        else:
            demisto.debug(
                f"File {file_name} has no extension and MIME type {mime_type} does not suggest an extension, defaulting to .txt"
            )
            file_name += ".txt"

    with open(file_path, "rb") as f:
        files = {"file": (file_name, f, mime_type)}
        response = kibana_http_request(
            "POST",
            f"/api/cases/{case_id}/files",
            space_id=space_id,
            files=files,
            proxies=proxies,
            json_data={"filename": file_name},
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
            raise DemistoException('"flapping_look_back_window" is required when configuring flapping settings.')
        if flapping_status_change_threshold is None:
            raise DemistoException('"flapping_status_change_threshold" is required when configuring flapping settings.')
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

    # The Kibana PUT /api/alerting/rule/{id} endpoint requires the rule's `params` field to be
    # present in every update request (it does not preserve existing params on partial updates).
    existing_rule = kibana_http_request("GET", f"/api/alerting/rule/{rule_id}", space_id=space_id, proxies=proxies)
    existing_params = existing_rule.get("params")
    if existing_params and "params" not in body:
        body["params"] = existing_params

    response = kibana_http_request("PUT", f"/api/alerting/rule/{rule_id}", space_id=space_id, json_data=body, proxies=proxies)

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

    kibana_http_request("POST", f"/api/alerting/rule/{rule_id}/alert/{alert_id}/_unmute", space_id=space_id, proxies=proxies)
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
    query_dict = safe_load_json(args.get("query")) if args.get("query") else None
    if query_dict:
        body["query"] = query_dict
    if args.get("reason"):
        body["reason"] = args["reason"]
    if args.get("conflicts"):
        body["conflicts"] = args["conflicts"]

    response = kibana_http_request(
        "POST", "/api/detection_engine/signals/status", space_id=space_id, json_data=body, proxies=proxies
    )

    hr = {"Total": response.get("total"), "Updated": response.get("updated")}
    readable_output = tableToMarkdown("Kibana Detection Alert Status Update", hr, removeNull=True, headers=list(hr.keys()))
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

    kibana_http_request("DELETE", "/api/endpoint_list/items", space_id=space_id, params={"item_id": item_id}, proxies=proxies)

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
        param_arg_map = {
            "filter": "filter",
            "sort_field": "sort_field",
            "sort_order": "sort_order",
            "page": "page",
            "size": "per_page",
        }
        for arg_name, param_name in param_arg_map.items():
            if args.get(arg_name) is not None:
                params[param_name] = args[arg_name]

        response = kibana_http_request("GET", "/api/endpoint_list/items/_find", space_id=space_id, params=params, proxies=proxies)
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

        response = kibana_http_request("GET", "/api/exception_lists/_find", space_id=space_id, params=params, proxies=proxies)
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

    response = kibana_http_request("POST", "/api/lists/items", space_id=space_id, json_data=body, params=params, proxies=proxies)

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
        raise DemistoException('Either "value_list_item_id" or both "value_list_id" and "value" must be specified.')
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

    response = kibana_http_request("POST", "/api/lists/items/_export", space_id=space_id, params=params, proxies=proxies)

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


"""MIRRORING FUNCTIONS"""

# The server does not dedup by dbotMirrorId, so the integration must remember ingested IDs to
# avoid re-creating incidents. IDs are pruned after this window to bound the lastRun object.
FETCHED_IDS_RETENTION_DAYS = 30


def prune_fetched_ids(fetched_ids: Dict[str, str], now: Optional[datetime] = None) -> Dict[str, str]:
    """Returns a copy of the ingested-ID map with entries older than FETCHED_IDS_RETENTION_DAYS removed."""
    reference = now or datetime.now(UTC)
    cutoff = reference - timedelta(days=FETCHED_IDS_RETENTION_DAYS)
    pruned: Dict[str, str] = {}

    for remote_id, fetched_at in (fetched_ids or {}).items():
        parsed = parse_to_utc(fetched_at)
        # Keep entries we cannot parse - dropping them would risk re-ingesting duplicates.
        if not parsed or parsed >= cutoff:
            pruned[remote_id] = fetched_at

    if len(pruned) != len(fetched_ids or {}):
        demisto.debug(f"Pruned {len(fetched_ids or {}) - len(pruned)} expired fetched IDs from last run.")

    return pruned


def fetch_security_alerts(proxies: dict) -> List[Dict[str, Any]]:
    """Fetches Elasticsearch Security Alerts as XSOAR incidents using the standard search mechanism."""
    es = elasticsearch_builder(proxies)
    last_run = demisto.getLastRun()
    last_fetch = last_run.get("alert_time") or FETCH_TIME
    time_range_dict = get_time_range(time_range_start=last_fetch)

    if RAW_QUERY:
        response = execute_raw_query(es, RAW_QUERY)
    else:
        query = QueryString(query="(" + FETCH_QUERY + ") AND " + TIME_FIELD + ":*") if FETCH_QUERY else QueryString(query="*")
        search = Search(using=es, index=FETCH_INDEX).filter(time_range_dict)
        search = search.sort({TIME_FIELD: {"order": "asc"}})[0:FETCH_SIZE].query(query)
        # Only include the "fields" key when there are fields to fetch; an empty list
        # would produce "fields": [] in the body and cause a 400 from Elasticsearch.
        search = search.extra(**build_fetch_extra_params(FIELDS_LIST))

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()
        else:
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

    hits = response.get("hits", {}).get("hits", [])
    incidents = []
    new_last_fetch_dt = parse_to_utc(last_fetch)

    # Authoritative dedup: the timestamp cursor is only a coarse pre-filter.
    fetched_alert_ids: Dict[str, str] = prune_fetched_ids(last_run.get("fetched_alert_ids") or {})
    ingested_at = datetime.now(UTC).isoformat()

    for hit in hits:
        source = hit.get("_source", {})
        index = hit.get("_index", "")
        hit_id = hit.get("_id", "")
        alert_uuid = get_alert_source_value(source, "kibana.alert.uuid") or hit_id

        time_val = get_alert_source_value(source, "@timestamp") or get_alert_source_value(source, str(TIME_FIELD))
        occurred = format_to_iso(parse(str(time_val)).isoformat()) if time_val else None
        if occurred:
            occurred_dt = parse_to_utc(occurred)
            if occurred_dt and (new_last_fetch_dt is None or occurred_dt > new_last_fetch_dt):
                new_last_fetch_dt = occurred_dt

        if alert_uuid and alert_uuid in fetched_alert_ids:
            demisto.debug(f"Skipping already-fetched alert ID: {alert_uuid}")
            continue

        severity = convert_severity(get_alert_source_value(source, "kibana.alert.severity") or "low")

        mirror_direction = MIRROR_DIRECTION_MAP.get(MIRROR_DIRECTION)
        mirror_instance = demisto.integrationInstance()

        # The incoming mapper reads root-level paths, so the hit is flattened to match the shape
        # get_remote_data_command returns; otherwise mirroring-in never starts for this incident.
        raw_data = flatten_alert_hit(hit)
        raw_data.update(
            {
                "mirror_id": alert_uuid,
                "mirror_instance": mirror_instance,
                "mirror_direction": mirror_direction,
                "severity": severity,  # XSOAR severity is numeric, not the Kibana name.
                ELASTIC_ENTITY_KIND_FIELD: get_alert_source_value(source, "event.kind") or ENTITY_KIND_SECURITY_ALERT,
            }
        )

        inc: Dict[str, Any] = {
            "name": f"Elasticsearch: {index} {alert_uuid}",
            "rawJSON": json.dumps(raw_data),
            "type": INCIDENT_TYPE_SECURITY_ALERT,
            "severity": severity,
            "dbotMirrorId": alert_uuid,
            "dbotMirrorInstance": mirror_instance,
            "dbotMirrorDirection": mirror_direction,
        }
        if occurred:
            inc["occurred"] = occurred

        if MAP_LABELS:
            inc["labels"] = incident_label_maker(source)

        # dbotMirrorId is logged so it can be matched against get-modified-remote-data output.
        mirror_debug(
            f"Ingesting security alert with dbotMirrorId={str(alert_uuid)!r} "
            f"(document _id={hit_id!r}, direction={mirror_direction!r}, instance={mirror_instance!r})."
        )

        incidents.append(inc)
        if alert_uuid:
            fetched_alert_ids[alert_uuid] = ingested_at

    last_run["alert_time"] = new_last_fetch_dt.isoformat() if new_last_fetch_dt else str(last_fetch)
    last_run["fetched_alert_ids"] = fetched_alert_ids
    demisto.setLastRun(last_run)
    return incidents


def fetch_cases(proxies: dict) -> List[Dict[str, Any]]:
    """Fetches Elasticsearch Cases as XSOAR incidents via the Kibana Cases API.

    Filters by FETCH_SEVERITY and FETCH_STATUS, and optionally fetches per-case alerts when
    FETCH_ALERTS_FOR_CASE is enabled.
    """
    last_run = demisto.getLastRun()
    last_fetch_str = last_run.get("case_time") or FETCH_TIME
    last_fetch_dt = parse_to_utc(last_fetch_str)

    # Authoritative dedup: once ingested a case is excluded from fetch, so remote edits do not
    # re-create it. The cursor sorts on createdAt (not updatedAt) so remote changes are delivered
    # via mirroring-in rather than re-fetched as new incidents.
    fetched_case_ids: Dict[str, str] = prune_fetched_ids(last_run.get("fetched_case_ids") or {})
    ingested_at = datetime.now(UTC).isoformat()

    params: Dict[str, Any] = {"perPage": FETCH_SIZE, "sortField": "createdAt", "sortOrder": "asc"}

    all_cases: List[Dict[str, Any]] = []
    statuses_to_fetch = FETCH_STATUS if FETCH_STATUS else ["open", "in-progress"]

    for status in statuses_to_fetch:
        status_params = dict(params)
        status_params["status"] = status
        if FETCH_SEVERITY:
            for sev in FETCH_SEVERITY:
                sev_params = dict(status_params)
                sev_params["severity"] = sev
                response = kibana_http_request("GET", "/api/cases/_find", params=sev_params, proxies=proxies)
                all_cases.extend(response.get("cases", []) if isinstance(response, dict) else [])
        else:
            response = kibana_http_request("GET", "/api/cases/_find", params=status_params, proxies=proxies)
            all_cases.extend(response.get("cases", []) if isinstance(response, dict) else [])
    incidents = []
    new_last_fetch = last_fetch_dt

    for case in all_cases:
        created_at_str = case.get("created_at") or case.get("updated_at", "")
        try:
            created_at = dateparser.parse(created_at_str, settings={"RETURN_AS_TIMEZONE_AWARE": True})
            if created_at and created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
        except Exception:
            created_at = None

        case_id = case.get("id", "")

        # Authoritative dedup: an ID is only ever ingested once.
        if case_id and case_id in fetched_case_ids:
            mirror_debug(f"Skipping already-fetched case ID: {case_id}")
            continue

        # Coarse pre-filter on the creation-time cursor.
        if created_at and last_fetch_dt and created_at < last_fetch_dt:
            continue

        alerts_data: List[Dict[str, Any]] = []
        if FETCH_ALERTS_FOR_CASE and case_id:
            try:
                alerts_resp = kibana_http_request("GET", f"/api/cases/{case_id}/alerts", proxies=proxies, allow_not_found=True)
                alerts_data = alerts_resp if isinstance(alerts_resp, list) else []
            except Exception as e:
                demisto.debug(f"Failed to fetch alerts for case {case_id}: {e}")

        severity = convert_severity(case.get("severity", "low"))

        mirror_direction = MIRROR_DIRECTION_MAP.get(MIRROR_DIRECTION)
        mirror_instance = demisto.integrationInstance()

        raw_data = dict(case)
        if alerts_data:
            raw_data["_alerts"] = alerts_data

        # Mirror values also go inside rawJSON so the incoming mapper can resolve the instance ID.
        raw_data.update(
            {
                "mirror_id": case_id,
                "mirror_instance": mirror_instance,
                "mirror_direction": mirror_direction,
                "severity": severity,  # XSOAR severity is numeric, not the Kibana name.
                ELASTIC_ENTITY_KIND_FIELD: case.get("owner") or ENTITY_KIND_CASE,
            }
        )

        inc: Dict[str, Any] = {
            "name": f"Elasticsearch: {case.get('title', case_id)}",
            "rawJSON": json.dumps(raw_data),
            "type": INCIDENT_TYPE_CASE,
            "severity": severity,
            "dbotMirrorId": case_id,
            "dbotMirrorInstance": mirror_instance,
            "dbotMirrorDirection": mirror_direction,
        }
        if created_at_str:
            inc["occurred"] = format_to_iso(created_at_str)

        incidents.append(inc)
        if case_id:
            fetched_case_ids[case_id] = ingested_at

        if created_at and (new_last_fetch is None or created_at > new_last_fetch):
            new_last_fetch = created_at

    if new_last_fetch:
        last_run["case_time"] = new_last_fetch.isoformat()
    last_run["fetched_case_ids"] = fetched_case_ids
    demisto.setLastRun(last_run)

    mirror_debug(f"fetch_cases ingested {len(incidents)} new case(s); remembering {len(fetched_case_ids)} ID(s).")
    return incidents


# Index pattern used for security-alert lookups when no fetch index is configured.
SECURITY_ALERT_DEFAULT_INDEX = ".internal.alerts-security.alerts-*,.alerts-security.alerts-*,.siem-signals-*"


def get_configured_fetch_incident_type() -> str:
    """Returns the mirroring incident type this instance is configured to fetch, or "".

    A reliable, network-free fallback for when both the incident context and the remote lookup
    come back empty during a mirroring run.
    """
    configured = PARAMS.get("fetch_incident_type") or PARAMS.get("incidentType", "")
    if configured in (INCIDENT_TYPE_SECURITY_ALERT, INCIDENT_TYPE_CASE):
        return configured
    return ""


def search_security_alerts(body: Dict[str, Any], proxies: dict) -> Dict[str, Any]:
    """Searches security alert documents via the Elasticsearch client, falling back to the Kibana API.

    The Elasticsearch client is preferred so mirroring works wherever fetch works; the Kibana API
    is a fallback for deployments where the alert indices are not directly readable.
    """
    index = FETCH_INDEX or SECURITY_ALERT_DEFAULT_INDEX
    try:
        es = elasticsearch_builder(proxies)
        search = Search(using=es, index=index).update_from_dict(body)
        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V9, ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()
        else:
            response = es.search(index=search._index, body=search.to_dict(), **search._params)
        hit_count = len(response.get("hits", {}).get("hits", []))
        mirror_debug(f"Security alert search against index {index!r} returned {hit_count} hit(s).")
        return response
    except Exception as es_error:
        mirror_debug(f"Elasticsearch alert search on {index!r} failed ({es_error}); falling back to the Kibana API.")

    try:
        response = kibana_http_request(
            "POST",
            "/api/detection_engine/signals/search",
            json_data=body,
            proxies=proxies,
        )
        return response if isinstance(response, dict) else {}
    except Exception as kibana_error:
        mirror_error(f"Security alert search failed on both Elasticsearch and Kibana: {kibana_error}")
        raise


def build_alert_lookup_body(remote_id: str, size: int = 1) -> Dict[str, Any]:
    """Builds a search body matching a security alert by either kibana.alert.uuid or document _id.

    Both ID forms are matched because fetch_security_alerts stores whichever one is available.
    """
    return {
        "query": {
            "bool": {
                "should": [
                    {"term": {"kibana.alert.uuid": remote_id}},
                    {"ids": {"values": [remote_id]}},
                ],
                "minimum_should_match": 1,
            }
        },
        "size": size,
    }


def resolve_remote_incident_type(remote_id: str, proxies: dict) -> str:
    """Resolves a remote ID to a Security Alert or Case by probing the remote system.

    Used when the incident context is unavailable. Returns the configured fetch type when the
    probes cannot reach the remote system, and "" only when the ID matches neither.
    """
    if not remote_id:
        return ""

    # Cases are cheaper to check (a single GET by ID).
    try:
        case = kibana_http_request("GET", f"/api/cases/{remote_id}", proxies=proxies, allow_not_found=True)
        if case:
            mirror_debug(f"Resolved remote id {remote_id} to an Elasticsearch Case.")
            return INCIDENT_TYPE_CASE
    except Exception as e:
        mirror_debug(f"Could not resolve remote id {remote_id} as a case: {e}")

    try:
        response = search_security_alerts(build_alert_lookup_body(remote_id), proxies)
        hits = (response or {}).get("hits", {}).get("hits", []) if isinstance(response, dict) else []
        if hits:
            mirror_debug(f"Resolved remote id {remote_id} to an Elasticsearch Security Alert.")
            return INCIDENT_TYPE_SECURITY_ALERT
    except Exception as e:
        mirror_debug(f"Could not resolve remote id {remote_id} as a security alert: {e}")

    # Neither probe matched - usually a connectivity/permission issue, so fall back to the
    # configured fetch type rather than giving up and mirroring nothing.
    configured = get_configured_fetch_incident_type()
    if configured:
        mirror_debug(f"Remote id {remote_id} could not be probed; assuming {configured!r} based on the instance configuration.")
        return configured

    mirror_debug(f"Remote id {remote_id} matched neither a case nor a security alert.")
    return ""


# Kibana severity name -> XSOAR numeric severity.
ELASTIC_SEVERITY_TO_XSOAR = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def convert_severity(severity: Any) -> int:
    """Converts a Kibana severity name to the XSOAR numeric severity."""
    return ELASTIC_SEVERITY_TO_XSOAR.get(str(severity).lower(), 0)


def convert_severity_to_elastic(severity: Any) -> Optional[str]:
    """Converts an XSOAR numeric severity to a Kibana severity name, or None when unmappable."""
    if isinstance(severity, str) and severity.lower() in ELASTIC_SEVERITY_TO_XSOAR:
        return severity.lower()

    try:
        numeric = int(float(severity))
    except (TypeError, ValueError):
        return None

    for name, value in ELASTIC_SEVERITY_TO_XSOAR.items():
        if value == numeric:
            return name
    return None


def flatten_alert_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
    """Merges an Elasticsearch hit's ``_source`` fields into the root, keeping metadata keys.

    The incoming mapper reads fields from the root, so the raw hit must be flattened.
    """
    flattened = {key: value for key, value in hit.items() if key != "_source"}
    source = hit.get("_source") or {}
    if isinstance(source, dict):
        flattened.update(source)
    return flattened


def get_remote_data_command(args: Dict[str, Any], proxies: dict) -> GetRemoteDataResponse:
    """Mirroring-in: fetches the latest state of a remote alert/case and returns it for XSOAR."""
    remote_id = args.get("id", "")
    last_update = args.get("lastUpdate", "")

    # The incident context is only a hint, so fall back to probing the remote system by ID.
    incident_type = get_incident_type() or resolve_remote_incident_type(remote_id, proxies)

    mirror_debug(f"get-remote-data called for id={remote_id}, type={incident_type}, lastUpdate={last_update}")

    updated_incident: Dict[str, Any] = {}
    entries: List[Dict[str, Any]] = []

    if incident_type == INCIDENT_TYPE_SECURITY_ALERT:
        try:
            response = search_security_alerts(build_alert_lookup_body(remote_id), proxies)
            hits = (response or {}).get("hits", {}).get("hits", []) if isinstance(response, dict) else []
            if hits:
                hit = hits[0]
                source = hit.get("_source", {})
                workflow_status = get_alert_source_value(source, "kibana.alert.workflow_status") or "open"

                # The mirrored object goes through the incoming mapper, so it must keep the raw
                # document key space, exactly like a fetched incident.
                updated_incident = flatten_alert_hit(hit)
                updated_incident["severity"] = convert_severity(get_alert_source_value(source, "kibana.alert.severity") or "low")
                updated_incident["kibana_alert_workflow_tags"] = (
                    get_alert_source_value(source, "kibana.alert.workflow_tags") or []
                )
                updated_incident[ELASTIC_ENTITY_KIND_FIELD] = (
                    get_alert_source_value(source, "event.kind") or ENTITY_KIND_SECURITY_ALERT
                )
                updated_incident["rawJSON"] = json.dumps(updated_incident)

                if CLOSE_INCIDENT and workflow_status == "closed":
                    reason = get_alert_source_value(source, "kibana.alert.workflow_reason") or "other"
                    xsoar_reason = ELASTIC_CLOSE_REASON_TO_XSOAR.get(reason, "other")
                    entries.append(
                        {
                            "Type": EntryType.NOTE,
                            "Contents": {
                                "dbotIncidentClose": True,
                                "closeReason": xsoar_reason,
                                "closeNotes": f"Closed by Elasticsearch mirroring. Reason: {reason}",
                            },
                            "ContentsFormat": EntryFormat.JSON,
                        }
                    )
        except Exception as e:
            demisto.debug(f"Failed to fetch security alert {remote_id}: {e}")

    elif incident_type == INCIDENT_TYPE_CASE:
        try:
            response = kibana_http_request("GET", f"/api/cases/{remote_id}", proxies=proxies, allow_not_found=True)
            if response:
                case_status = response.get("status", "open")

                # Keep the raw case document so the incoming mapper can map it.
                updated_incident = dict(response)
                updated_incident["severity"] = convert_severity(response.get("severity", "low"))
                updated_incident[ELASTIC_ENTITY_KIND_FIELD] = response.get("owner") or ENTITY_KIND_CASE
                updated_incident["rawJSON"] = json.dumps(updated_incident)

                if FETCH_ALERTS_FOR_CASE:
                    try:
                        alerts_resp = kibana_http_request(
                            "GET", f"/api/cases/{remote_id}/alerts", proxies=proxies, allow_not_found=True
                        )
                        if alerts_resp:
                            updated_incident["_alerts"] = alerts_resp
                    except Exception as e:
                        demisto.debug(f"Failed to fetch alerts for case {remote_id}: {e}")

                if CLOSE_INCIDENT and case_status == "closed":
                    close_reason = response.get("closeReason") or "other"
                    xsoar_reason = ELASTIC_CLOSE_REASON_TO_XSOAR.get(close_reason, "other")
                    entries.append(
                        {
                            "Type": EntryType.NOTE,
                            "Contents": {
                                "dbotIncidentClose": True,
                                "closeReason": xsoar_reason,
                                "closeNotes": f"Closed by Elasticsearch mirroring. Reason: {close_reason}",
                            },
                            "ContentsFormat": EntryFormat.JSON,
                        }
                    )
        except Exception as e:
            if _is_rate_limit_error(e):
                # Return an error with "API rate limit" so the sync loop restarts from this incident.
                return_error(f"API rate limit reached while fetching case {remote_id}. Error: {e}")
            demisto.debug(f"Failed to fetch case {remote_id}: {e}")

    # Re-assert the mirror instance on every incoming sync (self-healing), but only when there is
    # already something to update, to avoid forcing spurious incident updates.
    if updated_incident:
        updated_incident["dbotMirrorInstance"] = demisto.integrationInstance()
        mirror_debug(f"get-remote-data returning {len(updated_incident)} field(s) and {len(entries)} entry/entries.")
    else:
        mirror_debug("get-remote-data found no changes; returning an empty mirrored object.")

    return GetRemoteDataResponse(mirrored_object=updated_incident, entries=entries)


def update_remote_system_command(args: Dict[str, Any], proxies: dict) -> str:
    """Mirroring-out: pushes local XSOAR incident changes back to Elasticsearch/Kibana."""
    parsed_args = UpdateRemoteSystemArgs(args)
    remote_id = parsed_args.remote_incident_id
    delta = parsed_args.delta or {}
    inc_status = parsed_args.inc_status
    entries = parsed_args.entries or []

    # The type is resolved from the local incident (falling back to the remote lookup and finally
    # the instance configuration), since the mapper output does not carry "type".
    incident_type = (
        get_incident_type()
        or (parsed_args.data or {}).get("type", "")
        or resolve_remote_incident_type(remote_id, proxies)
        or get_configured_fetch_incident_type()
    )

    mirror_debug(
        f"update-remote-system called for id={remote_id}, type={incident_type}, status={inc_status}, "
        f"incident_changed={parsed_args.incident_changed}, delta_keys={list(delta.keys())}, entries={len(entries)}"
    )

    if not remote_id:
        mirror_debug("No remote_id provided, skipping update.")
        return remote_id or ""

    if incident_type == INCIDENT_TYPE_SECURITY_ALERT:
        if parsed_args.incident_changed:
            _mirror_out_security_alert(remote_id, delta, inc_status, proxies)
        else:
            mirror_debug(f"Security alert {remote_id} unchanged, nothing to mirror out.")

    elif incident_type == INCIDENT_TYPE_CASE:
        if parsed_args.incident_changed:
            _mirror_out_case(remote_id, delta, inc_status, proxies, parsed_args.data or {})
        else:
            mirror_debug(f"Case {remote_id} unchanged, only entries will be mirrored out.")
        _mirror_out_case_entries(remote_id, entries, proxies)

    else:
        mirror_error(
            f"Unexpected incident type {incident_type!r} for remote id {remote_id} - nothing was mirrored out. "
            f"Available mapper output keys: {list((parsed_args.data or {}).keys())}. "
            f"Set the 'Fetch incident types' parameter to {INCIDENT_TYPE_SECURITY_ALERT!r} or {INCIDENT_TYPE_CASE!r} "
            "so the type can be resolved even when the remote lookup fails."
        )

    return remote_id


def _mirror_out_case_entries(remote_id: str, entries: List[dict], proxies: dict) -> None:
    """Mirrors tagged War Room entries out to Elasticsearch as Kibana case comments."""
    for entry in entries:
        tags = entry.get("Tags") or []
        if "comment" not in tags:
            mirror_debug(f"Entry {entry.get('ID')} has no mirror tag, skipping.")
            continue

        contents = entry.get("Contents", "")
        comment = contents if isinstance(contents, str) else json.dumps(contents)
        if not comment:
            mirror_debug(f"Entry {entry.get('ID')} has empty contents, skipping.")
            continue

        try:
            kibana_http_request(
                "POST",
                f"/api/cases/{remote_id}/comments",
                json_data={"type": "user", "comment": comment, "owner": "cases"},
                proxies=proxies,
            )
            mirror_debug(f"Mirrored entry {entry.get('ID')} to case {remote_id} as a comment.")
        except Exception as e:
            mirror_error(f"Failed to mirror entry {entry.get('ID')} to case {remote_id}: {e}")


def _mirror_out_security_alert(
    remote_id: str,
    delta: Dict[str, Any],
    inc_status: Optional[int],
    proxies,
) -> None:
    """Pushes a Security Alert incident's status/reason/tags changes back to Kibana.

    Writes go through Kibana (not the Elasticsearch client) because the alert indices are Kibana
    system indices; a direct write would skip Kibana bookkeeping and break mirroring-in.
    """
    new_status = delta.get("status")
    new_reason = delta.get("reason")
    new_tags = delta.get("tags")

    mirror_debug(
        f"_mirror_out_security_alert {remote_id}: status={new_status}, reason={new_reason}, "
        f"tags={new_tags}, inc_status={inc_status}"
    )

    is_closing = is_incident_closing(inc_status, delta)

    # Kibana can only change status/reason/tags on a detection alert; any other edited field is
    # dropped by the mapper and cannot be mirrored out.
    if new_status is None and new_reason is None and new_tags is None and not is_closing:
        mirror_error(
            f"Nothing to mirror out for alert {remote_id}: the change contains none of the fields "
            f"Elasticsearch accepts for a detection alert ({MIRRORABLE_ALERT_FIELDS}). Fields such as "
            "severity cannot be pushed back to Elasticsearch - only the workflow status, its reason "
            f"and the workflow tags are mirrored out. Received delta keys: {list(delta.keys())}."
        )
        return

    if is_closing and not CLOSE_ELASTIC_INCIDENT:
        mirror_debug(
            f"Alert {remote_id} incident was closed but 'Close Mirrored Elasticsearch Incident' is "
            "disabled, so the alert status is left unchanged."
        )

    if CLOSE_ELASTIC_INCIDENT and is_closing:
        new_status = new_status or "closed"
        # Translate the XSOAR close reason into Kibana's vocabulary.
        xsoar_close_reason = delta.get("closeReason") or delta.get("closeNotes")
        new_reason = new_reason or XSOAR_CLOSE_REASON_TO_ELASTIC.get(str(xsoar_close_reason), "other")

    if new_status:
        try:
            # Update by query (matching either identifier) rather than signal_ids, which only
            # matches the document _id and would silently update nothing when a UUID is stored.
            body: Dict[str, Any] = {
                "status": new_status,
                "query": build_alert_lookup_body(remote_id)["query"],
            }
            if new_reason:
                body["reason"] = new_reason
            response = kibana_http_request(
                "POST",
                "/api/detection_engine/signals/status",
                json_data=body,
                proxies=proxies,
            )
            updated = (response or {}).get("updated") if isinstance(response, dict) else None
            if updated == 0:
                mirror_error(
                    f"Elasticsearch reported 0 alerts updated for {remote_id}; the status was NOT changed. "
                    "The alert may live in an index this user cannot write to, or the remote ID no longer exists."
                )
            else:
                mirror_debug(f"Updated alert {remote_id} status to {new_status} (updated={updated}).")
        except Exception as e:
            mirror_error(f"Failed to update alert status for {remote_id}: {e}")

    if new_tags is not None:
        try:
            search_resp = search_security_alerts(build_alert_lookup_body(remote_id), proxies)
            hits = (search_resp or {}).get("hits", {}).get("hits", []) if isinstance(search_resp, dict) else []
            current_tags: List[str] = []
            if hits:
                current_tags = get_alert_source_value(hits[0].get("_source", {}), "kibana.alert.workflow_tags") or []
            else:
                mirror_error(
                    f"Alert {remote_id} was not found, so its tags cannot be updated. "
                    "Verify the remote ID still exists and is readable by this user."
                )

            new_tags_list = argToList(new_tags)
            tags_to_add = [t for t in new_tags_list if t not in current_tags]
            tags_to_remove = [t for t in current_tags if t not in new_tags_list]

            if hits and (tags_to_add or tags_to_remove):
                # The tags API addresses alerts by document _id, so use the fetched hit's _id.
                document_id = hits[0].get("_id") or remote_id
                tags_body: Dict[str, Any] = {
                    "ids": [document_id],
                    "tags": {"tags_to_add": tags_to_add, "tags_to_remove": tags_to_remove},
                }
                kibana_http_request(
                    "POST",
                    "/api/detection_engine/signals/tags",
                    json_data=tags_body,
                    proxies=proxies,
                )
                mirror_debug(f"Updated tags for alert {remote_id}: add={tags_to_add}, remove={tags_to_remove}")
        except Exception as e:
            mirror_error(f"Failed to update tags for alert {remote_id}: {e}")


def _mirror_out_case(
    remote_id: str,
    delta: Dict[str, Any],
    inc_status: Optional[int],
    proxies,
    incident_data: Dict[str, Any],
) -> None:
    """Pushes a Case incident's field changes back to Kibana, optionally closing it and its alerts."""
    # The current case is needed for the version required by the PATCH API.
    try:
        current_case = kibana_http_request("GET", f"/api/cases/{remote_id}", proxies=proxies, allow_not_found=True)
    except Exception as e:
        mirror_error(f"Failed to fetch case {remote_id} for update: {e}")
        return

    if not current_case:
        mirror_debug(f"Case {remote_id} not found in Elasticsearch, skipping update.")
        return

    version = current_case.get("version")
    if not version:
        mirror_debug(f"No version found for case {remote_id}, skipping update.")
        return

    case_fields: Dict[str, Any] = {"id": remote_id, "version": version}

    # delta keys are already Kibana Cases API field names; forward only the accepted ones.
    supported_kibana_fields = ("title", "description", "severity", "status", "tags")
    for kibana_field in supported_kibana_fields:
        if kibana_field in delta:
            case_fields[kibana_field] = delta[kibana_field]

    # The Cases API expects a severity name, not the XSOAR numeric value.
    if "severity" in case_fields:
        elastic_severity = convert_severity_to_elastic(case_fields["severity"])
        if elastic_severity:
            case_fields["severity"] = elastic_severity
        else:
            mirror_debug(f"Dropping unmappable severity {case_fields['severity']!r} for case {remote_id}.")
            case_fields.pop("severity")

    is_closing = CLOSE_ELASTIC_INCIDENT and is_incident_closing(inc_status, delta)
    if is_closing:
        case_fields["status"] = "closed"
        case_fields["closeReason"] = delta.get("closeReason") or incident_data.get("closeReason") or "other"

    if len(case_fields) > 2:  # more than just id + version
        try:
            kibana_http_request(
                "PATCH",
                "/api/cases",
                json_data={"cases": [case_fields]},
                proxies=proxies,
            )
            mirror_debug(f"Updated case {remote_id} with fields: {list(case_fields.keys())}")
        except Exception as e:
            mirror_error(f"Failed to update case {remote_id}: {e}")
    else:
        mirror_debug(f"No supported case fields changed for {remote_id}; delta keys were {list(delta.keys())}.")

    if is_closing:
        try:
            alerts_resp = kibana_http_request("GET", f"/api/cases/{remote_id}/alerts", proxies=proxies, allow_not_found=True)
            alert_ids = [a.get("id") for a in (alerts_resp or []) if a.get("id")]
            if alert_ids:
                kibana_http_request(
                    "POST",
                    "/api/detection_engine/signals/status",
                    json_data={"signal_ids": alert_ids, "status": "closed"},
                    proxies=proxies,
                )
                demisto.debug(f"Closed {len(alert_ids)} alerts related to case {remote_id}")
        except Exception as e:
            demisto.debug(f"Failed to close alerts for case {remote_id}: {e}")


def _is_rate_limit_error(error: Exception) -> bool:
    """Returns True if the given error represents an API rate limit (HTTP 429)."""
    message = str(error).lower()
    return "429" in message or "rate limit" in message or "too many requests" in message


# Maximum number of modified alerts/cases pulled per sync run.
MODIFIED_PAGE_SIZE = 100

# Timestamp fields that indicate a security alert changed. All are listed because no single field
# covers every change type (e.g. updated_at is the only one that moves on a tag-only edit). A range
# query against a missing field simply does not match, so a broad `should` is safe.
ALERT_MODIFICATION_TIME_FIELDS = (
    "kibana.alert.updated_at",
    "kibana.alert.workflow_status_updated_at",
    "kibana.alert.last_detected",
    "@timestamp",
)


def parse_to_utc(value: Any) -> Optional[datetime]:
    """Parses a timestamp into a timezone-aware datetime (for total comparisons), or None."""
    if not value:
        return None
    parsed = dateparser.parse(str(value), settings={"RETURN_AS_TIMEZONE_AWARE": True})
    # dateparser can still return a naive datetime for some inputs; force UTC so callers can
    # always perform timezone-aware comparisons without raising a TypeError.
    if parsed and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _get_modified_alert_ids(last_update: str, proxies: dict) -> List[str]:
    """Returns the UUIDs of security alerts modified since ``last_update``."""
    if not last_update:
        # Without a cursor there is nothing meaningful to filter on; {"gte": ""} is also rejected.
        mirror_debug("No lastUpdate provided; skipping the modified-alerts lookup.")
        return []

    body: Dict[str, Any] = {
        "query": {
            "bool": {
                "should": [{"range": {field: {"gte": last_update}}} for field in ALERT_MODIFICATION_TIME_FIELDS],
                "minimum_should_match": 1,
            }
        },
        "size": MODIFIED_PAGE_SIZE,
        # Oldest-first so truncation at MODIFIED_PAGE_SIZE is deterministic (dropped hits are
        # picked up on a later sync).
        "sort": [{"@timestamp": {"order": "asc"}}],
        # Full _source is required: source filtering on flat dotted keys breaks the UUID lookup
        # below, which must match the dbotMirrorId stored by fetch_security_alerts.
        "_source": True,
    }
    # Errors are not swallowed here - a failure must surface rather than look like "nothing changed".
    response = search_security_alerts(body, proxies)

    hits = (response or {}).get("hits", {}).get("hits", []) if isinstance(response, dict) else []
    mirror_debug(f"get-modified-remote-data fetched {len(hits)} modified security alert(s).")

    alert_ids: List[str] = []
    fell_back_to_doc_id = 0
    for hit in hits:
        source = hit.get("_source", {})
        # Fall back to _id like fetch_security_alerts, so the IDs match the stored dbotMirrorId.
        alert_uuid = get_alert_source_value(source, "kibana.alert.uuid")
        if not alert_uuid:
            alert_uuid = hit.get("_id")
            fell_back_to_doc_id += 1
        if alert_uuid:
            alert_ids.append(str(alert_uuid))
        else:
            mirror_debug(f"Skipping modified alert hit without a resolvable ID: {hit.get('_index')}")

    if fell_back_to_doc_id:
        mirror_debug(
            f"{fell_back_to_doc_id} of {len(hits)} modified alert(s) fell back to the document _id; "
            "these will not match incidents ingested with a UUID."
        )

    if hits and not alert_ids:
        mirror_error(
            f"Fetched {len(hits)} modified alert(s) but could not resolve an ID from any of them - "
            "no updates will be mirrored in. This usually means the alert documents have an unexpected shape."
        )

    return alert_ids


def _get_modified_case_ids(last_update: str, proxies: dict) -> List[str]:
    """Returns the IDs of Kibana cases modified since ``last_update``."""
    last_update_dt = parse_to_utc(last_update)
    if not last_update_dt:
        mirror_debug(f"Could not parse lastUpdate {last_update!r}; skipping the modified-cases lookup.")
        return []

    params: Dict[str, Any] = {
        "perPage": MODIFIED_PAGE_SIZE,
        "sortField": "updatedAt",
        "sortOrder": "desc",
    }
    response = kibana_http_request("GET", "/api/cases/_find", params=params, proxies=proxies)
    cases = (response or {}).get("cases", []) if isinstance(response, dict) else []

    case_ids: List[str] = []
    for case in cases:
        case_id = case.get("id")
        updated_at = parse_to_utc(case.get("updated_at"))
        if not updated_at:
            mirror_debug(f"Case {case_id} has an unparsable updated_at {case.get('updated_at')!r}; skipping.")
            continue
        if updated_at > last_update_dt and case_id:
            case_ids.append(str(case_id))

    mirror_debug(f"get-modified-remote-data found {len(case_ids)} modified case(s) out of {len(cases)} returned.")
    return case_ids


def get_modified_remote_data_command(args: Dict[str, Any], proxies: dict) -> GetModifiedRemoteDataResponse:
    """Returns the remote IDs of alerts/cases modified since lastUpdate, for XSOAR to pull."""
    last_update = args.get("lastUpdate", "")
    mirror_debug(f"get-modified-remote-data called with lastUpdate={last_update}")

    modified_ids: List[str] = []

    try:
        modified_ids.extend(_get_modified_alert_ids(last_update, proxies))
    except Exception as e:
        if _is_rate_limit_error(e):
            # Signal the server to stop the sync loop and skip the get-remote-data run.
            return_error(f"API rate limit reached while fetching modified alerts, skip update. Error: {e}", error=e)
        mirror_error(f"Failed to fetch modified security alerts: {e}")

    try:
        modified_ids.extend(_get_modified_case_ids(last_update, proxies))
    except Exception as e:
        if _is_rate_limit_error(e):
            # Signal the server to stop the sync loop and skip the get-remote-data run.
            return_error(f"API rate limit reached while fetching modified cases, skip update. Error: {e}", error=e)
        mirror_error(f"Failed to fetch modified cases: {e}")

    # The same ID can legitimately be reported by both lookups; XSOAR would then sync it twice.
    deduped_ids = list(dict.fromkeys(modified_ids))

    mirror_debug(f"get-modified-remote-data returning {len(deduped_ids)} modified ID(s): {deduped_ids}")
    return GetModifiedRemoteDataResponse(deduped_ids)


def main():  # pragma: no cover
    proxies = handle_proxy() or {}
    args = demisto.args()
    try:
        LOG(f"command is {demisto.command()}")
        if demisto.command() == "test-module":
            return_results(test_func(proxies))
        elif demisto.command() == "fetch-incidents":
            fetch_incident_type = PARAMS.get("fetch_incident_type") or PARAMS.get("incidentType", "")
            if fetch_incident_type == INCIDENT_TYPE_SECURITY_ALERT:
                demisto.incidents(fetch_security_alerts(proxies))
            elif fetch_incident_type == INCIDENT_TYPE_CASE:
                demisto.incidents(fetch_cases(proxies))
            else:
                fetch_incidents(proxies)
        elif demisto.command() == "get-remote-data":
            return_results(get_remote_data_command(args, proxies))
        elif demisto.command() == "update-remote-system":
            return_results(update_remote_system_command(args, proxies))
        elif demisto.command() == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(args, proxies))
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
