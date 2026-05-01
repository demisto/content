register_module_line("Kibana", "start", __line__())
CONSTANT_PACK_VERSION = "1.4.1"
demisto.debug("pack id = CommunityElasticsearch, pack version = 1.4.1")

"""IMPORTS"""
import requests
import json
from datetime import datetime

"""Parameters"""
PARAMS = demisto.params()
AUTH_TYPE = PARAMS.get("auth_type", "Basic auth")
USERNAME: str = PARAMS.get("credentials", {}).get("identifier")
PASSWORD: str = PARAMS.get("credentials", {}).get("password")
AUTH = (USERNAME, PASSWORD)
API_KEY_ID: str = PARAMS.get("api_key_auth_credentials", {}).get("identifier")
API_KEY_SECRET: str = PARAMS.get("api_key_auth_credentials", {}).get("password")
API_KEY = None
ES_DEFAULT_DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss.SSSSSS"
PYTHON_DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
PROXY = PARAMS.get("proxy")
ELASTIC_SERVER = PARAMS.get("url", "").rstrip("/") + ":" + PARAMS.get("elastic_port")  ### change test func to use kibana_server
KIBANA_SERVER = PARAMS.get("url", "").rstrip("/") + ":" + PARAMS.get("kibana_port")
INSECURE = not PARAMS.get("insecure", False)
TIMEOUT = int(PARAMS.get("timeout") or 60)

# .ymla values
BASIC_AUTH = "Basic auth"
BEARER_AUTH = "Bearer auth"
API_KEY_AUTH = "API key auth"
API_KEY_PREFIX = "_api_key_id:"

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
    from opensearchpy import RequestsHttpConnection
    from opensearchpy import OpenSearch as Elasticsearch
elif ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, ELASTICSEARCH_V9]:
    from elastic_transport import RequestsHttpNode
    from elasticsearch import Elasticsearch  # type: ignore[assignment]
else:  # Elasticsearch (<= v7)
    from elasticsearch7 import Elasticsearch, RequestsHttpConnection  # type: ignore[assignment,misc]

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
        url = urljoin(ELASTIC_SERVER, "_security/oauth2/token")
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
        "hosts": [ELASTIC_SERVER],
        "verify_certs": INSECURE,
        "timeout": TIMEOUT,
    }
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


def http_request(method, url_suffix, headers, auth=AUTH, params=None, data=None, files=None, safe=False, parse_json=True):
    """
    A wrapper for requests lib to send our requests and handle requests and responses better.

    :type method: ``str``
    :param method: HTTP method for the request.

    :type url_suffix: ``str``
    :param url_suffix: The suffix of the URL (endpoint)

    :type params: ``dict``
    :param params: The URL params to be passed.

    :type data: ``dict``
    :param data: The body data of the request.

    :type headers: ``dict``
    :param headers: Request headers

    :type safe: ``bool``
    :param safe: If set to true will return None in case of error

    :return: Returns the http request response json
    :rtype: ``dict`` or ``str``
    """
    url = KIBANA_SERVER + url_suffix
    try:
        res = requests.request(
            method,
            url,
            auth=auth,
            verify=INSECURE,
            params=params,
            json=data,
            files=files,
            headers=headers,
        )
    except requests.exceptions.RequestException as e:
        LOG(str(e))
        return_error("Error in connection to the server. Please make sure you entered the URL correctly.")
    # Handle error responses gracefully

    if res.status_code not in {200, 201}:
        if safe:
            return None
        elif res.status_code == 401:
            reason = "Unauthorized. Please check your API token"
        elif res.status_code == 204:
            return None
        else:
            try:
                reason = res.json()
            except ValueError:
                reason = res.reason
        return_error(f"Error in API call status code: {res.status_code}, reason: {reason}")
    if parse_json:
        return res.json()
    return res.content


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
    return "ok"


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
            res = requests.get(ELASTIC_SERVER, auth=(USERNAME, PASSWORD), verify=INSECURE, headers=headers)

        elif AUTH_TYPE == API_KEY_AUTH:
            demisto.debug("test_connectivity_auth - API key auth setting authorization header and sending request")
            headers["authorization"] = get_api_key_header_val(API_KEY)
            res = requests.get(ELASTIC_SERVER, verify=INSECURE, headers=headers)

        elif AUTH_TYPE == BEARER_AUTH:
            demisto.debug("test_connectivity_auth - Bearer auth setting authorization header and sending request")
            headers["Authorization"] = f"Bearer {get_elastic_token()}"
            res = requests.get(ELASTIC_SERVER, verify=INSECURE, headers=headers)

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


def kibana_find_cases(args, proxies):
    """
    Returns information on the cases in Kibana.
    API reference: https://www.elastic.co/docs/api/doc/kibana/operation/operation-findcasesdefaultspace
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    status = args.get("status")
    severity = args.get("severity")
    from_time = args.get("from_time")

    query_params = {"status": status, "severity": severity, "from": from_time}

    response = http_request(method="GET", url_suffix="/api/cases/_find", params=query_params, headers=headers)
    json_data = response["cases"]

    # output results to markdown table
    md = tableToMarkdown("Kibana Cases", json_data, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Cases", outputs=json_data)

    return result


def kibana_find_alerts_for_case(args, proxies):
    """
    Returns information on the alerts of a case in Kibana.
    API reference: https://www.elastic.co/docs/api/doc/kibana/operation/operation-getcasealertsdefaultspace
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    case_id = args.get("case_id")

    response = http_request(method="GET", url_suffix=f"/api/cases/{case_id}/alerts", headers=headers)

    # output results to markdown table
    md = tableToMarkdown("Kibana Alerts For Case", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Alerts.For.Case", outputs=response)

    return result


def kibana_update_alert_status(args, proxies):
    """
    Update status of input alert in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-setalertsstatus
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    alert_id = args.get("alert_id")
    status = args.get("status")

    data = {
        "status": status,
        "signal_ids": [
            alert_id,
        ],
    }

    response = http_request(method="POST", url_suffix="/api/detection_engine/signals/status", data=data, headers=headers)

    return f"Updated alert ID {alert_id} to status of {status}"


def kibana_update_case_status(args, proxies):
    """
    Update status of input case in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-updatecasedefaultspace
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    case_id = args.get("case_id")
    status = args.get("status")
    version = args.get("version_id")

    data = {"cases": [{"id": case_id, "status": status, "version": version}]}

    response = http_request(method="PATCH", url_suffix="/api/cases", data=data, headers=headers)

    # output results to markdown table
    md = tableToMarkdown("Kibana Updated Case Status", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Updated.Case.Status", outputs=response)

    return result


def kibana_find_user_spaces(args, proxies):
    """
    Get list of user spaces in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-spaces-space
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    response = http_request(method="GET", url_suffix="/api/spaces/space", headers=headers)

    # output results to markdown table
    md = tableToMarkdown("Kibana User Spaces", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.User.Spaces", outputs=response)

    return result


def kibana_find_case_comments(args, proxies):
    """
    Get list of comments for a case in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-findcasecommentsdefaultspace
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    case_id = args.get("case_id")

    response = http_request(method="GET", url_suffix=f"/api/cases/{case_id}/comments/_find", headers=headers)
    response = response["comments"]

    # output results to markdown table
    md = tableToMarkdown("Kibana Case Comments", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Case.Comments", outputs=response)

    return result


def kibana_delete_case(args, proxies):
    """
    Delete case in Kibana based on input case ID.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-deletecasedefaultspace
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    case_id = args.get("case_id")
    case_id = '["' + case_id + '"]'
    case_list = []
    case_list.append(case_id)

    params = {"ids": case_list}

    response = http_request(method="DELETE", url_suffix="/api/cases", params=params, headers=headers)

    return f"Successfully deleted case with ID of {case_id}"


def kibana_delete_rule(args, proxies):
    """
    Delete rule in Kibana based on input rule ID.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-delete-alerting-rule-id
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    rule_id = args.get("rule_id")

    response = http_request(method="DELETE", url_suffix=f"/api/alerting/rule/{rule_id}", headers=headers)

    return f"Successfully deleted rule with ID of {rule_id}"


def kibana_search_rule_details(args, proxies):
    """
    Retrieve details about detection rule in Kibana based on input KQL filter.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-alerting-rules-find
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    kql_query = args.get("kql_query")

    params = {"filter": kql_query}

    response = http_request(method="GET", url_suffix="/api/alerting/rules/_find", params=params, headers=headers)
    response = response["data"]

    # output results to markdown table
    md = tableToMarkdown("Kibana Rule Details", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Rule.Details", outputs=response)

    return result


def kibana_add_case_comment(args, proxies):
    """
    Add comment to case in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-addcasecommentdefaultspace
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    case_id = args.get("case_id")
    case_owner = args.get("case_owner")
    comment = args.get("comment")

    json_data = {
        "type": "user",
        "owner": case_owner,
        "comment": comment,
    }

    response = http_request(method="POST", url_suffix=f"/api/cases/{case_id}/comments", data=json_data, headers=headers)
    updated_at = response["updated_at"]

    return f"Case comment updated at {updated_at}"


def kibana_get_user_list(args, proxies):
    """
    Search for a list of all users and UIDs in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-query-user
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    es = elasticsearch_builder(proxies)

    try:
        all_users = es.security.query_user(with_profile_uid=True, size=100)
        all_users = all_users.body["users"]

        # output results to markdown table
        md = tableToMarkdown("Kibana User List", all_users, headers=[])

        result = CommandResults(readable_output=md, outputs_prefix="Kibana.User.List", outputs=all_users)

        return result

    except Exception as e:
        return f"Error querying all users: {e}"


def kibana_assign_alert_user(args, proxies):
    """
    Assign user to input alert in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-setalertassignees
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    alert_id = args.get("alert_id")
    user_id = args.get("user_id")

    json_data = {
        "ids": [
            alert_id,
        ],
        "assignees": {
            "add": [
                user_id,
            ],
            "remove": [],
        },
    }

    response = http_request(method="POST", url_suffix="/api/detection_engine/signals/assignees", data=json_data, headers=headers)

    return f"Assigned user ID {user_id} to alert {alert_id}"


def kibana_list_detection_alerts(args, proxies):
    """
    List detection alerts in Kibana matching a status filter.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-searchalerts
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    alert_status = args.get("alert_status")

    json_data = {
        "query": {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "must": [],
                            "filter": [
                                {
                                    "match_phrase": {
                                        "kibana.alert.workflow_status": alert_status,
                                    },
                                },
                            ],
                        },
                    },
                ],
            },
        },
        "runtime_mappings": {},
    }

    response = http_request(method="POST", url_suffix="/api/detection_engine/signals/search", data=json_data, headers=headers)

    result_json = response["hits"]
    result_list = result_json.get("hits")
    result_list_final = []

    # append each _source dict in list of dicts to a final results list
    for item in result_list:
        result_list_final.append(item.get("_source"))

    # output results to markdown table
    md = tableToMarkdown("Kibana Detection Alerts", result_list_final, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Detection.Alerts", outputs=result_list_final)

    return result


def kibana_add_alert_note(args, proxies):
    """
    Add note to detection alerts in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-persistnoteroute
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    event_id = args.get("alert_id")
    note = args.get("note")

    url = f"{KIBANA_SERVER}/api/note"

    json_data = {
        "note": {
            "eventId": event_id,
            "note": note,
            "timelineId": "",
        },
    }

    response = http_request(method="PATCH", url_suffix="/api/note", data=json_data, headers=headers)

    return f"Added note {note} to alert {event_id}"


def kibana_get_alerting_health(args, proxies):
    """
    Get alerting framework health in Kibana.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-getalertinghealth
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    response = http_request(method="GET", url_suffix="/api/alerting/_health", headers=headers)

    # output results to markdown table
    md = tableToMarkdown("Alerting Framework Health", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Alerting.Framework.Health", outputs=response)

    return result


def kibana_disable_alert_rule(args, proxies):
    """
    Used to disable a rule used for detection alerting. Clears all associated alerts from active alerts page.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-alerting-rule-id-disable
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    rule_id = args.get("rule_id")

    json_data = {
        "untrack": True,
    }

    response = http_request(method="POST", url_suffix=f"/api/alerting/rule/{rule_id}/_disable", data=json_data, headers=headers)

    return f"Successfully disabled rule with ID of {rule_id}"


def kibana_enable_alert_rule(args, proxies):
    """
    Used to enable a rule used for detection alerting.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-alerting-rule-id-enable
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    rule_id = args.get("rule_id")

    response = http_request(method="POST", url_suffix=f"/api/alerting/rule/{rule_id}/_enable", headers=headers)

    return f"Successfully enabled rule with ID of {rule_id}"


def kibana_get_exception_lists(args, proxies):
    """
    Used to get a list of all exception list containers.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-findexceptionlists
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    response = http_request(method="GET", url_suffix="/api/exception_lists/_find", headers=headers)
    response = response["data"]

    # output results to markdown table
    md = tableToMarkdown("Kibana Exception Lists", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Exception.Lists", outputs=response)

    return result


def kibana_create_value_list(args, proxies):
    """
    Used to create a value list in Kibana Detection Rules menu.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-createlist
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    description = args.get("description")
    list_id = args.get("list_id")
    name = args.get("name")
    data_type = args.get("data_type")

    json_data = {
        "id": list_id,
        "name": name,
        "type": data_type,
        "description": description,
    }

    response = http_request(method="POST", url_suffix="/api/lists", data=json_data, headers=headers)

    return f"Successfully created value list with name of {name}"


def kibana_get_value_lists(args, proxies):
    """
    Used to find all value lists in Kibana Detection Rules menu.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-findlists
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    response = http_request(method="GET", url_suffix="/api/lists/_find", headers=headers)
    result_json = response["data"]

    # output results to markdown table
    md = tableToMarkdown("Alerting Value Lists", result_json, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Alerting.Value.Lists", outputs=result_json)

    return result


def kibana_import_value_list_items(args, proxies):
    """
    Used to import value list items from a TXT file.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-importlistitems
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    list_id = args.get("list_id")
    file_content = args.get("file_content")

    json_data = {
        "list_id": list_id,
    }

    files = {"file": ("value_list.txt", file_content, "text/plain")}

    response = http_request(method="POST", url_suffix="/api/lists/items/_import", params=json_data, files=files, headers=headers)

    return f"Successfully imported {file_content} to value list with ID of {list_id}"


def kibana_create_value_list_item(args, proxies):
    """
    Used to create a value list item and associate it with the specified value list.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-createlistitem
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    list_id = args.get("list_id")
    new_item = args.get("new_value_list_item")

    json_data = {"value": new_item, "list_id": list_id}

    response = http_request(method="POST", url_suffix="/api/lists/items", data=json_data, headers=headers)

    return f"Successfully added {new_item} to value list with ID of {list_id}"


def kibana_get_value_list_items(args, proxies):
    """
    Used to display entries in an input value list.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-findlistitems
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    list_id = args.get("list_id")
    result_size = args.get("result_size")

    params = {"list_id": list_id, "sort_field": "created_at", "sort_order": "asc", "per_page": result_size}

    response = http_request(method="GET", url_suffix="/api/lists/items/_find", params=params, headers=headers)
    result_output = response["data"]

    # output results to markdown table
    md = tableToMarkdown("Value List Items", result_output, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Value.List.Items", outputs=result_output)

    return result


def kibana_delete_value_list_item(args, proxies):
    """
    Used to delete a value list item given the item ID as input.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-deletelistitem
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
        "Content-Type": "application/json",
    }

    item_id = args.get("item_id")
    list_id = args.get("list_id")

    json_data = {"id": item_id, "list_id": list_id}

    response = http_request(method="DELETE", url_suffix="/api/lists/items", params=json_data, headers=headers)

    return f"Successfully deleted {item_id} from value list with ID of {list_id}"


def kibana_delete_value_list(args, proxies):
    """
    Used to delete a value list given the list ID as input.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-deletelist
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
        "Content-Type": "application/json",
    }

    list_id = args.get("list_id")

    params = {"id": list_id}

    response = http_request(method="DELETE", url_suffix="/api/lists", params=params, headers=headers)

    return f"Successfully deleted value list with ID of {list_id}"


def kibana_get_status(args, proxies):
    """
    Used to check Kibana's operational status.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-status
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    response = http_request(method="GET", url_suffix="/api/status", headers=headers)
    response = response["status"]

    # output results to markdown table
    md = tableToMarkdown("Kibana Operational Status", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Operational.Status", outputs=response)

    return result


def kibana_get_task_manager_health(args, proxies):
    """
    Get the health status of the Kibana task manager.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-task-manager-health
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    response = http_request(method="GET", url_suffix="/api/task_manager/_health", headers=headers)
    response = response["stats"]

    # output results to markdown table
    md = tableToMarkdown("Kibana Task Manager Health", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Task.Manager.Health", outputs=response)

    return result


def kibana_get_upgrade_readiness_status(args, proxies):
    """
    Check the upgrade readiness status of your cluster.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-upgrade-status
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    response = http_request(method="GET", url_suffix="/api/upgrade_assistant/status", headers=headers)

    # output results to markdown table
    md = tableToMarkdown("Kibana Upgrade Readiness Status", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Upgrade.Readiness.Status", outputs=response)

    return result


def kibana_delete_case_comment(args, proxies):
    """
    Delete a case comment.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-deletecasecommentdefaultspace
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    case_id = args.get("case_id")
    comment_id = args.get("comment_id")

    response = http_request(method="DELETE", url_suffix=f"/api/cases/{case_id}/comments/{comment_id}", headers=headers)

    return f"Deleted comment with ID {comment_id} from case {case_id}"


def kibana_add_file_to_case(args, proxies):
    """
    Attach a file to a case.
    Reference - https://www.elastic.co/docs/api/doc/kibana/operation/operation-addcasefiledefaultspace
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    case_id = args.get("case_id")
    file_id = args.get("file_id")

    file_path_dict = demisto.getFilePath(file_id)
    file_path = file_path_dict["path"]
    file_name = file_path_dict["name"]

    with open(file_path, "rb") as f:
        files = {"file": (file_name, f)}

        response = http_request(method="POST", url_suffix=f"/api/cases/{case_id}/files", files=files, headers=headers)
        return f"Successfully added file {file_name} to case {case_id}"


def kibana_get_user_by_email(args, proxies):
    """
    Search for a single user's UID in Kibana by email address filter.
    Reference - https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-query-user
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    email_wildcard = args.get("email_wildcard")

    es = elasticsearch_builder(proxies)

    query_body = {"query": {"wildcard": {"email": {"value": email_wildcard, "case_insensitive": True}}}}

    try:
        user_data = es.security.query_user(with_profile_uid=True, body=query_body)
        user_data = user_data["users"]

        # output results to markdown table
        md = tableToMarkdown("Kibana User Data", user_data, headers=[])

        result = CommandResults(readable_output=md, outputs_prefix="Kibana.User.Data", outputs=user_data)

        return result

    except Exception as e:
        return f"Error querying all users: {e}"


def kibana_get_case_information(args, proxies):
    """
    Retrieve information for a specific case in Kibana.
    API reference: https://www.elastic.co/docs/api/doc/kibana/operation/operation-getcasedefaultspace
    """
    headers = {
        "kbn-xsrf": "true",  # Required for Kibana API requests
    }

    case_id = args.get("case_id")

    response = http_request(method="GET", url_suffix=f"/api/cases/{case_id}", headers=headers)

    # output results to markdown table
    md = tableToMarkdown("Kibana Case Info", response, headers=[])

    result = CommandResults(readable_output=md, outputs_prefix="Kibana.Case.Info", outputs=response)

    return result


def main():  # pragma: no cover
    proxies = handle_proxy()
    proxies = proxies if proxies else None
    args = demisto.args()
    try:
        LOG(f"command is {demisto.command()}")
        if demisto.command() == "test-module":
            return_results(test_func(proxies))
        elif demisto.command() == "kibana-cases-find":
            return_results(kibana_find_cases(args, proxies))
        elif demisto.command() == "kibana-case-alerts-find":
            return_results(kibana_find_alerts_for_case(args, proxies))
        elif demisto.command() == "kibana-alert-status-update":
            return_results(kibana_update_alert_status(args, proxies))
        elif demisto.command() == "kibana-case-status-update":
            return_results(kibana_update_case_status(args, proxies))
        elif demisto.command() == "kibana-user-spaces-find":
            return_results(kibana_find_user_spaces(args, proxies))
        elif demisto.command() == "kibana-case-comments-find":
            return_results(kibana_find_case_comments(args, proxies))
        elif demisto.command() == "kibana-case-delete":
            return_results(kibana_delete_case(args, proxies))
        elif demisto.command() == "kibana-rule-delete":
            return_results(kibana_delete_rule(args, proxies))
        elif demisto.command() == "kibana-rule-details-search":
            return_results(kibana_search_rule_details(args, proxies))
        elif demisto.command() == "kibana-case-comment-add":
            return_results(kibana_add_case_comment(args, proxies))
        elif demisto.command() == "kibana-user-list-get":
            return_results(kibana_get_user_list(args, proxies))
        elif demisto.command() == "kibana-alert-assign":
            return_results(kibana_assign_alert_user(args, proxies))
        elif demisto.command() == "kibana-detection-alerts-list":
            return_results(kibana_list_detection_alerts(args, proxies))
        elif demisto.command() == "kibana-alert-note-add":
            return_results(kibana_add_alert_note(args, proxies))
        elif demisto.command() == "kibana-alerting-health-get":
            return_results(kibana_get_alerting_health(args, proxies))
        elif demisto.command() == "kibana-alert-rule-disable":
            return_results(kibana_disable_alert_rule(args, proxies))
        elif demisto.command() == "kibana-alert-rule-enable":
            return_results(kibana_enable_alert_rule(args, proxies))
        elif demisto.command() == "kibana-exception-lists-get":
            return_results(kibana_get_exception_lists(args, proxies))
        elif demisto.command() == "kibana-value-list-create":
            return_results(kibana_create_value_list(args, proxies))
        elif demisto.command() == "kibana-value-lists-get":
            return_results(kibana_get_value_lists(args, proxies))
        elif demisto.command() == "kibana-value-list-items-import":
            return_results(kibana_import_value_list_items(args, proxies))
        elif demisto.command() == "kibana-value-list-item-create":
            return_results(kibana_create_value_list_item(args, proxies))
        elif demisto.command() == "kibana-value-list-items-get":
            return_results(kibana_get_value_list_items(args, proxies))
        elif demisto.command() == "kibana-value-list-item-delete":
            return_results(kibana_delete_value_list_item(args, proxies))
        elif demisto.command() == "kibana-value-list-delete":
            return_results(kibana_delete_value_list(args, proxies))
        elif demisto.command() == "kibana-status-get":
            return_results(kibana_get_status(args, proxies))
        elif demisto.command() == "kibana-task-manager-health-get":
            return_results(kibana_get_task_manager_health(args, proxies))
        elif demisto.command() == "kibana-upgrade-readiness-status-get":
            return_results(kibana_get_upgrade_readiness_status(args, proxies))
        elif demisto.command() == "kibana-case-comment-delete":
            return_results(kibana_delete_case_comment(args, proxies))
        elif demisto.command() == "kibana-case-file-add":
            return_results(kibana_add_file_to_case(args, proxies))
        elif demisto.command() == "kibana-user-by-email-get":
            return_results(kibana_get_user_by_email(args, proxies))
        elif demisto.command() == "kibana-case-information-get":
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

register_module_line("Kibana", "end", __line__())