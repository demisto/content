import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime, timedelta  # noqa: E402
from enum import Enum  # noqa: E402

import dateparser  # noqa: E402
import requests  # noqa: E402
import urllib3  # noqa: E402
from pydantic import AnyUrl, BaseConfig, BaseModel, Field, Json  # noqa: E402  # pylint: disable=no-name-in-module
from requests.auth import HTTPBasicAuth  # noqa: E402

from AtlassianApiModule import *  # type: ignore[import,assignment] # noqa: F401,E402

urllib3.disable_warnings()

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
VENDOR = "atlassian"
PRODUCT = "jira"
DEFAULT_FIRST_FETCH = "3 days"
ATLASSIAN_API_GATEWAY_JIRA_URL = "https://api.atlassian.com/ex/jira"
CLOUD_AUDIT_RECORDS_PATH = "rest/api/3/auditing/record"
DATA_CENTER_AUDIT_EVENTS_PATH = "rest/auditing/1.0/events"
UCP_OAUTH_FLOW_NOT_NEEDED = (
    "`!{command}` is not needed in the Atlassian Standard Connector: the platform signs in and refreshes the token."
)


class Method(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    HEAD = "HEAD"
    PATCH = "PATCH"
    DELETE = "DELETE"


class Args(BaseModel):
    from_: str = Field(
        datetime.strftime(
            dateparser.parse(demisto.params().get("first_fetch") or DEFAULT_FIRST_FETCH, settings={"TIMEZONE": "UTC"})
            or datetime.now() - timedelta(days=3),
            DATETIME_FORMAT,
        ),
        alias="from",
    )
    limit: int = 1000
    offset: int = 0


class ReqParams(BaseModel):
    from_: str = Field(
        datetime.strftime(
            dateparser.parse(demisto.params().get("first_fetch") or DEFAULT_FIRST_FETCH, settings={"TIMEZONE": "UTC"})
            or datetime.now() - timedelta(days=3),
            "%Y-%m-%dT%H:%M:%S.000Z",
        ),
        alias="from",
    )
    limit: int = 1000
    offset: int = 0


class Request(BaseModel):
    method: Method = Method.GET
    url: AnyUrl
    headers: Union[Json, dict] = {}
    params: ReqParams
    insecure: bool = Field(not demisto.params().get("insecure", False), alias="verify")
    proxy: bool = Field(demisto.params().get("proxy", False), alias="proxies")
    data: Optional[str] = None
    # Legacy Basic auth. Under the Atlassian Standard Connector the credentials param
    # is unbound (None) and Client.call() replaces this with the UCP credential.
    auth: Optional[HTTPBasicAuth] = Field(
        HTTPBasicAuth(
            (demisto.params().get("credentials") or {}).get("identifier") or "",
            (demisto.params().get("credentials") or {}).get("password") or "",
        )
    )

    class Config(BaseConfig):
        arbitrary_types_allowed = True


class Client:
    def __init__(self, request: Request, session=requests.Session(), oauth_client=None):
        self.request = request
        self.session = session
        self.oauth_client = oauth_client
        self._set_proxy()
        self._set_cert_verification()

    def __del__(self):
        try:
            self.session.close()
        except AttributeError as err:
            demisto.debug(f"Ignore exceptions raised due to session not used by the client. {err}")

    def call(self) -> requests.Response:
        try:
            request_dict = self.request.dict(by_alias=True)

            if should_use_ucp_auth():
                # Atlassian Standard Connector: the credential of the selected
                # connection profile is read on every request (the platform refreshes it).
                apply_ucp_auth_to_request(request_dict)
            # Handle OAuth authentication
            elif self.oauth_client:
                access_token = self.oauth_client.get_access_token()
                if "headers" not in request_dict:
                    request_dict["headers"] = {}
                request_dict["headers"]["Authorization"] = f"Bearer {access_token}"
                # Remove basic auth if present
                request_dict.pop("auth", None)

            # Disable redirects to prevent following to login pages
            request_dict["allow_redirects"] = False

            demisto.debug(f"Sending request to {request_dict.get('url')} with method {request_dict.get('method')}")
            if "headers" in request_dict:
                headers_to_log = request_dict["headers"].copy()
                if "Authorization" in headers_to_log:
                    headers_to_log["Authorization"] = "Bearer *****"
                demisto.debug(f"Request headers: {headers_to_log}")

            response = self.session.request(**request_dict)

            demisto.debug(f"Response status code: {response.status_code}")
            if response.status_code == 401 and should_use_ucp_auth():
                # Drop the cached UCP credential so the next request fetches a fresh one.
                invalidate_ucp_credentials(get_ucp_method_unique_id())
            if response.status_code in (301, 302, 303, 307, 308):
                raise DemistoException(
                    f"The request was redirected to '{response.headers.get('Location')}'.\n"
                    "This usually indicates an authentication issue (e.g., invalid credentials, expired token) "
                    "or an incorrect URL configuration.\n"
                    "Please verify your authentication credentials and URL."
                )

            try:
                response.raise_for_status()
            except Exception as e:
                demisto.debug(f"Request failed. Response content: {response.text}")
                raise e

            if "json" not in response.headers.get("Content-Type", "").lower():
                raise DemistoException(
                    f"Response content type is '{response.headers.get('Content-Type')}', but JSON was expected.\n"
                    "This usually occurs when authentication fails and the request is redirected to a login page.\n"
                    "Please verify your authentication credentials (API Key, Bearer Token, etc.) and URL."
                )

            return response
        except Exception as exc:
            msg = f"Something went wrong with the http call {exc}"
            LOG(msg)
            raise DemistoException(msg) from exc

    def prepare_next_run(self, offset: int):
        self.request.params.offset += offset

    def _set_cert_verification(self):
        if not self.request.insecure:
            skip_cert_verification()

    def _set_proxy(self):
        if self.request.proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()


class GetEvents:
    def __init__(self, client: Client) -> None:
        self.client = client

    def call(self) -> list:
        resp = self.client.call()
        json_response = resp.json()
        demisto.debug(f"API response keys: {json_response.keys() if isinstance(json_response, dict) else 'not a dict'}")
        demisto.debug(f"API response (first 1000 chars): {str(json_response)[:1000]}")

        # Jira Data Center /rest/auditing/1.0/events uses 'entities' key
        # Jira Cloud /rest/api/3/auditing/record uses 'records' key
        events = json_response.get("entities") or json_response.get("records", [])
        demisto.debug(f"Found {len(events)} events")
        return events

    def _iter_events(self):
        events = self.call()

        while events:
            yield events

            self.client.prepare_next_run(self.client.request.params.limit)
            events = self.call()

    def run(self, max_fetch: int = 1000, update_last_run: bool = True) -> List[dict]:
        """
        Fetch up to max_fetch events.

        Args:
            max_fetch: The maximum number of events to return.
            update_last_run: Whether to store the pagination offset in the last run.
                Connectivity checks pass False so they never move the fetch position.
        """
        stored = []
        last_run = demisto.getLastRun()

        for logs in self._iter_events():
            stored.extend(logs)

            if len(stored) > max_fetch:
                last_run["offset"] = last_run.get("offset", 0) + max_fetch
                if update_last_run:
                    demisto.setLastRun(last_run)
                return stored[:max_fetch]

        last_run["offset"] = 0
        if update_last_run:
            demisto.setLastRun(last_run)
        return stored

    @staticmethod
    def set_next_run(log: dict) -> dict:
        """
        Handles and saves the values required for next fetch.

        There are 3 values:
            * from: From which time to fetch
            * next_run: Time of creation of the last event fetched
            * offset: The size of the offset (how many events to skip)

        Since the rest API returns the events in desc order (the last event returns first), We need to save the last
        event time creation in some variable (next_run) for the next fetches, in addition we need to save in another
        variable (offset) the number of how many events we already fetched to skip them in the next fetch to avoid
        duplicates, in addition we need to save the time (from) from when to fetch if there is still some incident
        to fetch with offset
        """
        last_run = demisto.getLastRun()

        if not last_run.get("next_time"):
            # Jira Data Center uses 'timestamp', Cloud uses 'created'
            last_datetime = log.get("timestamp") or log.get("created", "")
            # Remove timezone suffix if present (e.g., +0000 or Z)
            last_datetime = last_datetime.removesuffix("+0000").removesuffix("Z")

            if not last_datetime:
                demisto.debug("No timestamp found in event, skipping next_run update")
                return last_run

            LOG_PREFIX = "[Jira Event Collector]"

            try:
                # Parse with milliseconds (Data Center format: 2026-01-19T11:36:01.892)
                demisto.debug(f"{LOG_PREFIX} Attempting to parse timestamp with milliseconds: {last_datetime}")
                last_datetime_obj = datetime.strptime(last_datetime, "%Y-%m-%dT%H:%M:%S.%f")
            except ValueError:
                try:
                    # Fallback for formats without milliseconds
                    demisto.debug(f"{LOG_PREFIX} Attempting to parse timestamp without milliseconds: {last_datetime}")
                    last_datetime_obj = datetime.strptime(last_datetime, "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    try:
                        # Try original format with microseconds
                        demisto.debug(f"{LOG_PREFIX} Attempting to parse timestamp with microseconds: {last_datetime}")
                        last_datetime_obj = datetime.strptime(last_datetime, DATETIME_FORMAT)
                    except ValueError as e:
                        demisto.debug(f"{LOG_PREFIX} Failed to parse timestamp '{last_datetime}': {e}")
                        return last_run

            # Add 1 second to ensure we don't fetch duplicates (since we truncate milliseconds)
            last_datetime_with_delta = last_datetime_obj + timedelta(seconds=1)

            # Use format without milliseconds for compatibility with Data Center
            next_time = datetime.strftime(last_datetime_with_delta, "%Y-%m-%dT%H:%M:%S")

            if last_run.get("offset"):
                last_run["next_time"] = next_time
            else:
                last_run["from"] = next_time

        else:
            if not last_run.get("offset"):
                last_run["from"] = last_run.pop("next_time")

        return last_run


def apply_ucp_auth_to_request(request_dict: dict) -> None:
    """
    Put the UCP credential of the selected connection profile on a request.

    oauth2 / api_key profiles become an Authorization header (both are bearer tokens
    for Atlassian); a plain profile becomes requests Basic auth. Any legacy auth on
    the request is replaced.

    Args:
        request_dict: The keyword arguments for requests.Session.request (mutated).
    """
    ucp_headers, basic_auth = build_atlassian_ucp_auth_headers()
    headers = dict(request_dict.get("headers") or {})
    headers.pop("Authorization", None)
    request_dict["headers"] = headers | ucp_headers
    if basic_auth:
        request_dict["auth"] = basic_auth
    else:
        request_dict.pop("auth", None)


def build_audit_url(base_url: str, cloud_id: str, ucp_auth_type: str = "") -> str:
    """
    Build the audit endpoint URL for the Atlassian Standard Connector (UCP) path.

    Args:
        base_url: The Server URL param (site URL, Data Center URL or the API gateway).
        cloud_id: The Atlassian site Cloud ID.
        ucp_auth_type: "oauth2", "api_key" or "plain".

    Raises:
        DemistoException: If the Cloud ID is missing where the API gateway is used.

    Returns:
        str: The audit records (Cloud) or audit events (Data Center) URL.
    """
    base_url = base_url.removesuffix("/")
    if ucp_auth_type == ATLASSIAN_UCP_AUTH_OAUTH2 or base_url.lower() == ATLASSIAN_API_GATEWAY_JIRA_URL:
        # OAuth 2.0 (3LO) tokens are only accepted on the API gateway; email + API
        # token also works there, so a Server URL left on the gateway default is kept.
        if not cloud_id:
            raise DemistoException(
                "The Cloud ID is required to collect Jira Cloud audit records through the Atlassian API gateway"
                f" ({ATLASSIAN_API_GATEWAY_JIRA_URL}). Set it on the connection page."
            )
        return f"{ATLASSIAN_API_GATEWAY_JIRA_URL}/{cloud_id}/{CLOUD_AUDIT_RECORDS_PATH}"
    if ".atlassian.net" in base_url.lower():
        return f"{base_url}/{CLOUD_AUDIT_RECORDS_PATH}"
    return f"{base_url}/{DATA_CENTER_AUDIT_EVENTS_PATH}"


def oauth_start_command(oauth_client) -> CommandResults:
    """Start OAuth authentication flow."""
    url = oauth_client.oauth_start()
    return CommandResults(
        readable_output=(
            f"### Authorization Instructions\n"
            f"1. Click on the following link to authorize:\n{url}\n\n"
            f"2. After authorizing, you will be redirected to the callback URL\n"
            f"3. Copy the authorization code from the 'code' parameter in the URL\n"
            f"4. Run the command: `!jira-oauth-complete code=<your_code>`"
        )
    )


def oauth_complete_command(oauth_client, code: str) -> CommandResults:
    """Complete OAuth authentication flow."""
    oauth_client.oauth_complete(code=code)
    return CommandResults(
        readable_output=(
            "### Successfully authenticated!\n"
            "The access token and refresh token have been saved.\n"
            "You can now use the integration to fetch events."
        )
    )


def oauth_test_command(oauth_client) -> CommandResults:
    """Test OAuth authentication."""
    try:
        oauth_client.test_connection()
        return CommandResults(readable_output="✓ Authentication successful")
    except Exception as e:
        raise DemistoException(f"Authentication failed: {str(e)}")


def run_jira_event_collector_integration():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()

    # Atlassian Standard Connector (UCP): the connection profile decides the auth, so
    # the auth_method param and the instance credential params are ignored.
    is_ucp = should_use_ucp_auth()
    ucp_auth_type = get_atlassian_ucp_auth_type() if is_ucp else ""

    # Get authentication parameters
    auth_method = demisto_params.get("auth_method") or "Basic"
    is_oauth = auth_method == "OAuth 2.0" and not is_ucp

    # OAuth client initialization
    oauth_client = None
    if is_oauth:
        client_creds = demisto_params.get("client_credentials", {})
        client_id = client_creds.get("identifier", "")
        client_secret = client_creds.get("password", "")
        cloud_id = demisto_params.get("cloud_id", "")
        callback_url = demisto_params.get("callback_url", "")
        server_url = str(demisto_params.get("url", "")).removesuffix("/")

        if not client_id or not client_secret:
            raise DemistoException("Client ID and Client Secret are required for OAuth 2.0 authentication")
        if not callback_url:
            raise DemistoException("Callback URL is required for OAuth 2.0 authentication")

        # Create OAuth client using ApiModule (supports both Cloud and On-Prem)
        oauth_client = create_atlassian_oauth_client(
            client_id=client_id,
            client_secret=client_secret,
            callback_url=callback_url,
            cloud_id=cloud_id,
            server_url=server_url,
            verify=not demisto_params.get("insecure", False),
            proxy=demisto_params.get("proxy", False),
        )

    # Validate Basic auth credentials when using Basic authentication
    if not is_oauth and not is_ucp:
        credentials = demisto_params.get("credentials") or {}
        username = credentials.get("identifier", "")
        password = credentials.get("password", "")
        if not username or not password:
            return_error(
                "Username and API token are required for Basic authentication. "
                "Please provide valid credentials or switch to OAuth 2.0."
            )
            return

    # Build the API URL
    base_url = str(demisto_params.get("url") or "").removesuffix("/")
    if is_ucp:
        try:
            demisto_params["url"] = build_audit_url(base_url, demisto_params.get("cloud_id") or "", ucp_auth_type)
        except DemistoException as e:
            return_error(str(e))
            return
        demisto.debug(f"UCP auth ({ucp_auth_type}): collecting audit events from {demisto_params['url']}")
    elif is_oauth and oauth_client and hasattr(oauth_client, "cloud_id") and oauth_client.cloud_id:
        # For OAuth with Cloud ID, use the cloud-specific URL
        # We force the base URL to be the Atlassian API gateway for Cloud OAuth
        # Must use API v3 — the v2 audit endpoint does not support OAuth 2.0 (3LO) granular scopes
        base_url = "https://api.atlassian.com/ex/jira"
        demisto_params["url"] = f"{base_url}/{oauth_client.cloud_id}/rest/api/3/auditing/record"
    else:
        # Distinguish Jira Cloud vs Server/Data Center by the base URL.
        # Jira Cloud (e.g., *.atlassian.net) should use the v3 auditing endpoint,
        # while Jira Server/Data Center continues to use the legacy auditing endpoint.
        lower_base_url = base_url.lower()
        if ".atlassian.net" in lower_base_url:
            # Jira Cloud with Basic auth (or non-cloud OAuth without cloud ID)
            demisto_params["url"] = f"{base_url}/rest/api/3/auditing/record"
        else:
            # Jira Server/Data Center
            demisto_params["url"] = f"{base_url}/rest/auditing/1.0/events"

    demisto_params["params"] = ReqParams.model_validate(demisto_params)  # type: ignore[attr-defined]

    request = Request.model_validate(demisto_params)  # type: ignore[attr-defined]
    client = Client(request, oauth_client=oauth_client)
    get_events = GetEvents(client)
    command = demisto.command()

    try:
        if is_ucp and command in ("jira-oauth-start", "jira-oauth-complete"):
            raise DemistoException(UCP_OAUTH_FLOW_NOT_NEEDED.format(command=command))

        if is_ucp and command in ("test-module", "jira-oauth-test"):
            # Connectivity check with the connection profile credential; never moves
            # the fetch position.
            get_events.run(max_fetch=1, update_last_run=False)
            if command == "test-module":
                demisto.results("ok")
            else:
                return_results(CommandResults(readable_output="✓ Authentication successful"))

        elif command == "test-module":
            if oauth_client:
                # For OAuth, test the authentication
                oauth_client.test_connection()
            else:
                # For basic auth, try to fetch events
                get_events.run(max_fetch=1)
            demisto.results("ok")

        elif command == "jira-oauth-start":
            if not oauth_client:
                raise DemistoException("OAuth commands are only available when using OAuth 2.0 authentication")
            return_results(oauth_start_command(oauth_client))

        elif command == "jira-oauth-complete":
            if not oauth_client:
                raise DemistoException("OAuth commands are only available when using OAuth 2.0 authentication")
            code = demisto.args().get("code", "")
            if not code:
                raise DemistoException("Authorization code is required")
            return_results(oauth_complete_command(oauth_client, code))

        elif command == "jira-oauth-test":
            if not oauth_client:
                raise DemistoException("OAuth commands are only available when using OAuth 2.0 authentication")
            return_results(oauth_test_command(oauth_client))

        elif command in ("fetch-events", "jira-get-events"):
            events = get_events.run(int(demisto_params.get("max_fetch") or 1000))
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            if events:
                demisto.setLastRun(get_events.set_next_run(events[0]))
                demisto.debug(f"Last run set to {demisto.getLastRun()}")
                if command == "jira-get-events":
                    command_results = CommandResults(
                        readable_output=tableToMarkdown(
                            "Jira Audit Records", events, removeNull=True, headerTransform=pascalToSpace
                        ),
                        raw_response=events,
                    )
                    return_results(command_results)
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")
