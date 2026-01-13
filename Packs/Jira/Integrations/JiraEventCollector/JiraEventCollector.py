from datetime import datetime, timedelta
from enum import Enum

import dateparser
import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401
from pydantic import AnyUrl, BaseConfig, BaseModel, Field, Json  # pylint: disable=no-name-in-module
from requests.auth import HTTPBasicAuth

from AtlassianApiModule import create_atlassian_oauth_client  # type: ignore[import] # noqa: F401

urllib3.disable_warnings()

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
VENDOR = "atlassian"
PRODUCT = "jira"


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
            dateparser.parse(demisto.params().get("first_fetch", "3 days"), settings={"TIMEZONE": "UTC"})
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
            dateparser.parse(demisto.params().get("first_fetch", "3 days"), settings={"TIMEZONE": "UTC"})
            or datetime.now() - timedelta(days=3),
            DATETIME_FORMAT,
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
    auth: Optional[HTTPBasicAuth] = Field(
        HTTPBasicAuth(
            demisto.params().get("credentials", {}).get("identifier"), demisto.params().get("credentials", {}).get("password")
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
            
            # Handle OAuth authentication
            if self.oauth_client:
                access_token = self.oauth_client.get_access_token()
                if 'headers' not in request_dict:
                    request_dict['headers'] = {}
                request_dict['headers']['Authorization'] = f"Bearer {access_token}"
                # Remove basic auth if present
                request_dict.pop('auth', None)
            
            response = self.session.request(**request_dict)
            response.raise_for_status()
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
        return resp.json().get("records", [])

    def _iter_events(self):
        events = self.call()

        while events:
            yield events

            self.client.prepare_next_run(self.client.request.params.limit)
            events = self.call()

    def run(self, max_fetch: int = 1000) -> List[dict]:
        stored = []
        last_run = demisto.getLastRun()

        for logs in self._iter_events():
            stored.extend(logs)

            if len(stored) > max_fetch:
                last_run["offset"] = last_run.get("offset", 0) + max_fetch
                demisto.setLastRun(last_run)
                return stored[:max_fetch]

        last_run["offset"] = 0
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
            last_datetime = log.get("created", "").removesuffix("+0000")
            last_datetime_with_delta = datetime.strptime(last_datetime, DATETIME_FORMAT) + timedelta(milliseconds=1)
            next_time = datetime.strftime(last_datetime_with_delta, DATETIME_FORMAT)

            if last_run.get("offset"):
                last_run["next_time"] = next_time
            else:
                last_run["from"] = next_time

        else:
            if not last_run.get("offset"):
                last_run["from"] = last_run.pop("next_time")

        return last_run


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


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    
    # Get authentication parameters
    auth_method = demisto_params.get("auth_method", "Basic")
    is_oauth = auth_method == "OAuth 2.0"
    
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
            raise DemistoException(
                "Client ID and Client Secret are required for OAuth 2.0 authentication"
            )
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
            proxy=demisto_params.get("proxy", False)
        )

    # Build the API URL
    base_url = str(demisto_params.get("url", "")).removesuffix("/")
    if is_oauth and oauth_client and hasattr(oauth_client, 'cloud_id') and oauth_client.cloud_id:
        # For OAuth with Cloud ID, use the cloud-specific URL
        demisto_params["url"] = f"{base_url}/{oauth_client.cloud_id}/rest/api/3/auditing/record"
    else:
        # For Basic auth or On-Prem OAuth
        demisto_params["url"] = f"{base_url}/rest/api/3/auditing/record"
    
    demisto_params["params"] = ReqParams.model_validate(demisto_params)  # type: ignore[attr-defined]

    request = Request.model_validate(demisto_params)  # type: ignore[attr-defined]
    client = Client(request, oauth_client=oauth_client)
    get_events = GetEvents(client)
    command = demisto.command()

    try:
        if command == "test-module":
            if oauth_client:
                # For OAuth, test the authentication
                oauth_client.test_connection()
            else:
                # For basic auth, try to fetch events
                get_events.run(max_fetch=1)
            demisto.results("ok")

        elif command == "jira-oauth-start":
            if not oauth_client:
                raise DemistoException(
                    "OAuth commands are only available when using OAuth 2.0 authentication"
                )
            return_results(oauth_start_command(oauth_client))

        elif command == "jira-oauth-complete":
            if not oauth_client:
                raise DemistoException(
                    "OAuth commands are only available when using OAuth 2.0 authentication"
                )
            code = demisto.args().get("code", "")
            if not code:
                raise DemistoException("Authorization code is required")
            return_results(oauth_complete_command(oauth_client, code))

        elif command == "jira-oauth-test":
            if not oauth_client:
                raise DemistoException(
                    "OAuth commands are only available when using OAuth 2.0 authentication"
                )
            return_results(oauth_test_command(oauth_client))

        elif command in ("fetch-events", "jira-get-events"):
            events = get_events.run(int(demisto_params.get("max_fetch", 1000)))
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


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
