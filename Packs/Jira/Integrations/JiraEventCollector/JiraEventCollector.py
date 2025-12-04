from datetime import datetime, timedelta
from enum import Enum

import dateparser
import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401
from pydantic import AnyUrl, BaseConfig, BaseModel, Field, Json  # pylint: disable=no-name-in-module
from requests.auth import HTTPBasicAuth
import urllib.parse
import secrets

urllib3.disable_warnings()

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
VENDOR = "atlassian"
PRODUCT = "jira"

AUTH_URL = "https://auth.atlassian.com/authorize"
TOKEN_URL = "https://auth.atlassian.com/oauth/token"
SCOPES = "read:audit-log:jira read:user:jira offline_access"


def jira_oauth_start(client_id: str, redirect_uri: str) -> CommandResults:
    state = secrets.token_hex(16)
    params = {
        "audience": "api.atlassian.com",
        "client_id": client_id,
        "scope": SCOPES,
        "redirect_uri": redirect_uri,
        "state": state,
        "response_type": "code",
        "prompt": "consent",
    }
    url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"  # type: ignore
    return CommandResults(
        readable_output=f"Please authenticate [here]({url})",
        raw_response=url,
    )


def jira_oauth_complete(client_id: str, client_secret: str, code: str, state: str, redirect_uri: str) -> CommandResults:
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    response = requests.post(TOKEN_URL, json=data)
    response.raise_for_status()
    token_data = response.json()

    expires_in = token_data.get("expires_in", 3600)
    token_data["valid_until"] = (datetime.now() + timedelta(seconds=expires_in - 60)).timestamp()

    integration_context = demisto.getIntegrationContext()
    integration_context.update(token_data)
    demisto.setIntegrationContext(integration_context)

    return CommandResults(readable_output="✅ Authorization completed successfully.")


def get_access_token(client_id: str, client_secret: str, redirect_uri: str) -> str:
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get("access_token")
    refresh_token = integration_context.get("refresh_token")
    valid_until = integration_context.get("valid_until")

    if not access_token or not refresh_token:
        raise DemistoException("Access token or refresh token not found. Please run !jira-oauth-start.")

    now = datetime.now().timestamp()
    if valid_until and now >= valid_until:
        demisto.debug("Token expired, refreshing...")
        return refresh_access_token(client_id, client_secret, refresh_token, redirect_uri)

    return access_token


def refresh_access_token(client_id: str, client_secret: str, refresh_token: str, redirect_uri: str) -> str:
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "redirect_uri": redirect_uri,
    }
    response = requests.post(TOKEN_URL, json=data)
    response.raise_for_status()
    token_data = response.json()

    expires_in = token_data.get("expires_in", 3600)
    token_data["valid_until"] = (datetime.now() + timedelta(seconds=expires_in - 60)).timestamp()

    integration_context = demisto.getIntegrationContext()
    integration_context.update(token_data)
    demisto.setIntegrationContext(integration_context)

    return token_data["access_token"]


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
    auth: Optional[HTTPBasicAuth] = None

    class Config(BaseConfig):
        arbitrary_types_allowed = True


class Client:
    def __init__(self, request: Request, session=requests.Session()):
        self.request = request
        self.session = session
        self._set_proxy()
        self._set_cert_verification()

    def __del__(self):
        try:
            self.session.close()
        except AttributeError as err:
            demisto.debug(f"Ignore exceptions raised due to session not used by the client. {err}")

    def call(self) -> requests.Response:
        try:
            response = self.session.request(**self.request.dict(by_alias=True))
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


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    command = demisto.command()

    cloud_id = demisto_params.get("cloud_id")
    client_id = demisto_params.get("client_id")
    client_secret = demisto_params.get("client_secret")
    callback_url = demisto_params.get("callback_url")

    # Handle OAuth commands
    if command == "jira-oauth-start":
        return_results(jira_oauth_start(client_id, callback_url))
        return
    elif command == "jira-oauth-complete":
        return_results(jira_oauth_complete(
            client_id, client_secret, demisto.args().get("code"), demisto.args().get("state"), callback_url
        ))
        return
    elif command == "jira-oauth-test":
        get_access_token(client_id, client_secret, callback_url)
        return_results("✅ OAuth connection test successful.")
        return

    headers = {}

    if cloud_id and client_id and client_secret:
        # OAuth
        demisto_params["url"] = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/auditing/record"
        access_token = get_access_token(client_id, client_secret, callback_url)
        headers["Authorization"] = f"Bearer {access_token}"
    else:
        # Basic Auth
        url = demisto_params.get("url", "")
        if not url:
            raise DemistoException("Server URL is required for Basic Authentication.")
        demisto_params["url"] = f'{str(url).removesuffix("/")}/rest/api/3/auditing/record'

        creds = demisto_params.get("credentials", {})
        identifier = creds.get("identifier")
        password = creds.get("password")
        if identifier and password:
            demisto_params["auth"] = HTTPBasicAuth(identifier, password)

    demisto_params["headers"] = headers
    demisto_params["params"] = ReqParams.model_validate(demisto_params)  # type: ignore[attr-defined]

    request = Request.model_validate(demisto_params)  # type: ignore[attr-defined]
    client = Client(request)
    get_events = GetEvents(client)

    if command == "test-module":
        get_events.run(max_fetch=1)
        demisto.results("ok")

    elif command in ("fetch-events", "jira-get-events"):
        events = get_events.run(int(demisto_params.get("max_fetch", 1000)))
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        if events:
            demisto.setLastRun(get_events.set_next_run(events[0]))
            demisto.debug(f"Last run set to {demisto.getLastRun()}")
            if command == "jira-get-events":
                command_results = CommandResults(
                    readable_output=tableToMarkdown("Jira Audit Records", events, removeNull=True, headerTransform=pascalToSpace),
                    raw_response=events,
                )
                return_results(command_results)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
