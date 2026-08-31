import copy
import traceback
from abc import ABC
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from typing import Any, NamedTuple

import dateparser
import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from MicrosoftApiModule import *
from pydantic import AnyUrl, BaseConfig, BaseModel, Field, HttpUrl, parse_obj_as, validator  # type: ignore[E0611, E0611, E0611]
from requests.auth import HTTPBasicAuth

# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument
from CommonServerUserPython import *  # noqa


DEFAULT_FROM_FETCH_PARAMETER = "3 days"

# Per-type API page size (events requested per API call) and per-cycle cap (max events fetched
# per event type per cycle). The activities endpoint honors a larger page size only in scan mode
# (isScan=true); the per-cycle cap bounds how many events a single cycle drains per type. Event
# types are fetched concurrently (one thread each) so no type is starved, and each cycle stays
# short enough to complete within the execution timeout.
ALERTS_PAGE_SIZE = 100
ALERTS_LIMIT = 1000
ACTIVITIES_PAGE_SIZE = 500
ACTIVITIES_LIMIT = 5000


class EventFilter(NamedTuple):
    ui_name: str
    name: str
    attributes: dict
    page_size: int


ALERTS_FILTER = EventFilter("Alerts", "alerts", {"type": "alerts", "filters": {}}, page_size=ALERTS_PAGE_SIZE)
ADMIN_ACTIVITIES_FILTER = EventFilter(
    "Admin activities",
    "activities_admin",
    {"type": "activities", "filters": {"activity.type": {"eq": True}}},
    page_size=ACTIVITIES_PAGE_SIZE,
)
LOGIN_ACTIVITIES_FILTER = EventFilter(
    "Login activities",
    "activities_login",
    {"type": "activities", "filters": {"activity.eventType": {"eq": ["EVENT_CATEGORY_LOGIN", "EVENT_CATEGORY_FAILED_LOGIN"]}}},
    page_size=ACTIVITIES_PAGE_SIZE,
)

ALL_EVENT_FILTERS: list[EventFilter] = [ALERTS_FILTER, ADMIN_ACTIVITIES_FILTER, LOGIN_ACTIVITIES_FILTER]

UI_NAME_TO_EVENT_FILTERS = {event_filter.ui_name: event_filter for event_filter in ALL_EVENT_FILTERS}

""" CONSTANTS """
AUTH_ERROR_MSG = "Authorization Error: make sure tenant id, client id and client secret is correctly set"
VENDOR = "Microsoft"
PRODUCT = "defender_cloud_apps"

""" HELPER CLASSES """


# COPY OF SiemApiModule


class Method(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    HEAD = "HEAD"
    PATCH = "PATCH"
    DELETE = "DELETE"


def load_json(v: Any) -> dict:
    if not isinstance(v, dict | str):
        raise ValueError("headers are not dict or a valid json")
    if isinstance(v, str):
        try:
            v = json.loads(v)
            if not isinstance(v, dict):
                raise ValueError("headers are not from dict type")
        except json.decoder.JSONDecodeError as exc:
            raise ValueError("headers are not valid Json object") from exc
    return v if isinstance(v, dict) else None


class IntegrationHTTPRequest(BaseModel):
    method: Method
    url: AnyUrl
    verify: bool = True
    headers: dict = {}  # type: ignore[type-arg]
    auth: HTTPBasicAuth | None = None
    data: Any = None
    # JSON body sent with the request (requests sets Content-Type: application/json). The
    # activities API reads paging params (filters, limit, sortDirection) from the POST body.
    json: Any = None

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    _normalize_headers = validator("headers", pre=True, allow_reuse=True)(load_json)  # type: ignore[type-var]


class Credentials(BaseModel):
    identifier: str | None
    password: str


def set_authorization(request: IntegrationHTTPRequest, auth_credentials: dict) -> None:
    """Automatic authorization.
    Supports {Authorization: Bearer __token__}
    or Basic Auth.
    """
    creds = Credentials.parse_obj(auth_credentials)
    if creds.password and creds.identifier:
        request.auth = HTTPBasicAuth(creds.identifier, creds.password)
    auth = {"Authorization": f"Bearer {creds.password}"}
    if request.headers:
        request.headers |= auth  # type: ignore[assignment, operator]
    else:
        request.headers = auth  # type: ignore[assignment]


class IntegrationOptions(BaseModel):
    """Add here any option you need to add to the logic"""

    proxy: bool | None = False
    # Per-type per-cycle caps (max events fetched per event type per cycle). These are
    # user-configurable but default to sensible per-type values: alerts are low-volume, while
    # activities (admin + login) can be very high-volume. There is no upper cap. The API page
    # size is NOT user-configurable: it is a per-type constant (ALERTS_PAGE_SIZE /
    # ACTIVITIES_PAGE_SIZE) carried on each EventFilter.
    alerts_limit: int = Field(ALERTS_LIMIT, ge=1)
    activities_limit: int = Field(ACTIVITIES_LIMIT, ge=1)


class IntegrationEventsClient(ABC):
    def __init__(
        self,
        request: IntegrationHTTPRequest,
        options: IntegrationOptions,
        session=requests.Session(),
    ):
        self.request = request
        self.options = options
        self.session = session
        self._set_proxy()
        self._skip_cert_verification()

    @abstractmethod
    def set_request_filter(self, after: Any):
        """TODO: set the next request's filter.
        Example:
        """
        self.request.headers["after"] = after

    def __del__(self):
        try:
            self.session.close()
        except AttributeError as err:
            demisto.debug(f"ignore exceptions raised due to session not used by the client. {err=}")

    def call(self, request: IntegrationHTTPRequest) -> requests.Response:
        try:
            response = self.session.request(**request.dict())
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f"something went wrong with the http call {exc}"
            demisto.debug(msg)
            raise DemistoException(msg) from exc

    def _skip_cert_verification(self, skip_cert_verification_callable: Callable = skip_cert_verification):
        if not self.request.verify:
            skip_cert_verification_callable()

    def _set_proxy(self):
        if self.options.proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()


class IntegrationGetEvents(ABC):
    def __init__(
        self, client: IntegrationEventsClient, options: IntegrationOptions, event_filters: list[EventFilter], base_url: AnyUrl
    ) -> None:
        self.client = client
        self.options = options
        self.filter_name_to_event_filter = {event_filter.name: event_filter for event_filter in event_filters}
        self.base_url = base_url

    def run(self):
        # In this integration we fetch 3 event types (activities_admin, activities_login, alerts).
        # They are fetched CONCURRENTLY (one thread each): a high-volume type (e.g. activities_login)
        # must not starve the others by monopolizing a single sequential run. Each type paginates
        # with its own cloned client (so request state does not race) and advances its own watermark.
        #
        # Thread-safety (mirrors the Koi collector pattern): getLastRun() is read ONCE here on the
        # main thread and the per-type start watermark is passed into each worker; worker threads do
        # HTTP only and never touch demisto server state.
        last_run = demisto.getLastRun()
        final_stored_all_types: list = []
        if not self.filter_name_to_event_filter:
            return final_stored_all_types
        with ThreadPoolExecutor(max_workers=len(self.filter_name_to_event_filter)) as executor:
            future_to_type = {
                executor.submit(
                    self._fetch_type, event_type_name, event_filter, last_run.get(event_type_name)
                ): event_type_name
                for event_type_name, event_filter in self.filter_name_to_event_filter.items()
            }
            for future in future_to_type:
                final_stored_all_types.extend(future.result())
        demisto.debug(f"[MicrosoftDefender] keeping {len(final_stored_all_types)} events from all event types")
        return final_stored_all_types

    def _fetch_type(self, event_type_name: str, event_filter: "EventFilter", after: Any) -> list:
        """Fetch a single event type up to its per-cycle cap, on its own cloned client.

        Runs in its own thread so one high-volume type cannot starve the others. `after` is the
        per-type start watermark read once on the main thread. A failure is caught and logged so
        the type's watermark is NOT advanced past unfetched events (no data loss); it is retried
        next cycle, and other types are unaffected.
        """
        # Per-cycle cap is per-type: alerts vs activities. The alerts endpoint is identified by its
        # attributes["type"]; admin + login share "activities".
        is_alerts = event_filter.attributes["type"] == "alerts"
        per_cycle_limit = self.options.alerts_limit if is_alerts else self.options.activities_limit
        # Deep-copy the client so each thread mutates its own request (url/json) without racing.
        client = copy.deepcopy(self.client)
        stored_per_type: list = []
        try:
            for logs in self._iter_events(event_type_name, event_filter, after, client=client):
                stored_per_type.extend(logs)
                if len(stored_per_type) >= per_cycle_limit:
                    demisto.debug(f"[Slicing Events] reached {per_cycle_limit=} for {event_type_name=}, slicing per type.")
                    stored_per_type = stored_per_type[:per_cycle_limit]
                    break
        except Exception as e:
            demisto.error(
                f"[Fetch Events] failed fetching {event_type_name=}, skipping it this cycle. "
                f"Error: {e!s}\n{traceback.format_exc()}"
            )
            return []
        demisto.debug(f"[MicrosoftDefender] kept {len(stored_per_type)} events for {event_type_name=}")
        return stored_per_type

    def call(self) -> requests.Response:
        return self.client.call(self.client.request)

    @staticmethod
    @abstractmethod
    def get_last_run(events: list) -> dict:
        """Logic to get the last run from the events
        Example:
        """
        return {"after": events[-1]["created"]}

    @abstractmethod
    def _iter_events(self, event_type_name: str, event_filter: "EventFilter", after: Any = None, client: Any = None):
        """Create iterators with Yield.

        `after` is the per-type start watermark (read once on the main thread) and `client` is the
        per-thread client used for concurrent fetching; both are optional for direct calls.
        """
        raise NotImplementedError


# END COPY OF SiemApiModule


class DefenderAuthenticator(BaseModel):
    verify: bool
    url: str
    tenant_id: str
    client_id: str
    client_secret: str
    scope: str
    ms_client: Any = None
    endpoint_type: str

    def set_authorization(self, request: IntegrationHTTPRequest):
        try:
            endpoint_type_name = self.endpoint_type or "Worldwide"
            endpoint_type = MICROSOFT_DEFENDER_FOR_APPLICATION_TYPE[endpoint_type_name]
            azure_cloud = AZURE_CLOUDS[endpoint_type]  # The MDA endpoint type is a subset of the azure clouds.

            if not self.ms_client:
                demisto.debug("try init the ms client for the first time")
                self.ms_client = MicrosoftClient(
                    base_url=self.url,
                    tenant_id=self.tenant_id,
                    auth_id=self.client_id,
                    enc_key=self.client_secret,
                    scope=self.scope,
                    verify=self.verify,
                    self_deployed=True,
                    azure_cloud=azure_cloud,
                    command_prefix="microsoft-defender-cloud-apps",
                )

            token = self.ms_client.get_access_token()
            auth = {"Authorization": f"Bearer {token}"}
            if request.headers:
                request.headers |= auth  # type: ignore[assignment, operator]
            else:
                request.headers = auth  # type: ignore[assignment]

            demisto.debug("MD: getting access token for Defender Authenticator - succeeded")

        except BaseException as e:
            # catch BaseException to catch also sys.exit via return_error
            demisto.error(f"Fail to authenticate with Microsoft services: {e!s}")

            err_msg = "Fail to authenticate with Microsoft services, see the error details in the log"
            raise DemistoException(err_msg) from e


class DefenderHTTPRequest(IntegrationHTTPRequest):
    # The activities API honors paging (limit up to 5000) only via a POST JSON body; the GET
    # query param `limit` is silently ignored and caps pages at 100. The body is populated
    # per-request in DefenderGetEvents._iter_events.
    json: dict = {"sortDirection": "asc"}
    method: Method = Method.POST

    _normalize_url = validator("url", pre=True, allow_reuse=True)(lambda base_url: f"{base_url}/api/v1/")  # type: ignore[type-var]


class DefenderClient(IntegrationEventsClient):
    authenticator: DefenderAuthenticator
    request: DefenderHTTPRequest
    options: IntegrationOptions

    def __init__(
        self, request: DefenderHTTPRequest, options: IntegrationOptions, authenticator: DefenderAuthenticator, after: int
    ):
        self.after = after
        self.authenticator = authenticator
        super().__init__(request, options)

    def set_request_filter(self, after: Any):
        # Advance the pagination window inside the POST JSON body.
        self.request.json["filters"]["date"] = {"gte": after + 1}

    def authenticate(self):
        self.authenticator.set_authorization(self.request)


class DefenderGetEvents(IntegrationGetEvents):
    client: DefenderClient

    def _iter_events(
        self, event_type_name: str, event_filter: "EventFilter", after: Any = None, client: "DefenderClient | None" = None
    ):
        # Each concurrent type fetch passes its own cloned client so request state does not race.
        # Falls back to self.client when called directly (e.g. in unit tests).
        client = client or self.client
        # `after` is the per-type start watermark read once on the main thread (thread-safe); fall
        # back to the client's first-fetch default when no watermark exists yet.
        after = after or client.after
        self.last_timestamp: dict = {}
        base_url = self.base_url
        client.authenticate()

        endpoint_details = event_filter.attributes
        client.request.url = parse_obj_as(HttpUrl, f'{base_url}{endpoint_details["type"]}')

        # get the filter for this type
        filters = endpoint_details["filters"]

        # add the time filter
        if after:
            filters["date"] = {"gte": after}  # type: ignore

        demisto.debug(f"MD: Sending request with filters {filters}")
        # The activities endpoint only returns large pages (up to 5000) in "scan mode"
        # (isScan=true), and then paginates via a server-provided `nextQueryFilters` cursor. The
        # alerts endpoint has no scan mode: it caps at 100/page and we advance the date filter
        # ourselves (its volume is low, so this is not a bottleneck).
        is_scan = endpoint_details["type"] == "activities"
        client.request.json = {
            "filters": filters,
            "limit": event_filter.page_size,
            "sortDirection": "asc",
        }
        if is_scan:
            client.request.json["isScan"] = True
        demisto.debug(f"MD: Sending API call {client.request.method} {client.request.url} body={client.request.json}")
        response = client.call(client.request).json()
        events = response.get("data", [])
        demisto.debug(f"MD: Got {len(events)} events for {event_type_name=}")

        # add new field with the event type
        for event in events:
            event["event_type_name"] = event_type_name

        has_next = response.get("hasNext")

        yield events

        while has_next:
            demisto.debug("MD: Got more events to fetch")
            if is_scan:
                # Scan mode: reuse the server's cursor verbatim (it already drops the tail so all
                # data is listed exactly once); do NOT advance the date filter ourselves.
                client.request.json["filters"] = response.get("nextQueryFilters")
            else:
                last = events.pop()
                client.set_request_filter(last["timestamp"])
            response = client.call(client.request).json()
            events = response.get("data", [])
            demisto.debug(f"MD: Got {len(events)} events for {event_type_name=}")
            # add new field with the event type
            for event in events:
                event["event_type_name"] = event_type_name

            has_next = response.get("hasNext")

            yield events

    @staticmethod
    def get_last_run(events: list, fetched_types: Iterable[str] | None = None) -> dict:
        last_run = demisto.getLastRun()
        demisto.debug(f"MD: Got the last run: {last_run}")

        latest_per_type: dict[str, int] = {}
        for event in events:
            event_type = event["event_type_name"]
            timestamp = event["timestamp"]
            demisto.debug(f"MD: Got event from type {event_type}, with timestamp {timestamp}")
            if timestamp > latest_per_type.get(event_type, 0):
                latest_per_type[event_type] = timestamp

        # Seed a watermark for every fetched type, including ones with 0 events, so a type
        # without a watermark stops re-scanning the same first-fetch window every cycle.
        types_in_play = set(latest_per_type)
        if fetched_types is not None:
            types_in_play |= set(fetched_types)

        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        for event_type in types_in_play:
            latest = latest_per_type.get(event_type, 0)
            if latest:
                last_run[event_type] = latest + 1
            elif event_type not in last_run:
                # No events and no existing watermark: move forward so we don't loop.
                demisto.debug(f"MD: seeding forward watermark for {event_type=} to {now_ms}")
                last_run[event_type] = now_ms

        return last_run


""" HELPER FUNCTIONS """

""" COMMAND FUNCTIONS """


def module_test(get_events: DefenderGetEvents) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type get_events: ``DefenderGetEvents``
    :param get_events: the get_events instance

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        # Probe with a minimal per-cycle cap for every type so test-module stops after one event
        # per type (the request body, including page size, is rebuilt per type in _iter_events).
        get_events.options.alerts_limit = 1
        get_events.options.activities_limit = 1
        get_events.run()
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "authenticate" in str(e):
            message = AUTH_ERROR_MSG
        else:
            raise
    return message


def select_event_filters(requested_event_types: list) -> list[EventFilter]:
    """Map requested UI event-type names to their EventFilter definitions.

    When no types are requested, all event filters are returned so the default
    behavior (fetch everything configured on the instance) is preserved.

    Args:
        requested_event_types: UI display names (for example, ["Login activities"]).

    Returns:
        The matching EventFilter list, or ALL_EVENT_FILTERS when nothing is requested.
    """
    if not requested_event_types:
        return ALL_EVENT_FILTERS
    return [event_filter for ui_name, event_filter in UI_NAME_TO_EVENT_FILTERS.items() if ui_name in requested_event_types]


def main(command: str, demisto_params: dict | None = None):
    demisto.debug(f"MD: Command being called is {command}")

    if demisto_params is None:
        # Args is always stronger. getLastRun is even stronger.
        demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()

    try:
        demisto_params["client_secret"] = demisto_params["credentials"]["password"]
        push_to_xsiam = argToBoolean(demisto_params.get("should_push_events", "false"))

        event_filters = select_event_filters(argToList(demisto_params.get("event_types_to_fetch", [])))

        after = demisto_params.get("after") or DEFAULT_FROM_FETCH_PARAMETER

        if after and not isinstance(after, int):
            demisto.debug(f"MD: Got after argument: {after}")
            timestamp = dateparser.parse(after)  # type: ignore
            after = int(timestamp.timestamp() * 1000)  # type: ignore
            demisto.debug(f"MD: Parsed the after arg: {after}")

        # Drop empty/None per-cycle limits so pydantic applies the per-type Field defaults
        # (an unset instance config field is passed as None, which would fail int validation).
        for limit_key in ("alerts_limit", "activities_limit"):
            if demisto_params.get(limit_key) in (None, ""):
                demisto.debug(f"MD: {limit_key} not set, falling back to per-type default.")
                demisto_params.pop(limit_key, None)

        options = IntegrationOptions.parse_obj(demisto_params)
        demisto.debug(f"MD: Using per-cycle caps {options.alerts_limit=}, {options.activities_limit=}")
        request = DefenderHTTPRequest.parse_obj(demisto_params)
        authenticator = DefenderAuthenticator.parse_obj(demisto_params)

        # Based on the flow of the code, after is always an int so ignore it
        client = DefenderClient(request=request, options=options, authenticator=authenticator, after=after)  # type:ignore[arg-type]
        get_events = DefenderGetEvents(client=client, base_url=request.url, options=options, event_filters=event_filters)

        if command == "test-module":
            return_results(module_test(get_events=get_events))

        elif command == "microsoft-defender-cloud-apps-auth-reset":
            return_results(reset_auth())

        elif command in ("fetch-events", "microsoft-defender-cloud-apps-get-events"):
            events = get_events.run()

            if command == "fetch-events":
                # publishing events to XSIAM
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)  # type: ignore
                next_run = DefenderGetEvents.get_last_run(events, get_events.filter_name_to_event_filter.keys())
                demisto.debug(f"MD: setting the next run: {next_run}")
                demisto.setLastRun(next_run)

            elif command == "microsoft-defender-cloud-apps-get-events":
                command_results = CommandResults(
                    readable_output=tableToMarkdown(
                        "microsoft defender cloud apps events", events, headerTransform=pascalToSpace
                    ),
                    outputs_prefix="Microsoft.Events",
                    outputs_key_field="_id",
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)
                if push_to_xsiam:
                    # publishing events to XSIAM
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)  # type: ignore

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main(demisto.command())
