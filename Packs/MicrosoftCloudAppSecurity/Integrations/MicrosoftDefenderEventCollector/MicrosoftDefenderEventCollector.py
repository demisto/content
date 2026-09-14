import traceback
from abc import ABC
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
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


DEFAULT_LIMIT = 5000
DEFAULT_FROM_FETCH_PARAMETER = "3 days"
# Events requested per API call. alerts honors this directly; activities is capped at 250 unless
# isScan=true is sent, which raises the per-page cap to 500 (the hard ceiling).
API_PAGE_SIZE = 500
ACTIVITIES_ENDPOINT_TYPE = "activities"
# When a fetched event type returns 0 events and has no existing watermark, seed its watermark to
# (now - this buffer) instead of exactly "now". The small step-back covers the vendor's ingestion
# lag (~2-3 min) so events that occurred just before "now" but were not yet available are not
# skipped, while the watermark still advances every cycle (so an empty type never loops).
WATERMARK_SAFETY_BUFFER_MS = 5 * 60 * 1000  # 5 minutes


class EventFilter(NamedTuple):
    ui_name: str
    name: str
    attributes: dict


ALERTS_FILTER = EventFilter("Alerts", "alerts", {"type": "alerts", "filters": {}})
ADMIN_ACTIVITIES_FILTER = EventFilter(
    "Admin activities", "activities_admin", {"type": "activities", "filters": {"activity.type": {"eq": True}}}
)
LOGIN_ACTIVITIES_FILTER = EventFilter(
    "Login activities",
    "activities_login",
    {"type": "activities", "filters": {"activity.eventType": {"eq": ["EVENT_CATEGORY_LOGIN", "EVENT_CATEGORY_FAILED_LOGIN"]}}},
)

ALL_EVENT_FILTERS: list[EventFilter] = [ALERTS_FILTER, ADMIN_ACTIVITIES_FILTER, LOGIN_ACTIVITIES_FILTER]

UI_NAME_TO_EVENT_FILTERS = {event_filter.ui_name: event_filter for event_filter in ALL_EVENT_FILTERS}

""" CONSTANTS """
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

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    _normalize_headers = validator("headers", pre=True, allow_reuse=True)(load_json)  # type: ignore[type-var]


class Credentials(BaseModel):
    identifier: str | None
    password: str


def set_authorization(request: IntegrationHTTPRequest, auth_credentials):
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
    # limit is the maximum number of events to fetch per event type per fetch cycle.
    # Defaults to DEFAULT_LIMIT so fetch-events pagination is always bounded. There is no
    # upper cap: the correct value depends on the tenant's event volume, which we cannot
    # know in advance, so admins may raise it as needed. Pagination loops in pages of
    # API_PAGE_SIZE.
    limit: int = Field(DEFAULT_LIMIT, ge=1)


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
        self.filter_name_to_attributes = {event_filter.name: event_filter.attributes for event_filter in event_filters}
        self.base_url = base_url

    @abstractmethod
    def run(self):
        """Fetch all event types for one cycle. Implemented by the concrete subclass."""
        raise NotImplementedError

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
    def _iter_events(self, client: "DefenderClient", event_type_name: str, endpoint_details: dict):
        """Create iterators with Yield"""
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
    params: dict = {"sortDirection": "asc"}
    method: Method = Method.GET

    _normalize_url = validator("url", pre=True, allow_reuse=True)(lambda base_url: f"{base_url}/api/v1/")  # type: ignore[type-var]


class DefenderClient(IntegrationEventsClient):
    authenticator: DefenderAuthenticator
    request: DefenderHTTPRequest
    options: IntegrationOptions

    def __init__(
        self,
        request: DefenderHTTPRequest,
        options: IntegrationOptions,
        authenticator: DefenderAuthenticator,
        after: int,
        session: requests.Session | None = None,
    ):
        self.after = after
        self.authenticator = authenticator
        super().__init__(request, options, session=session or requests.Session())

    def set_request_filter(self, after: Any):
        curr_filters = json.loads(self.request.params["filters"])
        curr_filters["date"] = {"gte": after + 1}
        self.request.params["filters"] = json.dumps(curr_filters)

    def authenticate(self):
        self.authenticator.set_authorization(self.request)

    def clone(self) -> "DefenderClient":
        """A fresh client with its own request and session, safe for a single thread.

        The request is deep-copied so per-type mutations (url, filters, isScan) don't clash, and a
        new requests.Session is used because a Session is not guaranteed thread-safe. The MS token
        is cached on the shared authenticator, so cloned clients reuse it without re-authenticating.
        """
        return DefenderClient(
            request=self.request.copy(deep=True),
            options=self.options,
            authenticator=self.authenticator,
            after=self.after,
            session=requests.Session(),
        )


class DefenderGetEvents(IntegrationGetEvents):
    client: DefenderClient
    limit_reached: bool = False

    def run(self):
        self.client.authenticate()
        # Reset per-cycle: set True if any type fills its limit, signalling a backlog to drain next cycle.
        self.limit_reached = False
        types = list(self.filter_name_to_attributes.items())
        demisto.debug(
            f"[MicrosoftDefender] authenticated; fetching {len(types)} event types concurrently: {[t[0] for t in types]}"
        )
        results: list = []
        with ThreadPoolExecutor(max_workers=len(types) or 1) as pool:
            futures = [
                pool.submit(self._collect_type, self.client.clone(), event_type_name, endpoint_details)
                for event_type_name, endpoint_details in types
            ]
            for future in as_completed(futures):
                results.extend(future.result())
        demisto.debug(f"[MicrosoftDefender] keeping {len(results)} events from all event types")
        return results

    def _collect_type(self, client: "DefenderClient", event_type_name: str, endpoint_details: dict) -> list:
        stored: list = []
        try:
            for logs in self._iter_events(client, event_type_name, endpoint_details):
                stored.extend(logs)
                if len(stored) >= self.options.limit:
                    stored = stored[: self.options.limit]
                    # This type filled its limit, so more events are likely waiting; signal the fetch
                    # cycle to re-trigger immediately (nextTrigger=0) instead of idling until the next interval.
                    self.limit_reached = True
                    demisto.debug(f"[MicrosoftDefender] {event_type_name=} reached the limit; will request an immediate next run")
                    break
        except Exception as e:
            # Discard the partial batch so the watermark is not advanced past unfetched events.
            demisto.error(
                f"[Fetch Events] failed fetching {event_type_name=}, skipping it this cycle. "
                f"Error: {e!s}\n{traceback.format_exc()}"
            )
            return []
        demisto.debug(f"[MicrosoftDefender] kept {len(stored)} events for {event_type_name=}")
        return stored

    def _iter_events(self, client: "DefenderClient", event_type_name, endpoint_details):
        base_url = self.base_url

        client.request.params.pop("filters", None)
        endpoint_type = endpoint_details["type"]
        client.request.url = parse_obj_as(HttpUrl, f"{base_url}{endpoint_type}")

        # activities returns up to 500 per page only with isScan=true (otherwise 250); alerts must
        # not send isScan.
        client.request.params["limit"] = API_PAGE_SIZE
        if endpoint_type == ACTIVITIES_ENDPOINT_TYPE:
            client.request.params["isScan"] = "true"
        else:
            client.request.params.pop("isScan", None)

        filters = endpoint_details["filters"]

        after = demisto.getLastRun().get(event_type_name) or client.after
        if after:
            filters["date"] = {"gte": after}  # type: ignore

        demisto.debug(f"MD: Sending request for {event_type_name=} with filters {filters}")
        client.request.params["filters"] = json.dumps(filters)
        response = client.call(client.request).json()
        events = response.get("data", [])
        demisto.debug(f"MD: Got {len(events)} events for {event_type_name=}")

        for event in events:
            event["event_type_name"] = event_type_name

        has_next = response.get("hasNext")

        yield events

        while has_next:
            demisto.debug(f"MD: Got more events to fetch for {event_type_name=}")
            last = events.pop()
            client.set_request_filter(last["timestamp"])
            response = client.call(client.request).json()
            events = response.get("data", [])
            demisto.debug(f"MD: Got {len(events)} events for {event_type_name=}")
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

        # Seed to (now - safety buffer) rather than exactly "now": the step-back covers the vendor's
        # ingestion lag so events that occurred just before now (but were not yet available) are not
        # skipped, while the watermark still advances every cycle so an empty type never loops.
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        seed_ms = now_ms - WATERMARK_SAFETY_BUFFER_MS
        for event_type in types_in_play:
            latest = latest_per_type.get(event_type, 0)
            if latest:
                last_run[event_type] = latest + 1
            elif event_type not in last_run:
                # No events and no existing watermark: seed forward (minus the buffer) so we advance
                # without looping and without skipping recent, not-yet-available events.
                demisto.debug(f"MD: seeding forward watermark for {event_type=} to {seed_ms}")
                last_run[event_type] = seed_ms

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

    get_events.client.authenticate()
    get_events.client.request.params = {"limit": 1}
    get_events.options.limit = 1

    # Call _iter_events directly on a single event type instead of run(): run() isolates per-type
    # failures (a 403/auth error for one type is logged and swallowed so the fetch cycle survives),
    # which would hide the connectivity/authorization problems that test-module must surface.
    event_type_name, endpoint_details = next(iter(get_events.filter_name_to_attributes.items()))
    events = get_events._iter_events(get_events.client, event_type_name, endpoint_details)
    next(events, None)  # trigger the first API call; a 403/auth error propagates and fails the test
    return "ok"


def main(command: str, demisto_params: dict):
    demisto.debug(f"MD: Command being called is {command}")
    demisto.debug(f"MD: received param keys: {sorted(demisto_params.keys())}")

    try:
        demisto_params["client_secret"] = demisto_params["credentials"]["password"]
        push_to_xsiam = argToBoolean(demisto_params.get("should_push_events", "false"))

        if user_requested_event_types := argToList(demisto_params.get("event_types_to_fetch", [])):
            event_filters: list[EventFilter] = [
                event_filter
                for ui_name, event_filter in UI_NAME_TO_EVENT_FILTERS.items()
                if ui_name in user_requested_event_types
            ]
        else:
            event_filters = ALL_EVENT_FILTERS

        after = demisto_params.get("after") or DEFAULT_FROM_FETCH_PARAMETER

        if after and not isinstance(after, int):
            demisto.debug(f"MD: Got after argument: {after}")
            timestamp = dateparser.parse(after)  # type: ignore
            after = int(timestamp.timestamp() * 1000)  # type: ignore
            demisto.debug(f"MD: Parsed the after arg: {after}")

        options = IntegrationOptions.parse_obj(demisto_params)
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
                next_run = DefenderGetEvents.get_last_run(events, get_events.filter_name_to_attributes.keys())
                if get_events.limit_reached:
                    # A type filled its limit this cycle, so a backlog likely remains; re-trigger the
                    # fetch immediately instead of waiting for the next scheduled interval.
                    next_run["nextTrigger"] = "0"
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

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    # Args is always stronger. Get getIntegrationContext even stronger
    compound_demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), compound_demisto_params)
