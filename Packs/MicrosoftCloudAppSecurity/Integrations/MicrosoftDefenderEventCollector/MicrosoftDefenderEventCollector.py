from abc import ABC
from collections.abc import Callable
from datetime import datetime, UTC
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

MAX_FETCH = 100
DEFAULT_FROM_FETCH_PARAMETER = "3 days"

# Debug version identifier
DEBUG_VERSION = "2026-01-07-v1"


class EventFilter(NamedTuple):
    ui_name: str
    name: str
    attributes: dict


ALERTS_FILTER = EventFilter("Alerts", "alerts", {"type": "alerts", "filters": {}})
# The filter for admin activities might be incorrect.
# If 'activity.type' is not supported, consider using a different filter or removing it to fetch all activities
# (excluding logins if possible).
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
    limit: int | None = Field(None, ge=1, le=MAX_FETCH)


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
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Making API call to {request.url}")
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Request params: {getattr(request, 'params', 'N/A')}")

            response = self.session.request(**request.dict())

            # Log response headers for debugging (especially rate limit info)
            rate_limit_headers = {
                k: v
                for k, v in response.headers.items()
                if "rate" in k.lower() or "limit" in k.lower() or "retry" in k.lower() or "x-" in k.lower()
            }
            if rate_limit_headers:
                demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Rate limit/retry headers: {rate_limit_headers}")

            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Response status code: {response.status_code}")

            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as exc:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: HTTP Error occurred: {exc}")
            if exc.response is not None:
                demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Error response status: {exc.response.status_code}")
                demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Error response headers: {dict(exc.response.headers)}")
                try:
                    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Error response body: {exc.response.text[:1000]}")
                except Exception:
                    pass

                if exc.response.status_code == 500:
                    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Got 500 error, retrying once...")
                    try:
                        response = self.session.request(**request.dict())
                        response.raise_for_status()
                        return response
                    except Exception as retry_exc:
                        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Retry failed: {retry_exc}")
                        msg = f"something went wrong with the http call {retry_exc}"
                        demisto.debug(msg)
                        raise DemistoException(msg) from retry_exc

            msg = f"something went wrong with the http call {exc}"
            demisto.debug(msg)
            raise DemistoException(msg) from exc
        except Exception as exc:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Unexpected error: {exc}")
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

    def run(self):
        final_stored_all_types = []
        # In this integration we need to do 3 API calls:
        # - activities with filter to get the admin events
        # - activities with different filter to get the login events
        # - alerts with no filter
        for event_type_name, endpoint_details in self.filter_name_to_attributes.items():
            stored_per_type = []
            for logs in self._iter_events(event_type_name, endpoint_details):
                stored_per_type.extend(logs)
                if self.options.limit:
                    demisto.debug(
                        f"MD: {self.options.limit=} reached. slicing from {len(logs)=}."
                        " limit must be presented ONLY in commands and not in fetch-events."
                    )
                    if len(stored_per_type) >= self.options.limit:
                        final_stored_all_types.extend(stored_per_type[: self.options.limit])
                        break
            else:
                final_stored_all_types.extend(stored_per_type)

        demisto.debug(f"MD: Sliced events, keeping {len(final_stored_all_types)} events from all event types")
        return final_stored_all_types

    def call(self) -> requests.Response:
        return self.client.call(self.client.request)

    @abstractmethod
    def get_last_run(self, events: list) -> dict:
        """Logic to get the last run from the events
        Example:
        """
        return {"after": events[-1]["created"]}

    @abstractmethod
    def _iter_events(self, event_type_name: str, endpoint_details: dict):
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
        self, request: DefenderHTTPRequest, options: IntegrationOptions, authenticator: DefenderAuthenticator, after: int
    ):
        self.after = after
        self.authenticator = authenticator
        super().__init__(request, options)

    def set_request_filter(self, after: Any):
        curr_filters = json.loads(self.request.params["filters"])
        curr_filters["date"] = {"gte": after + 1}
        self.request.params["filters"] = json.dumps(curr_filters)

    def authenticate(self):
        self.authenticator.set_authorization(self.request)


def _timestamp_to_human_readable(timestamp_ms: int) -> str:
    """Convert millisecond timestamp to human readable format."""
    try:
        dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=UTC)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"Invalid timestamp: {timestamp_ms}"


def _get_time_gap_info(timestamp_ms: int) -> str:
    """Get information about the time gap between timestamp and now."""
    try:
        now = datetime.now(tz=UTC)
        event_time = datetime.fromtimestamp(timestamp_ms / 1000, tz=UTC)
        gap = now - event_time
        return f"Gap from now: {gap.days} days, {gap.seconds // 3600} hours, {(gap.seconds % 3600) // 60} minutes"
    except Exception as e:
        return f"Could not calculate gap: {e}"


class DefenderGetEvents(IntegrationGetEvents):
    client: DefenderClient

    def __init__(
        self, client: IntegrationEventsClient, options: IntegrationOptions, event_filters: list[EventFilter], base_url: AnyUrl
    ) -> None:
        super().__init__(client, options, event_filters, base_url)
        self.requested_start_times: dict[str, int] = {}

    def _iter_events(self, event_type_name, endpoint_details):
        self.last_timestamp = {}
        base_url = self.base_url
        self.client.authenticate()

        self.client.request.params.pop("filters", None)
        self.client.request.url = parse_obj_as(HttpUrl, f'{base_url}{endpoint_details["type"]}')

        # get the filter for this type
        filters = endpoint_details["filters"]

        last_run_data = demisto.getLastRun()
        after = last_run_data.get(event_type_name) or self.client.after
        self.requested_start_times[event_type_name] = after

        # Enhanced debug logging for timestamp tracking
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: ========== Starting fetch for {event_type_name} ==========")
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Full last_run data: {last_run_data}")
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Using 'after' timestamp: {after}")
        if after:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: 'after' as human readable: {_timestamp_to_human_readable(after)}")
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: {_get_time_gap_info(after)}")

        # add the time filter
        if after:
            filters["date"] = {"gte": after}  # type: ignore

        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Sending request with filters: {filters}")
        self.client.request.params["filters"] = json.dumps(filters)

        response = self.client.call(self.client.request)
        response_json = response.json()

        # Enhanced response logging
        events = response_json.get("data", [])
        has_next = response_json.get("hasNext")
        total = response_json.get("total", "N/A")

        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Response for {event_type_name}:")
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   - Event count: {len(events)}")
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   - hasNext: {has_next}")
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   - total (if available): {total}")

        # Log additional response fields that might be useful
        other_fields = {k: v for k, v in response_json.items() if k not in ["data", "hasNext", "total"]}
        if other_fields:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   - Other response fields: {other_fields}")

        # If no events, log more details
        if len(events) == 0:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: WARNING - Zero events returned for {event_type_name}")
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Full response (truncated): {str(response_json)[:500]}")
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: This could indicate:")
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   1. No new events since timestamp {after}")
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   2. API data availability issue")
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   3. Filter mismatch")
        else:
            # Log first and last event timestamps
            first_event_ts = events[0].get("timestamp", "N/A")
            last_event_ts = events[-1].get("timestamp", "N/A")
            first_ts_str = _timestamp_to_human_readable(first_event_ts) if isinstance(first_event_ts, int) else "N/A"
            last_ts_str = _timestamp_to_human_readable(last_event_ts) if isinstance(last_event_ts, int) else "N/A"
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: First event timestamp: {first_event_ts} ({first_ts_str})")
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Last event timestamp: {last_event_ts} ({last_ts_str})")

        demisto.debug(f"MD: Got {len(events)} events for {event_type_name=}")

        # add new field with the event type
        for event in events:
            event["event_type_name"] = event_type_name

        yield events

        page_count = 1
        while has_next:
            page_count += 1
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Fetching page {page_count} for {event_type_name}")
            demisto.debug("MD: Got more events to fetch")
            last = events.pop()
            last_timestamp = last["timestamp"]
            ts_readable = _timestamp_to_human_readable(last_timestamp)
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Setting next filter timestamp: {last_timestamp} ({ts_readable})")

            self.client.set_request_filter(last_timestamp)
            response = self.client.call(self.client.request)
            response_json = response.json()
            events = response_json.get("data", [])
            has_next = response_json.get("hasNext")

            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Page {page_count} - Got {len(events)} events, hasNext: {has_next}")
            demisto.debug(f"MD: Got {len(events)} events for {event_type_name=}")

            # add new field with the event type
            for event in events:
                event["event_type_name"] = event_type_name

            yield events

        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: ===== Finished {event_type_name} (pages: {page_count}) =====")

    def get_last_run(self, events: list) -> dict:
        last_run = demisto.getLastRun()
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: ========== Calculating next last_run ==========")
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Current last_run: {last_run}")
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Total events to process: {len(events)}")
        demisto.debug(f"MD: Got the last run: {last_run}")

        alerts_last_run = 0
        activities_admin_last_run = 0
        activities_login_last_run = 0

        # Count events by type
        event_counts = {"alerts": 0, "activities_login": 0, "activities_admin": 0}

        for event in events:
            event_type = event["event_type_name"]
            timestamp = event["timestamp"]
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            demisto.debug(f"MD: Got event from type {event_type}, with timestamp {timestamp}")
            if event_type == "alerts":
                alerts_last_run = timestamp
            elif event_type == "activities_login":
                activities_login_last_run = timestamp
            elif event_type == "activities_admin":
                activities_admin_last_run = timestamp

        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Event counts by type: {event_counts}")

        # Log what will be updated
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Timestamp updates:")
        if alerts_last_run:
            old_val = last_run.get("alerts", "None")
            new_val = alerts_last_run + 1
            ts_str = _timestamp_to_human_readable(new_val)
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   alerts: {old_val} -> {new_val} ({ts_str})")
            last_run["alerts"] = new_val
        else:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   alerts: NOT UPDATED (no events)")

        if activities_login_last_run:
            old_val = last_run.get("activities_login", "None")
            new_val = activities_login_last_run + 1
            ts_str = _timestamp_to_human_readable(new_val)
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   activities_login: {old_val} -> {new_val} ({ts_str})")
            last_run["activities_login"] = new_val
        else:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   activities_login: NOT UPDATED (no events)")

        if activities_admin_last_run:
            old_val = last_run.get("activities_admin", "None")
            new_val = activities_admin_last_run + 1
            ts_str = _timestamp_to_human_readable(new_val)
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   activities_admin: {old_val} -> {new_val} ({ts_str})")
            last_run["activities_admin"] = new_val
        else:
            demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]:   activities_admin: NOT UPDATED (no events)")

        # Ensure all requested types are in last_run
        for event_type, start_time in self.requested_start_times.items():
            if event_type not in last_run and start_time:
                demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Initializing missing last_run key for {event_type} with {start_time}")
                last_run[event_type] = start_time

        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Final last_run: {last_run}")
        demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: ========== Finished calculating last_run ==========")
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
        get_events.client.request.params = {"limit": 1}
        get_events.options.limit = 1
        get_events.run()
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "authenticate" in str(e):
            message = AUTH_ERROR_MSG
        else:
            raise
    return message


def main(command: str, demisto_params: dict):
    demisto.debug(f"MD: Command being called is {command}")
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Debug version active - enhanced logging enabled")
    demisto.debug(f"MD-DEBUG [{DEBUG_VERSION}]: Current time: {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")

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
        client = DefenderClient(
            request=request,
            options=options,
            authenticator=authenticator,
            after=after,  # type:ignore[arg-type]
        )
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
                next_run = get_events.get_last_run(events)
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
