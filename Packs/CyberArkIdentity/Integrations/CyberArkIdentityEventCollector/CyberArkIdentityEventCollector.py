# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument
import urllib3
from SiemApiModule import *  # noqa: E402

urllib3.disable_warnings()

# -----------------------------------------  GLOBAL VARIABLES  -----------------------------------------
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
EVENT_FIELDS = [
    "ID",
    "EventType",
    "AuthMethod",
    "DirectoryServiceUuid",
    "DirectoryServicePartnerName",
    "EntityName",
    "EntityType",
    "EntityUuid",
    "FromIPAddress",
    "ImpersonatorUuid",
    "Level",
    "NewEntity",
    "NormalizedUser",
    "OldEntity",
    "RequestDeviceOS",
    "RequestHostName",
    "RequestIsMobileDevice",
    "Tenant",
    "UserGuid",
    "WhenLogged",
    "WhenOccurred",
    "ObjectName",
    "ObjectType",
    "RoleId",
    "Role",
    "Changer",
    "ChangerUuid",
    "Result",
    "Alias",
    "ReplaceDomain",
    "Type",
    "Id",
    "ProfileName",
    "Thumbprint",
    "TargetUserID",
    "TargetUser",
    "Uuid",
    "Key",
    "Value",
    "UserState",
    "PreviousUserState",
    "FailedMessage",
    "Exception",
    "DSType",
    "DSName",
    "DSUuid",
    "ImpersonateTargetUuid",
    "ImpersonateTargetName",
    "EmailAddress",
    "Session",
    "MfaResult",
    "MfaReason",
    "SetPath",
    "ProxyId",
    "MachineName",
    "ClientAddress",
    "ConnectorUuid",
    "HostAddress",
    "UserName",
    "Target",
    "Cname",
    "OldState",
    "NewState",
    "AffectedTenant",
    "OU",
    "DeviceID",
    "EnrollProfileUser",
    "LocalAccountUuid",
    "DeviceName",
    "FailureReason",
    "From",
    "To",
    "Description",
    "DeleteReason",
    "LicenseType",
    "NewLicenseType",
    "OldLicenseType",
    "ApplicationType",
    "ApplicationName",
    "ApplicationID",
    "MobileAppType",
    "AppId",
    "AppName",
    "JobUniqueId",
    "SyncAction",
    "SyncActionReason",
    "SyncResult",
    "SessionId",
]
PRODUCT = "identity"
VENDOR = "cyberark"
# Events per RedRock page.
PAGE_SIZE = 1000
# Max pages per fetch-events run; the next run continues from the cursor.
MAX_PAGES_PER_FETCH = 10


class CyberArkIdentityEventsOptions(IntegrationOptions):
    app_id: str


class CyberArkIdentityEventsRequest(IntegrationHTTPRequest):
    method: Method = Method.POST
    headers: dict = {"Accept": "*/*", "Content-Type": "application/json"}


class CyberArkIdentityEventsClient(IntegrationEventsClient):
    request: IntegrationHTTPRequest
    options: CyberArkIdentityEventsOptions

    def __init__(
        self,
        request: CyberArkIdentityEventsRequest,
        options: CyberArkIdentityEventsOptions,
        credentials: Credentials,
        session=requests.Session(),
    ) -> None:
        self.access_token = None
        self.credentials = credentials
        super().__init__(request, options, session)

    def set_request_filter(self, after: Any):
        return after

    def authenticate(self):
        demisto.debug("[authenticate] Authenticating against the CyberArk Identity OAuth platformtoken endpoint.")
        credentials = base64.b64encode(f"{self.credentials.identifier}:{self.credentials.password}".encode()).decode()
        token_url = f"{str(self.request.url).removesuffix('/RedRock/Query')}/oauth2/platformtoken"
        demisto.debug(f"[authenticate] Requesting access token from {token_url}.")
        request = IntegrationHTTPRequest(
            method=Method.POST,
            url=token_url,  # type: ignore[arg-type]
            headers={"Authorization": f"Basic {credentials}"},
            data={"grant_type": "client_credentials", "scope": "siem"},
            verify=self.request.verify,
        )

        response = self.call(request)
        if response.ok:
            demisto.debug(f"[authenticate] Authenticated successfully (status code {response.status_code}).")
            self.access_token = response.json()["access_token"]
            self.request.headers["Authorization"] = f"Bearer {self.access_token}"
        else:
            demisto.debug(f"[authenticate] Authentication failed (status code {response.status_code}): {response.json()}")


class CyberArkIdentityGetEvents(IntegrationGetEvents):
    client: CyberArkIdentityEventsClient

    @staticmethod
    def get_when_occurred_ms(event: dict) -> int:
        """Return WhenOccurred ('/Date(1651483379362)/') as epoch milliseconds."""
        return int(str(event.get("WhenOccurred", "")).removesuffix(")/").removeprefix("/Date("))

    @staticmethod
    def get_last_run_time(last_timestamp_ms: int) -> str:
        # Integer math, so the cursor matches the event's millisecond exactly.
        last_run_time = (datetime(1970, 1, 1) + timedelta(milliseconds=last_timestamp_ms)).strftime(DATETIME_FORMAT)
        demisto.debug(f"[get_last_run_time] Computed last-run cursor (max WhenOccurred) = {last_run_time}.")
        return last_run_time

    @staticmethod
    def get_last_run_ids(events: list, last_timestamp_ms: int) -> list:
        # The next query is >= cursor, so only events at the cursor millisecond can repeat.
        ids = [event.get("ID") for event in events if CyberArkIdentityGetEvents.get_when_occurred_ms(event) == last_timestamp_ms]
        demisto.debug(f"[get_last_run_ids] Kept {len(ids)} event IDs at the cursor millisecond for the next-run dedup list.")
        return ids

    def get_last_run(self, events: list) -> dict:  # type: ignore
        last_timestamp_ms = max(self.get_when_occurred_ms(event) for event in events)
        last_run_time = self.get_last_run_time(last_timestamp_ms)
        ids = self.get_last_run_ids(events, last_timestamp_ms)
        previous_last_run = demisto.getLastRun()
        if previous_last_run.get("from") == last_run_time:
            # Cursor didn't move: keep the previous IDs too.
            ids = list(dict.fromkeys(previous_last_run.get("ids", []) + ids))
            demisto.debug(f"[get_last_run] Cursor did not move; merged with the previous dedup list ({len(ids)} ids).")
        last_run = {"from": last_run_time, "ids": ids}
        demisto.debug(f"[get_last_run] Built last run with from={last_run['from']} and {len(last_run['ids'])} ids.")
        return last_run

    @staticmethod
    def _parse_redrock_response(response_json: dict, page_number: int) -> dict:
        """Return the response's Result, or raise if RedRock returned success=false / Result=null."""
        result = response_json.get("Result")
        if response_json.get("success") is False or not isinstance(result, dict):
            error_details = {
                "Message": response_json.get("Message"),
                "MessageID": response_json.get("MessageID"),
                "ErrorID": response_json.get("ErrorID"),
                "ErrorCode": response_json.get("ErrorCode"),
                "Exception": str(response_json.get("Exception"))[:500],
            }
            demisto.debug(f"[_parse_redrock_response] RedRock query failed on page {page_number}: {error_details}")
            raise DemistoException(
                f"CyberArk RedRock query failed on page {page_number}: "
                f"{error_details['Message'] or 'no error message returned'} (ErrorID: {error_details['ErrorID']})"
            )
        return result

    def _set_page_number(self, page_number: int) -> None:
        """Set PageNumber in the request body."""
        body = json.loads(self.client.request.data)  # type: ignore[arg-type]
        body["args"]["PageNumber"] = page_number
        self.client.request.data = json.dumps(body)
        demisto.debug(f"[_set_page_number] Set request PageNumber to {page_number}.")

    def _iter_events(self):
        demisto.debug("[_iter_events] Starting event collection.")
        self.client.authenticate()

        # Set for constant-time lookups.
        fetched_events_ids = set(demisto.getLastRun().get("ids", []))
        demisto.debug(f"[_iter_events] Loaded {len(fetched_events_ids)} already-fetched event IDs from last run for dedup.")
        page_number = 1
        collected = 0

        # Page until all rows are read; fetch-events stops after MAX_PAGES_PER_FETCH pages.
        max_pages = MAX_PAGES_PER_FETCH if demisto.command() == "fetch-events" else None
        while True:
            demisto.debug(f"[_iter_events] Requesting RedRock page {page_number} (PageSize={PAGE_SIZE}).")
            self._set_page_number(page_number)
            result = self._parse_redrock_response(self.client.call(self.client.request).json(), page_number)

            events = result.get("Results") or []
            page_count = len(events)
            if not page_count:
                demisto.debug(f"[_iter_events] Page {page_number} returned no events. Stopping pagination.")
                break

            full_count = result.get("FullCount", page_count)
            collected += page_count
            demisto.debug(
                f"[_iter_events] Page {page_number}: received {page_count} events "
                f"(collected {collected} out of FullCount={full_count})."
            )

            new_events = [event.get("Row") for event in events if event.get("Row", {}).get("ID") not in fetched_events_ids]
            demisto.debug(
                f"[_iter_events] Page {page_number}: {len(new_events)} new events after dedup "
                f"({page_count - len(new_events)} already-seen events skipped)."
            )
            yield new_events

            # Last page.
            if collected >= full_count or page_count < PAGE_SIZE:
                demisto.debug(
                    f"[_iter_events] Finished paginating after page {page_number} "
                    f"(collected={collected}, FullCount={full_count}, page_count={page_count})."
                )
                break

            if max_pages and page_number >= max_pages:
                demisto.debug(
                    f"[_iter_events] Reached the per-fetch cap of {max_pages} pages ({collected} events). "
                    f"The remaining events (FullCount={full_count}) will be collected by the next runs."
                )
                break

            page_number += 1

        demisto.debug(f"[_iter_events] Event collection finished. Total events pulled from RedRock: {collected}.")


def get_request_params(**kwargs: dict) -> dict:
    fetch_from = str(kwargs.get("from", "3 days"))
    demisto.debug(f"[get_request_params] Building request params with 'from'={fetch_from!r}.")
    default_from_day = datetime.now() - timedelta(days=3)
    from_time = datetime.strftime(dateparser.parse(fetch_from, settings={"TIMEZONE": "UTC"}) or default_from_day, DATETIME_FORMAT)
    demisto.debug(f"[get_request_params] Parsed 'from' time (UTC) = {from_time}.")

    params = {
        "url": f"{str(kwargs.get('url', '')).removesuffix('/')}/RedRock/Query",
        "data": json.dumps(
            {
                # Inclusive cursor + ID tiebreak: events at the cursor millisecond repeat and are deduped by ID.
                # Caching=-1 requests live data.
                "Script": f"Select {', '.join(EVENT_FIELDS)} from Event where WhenOccurred >= '{from_time}' "
                f"ORDER BY WhenOccurred ASC, ID ASC",
                "args": {"PageNumber": 1, "PageSize": PAGE_SIZE, "Caching": -1},
            }
        ),
        "verify": not kwargs.get("insecure"),
    }
    demisto.debug(f"[get_request_params] Built request to {params['url']} (verify={params['verify']}).")
    return params


def main(command: str, demisto_params: dict):
    demisto.debug(f"[main] Command '{command}' started (build: XSUP-78439 cap+dedup).")
    credentials = Credentials(**demisto_params.get("credentials", {}))
    options = CyberArkIdentityEventsOptions(**demisto_params)
    # "limit" only applies to cyberarkidentity-get-events; fetch-events is bounded by MAX_PAGES_PER_FETCH.
    if command == "fetch-events":
        demisto.debug(
            f"[main] fetch-events: disabling the collected-events limit (was {options.limit}) to drain the full backlog."
        )
        options.limit = None
    else:
        demisto.debug(f"[main] {command}: using configured limit={options.limit}.")
    request_params = get_request_params(**demisto_params)
    request = CyberArkIdentityEventsRequest(**request_params)
    client = CyberArkIdentityEventsClient(request, options, credentials)
    get_events = CyberArkIdentityGetEvents(client, options)

    try:
        if command == "test-module":
            demisto.debug("[main] Running test-module.")
            get_events.run()
            demisto.results("ok")

        if command in ("fetch-events", "cyberarkidentity-get-events"):
            events = get_events.run()
            demisto.debug(f"[main] Collected {len(events)} events for command '{command}'.")

            if command == "fetch-events" or demisto_params.get("should_push_events"):
                demisto.debug(f"[main] Sending {len(events)} events to XSIAM (vendor={VENDOR}, product={PRODUCT}).")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if events:
                    last_run = get_events.get_last_run(events)
                    demisto.debug(f"[main] Set last run to {last_run}.")
                    demisto.setLastRun(last_run)
                else:
                    demisto.debug("[main] No events collected - last run was not updated.")

            if command == "cyberarkidentity-get-events":
                demisto.debug(f"[main] Returning {len(events)} events as command results.")
                command_results = CommandResults(
                    readable_output=tableToMarkdown(
                        "CyberArk Identity RedRock records", events, removeNull=True, headerTransform=pascalToSpace
                    ),
                    raw_response=events,
                )
                return_results(command_results)

        demisto.debug(f"[main] Command '{command}' finished.")

    except Exception as e:
        demisto.debug(f"[main] Command '{command}' failed with error: {e}")
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params_ = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params_)
