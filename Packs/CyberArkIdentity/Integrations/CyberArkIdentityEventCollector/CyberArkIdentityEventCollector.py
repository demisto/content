# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument
import re
from datetime import UTC

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
# Max events per RedRock page.
PAGE_SIZE = 1000
DEFAULT_LIMIT = 5000
# Epoch milliseconds in a WhenOccurred value, e.g. '/Date(1651483379362)/' or '/Date(1651483379362+0300)/'.
WHEN_OCCURRED_PATTERN = re.compile(r"/Date\((-?\d+)")
EPOCH = datetime(1970, 1, 1)


def ms_to_cursor(milliseconds: int) -> str:
    """Format epoch milliseconds as a cursor string (UTC)."""
    return (EPOCH + timedelta(milliseconds=milliseconds)).strftime(DATETIME_FORMAT)


def cursor_to_ms(cursor: str) -> int:
    """Parse a cursor string (UTC) to epoch milliseconds."""
    return (datetime.strptime(cursor, DATETIME_FORMAT) - EPOCH) // timedelta(milliseconds=1)


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

        try:
            response = self.call(request)  # raises on a non-2xx response
        except DemistoException as e:
            raise DemistoException(f"CyberArk authentication failed: {e}") from e
        body = parse_json_response(response, "CyberArk authentication")
        access_token = body.get("access_token")
        if not access_token:
            raise DemistoException(
                f"CyberArk authentication failed: no access_token in the response (status code {response.status_code})."
            )
        demisto.debug(f"[authenticate] Authenticated successfully (status code {response.status_code}).")
        self.access_token = access_token
        self.request.headers["Authorization"] = f"Bearer {self.access_token}"


class CyberArkIdentityGetEvents(IntegrationGetEvents):
    client: CyberArkIdentityEventsClient

    def __init__(
        self,
        client: CyberArkIdentityEventsClient,
        options: CyberArkIdentityEventsOptions,
        from_time: str,
        last_run: dict | None = None,
        max_events: int | None = None,
        page_size: int = PAGE_SIZE,
        max_pages: int | None = None,
    ) -> None:
        super().__init__(client, options)
        self.from_time = from_time
        self.last_run = last_run or {}
        self.max_events = max_events
        self.page_size = page_size
        self.max_pages = max_pages

    @staticmethod
    def get_when_occurred_ms(event: dict) -> int | None:
        """Return WhenOccurred as epoch milliseconds, or None if it can't be parsed."""
        match = WHEN_OCCURRED_PATTERN.search(str(event.get("WhenOccurred") or ""))
        return int(match.group(1)) if match else None

    @staticmethod
    def get_last_run_ids(events: list, last_timestamp_ms: int) -> list:
        # The next query is >= cursor, so only events at the cursor millisecond can repeat.
        ids = [event.get("ID") for event in events if CyberArkIdentityGetEvents.get_when_occurred_ms(event) == last_timestamp_ms]
        demisto.debug(f"[get_last_run_ids] Kept {len(ids)} event IDs at the cursor millisecond for the next-run dedup list.")
        return ids

    def get_last_run(self, events: list) -> dict:  # type: ignore
        timestamps = [self.get_when_occurred_ms(event) for event in events]
        unparsed_ids = [event.get("ID") for event, ms in zip(events, timestamps, strict=True) if ms is None and event.get("ID")]
        if unparsed_ids:
            demisto.debug(
                f"[get_last_run] {len(unparsed_ids)} events have no parseable WhenOccurred (e.g. {unparsed_ids[:3]}); "
                "they are not used for the cursor."
            )
        parsed = [ms for ms in timestamps if ms is not None]
        if parsed:
            last_timestamp_ms = max(parsed)
            last_run_time = ms_to_cursor(last_timestamp_ms)
            ids = self.get_last_run_ids(events, last_timestamp_ms)
        else:
            last_run_time, ids = self.from_time, []
        if last_run_time == self.from_time:
            # Cursor didn't move: keep the previous IDs too.
            ids = self.last_run.get("ids", []) + ids
            demisto.debug("[get_last_run] Cursor did not move; merged with the previous dedup list.")
        # Unparsed events may be returned again, so keep their IDs for dedup.
        last_run = {"from": last_run_time, "ids": list(dict.fromkeys(ids + unparsed_ids))}
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
                "Exception": str(response_json.get("Exception") or "")[:500],
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

    def _filter_new_events(self, rows: list, seen_ids: set, cursor_ms: int, page_number: int) -> list:
        """Drop rows already sent or older than the cursor, and add the kept IDs to seen_ids."""
        new_events = []
        duplicates = older = 0
        for row in rows:
            if not row:
                continue
            event_id = row.get("ID")
            if event_id and event_id in seen_ids:
                duplicates += 1
                continue
            when_occurred_ms = self.get_when_occurred_ms(row)
            # Client-side check, so dedup doesn't depend on how RedRock compares the cursor.
            if when_occurred_ms is not None and when_occurred_ms < cursor_ms:
                older += 1
                continue
            if event_id:
                seen_ids.add(event_id)
            new_events.append(row)
        demisto.debug(
            f"[_iter_events] Page {page_number}: {len(new_events)} new events "
            f"({duplicates} already seen, {older} older than the cursor skipped)."
        )
        return new_events

    def _iter_events(self):
        demisto.debug("[_iter_events] Starting event collection.")
        self.client.authenticate()

        cursor_ms = cursor_to_ms(self.from_time)
        page_size = self.page_size
        # The last run's boundary IDs, plus every ID collected in this run.
        seen_ids = set(self.last_run.get("ids", []))
        demisto.debug(f"[_iter_events] Loaded {len(seen_ids)} already-fetched event IDs from last run for dedup.")
        page_number = 1
        collected = 0
        kept = 0

        while True:
            demisto.debug(f"[_iter_events] Requesting RedRock page {page_number} (PageSize={page_size}).")
            self._set_page_number(page_number)
            response = self.client.call(self.client.request)
            result = self._parse_redrock_response(parse_json_response(response, "CyberArk RedRock query"), page_number)

            results = result.get("Results") or []
            page_count = len(results)
            if not page_count:
                demisto.debug(f"[_iter_events] Page {page_number} returned no events. Stopping pagination.")
                break

            # FullCount can be null; then only a short page ends the paging.
            full_count = result.get("FullCount")
            collected += page_count
            demisto.debug(
                f"[_iter_events] Page {page_number}: received {page_count} events "
                f"(collected {collected} out of FullCount={full_count})."
            )
            new_events = self._filter_new_events([item.get("Row") for item in results], seen_ids, cursor_ms, page_number)
            if self.max_events is not None:
                new_events = new_events[: self.max_events - kept]
            kept += len(new_events)
            yield new_events

            # Last page.
            if (full_count is not None and collected >= full_count) or page_count < page_size:
                demisto.debug(
                    f"[_iter_events] Finished paginating after page {page_number} "
                    f"(collected={collected}, FullCount={full_count}, page_count={page_count})."
                )
                break

            if self.max_events is not None and kept >= self.max_events:
                demisto.debug(
                    f"[_iter_events] Reached the limit of {self.max_events} events. "
                    f"The remaining events (FullCount={full_count}) will be collected by the next runs."
                )
                break

            if self.max_pages and page_number >= self.max_pages:
                demisto.debug(f"[_iter_events] Reached the cap of {self.max_pages} pages.")
                break

            page_number += 1

        demisto.debug(f"[_iter_events] Event collection finished. Pulled {collected} events from RedRock, kept {kept}.")


def parse_json_response(response: requests.Response, source: str) -> dict:
    """Return the response body as a dict, or raise a clear error for a non-JSON or non-object body."""
    try:
        body = response.json()
    except ValueError as e:
        raise DemistoException(
            f"{source} returned a non-JSON response (status code {response.status_code}): {response.text[:200]}"
        ) from e
    if not isinstance(body, dict):
        raise DemistoException(f"{source} returned an unexpected response (status code {response.status_code}).")
    return body


def get_from_time(demisto_params: dict, last_run: dict) -> str:
    """Return the query cursor: the saved last-run cursor if there is one, otherwise the first fetch time."""
    if last_run_from := last_run.get("from"):
        try:
            return datetime.strptime(str(last_run_from), DATETIME_FORMAT).strftime(DATETIME_FORMAT)
        except ValueError as e:
            raise DemistoException(
                f"Invalid saved last run cursor {last_run_from!r}, expected the format {DATETIME_FORMAT}. "
                "Reset the last run of the instance to recover."
            ) from e
    fetch_from = str(demisto_params.get("from") or "3 days")
    default_from = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=3)
    parsed = dateparser.parse(fetch_from, settings={"TIMEZONE": "UTC", "TO_TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": False})
    return (parsed or default_from).strftime(DATETIME_FORMAT)


def get_request_params(from_time: str, url: str, insecure: Any = False, page_size: int = PAGE_SIZE) -> dict:
    return {
        "url": f"{str(url or '').removesuffix('/')}/RedRock/Query",
        "data": json.dumps(
            {
                # Inclusive cursor + ID tiebreak: events at the cursor millisecond repeat and are deduped by ID.
                # Caching=-1 requests live data.
                "Script": f"Select {', '.join(EVENT_FIELDS)} from Event where WhenOccurred >= '{from_time}' "
                f"ORDER BY WhenOccurred ASC, ID ASC",
                "args": {"PageNumber": 1, "PageSize": page_size, "Caching": -1},
            }
        ),
        "verify": not insecure,
    }


def main(command: str, demisto_params: dict):
    demisto.debug(f"[main] Command '{command}' started.")

    try:
        credentials = Credentials(**demisto_params.get("credentials", {}))
        # The limit is applied in _iter_events, so turn off the base class's own truncation.
        options = CyberArkIdentityEventsOptions(**(demisto_params | {"limit": None}))
        limit = arg_to_number(demisto_params.get("limit"), arg_name="limit")
        if limit is None:
            limit = DEFAULT_LIMIT
        if limit < 1:
            raise DemistoException(f"limit must be a positive number, got {limit}.")
        max_events = 1 if command == "test-module" else limit
        page_size = min(max_events, PAGE_SIZE)
        should_push = command == "fetch-events" or (
            command == "cyberarkidentity-get-events" and argToBoolean(demisto_params.get("should_push_events", False))
        )
        # Only runs that push events use and move the saved cursor. test-module and a display-only
        # command start from the first fetch time (or the command's 'from' argument) instead.
        last_run = (demisto.getLastRun() or {}) if should_push else {}
        demisto.debug(f"[main] {command}: collecting up to {max_events} events (PageSize={page_size}, push={should_push}).")

        from_time = get_from_time(demisto_params, last_run)
        request = CyberArkIdentityEventsRequest(
            **get_request_params(from_time, demisto_params.get("url", ""), demisto_params.get("insecure"), page_size)
        )
        client = CyberArkIdentityEventsClient(request, options, credentials)
        get_events = CyberArkIdentityGetEvents(
            client,
            options,
            from_time=from_time,
            last_run=last_run,
            max_events=max_events,
            page_size=page_size,
            max_pages=1 if command == "test-module" else None,
        )

        if command == "test-module":
            demisto.debug("[main] Running test-module.")
            get_events.run()
            demisto.results("ok")

        if command in ("fetch-events", "cyberarkidentity-get-events"):
            events = get_events.run()
            demisto.debug(f"[main] Collected {len(events)} events for command '{command}'.")

            if should_push:
                demisto.debug(f"[main] Sending {len(events)} events to XSIAM (vendor={VENDOR}, product={PRODUCT}).")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if events:
                    next_last_run = get_events.get_last_run(events)
                    demisto.debug(f"[main] Set last run to {next_last_run}.")
                    demisto.setLastRun(next_last_run)
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
    # Command arguments override instance parameters. The last run is read in main().
    main(demisto.command(), demisto.params() | demisto.args())
