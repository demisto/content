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
# The maximum number of events to request from RedRock in a single page.
# RedRock queries time out after two minutes, so we page through the results
# instead of requesting everything at once.
PAGE_SIZE = 1000


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
        request = IntegrationHTTPRequest(
            method=Method.POST,
            url=f"{str(self.request.url).removesuffix('/RedRock/Query')}/oauth2/platformtoken",  # type: ignore[arg-type]
            headers={"Authorization": f"Basic {credentials}"},
            data={"grant_type": "client_credentials", "scope": "siem"},
            verify=self.request.verify,
        )

        response = self.call(request)
        if response.ok:
            demisto.debug("authenticated successfully")
            self.access_token = response.json()["access_token"]
            self.request.headers["Authorization"] = f"Bearer {self.access_token}"
        else:
            demisto.debug(f"authentication failed: {response.json()}")


class CyberArkIdentityGetEvents(IntegrationGetEvents):
    client: CyberArkIdentityEventsClient

    @staticmethod
    def get_last_run_ids(events: list) -> list:
        return [event.get("ID") for event in events]

    @staticmethod
    def get_last_run_time(events: list) -> str:
        # The date is in timestamp format and looks like {'WhenOccurred': '/Date(1651483379362)/'}
        last_timestamp = max([int(e.get("WhenOccurred", "").removesuffix(")/").removeprefix("/Date(")) for e in events])

        return datetime.utcfromtimestamp(last_timestamp / 1000).strftime(DATETIME_FORMAT)

    def get_last_run(self, events: list) -> dict:  # type: ignore
        return {"from": self.get_last_run_time(events), "ids": self.get_last_run_ids(events)}

    def _set_page_number(self, page_number: int) -> None:
        """Update the PageNumber in the request body so the next call fetches the given page."""
        body = json.loads(self.client.request.data)  # type: ignore[arg-type]
        body["args"]["PageNumber"] = page_number
        self.client.request.data = json.dumps(body)

    def _iter_events(self):
        self.client.authenticate()

        fetched_events_ids = demisto.getLastRun().get("ids", [])
        page_number = 1
        collected = 0

        # RedRock returns at most PageSize rows per call and reports the total number of
        # matching rows in "FullCount". We page through the result set (ordered ascending by
        # WhenOccurred) until we have collected every matching row, so no events are dropped
        # when a single fetch window contains more than one page of events.
        while True:
            self._set_page_number(page_number)
            result = self.client.call(self.client.request).json().get("Result") or {}

            events = result.get("Results") or []
            page_count = len(events)
            if not page_count:
                break

            full_count = result.get("FullCount", page_count)
            collected += page_count
            demisto.debug(f"CyberArk RedRock page {page_number}: got {page_count} events (collected {collected}/{full_count})")

            yield [event.get("Row") for event in events if event.get("Row", {}).get("ID") not in fetched_events_ids]

            # Stop once we've drained every matching row, or the page was not full (last page).
            if collected >= full_count or page_count < PAGE_SIZE:
                break

            page_number += 1


def get_request_params(**kwargs: dict) -> dict:
    fetch_from = str(kwargs.get("from", "3 days"))
    default_from_day = datetime.now() - timedelta(days=3)
    from_time = datetime.strftime(dateparser.parse(fetch_from, settings={"TIMEZONE": "UTC"}) or default_from_day, DATETIME_FORMAT)

    params = {
        "url": f"{str(kwargs.get('url', '')).removesuffix('/')}/RedRock/Query",
        "data": json.dumps(
            {
                # Order ascending by WhenOccurred so pagination is deterministic and the last-run
                # cursor (max WhenOccurred) is safe. Caching=-1 requests live (non-cached) data.
                "Script": f"Select {', '.join(EVENT_FIELDS)} from Event where WhenOccurred > '{from_time}' "
                f"ORDER BY WhenOccurred ASC",
                "args": {"PageNumber": 1, "PageSize": PAGE_SIZE, "Caching": -1},
            }
        ),
        "verify": not kwargs.get("insecure"),
    }
    return params


def main(command: str, demisto_params: dict):
    credentials = Credentials(**demisto_params.get("credentials", {}))
    options = CyberArkIdentityEventsOptions(**demisto_params)
    # On fetch-events we must drain the full backlog, so the configured "limit" must not
    # truncate the collected events (otherwise events beyond the limit are silently dropped
    # and the cursor advances past them). "limit" is only meant to cap the manual
    # cyberarkidentity-get-events command.
    if command == "fetch-events":
        options.limit = 0
    request_params = get_request_params(**demisto_params)
    request = CyberArkIdentityEventsRequest(**request_params)
    client = CyberArkIdentityEventsClient(request, options, credentials)
    get_events = CyberArkIdentityGetEvents(client, options)

    try:
        if command == "test-module":
            get_events.run()
            demisto.results("ok")

        if command in ("fetch-events", "cyberarkidentity-get-events"):
            events = get_events.run()

            if command == "fetch-events" or demisto_params.get("should_push_events"):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if events:
                    last_run = get_events.get_last_run(events)
                    demisto.debug(f"Set last run to {last_run}")
                    demisto.setLastRun(last_run)

            if command == "cyberarkidentity-get-events":
                command_results = CommandResults(
                    readable_output=tableToMarkdown(
                        "CyberArk Identity RedRock records", events, removeNull=True, headerTransform=pascalToSpace
                    ),
                    raw_response=events,
                )
                return_results(command_results)

    except Exception as e:
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params_ = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params_)
