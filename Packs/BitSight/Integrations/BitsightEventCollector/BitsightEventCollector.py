from datetime import datetime, timedelta
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = "Bitsight"
PRODUCT = "Bitsight"

BITSIGHT_DATE_FORMAT = "%Y-%m-%d"  # TODO can this be improved?
DEFAULT_MAX_FETCH = 1000
# Lookback windows
FETCH_EVENTS_LOOKBACK_HOURS = 1
GET_EVENTS_LOOKBACK_DAYS = 1

# Bitsight headers per existing integration
CALLING_PLATFORM_VERSION = "XSIAM"
CONNECTOR_NAME_VERSION = f"Bitsight - {get_pack_version() or '1.0.0'}"


class Client(BaseClient):
    """Client to interact with Bitsight API."""

    def get_companies_guid(self) -> dict[str, Any]:
        """Retrieve the companies metadata for the authenticated API key.

        Returns:
            dict[str, Any]: The response payload from Bitsight's `/v1/companies` API, containing
            information about the authorized company (e.g., `myCompany`) and related metadata.
        """
        return self._http_request(method="GET", url_suffix="v1/companies")

    def get_company_findings(
        self,
        guid: str,
        first_seen_gte: str,
        last_seen_lte: str,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        """Get company findings for given guid and time range.

        Args:
            guid (str): guid of the company whose findings need to be retrieved
            first_seen_gte (str): first seen date (YYYY-MM-DD) of the findings
            last_seen_lte (str): last seen date (YYYY-MM-DD) of the findings
            limit (int): maximum number of findings to return
            offset (int): offset to begin returning findings from

        Returns:
            dict[str, Any]: findings response
        """
        params = {
            "first_seen_gte": first_seen_gte,
            "last_seen_lte": last_seen_lte,
            "unsampled": "true",
            "expand": "attributed_companies",
            "limit": limit,
            "offset": offset,
        }
        return self._http_request(method="GET", url_suffix=f"v1/companies/{encode_string_results(guid)}/findings", params=params)


def to_bitsight_date(ts: int) -> str:
    """Convert a UNIX timestamp (seconds) to Bitsight date format (YYYY-MM-DD).

    Args:
        ts (int): UNIX timestamp in seconds.

    Returns:
        str: Date string formatted as YYYY-MM-DD (UTC).
    """
    return datetime.utcfromtimestamp(ts).strftime(BITSIGHT_DATE_FORMAT)


def findings_to_events(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Transform Bitsight findings into XSIAM event objects.

    - Preserves original finding fields.
    - Sets the XSIAM `_time` field using the finding's `first_seen` (YYYY-MM-DD) when available.

    Args:
        findings (list[dict[str, Any]]): A list of Bitsight findings as returned from the API.

    Returns:
        list[dict[str, Any]]: A list of event dictionaries suitable for pushing to XSIAM.
        
    Raises:
        ValueError: If a finding is missing both first_seen and firstSeen fields.
    """
    events: list[dict[str, Any]] = []
    for f in findings:
        event = dict(f)  # keep original keys
        # Set XSIAM time field to first_seen
        first_seen = f.get("first_seen") or f.get("firstSeen")
        if first_seen:
            # Bitsight returns YYYY-MM-DD for first_seen
            try:
                dt = datetime.strptime(first_seen, BITSIGHT_DATE_FORMAT)
                event["_time"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception as e:
                demisto.debug(f"Failed to parse first_seen date '{first_seen}' for finding {f.get('id', 'unknown')}: {e}")
                event["_time"] = first_seen
        else:
            finding_id = f.get('id', 'unknown')
            raise ValueError(
                f"No first_seen date found for finding {finding_id}. "
                "All findings must have a first_seen or firstSeen field."
            )
        events.append(event)
    return events


def fetch_events(
    client: Client,
    guid: str,
    max_fetch: int,
    last_run: dict[str, Any],
    start_time: int,
    end_time: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch Bitsight findings as events using offset pagination within a time window.

    This function pages through Bitsight findings for the specified company and time range,
    converts the results to events, and returns both the events and an updated `last_run`
    object to persist collection state (offset/window).

    Args:
        client (Client): Initialized API client.
        guid (str): Company GUID to collect findings for.
        max_fetch (int): Maximum number of findings to request for this page.
        last_run (dict[str, Any]): State from the previous run (expects keys `window_start`, `offset`).
        start_time (int): Window start in UNIX epoch seconds.
        end_time (int): Window end in UNIX epoch seconds.

    Returns:
        tuple[list[dict[str, Any]], dict[str, Any]]: The list of events and the updated `last_run` state.
    """
    window_start = last_run.get("window_start", start_time)
    offset = last_run.get("offset", 0)

    first_seen_gte = to_bitsight_date(window_start)
    last_seen_lte = to_bitsight_date(end_time)

    res = client.get_company_findings(
        guid, first_seen_gte=first_seen_gte, last_seen_lte=last_seen_lte, limit=max_fetch, offset=offset
    )
    findings = res.get("results", [])
    count = len(findings)

    events = findings_to_events(findings)

    # Update last_run
    new_offset = offset + count
    new_last_run: dict[str, Any] = {
        "window_start": window_start,
        "offset": new_offset,
    }

    # If fewer than requested returned, we likely exhausted window; move window to end_time and reset offset for next run
    if count == 0 or (count < max_fetch and not res.get("links", {}).get("next")):
        new_last_run = {
            "window_start": end_time,
            "offset": 0,
        }

    return events, new_last_run


def bitsight_get_events_command(client: Client, guid: str, limit: int, should_push: bool) -> CommandResults:
    """Command implementation for `bitsight-get-events`.

    Executes a one-off retrieval of findings for the last 1 day (24 hours) and optionally
    pushes them to XSIAM when `should_push_events=true`.

    Args:
        client (Client): Initialized API client.
        guid (str): Resolved company GUID to collect findings for.
        limit (int): Max events to fetch in this invocation.
        should_push (bool): When true, pushes events to XSIAM; otherwise returns them as output only.

    Returns:
        CommandResults: CommandResults object with table output (when not pushing) or a summary message.
    """
    last_run = demisto.getLastRun() or {}
    # Hardcode a 1-day window for this command: [now-1day, now]
    start_ts, end_ts = time_window(days=GET_EVENTS_LOOKBACK_DAYS)

    events, new_last_run = fetch_events(
        client, guid=guid, max_fetch=int(limit), last_run=last_run, start_time=start_ts, end_time=end_ts
    )

    title = "Bitsight Findings Events (pushed)" if should_push else "Bitsight Findings Events"
    if should_push:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    return CommandResults(readable_output=tableToMarkdown(title, events, removeNull=True))


def test_module(client: Client, guid: str | None) -> str:
    """Validate connection and optional GUID permissions.

    Performs a lightweight API call to ensure credentials are valid. If a GUID is provided
    in integration parameters, also validates that the findings endpoint for that GUID is reachable.

    Args:
        client (Client): Initialized API client.
        guid (str | None): Optional company GUID to validate findings access for.

    Returns:
        str: "ok" when validation succeeds; otherwise raises an error.
    """
    # Validate credentials and, if guid provided, that findings endpoint is reachable
    try:
        # simple call to companies to validate auth
        client.get_companies_guid()
        if guid:
            start, end = time_window(days=1)
            client.get_company_findings(guid, to_bitsight_date(start), to_bitsight_date(end), limit=1, offset=0)
    except DemistoException as e:
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        raise
    return "ok"


""" HELPER FUNCTIONS """

def time_window(*, hours: int | None = None, days: int | None = None) -> tuple[int, int]:
    """Return a [start_ts, end_ts] window ending at now using hours or days back.

    Exactly one of `hours` or `days` should be provided.
    """
    now_dt = datetime.now()
    if hours is not None and days is None:
        start_dt = now_dt - timedelta(hours=hours)
    elif days is not None and hours is None:
        start_dt = now_dt - timedelta(days=days)
    else:
        raise ValueError("Provide exactly one of 'hours' or 'days'.")
    return int(start_dt.timestamp()), int(now_dt.timestamp())


def resolve_guid(client: Client, guid_from_args: str | None, guid_from_params: str | None) -> str:
    """Resolve the company GUID, preferring command arg, then integration param, then myCompany.

    Raises ValueError if no GUID could be determined.
    """
    guid = guid_from_args or guid_from_params
    if guid:
        return guid
    companies = client.get_companies_guid()
    guid = (companies.get("myCompany") or {}).get("guid")
    if not guid:
        raise ValueError("Company GUID is required. Provide it as an argument or in the integration parameters.")
    return guid


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("base_url") or "https://api.bitsighttech.com"
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    api_key = params.get("apikey", "")

    demisto.debug(f"Command being called is {command}")

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        ok_codes=[200],
        auth=requests.auth.HTTPBasicAuth(api_key, ""),
        headers={
            "X-BITSIGHT-CALLING-PLATFORM_VERSION": CALLING_PLATFORM_VERSION,
            "X-BITSIGHT-CONNECTOR-NAME-VERSION": CONNECTOR_NAME_VERSION,
        },
    )

    try:
        if command == "test-module":
            return_results(test_module(client, params.get("guid")))

        elif command == "fetch-events":
            max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH))
            guid = resolve_guid(client, None, params.get("guid"))
            last_run = demisto.getLastRun() or {}
            # Hardcode a 1-hour window for scheduled fetch: [now-1hour, now]
            start_ts, end_ts = time_window(hours=FETCH_EVENTS_LOOKBACK_HOURS)
            events, new_last_run = fetch_events(
                client, guid=guid, max_fetch=int(max_fetch), last_run=last_run, start_time=start_ts, end_time=end_ts
            )
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(new_last_run)
            demisto.debug(f"Fetched and pushed {len(events)} events")
            return

        elif command == "bitsight-get-events":
            should_push = argToBoolean(args.get("should_push_events", "false"))
            limit = arg_to_number(args.get("limit", 100))
            guid = resolve_guid(client, args.get("guid"), params.get("guid"))
            return_results(bitsight_get_events_command(client, guid, limit, should_push))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {e}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
