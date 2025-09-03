from datetime import datetime, timedelta, UTC
from typing import Any
import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = "Bitsight"
PRODUCT = "Bitsight"

BITSIGHT_DATE_FORMAT = "%Y-%m-%d"
DEFAULT_MAX_FETCH = 1000
GET_EVENTS_LOOKBACK_DAYS = 2

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
    return datetime.fromtimestamp(ts, tz=UTC).strftime(BITSIGHT_DATE_FORMAT)


def findings_to_events(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Transform Bitsight findings into XSIAM event objects.

    - Preserves original finding fields.
    - Sets the XSIAM `_time` field using the finding's `first_seen` (YYYY-MM-DD) when available.
    - Collects findings without dates for later error handling.

    Args:
        findings (list[dict[str, Any]]): A list of Bitsight findings as returned from the API.

    Returns:
        tuple[list[dict[str, Any]], list[str]]: A tuple containing:
            - A list of event dictionaries suitable for pushing to XSIAM
            - A list of finding IDs that lack date fields (for error handling after offset update)
    """
    events: list[dict[str, Any]] = []
    missing_date_findings: list[str] = []

    for f in findings:
        event = dict(f)
        # Set XSIAM time field to first_seen
        first_seen = f.get("first_seen") or f.get("firstSeen")
        if first_seen:
            # Bitsight returns YYYY-MM-DD for first_seen
            try:
                first_seen_dt = datetime.strptime(first_seen, BITSIGHT_DATE_FORMAT)
                event["_time"] = first_seen_dt.strftime("%Y-%m-%dT%H:%M:%S")
            except Exception as e:
                demisto.debug(f"Failed to parse first_seen date '{first_seen}' for finding {f.get('id', 'unknown')}: {e}")
                event["_time"] = first_seen
        else:
            # Track findings missing dates for later error handling
            finding_id = f.get("id", "unknown")
            missing_date_findings.append(finding_id)

        events.append(event)

    return events, missing_date_findings


def fetch_events(
    client: Client,
    guid: str,
    max_fetch: int,
    last_run: dict[str, Any],
    lookback_days: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Fetch Bitsight findings as events using offset pagination from a fixed starting date.

    This function pages through Bitsight findings for the specified company starting from
    a fixed date (first_fetch) and uses offset pagination to avoid duplicates.
    Since the API only supports date-level precision, we start from current date for scheduled
    fetches or use lookback_days for command calls.

    Args:
        client (Client): Initialized API client.
        guid (str): Company GUID to collect findings for.
        max_fetch (int): Maximum number of findings to request for this page.
        last_run (dict[str, Any]): State from the previous run (expects keys `first_fetch`, `offset`).
        lookback_days (int | None): Days to look back for initial fetch. If None, uses current date.

    Returns:
        tuple[list[dict[str, Any]], dict[str, Any], list[str]]: A tuple containing:
            - list of events
            - updated last_run dictionary with incremented offset
            - list of finding IDs that lack date fields (for error handling by caller)
    """
    if "offset" in last_run:
        offset = last_run["offset"]
        first_fetch_date = last_run["first_fetch"]
    else:
        # Initial fetch - start from current date or lookback
        offset = 0
        current_time = datetime.now()
        if lookback_days:
            lookback_time = current_time - timedelta(days=lookback_days)
            first_fetch_date = to_bitsight_date(int(lookback_time.timestamp()))
        else:
            first_fetch_date = to_bitsight_date(int(current_time.timestamp()))

    # Always use same starting date, current date as end
    first_seen_gte = first_fetch_date
    last_seen_lte = to_bitsight_date(int(datetime.now().timestamp()))

    res = client.get_company_findings(
        guid, first_seen_gte=first_seen_gte, last_seen_lte=last_seen_lte, limit=max_fetch, offset=offset
    )
    findings = res.get("results", [])

    events, missing_date_findings = findings_to_events(findings)

    # Update last_run with incremented offset (matches Performance Management pattern)
    # Note: Although the API returns pagination links (next/previous) in rare cases of very large amounts of data,
    # we ignore them since our offset-based approach will automatically fetch remaining data in subsequent calls
    # See: https://help.bitsighttech.com/hc/en-us/articles/360050111794-Pagination
    new_offset = offset + len(events)
    new_last_run: dict[str, Any] = {
        "first_fetch": first_fetch_date,
        "offset": new_offset,
    }

    return events, new_last_run, missing_date_findings


def bitsight_get_events_command(client: Client, guid: str, limit: int, should_push: bool) -> CommandResults:
    """Command implementation for `bitsight-get-events`.

    Executes a one-off retrieval of findings for the last 2 days (48 hours) and optionally
    pushes them to XSIAM when `should_push_events=true`.

    Args:
        client (Client): Initialized API client.
        guid (str): Resolved company GUID to collect findings for.
        limit (int): Max events to fetch in this invocation.
        should_push (bool): When true, pushes events to XSIAM; otherwise returns them as output only.

    Returns:
        CommandResults: CommandResults object with table output (when not pushing) or a summary message.
    """
    events, _, missing_date_findings = fetch_events(
        client, guid=guid, max_fetch=int(limit), last_run={}, lookback_days=GET_EVENTS_LOOKBACK_DAYS
    )

    title = "Bitsight Findings Events (pushed)" if should_push else "Bitsight Findings Events"
    if should_push:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        if missing_date_findings:
            raise ValueError(f"No first_seen date found for findings: {', '.join(missing_date_findings)}")
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
    client.get_companies_guid()
    if guid:
        # Use a simple 2-day lookback for testing connectivity
        current_time = datetime.now()
        lookback_time = current_time - timedelta(days=GET_EVENTS_LOOKBACK_DAYS)
        start_date = to_bitsight_date(int(lookback_time.timestamp()))
        end_date = to_bitsight_date(int(current_time.timestamp()))
        client.get_company_findings(guid, start_date, end_date, limit=1, offset=0)
    return "ok"


""" HELPER FUNCTIONS """


def handle_api_error(e: DemistoException, context: str = "API operation") -> str:
    """Centralized error handling for DemistoException with user-friendly messages.

    Args:
        e: The DemistoException to handle
        context: Context description for the error message

    Returns:
        User-friendly error message string
    """
    error_str = str(e)
    message = None

    if "401" in error_str or "Unauthorized" in error_str:
        message = "Authentication failed. Please verify your API key is correct and has proper permissions."

    elif "403" in error_str or "Forbidden" in error_str:
        message = "Access denied. Your API key does not have sufficient permissions to access BitSight data."

    elif "404" in error_str or "Not Found" in error_str:
        message = "Resource not found. Please verify the Company GUID is correct."

    # Return formatted error message
    if message:
        return f"{context} failed: {message} Original error: {error_str}"
    else:
        return f"{context} failed: {error_str}"


def resolve_guid(client: Client, guid_from_args: str | None, guid_from_params: str | None) -> str:
    """Resolve the company GUID, preferring command arg, then integration param, then myCompany.

    Raises ValueError if no GUID could be determined.
    """
    guid = guid_from_args or guid_from_params
    if guid:
        return guid

    companies = client.get_companies_guid()

    guid = (companies.get("my_company") or {}).get("guid")
    if not guid:
        raise ValueError("Company GUID is required. Provide it as an argument or in the integration parameters.")
    return guid


def main():
    # Extract command and parameters
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # Extract configuration variables
    base_url = params.get("base_url") or "https://api.bitsighttech.com"
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    api_key = params.get("credentials", {}).get("identifier", "")

    # Extract command-specific variables
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    should_push = argToBoolean(args.get("should_push_events", "false")) if args.get("should_push_events") else False
    limit = arg_to_number(args.get("limit")) or 5
    last_run = demisto.getLastRun() or {}

    demisto.debug(f"Command being called is {command}")

    # Create API client
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
        guid = resolve_guid(client, args.get("guid"), params.get("guid"))

        if command == "test-module":
            return_results(test_module(client, params.get("guid")))

        elif command == "fetch-events":
            events, new_last_run, missing_date_findings = fetch_events(client, guid=guid, max_fetch=max_fetch, last_run=last_run)
            demisto.setLastRun(new_last_run)

            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"Fetched and pushed {len(events)} events")
            if missing_date_findings:
                raise ValueError(f"No first_seen date found for findings: {', '.join(missing_date_findings)}")
            return

        elif command == "bitsight-get-events":
            return_results(bitsight_get_events_command(client, guid, limit, should_push))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except DemistoException as e:
        demisto.error(traceback.format_exc())
        return_error(handle_api_error(e, f"{command} command"))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command. Error: {e}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
