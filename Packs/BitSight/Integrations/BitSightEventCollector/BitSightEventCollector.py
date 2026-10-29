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
# Deterministic sort so newly-created findings always append at the tail of the
# result set. Without this the API returns findings in an unspecified (severity-based)
# order, which makes offset-based pagination skip new findings that sort before the
# current offset cursor.
FINDINGS_SORT = "first_seen"

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
        last_seen_lte: str | None,
        limit: int,
        offset: int,
        first_seen_lte: str | None = None,
    ) -> dict[str, Any]:
        """Get company findings for given guid and time range, sorted by first_seen.

        Args:
            guid (str): guid of the company whose findings need to be retrieved
            first_seen_gte (str): only findings first seen on or after this date (YYYY-MM-DD)
            last_seen_lte (str | None): only findings last seen on or before this date (YYYY-MM-DD)
            limit (int): maximum number of findings to return
            offset (int): offset to begin returning findings from
            first_seen_lte (str | None): only findings first seen on or before this date (YYYY-MM-DD)

        Returns:
            dict[str, Any]: findings response
        """
        params: dict[str, Any] = {
            "first_seen_gte": first_seen_gte,
            "unsampled": "true",
            "expand": "attributed_companies",
            "limit": limit,
            "offset": offset,
            # Ascending by first_seen so new findings always append at the tail; required for
            # offset pagination to be correct.
            "sort": FINDINGS_SORT,
        }
        if last_seen_lte:
            params["last_seen_lte"] = last_seen_lte
        if first_seen_lte:
            params["first_seen_lte"] = first_seen_lte
        demisto.debug(
            f"BitSight: requesting findings guid={guid} first_seen_gte={first_seen_gte} first_seen_lte={first_seen_lte} "
            f"last_seen_lte={last_seen_lte} sort={FINDINGS_SORT} limit={limit} offset={offset}"
        )
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

    The findings are requested sorted by first_seen (ascending), so new findings append at the tail of
    the result set and the offset does not skip or repeat them. No key-based de-duplication is done,
    because different findings can share the same rolledup_observation_id and first_seen.

    State saved by versions that did not sort the findings (recognised by the missing `api_count` key)
    has an offset that counts findings in a different order. For that state the offset is reset to 0
    once, so every finding since `first_fetch` is fetched again in the sorted order (some may be sent twice).

    Args:
        client (Client): Initialized API client.
        guid (str): Company GUID to collect findings for.
        max_fetch (int): Maximum number of findings to request for this page.
        last_run (dict[str, Any]): State from the previous run (keys `first_fetch`, `offset`, `api_count`).
        lookback_days (int | None): Days to look back for initial fetch. If None, uses current date.

    Returns:
        tuple[list[dict[str, Any]], dict[str, Any], list[str]]: A tuple containing:
            - list of events
            - updated last_run dictionary (first_fetch, offset, api_count)
            - list of finding IDs that lack date fields (for error handling by caller)
    """
    if "offset" in last_run:
        offset = last_run["offset"]
        first_fetch_date = last_run["first_fetch"]
        if "api_count" not in last_run:
            demisto.info(
                f"BitSight: state from a version without sorted findings (offset={offset}). "
                f"Resetting offset to 0 to fetch all findings since {first_fetch_date} in sorted order."
            )
            offset = 0
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
    findings = res.get("results", []) or []
    api_count = res.get("count")

    events, missing_date_findings = findings_to_events(findings)
    if missing_date_findings:
        demisto.debug(f"BitSight: findings missing first_seen date (no _time set): {missing_date_findings}")

    # Advance offset by the number of findings returned by the API.
    # See: https://help.bitsighttech.com/hc/en-us/articles/360050111794-Pagination
    new_offset = offset + len(findings)

    new_last_run: dict[str, Any] = {
        "first_fetch": first_fetch_date,
        "offset": new_offset,
        # Total findings in the window as reported by the API. After a fetch that drained the window,
        # offset == api_count. Its presence also marks the state as using the sorted order.
        "api_count": api_count,
    }
    if isinstance(api_count, int) and new_offset > api_count:
        demisto.info(
            f"BitSight: offset {new_offset} is larger than the total findings reported by the API ({api_count}). "
            "Findings may have been removed from the window, so newer findings could be skipped."
        )

    demisto.debug(
        f"BitSight: fetch_events first_fetch={first_fetch_date} offset={offset} returned={len(findings)} "
        f"new_offset={new_offset} api_count={api_count}"
    )
    return events, new_last_run, missing_date_findings


def resolve_first_seen_window(start_date: str | None, end_date: str | None) -> tuple[str, str]:
    """Turn the start_date/end_date command arguments into a first_seen window (YYYY-MM-DD, UTC).

    end_date defaults to now; start_date defaults to GET_EVENTS_LOOKBACK_DAYS before end_date.

    Raises:
        ValueError: If start_date is after end_date.
    """
    end_dt = arg_to_datetime(end_date, arg_name="end_date") if end_date else datetime.now(UTC)
    start_dt = arg_to_datetime(start_date, arg_name="start_date") if start_date else None
    if not start_dt:
        start_dt = end_dt - timedelta(days=GET_EVENTS_LOOKBACK_DAYS)  # type: ignore[operator]
    first_seen_gte = start_dt.strftime(BITSIGHT_DATE_FORMAT)
    first_seen_lte = end_dt.strftime(BITSIGHT_DATE_FORMAT)  # type: ignore[union-attr]
    if first_seen_gte > first_seen_lte:
        raise ValueError(f"start_date ({first_seen_gte}) must not be after end_date ({first_seen_lte}).")
    return first_seen_gte, first_seen_lte


def bitsight_get_events_command(
    client: Client,
    guid: str,
    limit: int,
    should_push: bool,
    start_date: str | None = None,
    end_date: str | None = None,
) -> CommandResults:
    """Command implementation for `bitsight-get-events`.

    Executes a one-off retrieval of findings and optionally pushes them to XSIAM when
    `should_push_events=true`. By default it looks back 2 days (48 hours). When `start_date`
    and/or `end_date` are provided, it returns the findings first seen in that window instead,
    which allows retrieving findings from the past.

    Args:
        client (Client): Initialized API client.
        guid (str): Resolved company GUID to collect findings for.
        limit (int): Max events to fetch in this invocation.
        should_push (bool): When true, pushes events to XSIAM; otherwise returns them as output only.
        start_date (str | None): Start of the first_seen window. Accepts free text ("2 days ago") or a
            date ("2026-08-31"). Defaults to 2 days before end_date.
        end_date (str | None): End of the first_seen window. Accepts the same formats. Defaults to now.

    Returns:
        CommandResults: CommandResults object with table output (when not pushing) or a summary message.
    """
    if start_date or end_date:
        first_seen_gte, first_seen_lte = resolve_first_seen_window(start_date, end_date)
        demisto.debug(
            f"BitSight: bitsight-get-events explicit window guid={guid} "
            f"first_seen_gte={first_seen_gte} first_seen_lte={first_seen_lte} limit={limit}"
        )
        res = client.get_company_findings(
            guid,
            first_seen_gte=first_seen_gte,
            last_seen_lte=None,
            limit=int(limit),
            offset=0,
            first_seen_lte=first_seen_lte,
        )
        events, missing_date_findings = findings_to_events(res.get("results", []) or [])
    else:
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
    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH)) or DEFAULT_MAX_FETCH
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

            # Push first, then save state: if the push fails, the same page is fetched again next run.
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(new_last_run)
            demisto.info(
                f"BitSight: pushed {len(events)} events. New last run: first_fetch={new_last_run.get('first_fetch')} "
                f"offset={new_last_run.get('offset')} api_count={new_last_run.get('api_count')}"
            )
            if missing_date_findings:
                raise ValueError(f"No first_seen date found for findings: {', '.join(missing_date_findings)}")
            return

        elif command == "bitsight-get-events":
            return_results(
                bitsight_get_events_command(
                    client,
                    guid,
                    limit,
                    should_push,
                    start_date=args.get("start_date"),
                    end_date=args.get("end_date"),
                )
            )

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
