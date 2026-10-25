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
# current offset cursor. See XSUP-77274.
FINDINGS_SORT = "first_seen"
# Cap the dedup memory kept in last_run so the state object cannot grow unbounded.
MAX_DEDUP_KEYS = 20000
# TEMPORARY DEBUG (XSUP-77274): on every fetch, also issue the same request WITHOUT the sort
# and log a comparison, to prove the sort changes what the offset window returns.
# The unsorted response is never sent to XSIAM and never affects last_run. Remove before merge.
DEBUG_COMPARE_UNSORTED = True
# Max keys printed per list in the comparison log lines.
DEBUG_COMPARE_MAX_KEYS = 200

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
        sort: str | None = FINDINGS_SORT,
    ) -> dict[str, Any]:
        """Get company findings for given guid and time range.

        Args:
            guid (str): guid of the company whose findings need to be retrieved
            first_seen_gte (str): first seen date (YYYY-MM-DD) of the findings
            last_seen_lte (str): last seen date (YYYY-MM-DD) of the findings
            limit (int): maximum number of findings to return
            offset (int): offset to begin returning findings from
            sort (str | None): sort field. Defaults to FINDINGS_SORT. None omits the sort param
                (API default order) and is used only by the temporary debug comparison.

        Returns:
            dict[str, Any]: findings response
        """
        params: dict[str, Any] = {
            "first_seen_gte": first_seen_gte,
            "last_seen_lte": last_seen_lte,
            "unsampled": "true",
            "expand": "attributed_companies",
            "limit": limit,
            "offset": offset,
        }
        if sort:
            # Force a deterministic ascending order by first_seen so new findings always
            # append at the tail. This is required for offset pagination to be correct
            # (see XSUP-77274). Without it, the API's default ordering is unstable and
            # new findings can be silently skipped by the advancing offset cursor.
            params["sort"] = sort
        demisto.debug(
            f"BitSight: requesting findings guid={guid} first_seen_gte={first_seen_gte} "
            f"last_seen_lte={last_seen_lte} sort={sort} limit={limit} offset={offset}"
        )
        return self._http_request(method="GET", url_suffix=f"v1/companies/{encode_string_results(guid)}/findings", params=params)


def finding_key(finding: dict[str, Any]) -> str:
    """Build the identity key of a finding: rolledup_observation_id + "-#-" + first_seen."""
    return f"{finding.get('rolledup_observation_id', '')}-#-{finding.get('first_seen', '')}"


def count_first_seen_descents(findings: list[dict[str, Any]]) -> int:
    """Count adjacent pairs where first_seen goes DOWN (0 means ascending by first_seen)."""
    dates = [str(f.get("first_seen") or "") for f in findings]
    return sum(1 for prev, cur in zip(dates, dates[1:]) if cur < prev)


def debug_compare_unsorted(
    client: "Client",
    guid: str,
    first_seen_gte: str,
    last_seen_lte: str,
    limit: int,
    offset: int,
    sorted_res: dict[str, Any],
) -> None:
    """TEMPORARY DEBUG (XSUP-77274): repeat the request without the sort and log the differences.

    Logged with demisto.info (prefix "BitSight sort-compare:") so it is visible without debug mode.
    Never raises; the unsorted response is discarded.
    """
    try:
        unsorted_res = client.get_company_findings(
            guid, first_seen_gte=first_seen_gte, last_seen_lte=last_seen_lte, limit=limit, offset=offset, sort=None
        )
        sorted_findings = sorted_res.get("results", []) or []
        unsorted_findings = unsorted_res.get("results", []) or []
        sorted_keys = [finding_key(f) for f in sorted_findings]
        unsorted_keys = [finding_key(f) for f in unsorted_findings]
        sorted_set, unsorted_set = set(sorted_keys), set(unsorted_keys)
        only_unsorted = [k for k in unsorted_keys if k not in sorted_set]
        only_sorted = [k for k in sorted_keys if k not in unsorted_set]
        moved = sum(1 for a, b in zip(sorted_keys, unsorted_keys) if a != b)
        cap = DEBUG_COMPARE_MAX_KEYS

        demisto.info(
            f"BitSight sort-compare: window first_seen_gte={first_seen_gte} last_seen_lte={last_seen_lte} "
            f"offset={offset} limit={limit} | sorted(sort={FINDINGS_SORT}): count={sorted_res.get('count')} "
            f"returned={len(sorted_keys)} first_seen_descents={count_first_seen_descents(sorted_findings)} | "
            f"unsorted: count={unsorted_res.get('count')} returned={len(unsorted_keys)} "
            f"first_seen_descents={count_first_seen_descents(unsorted_findings)} | "
            f"same_order={sorted_keys == unsorted_keys} same_set={sorted_set == unsorted_set} "
            f"positions_differ={moved} only_in_unsorted={len(only_unsorted)} only_in_sorted={len(only_sorted)}"
        )
        demisto.info(f"BitSight sort-compare: only_in_sorted (new code fetches, old code would not): {only_sorted[:cap]}")
        demisto.info(f"BitSight sort-compare: only_in_unsorted (old code fetches, new code does not): {only_unsorted[:cap]}")
        demisto.info(f"BitSight sort-compare: sorted order: {sorted_keys[:cap]}")
        demisto.info(f"BitSight sort-compare: unsorted order: {unsorted_keys[:cap]}")
    except Exception as e:  # never let the debug comparison affect the real fetch
        demisto.info(f"BitSight sort-compare: comparison failed and was skipped: {e}")


# TEMPORARY DEBUG (XSUP-77274): offset-paging simulation, with vs without the sort.
DEBUG_SORT_SIM = True
# TEMPORARY (XSUP-78867): one-time automatic fetch reset, no instance configuration needed.
# On the first scheduled fetch after upload, last_run is reset to first_fetch=this date, offset=0, dedup
# cleared. The value is stored as applied_fetch_start, so later runs move forward normally. To reset again
# in a later upload, change this value. Set to "" to disable.
FORCED_FETCH_START = "30 days ago"
DEBUG_SORT_SIM_PAGE_SIZE = 1000
DEBUG_SORT_SIM_MAX_PAGES = 20  # up to 20,000 findings per order
DEBUG_SORT_SIM_MAX_STORED_KEYS = 25000  # per order, kept in integration context
DEBUG_SORT_SIM_MAX_LISTED_KEYS = 20


def debug_fetch_all_keys(
    client: "Client", guid: str, first_seen_gte: str, last_seen_lte: str, sort: str | None
) -> tuple[list[str], Any, int, bool]:
    """Fetch the full window (all pages from offset 0) in one order.

    Returns: (finding keys in API order, API count, number of first_seen descents, truncated flag).
    """
    keys: list[str] = []
    api_count: Any = None
    descents = 0
    previous_first_seen: str | None = None
    for page in range(DEBUG_SORT_SIM_MAX_PAGES):
        res = client.get_company_findings(
            guid,
            first_seen_gte=first_seen_gte,
            last_seen_lte=last_seen_lte,
            limit=DEBUG_SORT_SIM_PAGE_SIZE,
            offset=page * DEBUG_SORT_SIM_PAGE_SIZE,
            sort=sort,
        )
        results = res.get("results") or []
        api_count = res.get("count", api_count)
        for finding in results:
            first_seen = str(finding.get("first_seen") or "")
            if previous_first_seen is not None and first_seen < previous_first_seen:
                descents += 1
            previous_first_seen = first_seen
            keys.append(finding_key(finding))
        if len(results) < DEBUG_SORT_SIM_PAGE_SIZE:
            return keys, api_count, descents, False
    return keys, api_count, descents, True


def debug_simulate_offset_paging(previous_keys: list[str], current_keys: list[str]) -> dict[str, list[str]]:
    """Simulate a collector that had consumed everything up to the previous snapshot (offset = len(previous)).

    Its next page is current_keys[len(previous_keys):]. A NEW finding (not in previous) that is not in that
    page is SKIPPED forever. An OLD finding that is in that page is a DUPLICATE.
    """
    previous_set = set(previous_keys)
    current_set = set(current_keys)
    next_page = current_keys[len(previous_keys) :]
    next_page_set = set(next_page)
    new_keys = [k for k in current_keys if k not in previous_set]
    return {
        "new": new_keys,
        "skipped": [k for k in new_keys if k not in next_page_set],
        "duplicated": [k for k in next_page if k in previous_set],
        "removed": [k for k in previous_keys if k not in current_set],
    }


def debug_sort_simulation(client: "Client", guid: str, first_seen_gte: str, last_seen_lte: str) -> dict[str, Any]:
    """TEMPORARY DEBUG (XSUP-77274): prove whether the sort prevents offset-paging skips.

    Every run: fetch the full window both WITH the sort and WITHOUT it, compare each order to the previous
    run's snapshot (kept in integration context) and count the new findings that offset paging would skip
    in each order. Running totals are accumulated. Results are logged (demisto.info, prefix
    "BitSight sort-sim:") and returned as a compact dict that the caller stores in last_run, so they also
    appear in the server-side lastRun log lines. Never raises and never affects what is ingested.
    """
    try:
        context = get_integration_context() or {}
        state = context.get("sort_sim") or {}
        sorted_keys, sorted_count, sorted_descents, sorted_truncated = debug_fetch_all_keys(
            client, guid, first_seen_gte, last_seen_lte, FINDINGS_SORT
        )
        unsorted_keys, unsorted_count, unsorted_descents, unsorted_truncated = debug_fetch_all_keys(
            client, guid, first_seen_gte, last_seen_lte, None
        )
        summary: dict[str, Any] = {
            "run_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window": f"{first_seen_gte}..{last_seen_lte}",
            "count_sorted": sorted_count,
            "count_unsorted": unsorted_count,
            "fetched_sorted": len(sorted_keys),
            "fetched_unsorted": len(unsorted_keys),
            "first_seen_descents_sorted": sorted_descents,
            "first_seen_descents_unsorted": unsorted_descents,
            "same_order": sorted_keys == unsorted_keys,
            "same_set": set(sorted_keys) == set(unsorted_keys),
            "truncated": sorted_truncated or unsorted_truncated,
        }
        totals: dict[str, int] = state.get("totals") or {}
        same_window = state.get("window_start") == first_seen_gte
        if not same_window:
            totals = {}
        if same_window and state.get("sorted") is not None and state.get("unsorted") is not None:
            with_sort = debug_simulate_offset_paging(state["sorted"], sorted_keys)
            without_sort = debug_simulate_offset_paging(state["unsorted"], unsorted_keys)
            cap = DEBUG_SORT_SIM_MAX_LISTED_KEYS
            summary.update(
                {
                    "baseline": False,
                    "new_findings": len(with_sort["new"]),
                    "removed_findings": len(with_sort["removed"]),
                    "skipped_with_sort": len(with_sort["skipped"]),
                    "skipped_without_sort": len(without_sort["skipped"]),
                    "duplicated_with_sort": len(with_sort["duplicated"]),
                    "duplicated_without_sort": len(without_sort["duplicated"]),
                    "skipped_keys_with_sort": with_sort["skipped"][:cap],
                    "skipped_keys_without_sort": without_sort["skipped"][:cap],
                }
            )
            for name in (
                "new_findings",
                "removed_findings",
                "skipped_with_sort",
                "skipped_without_sort",
                "duplicated_with_sort",
                "duplicated_without_sort",
            ):
                totals[name] = totals.get(name, 0) + summary[name]
            totals["compared_runs"] = totals.get("compared_runs", 0) + 1
        else:
            summary["baseline"] = True  # first snapshot for this window, nothing to compare yet
        summary["totals"] = totals

        max_keys = DEBUG_SORT_SIM_MAX_STORED_KEYS
        context["sort_sim"] = {
            "window_start": first_seen_gte,
            "sorted": sorted_keys[:max_keys],
            "unsorted": unsorted_keys[:max_keys],
            "totals": totals,
        }
        set_integration_context(context)
        demisto.info(f"BitSight sort-sim: {json.dumps(summary)}")
        return summary
    except Exception as e:  # never let the debug simulation affect the real fetch
        demisto.info(f"BitSight sort-sim: simulation failed and was skipped: {e}")
        return {"error": str(e)}


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


def apply_fetch_start_reset(last_run: dict[str, Any], fetch_start_param: str | None) -> dict[str, Any]:
    """Apply a one-time reset of the fetch state from the `fetch_start_date` instance parameter.

    The reset is applied only when the parameter value differs from the value that was last applied
    (stored in last_run as `applied_fetch_start`). Following runs see the same value, skip the reset
    and keep moving forward from the stored offset. To reset again, change the parameter value.
    Clearing the parameter never resets anything.

    On reset: first_fetch = the parsed date, offset = 0 and the dedup memory is cleared, so every
    finding from that date onward is fetched again.

    Args:
        last_run (dict[str, Any]): The stored last run.
        fetch_start_param (str | None): Raw parameter value, e.g. "2026-09-25" or "30 days ago".

    Returns:
        dict[str, Any]: The last run to use for this fetch (a new dict when a reset is applied).
    """
    fetch_start_param = (fetch_start_param or "").strip()
    if not fetch_start_param or fetch_start_param == last_run.get("applied_fetch_start"):
        return last_run

    start_dt = arg_to_datetime(fetch_start_param, arg_name="fetch_start_date", required=True)
    first_fetch_date = start_dt.strftime(BITSIGHT_DATE_FORMAT)  # type: ignore[union-attr]
    demisto.info(
        f"BitSight: applying fetch reset fetch_start_date='{fetch_start_param}' -> first_fetch={first_fetch_date}, "
        f"offset=0, dedup cleared. Previous state: first_fetch={last_run.get('first_fetch')} "
        f"offset={last_run.get('offset')} applied_fetch_start={last_run.get('applied_fetch_start')}"
    )
    return {
        "first_fetch": first_fetch_date,
        "offset": 0,
        "already_fetched_findings": [],
        "applied_fetch_start": fetch_start_param,
    }


def fetch_events(
    client: Client,
    guid: str,
    max_fetch: int,
    last_run: dict[str, Any],
    lookback_days: int | None = None,
    debug_compare_unsorted_request: bool = False,
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
        debug_compare_unsorted_request (bool): TEMPORARY DEBUG (XSUP-77274). When True, also send the
            same request without the sort and log the comparison. Has no effect on the results.

    Returns:
        tuple[list[dict[str, Any]], dict[str, Any], list[str]]: A tuple containing:
            - list of events (already de-duplicated against previously sent findings)
            - updated last_run dictionary with incremented offset and dedup keys
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

    # Previously-sent finding keys (rolledup_observation_id + "-#-" + first_seen).
    # Used as a safety net so that even if the API ordering shifts, we never re-send
    # (or, combined with the deterministic sort, never skip) a finding. See XSUP-77274.
    already_fetched_findings: list[str] = last_run.get("already_fetched_findings") or []
    already_fetched_set = set(already_fetched_findings)

    # Always use same starting date, current date as end
    first_seen_gte = first_fetch_date
    last_seen_lte = to_bitsight_date(int(datetime.now().timestamp()))

    demisto.debug(
        f"BitSight: fetch_events start first_fetch={first_fetch_date} offset={offset} "
        f"max_fetch={max_fetch} known_dedup_keys={len(already_fetched_set)}"
    )

    res = client.get_company_findings(
        guid, first_seen_gte=first_seen_gte, last_seen_lte=last_seen_lte, limit=max_fetch, offset=offset
    )
    findings = res.get("results", [])

    if debug_compare_unsorted_request and DEBUG_COMPARE_UNSORTED:
        debug_compare_unsorted(client, guid, first_seen_gte, last_seen_lte, max_fetch, offset, res)

    # Log the API-level pagination metadata so we can tell, on failure, whether the current
    # window still has more pages than this single fetch pulled (i.e. offset hasn't reached
    # a given finding's page yet). See XSUP-77274.
    api_count = res.get("count")
    api_links = res.get("links") or {}
    demisto.debug(
        f"BitSight: API response count={api_count} returned={len(findings)} "
        f"has_next={bool(api_links.get('next'))} offset={offset} limit={max_fetch}"
    )

    # Log the identities of every raw finding returned so we can confirm whether a specific
    # finding (e.g. a reported-missing rolledup_observation_id) was actually returned by the
    # API on this page, versus never returned at all.
    raw_finding_keys = [f"{f.get('rolledup_observation_id', '')}-#-{f.get('first_seen', '')}" for f in findings]
    demisto.debug(f"BitSight: raw finding keys returned this page: {raw_finding_keys}")

    all_events, missing_date_findings = findings_to_events(findings)
    if missing_date_findings:
        demisto.debug(f"BitSight: findings missing first_seen date (no _time set): {missing_date_findings}")

    # De-duplicate: only send findings we have not already sent, keyed by
    # rolledup_observation_id + first_seen (creation day). This mirrors the proven
    # pattern used by the BitSight Performance Management integration.
    events: list[dict[str, Any]] = []
    duplicate_keys: list[str] = []
    for event in all_events:
        key = f"{event.get('rolledup_observation_id', '')}-#-{event.get('first_seen', '')}"
        if key in already_fetched_set:
            duplicate_keys.append(key)
            continue
        events.append(event)
        already_fetched_set.add(key)
        already_fetched_findings.append(key)

    # Advance offset by the number of RAW findings returned by the API (not the number
    # of de-duplicated events) so pagination keeps moving forward through the result set.
    # See: https://help.bitsighttech.com/hc/en-us/articles/360050111794-Pagination
    new_offset = offset + len(all_events)

    # Bound the dedup memory so last_run cannot grow without limit.
    if len(already_fetched_findings) > MAX_DEDUP_KEYS:
        already_fetched_findings = already_fetched_findings[-MAX_DEDUP_KEYS:]

    new_last_run: dict[str, Any] = {
        "first_fetch": first_fetch_date,
        "offset": new_offset,
        "already_fetched_findings": already_fetched_findings,
    }
    # Keep the marker of the last applied reset so the same reset is not applied again.
    if last_run.get("applied_fetch_start"):
        new_last_run["applied_fetch_start"] = last_run["applied_fetch_start"]

    demisto.debug(
        f"BitSight: fetch_events done raw_findings={len(all_events)} new_events={len(events)} "
        f"skipped_duplicates={len(duplicate_keys)} new_offset={new_offset} "
        f"total_dedup_keys={len(already_fetched_findings)}"
    )
    if duplicate_keys:
        demisto.debug(f"BitSight: skipped duplicate finding keys: {duplicate_keys}")

    return events, new_last_run, missing_date_findings


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
    and/or `end_date` are provided, it queries that explicit window instead - this allows
    retrieving findings created in the past (e.g. to validate that a historical finding is
    now returned by the API after the deterministic-sort change). See XSUP-77274.

    Args:
        client (Client): Initialized API client.
        guid (str): Resolved company GUID to collect findings for.
        limit (int): Max events to fetch in this invocation.
        should_push (bool): When true, pushes events to XSIAM; otherwise returns them as output only.
        start_date (str | None): Optional window start. Accepts free text ("2 days ago", "1 week",
            "2026-08-31") or an ISO timestamp. Defaults to 2 days ago when a window is requested.
        end_date (str | None): Optional window end. Accepts the same free-text/ISO formats.
            Defaults to now.

    Returns:
        CommandResults: CommandResults object with table output (when not pushing) or a summary message.
    """
    if start_date or end_date:
        # Explicit window: query the given date range directly (bypasses the watermark/lookback
        # logic used by scheduled fetches) so an arbitrary historical window can be inspected.
        # arg_to_datetime parses human-friendly input such as "2 days ago" or "2026-08-31".
        start_dt = arg_to_datetime(start_date, arg_name="start_date") if start_date else None
        end_dt = arg_to_datetime(end_date, arg_name="end_date") if end_date else None

        now = datetime.now()
        first_seen_gte = (start_dt or (now - timedelta(days=GET_EVENTS_LOOKBACK_DAYS))).strftime(BITSIGHT_DATE_FORMAT)
        last_seen_lte = (end_dt or now).strftime(BITSIGHT_DATE_FORMAT)
        demisto.debug(
            f"BitSight: bitsight-get-events explicit window guid={guid} "
            f"first_seen_gte={first_seen_gte} last_seen_lte={last_seen_lte} limit={limit}"
        )
        res = client.get_company_findings(
            guid, first_seen_gte=first_seen_gte, last_seen_lte=last_seen_lte, limit=int(limit), offset=0
        )
        events, missing_date_findings = findings_to_events(res.get("results", []))
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
            last_run = apply_fetch_start_reset(last_run, FORCED_FETCH_START)
            events, new_last_run, missing_date_findings = fetch_events(
                client, guid=guid, max_fetch=max_fetch, last_run=last_run, debug_compare_unsorted_request=True
            )

            # Push first, then save state: if the push fails, the same page is fetched again next run.
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            if DEBUG_SORT_SIM:
                # TEMPORARY DEBUG (XSUP-77274). Stored in last_run so it also shows in the server lastRun logs.
                # Key starts with "_" so it sorts first in the server's "New last run" log line (Go sorts JSON
                # map keys alphabetically); a truncated line still shows it before the long dedup list.
                sim_summary = debug_sort_simulation(
                    client, guid, new_last_run["first_fetch"], to_bitsight_date(int(datetime.now().timestamp()))
                )
                new_last_run = {"_debug_sort_sim": sim_summary, **new_last_run}
            demisto.setLastRun(new_last_run)
            demisto.info(
                f"BitSight: pushed {len(events)} events. New last run: first_fetch={new_last_run.get('first_fetch')} "
                f"offset={new_last_run.get('offset')} dedup_keys={len(new_last_run.get('already_fetched_findings', []))} "
                f"applied_fetch_start={new_last_run.get('applied_fetch_start')}"
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
