import json
from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING

import demistomock as demisto  # noqa: F401
from AWSApiModule import *  # noqa: E402
from CommonServerPython import *  # noqa: F401

# The following import are used only for type hints and autocomplete.
# It is not used at runtime, and not exist in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_guardduty import GuardDutyClient


CLIENT_SERVICE = "guardduty"
MAX_IDS_PER_REQ = 50
MAX_RESULTS = 50
GD_SEVERITY_DICT = {"Low": 1, "Medium": 4, "High": 7}

# XSUP-71079: a fully-deduped cursor boundary second is only escaped once it is
# at least this far in the past relative to the fetch start time. This keeps a
# still-current second pinned (so a genuine later same-second update is still
# catchable) while breaking a boundary that has clearly gone stale.
STALE_BOUNDARY_MARGIN = timedelta(minutes=2)

PRODUCT = "guardduty"
VENDOR = "aws"


class DatetimeEncoder(json.JSONEncoder):
    """Json encoder class for encoding datetime objects. Use with json.dumps method."""

    def default(self, obj):  # pylint: disable=W9014
        if isinstance(obj, datetime | date):
            return obj.strftime("%Y-%m-%dT%H:%M:%S.%f")
        return json.JSONEncoder.default(self, obj)


def convert_events_with_datetime_to_str(events: list) -> list:
    """Convert datetime fields in events to string.

    Args:
        events (list): Events received from AWS python SDK with datetime in certain fields.

    Returns:
        events (list): Events with dates as strings only.
    """
    output_events = []
    for event in events:
        # Encode the datetime fields of the event to str using json dumps.
        output = json.dumps(event, cls=DatetimeEncoder)
        # Load the event with datetime fields converted to str.
        output_events.append(json.loads(output))
    return output_events


def _normalize_last_ids_entry(value) -> set[str]:
    """Coerce a stored ``last_ids`` value into a set of ids.

    The integration historically stored ``last_ids[detector_id]`` as a single
    string (the last finding id seen). To fix XSUP-67097 we now track every
    finding id sharing the cursor's ``UpdatedAt`` second, which means the
    value is conceptually a set. ``demisto.setLastRun`` serializes as JSON,
    so the on-disk representation must be a ``list``. This helper normalizes
    all three legacy / current shapes into a ``set[str]``:

        * ``str`` → ``{value}``                  (legacy state from <1.3.67)
        * ``list`` / ``tuple`` → ``set(value)``  (rehydrated from setLastRun)
        * ``set`` → ``set(value)``               (in-memory)
        * ``None`` / ``""`` / falsy → ``set()``

    Anything else logs a warning and falls back to an empty set so a single
    bad cache entry never blocks a fetch cycle.
    """
    if not value:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, list | tuple | set):
        return {item for item in value if isinstance(item, str)}
    demisto.debug(f"AWSGuardDutyEventCollector - Unexpected last_ids value type {type(value).__name__}; treating as empty.")
    return set()


def _build_finding_criterion(updated_at: Optional[datetime], severity: str, exclude_archived: bool) -> dict:
    """Build the ``FindingCriteria.Criterion`` dict for ``list_findings``.

    Args:
        updated_at: Inclusive lower bound on ``updatedAt``.
        severity: Minimum severity label (Low/Medium/High).
        exclude_archived: When ``True``, adds ``service.archived = false`` so suppressed/archived
            findings (XSUP-67097 / XSUP-71079 complaint #2) are not re-fetched.

    Returns:
        The criterion dict.
    """
    criterion: dict = {
        "updatedAt": {"Gte": date_to_timestamp(updated_at)},
        "severity": {"Gte": GD_SEVERITY_DICT.get(severity, 1)},
    }
    if exclude_archived:
        # GuardDuty represents the archived flag as the string "false"/"true" in FindingCriteria.
        criterion["service.archived"] = {"Eq": ["false"]}
    return criterion


def _event_updated_at(event: dict) -> Any:
    """Return the timestamp used as the fetch cursor for a single finding."""
    return event.get("UpdatedAt", event.get("CreatedAt"))


def _cursor_second(value: Any) -> datetime:
    """Return the whole-second (microseconds truncated) datetime for a timestamp.

    XSUP-73410: GuardDuty findings carry MILLISECOND-precision ``UpdatedAt``
    values, and several findings routinely share the same whole second while
    differing in their milliseconds. The fetch cursor and the same-second
    sibling dedup (XSUP-67097 / 71079 / 72455) are defined at SECOND resolution,
    so all comparisons and grouping must truncate sub-second precision. Doing so
    keeps the cursor deterministic (independent of AWS ``get_findings`` ordering)
    and lets every finding sharing the cursor second be recognized as an
    already-seen sibling on the inclusive ``Gte`` re-query.

    Args:
        value: A timestamp string or a ``datetime``. Every GuardDuty finding
            carries a real ``UpdatedAt``/``CreatedAt``, so a value is always present.

    Returns:
        The corresponding ``datetime`` truncated to whole seconds.

    Raises:
        ValueError: If ``value`` is not a parseable timestamp. This is not
            expected from real GuardDuty data and surfaces loudly rather than
            silently corrupting the fetch cursor.
    """
    if isinstance(value, datetime):
        return value.replace(microsecond=0)
    return parse_date_string(value).replace(microsecond=0)


def get_events(
    aws_client: "GuardDutyClient",
    collect_from: dict,
    collect_from_default: Optional[datetime],
    last_ids: dict,
    severity: str,
    limit: int = MAX_RESULTS,
    detectors_num: int = MAX_RESULTS,
    max_ids_per_req: int = MAX_IDS_PER_REQ,
    exclude_archived: bool = False,
) -> tuple[list, dict, dict]:
    """Get events from AWSGuardDuty.

    Args:
        aws_client: AWSClient session to get events from.
        collect_from: Dict of {detector_id: datestring to start collecting from}, used when fetching.
        collect_from_default: datetime to start collecting from if detector id is not found in collect_from keys.
        last_ids: Dict of {detector_id: <ids seen at the cursor second>}, used to avoid duplicates and to
            prevent same-second sibling loss. Each value may be a ``set``, ``list``, ``tuple``, or — for
            backwards compatibility with state written by integration versions <1.3.67 — a single ``str``.
            All shapes are normalized to ``set[str]`` internally.
        severity: The minimum severity to start fetching from. (inclusive)
        limit: The maximum number of events to fetch.
        detectors_num: The maximum number of detectors to fetch.
        max_ids_per_req: The maximum number of findings to get per API request.
        exclude_archived: When ``True``, archived/suppressed findings are excluded from the fetch.

    Returns:
        (events, new_last_ids, new_collect_from)
        events (list): The events fetched.
        new_last_ids (dict): The new last_ids dict, expected to receive as last_ids input in the next run.
            Each value is a ``list[str]`` (JSON-serializable for setLastRun).
        new_collect_from (dict): The new collect_from dict, expected to receive as collect_from input in the next run.

    Note (XSUP-71079): The fetch cursor is second-resolution and the ``updatedAt`` filter is inclusive
    (``Gte``). To avoid silently skipping findings, the cursor is NEVER advanced into a second that was
    only partially consumed because ``limit`` was reached. When a fetch is truncated mid-second the cursor
    is rolled back to the last fully-drained second (and its sibling ids are persisted) so the next run
    re-queries the truncated second from its start. This guarantees forward progress without data loss.
    """

    events: list = []
    detector_ids: list = []
    next_token = "starting_token"
    new_last_ids = last_ids.copy()
    new_collect_from = collect_from.copy()

    demisto.debug(f"AWSGuardDutyEventCollector Starting get_events. {collect_from=}, {collect_from_default=}, {last_ids=}")

    # List all detectors
    while next_token:
        list_detectors_args: dict = {"MaxResults": detectors_num}
        if next_token != "starting_token":
            list_detectors_args.update({"NextToken": next_token})

        response = aws_client.list_detectors(**list_detectors_args)
        detector_ids += response.get("DetectorIds", [])
        next_token = response.get("NextToken", "")

    demisto.debug(f"AWSGuardDutyEventCollector - Found detector ids: {detector_ids}")

    for detector_id in detector_ids:
        demisto.debug(
            f"AWSGuardDutyEventCollector - Getting finding ids for detector id {detector_id}. "
            f"Collecting from {collect_from.get(detector_id, collect_from_default)}"
        )
        next_token = "starting_token"
        finding_ids: list = []
        detector_events: list = []
        updated_at = parse_date_string(collect_from.get(detector_id)) if collect_from.get(detector_id) else collect_from_default
        # XSUP-67097: dedup against ALL ids seen at the cursor second, not just one.
        seen_ids = _normalize_last_ids_entry(last_ids.get(detector_id))
        # List all finding ids
        while next_token and len(events) + len(finding_ids) < limit:
            demisto.debug(f"AWSGuardDutyEventCollector - Getting more finding ids with {next_token=}, {updated_at=}")
            list_finding_args = {
                "DetectorId": detector_id,
                "FindingCriteria": {"Criterion": _build_finding_criterion(updated_at, severity, exclude_archived)},
                "SortCriteria": {"AttributeName": "updatedAt", "OrderBy": "ASC"},
                "MaxResults": min(limit - (len(events) + len(set(finding_ids))), MAX_RESULTS),
            }
            if next_token != "starting_token":
                list_finding_args.update({"NextToken": next_token})
            list_findings = aws_client.list_findings(**list_finding_args)
            finding_ids += list_findings.get("FindingIds", [])
            next_token = list_findings.get("NextToken", "")

        # Handle duplicates in response while preserving order
        finding_ids_unique = list(dict.fromkeys(finding_ids))
        demisto.debug(f"Detector id {detector_id} unique finding ids found: {finding_ids_unique}")
        # Get all relevant findings
        chunked_finding_ids = [
            finding_ids_unique[i : i + max_ids_per_req] for i in range(0, len(finding_ids_unique), max_ids_per_req)
        ]
        for chunk_of_finding_ids in chunked_finding_ids:
            demisto.debug(f"Getting {chunk_of_finding_ids=}")
            findings_response = aws_client.get_findings(DetectorId=detector_id, FindingIds=chunk_of_finding_ids)
            detector_events += findings_response.get("Findings", [])

        # Dedup already-seen findings — but only at the cursor second.
        #
        # XSUP-67097: drop every finding we already ingested that still shares the cursor's UpdatedAt
        # second (same-second siblings re-returned by the inclusive Gte query).
        #
        # XSUP-72455: do NOT drop a finding whose UpdatedAt has advanced past the cursor second. GuardDuty
        # findings are long-lived and update in place; when a recurring finding gets a new occurrence its
        # UpdatedAt moves forward and AWS returns it again. That is a legitimate new event and must be
        # ingested. The previous ID-only dedup dropped it because its id was in last_ids, which produced an
        # empty result and, because the cursor only advances when events are ingested, pinned the fetch
        # behind that finding indefinitely.
        # XSUP-73410: compare at whole-second resolution. GuardDuty UpdatedAt values carry
        # milliseconds and several findings share the same second at different ms, so an
        # exact-microsecond comparison treats same-second siblings as distinct and never dedups them.
        cursor_second = _cursor_second(updated_at)
        if seen_ids:
            before_ids = [ev.get("Id") for ev in detector_events]
            detector_events = [
                ev
                for ev in detector_events
                if ev.get("Id") not in seen_ids or _cursor_second(_event_updated_at(ev)) != cursor_second
            ]
            after_ids = [ev.get("Id") for ev in detector_events]
            if before_ids != after_ids:
                demisto.debug(
                    f"AWSGuardDutyEventCollector - Dedup removed already-seen same-second findings "
                    f"for {detector_id=}. Before: {before_ids}, after: {after_ids}, removed via {seen_ids=} "
                    f"at cursor second {cursor_second=}."
                )
            else:
                # XSUP-73410: dedup ran but nothing matched — log it so we can distinguish "dedup did not
                # execute" from "dedup executed and found no already-seen same-second findings to drop".
                demisto.debug(
                    f"AWSGuardDutyEventCollector - Dedup ran for {detector_id=} at cursor second "
                    f"{cursor_second=} but removed nothing ({len(before_ids)} findings kept, "
                    f"{len(seen_ids)} seen ids carried in)."
                )

        demisto.debug(f"AWSGuardDutyEventCollector - {detector_id=} findings found ({len(detector_events)}): {detector_events}")
        events += detector_events
        demisto.debug(f"AWSGuardDutyEventCollector - Number of events is {len(events)}")

        # XSUP-71079: advance the cursor safely.
        #
        # The cursor is second-resolution and the updatedAt query is inclusive (Gte). Two failure modes
        # are guarded here:
        #   1. Same-second siblings (XSUP-67097): persist EVERY finding id whose UpdatedAt equals the
        #      cursor second so the next run can dedup them all (not just one).
        #   2. Mid-second truncation (XSUP-71079): if this fetch stopped because it hit `limit` while
        #      there were still un-fetched findings (next_token is truthy) AND the last second is only
        #      partially consumed, advancing the cursor to that last second would skip the remaining
        #      siblings of that second (they fall on the same inclusive boundary but AWS may order them
        #      after the truncation point). To guarantee no loss we roll the cursor back to the last
        #      FULLY-drained second and persist its sibling ids, so the next run re-queries the
        #      truncated second from its start and makes forward progress.
        truncated_by_limit = bool(next_token)  # loop exited with a pending token => stopped due to limit
        if detector_events:
            # XSUP-73410: choose the cursor deterministically at WHOLE-SECOND resolution, independent of AWS
            # get_findings ordering. Group every ingested finding by its UpdatedAt second; the latest such
            # second is the boundary, and the cursor string is the max UpdatedAt within it — a single
            # deterministic representative, so millisecond siblings no longer make the cursor churn.
            event_seconds = [(ev, _cursor_second(_event_updated_at(ev))) for ev in detector_events]
            latest_second = max(sec for _, sec in event_seconds)
            cursor_second_target = latest_second
            if truncated_by_limit:
                # Find the latest whole-second strictly older than the last (partial) second.
                distinct_seconds = {sec for _, sec in event_seconds}
                fully_drained = sorted(s for s in distinct_seconds if s != latest_second)
                if fully_drained:
                    cursor_second_target = fully_drained[-1]
                    demisto.debug(
                        f"AWSGuardDutyEventCollector - Fetch truncated by limit for {detector_id=}. "
                        f"Rolling cursor back from partial second {latest_second} to last fully-drained "
                        f"second {cursor_second_target} to avoid skipping same-second siblings."
                    )
                else:
                    # The entire page is a single second that we could not fully drain. Keep the cursor
                    # on that second and accumulate seen ids so progress happens via dedup next run.
                    demisto.debug(
                        f"AWSGuardDutyEventCollector - Fetch truncated by limit for {detector_id=} within a "
                        f"single second {latest_second}; keeping cursor and accumulating seen ids."
                    )
            # Events sharing the target whole-second are the cursor's same-second siblings.
            cursor_second_events = [ev for ev, sec in event_seconds if sec == cursor_second_target]
            cursor_ts = max(_event_updated_at(ev) for ev in cursor_second_events)
            new_collect_from[detector_id] = cursor_ts
            cursor_sibling_ids = {ev.get("Id") for ev in cursor_second_events}
            cursor_sibling_ids.discard(None)
            # Carry forward previously-seen ids when the cursor second did not advance past them,
            # so we never forget same-second siblings across runs.
            carried_forward = seen_ids and cursor_second_target == cursor_second
            if carried_forward:
                cursor_sibling_ids |= seen_ids
            # XSUP-73410: log the chosen whole-second boundary, the deterministic max-in-second cursor
            # value, and how many same-second sibling ids are remembered — so future troubleshooting can
            # confirm the cursor no longer churns within a second and all siblings are tracked for dedup.
            demisto.debug(
                f"AWSGuardDutyEventCollector - Cursor advance for {detector_id=}: "
                f"boundary_second={cursor_second_target}, cursor_ts={cursor_ts!r}, "
                f"same_second_sibling_count={len(cursor_sibling_ids)}, {carried_forward=}."
            )
            # Stored as list so demisto.setLastRun can JSON-serialize it; round-trips via
            # _normalize_last_ids_entry on the next call.
            new_last_ids[detector_id] = sorted(cursor_sibling_ids)
        elif finding_ids:
            # No detector_events but we did see ids — everything AWS returned at/after the cursor
            # second deduped away as already-seen same-second siblings.
            #
            # XSUP-71079 (fully-deduped stale boundary): when this fetch was NOT truncated by limit
            # (AWS returned everything at/after the cursor and there is nothing newer) AND the cursor
            # boundary second is safely in the PAST, leaving the cursor unchanged wedges the fetch
            # forever — every cycle re-lists the same already-seen finding, ingests nothing, and the
            # cursor (which only advances on ingestion) never moves. To break the dead-end, step the
            # cursor one whole second past the drained boundary and drop the now-stale seen ids. A
            # RECENT boundary is left pinned so a genuine later same-second update is still catchable.
            fetch_start = collect_from_default or datetime.utcnow()
            boundary_is_stale = cursor_second < (fetch_start - STALE_BOUNDARY_MARGIN)
            if not truncated_by_limit and boundary_is_stale:
                next_second = cursor_second + timedelta(seconds=1)
                new_collect_from[detector_id] = next_second.isoformat()
                new_last_ids[detector_id] = []
                demisto.debug(
                    f"AWSGuardDutyEventCollector - Fully-deduped STALE boundary for {detector_id=}: "
                    f"{len(finding_ids)} finding id(s) listed but all deduped, nothing newer, and the "
                    f"boundary second {cursor_second} is older than {STALE_BOUNDARY_MARGIN} before "
                    f"{fetch_start}. Advancing cursor to {next_second.isoformat()} and clearing seen ids "
                    f"to break the stall."
                )
            else:
                # Keep the prior seen_ids as-is so we don't forget them next fetch. This is the correct
                # bounded pause for a still-current boundary, or when a limit-truncated page may still
                # have un-fetched siblings at this second.
                new_last_ids[detector_id] = sorted(seen_ids) if seen_ids else []
                demisto.debug(
                    f"AWSGuardDutyEventCollector - No new events for {detector_id=}: {len(finding_ids)} finding "
                    f"id(s) were listed but all were deduped as already-seen. Cursor left unchanged "
                    f"({truncated_by_limit=}, {boundary_is_stale=}); {len(seen_ids)} seen id(s) carried forward."
                )
        else:
            # Neither events nor finding ids — nothing matched the query this cycle. Cursor unchanged.
            demisto.debug(
                f"AWSGuardDutyEventCollector - No findings returned for {detector_id=} this cycle. " f"Cursor left unchanged."
            )

    demisto.debug(f"AWSGuardDutyEventCollector - Total number of events is {len(events)}")
    # XSUP-73410: log the outgoing cursor value+type that will be persisted via setLastRun, so we can
    # verify collect_from is stored in a parse_date_string-compatible format. Only the cursor (small)
    # and the per-detector last_ids COUNT are logged to keep the line bounded even with many siblings.
    demisto.debug(
        "AWSGuardDutyEventCollector - Persisting state. "
        f"new_collect_from={ {k: f'{v!r} ({type(v).__name__})' for k, v in new_collect_from.items()} }, "
        f"new_last_ids_counts={ {k: len(v) for k, v in new_last_ids.items()} }"
    )
    events = convert_events_with_datetime_to_str(events)
    return events, new_last_ids, new_collect_from


def main():  # pragma: no cover
    params = demisto.params()
    aws_default_region = params.get("defaultRegion")
    aws_role_arn = params.get("roleArn")
    aws_role_session_name = params.get("roleSessionName")
    aws_role_session_duration = params.get("sessionDuration")
    aws_role_policy = None
    aws_access_key_id = params.get("credentials", {}).get("identifier")
    aws_secret_access_key = params.get("credentials", {}).get("password")
    verify_certificate = not params.get("insecure", True)
    timeout = params.get("timeout") or 1
    retries = params.get("retries") or 5
    aws_gd_severity = params.get("gd_severity", "")
    first_fetch = arg_to_datetime(params.get("first_fetch"))
    limit = arg_to_number(params.get("limit"))
    sts_endpoint_url = params.get("sts_endpoint_url") or None
    endpoint_url = params.get("endpoint_url") or None
    exclude_archived = argToBoolean(params.get("exclude_archived", False))

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key)

        # proxy is being handled in AWSClient.
        aws_client = AWSClient(
            aws_default_region,
            aws_role_arn,
            aws_role_session_name,
            aws_role_session_duration,
            aws_role_policy,
            aws_access_key_id,
            aws_secret_access_key,
            verify_certificate,
            timeout,
            retries,
            sts_endpoint_url=sts_endpoint_url,
            endpoint_url=endpoint_url,
        )

        client: GuardDutyClient = aws_client.aws_session(service=CLIENT_SERVICE, region=aws_default_region)

        command = demisto.command()
        if command == "test-module":
            get_events(
                aws_client=client,
                collect_from={},
                collect_from_default=first_fetch,
                last_ids={},
                severity=aws_gd_severity,
                limit=1,
                detectors_num=1,
            )
            return_results("ok")

        elif command == "aws-gd-get-events":
            collect_from = arg_to_datetime(demisto.args().get("collect_from", params.get("first_fetch")))
            severity = demisto.args().get("severity", aws_gd_severity)
            command_limit = arg_to_number(demisto.args().get("limit", limit))
            events, new_last_ids, _ = get_events(
                aws_client=client,
                collect_from={},
                collect_from_default=collect_from,
                last_ids={},
                severity=severity,
                limit=command_limit if command_limit else MAX_RESULTS,
                exclude_archived=exclude_archived,
            )

            command_results = CommandResults(
                readable_output=tableToMarkdown("AWSGuardDuty Logs", events, headerTransform=pascalToSpace),
                raw_response=events,
            )
            return_results(command_results)

            if argToBoolean(demisto.args().get("should_push_events", "true")):
                send_events_to_xsiam(events, VENDOR, PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            collect_from_dict = last_run.get("collect_from", {})
            last_ids = last_run.get("last_ids", {})

            events, new_last_ids, new_collect_from_dict = get_events(
                aws_client=client,
                collect_from=collect_from_dict,
                collect_from_default=first_fetch,
                last_ids=last_ids,
                severity=aws_gd_severity,
                limit=limit if limit else MAX_RESULTS,
                exclude_archived=exclude_archived,
            )

            send_events_to_xsiam(events, VENDOR, PRODUCT)
            demisto.setLastRun({"collect_from": new_collect_from_dict, "last_ids": new_last_ids})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command in AWSGuardDutyEventCollector.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
