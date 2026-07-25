# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Portkey Audit Logs Event Collector for Cortex XSIAM.

Pulls control-plane audit logs from the Portkey Admin API
(GET /audit-logs) and ingests them into the ``portkey_audit_raw`` dataset via
``send_events_to_xsiam``.

The endpoint requires a start and end time and an organisation ID, and paginates
with ``current_page`` / ``page_size``. Collection advances a high-water mark (the
newest audit ``timestamp`` seen): each run resumes from that mark with an
inclusive start time and de-duplicates the boundary by ``request_id``, so a
delayed, skipped, or overlapping poll never leaves a gap.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

VENDOR = "portkey"
PRODUCT = "audit"
DEFAULT_BASE_URL = "https://api.portkey.ai/v1"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50
DEFAULT_PAGE_SIZE = 100
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class Client(BaseClient):
    """HTTP client for the Portkey Admin API."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {
            "x-portkey-api-key": api_key,
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_audit_logs(
        self,
        start_time: str,
        end_time: str,
        current_page: int = 0,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> dict:
        """Fetch a single page of audit logs.

        Portkey returns results wrapped in ``{"records": [...], "total": int}``,
        newest record first. ``current_page`` is zero-based: page 0 is the first
        page. ``total`` is the count of records matching the window, and drops to
        zero once ``current_page`` runs past the last page.

        The organisation is implied by the API key and must not be sent as a
        query parameter: supplying ``organisation_id`` makes the endpoint reject
        the request with 403 ``AB03`` (insufficient permissions).
        """
        params: dict[str, Any] = {
            "start_time": start_time,
            "end_time": end_time,
            "current_page": current_page,
            "page_size": page_size,
        }
        return self._http_request(method="GET", url_suffix="/audit-logs", params=params)


def _to_iso8601(value: Any) -> str:
    """Normalise a datetime/str into an ISO8601 string with a trailing Z."""
    dt = arg_to_datetime(value, required=True)
    assert dt is not None  # arg_to_datetime raises otherwise
    return dt.strftime(DATE_FORMAT)


def add_fields_to_event(event: dict) -> dict:
    """Attach XSIAM ingestion metadata to a raw audit log event.

    Each record carries its own ``organisation_id``, so the organisation is
    taken from the event rather than from configuration.
    """
    event["_time"] = event.get("timestamp")
    event["source_log_type"] = "audit"
    event["portkey_organisation_id"] = event.get("organisation_id")
    return event


def dedup_events(events: list[dict], last_ids: set) -> tuple[list[dict], str, set]:
    """Remove already-seen events and compute the next-run cursor.

    Returns the filtered events, the newest ``timestamp`` seen, and the set of
    request ids that share that newest timestamp (to dedup on the next fetch).
    """
    new_events = [e for e in events if e.get("request_id") not in last_ids]
    if not new_events:
        return [], "", last_ids

    newest_ts = max(e.get("timestamp", "") for e in new_events)
    newest_ids = {e["request_id"] for e in new_events if e.get("timestamp") == newest_ts and e.get("request_id")}
    return new_events, newest_ts, newest_ids


def fetch_audit_logs(
    client: Client,
    start_time: str,
    end_time: str,
    max_fetch: int,
    last_ids: set,
    page_size: int,
) -> tuple[list[dict], str, set]:
    """Page through the audit logs for the window until ``max_fetch``.

    Returns collected events (with metadata), the new last-seen timestamp, and
    the new dedup id set. If nothing new is found the previous cursor is kept.
    Paging starts at page 0, which is the first page for this endpoint.
    """
    collected: list[dict] = []
    page = 0

    while len(collected) < max_fetch:
        response = client.get_audit_logs(
            start_time=start_time,
            end_time=end_time,
            current_page=page,
            page_size=page_size,
        )
        records = response.get("records") or []
        if not records:
            break

        collected.extend(records)

        total = response.get("total")
        if total is not None and len(collected) >= total:
            break
        if len(records) < page_size:
            break
        page += 1

    collected = collected[:max_fetch]
    new_events, newest_ts, newest_ids = dedup_events(collected, last_ids)

    for event in new_events:
        add_fields_to_event(event)

    if not newest_ts:
        return new_events, start_time, last_ids

    return new_events, newest_ts, newest_ids


def fetch_events(
    client: Client,
    last_run: dict,
    first_fetch: str,
    max_fetch: int,
    page_size: int,
) -> tuple[list[dict], dict]:
    """Fetch events for the organisation behind the API key and build next_run."""
    since = last_run.get("last_ts") or _to_iso8601(first_fetch)
    last_ids = set(last_run.get("last_ids", []))
    end_time = _to_iso8601("now")

    events, new_ts, new_ids = fetch_audit_logs(
        client=client,
        start_time=since,
        end_time=end_time,
        max_fetch=max_fetch,
        last_ids=last_ids,
        page_size=page_size,
    )
    next_run = {"last_ts": new_ts, "last_ids": list(new_ids)}
    demisto.debug(f"Portkey: fetched {len(events)} audit events")
    return events, next_run


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client) -> str:
    """Validate connectivity and token scope with a minimal fetch."""
    try:
        client.get_audit_logs(
            start_time=_to_iso8601("1 day"),
            end_time=_to_iso8601("now"),
            current_page=0,
            page_size=1,
        )
    except DemistoException as e:
        message = str(e)
        if any(token in message for token in ("[401]", "[403]", "Unauthorized", "Forbidden", "AB03")):
            raise DemistoException(
                "Authorisation failed. Check that the Portkey API key is an organisation-scoped "
                "admin API key that includes the 'audit_logs.list' scope. Audit logs are a "
                f"Portkey Enterprise feature. Original error: {message}"
            )
        raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) audit log events."""
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    since = _to_iso8601(args.get("since") or DEFAULT_FIRST_FETCH)

    events, _ = fetch_events(
        client=client,
        last_run={"last_ts": since},
        first_fetch=since,
        max_fetch=limit,
        page_size=min(DEFAULT_PAGE_SIZE, limit),
    )

    human_readable = tableToMarkdown(
        "Portkey Audit Logs",
        events,
        headers=["timestamp", "method", "uri", "action", "user_id", "user_type", "response_status_code"],
        removeNull=True,
    )
    return events, CommandResults(readable_output=human_readable, raw_response=events)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_key = (params.get("credentials") or {}).get("password", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    page_size = arg_to_number(params.get("page_size")) or DEFAULT_PAGE_SIZE
    first_fetch = params.get("first_fetch") or DEFAULT_FIRST_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not api_key:
            raise DemistoException("A Portkey admin API key must be configured.")

        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "portkey-audit-logs-get-events":
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            events, next_run = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                page_size=page_size,
            )
            push_events(events)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
