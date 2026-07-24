# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cloudflare Audit Logs Event Collector for Cortex XSIAM.

Pulls account audit logs from the Cloudflare API
(GET /accounts/{account_id}/audit_logs) and ingests them into the
``cloudflare_account_audit_raw`` dataset via ``send_events_to_xsiam``.

Collection window: the fetch advances a per-account high-water mark (the newest
audit ``when`` timestamp seen), not a fixed poll-interval offset. Each run resumes
from that mark, so a delayed, skipped, or overlapping poll never leaves a gap.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
VENDOR = "cloudflare"
# Product string drives the dataset name: cloudflare_account_audit_raw.
# Each Cloudflare log type gets its own product/dataset (see pack roadmap).
PRODUCT = "account_audit"
DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50
# Cloudflare caps per_page at 1000 for the audit_logs endpoint.
API_MAX_PER_PAGE = 1000
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Client(BaseClient):
    """HTTP client for the Cloudflare audit logs API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_audit_logs(
        self,
        account_id: str,
        since: Optional[str] = None,
        before: Optional[str] = None,
        page: int = 1,
        per_page: int = API_MAX_PER_PAGE,
        direction: str = "asc",
        hide_user_logs: bool = False,
    ) -> dict:
        """Fetch a single page of audit logs for an account.

        Cloudflare returns results wrapped in
        ``{"result": [...], "result_info": {...}, "success": bool}``.
        """
        params: dict[str, Any] = {
            "page": page,
            "per_page": per_page,
            "direction": direction,
        }
        if since:
            params["since"] = since
        if before:
            params["before"] = before
        if hide_user_logs:
            params["hide_user_logs"] = "true"

        return self._http_request(
            method="GET",
            url_suffix=f"/accounts/{account_id}/audit_logs",
            params=params,
        )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _to_rfc3339(value: Any) -> str:
    """Normalise a datetime/str into a Cloudflare-friendly RFC3339 string."""
    dt = arg_to_datetime(value, required=True)
    assert dt is not None  # for type-checkers; arg_to_datetime raises otherwise
    return dt.strftime(DATE_FORMAT)


def add_fields_to_event(event: dict, account_id: str) -> dict:
    """Attach XSIAM ingestion metadata to a raw audit log event."""
    event["_time"] = event.get("when")
    event["source_log_type"] = "audit"
    event["cloudflare_account_id"] = account_id
    return event


def dedup_events(events: list[dict], last_ids: set) -> tuple[list[dict], str, set]:
    """Remove already-seen events and compute the next-run cursor.

    Events are expected in ascending ``when`` order. Returns the filtered
    events, the newest ``when`` timestamp seen, and the set of event ids that
    share that newest timestamp (to dedup on the next fetch).
    """
    new_events = [e for e in events if e.get("id") not in last_ids]
    if not new_events:
        return [], "", last_ids

    newest_ts = max(e.get("when", "") for e in new_events)
    newest_ids = {e["id"] for e in new_events if e.get("when") == newest_ts and e.get("id")}
    return new_events, newest_ts, newest_ids


def fetch_audit_logs_for_account(
    client: Client,
    account_id: str,
    since: str,
    max_fetch: int,
    last_ids: set,
    hide_user_logs: bool,
) -> tuple[list[dict], str, set]:
    """Page through the audit logs for one account until ``max_fetch``.

    Returns collected events (with metadata), the new last-seen timestamp, and
    the new dedup id set. If nothing new is found the previous cursor is kept.
    """
    collected: list[dict] = []
    page = 1
    per_page = min(API_MAX_PER_PAGE, max_fetch) or API_MAX_PER_PAGE

    while len(collected) < max_fetch:
        response = client.get_audit_logs(
            account_id=account_id,
            since=since,
            page=page,
            per_page=per_page,
            direction="asc",
            hide_user_logs=hide_user_logs,
        )
        results = response.get("result") or []
        if not results:
            break

        collected.extend(results)

        result_info = response.get("result_info") or {}
        total_pages = result_info.get("total_pages")
        if total_pages is not None and page >= total_pages:
            break
        page += 1

    # Trim to the requested ceiling before dedup/metadata.
    collected = collected[:max_fetch]
    new_events, newest_ts, newest_ids = dedup_events(collected, last_ids)

    for event in new_events:
        add_fields_to_event(event, account_id)

    if not newest_ts:
        # Nothing new; keep the existing cursor for next run.
        return new_events, since, last_ids

    return new_events, newest_ts, newest_ids


def fetch_events(
    client: Client,
    account_ids: list[str],
    last_run: dict,
    first_fetch: str,
    max_fetch: int,
    hide_user_logs: bool,
) -> tuple[list[dict], dict]:
    """Fetch events across all configured accounts and build next_run."""
    all_events: list[dict] = []
    next_run: dict = {}

    for account_id in account_ids:
        account_state = last_run.get(account_id, {})
        since = account_state.get("last_ts") or first_fetch
        last_ids = set(account_state.get("last_ids", []))

        events, new_ts, new_ids = fetch_audit_logs_for_account(
            client=client,
            account_id=account_id,
            since=since,
            max_fetch=max_fetch,
            last_ids=last_ids,
            hide_user_logs=hide_user_logs,
        )
        all_events.extend(events)
        next_run[account_id] = {"last_ts": new_ts, "last_ids": list(new_ids)}
        demisto.debug(f"Cloudflare: fetched {len(events)} events for account {account_id}")

    return all_events, next_run


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #
def test_module(client: Client, account_ids: list[str], hide_user_logs: bool) -> str:
    """Validate connectivity and token scope with a minimal fetch per account."""
    since = _to_rfc3339("1 day")
    for account_id in account_ids:
        try:
            client.get_audit_logs(
                account_id=account_id,
                since=since,
                page=1,
                per_page=1,
                direction="desc",
                hide_user_logs=hide_user_logs,
            )
        except DemistoException as e:
            message = str(e)
            if any(token in message for token in ("[401]", "[403]", "Authentication error", "10000")):
                raise DemistoException(
                    f"Authorisation failed for account '{account_id}'. Check that the Cloudflare API "
                    f"Token has the 'Account Settings: Read' permission (not 'Access: Audit Logs Read', "
                    f"which is for Zero Trust) and is scoped to this account. Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: Client, args: dict, hide_user_logs: bool) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) audit log events."""
    account_ids = argToList(args["account_ids"])
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    since = _to_rfc3339(args.get("since") or DEFAULT_FIRST_FETCH)

    events, _ = fetch_events(
        client=client,
        account_ids=account_ids,
        last_run={},
        first_fetch=since,
        max_fetch=limit,
        hide_user_logs=hide_user_logs,
    )

    human_readable = tableToMarkdown(
        "Cloudflare Audit Logs",
        events,
        headers=["id", "when", "cloudflare_account_id", "interface"],
        removeNull=True,
    )
    results = CommandResults(readable_output=human_readable, raw_response=events)
    return events, results


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_token = (params.get("credentials") or {}).get("password", "")
    account_ids = argToList(params.get("account_ids"))
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    hide_user_logs = params.get("hide_user_logs", False)
    max_fetch = arg_to_number(params.get("max_fetch_per_account")) or DEFAULT_MAX_FETCH
    first_fetch = _to_rfc3339(params.get("first_fetch") or DEFAULT_FIRST_FETCH)

    demisto.debug(f"Command being called is {command}")
    try:
        if not account_ids:
            raise DemistoException("At least one Cloudflare account ID must be configured.")

        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, account_ids, hide_user_logs))

        elif command == "cloudflare-audit-logs-get-events":
            args.setdefault("account_ids", params.get("account_ids"))
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args, hide_user_logs)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            events, next_run = fetch_events(
                client=client,
                account_ids=account_ids,
                last_run=last_run,
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                hide_user_logs=hide_user_logs,
            )
            push_events(events)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
