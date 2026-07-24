# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cloudflare Access Authentication Logs Event Collector for Cortex XSIAM.

Pulls Zero Trust Access authentication logs from the Cloudflare API
(GET /accounts/{account_id}/access/logs/access_requests) and ingests them into
the ``cloudflare_access_auth_raw`` dataset via ``send_events_to_xsiam``.

Each record is one authentication event against a Cloudflare Access protected
application: who authenticated, from where, to which app, and whether it was
allowed. The fetch advances a per-account high-water mark (the newest
``created_at`` seen), resuming from that mark with an inclusive ``since`` and
de-duplicating the boundary by ``ray_id``, so a delayed, skipped, or
overlapping poll never leaves a gap.

This is Zero Trust Access data. The API token needs the
"Access: Audit Logs Read" permission (with "Account Settings Read" as a
fallback some configurations require) and must be scoped to the account.
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

VENDOR = "cloudflare"
PRODUCT = "access_auth"
SOURCE_LOG_TYPE = "access_auth"
DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50
# Cloudflare caps the Access logs page at 1000 records.
API_MAX_LIMIT = 1000
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Client(BaseClient):
    """Bearer-auth HTTP client for the Cloudflare Access logs API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_access_logs(
        self,
        account_id: str,
        since: str,
        until: str,
        limit: int = API_MAX_LIMIT,
        direction: str = "asc",
    ) -> dict:
        """Fetch a page of Access authentication logs for an account.

        Returns the wrapper ``{"result": [...], "result_info": {...}, "success": bool}``.
        """
        params: dict[str, Any] = {
            "since": since,
            "until": until,
            "limit": limit,
            "direction": direction,
        }
        return self._http_request(
            method="GET",
            url_suffix=f"/accounts/{account_id}/access/logs/access_requests",
            params=params,
        )


def _to_rfc3339(value: Any) -> str:
    """Normalise a datetime/str into a Cloudflare-friendly RFC3339 string."""
    dt = arg_to_datetime(value, required=True)
    assert dt is not None  # arg_to_datetime raises otherwise
    return dt.strftime(DATE_FORMAT)


def add_fields_to_event(event: dict, account_id: str) -> dict:
    """Attach XSIAM ingestion metadata to a raw Access log event."""
    event["_time"] = event.get("created_at")
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["cloudflare_account_id"] = account_id
    return event


def dedup_events(events: list[dict], last_ids: set) -> tuple[list[dict], str, set]:
    """Drop already-seen events and compute the next-run cursor.

    Events are expected in ascending ``created_at`` order. Returns the filtered
    events, the newest ``created_at`` seen, and the set of ``ray_id`` values that
    share that newest timestamp (to dedup on the next fetch).
    """
    new_events = [e for e in events if e.get("ray_id") not in last_ids]
    if not new_events:
        return [], "", last_ids

    newest_ts = max(e.get("created_at", "") for e in new_events)
    newest_ids = {
        e["ray_id"] for e in new_events if e.get("created_at") == newest_ts and e.get("ray_id")
    }
    return new_events, newest_ts, newest_ids


def fetch_access_logs_for_account(
    client: Client,
    account_id: str,
    since: str,
    until: str,
    max_fetch: int,
    last_ids: set,
) -> tuple[list[dict], str, set]:
    """Page through the Access logs for one account until ``max_fetch``.

    The endpoint returns up to ``limit`` records for the window. When a full page
    is returned there may be more, so the window start is advanced to the newest
    ``created_at`` seen and the fetch continues, de-duplicating the boundary.
    """
    collected: list[dict] = []
    cursor = since
    limit = min(API_MAX_LIMIT, max_fetch) or API_MAX_LIMIT
    seen_ray_ids: set = set(last_ids)

    while len(collected) < max_fetch:
        response = client.get_access_logs(
            account_id=account_id, since=cursor, until=until, limit=limit, direction="asc"
        )
        results = response.get("result") or []
        if not results:
            break

        fresh = [e for e in results if e.get("ray_id") not in seen_ray_ids]
        collected.extend(fresh)
        seen_ray_ids.update(e.get("ray_id") for e in results if e.get("ray_id"))

        if len(results) < limit:
            break
        newest = max(e.get("created_at", "") for e in results)
        if not newest or newest == cursor:
            break
        cursor = newest

    collected = collected[:max_fetch]
    new_events, newest_ts, newest_ids = dedup_events(collected, last_ids)

    for event in new_events:
        add_fields_to_event(event, account_id)

    if not newest_ts:
        return new_events, since, last_ids
    return new_events, newest_ts, newest_ids


def fetch_events(
    client: Client,
    account_ids: list[str],
    last_run: dict,
    first_fetch: str,
    max_fetch: int,
) -> tuple[list[dict], dict]:
    """Fetch events across all configured accounts and build next_run."""
    all_events: list[dict] = []
    next_run: dict = {}
    until = _to_rfc3339("now")

    for account_id in account_ids:
        account_state = last_run.get(account_id, {})
        since = account_state.get("last_ts") or _to_rfc3339(first_fetch)
        last_ids = set(account_state.get("last_ids", []))

        events, new_ts, new_ids = fetch_access_logs_for_account(
            client=client,
            account_id=account_id,
            since=since,
            until=until,
            max_fetch=max_fetch,
            last_ids=last_ids,
        )
        all_events.extend(events)
        next_run[account_id] = {"last_ts": new_ts, "last_ids": list(new_ids)}
        demisto.debug(f"Cloudflare: fetched {len(events)} Access events for account {account_id}")

    return all_events, next_run


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, account_ids: list[str]) -> str:
    """Validate connectivity and token scope with a minimal fetch per account."""
    since = _to_rfc3339("1 day")
    until = _to_rfc3339("now")
    for account_id in account_ids:
        try:
            client.get_access_logs(account_id=account_id, since=since, until=until, limit=1, direction="desc")
        except DemistoException as e:
            message = str(e)
            if any(token in message for token in ("[401]", "[403]", "Authentication error", "10000")):
                raise DemistoException(
                    f"Authorisation failed for account '{account_id}'. Check that the Cloudflare API "
                    "Token has the 'Access: Audit Logs Read' permission (add 'Account Settings Read' "
                    "if your configuration requires it) and is scoped to this account. "
                    f"Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) Access log events."""
    account_ids = argToList(args["account_ids"])
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    since = _to_rfc3339(args.get("since") or DEFAULT_FIRST_FETCH)

    events, _ = fetch_events(
        client=client,
        account_ids=account_ids,
        last_run={},
        first_fetch=since,
        max_fetch=limit,
    )

    human_readable = tableToMarkdown(
        "Cloudflare Access Authentication Logs",
        events,
        headers=["created_at", "user_email", "ip_address", "app_domain", "allowed", "action"],
        removeNull=True,
    )
    return events, CommandResults(readable_output=human_readable, raw_response=events)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_token = (params.get("credentials") or {}).get("password", "")
    account_ids = argToList(params.get("account_ids"))
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    first_fetch = params.get("first_fetch") or DEFAULT_FIRST_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not account_ids:
            raise DemistoException("At least one Cloudflare account ID must be configured.")

        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, account_ids))

        elif command == "cloudflare-access-auth-logs-get-events":
            args.setdefault("account_ids", params.get("account_ids"))
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
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
            )
            push_events(events)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
