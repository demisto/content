# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cloudflare Audit Logs (version 2) Event Collector for Cortex XSIAM.

Collects the account audit log from Cloudflare's version 2 endpoint and ingests
it into the ``cloudflare_account_audit_v2_raw`` dataset.

Why this exists alongside the version 1 collector: the two endpoints return
DIFFERENT records with different identifier schemes, and only version 2 reports
authentication. Measured over an identical fourteen day window, version 1
returned 235 records and no sign-in of any kind, while version 2 returned 244
including LOGIN events carrying the actor's email address and source IP. An
account can therefore look fully audited while every dashboard sign-in goes
unrecorded.

    GET /accounts/{account_id}/logs/audit        version 2, this collector
    GET /accounts/{account_id}/audit_logs        version 1, the other collector

Two behaviours of this endpoint differ from version 1 and are easy to get wrong:

  * It REQUIRES both ``since`` and ``before``. Omitting ``before`` returns 400.
  * It IGNORES ``page`` and ``per_page``. Asking for page 1, 2 or 3 returns the
    identical records every time, so a page loop would re-send the same events
    indefinitely. Paging is by the opaque ``result_info.cursor``, and the page
    size is set by ``limit``.

A sign-in happens once and never changes, so this is a TIME-SERIES collector: it
tails with a high-water mark and re-reading an event is a defect.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

VENDOR = "cloudflare"
# Product string drives the dataset name: cloudflare_account_audit_v2_raw.
PRODUCT = "account_audit_v2"
SOURCE_LOG_TYPE = "audit_v2"
DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# The endpoint caps a page at 100 whatever is asked for, so this is the page
# size used for cursor paging rather than a value the API will honour verbatim.
API_PAGE_LIMIT = 100

# Nested objects flattened onto the event, so every column is queryable without
# parsing. Cortex reads raw columns as top level fields (Pattern D).
NESTED_OBJECTS = ("account", "action", "actor", "resource", "zone", "raw")

# Sub-fields carrying structured payloads rather than scalars. Kept as JSON
# strings: they are evidence worth having, but they have no fixed shape.
JSON_SUBFIELDS = {"resource_value", "resource_request", "resource_response"}


class Client(BaseClient):
    """Bearer-auth HTTP client for the Cloudflare audit logs v2 API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_audit_logs(
        self,
        account_id: str,
        since: str,
        before: str,
        limit: int = API_PAGE_LIMIT,
        cursor: Optional[str] = None,
    ) -> dict:
        """Fetch one page of version 2 audit logs.

        ``since`` and ``before`` are both mandatory. ``cursor`` continues a
        previous page and is opaque: never construct or parse it.
        """
        params: dict[str, Any] = {"since": since, "before": before, "limit": limit}
        if cursor:
            params["cursor"] = cursor

        return self._http_request(
            method="GET",
            url_suffix=f"/accounts/{account_id}/logs/audit",
            params=params,
        )


def _to_rfc3339(value: Any) -> str:
    """Normalise a datetime/str into a Cloudflare-friendly RFC3339 string."""
    dt = arg_to_datetime(value, required=True)
    assert dt is not None  # for type-checkers; arg_to_datetime raises otherwise
    return dt.strftime(DATE_FORMAT)


def _now_rfc3339() -> str:
    now = arg_to_datetime("now", required=True)
    assert now is not None
    return now.strftime(DATE_FORMAT)


def flatten_event(record: dict, account_id: str) -> dict:
    """Flatten one v2 record into top-level columns.

    ``account.name`` becomes ``account_name``, ``actor.ip_address`` becomes
    ``actor_ip_address``, and so on. Nothing nested survives, so a correlation
    can filter any field without parsing JSON.
    """
    event: dict[str, Any] = {}

    for key, value in record.items():
        if key in NESTED_OBJECTS and isinstance(value, dict):
            for sub_key, sub_value in value.items():
                column = f"{key}_{sub_key}"
                if column in JSON_SUBFIELDS or isinstance(sub_value, dict | list):
                    event[column] = json.dumps(sub_value) if sub_value not in (None, "", [], {}) else None
                else:
                    event[column] = sub_value
        elif not isinstance(value, dict | list):
            event[key] = value

    # The event time is the ACTION time, never ingest time. A re-read of an old
    # event keeps its original _time, falls outside a short correlation window,
    # and so cannot re-alert.
    event["_time"] = event.get("action_time")
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["cloudflare_account_id"] = account_id
    return event


def dedup_events(events: list[dict], last_ids: set) -> tuple[list[dict], str, set]:
    """Remove already-seen records and compute the next-run cursor.

    Returns the filtered events, the newest ``action_time`` seen, and the ids
    sharing that newest timestamp, which are carried forward so an inclusive
    re-fetch of the boundary second does not duplicate them.
    """
    new_events = [e for e in events if e.get("id") not in last_ids]
    if not new_events:
        return [], "", last_ids

    newest_ts = max(e.get("action_time") or "" for e in new_events)
    newest_ids = {e["id"] for e in new_events if (e.get("action_time") or "") == newest_ts and e.get("id")}
    return new_events, newest_ts, newest_ids


def fetch_logs_for_account(
    client: Client,
    account_id: str,
    since: str,
    before: str,
    max_fetch: int,
) -> list[dict]:
    """Walk the cursor for one account until exhausted or ``max_fetch`` reached.

    Terminates on an empty page or an absent cursor. It never increments a page
    number: this endpoint ignores ``page`` and would loop forever.
    """
    collected: list[dict] = []
    cursor: Optional[str] = None

    while len(collected) < max_fetch:
        response = client.get_audit_logs(
            account_id=account_id,
            since=since,
            before=before,
            limit=API_PAGE_LIMIT,
            cursor=cursor,
        )
        results = response.get("result") or []
        if not results:
            break

        collected.extend(results)

        cursor = (response.get("result_info") or {}).get("cursor")
        if not cursor:
            break

    return collected[:max_fetch]


def fetch_events(
    client: Client,
    account_ids: list[str],
    last_run: dict,
    first_fetch: str,
    max_fetch: int,
) -> tuple[list[dict], dict]:
    """Fetch across every configured account and build next_run."""
    all_events: list[dict] = []
    next_run: dict = {}
    before = _now_rfc3339()

    for account_id in account_ids:
        account_state = last_run.get(account_id, {})
        since = account_state.get("last_ts") or first_fetch
        last_ids = set(account_state.get("last_ids", []))

        try:
            raw = fetch_logs_for_account(
                client=client,
                account_id=account_id,
                since=since,
                before=before,
                max_fetch=max_fetch,
            )
        except Exception as e:  # noqa: BLE001 - one account must not stop the others
            # Carry this account's cursor forward untouched. If the exception
            # escaped, setLastRun would never run and EVERY account would
            # re-read its whole window on the next poll.
            demisto.error(f"Cloudflare: v2 audit fetch failed for account {account_id}, keeping its cursor: {e}")
            next_run[account_id] = account_state
            continue

        events = [flatten_event(record, account_id) for record in raw if isinstance(record, dict)]
        new_events, newest_ts, newest_ids = dedup_events(events, last_ids)

        all_events.extend(new_events)
        if newest_ts:
            next_run[account_id] = {"last_ts": newest_ts, "last_ids": list(newest_ids)}
        else:
            next_run[account_id] = account_state or {"last_ts": since, "last_ids": list(last_ids)}

        demisto.debug(f"Cloudflare: fetched {len(new_events)} v2 audit events for account {account_id}")

    return all_events, next_run


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, account_ids: list[str]) -> str:
    """Validate connectivity and token scope with a minimal request per account."""
    since = _to_rfc3339("1 day")
    before = _now_rfc3339()
    for account_id in account_ids:
        try:
            client.get_audit_logs(account_id=account_id, since=since, before=before, limit=1)
        except DemistoException as e:
            message = str(e)
            if any(token in message for token in ("[401]", "[403]", "Authentication error", "10000")):
                raise DemistoException(
                    f"Authorisation failed for account '{account_id}'. Check that the Cloudflare API "
                    "token is scoped to this account and carries audit log read access. "
                    f"Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) recent audit events."""
    account_ids = argToList(args["account_ids"])
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    since = _to_rfc3339(args.get("since") or "1 day")
    before = _now_rfc3339()

    events: list[dict] = []
    for account_id in account_ids:
        raw = fetch_logs_for_account(client, account_id, since, before, limit)
        events.extend(flatten_event(r, account_id) for r in raw if isinstance(r, dict))

    human_readable = tableToMarkdown(
        "Cloudflare Audit Logs (v2)",
        events,
        headers=["action_time", "action_description", "action_result", "actor_email", "actor_ip_address", "resource_type"],
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
    first_fetch = _to_rfc3339(params.get("first_fetch") or DEFAULT_FIRST_FETCH)
    max_fetch = arg_to_number(params.get("max_fetch_per_account")) or DEFAULT_MAX_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not account_ids:
            raise DemistoException("At least one Cloudflare account ID must be configured.")

        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, account_ids))

        elif command == "cloudflare-audit-v2-get-events":
            args.setdefault("account_ids", params.get("account_ids"))
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            events, next_run = fetch_events(client, account_ids, last_run, first_fetch, max_fetch)
            push_events(events)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
