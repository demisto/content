# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CircleCI Pipelines Event Collector for Cortex XSIAM.

Pulls pipelines from the CircleCI v2 API (GET /pipeline?org-slug=...) and
ingests them into the ``circleci_pipelines_raw`` dataset via
``send_events_to_xsiam``.

The endpoint returns pipelines newest-first with ``page-token`` pagination.
The fetch advances a per-organisation high-water mark (the newest pipeline
``created_at`` seen): each run pages until it reaches the previous mark, so a
delayed, skipped, or overlapping poll never leaves a gap.
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from datetime import datetime, timezone
from typing import Any

urllib3.disable_warnings()

VENDOR = "circleci"
# Product string drives the dataset name: circleci_pipelines_raw.
PRODUCT = "pipelines"
SOURCE_LOG_TYPE = "pipeline"
DEFAULT_BASE_URL = "https://circleci.com/api/v2"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50


class Client(BaseClient):
    """HTTP client for the CircleCI v2 API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Circle-Token": api_token,
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_pipelines(self, org_slug: str, page_token: Optional[str] = None) -> dict:
        """Fetch a single page of pipelines for an organisation (newest first)."""
        params: dict[str, Any] = {"org-slug": org_slug}
        if page_token:
            params["page-token"] = page_token
        return self._http_request(method="GET", url_suffix="/pipeline", params=params)


def _parse_ts(value: str) -> datetime:
    """Parse a CircleCI RFC3339 timestamp (handles the trailing Z)."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _cutoff_from_first_fetch(first_fetch: str) -> datetime:
    dt = arg_to_datetime(first_fetch, required=True)
    assert dt is not None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def add_fields_to_event(event: dict, org_slug: str) -> dict:
    """Attach XSIAM ingestion metadata to a raw pipeline record."""
    event["_time"] = event.get("created_at")
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["circleci_org_slug"] = org_slug
    return event


def fetch_pipelines_for_org(
    client: Client,
    org_slug: str,
    cutoff: datetime,
    last_ids: set,
    max_fetch: int,
) -> tuple[list[dict], str, set]:
    """Page newest-first until the high-water mark, collecting new pipelines.

    Returns collected events (with metadata), the new last-seen timestamp
    (ISO string), and the new boundary dedup id set. If nothing new is found
    the previous cursor values are kept by the caller.
    """
    collected: list[dict] = []
    page_token: Optional[str] = None

    while len(collected) < max_fetch:
        response = client.list_pipelines(org_slug=org_slug, page_token=page_token)
        items = response.get("items") or []
        if not items:
            break

        reached_mark = False
        for item in items:
            created_at = item.get("created_at") or ""
            if not created_at or _parse_ts(created_at) < cutoff:
                reached_mark = True
                break
            if item.get("id") in last_ids:
                continue
            collected.append(item)

        page_token = response.get("next_page_token")
        if reached_mark or not page_token:
            break

    collected = collected[:max_fetch]
    if not collected:
        return [], "", last_ids

    newest_ts = max(e.get("created_at", "") for e in collected)
    newest_ids = {e["id"] for e in collected if e.get("created_at") == newest_ts and e.get("id")}

    for event in collected:
        add_fields_to_event(event, org_slug)

    return collected, newest_ts, newest_ids


def fetch_events(
    client: Client,
    org_slugs: list[str],
    last_run: dict,
    first_fetch: str,
    max_fetch: int,
) -> tuple[list[dict], dict]:
    """Fetch pipelines across all configured organisations and build next_run."""
    all_events: list[dict] = []
    next_run: dict = {}

    for org_slug in org_slugs:
        org_state = last_run.get(org_slug, {})
        last_ts = org_state.get("last_ts")
        last_ids = set(org_state.get("last_ids", []))
        cutoff = _parse_ts(last_ts) if last_ts else _cutoff_from_first_fetch(first_fetch)

        events, new_ts, new_ids = fetch_pipelines_for_org(
            client=client,
            org_slug=org_slug,
            cutoff=cutoff,
            last_ids=last_ids,
            max_fetch=max_fetch,
        )
        all_events.extend(events)
        next_run[org_slug] = {
            "last_ts": new_ts or last_ts or "",
            "last_ids": list(new_ids) if new_ts else list(last_ids),
        }
        demisto.debug(f"CircleCI: fetched {len(events)} pipelines for org {org_slug}")

    return all_events, next_run


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, org_slugs: list[str]) -> str:
    """Validate connectivity and token access with a minimal fetch per organisation."""
    for org_slug in org_slugs:
        try:
            client.list_pipelines(org_slug=org_slug)
        except DemistoException as e:
            message = str(e)
            if any(token in message for token in ("[401]", "[403]", "[404]", "Authentication error")):
                raise DemistoException(
                    f"Authorisation failed for organisation '{org_slug}'. Check that the CircleCI "
                    "personal API token is valid and that the org slug is correct (e.g. "
                    "'gh/MyOrg' or 'circleci/<org-id>'; list yours via the /me/collaborations "
                    f"endpoint). Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) pipeline events."""
    org_slugs = argToList(args["org_slugs"])
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    since = args.get("since") or DEFAULT_FIRST_FETCH

    events, _ = fetch_events(
        client=client,
        org_slugs=org_slugs,
        last_run={},
        first_fetch=since,
        max_fetch=limit,
    )

    human_readable = tableToMarkdown(
        "CircleCI Pipelines",
        events,
        headers=["id", "number", "project_slug", "state", "created_at"],
        removeNull=True,
    )
    return events, CommandResults(readable_output=human_readable, raw_response=events)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_token = (params.get("credentials") or {}).get("password", "")
    org_slugs = argToList(params.get("org_slugs"))
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch_per_org")) or DEFAULT_MAX_FETCH
    first_fetch = params.get("first_fetch") or DEFAULT_FIRST_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not org_slugs:
            raise DemistoException("At least one CircleCI organisation slug must be configured.")

        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, org_slugs))

        elif command == "circleci-pipelines-get-events":
            args.setdefault("org_slugs", params.get("org_slugs"))
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            events, next_run = fetch_events(
                client=client,
                org_slugs=org_slugs,
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
