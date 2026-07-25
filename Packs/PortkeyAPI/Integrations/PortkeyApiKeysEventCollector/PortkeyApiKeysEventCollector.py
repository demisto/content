# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Portkey API Keys Event Collector for Cortex XSIAM.

Collects the API key inventory from the Portkey Admin API (GET /api-keys) and
ingests it into the ``portkey_api_keys_raw`` dataset. API keys are current
configuration (an inventory), so each run sends the full snapshot, which lets
downstream correlations compare snapshots over time and detect a key whose
scopes were widened, whose expiry was removed, or that was newly created.

The scopes array is preserved as-is so a correlation can test for a specific
permission, and the counts that correlations filter on (scope count, rate-limit
count, whether a usage limit exists) are flattened to top-level scalars so no
JSON parsing is needed at query time.

Pagination is zero-based: page 0 is the first page. The endpoint reports the
grand total in ``total``, which stays populated past the last page, so paging
terminates on an empty page rather than on the total.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from datetime import datetime, UTC
from typing import Any

urllib3.disable_warnings()

VENDOR = "portkey"
# Product string drives the dataset name: portkey_api_keys_raw.
PRODUCT = "api_keys"
SOURCE_LOG_TYPE = "api_key"
DEFAULT_BASE_URL = "https://api.portkey.ai/v1"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50
# The Portkey list endpoints cap page_size at 100.
DEFAULT_PAGE_SIZE = 100


class Client(BaseClient):
    """HTTP client for the Portkey Admin API."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {
            "x-portkey-api-key": api_key,
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_api_keys(self, current_page: int = 0, page_size: int = DEFAULT_PAGE_SIZE) -> dict:
        """Fetch a single page of API keys.

        Portkey returns ``{"data": [...], "total": int}``. ``current_page`` is
        zero-based.
        """
        params: dict[str, Any] = {"current_page": current_page, "page_size": page_size}
        return self._http_request(method="GET", url_suffix="/api-keys", params=params)


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_api_key_event(record: dict, now: str) -> dict:
    """Stamp ingestion metadata and flatten the counts correlations filter on."""
    event = dict(record)
    scopes = record.get("scopes") or []
    rate_limits = record.get("rate_limits") or []

    event["scope_count"] = len(scopes)
    event["rate_limit_count"] = len(rate_limits)
    event["has_usage_limit"] = record.get("usage_limits") is not None
    event["has_expiry"] = record.get("expires_at") is not None

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    return event


def fetch_events(client: Client, max_fetch: int, page_size: int = DEFAULT_PAGE_SIZE) -> list[dict]:
    """Fetch the current API key snapshot, paging from page 0."""
    collected: list[dict] = []
    page = 0
    now = _now_rfc3339()

    while len(collected) < max_fetch:
        response = client.list_api_keys(current_page=page, page_size=page_size)
        records = response.get("data") or []
        if not records:
            break
        collected.extend(records)
        if len(records) < page_size:
            break
        page += 1

    events = [build_api_key_event(record, now) for record in collected[:max_fetch]]
    demisto.debug(f"Portkey: fetched {len(events)} API keys")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client) -> str:
    """Validate connectivity and token scope with a minimal request."""
    try:
        client.list_api_keys(current_page=0, page_size=1)
    except DemistoException as e:
        message = str(e)
        if any(token in message for token in ("[401]", "[403]", "Unauthorized", "Forbidden", "AB03")):
            raise DemistoException(
                "Authorisation failed. Check that the Portkey API key includes the API key list "
                "scopes (organisation_service_api_keys.list, workspace_service_api_keys.list and "
                f"workspace_user_api_keys.list). Original error: {message}"
            )
        raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the API key inventory."""
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    events = fetch_events(client, limit, min(DEFAULT_PAGE_SIZE, limit))
    human_readable = tableToMarkdown(
        "Portkey API Keys",
        events,
        headers=["id", "name", "type", "status", "scope_count", "expires_at", "created_at"],
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

    demisto.debug(f"Command being called is {command}")
    try:
        if not api_key:
            raise DemistoException("A Portkey admin API key must be configured.")

        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "portkey-api-keys-get-events":
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_events(client, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_snapshot": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
