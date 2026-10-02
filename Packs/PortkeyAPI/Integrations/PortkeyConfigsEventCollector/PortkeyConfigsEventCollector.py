# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Portkey Configs Event Collector for Cortex XSIAM.

Collects the gateway config inventory from the Portkey Admin API
(GET /configs) and ingests it into the ``portkey_configs_raw`` dataset. A
Portkey config defines how requests are routed: the provider and model chosen,
the fallback and retry behaviour, caching, and which guardrails are attached.
Configs are current configuration (an inventory), so each run sends the full
snapshot, which lets downstream correlations compare snapshots over time and
detect a config that was newly created or re-owned.

Unlike the other Portkey list endpoints, GET /configs takes NO parameters: the
OpenAPI specification declares none, and the endpoint ignores current_page and
page_size, returning the identical full list for every page number. Paging it
the way /api-keys is paged would re-request the same records forever, so this
collector issues a single request and never pages.

The list endpoint returns config metadata only. The config body, which holds
the routing rules and attached guardrails, is served by GET /configs/{slug} and
needs the separate configs.read scope.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from datetime import datetime, UTC
from typing import Any

urllib3.disable_warnings()

VENDOR = "portkey"
# Product string drives the dataset name: portkey_configs_raw.
PRODUCT = "configs"
SOURCE_LOG_TYPE = "config"
DEFAULT_BASE_URL = "https://api.portkey.ai/v1"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50


class Client(BaseClient):
    """HTTP client for the Portkey Admin API."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {
            "x-portkey-api-key": api_key,
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_configs(self) -> dict:
        """Fetch the full config list.

        The endpoint takes no parameters and is not paginated: it returns the
        complete list on every call.
        """
        return self._http_request(method="GET", url_suffix="/configs")


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_config_event(record: dict, now: str) -> dict:
    """Stamp ingestion metadata onto a config record."""
    event: dict[str, Any] = {}
    for key, value in record.items():
        if isinstance(value, bool | str | int | float) or value is None:
            event[key] = value

    # A config whose last editor differs from its owner is worth surfacing.
    owner = record.get("owner_id")
    updated_by = record.get("updated_by")
    event["updated_by_owner"] = bool(owner) and owner == updated_by

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    return event


def fetch_events(client: Client, max_fetch: int) -> list[dict]:
    """Fetch the current config snapshot in a single request."""
    response = client.list_configs()
    records = response.get("data") or []
    now = _now_rfc3339()
    events = [build_config_event(record, now) for record in records[:max_fetch]]

    total = response.get("total")
    if total is not None and len(records) < total:
        demisto.debug(
            f"Portkey: the configs endpoint returned {len(records)} of {total} records. "
            "The endpoint is not paginated, so the remainder cannot be requested."
        )
    demisto.debug(f"Portkey: fetched {len(events)} configs")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client) -> str:
    """Validate connectivity and token scope with a minimal request."""
    try:
        client.list_configs()
    except DemistoException as e:
        message = str(e)
        if any(token in message for token in ("[401]", "[403]", "Unauthorized", "Forbidden", "AB03")):
            raise DemistoException(
                f"Authorisation failed. Check that the Portkey API key includes the configs.list scope. Original error: {message}"
            )
        raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the config inventory."""
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    events = fetch_events(client, limit)
    human_readable = tableToMarkdown(
        "Portkey Configs",
        events,
        headers=["id", "name", "slug", "status", "workspace_id", "owner_id", "last_updated_at"],
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

        elif command == "portkey-configs-get-events":
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
