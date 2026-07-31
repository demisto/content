# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Grafana Data Sources Event Collector for Cortex XSIAM.

Collects the data source inventory from a Grafana instance and ingests it into
the ``grafana_datasources_raw`` dataset.

A Grafana data source is a configured connection to a backend system, holding
its URL, its access mode and, where basic auth is used, a stored credential. It
is therefore both a credential store and a path out of the estate: a data source
pointed at an unexpected URL can move query results somewhere they should not
go. The inventory answers what this Grafana can reach and how it authenticates.

    GET /api/datasources

This endpoint IGNORES pagination. Proven on a live instance: ``perpage=1``
returned all fifteen records. It is requested once and never paged, because a
page loop over it would re-send the same records indefinitely.

Credential VALUES are never returned by this endpoint and are never collected.
Grafana holds them in ``secureJsonData``, which the list endpoint omits entirely.
The basic-auth USERNAME is returned and is collected, because it identifies the
account being used without exposing its secret.

There is no event stream here, only current state, so this is a SNAPSHOT
collector: it re-sends the full inventory every run. Duplicate rows across runs
are correct, because comparing successive snapshots is what makes a change
detectable.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

VENDOR = "grafana"
# Product string drives the dataset name: grafana_datasources_raw.
PRODUCT = "datasources"
SOURCE_LOG_TYPE = "datasource"
DEFAULT_MAX_FETCH = 5000
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# jsonData is free-form per plugin, so it is kept as a JSON string rather than
# flattened into unpredictable columns. These keys inside it are worth lifting
# out because they describe how the connection authenticates.
JSON_DATA_KEYS_OF_INTEREST = (
    "authType",
    "httpMethod",
    "sigV4Auth",
    "oauthPassThru",
    "tlsSkipVerify",
    "tlsAuth",
    "tlsAuthWithCACert",
)


class Client(BaseClient):
    """Bearer-auth HTTP client for the Grafana instance API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_datasources(self) -> list:
        """Fetch every data source.

        Requested once: the endpoint accepts pagination parameters and ignores
        them, returning the whole list regardless.
        """
        return self._http_request(method="GET", url_suffix="/api/datasources")


def _now_rfc3339() -> str:
    now = arg_to_datetime("now", required=True)
    assert now is not None  # for type-checkers; arg_to_datetime raises otherwise
    return now.strftime(DATE_FORMAT)


def summarise_json_data(json_data: Any) -> dict:
    """Lift the authentication-relevant keys out of the free-form jsonData blob."""
    summary: dict[str, Any] = {"json_data": None}
    if not isinstance(json_data, dict) or not json_data:
        return summary

    summary["json_data"] = json.dumps(json_data)
    for key in JSON_DATA_KEYS_OF_INTEREST:
        if key in json_data:
            value = json_data[key]
            if not isinstance(value, dict | list):
                summary[f"json_{key}"] = value
    return summary


def build_event(datasource: dict, instance_url: str, now: str) -> dict:
    """Build one snapshot event for a data source."""
    event: dict[str, Any] = {}

    for key, value in datasource.items():
        if key == "jsonData":
            continue
        if not isinstance(value, dict | list):
            event[key] = value

    event.update(summarise_json_data(datasource.get("jsonData")))

    # A data source with a URL points somewhere. Recording whether it does at
    # all keeps a correlation from having to test for an empty string.
    event["has_url"] = bool(datasource.get("url"))

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["grafana_instance"] = instance_url
    return event


def fetch_datasources(client: Client, max_fetch: int) -> list[dict]:
    """Collect the data source snapshot. A single request, never paged."""
    datasources = client.list_datasources() or []
    if not isinstance(datasources, list):
        datasources = []

    now = _now_rfc3339()
    instance_url = client._base_url  # noqa: SLF001 - the configured instance identifies the tenant
    events = [build_event(ds, instance_url, now) for ds in datasources[:max_fetch] if isinstance(ds, dict) and ds.get("uid")]
    demisto.debug(f"Grafana: fetched {len(events)} data sources")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client) -> str:
    """Validate connectivity and token scope with a minimal request."""
    try:
        client.list_datasources()
    except DemistoException as e:
        message = str(e)
        if any(token in message for token in ("[401]", "[403]", "Unauthorized", "accessErrorId")):
            raise DemistoException(
                "Authorisation failed. The Grafana service account token needs the Admin role, or a "
                "role carrying the 'datasources:read' permission, in the organisation being "
                f"collected. Original error: {message}"
            )
        raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the data source inventory."""
    limit = arg_to_number(args.get("limit")) or 50
    events = fetch_datasources(client, limit)
    human_readable = tableToMarkdown(
        "Grafana Data Sources",
        events,
        headers=["name", "type", "access", "url", "basicAuth", "user", "readOnly", "isDefault"],
        removeNull=True,
    )
    return events, CommandResults(readable_output=human_readable, raw_response=events)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = (params.get("url") or "").rstrip("/")
    api_token = (params.get("credentials") or {}).get("password", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not base_url:
            raise DemistoException("The Grafana instance URL must be configured, for example https://your-stack.grafana.net")

        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "grafana-datasources-get-events":
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_datasources(client, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_snapshot": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
