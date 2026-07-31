# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Grafana Organisation Users Event Collector for Cortex XSIAM.

Collects the organisation's human user inventory from a Grafana instance and
ingests it into the ``grafana_org_users_raw`` dataset.

This is the identity half of the picture the service account collector covers
for machines. It answers who can sign in to this Grafana, at what role, whether
their identity comes from an external provider, and when they were last seen.
``lastSeenAt`` is what makes a dormant privileged account visible.

    GET /api/org/users

This endpoint IGNORES pagination and returns the whole membership in a single
request, so it is never paged. Note that the instance it was characterised
against had one member, so the inference rests on page 2 returning that same
record rather than nothing. It is worth re-checking on a larger organisation.

The wider `/api/users` endpoint covers every user across all organisations, but
it needs the `users:read` permission which a normal Admin service account does
not hold, so this collector deliberately reads the organisation-scoped endpoint
that an Admin token can reach.

There is no event stream here, only current state, so this is a SNAPSHOT
collector: it re-sends the full membership every run. Duplicate rows across runs
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
# Product string drives the dataset name: grafana_org_users_raw.
PRODUCT = "org_users"
SOURCE_LOG_TYPE = "org_user"
DEFAULT_MAX_FETCH = 5000
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Client(BaseClient):
    """Bearer-auth HTTP client for the Grafana instance API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_org_users(self) -> list:
        """Fetch every user in the token's organisation.

        Requested once: the endpoint accepts pagination parameters and ignores
        them, returning the whole membership regardless.
        """
        return self._http_request(method="GET", url_suffix="/api/org/users")


def _now_rfc3339() -> str:
    now = arg_to_datetime("now", required=True)
    assert now is not None  # for type-checkers; arg_to_datetime raises otherwise
    return now.strftime(DATE_FORMAT)


def build_event(user: dict, instance_url: str, now: str) -> dict:
    """Build one snapshot event for an organisation member."""
    event: dict[str, Any] = {}

    for key, value in user.items():
        if key == "authLabels":
            continue
        if not isinstance(value, dict | list):
            event[key] = value

    # authLabels names the identity provider or providers behind the account.
    # Flattened so a correlation can filter on it without parsing.
    labels = user.get("authLabels") or []
    if isinstance(labels, list):
        event["auth_labels"] = "|".join(sorted(str(x) for x in labels if x))
        event["auth_label_count"] = len(labels)
    else:
        event["auth_labels"] = ""
        event["auth_label_count"] = 0

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["grafana_instance"] = instance_url
    return event


def fetch_org_users(client: Client, max_fetch: int) -> list[dict]:
    """Collect the organisation membership snapshot. A single request, never paged."""
    users = client.list_org_users() or []
    if not isinstance(users, list):
        users = []

    now = _now_rfc3339()
    instance_url = client._base_url  # noqa: SLF001 - the configured instance identifies the tenant
    events = [
        build_event(u, instance_url, now)
        for u in users[:max_fetch]
        if isinstance(u, dict) and u.get("userId") is not None
    ]
    demisto.debug(f"Grafana: fetched {len(events)} organisation users")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client) -> str:
    """Validate connectivity and token scope with a minimal request."""
    try:
        client.list_org_users()
    except DemistoException as e:
        message = str(e)
        if any(token in message for token in ("[401]", "[403]", "Unauthorized", "accessErrorId")):
            raise DemistoException(
                "Authorisation failed. The Grafana service account token needs the Admin role, or a "
                "role carrying the 'org.users:read' permission, in the organisation being collected. "
                f"Original error: {message}"
            )
        raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the organisation membership."""
    limit = arg_to_number(args.get("limit")) or 50
    events = fetch_org_users(client, limit)
    human_readable = tableToMarkdown(
        "Grafana Organisation Users",
        events,
        headers=["login", "email", "role", "isDisabled", "auth_labels", "lastSeenAt", "created"],
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

        elif command == "grafana-org-users-get-events":
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_org_users(client, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_snapshot": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
