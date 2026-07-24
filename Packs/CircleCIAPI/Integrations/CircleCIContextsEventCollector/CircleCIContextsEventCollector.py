# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CircleCI Contexts Event Collector for Cortex XSIAM.

Collects the shared-context and context environment-variable inventory from
the CircleCI v2 API (GET /context, then
GET /context/{context_id}/environment-variable) and ingests it into the
``circleci_context_envvars_raw`` dataset. Environment-variable values are
masked by the API, so this is a names-only inventory: it captures which secret
names exist in which context, not the secret values.

Contexts are the exact data class exfiltrated in the January 2023 CircleCI
incident, so tracking their inventory over time lets downstream correlations
detect a newly created context (credential staging) or a newly added secret
name (credential access), without ever handling the secret value.

Each context produces one record with source_log_type "context" and one record
per environment variable with source_log_type "context_envvar". Contexts are
owned by an organisation, so configuration takes organisation slugs directly;
no project discovery is required.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from datetime import datetime, UTC
from typing import Any

urllib3.disable_warnings()

VENDOR = "circleci"
# Product string drives the dataset name: circleci_context_envvars_raw.
PRODUCT = "context_envvars"
DEFAULT_BASE_URL = "https://circleci.com/api/v2"
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

    def list_contexts(self, owner_slug: str, page_token: Optional[str] = None) -> dict:
        """Fetch a single page of contexts for an organisation."""
        params: dict[str, Any] = {"owner-slug": owner_slug, "owner-type": "organization"}
        if page_token:
            params["page-token"] = page_token
        return self._http_request(method="GET", url_suffix="/context", params=params)

    def list_context_envvars(self, context_id: str, page_token: Optional[str] = None) -> dict:
        """Fetch a single page of environment-variable names for a context."""
        params: dict[str, Any] = {}
        if page_token:
            params["page-token"] = page_token
        return self._http_request(method="GET", url_suffix=f"/context/{context_id}/environment-variable", params=params)


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _paginate(fetch_page, max_fetch: int) -> list[dict]:
    """Collect items across pages until exhausted or ``max_fetch`` reached."""
    collected: list[dict] = []
    page_token: Optional[str] = None
    while len(collected) < max_fetch:
        response = fetch_page(page_token)
        items = response.get("items") or []
        if not items:
            break
        collected.extend(items)
        page_token = response.get("next_page_token")
        if not page_token:
            break
    return collected[:max_fetch]


def fetch_events_for_org(client: Client, owner_slug: str, max_fetch: int) -> list[dict]:
    """Collect contexts and their environment-variable names for one organisation."""
    events: list[dict] = []
    now = _now_rfc3339()
    contexts = _paginate(lambda token: client.list_contexts(owner_slug, token), max_fetch)

    for context in contexts:
        context_id = context.get("id")
        context_name = context.get("name")
        context_record = dict(context)
        context_record["_time"] = now
        context_record["snapshot_at"] = now
        context_record["source_log_type"] = "context"
        context_record["circleci_org_slug"] = owner_slug
        events.append(context_record)
        if len(events) >= max_fetch:
            break

        if not context_id:
            continue
        envvars = _paginate(
            lambda token, cid=context_id: client.list_context_envvars(cid, token),
            max_fetch - len(events),
        )
        for envvar in envvars:
            record = dict(envvar)
            record["_time"] = now
            record["snapshot_at"] = now
            record["source_log_type"] = "context_envvar"
            record["context_name"] = context_name
            record["circleci_org_slug"] = owner_slug
            events.append(record)
        if len(events) >= max_fetch:
            break

    return events[:max_fetch]


def fetch_events(client: Client, owner_slugs: list[str], max_fetch: int) -> list[dict]:
    """Fetch the context and env-var inventory for each configured organisation."""
    all_events: list[dict] = []
    for owner_slug in owner_slugs:
        events = fetch_events_for_org(client, owner_slug, max_fetch)
        all_events.extend(events)
        demisto.debug(f"CircleCI: fetched {len(events)} context records for org {owner_slug}")
    return all_events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, owner_slugs: list[str]) -> str:
    """Validate connectivity and token access with a minimal request per organisation."""
    for owner_slug in owner_slugs:
        try:
            client.list_contexts(owner_slug)
        except DemistoException as e:
            message = str(e)
            if any(token in message for token in ("[401]", "[403]", "[404]", "Authentication error")):
                raise DemistoException(
                    f"Authorisation failed for organisation '{owner_slug}'. Check that the CircleCI "
                    "personal API token is valid and that the organisation slug is correct (e.g. "
                    "'gh/MyOrg' or 'circleci/<org-id>'; list yours via the /me/collaborations "
                    f"endpoint). Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the context inventory."""
    owner_slugs = argToList(args["org_slugs"])
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    events = fetch_events(client, owner_slugs, limit)

    human_readable = tableToMarkdown(
        "CircleCI Contexts and Environment Variables",
        events,
        headers=["source_log_type", "name", "variable", "context_name", "circleci_org_slug", "created_at"],
        removeNull=True,
    )
    return events, CommandResults(readable_output=human_readable, raw_response=events)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_token = (params.get("credentials") or {}).get("password", "")
    owner_slugs = argToList(params.get("org_slugs"))
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not owner_slugs:
            raise DemistoException("At least one CircleCI organisation slug must be configured.")

        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, owner_slugs))

        elif command == "circleci-contexts-get-events":
            args.setdefault("org_slugs", params.get("org_slugs"))
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_events(client, owner_slugs, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_snapshot": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
