# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CircleCI Triggers Event Collector for Cortex XSIAM.

Collects the pipeline trigger inventory from the CircleCI v2 API
(GET /projects/{project_id}/pipeline-definitions, then
GET /projects/{project_id}/pipeline-definitions/{id}/triggers) and ingests it
into the ``circleci_triggers_raw`` dataset. Triggers are current
configuration (an inventory), so each run sends the full snapshot for every
covered project. The inventory covers both scheduled triggers
(event_source.provider = "schedule", with the cron expression and the
attribution actor) and VCS push triggers (provider = "github_app"), so
comparing snapshots over time detects any newly created trigger.

This is the scheduling surface used by GitHub App organisations. The legacy
scheduled-pipelines endpoint (GET /project/{project-slug}/schedule) is a
separate store used by classic OAuth organisations and is not collected here.

Projects can be configured explicitly (project IDs) and/or auto-discovered
from an organisation slug: the collector walks recent pipeline activity
(GET /pipeline?org-slug=...), resolves each distinct project_slug via
GET /project/{project-slug}, and collects triggers for every project found.
Discovery only sees projects with pipeline activity; configure explicit
project IDs for dormant projects.
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
import urllib.parse
from datetime import datetime, timezone
from typing import Any

urllib3.disable_warnings()

VENDOR = "circleci"
# Product string drives the dataset name: circleci_triggers_raw.
PRODUCT = "triggers"
SOURCE_LOG_TYPE = "trigger"
DEFAULT_BASE_URL = "https://circleci.com/api/v2"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50

# Pages of pipeline history walked per organisation when discovering projects.
DISCOVERY_MAX_PAGES = 5


class Client(BaseClient):
    """HTTP client for the CircleCI v2 API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Circle-Token": api_token,
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_pipeline_definitions(self, project_id: str, page_token: Optional[str] = None) -> dict:
        """Fetch a single page of pipeline definitions for a project."""
        params: dict[str, Any] = {}
        if page_token:
            params["page-token"] = page_token
        return self._http_request(
            method="GET", url_suffix=f"/projects/{project_id}/pipeline-definitions", params=params
        )

    def list_triggers(self, project_id: str, definition_id: str, page_token: Optional[str] = None) -> dict:
        """Fetch a single page of triggers for a pipeline definition."""
        params: dict[str, Any] = {}
        if page_token:
            params["page-token"] = page_token
        return self._http_request(
            method="GET",
            url_suffix=f"/projects/{project_id}/pipeline-definitions/{definition_id}/triggers",
            params=params,
        )

    def list_pipelines(self, org_slug: str, page_token: Optional[str] = None) -> dict:
        """Fetch a single page of pipelines for an organisation (used for project discovery)."""
        params: dict[str, Any] = {"org-slug": org_slug}
        if page_token:
            params["page-token"] = page_token
        return self._http_request(method="GET", url_suffix="/pipeline", params=params)

    def get_project(self, project_slug: str) -> dict:
        """Fetch a project by slug (returns its UUID in ``id``)."""
        encoded = urllib.parse.quote(project_slug, safe="")
        return self._http_request(method="GET", url_suffix=f"/project/{encoded}")


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def discover_project_ids(
    client: Client,
    org_slugs: list[str],
    slug_cache: dict,
) -> tuple[list[str], dict]:
    """Discover project IDs from recent pipeline activity across organisations.

    Walks up to ``DISCOVERY_MAX_PAGES`` pages of pipelines per organisation,
    collects distinct ``project_slug`` values, and resolves each to its project
    UUID via GET /project/{slug}. Resolutions are cached in ``slug_cache``
    (persisted in lastRun) so each slug is only resolved once.
    """
    discovered: list[str] = []
    for org_slug in org_slugs:
        slugs: set = set()
        page_token: Optional[str] = None
        for _ in range(DISCOVERY_MAX_PAGES):
            response = client.list_pipelines(org_slug=org_slug, page_token=page_token)
            for item in response.get("items") or []:
                slug = item.get("project_slug")
                if slug:
                    slugs.add(slug)
            page_token = response.get("next_page_token")
            if not page_token:
                break
        for slug in sorted(slugs):
            project_id = slug_cache.get(slug)
            if not project_id:
                try:
                    project_id = client.get_project(slug).get("id")
                except DemistoException as e:
                    demisto.debug(f"CircleCI: could not resolve project {slug}: {e}")
                    continue
                if project_id:
                    slug_cache[slug] = project_id
            if project_id:
                discovered.append(project_id)
        demisto.debug(f"CircleCI: discovered {len(slugs)} project slugs for org {org_slug}")
    return discovered, slug_cache


def resolve_project_ids(
    client: Client,
    project_ids: list[str],
    org_slugs: list[str],
    slug_cache: dict,
) -> tuple[list[str], dict]:
    """Union of explicitly configured project IDs and auto-discovered ones."""
    resolved = list(project_ids)
    if org_slugs:
        discovered, slug_cache = discover_project_ids(client, org_slugs, slug_cache)
        for project_id in discovered:
            if project_id not in resolved:
                resolved.append(project_id)
    return resolved, slug_cache


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


def fetch_triggers_for_project(client: Client, project_id: str, max_fetch: int) -> list[dict]:
    """Collect the full trigger inventory for one project across its pipeline definitions."""
    collected: list[dict] = []
    definitions = _paginate(
        lambda token: client.list_pipeline_definitions(project_id, token), max_fetch
    )
    for definition in definitions:
        definition_id = definition.get("id")
        if not definition_id:
            continue
        triggers = _paginate(
            lambda token: client.list_triggers(project_id, definition_id, token),
            max_fetch - len(collected),
        )
        for trigger in triggers:
            trigger["pipeline_definition_id"] = definition_id
            trigger["pipeline_definition_name"] = definition.get("name")
        collected.extend(triggers)
        if len(collected) >= max_fetch:
            break
    return collected[:max_fetch]


def fetch_events(client: Client, project_ids: list[str], max_fetch: int) -> list[dict]:
    """Fetch the current trigger snapshot for each covered project."""
    all_events: list[dict] = []
    now = _now_rfc3339()

    for project_id in project_ids:
        triggers = fetch_triggers_for_project(client, project_id, max_fetch)
        for trigger in triggers:
            trigger["_time"] = now
            trigger["source_log_type"] = SOURCE_LOG_TYPE
            trigger["circleci_project_id"] = project_id
            trigger["snapshot_at"] = now
        all_events.extend(triggers)
        demisto.debug(f"CircleCI: fetched {len(triggers)} triggers for project {project_id}")

    return all_events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, project_ids: list[str], org_slugs: list[str]) -> str:
    """Validate connectivity and token access for the configured scope."""
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
    for project_id in project_ids:
        try:
            client.list_pipeline_definitions(project_id)
        except DemistoException as e:
            message = str(e)
            if any(token in message for token in ("[401]", "[403]", "[404]", "Authentication error")):
                raise DemistoException(
                    f"Authorisation failed for project '{project_id}'. Check that the CircleCI "
                    "personal API token is valid and that the project ID is correct. It is the "
                    "project UUID shown by GET /project/{project-slug}, not the project slug. "
                    f"Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the trigger inventory."""
    project_ids = argToList(args.get("project_ids"))
    org_slugs = argToList(args.get("org_slugs"))
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    project_ids, _ = resolve_project_ids(client, project_ids, org_slugs, {})
    events = fetch_events(client, project_ids, limit)

    human_readable = tableToMarkdown(
        "CircleCI Triggers",
        events,
        headers=["id", "event_name", "description", "circleci_project_id", "created_at"],
        removeNull=True,
    )
    return events, CommandResults(readable_output=human_readable, raw_response=events)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_token = (params.get("credentials") or {}).get("password", "")
    project_ids = argToList(params.get("project_ids"))
    org_slugs = argToList(params.get("org_slugs"))
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not project_ids and not org_slugs:
            raise DemistoException(
                "Configure at least one CircleCI project ID, or an organisation slug "
                "for automatic project discovery."
            )

        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, project_ids, org_slugs))

        elif command == "circleci-triggers-get-events":
            args.setdefault("project_ids", params.get("project_ids"))
            args.setdefault("org_slugs", params.get("org_slugs"))
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            slug_cache = last_run.get("project_slug_cache", {})
            all_project_ids, slug_cache = resolve_project_ids(
                client, project_ids, org_slugs, slug_cache
            )
            events = fetch_events(client, all_project_ids, max_fetch)
            push_events(events)
            demisto.setLastRun(
                {"last_snapshot": _now_rfc3339(), "project_slug_cache": slug_cache}
            )

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
