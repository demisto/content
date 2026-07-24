# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CircleCI Project Settings Event Collector for Cortex XSIAM.

Collects the advanced project-settings posture from the CircleCI v2 API
(GET /project/{provider}/{organization}/{project}/settings) and ingests it into
the ``circleci_project_settings_raw`` dataset. The advanced settings include the
Poisoned Pipeline Execution preconditions: ``forks_receive_secret_env_vars``
(forked pull requests receive the project's secrets) and ``build_fork_prs``
(forked pull requests can trigger builds), plus ``disable_ssh``, ``oss`` and
``write_settings_requires_admin``.

Settings are current configuration (a posture snapshot), so each run sends the
full snapshot for every covered project. The ``advanced`` object is flattened
to top-level boolean columns so downstream posture correlations can filter on a
single dangerous setting.

Projects can be configured explicitly (project slugs) and/or auto-discovered
from an organisation slug: the collector walks recent pipeline activity
(GET /pipeline?org-slug=...) and collects settings for every distinct
project_slug found. The settings endpoint splits the slug into its provider,
organisation and project segments. Discovery only sees projects with pipeline
activity; configure explicit project slugs for dormant projects.
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
# Product string drives the dataset name: circleci_project_settings_raw.
PRODUCT = "project_settings"
SOURCE_LOG_TYPE = "project_settings"
DEFAULT_BASE_URL = "https://circleci.com/api/v2"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50
DISCOVERY_MAX_PAGES = 5


class Client(BaseClient):
    """HTTP client for the CircleCI v2 API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {"Circle-Token": api_token, "Content-Type": "application/json"}
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_project_settings(self, project_slug: str) -> dict:
        """Fetch the advanced settings for a project.

        The endpoint splits the slug into provider / organisation / project.
        """
        provider, organization, project = project_slug.split("/", 2)
        org = urllib.parse.quote(organization, safe="")
        proj = urllib.parse.quote(project, safe="")
        return self._http_request(
            method="GET", url_suffix=f"/project/{provider}/{org}/{proj}/settings"
        )

    def list_pipelines(self, org_slug: str, page_token: Optional[str] = None) -> dict:
        """Fetch a single page of pipelines for an organisation (used for project discovery)."""
        params: dict[str, Any] = {"org-slug": org_slug}
        if page_token:
            params["page-token"] = page_token
        return self._http_request(method="GET", url_suffix="/pipeline", params=params)


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def discover_project_slugs(client: Client, org_slugs: list[str]) -> list[str]:
    """Discover project slugs from recent pipeline activity across organisations."""
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
        discovered.extend(sorted(slugs))
        demisto.debug(f"CircleCI: discovered {len(slugs)} project slugs for org {org_slug}")
    return discovered


def resolve_project_slugs(client: Client, project_slugs: list[str], org_slugs: list[str]) -> list[str]:
    """Union of explicitly configured project slugs and auto-discovered ones."""
    resolved = list(project_slugs)
    for slug in discover_project_slugs(client, org_slugs) if org_slugs else []:
        if slug not in resolved:
            resolved.append(slug)
    return resolved


def build_settings_event(project_slug: str, settings: dict, now: str) -> dict:
    """Flatten the advanced settings object to top-level boolean columns."""
    advanced = settings.get("advanced") or {}
    event: dict[str, Any] = {}
    for key, value in advanced.items():
        # Skip nested/array settings; keep the scalar posture flags.
        if isinstance(value, (bool, str, int, float)) or value is None:
            event[key] = value
    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["circleci_project_slug"] = project_slug
    return event


def fetch_events(client: Client, project_slugs: list[str], max_fetch: int) -> list[dict]:
    """Fetch the current settings snapshot for each covered project."""
    all_events: list[dict] = []
    now = _now_rfc3339()
    for project_slug in project_slugs:
        if len(all_events) >= max_fetch:
            break
        try:
            settings = client.get_project_settings(project_slug)
        except DemistoException as e:
            demisto.debug(f"CircleCI: could not fetch settings for {project_slug}: {e}")
            continue
        all_events.append(build_settings_event(project_slug, settings, now))
        demisto.debug(f"CircleCI: fetched settings for project {project_slug}")
    return all_events[:max_fetch]


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, project_slugs: list[str], org_slugs: list[str]) -> str:
    """Validate connectivity and token access for the configured scope."""
    for org_slug in org_slugs:
        try:
            client.list_pipelines(org_slug=org_slug)
        except DemistoException as e:
            message = str(e)
            if any(t in message for t in ("[401]", "[403]", "[404]", "Authentication error")):
                raise DemistoException(
                    f"Authorisation failed for organisation '{org_slug}'. Check that the CircleCI "
                    "personal API token is valid and that the org slug is correct (e.g. "
                    "'gh/MyOrg' or 'circleci/<org-id>'; list yours via the /me/collaborations "
                    f"endpoint). Original error: {message}"
                )
            raise
    for project_slug in project_slugs:
        try:
            client.get_project_settings(project_slug)
        except DemistoException as e:
            message = str(e)
            if any(t in message for t in ("[401]", "[403]", "[404]", "Authentication error")):
                raise DemistoException(
                    f"Authorisation failed for project '{project_slug}'. Check that the CircleCI "
                    "personal API token is valid and that the project slug is correct "
                    f"(e.g. 'gh/MyOrg/my-repo'). Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the project-settings posture."""
    project_slugs = argToList(args.get("project_slugs"))
    org_slugs = argToList(args.get("org_slugs"))
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    events = fetch_events(client, resolve_project_slugs(client, project_slugs, org_slugs), limit)
    human_readable = tableToMarkdown(
        "CircleCI Project Settings",
        events,
        headers=["circleci_project_slug", "build_fork_prs", "forks_receive_secret_env_vars",
                 "disable_ssh", "oss", "write_settings_requires_admin"],
        removeNull=True,
    )
    return events, CommandResults(readable_output=human_readable, raw_response=events)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_token = (params.get("credentials") or {}).get("password", "")
    project_slugs = argToList(params.get("project_slugs"))
    org_slugs = argToList(params.get("org_slugs"))
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not project_slugs and not org_slugs:
            raise DemistoException(
                "Configure at least one CircleCI project slug, or an organisation slug "
                "for automatic project discovery."
            )
        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, project_slugs, org_slugs))
        elif command == "circleci-project-settings-get-events":
            args.setdefault("project_slugs", params.get("project_slugs"))
            args.setdefault("org_slugs", params.get("org_slugs"))
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)
        elif command == "fetch-events":
            all_slugs = resolve_project_slugs(client, project_slugs, org_slugs)
            events = fetch_events(client, all_slugs, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_snapshot": _now_rfc3339()})
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
