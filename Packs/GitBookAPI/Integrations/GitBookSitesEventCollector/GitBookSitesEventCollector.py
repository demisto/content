# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GitBook Sites Event Collector for Cortex XSIAM.

Collects the organisation site inventory and ingests it into the
``gitbook_sites_raw`` dataset.

    GET /v1/orgs/{organizationId}/sites

A site is the public face of documentation. Its visibility and its published
state decide whether internal material is reachable from the internet, which
makes the site inventory the public exposure surface of the organisation. The
two are not the same thing: a site can be public in configuration and not yet be
published, so each is carried as its own column.

The GitBook API exposes NO audit log, so there is no event stream of who changed
a site. This is therefore a SNAPSHOT collector: it re-sends the full inventory
every run, and duplicate rows across runs are correct, because comparing
successive snapshots is the only way a change becomes visible.

Pagination is an OPAQUE CURSOR. The ``page`` parameter is a string identifier
returned by the previous response, not an offset, so a page loop must follow
``next.page`` and must never construct a page value of its own. The loop also
stops if the API returns a cursor it has already been given, because a cursor
that does not advance would otherwise re-request the same page indefinitely.

Every column is a scalar. The permissions object is flattened into one boolean
column per permission and the application URL is lifted out of the urls object,
because a value a rule has to parse first is a value a rule cannot filter on.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

VENDOR = "gitbook"
# Product string drives the dataset name: gitbook_sites_raw.
PRODUCT = "sites"
SOURCE_LOG_TYPE = "site"
DEFAULT_BASE_URL = "https://api.gitbook.com"
DEFAULT_MAX_FETCH = 5000
PAGE_SIZE = 100
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Nested keys handled explicitly below, or dropped because a list cannot be
# a column. Everything else is copied across as it arrives.
NESTED_KEYS = ("permissions", "urls", "features")


class Client(BaseClient):
    """Bearer-auth HTTP client for the GitBook API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_sites(self, organization_id: str, max_fetch: int) -> list:
        """Fetch every site in the organisation, following the cursor.

        Returns the accumulated items. The caller decides what to do with an
        empty list; an organisation that publishes no sites is a valid answer.
        """
        sites: list = []
        seen_cursors: set[str] = set()
        page: str | None = None

        while True:
            params: dict[str, Any] = {"limit": PAGE_SIZE}
            if page:
                params["page"] = page

            response = self._http_request(
                method="GET",
                url_suffix=f"/v1/orgs/{organization_id}/sites",
                params=params,
            )
            if not isinstance(response, dict):
                break

            items = response.get("items") or []
            if not isinstance(items, list):
                break
            sites.extend(items)

            if len(sites) >= max_fetch:
                demisto.debug(f"GitBook: reached max fetch of {max_fetch}, stopping pagination")
                break

            next_block = response.get("next")
            next_page = next_block.get("page") if isinstance(next_block, dict) else None
            if not next_page:
                break

            # A cursor the API has already issued means it is not advancing.
            # Continuing would re-request the same page for as long as the
            # instance runs, so stop and keep what has been collected.
            if next_page in seen_cursors:
                demisto.debug("GitBook: pagination cursor repeated, stopping to avoid a loop")
                break
            seen_cursors.add(next_page)
            page = next_page

        return sites[:max_fetch]

    def get_organization(self, organization_id: str) -> dict:
        """Fetch the organisation, used to confirm the token can reach it."""
        response = self._http_request(method="GET", url_suffix=f"/v1/orgs/{organization_id}")
        return response if isinstance(response, dict) else {}


def _now_rfc3339() -> str:
    now = arg_to_datetime("now", required=True)
    assert now is not None  # for type-checkers; arg_to_datetime raises otherwise
    return now.strftime(DATE_FORMAT)


def build_event(site: dict, organization_id: str, now: str) -> dict:
    """Build one snapshot event for a site.

    The nested ``permissions`` object becomes one boolean column per permission,
    because who may view or administer a public site is what a detection filters
    on. The ``features`` list is dropped and only the application URL is lifted
    out of ``urls``, since a column has to hold a scalar to be queryable.
    """
    event: dict[str, Any] = {}

    for key, value in site.items():
        if key in NESTED_KEYS:
            continue
        if not isinstance(value, dict | list):
            event[key] = value

    permissions = site.get("permissions")
    if isinstance(permissions, dict):
        for key, value in permissions.items():
            if not isinstance(value, dict | list):
                event[f"permission_{key}"] = bool(value)

    urls = site.get("urls")
    if isinstance(urls, dict):
        app_url = urls.get("app")
        if not isinstance(app_url, dict | list):
            event["urls_app"] = app_url

    # Visibility is the setting that exposes a site to the internet, so it is
    # resolved once here rather than in every rule. ``published`` stays a column
    # of its own, because a site can be public in configuration and unpublished.
    event["is_publicly_visible"] = str(site.get("visibility") or "").lower() == "public"

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["organization_id"] = organization_id
    return event


def fetch_sites(client: Client, organization_id: str, max_fetch: int) -> list[dict]:
    """Collect the site inventory snapshot."""
    sites = client.list_sites(organization_id, max_fetch) or []
    now = _now_rfc3339()
    events = [build_event(s, organization_id, now) for s in sites if isinstance(s, dict) and s.get("id")]
    demisto.debug(f"GitBook: fetched {len(events)} sites")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, organization_id: str) -> str:
    """Validate connectivity, token scope and the organisation identifier."""
    try:
        client.list_sites(organization_id, 1)
    except DemistoException as e:
        message = str(e)
        if any(token in message for token in ("[401]", "Unauthorized")):
            raise DemistoException(
                "Authorisation failed. Check the API token is a GitBook personal access "
                f"token and has not been revoked. Original error: {message}"
            )
        if any(token in message for token in ("[403]", "Forbidden")):
            raise DemistoException(
                "The token was accepted but is not permitted to list this organisation's "
                "sites. The token owner needs an administrator role in the organisation. "
                f"Original error: {message}"
            )
        if "[404]" in message:
            raise DemistoException(
                f"Organisation '{organization_id}' was not found. Take the identifier from "
                "the GitBook application URL, which has the form /o/<organizationId>/, or "
                f"from GET /v1/orgs. Original error: {message}"
            )
        raise
    return "ok"


def get_events_command(client: Client, organization_id: str, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the site inventory."""
    limit = arg_to_number(args.get("limit")) or 50
    events = fetch_sites(client, organization_id, limit)
    human_readable = tableToMarkdown(
        "GitBook Sites",
        events,
        headers=[
            "title",
            "basename",
            "visibility",
            "is_publicly_visible",
            "published",
            "type",
            "siteSpaces",
            "createdAt",
            "urls_app",
        ],
        removeNull=True,
    )
    return events, CommandResults(readable_output=human_readable, raw_response=events)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_token = (params.get("credentials") or {}).get("password") or params.get("api_token") or ""
    organization_id = (params.get("organization_id") or "").strip()
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not api_token:
            raise DemistoException("An API token is required. Paste it into the Password field.")
        if not organization_id:
            raise DemistoException("An Organization ID is required. Take it from the GitBook application URL.")

        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, organization_id))

        elif command == "gitbook-get-sites":
            events, results = get_events_command(client, organization_id, args)
            if argToBoolean(args.get("should_push_events", "false")):
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_sites(client, organization_id, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_fetch": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
