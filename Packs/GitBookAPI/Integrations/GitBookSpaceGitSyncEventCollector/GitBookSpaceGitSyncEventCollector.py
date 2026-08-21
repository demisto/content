# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GitBook Space Git Sync Event Collector for the Cortex Platform.

Collects the git sync configuration of every space in the organisation and
ingests it into the ``gitbook_git_sync_raw`` dataset.

    GET /v1/orgs/{organizationId}/spaces    the spaces, cursor paged
    GET /v1/spaces/{spaceId}/git/info       the git sync of one space

Git sync connects a space to an external repository, so it is both an egress
and an ingress path for content. Content can leave the platform into a
repository, and content can be pushed into published documentation from one.
Which spaces are wired to which repository, on which branch and in which
direction, is therefore what this collector exists to answer.

There is no list endpoint for git installations, ``/git/installations`` accepts
POST only, so the per space route is the only enumerable path and the collector
issues one request per space.

A space with no git sync configured answers 404 on ``git/info``. That is an
answer rather than a failure, so it becomes a record carrying
``git_sync_configured`` false. Every other status still raises, because a
failure that is quietly turned into a record would read as an all clear.

The GitBook API exposes NO audit log, so there is no event stream of who
changed a configuration. This is therefore a SNAPSHOT collector: it re-sends the
full inventory every run, and duplicate rows across runs are correct, because
comparing successive snapshots is the only way a change becomes visible.

Pagination is an OPAQUE CURSOR. The ``page`` parameter is a string identifier
returned by the previous response, not an offset, so a page loop must follow
``next.page`` and must never construct a page value of its own. The loop also
stops if the API returns a cursor it has already been given, because a cursor
that does not advance would otherwise re-request the same page indefinitely.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

VENDOR = "gitbook"
# Product string drives the dataset name: gitbook_git_sync_raw.
PRODUCT = "git_sync"
SOURCE_LOG_TYPE = "git_sync"
DEFAULT_BASE_URL = "https://api.gitbook.com"
DEFAULT_MAX_FETCH = 5000
PAGE_SIZE = 100
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# The repository IDENTITY is what a detection needs, because a space synced to a
# repository outside the organisation's own namespace is a content egress path
# while a space synced inside it is ordinary docs-as-code. GET /spaces/{id}/git/info
# returns repoName, url, installationProvider, integration, installationId,
# parentInstallationId, state and updatedAt, each of which the generic capture
# below lifts into a git_ prefixed column. There is no branch or sync-direction
# field in that response, so no column is invented for one.
GIT_IDENTITY_FIELDS = ("repoName", "url", "installationProvider")


class Client(BaseClient):
    """Bearer-auth HTTP client for the GitBook API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_spaces(self, organization_id: str, max_fetch: int) -> list:
        """Fetch every space in the organisation, following the cursor.

        Returns the accumulated items. The caller decides what to do with an
        empty list; an organisation with no spaces is a valid answer.
        """
        spaces: list = []
        seen_cursors: set[str] = set()
        page: str | None = None

        while True:
            params: dict[str, Any] = {"limit": PAGE_SIZE}
            if page:
                params["page"] = page

            response = self._http_request(
                method="GET",
                url_suffix=f"/v1/orgs/{organization_id}/spaces",
                params=params,
            )
            if not isinstance(response, dict):
                break

            items = response.get("items") or []
            if not isinstance(items, list):
                break
            spaces.extend(items)

            if len(spaces) >= max_fetch:
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

        return spaces[:max_fetch]

    def get_git_info(self, space_id: str) -> dict | None:
        """Fetch the git sync configuration of one space.

        Returns None when the space has no git sync configured.
        """
        try:
            response = self._http_request(
                method="GET",
                url_suffix=f"/v1/spaces/{space_id}/git/info",
            )
        except DemistoException as e:
            # 404 is the API saying this space has no git sync, which is the
            # answer. Any other status is a failure and must still raise.
            if _is_not_found(e):
                demisto.debug(f"GitBook: space {space_id} has no git sync configured")
                return None
            raise
        return response if isinstance(response, dict) else None


def _is_not_found(error: DemistoException) -> bool:
    """True when the API answered 404, whether or not a response is attached."""
    status = getattr(getattr(error, "res", None), "status_code", None)
    return status == 404 or "[404]" in str(error)


def _now_rfc3339() -> str:
    now = arg_to_datetime("now", required=True)
    assert now is not None  # for type-checkers; arg_to_datetime raises otherwise
    return now.strftime(DATE_FORMAT)


def build_event(space: dict, git_info: dict | None, organization_id: str, now: str) -> dict:
    """Build one snapshot event for a space and its git sync configuration.

    The record joins two objects, so space fields carry a ``space_`` prefix and
    git fields a ``git_`` prefix; without them the two ``url`` keys would
    collide. Nested objects are flattened into columns rather than kept as a
    blob, because a JSON string cannot be filtered without parsing it first.
    """
    event: dict[str, Any] = {}

    for key, value in space.items():
        if not isinstance(value, dict | list):
            event[f"space_{key}"] = value

    if isinstance(git_info, dict):
        for key, value in git_info.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if not isinstance(sub_value, dict | list):
                        event[f"git_{key}_{sub_key}"] = sub_value
            elif not isinstance(value, list):
                event[f"git_{key}"] = value

        # A single flag a rule can filter on without knowing which identity field
        # the provider populated. Its absence means sync is configured but the
        # repository cannot be named, which is a different finding from no sync.
        event["git_repository_named"] = any(isinstance(git_info.get(f), str) and git_info.get(f) for f in GIT_IDENTITY_FIELDS)

    # Written last so no collected field can overwrite it; the flag is what a
    # rule reads to see a space stop syncing.
    event["git_sync_configured"] = isinstance(git_info, dict)

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["organization_id"] = organization_id
    return event


def fetch_git_sync(client: Client, organization_id: str, max_fetch: int) -> list[dict]:
    """Collect the git sync snapshot, one record per space."""
    spaces = client.list_spaces(organization_id, max_fetch) or []
    now = _now_rfc3339()
    events = []
    for space in spaces:
        if not isinstance(space, dict) or not space.get("id"):
            continue
        # A space is reported whether or not it syncs, so that a space losing
        # its git sync is visible as a change rather than as a missing row.
        git_info = client.get_git_info(space["id"])
        events.append(build_event(space, git_info, organization_id, now))
    demisto.debug(f"GitBook: fetched the git sync state of {len(events)} spaces")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to the Cortex Platform. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, organization_id: str) -> str:
    """Validate connectivity, token scope and the organisation identifier."""
    try:
        client.list_spaces(organization_id, 1)
    except DemistoException as e:
        message = str(e)
        if any(token in message for token in ("[401]", "Unauthorized")):
            raise DemistoException(
                "Authorisation failed. Check the API token is a GitBook personal access "
                f"token and has not been revoked. Original error: {message}"
            )
        if any(token in message for token in ("[403]", "Forbidden")):
            raise DemistoException(
                "The token was accepted but is not permitted to read this organisation's "
                "spaces. The token owner needs an administrator role in the organisation. "
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
    """Manual command to preview (and optionally push) the git sync snapshot."""
    limit = arg_to_number(args.get("limit")) or 50
    events = fetch_git_sync(client, organization_id, limit)
    human_readable = tableToMarkdown(
        "GitBook Space Git Sync",
        events,
        headers=[
            "space_id",
            "space_title",
            "space_visibility",
            "git_sync_configured",
            "git_repoName",
            "git_installationProvider",
            "git_repository_named",
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

        elif command == "gitbook-get-git-sync":
            events, results = get_events_command(client, organization_id, args)
            if argToBoolean(args.get("should_push_events", "false")):
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_git_sync(client, organization_id, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_fetch": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
