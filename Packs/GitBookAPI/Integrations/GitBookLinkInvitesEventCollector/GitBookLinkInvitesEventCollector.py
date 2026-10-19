# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GitBook Link Invites Event Collector for Cortex XSIAM.

Collects the organisation link invites and ingests them into the
``gitbook_invites_raw`` dataset.

    GET /v1/orgs/{organizationId}/link-invites

A link invite is a standing URL that grants entry to the organisation. Anyone
holding it can join, it names no recipient, and it keeps working until somebody
revokes it. That makes it a live access path rather than a historical record,
which is why an inventory of the ones that exist is worth holding: each row is a
door that is currently open, and the role or level it carries decides how far
whoever walks through it can reach.

The GitBook API exposes NO audit log, so there is no event stream of who did
what. This is therefore a SNAPSHOT collector: it re-sends the full inventory
every run, and duplicate rows across runs are correct, because comparing
successive snapshots is the only way a change becomes visible.

Pagination is an OPAQUE CURSOR. The ``page`` parameter is a string identifier
returned by the previous response, not an offset, so a page loop must follow
``next.page`` and must never construct a page value of its own. The loop also
stops if the API returns a cursor it has already been given, because a cursor
that does not advance would otherwise re-request the same page indefinitely.

The API models an invite link as a union of three shapes: one to the
organisation, which carries ``role``, and one each to a space and to a
collection, which carry ``level`` and a nested target object. All three are
handled, so an organisation that uses only the narrower forms is still
collected.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

VENDOR = "gitbook"
# Product string drives the dataset name: gitbook_invites_raw.
PRODUCT = "invites"
SOURCE_LOG_TYPE = "link_invite"
DEFAULT_BASE_URL = "https://api.gitbook.com"
DEFAULT_MAX_FETCH = 5000
PAGE_SIZE = 100
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Client(BaseClient):
    """Bearer-auth HTTP client for the GitBook API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_link_invites(self, organization_id: str, max_fetch: int) -> list:
        """Fetch every link invite in the organisation, following the cursor.

        Returns the accumulated items. The caller decides what to do with an
        empty list; an organisation with no standing invites is a valid answer,
        and arguably the desirable one.
        """
        invites: list = []
        seen_cursors: set[str] = set()
        page: str | None = None

        while True:
            params: dict[str, Any] = {"limit": PAGE_SIZE}
            if page:
                params["page"] = page

            response = self._http_request(
                method="GET",
                url_suffix=f"/v1/orgs/{organization_id}/link-invites",
                params=params,
            )
            if not isinstance(response, dict):
                break

            items = response.get("items") or []
            if not isinstance(items, list):
                break
            invites.extend(items)

            if len(invites) >= max_fetch:
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

        return invites[:max_fetch]

    def get_organization(self, organization_id: str) -> dict:
        """Fetch the organisation, used to confirm the token can reach it."""
        response = self._http_request(method="GET", url_suffix=f"/v1/orgs/{organization_id}")
        return response if isinstance(response, dict) else {}


def _now_rfc3339() -> str:
    now = arg_to_datetime("now", required=True)
    assert now is not None  # for type-checkers; arg_to_datetime raises otherwise
    return now.strftime(DATE_FORMAT)


def build_event(invite: dict, organization_id: str, now: str) -> dict:
    """Build one snapshot event for a link invite.

    The nested ``space`` and ``collection`` objects are flattened into columns
    rather than kept as blobs, because a detection needs to filter on the target
    of an invite and a JSON string cannot be filtered without parsing it first.
    """
    event: dict[str, Any] = {}

    for key, value in invite.items():
        if key in ("space", "collection"):
            continue
        if not isinstance(value, dict | list):
            event[key] = value

    space = invite.get("space")
    if isinstance(space, dict):
        for key in ("id", "title", "visibility"):
            value = space.get(key)
            if not isinstance(value, dict | list):
                event[f"space_{key}"] = value

    collection = invite.get("collection")
    if isinstance(collection, dict):
        for key in ("id", "title"):
            value = collection.get(key)
            if not isinstance(value, dict | list):
                event[f"collection_{key}"] = value

    # An open URL that hands out an administrative role is a different problem
    # from one that hands out read access, so the distinction is resolved once
    # here rather than in every rule.
    role = str(invite.get("role") or "").lower()
    event["is_privileged_role"] = role in ("admin", "owner")

    # Which of the three invite shapes this record is. The values are the API's
    # own object names, so a rule filters on the same vocabulary as the API.
    if isinstance(space, dict):
        event["invite_target"] = "space"
    elif isinstance(collection, dict):
        event["invite_target"] = "collection"
    else:
        event["invite_target"] = "organization"

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["organization_id"] = organization_id
    return event


def fetch_link_invites(client: Client, organization_id: str, max_fetch: int) -> list[dict]:
    """Collect the link invite snapshot."""
    invites = client.list_link_invites(organization_id, max_fetch) or []
    now = _now_rfc3339()
    events = [build_event(i, organization_id, now) for i in invites if isinstance(i, dict) and i.get("id")]
    demisto.debug(f"GitBook: fetched {len(events)} link invites")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, organization_id: str) -> str:
    """Validate connectivity, token scope and the organisation identifier."""
    try:
        client.list_link_invites(organization_id, 1)
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
                "link invites. The token owner needs an administrator role in the "
                f"organisation. Original error: {message}"
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
    """Manual command to preview (and optionally push) the link invites."""
    limit = arg_to_number(args.get("limit")) or 50
    events = fetch_link_invites(client, organization_id, limit)
    human_readable = tableToMarkdown(
        "GitBook Link Invites",
        events,
        headers=[
            "id",
            "invite_target",
            "role",
            "level",
            "is_privileged_role",
            "redundant",
            "space_id",
            "space_title",
            "space_visibility",
            "collection_id",
            "collection_title",
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

        elif command == "gitbook-get-link-invites":
            events, results = get_events_command(client, organization_id, args)
            if argToBoolean(args.get("should_push_events", "false")):
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_link_invites(client, organization_id, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_fetch": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
