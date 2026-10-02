# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GitBook Organisation Members Event Collector for Cortex XSIAM.

Collects the organisation member roster and ingests it into the
``gitbook_members_raw`` dataset.

    GET /v1/orgs/{organizationId}/members

A member record is the whole access story for a person in GitBook. It carries
the role they hold, whether they arrived through single sign-on, whether the
account is disabled, when they joined and when they were last seen, and how many
spaces, sites and teams they can reach. That makes the roster the answer to the
questions this pack exists to ask: who administers the documentation, which of
those administrators authenticate with a password rather than through the
identity provider, and which privileged accounts nobody is using.

The GitBook API exposes NO audit log, so there is no event stream of who did
what. This is therefore a SNAPSHOT collector: it re-sends the full roster every
run, and duplicate rows across runs are correct, because comparing successive
snapshots is the only way a change becomes visible.

Pagination is an OPAQUE CURSOR. The ``page`` parameter is a string identifier
returned by the previous response, not an offset, so a page loop must follow
``next.page`` and must never construct a page value of its own. The loop also
stops if the API returns a cursor it has already been given, because a cursor
that does not advance would otherwise re-request the same page indefinitely.

The member email address IS collected. It is the identifier that makes an alert
actionable, since a display name is neither unique nor stable, and it is the
value an analyst needs to tie a GitBook administrator to an identity elsewhere.
It is organisation membership data rather than end-user content.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

VENDOR = "gitbook"
# Product string drives the dataset name: gitbook_members_raw.
PRODUCT = "members"
SOURCE_LOG_TYPE = "member"
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

    def list_members(self, organization_id: str, max_fetch: int) -> list:
        """Fetch every member of the organisation, following the cursor.

        Returns the accumulated items. The caller decides what to do with an
        empty list; an organisation with no members is a valid answer.
        """
        members: list = []
        seen_cursors: set[str] = set()
        page: str | None = None

        while True:
            params: dict[str, Any] = {"limit": PAGE_SIZE}
            if page:
                params["page"] = page

            response = self._http_request(
                method="GET",
                url_suffix=f"/v1/orgs/{organization_id}/members",
                params=params,
            )
            if not isinstance(response, dict):
                break

            items = response.get("items") or []
            if not isinstance(items, list):
                break
            members.extend(items)

            if len(members) >= max_fetch:
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

        return members[:max_fetch]

    def get_organization(self, organization_id: str) -> dict:
        """Fetch the organisation, used to confirm the token can reach it."""
        response = self._http_request(method="GET", url_suffix=f"/v1/orgs/{organization_id}")
        return response if isinstance(response, dict) else {}


def _now_rfc3339() -> str:
    now = arg_to_datetime("now", required=True)
    assert now is not None  # for type-checkers; arg_to_datetime raises otherwise
    return now.strftime(DATE_FORMAT)


def build_event(member: dict, organization_id: str, now: str) -> dict:
    """Build one snapshot event for a member.

    The nested ``user`` object is flattened into columns rather than kept as a
    blob, because every field in it is something a detection needs to filter on
    and a JSON string cannot be filtered without parsing it first.
    """
    event: dict[str, Any] = {}

    for key, value in member.items():
        if key == "user":
            continue
        if not isinstance(value, dict | list):
            event[key] = value

    user = member.get("user")
    if isinstance(user, dict):
        for key in ("id", "displayName", "email"):
            value = user.get(key)
            if not isinstance(value, dict | list):
                event[f"user_{key}"] = value

    # A member holding an administrative role without single sign-on
    # authenticates with a credential the identity provider does not control,
    # so the combination is worth resolving once here rather than in every rule.
    role = str(member.get("role") or "").lower()
    event["is_privileged_role"] = role in ("admin", "owner")
    event["uses_sso"] = bool(member.get("sso"))

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["organization_id"] = organization_id
    return event


def fetch_members(client: Client, organization_id: str, max_fetch: int) -> list[dict]:
    """Collect the member roster snapshot."""
    members = client.list_members(organization_id, max_fetch) or []
    now = _now_rfc3339()
    events = [build_event(m, organization_id, now) for m in members if isinstance(m, dict) and m.get("id")]
    demisto.debug(f"GitBook: fetched {len(events)} organisation members")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, organization_id: str) -> str:
    """Validate connectivity, token scope and the organisation identifier."""
    try:
        client.list_members(organization_id, 1)
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
                "members. The token owner needs an administrator role in the organisation. "
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
    """Manual command to preview (and optionally push) the member roster."""
    limit = arg_to_number(args.get("limit")) or 50
    events = fetch_members(client, organization_id, limit)
    human_readable = tableToMarkdown(
        "GitBook Organisation Members",
        events,
        headers=[
            "user_displayName",
            "user_email",
            "role",
            "sso",
            "disabled",
            "joinedAt",
            "lastSeenAt",
            "spaces",
            "teams",
            "sites",
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

        elif command == "gitbook-get-members":
            events, results = get_events_command(client, organization_id, args)
            if argToBoolean(args.get("should_push_events", "false")):
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_members(client, organization_id, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_fetch": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
