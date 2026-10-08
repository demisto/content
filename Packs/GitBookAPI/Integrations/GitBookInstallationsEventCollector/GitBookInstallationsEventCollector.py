# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GitBook Integration Installations Event Collector for Cortex XSIAM.

Collects the organisation integration installation inventory and ingests it
into the ``gitbook_installations_raw`` dataset.

    GET /v1/orgs/{organizationId}/installations

An installed integration is third-party code holding standing access to
documentation content. The inventory answers which third parties are connected,
what they are permitted to reach, whether the publisher is verified, and whether
the installation covers every space and site or only a selection. That is a
supply-chain question rather than a user-access one, so it is asked of the
installation and its integration together.

The GitBook API exposes NO audit log, so there is no event stream of who
installed what. This is therefore a SNAPSHOT collector: it re-sends the full
inventory every run, and duplicate rows across runs are correct, because
comparing successive snapshots is the only way a change becomes visible.

Pagination is an OPAQUE CURSOR. The ``page`` parameter is a string identifier
returned by the previous response, not an offset, so a page loop must follow
``next.page`` and must never construct a page value of its own. The loop also
stops if the API returns a cursor it has already been given, because a cursor
that does not advance would otherwise re-request the same page indefinitely.

Each list item wraps two objects, ``installation`` and ``integration``. The
column set is derived from the GitBook API specification rather than from
observed responses, so a field the specification marks optional may be absent
and every read here tolerates that.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

VENDOR = "gitbook"
# Product string drives the dataset name: gitbook_installations_raw.
PRODUCT = "installations"
SOURCE_LOG_TYPE = "installation"
DEFAULT_BASE_URL = "https://api.gitbook.com"
DEFAULT_MAX_FETCH = 5000
PAGE_SIZE = 100
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Scopes that let an integration change what readers see rather than only read
# it. Resolving them here keeps every rule from parsing the scope string.
CONTENT_WRITE_SCOPE = "space:content:write"
SCRIPT_INJECT_SCOPE = "site:script:inject"


class Client(BaseClient):
    """Bearer-auth HTTP client for the GitBook API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_installations(self, organization_id: str, max_fetch: int) -> list:
        """Fetch every integration installation, following the cursor.

        Returns the accumulated items. The caller decides what to do with an
        empty list; an organisation with no integrations installed is a valid
        answer.
        """
        installations: list = []
        seen_cursors: set[str] = set()
        page: str | None = None

        while True:
            params: dict[str, Any] = {"limit": PAGE_SIZE}
            if page:
                params["page"] = page

            response = self._http_request(
                method="GET",
                url_suffix=f"/v1/orgs/{organization_id}/installations",
                params=params,
            )
            if not isinstance(response, dict):
                break

            items = response.get("items") or []
            if not isinstance(items, list):
                break
            installations.extend(items)

            if len(installations) >= max_fetch:
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

        return installations[:max_fetch]

    def get_organization(self, organization_id: str) -> dict:
        """Fetch the organisation, used to confirm the token can reach it."""
        response = self._http_request(method="GET", url_suffix=f"/v1/orgs/{organization_id}")
        return response if isinstance(response, dict) else {}


def _now_rfc3339() -> str:
    now = arg_to_datetime("now", required=True)
    assert now is not None  # for type-checkers; arg_to_datetime raises otherwise
    return now.strftime(DATE_FORMAT)


def _set_scalar(event: dict, column: str, value: Any) -> None:
    """Write a column only when the value is scalar, so no blob reaches a column."""
    if not isinstance(value, dict | list):
        event[column] = value


def installation_id(item: Any) -> str:
    """Record identity, which sits one level down inside the item wrapper."""
    if not isinstance(item, dict):
        return ""
    installation = item.get("installation")
    if not isinstance(installation, dict):
        return ""
    return str(installation.get("id") or "")


def build_event(item: dict, organization_id: str, now: str) -> dict:
    """Build one snapshot event for an integration installation.

    The item wraps an ``installation`` and the ``integration`` it installs.
    Both are flattened into columns, because a detection filters on the scopes
    an integration holds and a JSON string cannot be filtered without parsing
    it first.
    """
    # Bind once, then narrow. Calling .get() inside the isinstance test and again for the
    # value checks one object and assigns another, so nothing guarantees the two agree and
    # the declared type stays optional even though the runtime value cannot be None.
    raw_installation = item.get("installation")
    raw_integration = item.get("integration")
    installation: dict[str, Any] = raw_installation if isinstance(raw_installation, dict) else {}
    integration: dict[str, Any] = raw_integration if isinstance(raw_integration, dict) else {}
    event: dict[str, Any] = {}

    # The configuration blob is integration-supplied and can hold the
    # credentials the integration authenticates with, so it is not collected.
    for key, value in installation.items():
        if key == "configuration":
            continue
        if not isinstance(value, dict | list):
            event[key] = value

    target = installation.get("target")
    if isinstance(target, dict):
        _set_scalar(event, "target_organization", target.get("organization"))

    network = installation.get("network")
    if isinstance(network, dict):
        event["network_proxy"] = bool(network.get("proxy"))

    urls = installation.get("urls")
    if isinstance(urls, dict):
        _set_scalar(event, "urls_app", urls.get("app"))

    external_ids = installation.get("externalIds")
    if isinstance(external_ids, list):
        event["external_ids"] = ",".join(str(i) for i in external_ids if not isinstance(i, dict | list))

    for key in (
        "name",
        "title",
        "description",
        "version",
        "verified",
        "visibility",
        "target",
    ):
        value = integration.get(key)
        if not isinstance(value, dict | list):
            event[f"integration_{key}"] = value

    # The owner is the third party the code comes from, which is the party an
    # analyst has to make a judgement about.
    owner = integration.get("owner")
    if isinstance(owner, dict):
        _set_scalar(event, "integration_owner_id", owner.get("id"))
        _set_scalar(event, "integration_owner_title", owner.get("title"))

    scopes = integration.get("scopes")
    scopes = [str(s) for s in scopes if not isinstance(s, dict | list)] if isinstance(scopes, list) else []
    event["integration_scopes"] = ",".join(scopes)
    event["integration_scope_count"] = len(scopes)

    # Writing content or injecting script into a published site is reach beyond
    # reading, so both are resolved once here rather than in every rule.
    event["can_write_content"] = CONTENT_WRITE_SCOPE in scopes
    event["can_inject_script"] = SCRIPT_INJECT_SCOPE in scopes

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["organization_id"] = organization_id
    return event


def fetch_installations(client: Client, organization_id: str, max_fetch: int) -> list[dict]:
    """Collect the integration installation snapshot."""
    installations = client.list_installations(organization_id, max_fetch) or []
    now = _now_rfc3339()
    events = [build_event(i, organization_id, now) for i in installations if installation_id(i)]
    demisto.debug(f"GitBook: fetched {len(events)} integration installations")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, organization_id: str) -> str:
    """Validate connectivity, token scope and the organisation identifier."""
    try:
        client.list_installations(organization_id, 1)
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
                "integration installations. The token owner needs an administrator role in "
                f"the organisation. Original error: {message}"
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
    """Manual command to preview (and optionally push) the installation inventory."""
    limit = arg_to_number(args.get("limit")) or 50
    events = fetch_installations(client, organization_id, limit)
    human_readable = tableToMarkdown(
        "GitBook Integration Installations",
        events,
        headers=[
            "integration_title",
            "integration_owner_title",
            "integration_verified",
            "status",
            "space_selection",
            "site_selection",
            "spaces",
            "integration_scopes",
            "can_write_content",
            "can_inject_script",
            "createdAt",
            "updatedAt",
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

        elif command == "gitbook-get-installations":
            events, results = get_events_command(client, organization_id, args)
            if argToBoolean(args.get("should_push_events", "false")):
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_installations(client, organization_id, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_fetch": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
