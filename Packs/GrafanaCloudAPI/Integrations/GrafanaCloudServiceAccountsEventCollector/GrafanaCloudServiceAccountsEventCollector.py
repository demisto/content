# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Grafana Service Accounts Event Collector for Cortex XSIAM.

Collects the service account inventory and each account's tokens from a Grafana
instance, and ingests them into the ``grafana_service_accounts_raw`` dataset.

Service accounts are Grafana's machine-credential surface. They replaced the old
standalone API keys, they hold a role that can reach Admin, and each carries one
or more long-lived tokens. The inventory answers which non-human identities can
reach this Grafana, what they are allowed to do, and whether their tokens ever
expire.

    GET /api/serviceaccounts/search        the inventory, paged
    GET /api/serviceaccounts/{id}/tokens   the tokens, per account

Two behaviours were established against a live instance and are easy to get
wrong:

  * The search endpoint's ``page`` parameter is ONE-BASED. Page 0 and page 1
    return identical records, so a zero-based loop re-reads the first page on
    every run. ``perpage`` is honoured.
  * ``totalCount`` stays populated past the end of the results, so it cannot be
    used to terminate. Stop on an empty page instead.

Token SECRETS are never returned by this API and are never collected. Only the
token's name, lifecycle dates and revocation state are read.

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
# Product string drives the dataset name: grafana_service_accounts_raw.
PRODUCT = "service_accounts"
SOURCE_LOG_TYPE = "service_account"
DEFAULT_MAX_FETCH = 5000
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# The search endpoint pages from ONE, not zero. Proven on a live instance:
# page=0 and page=1 return the same records.
FIRST_PAGE = 1
PAGE_SIZE = 100


class Client(BaseClient):
    """Bearer-auth HTTP client for the Grafana instance API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def search_service_accounts(self, page: int, per_page: int = PAGE_SIZE) -> dict:
        """Fetch one page of the service account inventory."""
        return self._http_request(
            method="GET",
            url_suffix="/api/serviceaccounts/search",
            params={"page": page, "perpage": per_page},
        )

    def get_tokens(self, service_account_id: int) -> list:
        """Fetch one service account's tokens. Secrets are not returned by the API."""
        return self._http_request(
            method="GET",
            url_suffix=f"/api/serviceaccounts/{service_account_id}/tokens",
        )


def _now_rfc3339() -> str:
    now = arg_to_datetime("now", required=True)
    assert now is not None  # for type-checkers; arg_to_datetime raises otherwise
    return now.strftime(DATE_FORMAT)


def summarise_tokens(tokens: list) -> dict:
    """Flatten an account's tokens into columns a correlation can filter on.

    Only lifecycle facts are kept. A token's secret is not returned by the API
    and is never collected. ``expiration`` being null means the token never
    expires, which is the posture fact worth surfacing.
    """
    summary: dict[str, Any] = {
        "token_count": 0,
        "token_names": "",
        "tokens_without_expiry": 0,
        "tokens_expired": 0,
        "tokens_revoked": 0,
        "tokens_never_used": 0,
        "oldest_token_created": None,
        "newest_token_created": None,
        "last_token_used_at": None,
    }
    names: list[str] = []
    created: list[str] = []
    used: list[str] = []

    for token in tokens or []:
        if not isinstance(token, dict):
            continue
        summary["token_count"] += 1
        name = token.get("name")
        if name:
            names.append(str(name))
        if not token.get("expiration"):
            summary["tokens_without_expiry"] += 1
        if token.get("hasExpired"):
            summary["tokens_expired"] += 1
        if token.get("isRevoked"):
            summary["tokens_revoked"] += 1
        if not token.get("lastUsedAt"):
            summary["tokens_never_used"] += 1
        if token.get("created"):
            created.append(str(token["created"]))
        if token.get("lastUsedAt"):
            used.append(str(token["lastUsedAt"]))

    summary["token_names"] = "|".join(sorted(set(names)))
    if created:
        summary["oldest_token_created"] = min(created)
        summary["newest_token_created"] = max(created)
    if used:
        summary["last_token_used_at"] = max(used)
    return summary


def build_event(account: dict, tokens: list, instance_url: str, now: str) -> dict:
    """Build one snapshot event for a service account."""
    event: dict[str, Any] = {}

    for key, value in account.items():
        # Keep the scalars. Nothing in this record is nested, but guard anyway
        # so an added field cannot break ingestion.
        if not isinstance(value, dict | list):
            event[key] = value

    event.update(summarise_tokens(tokens))

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["grafana_instance"] = instance_url
    return event


def fetch_service_accounts(client: Client, max_fetch: int) -> list[dict]:
    """Page the inventory, then read each account's tokens.

    Pages from ONE and stops on an empty page. It never trusts ``totalCount``,
    which stays populated past the end of the results.
    """
    accounts: list[dict] = []
    page = FIRST_PAGE

    while len(accounts) < max_fetch:
        response = client.search_service_accounts(page=page) or {}
        batch = response.get("serviceAccounts") or []
        if not batch:
            break
        accounts.extend(batch)
        page += 1

    accounts = accounts[:max_fetch]

    now = _now_rfc3339()
    instance_url = client._base_url  # noqa: SLF001 - the configured instance identifies the tenant
    events: list[dict] = []
    for account in accounts:
        if not isinstance(account, dict) or account.get("id") is None:
            continue
        try:
            tokens = client.get_tokens(int(account["id"])) or []
        except DemistoException as e:
            # An account whose tokens cannot be read is still worth reporting:
            # the inventory entry matters more than its token detail.
            demisto.debug(f"Grafana: could not read tokens for service account {account.get('id')}: {e}")
            tokens = []
        events.append(build_event(account, tokens if isinstance(tokens, list) else [], instance_url, now))

    demisto.debug(f"Grafana: fetched {len(events)} service accounts")
    return events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client) -> str:
    """Validate connectivity and token scope with a minimal request."""
    try:
        client.search_service_accounts(page=FIRST_PAGE, per_page=1)
    except DemistoException as e:
        message = str(e)
        if any(token in message for token in ("[401]", "[403]", "Unauthorized", "accessErrorId")):
            raise DemistoException(
                "Authorisation failed. The Grafana service account token needs the Admin role, or a "
                "role carrying the 'serviceaccounts:read' permission, in the organisation being "
                f"collected. Original error: {message}"
            )
        raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the service account inventory."""
    limit = arg_to_number(args.get("limit")) or 50
    events = fetch_service_accounts(client, limit)
    human_readable = tableToMarkdown(
        "Grafana Service Accounts",
        events,
        headers=["name", "login", "role", "isDisabled", "isExternal", "token_count", "tokens_without_expiry"],
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

        elif command == "grafana-service-accounts-get-events":
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_service_accounts(client, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_snapshot": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
