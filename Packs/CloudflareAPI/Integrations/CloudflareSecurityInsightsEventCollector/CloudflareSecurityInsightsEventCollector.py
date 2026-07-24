# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cloudflare Security Insights Event Collector for Cortex XSIAM.

Collects Security Center insights (findings) from the Cloudflare API
(GET /accounts/{account_id}/security-center/insights) and ingests them into the
``cloudflare_security_insights_raw`` dataset. Insights are current findings
(an inventory), so each run sends the full snapshot.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from datetime import datetime, UTC

urllib3.disable_warnings()

VENDOR = "cloudflare"
PRODUCT = "security_insights"
SOURCE_LOG_TYPE = "security_insight"
DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_MAX_FETCH = 5000
DEFAULT_GET_EVENTS_LIMIT = 50
# The Security Center insights endpoint requires per_page to be a multiple of 5.
INSIGHTS_PER_PAGE = 25
# Cloudflare caps per_page at 1000 on the paginated log endpoints.
CF_API_MAX_PER_PAGE = 1000


class CloudflareClient(BaseClient):
    """Bearer-auth HTTP client for the Cloudflare API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_logs(self, url_suffix: str, params: dict) -> dict:
        """GET a paginated Cloudflare endpoint, returning the response wrapper."""
        return self._http_request(method="GET", url_suffix=url_suffix, params=params)


def cf_fetch_all(
    client: "CloudflareClient",
    url_suffix: str,
    base_params: dict | None = None,
    max_fetch: int = 10000,
    result_key: str | None = None,
    per_page: int = CF_API_MAX_PER_PAGE,
) -> list:
    """Page through a non-time-series Cloudflare list endpoint and return all items.

    Inventory/snapshot sources have no ``since`` cursor; each poll returns the
    full current list. When the items are nested under a key in the ``result``
    object (e.g. ``result.issues``), pass ``result_key``.
    """
    collected: list = []
    page = 1
    while len(collected) < max_fetch:
        params = dict(base_params or {})
        params.update({"page": page, "per_page": per_page})
        response = client.get_logs(url_suffix, params)
        raw = response.get("result")
        results = (raw.get(result_key) if result_key and isinstance(raw, dict) else raw) or []
        if not results:
            break
        collected.extend(results)

        result_info = response.get("result_info") or {}
        total_pages = result_info.get("total_pages")
        total_count = result_info.get("total_count")
        if total_pages is not None and page >= total_pages:
            break
        if total_count is not None and len(collected) >= total_count:
            break
        if len(results) < per_page:
            break
        page += 1
    return collected[:max_fetch]


def cf_push(events: list, vendor: str, product: str) -> None:
    """Send events to XSIAM. Call even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=vendor, product=product)


def _insights_suffix(account_id: str) -> str:
    return f"/accounts/{account_id}/security-center/insights"


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_events(client: CloudflareClient, account_ids: list, max_fetch: int) -> list:
    """Fetch the current Security Center insights snapshot for each account."""
    all_events: list = []
    now = _now_rfc3339()
    for account_id in account_ids:
        issues = cf_fetch_all(
            client=client,
            url_suffix=_insights_suffix(account_id),
            max_fetch=max_fetch,
            result_key="issues",
            per_page=INSIGHTS_PER_PAGE,
        )
        for issue in issues:
            issue["_time"] = issue.get("timestamp") or now
            issue["source_log_type"] = SOURCE_LOG_TYPE
            issue["cloudflare_account_id"] = account_id
        all_events.extend(issues)
        demisto.debug(f"Cloudflare: fetched {len(issues)} insights for account {account_id}")
    return all_events


def test_module(client: CloudflareClient, account_ids: list) -> str:
    """Validate connectivity and token scope with a minimal request per account."""
    for account_id in account_ids:
        try:
            client.get_logs(_insights_suffix(account_id), {"page": 1, "per_page": 5})
        except DemistoException as e:
            message = str(e)
            if any(token in message for token in ("[401]", "[403]", "Authentication error", "10000")):
                raise DemistoException(
                    f"Authorisation failed for account '{account_id}'. Check that the Cloudflare API "
                    "Token has the 'Account Security Insights' (Security Center Insights Read) "
                    f"permission and is scoped to this account. Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: CloudflareClient, args: dict) -> tuple:
    """Manual command to preview (and optionally push) Security Center insights."""
    account_ids = argToList(args["account_ids"])
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    events = fetch_events(client, account_ids, limit)
    human_readable = tableToMarkdown(
        "Cloudflare Security Insights",
        events,
        headers=["id", "issue_class", "severity", "subject", "status", "timestamp"],
        removeNull=True,
    )
    return events, CommandResults(readable_output=human_readable, raw_response=events)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_token = (params.get("credentials") or {}).get("password", "")
    account_ids = argToList(params.get("account_ids"))
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        if not account_ids:
            raise DemistoException("At least one Cloudflare account ID must be configured.")

        client = CloudflareClient(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, account_ids))

        elif command == "cloudflare-security-insights-get-events":
            args.setdefault("account_ids", params.get("account_ids"))
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                cf_push(events, VENDOR, PRODUCT)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_events(client, account_ids, max_fetch)
            cf_push(events, VENDOR, PRODUCT)
            demisto.setLastRun({"last_snapshot": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
