# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cloudflare Workers Event Collector for Cortex XSIAM.

Collects the Workers script inventory from the Cloudflare API and ingests it
into the ``cloudflare_workers_raw`` dataset. A Worker is code running on
Cloudflare's edge in front of a hostname, so the inventory answers what code is
deployed, what it can reach through its bindings, and which hostnames it serves.

The account audit log already records that a script changed. It does not say
what exists now, what a script's bindings give it access to, or which hostname
it answers on, which is why this is collected as a snapshot rather than left to
the audit trail.

Three calls make up a snapshot, per account:

    GET /accounts/{id}/workers/scripts                     the inventory
    GET /accounts/{id}/workers/domains                     hostname to script
    GET /accounts/{id}/workers/scripts/{name}/settings     bindings, per script

The scripts endpoint IGNORES pagination: `per_page` and `page` are accepted and
the full list is returned regardless, so it is requested once and never paged.
Paging it would re-request the same records indefinitely.

Bindings are the security payload. A binding is how a Worker reaches a secret, a
KV namespace, an R2 bucket, a D1 database, a queue or another service, so the
binding set describes the blast radius of that code far better than the script
body does.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from datetime import datetime, UTC
from typing import Any

urllib3.disable_warnings()

VENDOR = "cloudflare"
# Product string drives the dataset name: cloudflare_workers_raw.
PRODUCT = "workers"
SOURCE_LOG_TYPE = "worker_script"
DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_MAX_FETCH = 5000

# Binding types that grant a Worker access to data or to another service. Used to
# flatten the binding set into columns a correlation can filter without parsing.
SENSITIVE_BINDING_TYPES = {
    "secret_text": "has_secret_binding",
    "kv_namespace": "has_kv_binding",
    "r2_bucket": "has_r2_binding",
    "d1": "has_d1_binding",
    "queue": "has_queue_binding",
    "service": "has_service_binding",
    "durable_object_namespace": "has_durable_object_binding",
    "ai": "has_ai_binding",
}


class Client(BaseClient):
    """Bearer-auth HTTP client for the Cloudflare API."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_scripts(self, account_id: str) -> dict:
        """Fetch the Workers script inventory for an account.

        Requested once: the endpoint accepts pagination parameters and ignores
        them, returning the whole list every time.
        """
        return self._http_request(method="GET", url_suffix=f"/accounts/{account_id}/workers/scripts")

    def list_domains(self, account_id: str) -> dict:
        """Fetch the hostname to script mapping for an account."""
        return self._http_request(method="GET", url_suffix=f"/accounts/{account_id}/workers/domains")

    def get_script_settings(self, account_id: str, script_name: str) -> dict:
        """Fetch one script's settings, which carry its bindings."""
        return self._http_request(
            method="GET",
            url_suffix=f"/accounts/{account_id}/workers/scripts/{script_name}/settings",
        )


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def summarise_bindings(bindings: list) -> dict:
    """Flatten a binding list into columns a correlation can filter on.

    Only the binding type and name are kept. A binding's value is not collected:
    for a secret the API does not return it, and for the rest it is configuration
    detail that would add volume without adding detection.
    """
    summary: dict[str, Any] = {flag: False for flag in SENSITIVE_BINDING_TYPES.values()}
    types: list[str] = []
    names: list[str] = []

    for binding in bindings or []:
        if not isinstance(binding, dict):
            continue
        btype = str(binding.get("type") or "")
        if btype:
            types.append(btype)
        name = binding.get("name")
        if name:
            names.append(str(name))
        flag = SENSITIVE_BINDING_TYPES.get(btype)
        if flag:
            summary[flag] = True

    summary["binding_count"] = len(types)
    summary["binding_types"] = "|".join(sorted(set(types)))
    summary["binding_names"] = "|".join(sorted(set(names)))
    return summary


def index_domains(domains: list) -> dict:
    """Map each script name to the hostnames it serves."""
    by_service: dict[str, list[dict]] = {}
    for domain in domains or []:
        if not isinstance(domain, dict):
            continue
        service = domain.get("service")
        if not service:
            continue
        by_service.setdefault(str(service), []).append(domain)
    return by_service


def build_script_event(script: dict, settings: dict, domains: list, account_id: str, now: str) -> dict:
    """Build one snapshot event for a Worker script."""
    event: dict[str, Any] = {}

    for key, value in script.items():
        # Keep the scalars; the nested observability object is flattened below.
        if isinstance(value, bool | str | int | float) or value is None:
            event[key] = value

    handlers = script.get("handlers") or []
    event["handlers"] = "|".join(str(h) for h in handlers) if isinstance(handlers, list) else None
    event["handler_count"] = len(handlers) if isinstance(handlers, list) else 0

    observability = script.get("observability") or {}
    event["observability_enabled"] = bool(observability.get("enabled")) if isinstance(observability, dict) else False

    settings_result = settings.get("result") if isinstance(settings, dict) else None
    settings_result = settings_result if isinstance(settings_result, dict) else {}
    event.update(summarise_bindings(settings_result.get("bindings") or []))

    tail_consumers = settings_result.get("tail_consumers") or []
    event["tail_consumer_count"] = len(tail_consumers) if isinstance(tail_consumers, list) else 0
    placement = settings_result.get("placement") or {}
    event["placement_mode"] = placement.get("mode") if isinstance(placement, dict) else None

    hostnames = [str(d.get("hostname")) for d in domains if d.get("hostname")]
    zones = [str(d.get("zone_name")) for d in domains if d.get("zone_name")]
    event["hostnames"] = "|".join(sorted(set(hostnames)))
    event["hostname_count"] = len(set(hostnames))
    event["zone_names"] = "|".join(sorted(set(zones)))
    event["environments"] = "|".join(sorted({str(d.get("environment")) for d in domains if d.get("environment")}))

    event["_time"] = now
    event["snapshot_at"] = now
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["cloudflare_account_id"] = account_id
    return event


def fetch_events_for_account(client: Client, account_id: str, max_fetch: int) -> list[dict]:
    """Collect the Workers snapshot for one account."""
    scripts = (client.list_scripts(account_id) or {}).get("result") or []
    domains_by_service = index_domains((client.list_domains(account_id) or {}).get("result") or [])

    events: list[dict] = []
    now = _now_rfc3339()
    for script in scripts[:max_fetch]:
        if not isinstance(script, dict):
            continue
        name = script.get("id")
        if not name:
            continue
        try:
            settings = client.get_script_settings(account_id, str(name))
        except DemistoException as e:
            # A script whose settings cannot be read is still worth reporting;
            # the inventory entry matters more than its bindings.
            demisto.debug(f"Cloudflare: could not read settings for Worker {name}: {e}")
            settings = {}
        events.append(build_script_event(script, settings, domains_by_service.get(str(name), []), account_id, now))

    demisto.debug(f"Cloudflare: fetched {len(events)} Workers for account {account_id}")
    return events


def fetch_events(client: Client, account_ids: list[str], max_fetch: int) -> list[dict]:
    """Collect the Workers snapshot across every configured account."""
    all_events: list[dict] = []
    for account_id in account_ids:
        try:
            all_events.extend(fetch_events_for_account(client, account_id, max_fetch))
        except Exception as e:  # noqa: BLE001 - one account must not stop the others
            demisto.error(f"Cloudflare: Workers collection failed for account {account_id}: {e}")
            continue
    return all_events


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, account_ids: list[str]) -> str:
    """Validate connectivity and token scope with a minimal request per account."""
    for account_id in account_ids:
        try:
            client.list_scripts(account_id)
        except DemistoException as e:
            message = str(e)
            if any(t in message for t in ("[401]", "[403]", "Authentication error", "10000")):
                raise DemistoException(
                    f"Authorisation failed for account '{account_id}'. Check that the Cloudflare API "
                    "token has the 'Workers Scripts Read' permission and is scoped to this account. "
                    f"Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manual command to preview (and optionally push) the Workers inventory."""
    account_ids = argToList(args["account_ids"])
    limit = arg_to_number(args.get("limit")) or 50
    events = fetch_events(client, account_ids, limit)
    human_readable = tableToMarkdown(
        "Cloudflare Workers",
        events,
        headers=["id", "hostnames", "binding_count", "binding_types", "modified_on", "observability_enabled"],
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

        client = Client(base_url=base_url, api_token=api_token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, account_ids))

        elif command == "cloudflare-workers-get-events":
            args.setdefault("account_ids", params.get("account_ids"))
            should_push = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            if should_push:
                push_events(events)
            return_results(results)

        elif command == "fetch-events":
            events = fetch_events(client, account_ids, max_fetch)
            push_events(events)
            demisto.setLastRun({"last_snapshot": _now_rfc3339()})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
