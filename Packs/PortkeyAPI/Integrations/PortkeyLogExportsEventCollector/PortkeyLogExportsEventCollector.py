# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Portkey LLM Request Logs Event Collector for Cortex XSIAM.

Collects the gateway request logs, the record of every call made through Portkey
to a model provider, into the ``portkey_llm_requests_raw`` dataset. These are the
logs Portkey shows under Logs, and they carry the prompt, the completion, the
model and provider, the token counts, the cost and the upstream status.

Portkey has no endpoint that lists request logs. The only bulk read path is the
asynchronous log export, so this collector drives that job through its lifecycle:

    POST /logs/exports              create for a time window, returns id and total
    POST /logs/exports/{id}/start   queue the job
    GET  /logs/exports/{id}         poll until status is success
    GET  /logs/exports/{id}/download   returns a pre-signed URL
    GET  <signed url>               the JSONL payload, on external object storage

An export takes longer than a collector run should block for, so the job is
carried across runs in lastRun: one run creates and starts it, later runs poll,
and the run that finds it complete downloads and ingests. Export runtime therefore
only affects latency, never correctness.

Collection is watermark driven rather than tied to the poll interval. The export
window is half-open, verified against the API: [min, max) with min inclusive and
max exclusive, so consecutive windows chain with neither a gap nor an overlap and
no boundary de-duplication is needed. The watermark advances only after a
successful download, so a failed export simply retries the identical window.

Two API behaviours are load bearing and easy to get wrong:

* ``workspace_id`` expects the workspace SLUG (``ws-example-a1b2c3``), not the
  workspace UUID. Passing the UUID returns HTTP 200 and silently matches nothing.
* An export is capped at 50,000 records. ``total`` is returned when the export is
  created, before it runs, so the window is measured first and bisected until it
  fits, rather than silently truncating.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
import requests
from datetime import datetime, timedelta, UTC
from typing import Any

urllib3.disable_warnings()

VENDOR = "portkey"
# Product string drives the dataset name: portkey_llm_requests_raw.
PRODUCT = "llm_requests"
SOURCE_LOG_TYPE = "llm_request"
DEFAULT_BASE_URL = "https://api.portkey.ai/v1"
DEFAULT_FIRST_FETCH = "1 day"
DEFAULT_LAG_MINUTES = 5
# A single export is capped at 50,000 records by the API.
EXPORT_RECORD_LIMIT = 50000
# How many times a window may be halved when it holds more than the cap.
MAX_WINDOW_BISECTS = 8
# Terminal export states.
STATUS_SUCCESS = "success"
STATUS_TERMINAL_FAILURES = ("failed", "stopped")

ALL_REQUESTED_DATA = [
    "id",
    "trace_id",
    "created_at",
    "request",
    "response",
    "is_success",
    "ai_org",
    "ai_model",
    "req_units",
    "res_units",
    "total_units",
    "request_url",
    "cost",
    "cost_currency",
    "response_time",
    "response_status_code",
    "mode",
    "config",
    "prompt_slug",
    "metadata",
]
# The prompt and completion bodies dominate the payload size, so they can be left out.
BODY_FIELDS = ("request", "response")


class Client(BaseClient):
    """HTTP client for the Portkey log export API."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {
            "x-portkey-api-key": api_key,
            "Content-Type": "application/json",
        }
        self.verify_ssl = verify
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def create_export(self, workspace_slug: str, start: str, end: str, requested_data: list[str]) -> dict:
        """Create an export and return ``{id, total, object}``.

        ``workspace_id`` takes the workspace slug. ``description`` is rejected as
        missing when absent, although the specification does not mark it required.
        The response reports ``total`` before the job runs, which is what lets the
        window be measured against the record cap.
        """
        body: dict[str, Any] = {
            "workspace_id": workspace_slug,
            "description": "GoCortexIO Cortex Platform log export",
            "filters": {"time_of_generation_min": start, "time_of_generation_max": end},
            "requested_data": requested_data,
        }
        return self._http_request(method="POST", url_suffix="/logs/exports", json_data=body)

    def start_export(self, export_id: str) -> dict:
        return self._http_request(method="POST", url_suffix=f"/logs/exports/{export_id}/start")

    def cancel_export(self, export_id: str) -> dict:
        return self._http_request(method="POST", url_suffix=f"/logs/exports/{export_id}/cancel")

    def get_export(self, export_id: str) -> dict:
        return self._http_request(method="GET", url_suffix=f"/logs/exports/{export_id}")

    def get_download_url(self, export_id: str) -> dict:
        return self._http_request(method="GET", url_suffix=f"/logs/exports/{export_id}/download")

    def fetch_signed_payload(self, signed_url: str) -> str:
        """Fetch the exported JSONL from the pre-signed object storage URL.

        Deliberately a bare request rather than the client's own: the URL points
        at third party storage, and the Portkey API key must not be sent to it.
        """
        response = requests.get(signed_url, timeout=120, verify=self.verify_ssl)
        response.raise_for_status()
        return response.text


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def parse_generated_at(value: str) -> Optional[str]:
    """Normalise a Portkey ``created_at`` into ISO 8601.

    Portkey returns a JavaScript date string, for example
    ``Sat Jul 25 2026 11:14:18 GMT+0000 (Coordinated Universal Time)``, which is
    not a format Cortex parses. The offset is always reported as GMT+0000 on this
    endpoint, so the leading portion is read and treated as UTC.
    """
    if not value:
        return None
    head = value.split(" GMT")[0].strip()
    try:
        return _iso(datetime.strptime(head, "%a %b %d %Y %H:%M:%S").replace(tzinfo=UTC))
    except ValueError:
        demisto.debug(f"Portkey: could not parse created_at '{value}'")
        return None


def requested_data_fields(include_bodies: bool) -> list[str]:
    """The field set asked of the export, optionally without the large bodies."""
    if include_bodies:
        return list(ALL_REQUESTED_DATA)
    return [f for f in ALL_REQUESTED_DATA if f not in BODY_FIELDS]


def extract_user_prompt(request: Any) -> str:
    """Return just the user-authored text from a chat request.

    Prompt-injection matching must see the user's input and nothing else. The
    system prompt sits in the same request object and legitimately contains the
    words an attack would use, so matching the whole request marks every call as
    suspicious: an application whose system prompt mentions "base64" would flag
    all of its own traffic. Only the user and tool turns are returned.

    Tool results are carried two different ways depending on the provider. Some
    put them in a message with role "tool" and a plain string body; others keep
    the role as "user" and place a tool_result block inside a multi-part content
    list, where the payload sits under "content" rather than "text". Reading only
    "text" discarded the whole of the second form, so tool output was invisible
    to every rule that inspects prompt content.

    The role labels are NOT preserved in the returned string. Anything reading
    this field can therefore see WHAT was sent but not WHO sent it, so no rule
    built on it can claim that content originated from a tool rather than from
    the sender.
    """
    if not isinstance(request, dict):
        return ""
    parts: list[str] = []
    for message in request.get("messages") or []:
        if not isinstance(message, dict):
            continue
        if message.get("role") not in ("user", "tool"):
            continue
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            # Multi-part content: keep the text segments and any tool result body.
            for part in content:
                if not isinstance(part, dict):
                    continue
                if isinstance(part.get("text"), str):
                    parts.append(part["text"])
                    continue
                nested = part.get("content")
                if isinstance(nested, str):
                    parts.append(nested)
                elif isinstance(nested, list):
                    for block in nested:
                        if isinstance(block, dict) and isinstance(block.get("text"), str):
                            parts.append(block["text"])
    return "\n".join(parts)


def extract_guardrail_results(response: Any) -> dict:
    """Flatten Portkey's own guardrail output into top-level columns.

    Portkey evaluates configured guardrails and records the outcome under
    ``response.hook_results``, as a list of hooks each holding a list of checks.
    That is two levels of array, which XQL cannot traverse, so the flattening is
    done here where it can be parsed properly and unit tested.

    This is the AUTHORITATIVE classification for a request: it is the vendor's
    own verdict, versioned by the vendor. It is preferred over anything derived
    by matching text.
    """
    out: dict[str, Any] = {
        "guardrail_evaluated": False,
        "guardrail_verdict": None,
        "guardrail_denied": False,
        "guardrail_soft_denied": False,
        "guardrail_flagged": False,
        "guardrail_flagged_categories": "",
        "guardrail_check_ids": "",
        "guardrail_top_category": None,
        "guardrail_top_score": None,
    }
    if isinstance(response, str):
        try:
            response = json.loads(response)
        except ValueError:
            return out
    if not isinstance(response, dict):
        return out

    hooks: list = []
    hook_results = response.get("hook_results") or {}
    if isinstance(hook_results, dict):
        for key in ("before_request_hooks", "after_request_hooks"):
            value = hook_results.get(key)
            if isinstance(value, list):
                hooks.extend(value)
    if not hooks:
        return out

    out["guardrail_evaluated"] = True
    categories: list[str] = []
    check_ids: list[str] = []
    verdicts: list[bool] = []
    top_category, top_score = None, -1.0

    for hook in hooks:
        if not isinstance(hook, dict):
            continue
        if hook.get("deny") is True:
            out["guardrail_denied"] = True
        if hook.get("softDeny200") is True:
            out["guardrail_soft_denied"] = True
        if isinstance(hook.get("verdict"), bool):
            verdicts.append(hook["verdict"])

        for check in hook.get("checks") or []:
            if not isinstance(check, dict):
                continue
            if check.get("id"):
                check_ids.append(str(check["id"]))
            data = check.get("data") or {}
            if not isinstance(data, dict):
                continue
            for key in ("allFlaggedCategories", "flaggedCategories"):
                for category in data.get(key) or []:
                    if category not in categories:
                        categories.append(str(category))
            moderation = data.get("moderationResults") or {}
            if isinstance(moderation, dict):
                if moderation.get("flagged") is True:
                    out["guardrail_flagged"] = True
                scores = moderation.get("category_scores") or {}
                if isinstance(scores, dict):
                    for name, score in scores.items():
                        try:
                            value = float(score)
                        except (TypeError, ValueError):
                            continue
                        if value > top_score:
                            top_category, top_score = str(name), value

    # A false verdict from any hook means the content did not pass.
    if verdicts:
        out["guardrail_verdict"] = all(verdicts)
    if categories:
        out["guardrail_flagged_categories"] = "|".join(sorted(categories))
    if check_ids:
        out["guardrail_check_ids"] = "|".join(sorted(set(check_ids)))
    if top_category is not None:
        out["guardrail_top_category"] = top_category
        out["guardrail_top_score"] = top_score
    return out


def build_event(record: dict, workspace_slug: str) -> dict:
    """Stamp ingestion metadata onto an exported log record."""
    event = dict(record)
    generated = parse_generated_at(str(record.get("created_at") or ""))
    event["_time"] = generated or _iso(_now())
    event["generated_at"] = generated
    event["source_log_type"] = SOURCE_LOG_TYPE
    event["portkey_workspace_slug"] = workspace_slug
    # Isolated so a correlation can match the user's input without the system
    # prompt polluting the match. The system prompt legitimately contains the
    # vocabulary an attack uses.
    event["user_prompt"] = extract_user_prompt(record.get("request"))
    # Portkey's own guardrail verdict, flattened from the nested hook results.
    event.update(extract_guardrail_results(record.get("response")))
    return event


def parse_export_payload(payload: str, workspace_slug: str) -> list[dict]:
    """Parse the JSONL export body into stamped events, skipping unreadable lines."""
    events: list[dict] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            demisto.debug("Portkey: skipping a log line that is not valid JSON")
            continue
        events.append(build_event(record, workspace_slug))
    return events


def _export_status(response: dict) -> str:
    """Read the status out of an export response, which may be wrapped in data."""
    body = response.get("data") if isinstance(response.get("data"), dict) else response
    return str((body or {}).get("status") or "")


def open_export_window(
    client: Client,
    workspace_slug: str,
    start: datetime,
    end: datetime,
    requested_data: list[str],
) -> tuple[Optional[str], datetime, int]:
    """Create an export sized to fit the record cap.

    Measures the window with the ``total`` returned at creation and halves it
    until it fits, so a busy period or a long catch-up is split across runs
    rather than silently truncated at 50,000 records. Returns the export id, the
    window end actually used, and the record count. The id is None when the
    window holds nothing, which needs no job at all.
    """
    window_end = end
    for _ in range(MAX_WINDOW_BISECTS):
        response = client.create_export(workspace_slug, _iso(start), _iso(window_end), requested_data)
        export_id = response.get("id")
        total = int(response.get("total") or 0)

        if total == 0:
            # Nothing in the window. Abandon the draft and move the watermark on.
            _try_cancel(client, export_id)
            return None, window_end, 0

        if total < EXPORT_RECORD_LIMIT:
            return export_id, window_end, total

        # Too big for one export. Abandon this draft and halve the window.
        _try_cancel(client, export_id)
        window_end = start + (window_end - start) / 2
        demisto.debug(f"Portkey: window held {total} records, narrowing to {_iso(window_end)}")

    demisto.error(
        f"Portkey: could not size a window under {EXPORT_RECORD_LIMIT} records for workspace "
        f"{workspace_slug} after {MAX_WINDOW_BISECTS} attempts."
    )
    return None, start, 0


def _try_cancel(client: Client, export_id: Optional[str]) -> None:
    """Cancel an export that will not be used. Failure to cancel is not fatal."""
    if not export_id:
        return
    try:
        client.cancel_export(export_id)
    except Exception as e:  # noqa: BLE001 - tidying only, must never break collection
        demisto.debug(f"Portkey: could not cancel unused export {export_id}: {e}")


def collect_finished_export(client: Client, workspace_slug: str, export_id: str) -> list[dict]:
    """Download a completed export and return its events."""
    download = client.get_download_url(export_id)
    body = download.get("data") if isinstance(download.get("data"), dict) else download
    signed_url = (body or {}).get("signed_url")
    if not signed_url:
        raise DemistoException(f"Export {export_id} completed but returned no download URL.")
    payload = client.fetch_signed_payload(signed_url)
    return parse_export_payload(payload, workspace_slug)


def advance_workspace(
    client: Client,
    workspace_slug: str,
    state: dict,
    first_fetch: datetime,
    lag: timedelta,
    requested_data: list[str],
) -> tuple[list[dict], dict]:
    """Move one workspace's export job forward by a single step.

    Returns the events collected on this step, which is usually none, and the
    next state. The watermark only moves after a successful download, so a
    failure retries the same window and cannot lose or duplicate records.
    """
    job = state.get("job") or {}
    last_ts = state.get("last_ts")

    if job.get("id"):
        export_id = job["id"]
        status = _export_status(client.get_export(export_id))

        if status == STATUS_SUCCESS:
            events = collect_finished_export(client, workspace_slug, export_id)
            demisto.debug(f"Portkey: export {export_id} yielded {len(events)} events for {workspace_slug}")
            return events, {"last_ts": job["win_end"]}

        if status in STATUS_TERMINAL_FAILURES:
            demisto.error(
                f"Portkey: export {export_id} for workspace {workspace_slug} ended as '{status}'. "
                "The same window will be retried on the next run."
            )
            return [], {"last_ts": last_ts} if last_ts else {}

        # Still draft or in progress. Leave the job in place and wait.
        demisto.debug(f"Portkey: export {export_id} is '{status}', waiting")
        return [], state

    start = _parse_iso(last_ts) if last_ts else first_fetch
    end = _now() - lag
    if end <= start:
        # The lag has not yet cleared a new window; nothing to do this run.
        return [], state

    export_id, window_end, total = open_export_window(client, workspace_slug, start, end, requested_data)

    if export_id is None:
        # Either an empty window, which just advances the watermark, or a window
        # that could not be sized, which leaves the watermark alone to retry.
        next_ts = _iso(window_end) if total == 0 and window_end > start else last_ts
        return [], {"last_ts": next_ts} if next_ts else {}

    client.start_export(export_id)
    demisto.debug(f"Portkey: started export {export_id} for {workspace_slug} covering {total} records")
    return [], {"last_ts": last_ts, "job": {"id": export_id, "win_end": _iso(window_end)}}


def fetch_events(
    client: Client,
    workspace_slugs: list[str],
    last_run: dict,
    first_fetch: str,
    lag_minutes: int,
    include_bodies: bool,
) -> tuple[list[dict], dict]:
    """Advance every workspace's export by one step and build next_run."""
    all_events: list[dict] = []
    next_run: dict = {}
    first = _now() - timedelta(days=1)
    parsed_first = arg_to_datetime(first_fetch)
    if parsed_first:
        first = parsed_first.astimezone(UTC)
    lag = timedelta(minutes=lag_minutes)
    requested_data = requested_data_fields(include_bodies)

    for slug in workspace_slugs:
        state = last_run.get(slug, {})
        try:
            events, new_state = advance_workspace(client, slug, state, first, lag, requested_data)
        except Exception as e:  # noqa: BLE001 - one workspace must not stall the others
            # Carry this workspace's state forward untouched. If the exception
            # escaped, setLastRun would never run and every workspace would
            # restart its window.
            demisto.error(f"Portkey: log export failed for workspace {slug}, keeping its state: {e}")
            next_run[slug] = state
            continue
        all_events.extend(events)
        next_run[slug] = new_state

    return all_events, next_run


def push_events(events: list[dict]) -> None:
    """Send events to XSIAM. Called even when empty to update fetch metrics."""
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def test_module(client: Client, workspace_slugs: list[str]) -> str:
    """Validate connectivity, scope and the workspace slugs."""
    for slug in workspace_slugs:
        try:
            client._http_request(method="GET", url_suffix="/logs/exports", params={"workspace_id": slug})
        except DemistoException as e:
            message = str(e)
            if any(token in message for token in ("[401]", "[403]", "Unauthorized", "Forbidden", "AB03")):
                raise DemistoException(
                    "Authorisation failed. Check that the Portkey API key includes the log export "
                    f"scopes (logs.list, logs.view and logs.export). Original error: {message}"
                )
            if "[500]" in message or "AB04" in message:
                raise DemistoException(
                    f"The log export endpoint rejected workspace '{slug}'. Check that this is the "
                    "workspace SLUG, for example 'ws-example-a1b2c3', and not the workspace UUID. "
                    f"Original error: {message}"
                )
            raise
    return "ok"


def get_events_command(client: Client, args: dict, workspace_slugs: list[str], include_bodies: bool) -> CommandResults:
    """Report the record count for a window without running an export.

    Creating an export returns the count before the job runs, so this previews
    the volume a real fetch would collect. The draft is cancelled afterwards.
    """
    since = arg_to_datetime(args.get("since") or "1 day")
    assert since is not None
    start, end = since.astimezone(UTC), _now()
    requested_data = requested_data_fields(include_bodies)

    rows = []
    for slug in workspace_slugs:
        response = client.create_export(slug, _iso(start), _iso(end), requested_data)
        _try_cancel(client, response.get("id"))
        rows.append({"workspace": slug, "window_start": _iso(start), "window_end": _iso(end), "records": response.get("total")})

    return CommandResults(
        readable_output=tableToMarkdown("Portkey LLM request logs available", rows),
        raw_response=rows,
    )


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url") or DEFAULT_BASE_URL
    api_key = (params.get("credentials") or {}).get("password", "")
    workspace_slugs = argToList(params.get("workspace_slugs"))
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    first_fetch = params.get("first_fetch") or DEFAULT_FIRST_FETCH
    lag_minutes = arg_to_number(params.get("lag_minutes"))
    if lag_minutes is None:
        lag_minutes = DEFAULT_LAG_MINUTES
    include_bodies = argToBoolean(params.get("include_bodies", True))

    demisto.debug(f"Command being called is {command}")
    try:
        if not api_key:
            raise DemistoException("A Portkey admin API key must be configured.")
        if not workspace_slugs:
            raise DemistoException(
                "At least one Portkey workspace slug must be configured, for example "
                "'ws-example-a1b2c3'. The workspace UUID is not accepted by the export API."
            )

        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, workspace_slugs))

        elif command == "portkey-log-exports-get-events":
            return_results(get_events_command(client, args, workspace_slugs, include_bodies))

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            events, next_run = fetch_events(
                client=client,
                workspace_slugs=workspace_slugs,
                last_run=last_run,
                first_fetch=first_fetch,
                lag_minutes=lag_minutes,
                include_bodies=include_bodies,
            )
            push_events(events)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
