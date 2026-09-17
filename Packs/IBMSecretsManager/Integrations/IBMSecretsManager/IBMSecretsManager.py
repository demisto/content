import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # IBM Cloud Logs timestamp format (RFC3339 with millis)
VENDOR = "ibm"
PRODUCT = "secrets_manager"
SOURCE_LOG_TYPE = "ibm_secrets_manager_audit"

DEFAULT_IAM_URL = "https://iam.cloud.ibm.com"
DEFAULT_MAX_EVENTS_PER_FETCH = 50000
# Base DataPrime query scoping to Secrets Manager audit events. The exact filter field/value
# is intentionally kept in code (not exposed as a param) and is validated against a live instance.
DEFAULT_QUERY = 'source logs | filter applicationname == "secrets-manager"'
# Default first-fetch look-back when there is no previous run state.
DEFAULT_FIRST_FETCH = "1 hour"
# Per the design: bound a single fetch cycle to at most this many calls to /v1/query.
MAX_CALLS_PER_FETCH = 10

""" CLIENT CLASS """


class Client(BaseClient):
    """Client to interact with IBM Cloud Logs (audit collection) and IBM Cloud IAM (auth)."""

    def __init__(self, server_url: str, api_key: str, iam_url: str, verify: bool, proxy: bool):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy)
        self.api_key = api_key
        self.iam_url = iam_url.rstrip("/")
        self._access_token: str | None = None

    def get_access_token(self) -> str:
        """Exchange the IAM API key for a short-lived Bearer access token.

        Integrations are stateless and the token is short-lived (~1h), so a fresh token is
        fetched per run. No refresh flow exists (``refresh_token`` is ``not_supported``).

        Returns:
            str: A Bearer access token.
        """
        if self._access_token:
            return self._access_token

        response = self._http_request(
            method="POST",
            full_url=f"{self.iam_url}/identity/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data={
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": self.api_key,
            },
        )
        access_token = response.get("access_token")
        if not access_token:
            raise DemistoException("Failed to obtain an IAM access token from the provided API key.")
        self._access_token = access_token
        return access_token

    def query_events(self, query: str, start_date: str, end_date: str, limit: int) -> list[dict]:
        """Run a DataPrime query against IBM Cloud Logs ``POST /v1/query``.

        The endpoint responds with Server-Sent Events (``text/event-stream``); this method
        parses the stream and returns the collected log results.

        Args:
            query (str): DataPrime query string.
            start_date (str): Inclusive start of the (half-open) time window, RFC3339.
            end_date (str): Exclusive end of the (half-open) time window, RFC3339.
            limit (int): Maximum number of results to request from the query.

        Returns:
            list[dict]: The list of result records returned by the query.
        """
        token = self.get_access_token()
        body = {
            "query": f"{query} | limit {limit}",
            "metadata": {
                "start_date": start_date,
                "end_date": end_date,
                "syntax": "dataprime",
            },
        }
        raw_response = self._http_request(
            method="POST",
            url_suffix="/v1/query",
            headers={
                "Accept": "text/event-stream",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            data=json.dumps(body),
            resp_type="text",
        )
        return parse_sse_results(raw_response)


""" HELPER FUNCTIONS """


def parse_sse_results(raw_response: str) -> list[dict]:
    """Parse a Server-Sent Events (``text/event-stream``) response body from ``/v1/query``.

    Each SSE frame carries one or more ``data:`` lines whose concatenation is a JSON object.
    The JSON contains query results under ``result.results``.

    Args:
        raw_response (str): The raw SSE response body.

    Returns:
        list[dict]: Flattened list of result records extracted from all frames.
    """
    events: list[dict] = []
    data_lines: list[str] = []

    def flush() -> None:
        if not data_lines:
            return
        payload = "".join(data_lines)
        data_lines.clear()
        try:
            parsed = json.loads(payload)
        except (ValueError, TypeError):
            demisto.debug(f"Skipping non-JSON SSE frame: {payload[:200]}")
            return
        results = dict_safe_get(parsed, ["result", "results"], default_return_value=[])
        if isinstance(results, list):
            events.extend(res for res in results if isinstance(res, dict))

    for raw_line in raw_response.splitlines():
        line = raw_line.rstrip("\r")
        if line == "":
            # Blank line terminates an SSE frame.
            flush()
            continue
        if line.startswith(":"):
            # SSE comment / keep-alive line.
            continue
        if line.startswith("data:"):
            data_lines.append(line[len("data:") :].lstrip())
    # Flush any trailing frame not followed by a blank line.
    flush()
    return events


def get_event_timestamp(event: dict) -> str:
    """Extract the event timestamp used for ``_TIME`` and de-dup.

    Args:
        event (dict): A single log result record.

    Returns:
        str: The event's ``metadata.timestamp`` value, or empty string if absent.
    """
    metadata = event.get("metadata") or {}
    return metadata.get("timestamp", "")


def add_time_to_events(events: list[dict]) -> None:
    """Enrich each event in-place with the XSIAM ``_time`` and ``_source_log_type`` fields.

    Args:
        events (list[dict]): Events to enrich.
    """
    for event in events:
        event["_time"] = get_event_timestamp(event)
        event["_source_log_type"] = SOURCE_LOG_TYPE


def dedup_events(events: list[dict], last_ids: set[str], boundary_ts: str) -> tuple[list[dict], set[str], str]:
    """Remove events already ingested at the previous window boundary and compute new state.

    Uses a half-open ``[start, end)`` window plus a set of IDs seen at the latest timestamp to
    avoid re-ingesting boundary events that share the same timestamp across fetch cycles.

    Args:
        events (list[dict]): Raw events returned by the query (may contain boundary duplicates).
        last_ids (set[str]): IDs already ingested at ``boundary_ts`` in a previous run.
        boundary_ts (str): The last-seen timestamp persisted from the previous run.

    Returns:
        tuple[list[dict], set[str], str]:
            The de-duplicated events, the set of IDs at the new latest timestamp,
            and the new latest timestamp to persist as the next ``start_date``.
    """
    new_events: list[dict] = []
    for event in events:
        event_id = event.get("id") or event.get("logid") or ""
        event_ts = get_event_timestamp(event)
        if event_ts == boundary_ts and event_id in last_ids:
            continue
        new_events.append(event)

    if not new_events:
        return [], last_ids, boundary_ts

    latest_ts = max(get_event_timestamp(event) for event in new_events)
    latest_ids = {
        (event.get("id") or event.get("logid") or "") for event in new_events if get_event_timestamp(event) == latest_ts
    }
    return new_events, latest_ids, latest_ts


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Validate connectivity and credentials by minting a token and running a bounded query.

    Args:
        client (Client): The configured client.

    Returns:
        str: ``"ok"`` on success.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    start_date = (now - timedelta(minutes=1)).strftime(DATE_FORMAT)
    end_date = now.strftime(DATE_FORMAT)
    client.query_events(query=DEFAULT_QUERY, start_date=start_date, end_date=end_date, limit=1)
    return "ok"


def fetch_events(client: Client, query: str, max_events: int, last_run: dict) -> tuple[list[dict], dict]:
    """Fetch Secrets Manager audit events from IBM Cloud Logs since the last run.

    Args:
        client (Client): The configured client.
        query (str): The base DataPrime query.
        max_events (int): Maximum number of events to collect in this cycle.
        last_run (dict): The previous run state (``last_timestamp`` and ``last_ids``).

    Returns:
        tuple[list[dict], dict]: The collected events and the new run state to persist.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    end_date = now.strftime(DATE_FORMAT)

    last_timestamp = last_run.get("last_timestamp")
    if not last_timestamp:
        first_fetch = dateparser.parse(DEFAULT_FIRST_FETCH, settings={"TIMEZONE": "UTC"})
        last_timestamp = first_fetch.strftime(DATE_FORMAT) if first_fetch else end_date
    last_ids = set(last_run.get("last_ids", []))

    per_call_limit = min(max_events, DEFAULT_MAX_EVENTS_PER_FETCH)
    demisto.debug(f"Fetching IBM Secrets Manager events in window [{last_timestamp}, {end_date}), limit={per_call_limit}.")

    raw_events = client.query_events(
        query=query,
        start_date=last_timestamp,
        end_date=end_date,
        limit=per_call_limit,
    )
    demisto.debug(f"Received {len(raw_events)} raw events from IBM Cloud Logs.")

    events, new_ids, new_timestamp = dedup_events(raw_events, last_ids, last_timestamp)
    events = events[:max_events]
    add_time_to_events(events)

    new_last_run = {"last_timestamp": new_timestamp, "last_ids": list(new_ids)}
    return events, new_last_run


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manually pull events (for debugging / on-demand use) without persisting run state.

    Args:
        client (Client): The configured client.
        args (dict): Command arguments (``limit``).

    Returns:
        tuple[list[dict], CommandResults]: The events and their human-readable representation.
    """
    limit = arg_to_number(args.get("limit")) or 50
    events, _ = fetch_events(client, query=DEFAULT_QUERY, max_events=limit, last_run={})

    human_readable = tableToMarkdown(
        name="IBM Secrets Manager Events",
        t=[
            {
                "Timestamp": get_event_timestamp(event),
                "Action": (event.get("userData") or {}).get("action") or event.get("action"),
                "ID": event.get("id") or event.get("logid"),
            }
            for event in events
        ],
        removeNull=True,
    )
    command_results = CommandResults(readable_output=human_readable)
    return events, command_results


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    server_url = params.get("url", "").rstrip("/")
    api_key = (params.get("credentials") or {}).get("password") or params.get("api_key")
    iam_url = params.get("iam_url") or DEFAULT_IAM_URL
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_events = arg_to_number(params.get("max_events_per_fetch")) or DEFAULT_MAX_EVENTS_PER_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(server_url=server_url, api_key=api_key, iam_url=iam_url, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "ibm-secrets-manager-get-events":
            events, command_results = get_events_command(client, args)
            if events and argToBoolean(args.get("should_push_events", False)):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            events, new_last_run = fetch_events(client, query=DEFAULT_QUERY, max_events=max_events, last_run=last_run)
            if events:
                demisto.debug(f"Sending {len(events)} events to Cortex.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(new_last_run)
            demisto.debug(f"Successfully saved last_run={new_last_run}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
