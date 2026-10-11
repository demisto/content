import time
from collections.abc import Generator
from datetime import datetime

import dateparser
import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from SiemApiModule import *  # noqa: E402

urllib3.disable_warnings()
VENDOR = "github"
PRODUCT = "github-audit"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def get_github_timestamp_format(value):
    """Converts int(epoch), str(3 days), or datetime to GitHub's API time format.

    Args:
        value (Any): The value to convert to GitHub's API time format.

    Returns:
        str: The value in GitHub's API time format.

    Raises:
        TypeError: If the input value is not a valid time.
    """
    if isinstance(value, int):
        value = datetime.utcfromtimestamp(value / 1000)
    elif isinstance(value, str):
        value = dateparser.parse(value)
    if not isinstance(value, datetime):
        raise TypeError(f"after is not a valid time {value}")

    return f"created:>{value.strftime(DATETIME_FORMAT)}"


def prepare_demisto_params(params: dict):
    params["phrase"] = params.get("after")
    del params["after"]


class GithubParams(BaseModel):
    """
    A class that stores the request query params
    """

    include: str
    order: str = "asc"
    phrase: str
    per_page: int = 100  # Maximum is 100
    _normalize_after = validator("phrase", pre=True, allow_reuse=True)(  # type: ignore[type-var]
        get_github_timestamp_format
    )


class GithubEventsRequestConfig(IntegrationHTTPRequest):
    url: AnyUrl
    method: Method = Method.GET
    params: GithubParams  # type: ignore


class GithubClient(IntegrationEventsClient):
    def set_request_filter(self, after: str):
        if self.request.params:
            self.request.params.phrase = get_github_timestamp_format(after)  # type: ignore


class GithubGetEvents(IntegrationGetEvents):
    @staticmethod
    def _log_response_diagnostics(page_number: int, response) -> list:
        """
        Diagnostic logging for a single audit-log API response (XSUP-78460).

        Logs the response status, the number of events, the Link/pagination headers (including the
        'Link' header content and whether a rel="next" cursor is present), and a sample of the first
        event's field names (keys only, not values) plus the first/last '@timestamp' of the page so
        cursor progress can be traced. Returns the parsed events list.
        """
        events = response.json()
        count = len(events) if isinstance(events, list) else "N/A (not a list)"

        link_header = response.headers.get("Link") or response.headers.get("link")
        has_next = bool(link_header) and 'rel="next"' in link_header

        demisto.debug(
            f"[GitHubEventCollector] Page #{page_number}: status={response.status_code}, "
            f"events_in_page={count}, has_next_link={has_next}"
        )
        demisto.debug(f"[GitHubEventCollector] Page #{page_number}: Link header = {link_header!r}")
        demisto.debug(f"[GitHubEventCollector] Page #{page_number}: request url = {response.request.url!r}")

        if isinstance(events, list) and events:
            first_event = events[0]
            if isinstance(first_event, dict):
                demisto.debug(
                    f"[GitHubEventCollector] Page #{page_number}: sample event field names = " f"{sorted(first_event.keys())}"
                )
            first_ts = events[0].get("@timestamp") if isinstance(events[0], dict) else None
            last_ts = events[-1].get("@timestamp") if isinstance(events[-1], dict) else None
            demisto.debug(
                f"[GitHubEventCollector] Page #{page_number}: first @timestamp={first_ts}, " f"last @timestamp={last_ts}"
            )
        return events

    def _iter_events(self) -> Generator | list:  # type: ignore[return]
        """
        Function that responsible for the iteration over the events returned from github api
        """
        page_number = 1
        demisto.debug("[GitHubEventCollector] Starting event iteration (page 1).")
        response = self.client.call(self.client.request)
        events = self._log_response_diagnostics(page_number, response)

        if not events:
            demisto.debug("[GitHubEventCollector] First page returned no events. Nothing to fetch.")
            return []

        total_events = 0
        while True:
            total_events += len(events)
            yield events
            last = events.pop()
            next_filter = last["@timestamp"]
            demisto.debug(
                f"[GitHubEventCollector] Advancing cursor after page #{page_number}: "
                f"last @timestamp={next_filter}, total events so far={total_events}"
            )
            self.client.set_request_filter(next_filter)
            page_number += 1
            response = self.client.call(self.client.request)
            events = self._log_response_diagnostics(page_number, response)
            try:
                assert events
            except (IndexError, AssertionError):
                demisto.debug(
                    f"[GitHubEventCollector] Empty page #{page_number} received, breaking. "
                    f"Total events fetched={total_events}."
                )
                LOG("empty list, breaking")
                break

    @staticmethod
    def get_last_run(events: List[dict]) -> dict:
        """
        Get the info from the last run, it returns the time to query from and a list of ids to prevent duplications
        """
        if not events:
            return demisto.getLastRun()
        last_timestamp = events[-1]["@timestamp"]
        return {"after": last_timestamp}


def main():  # pragma: no cover
    # Once the parameter "after" is hidden, the previous value of the parameter is saved, not the new default value which
    # is 1 minute. For example if the previous value of "after" (First fetch time interval) was "3 days", after the parameter
    # "after" is hidden it will remain "3 days" and each time Reset the "last run" timestamp is used, it will use "3 days"
    # instead of "1 minute".
    demisto.params()["after"] = "1 minute"
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    demisto.debug(f'{demisto_params.get("after")=}')

    should_push_events = argToBoolean(demisto_params.get("should_push_events", "false"))

    headers = {
        "Authorization": f"Bearer {demisto_params['auth_credendtials']['password']}",
        "Accept": "application/vnd.github.v3+json",
    }

    demisto_params["headers"] = headers

    prepare_demisto_params(demisto_params)
    demisto_params["params"] = GithubParams(**demisto_params)

    request = GithubEventsRequestConfig(**demisto_params)

    options = IntegrationOptions.parse_obj(demisto_params)
    client = GithubClient(request, options)

    get_events = GithubGetEvents(client, options)

    command = demisto.command()
    demisto.debug("[GitHubEventCollector] Running CUSTOM DIAGNOSTIC BUILD with extended logging.")
    demisto.debug(f"[GitHubEventCollector] Command '{command}' started. Request url={request.url!r}")
    try:
        if command == "test-module":
            get_events.run()
            return_results("ok")
        elif command in ("github-get-events", "fetch-events"):
            fetch_start = time.time()
            events = get_events.run()
            elapsed = time.time() - fetch_start
            demisto.debug(
                f"[GitHubEventCollector] Fetch completed: {len(events)} events in {elapsed:.2f}s " f"(command={command})."
            )

            if command == "fetch-events":
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                next_run = GithubGetEvents.get_last_run(events)
                demisto.debug(f"[GitHubEventCollector] Pushed {len(events)} events to XSIAM; setting lastRun={next_run}.")
                demisto.setLastRun(next_run)

            elif command == "github-get-events":
                command_results = CommandResults(
                    readable_output=tableToMarkdown("Github Logs", events, headerTransform=pascalToSpace),
                    outputs_prefix="Github.Logs",
                    outputs_key_field="@timestamp",
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)
                if should_push_events:
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    except Exception as e:
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
