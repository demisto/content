import demistomock as demisto
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from datetime import datetime, timedelta
from time import time as get_current_time_in_seconds

disable_warnings()


# CONSTANTS
VENDOR = "symantec"
PRODUCT = "endpoint_security"
DEFAULT_CONNECTION_TIMEOUT = 30
MAX_CHUNK_SIZE_TO_READ = 1024 * 1024 * 150  # 150 MB


class UnauthorizedToken(Exception): ...


class NextPointingNotAvailable(Exception): ...


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        stream_id: str,
        channel_id: str,
        verify: bool,
        proxy: bool,
        fetch_interval: int,
    ) -> None:

        self.headers: dict[str, str] = {}
        self.client_id = client_id
        self.client_secret = client_secret
        self.stream_id = stream_id
        self.channel_id = channel_id
        self.fetch_interval = fetch_interval

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            timeout=180,
        )

        self.get_token()

    def get_token(self):
        """
        Retrieves an access token using the `client_secret` provided in the params.
        """
        get_token_headers: dict[str, str] = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "Authorization": f"Bearer {self.client_secret}",
        }
        res = self._http_request(
            "POST",
            url_suffix="/v1/oauth2/tokens",
            headers=get_token_headers,
        )
        try:
            self.headers = {
                "Authorization": f'Bearer {res["access_token"]}',
                "Accept": "application/x-ndjson",
                "Content-Type": "application/json",
                "Accept-Encoding": "gzip",
            }
        except KeyError:
            raise DemistoException(
                f"The key 'access_token' does not exist in response, Response from API: {res}"
            )

    def test_module(self):
        self._http_request(
            "POST",
            url_suffix=f"/v1/event-export/stream/{self.stream_id}/{self.channel_id}",
            headers=self.headers,
            params={"connectionTimeout": DEFAULT_CONNECTION_TIMEOUT},
            stream=True,
        )

    def get_events(self, payload: dict[str, str]):
        """
        API call in streaming to fetch events
        """
        return self._http_request(
            method="POST",
            url_suffix=f"/v1/event-export/stream/{self.stream_id}/{self.channel_id}",
            json_data=payload,
            params={"connectionTimeout": DEFAULT_CONNECTION_TIMEOUT},
            stream=True,
        )


def update_integration_context(
    filtered_events: list[dict[str, str]],
    next_hash: str,
    include_last_fetch_events: bool,
    last_integration_context: dict[str, str],
):
    events_suspected_duplicates = extract_events_suspected_duplicates(filtered_events)
    latest_event_time = max(filtered_events, key=parse_event_time)["event_time"]

    if latest_event_time == last_integration_context.get("latest_event_time", ""):
        events_suspected_duplicates.extend(
            last_integration_context.get("events_suspected_duplicates", [])
        )

    integration_context = {
        "latest_event_time": latest_event_time,
        "events_suspected_duplicates": events_suspected_duplicates,
        "next_fetch": {"next": next_hash} if next_hash else {},
        "last_fetch_events": filtered_events if include_last_fetch_events else [],
    }

    # Call the set_integration_context with the final context_data
    set_integration_context(integration_context)


def push_events(events: list[dict]):
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
    demisto.debug(f"{len(events)} events were pushed to XSIAM")


def parse_event_time(event):
    return datetime.strptime(event["event_time"], "%Y-%m-%dT%H:%M:%S.%fZ")


def extract_events_suspected_duplicates(events: list[dict]) -> list[str]:

    # Find the maximum event_time
    latest_event_time = max(events, key=parse_event_time)["event_time"]

    # Filter all JSONs with the maximum event_time
    filtered_events = filter(lambda x: x["event_time"] == latest_event_time, events)

    # Extract the event_ids from the filtered events
    events_suspected_duplicates = [x["event_id"] for x in filtered_events]
    return events_suspected_duplicates


def is_duplicate(
    event_id: str,
    event_time: datetime,
    latest_event_time: datetime,
    events_suspected_duplicates: set,
) -> bool:
    if event_time < latest_event_time:
        return True
    elif event_time == latest_event_time and event_id in events_suspected_duplicates:
        return True
    return False


def filter_duplicate_events(events: list[dict[str, str]]) -> list[dict[str, str]]:
    integration_context = get_integration_context()
    events_suspected_duplicates = set(
        integration_context.get("events_suspected_duplicates", [])
    )
    latest_event_time = integration_context.get(
        "latest_event_time", ""
    )  # TODO default value
    latest_event_time = datetime.strptime(latest_event_time, "%Y-%m-%dT%H:%M:%S.%fZ")

    return [
        event
        for event in events
        if is_duplicate(
            event["event_id"],
            datetime.strptime(event["event_time"], "%Y-%m-%dT%H:%M:%S.%fZ"),
            latest_event_time,
            events_suspected_duplicates,
        )
    ]


def get_events_command(
    client: Client, integration_context: dict
) -> list[dict[str, str]]:

    events: list[dict] = []
    next_fetch: dict[str, str] = integration_context.get("next_fetch", {})

    try:
        with client.get_events(payload=next_fetch) as res:
            # Write the chunks from the response to the tmp file
            for chunk in res.iter_content(chunk_size=MAX_CHUNK_SIZE_TO_READ):
                json_res = json.loads(chunk)
                events.extend(json_res["events"])
                next_hash = json_res.get("next", "")

    except DemistoException as e:
        if e.res is not None and e.res.status_code == 401:
            raise UnauthorizedToken
        elif e.res is not None and e.res.status_code == 410:
            raise NextPointingNotAvailable
        raise e

    filtered_events = filter_duplicate_events(events)
    filtered_events.extend(integration_context.get("last_fetch_events", []))

    try:
        push_events(filtered_events)
    except Exception as e:
        update_integration_context(
            filtered_events=filtered_events,
            next_hash=next_hash,
            include_last_fetch_events=True,
            last_integration_context=integration_context,
        )
        demisto.debug(f"Failed to push events to XSIAM, The integration_context updated. Error: {e}")
        raise e

    update_integration_context(
            filtered_events=filtered_events,
            next_hash=next_hash,
            include_last_fetch_events=False,
            last_integration_context=integration_context,
        )

    return filtered_events


def perform_long_running_loop(client: Client):
    while True:
        # Used to calculate the duration of the fetch run.
        start_run = get_current_time_in_seconds()
        try:
            integration_context = get_integration_context()
            demisto.debug(f"Starting new fetch with {integration_context=}")

            get_events_command(client, integration_context=integration_context)

        except UnauthorizedToken:
            client.get_token()
            continue
        except NextPointingNotAvailable:
            integration_context.pop("next_fetch")
            continue
        except Exception as e:
            demisto.debug(f"Failed to fetch logs from API. Error: {e}")
            raise e

        # Used to calculate the duration of the fetch run.
        end_run = get_current_time_in_seconds()

        # Calculation of the fetch runtime against `client.fetch_interval`
        # If the runtime is less than the `client.fetch_interval` time
        # then it will go to sleep for the time difference
        # between the `client.fetch_interval` and the fetch runtime
        # Otherwise, the next fetch will occur immediately
        if (fetch_sleep := client.fetch_interval - (end_run - start_run)) > 0:
            time.sleep(fetch_sleep)


def test_module(client: Client) -> str:
    try:
        client.test_module()
    except DemistoException as e:
        if e.res is not None and e.res.status_code == 403:
            raise DemistoException(
                f"Authorization Error: make sure Client Secret is correctly set, Error: {e}"
            )
        else:
            raise e
    return "ok"


def main() -> None:  # pragma: no cover
    params = demisto.params()

    host = params["host"]
    client_id = params["client_id"]
    client_secret = params["client_secret"]
    stream_id = params["stream_id"]
    channel_id = params["channel_id"]
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    fetch_interval: int = arg_to_number(params.get("fetch_interval", 60), required=True)  # type: ignore

    command = demisto.command()
    try:
        client = Client(
            base_url=host,
            client_id=client_id,
            client_secret=client_secret,
            stream_id=stream_id,
            channel_id=channel_id,
            verify=verify,
            proxy=proxy,
            fetch_interval=fetch_interval,
        )

        if command == "test-module":
            return_results(test_module(client))
        if command == "long-running-execution":
            demisto.debug("Starting long running execution")
            perform_long_running_loop(client)
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in Symantec Endpoint Security Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
