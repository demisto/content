import demistomock as demisto
from CommonServerPython import *
import urllib3
import base64

MAX_EVENTS = 500
# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DATE_FORMAT_FOR_TOKEN = "%m/%d/%Y, %H:%M:%S"
VENDOR = "Druva"
PRODUCT = "Druva"

""" CLIENT CLASS """


class Client(BaseClient):

    def __init__(self, base_url: str, client_id: str, secret_key: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.credentials = f"{client_id}:{secret_key}"
        self.login()

    def login(self):
        """
        In this method, the validity of the Access Token is checked, since the Access Token has a 30 minutes validity period.
        Refreshes the token as needed.
        """
        now = datetime.utcnow()

        if (cache := get_integration_context()) and (token := cache.get("Token")):
            expiration_time = datetime.strptime(
                cache["expiration_time"], DATE_FORMAT_FOR_TOKEN
            )

            # check if token is still valid, and use the old one. otherwise regenerate a new one
            if (expiration_time - now).total_seconds() > 0:
                demisto.debug("No need to regenerate the token, it is still valid")
                self._set_headers(token)
                return

        demisto.debug("Since the cache is empty or the token has expired, regenerate a new token")
        raw_token, expires_in_seconds = self._refresh_access_token()
        self._set_headers(raw_token)

        #  token["expires_in"] - 60 seconds for safety
        set_integration_context(
            {
                "Token": raw_token,
                "expiration_time": (
                    now + timedelta(seconds=(expires_in_seconds - 60))
                ).strftime(DATE_FORMAT_FOR_TOKEN),
            }
        )

    def _refresh_access_token(self) -> tuple[str, int]:
        """
        Since the validity of the Access Token is 30 minutes, this method refreshes it and returns the new token json.
        returns:
            - the token
            - the expiration in seconds
        """
        encoded_credentials = base64.b64encode(self.credentials.encode())
        decoded_credentials = encoded_credentials.decode("utf-8")

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {decoded_credentials}",
        }
        data = {"grant_type": "client_credentials", "scope": "read"}

        try:
            response_json = self._http_request(
                method="POST", url_suffix="/token", headers=headers, data=data
            )
        except Exception as e:
            # 400 - "invalid_grant" - reason: invalid Server URL, Client ID or Secret Key.
            if isinstance(e, DemistoException) and e.res is not None and e.res.status_code == 400:
                informative_message = "Make sure Server URL, Client ID and Secret Key are correctly entered."
                raise DemistoException(
                    f"Error in test-module: {informative_message}"
                ) from e
            raise
        return response_json["access_token"], response_json["expires_in"]

    def search_events(self, tracker: Optional[str] = None) -> dict:
        """
        Searches for Druva events.

        Args:
            tracker: pointer to the last event we got last time

        Returns:
            dict: List of events
        """

        url_suffix_tracker = f"?tracker={tracker}" if tracker else ""
        headers = (self._headers or {}) | {
            "accept": "application/json"
        }  # self._headers won't really be None, just for mypy
        try:
            response = self._http_request(
                method="GET",
                url_suffix=f"/insync/eventmanagement/v2/events{url_suffix_tracker}",
                headers=headers,
            )
        except Exception as e:
            # 403 - "User is not authorized to access this resource with an explicit deny" - reason: tracker is expired
            # 400 - "Invalid tracker"
            raise DemistoException(f"Error in search-events: {str(e)}") from e
        return response

    def _set_headers(self, token: str):
        self._headers = {"Authorization": f"Bearer {token}"}


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Druva client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    get_events(client=client)
    return "ok"


def get_events(client: Client, tracker: Optional[str] = None) -> tuple[list[dict], str]:
    """
    Gets events from Druva API in one batch (max 500), if a tracker is given, the API returns events starting from its timestamp.
    Args:
        client: Druva client to use.
        tracker: A string received in a previous run, marking the point in time from which we want to fetch.

    Returns:
        Druva's events and tracker
    """

    response = client.search_events(tracker)
    return response["events"], response["tracker"]


def fetch_events(
    client: Client, last_run: dict[str, str]
) -> tuple[list[dict], dict[str, str]]:
    """
    Args:
        client (Client): Druva client to use.
        last_run (dict): A dict with a key containing a pointer to the latest event created time we got from last fetch.
    Returns:
        new_tracker (dict): Next run dict containing the next tracker (a pointer to the next event).
        events (list): List of events that will be created in XSIAM.
    """

    tracker = last_run.get("tracker")  # None on first run
    demisto.debug(f"fetching events, {tracker=}")
    events, new_tracker = get_events(client, tracker)
    demisto.debug(f"fetched {len(events or [])} events, {new_tracker=}")

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {"tracker": new_tracker}

    demisto.debug(f"Setting next run {next_run}.")
    return events, next_run


""" MAIN FUNCTION """


def add_time_to_events(events: list[dict]):
    """
    Adds the _time key to the events.
    Args:
        events: list[dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(event["timestamp"])
            event["_time"] = create_time.strftime(DATE_FORMAT)  # type: ignore[union-attr]


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=params["url"],
            client_id=params["credentials"]["identifier"],
            secret_key=params["credentials"]["password"],
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == "druva-get-events":
            events, tracker = get_events(client, args.get("tracker"))
            return_results(
                CommandResults(
                    readable_output=tableToMarkdown(f"{VENDOR} Events:", events),
                    outputs=tracker,
                    outputs_prefix=f"{VENDOR}.tracker",
                    outputs_key_field="tracker",
                    replace_existing=True,
                )
            )
            if argToBoolean(args["should_push_events"]):
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            events, next_run = fetch_events(
                client=client,
                last_run=demisto.getLastRun(),
            )

            add_time_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
