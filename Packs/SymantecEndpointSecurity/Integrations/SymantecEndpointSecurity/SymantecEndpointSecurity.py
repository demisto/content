import demistomock as demisto
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from time import time as get_current_time_in_seconds

disable_warnings()


# CONSTANTS
VENDOR = "symantec"
PRODUCT = "endpoint_security"
DEFAULT_CONNECTION_TIMEOUT = 30


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


def get_events_command(client: Client): ...


def perform_long_running_loop(client: Client):
    while True:
        # Used to calculate the duration of the fetch run.
        start_run = get_current_time_in_seconds()
        try:
            integration_context = get_integration_context()
            demisto.debug(f"Starting new fetch with {integration_context=}")
            integration_context = integration_context.get("last_run")

            get_events_command(client)

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
