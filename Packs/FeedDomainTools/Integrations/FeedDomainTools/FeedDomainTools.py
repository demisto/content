import demistomock as demisto  # noqa: F401
import urllib3
import json

from CommonServerPython import *  # noqa: F401
from collections.abc import Callable, Iterator


# disable insecure warnings
urllib3.disable_warnings()

"""
GLOBALS
"""
PROXIES = handle_proxy()


class Client:
    """
    Client to use in the DomainTools Feed integration. Overrides BaseClient.
    Uses the domaintools sdk to wrap the API call to DomainTools.
    """

    APP_PARTNER = "cortex_xsoar_feed"
    APP_NAME = "feed-plugin"
    APP_VERSION = "1.0.0"

    NOD_FEED = "nod"
    NAD_FEED = "nad"

    FEED_API_BASE_URL = "https://api.domaintools.com/v1/feed"

    def __init__(
        self,
        api_username: str,
        api_key: str,
        verify_ssl: bool = True,
        always_sign_api_key: bool = False,
    ):
        self.feed_type = "nod"  # default to NOD feeds

        if not (api_username and api_key):
            raise DemistoException(
                "The 'API Username' and 'API Key' parameters are required."
            )

        self.proxy_url = (
            PROXIES.get("https") if PROXIES.get("https") != "" else PROXIES.get("http")
        )

        self.api_username = api_username
        self.api_key = api_key
        self.verify_ssl = verify_ssl

    def _http_request(self, params, **kwargs) -> list:
        headers = {"Content-Type": "application/json"}

        query_params = {
            **params,
            "api_key": self.api_key,
            "api_username": self.api_username,
            "app_partner": self.APP_PARTNER,
            "app_name": self.APP_NAME,
        }

        res = requests.request(
            method="GET",
            url=f"{self.FEED_API_BASE_URL}/{self.feed_type}/",
            params=query_params,
            headers=headers,
            verify=self.verify_ssl,
            timeout=60,
            proxies=self.proxy_url,
        )
        res.raise_for_status()
        response = res.text.strip().split("\n") if res.text else []

        demisto.info(f"Fetched {len(response)} of {self.feed_type} feeds.")

        return response

    def _get_dt_feeds(
        self,
        session_id: str | None = None,
        domain: str | None = None,
        after: str | None = None,
        top: int | None = None,
    ):
        feed_type_name = self.feed_type.upper()
        params = {
            "top": top,
            "sessionID": session_id,
            "after": after,
            "domain": domain,
        }

        demisto.info(
            f"Fetching DomainTools {feed_type_name} feed type with params: {params}"
        )

        return self._http_request(params=params)

    def build_iterator(
        self, feed_type: str = "nod", limit: int | None = None, **kwargs
    ) -> Iterator:
        """
        Retrieves all entries from the feed.

        Args:
            feed_type (str): The feed type to fetch. (e.g: "nod", "nad")
            limit (Optional[int], optional): The limit of result to return. Defaults to None.

        Raises:
            ValueError

        Returns:
            list:  A list of objects, containing the indicators.
        """
        self.feed_type = feed_type

        # DomainTools feeds optional arguments
        session_id = kwargs.get("session_id") or "dt-{}-cortex-integration".format(
            self.feed_type
        )
        top = kwargs.get("top") or 100_000  # default to 100_000
        domain = kwargs.get("domain") or None
        after = kwargs.get("after") or None

        demisto.info(f"Start building list of indicators for {self.feed_type} feed.")
        limit_counter = 0
        try:
            dt_feeds = self._get_dt_feeds(
                session_id=session_id,
                domain=domain,
                after=after,
                top=top,
            )
            for feed in dt_feeds:
                if limit and limit_counter >= limit:
                    break

                json_feed = json.loads(feed)

                timestamp = json_feed.get("timestamp") or ""
                indicator = json_feed.get("domain") or None
                indicator_type = auto_detect_indicator_type(indicator)

                if indicator is not None and indicator_type is not None:
                    yield {
                        "value": indicator,
                        "type": indicator_type,
                        "timestamp": timestamp,
                        "tags": ["DomainToolsFeeds", self.feed_type],
                    }

                    limit_counter += 1

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(
                f"Could not parse returned data as indicator. \n\nError massage: {err}"
            )


def fetch_indicators(
    client: Client, feed_type: str = "nod", limit: int | None = None, **kwargs
) -> list[dict]:
    """Retrieves indicators from the feed

    Args:
        client (Client): Client object with request.
        feed_type (str): The feed type to fetch.
        limit (int): limit the results.

    Returns:
        Indicators.
    """
    indicators = []
    try:
        # extract values from iterator
        for item in client.build_iterator(feed_type=feed_type, limit=limit, **kwargs):
            value_ = item.get("value")
            type_ = item.get("type")
            timestamp_ = item.get("timestamp")
            tags_ = item.get("tags")

            raw_data = {
                "value": value_,
                "type": type_,
                "timestamp": timestamp_,
                "service": "DomainTools Feeds",
                "tags": ",".join(tags_),
            }

            # Create indicator object for each value.
            indicator_obj = {
                "value": value_,
                "type": type_,
                "fields": {
                    "tags": tags_,
                },
                "rawJSON": raw_data,
            }
            indicators.append(indicator_obj)
    except Exception as e:
        raise Exception(f"Unable to fetch feeds from DomainTools. Reason: {str(e)}")

    return indicators


def get_indicators_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        args: demisto.args()
    Returns:
        Outputs.
    """

    limit = int(args.get("limit", "10"))
    feed_type = args.get("feed_type") or ""
    session_id = args.get("session_id")
    domain = args.get("domain")
    after = args.get("after")
    top = args.get("top")

    dt_feeds_kwargs = {
        "session_id": session_id,
        "after": after,
        "domain": domain,
        "top": top,
    }

    demisto.debug(f"Fetching feed indicators by feed_type: {feed_type}")
    indicators = fetch_indicators(
        client, feed_type=feed_type, limit=limit, **dt_feeds_kwargs
    )

    human_readable = tableToMarkdown(
        f"Indicators from DomainTools {feed_type.upper()} Feed:",
        indicators,
        headers=["value", "type", "fields", "rawJSON"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="",
        outputs_key_field="",
        raw_response=indicators,
        outputs={},
    )


def fetch_indicators_command(client: Client, **kwargs) -> list[dict]:
    """
    Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request
    Returns:
        Indicators.
    """

    DEFAULT_FEEDS_TO_PROCESS = {
        client.NOD_FEED: {"session_id": "dt-nod-cortex-integrations", "top": 10},
        client.NAD_FEED: {"session_id": "dt-nad-cortex-integrations", "top": 10},
    }

    fetched_indicators = []
    for feed_type, params in DEFAULT_FEEDS_TO_PROCESS.items():
        demisto.info(
            f"Fetching DomainTools {feed_type} feeds using `fetch_indicators_command`. {params}"
        )
        indicators = fetch_indicators(client, feed_type=feed_type, limit=10, **params)

        fetched_indicators.extend(indicators)

    return fetched_indicators


def test_module(client: Client, *_) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    try:
        next(client.build_iterator(limit=1, top=1))
    except Exception as e:
        raise Exception(
            "Could not fetch DomainTools Feed\n"
            f"\nCheck your API username/key and your connection to DomainTools. \nReason: {str(e)}"
        )

    return "ok"


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    commands: dict[str, Callable] = {
        "test-module": test_module,
        "dtfeeds-get-indicators": get_indicators_command,
    }

    api_username = params.get("api_username")
    api_key = params.get("api_key")
    insecure = not params.get("insecure", False)

    try:
        client = Client(api_username=api_username, api_key=api_key, verify_ssl=insecure)

        demisto.debug(f"Command being called is {command}")
        if command in commands:
            return_results(commands[command](client, args))

        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, **params)
            for iter_ in batch(indicators, batch_size=1000):
                demisto.createIndicators(iter_)
        else:
            raise NotImplementedError(f"Command {command} is not supported")

    except Exception as e:
        # Log exceptions and return errors
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
