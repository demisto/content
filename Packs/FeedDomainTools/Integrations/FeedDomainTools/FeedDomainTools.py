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


class DomainToolsClient(BaseClient):
    """
    Client to use in the DomainTools Feed integration.
    """

    APP_PARTNER = "cortex_xsoar_feed"
    APP_NAME = "feed-plugin"
    APP_VERSION = "1.0.0"

    NOD_FEED = "nod"
    NAD_FEED = "nad"

    FEED_URL = "/v1/feed"
    DOMAINTOOLS_API_BASE_URL = "https://api.domaintools.com"

    def __init__(
        self,
        api_username: str,
        api_key: str,
        verify_ssl: bool = True,
        proxy: bool = False,
        tags: str = "",
        tlp_color: str | None = None
    ):
        self.feed_type = "nod"  # default to NOD feeds
        self.tags = tags
        self.tlp_color = tlp_color

        if not (api_username and api_key):
            raise DemistoException(
                "The 'API Username' and 'API Key' parameters are required."
            )

        self.api_username = api_username
        self.api_key = api_key

        super().__init__(base_url=self.DOMAINTOOLS_API_BASE_URL, headers={
            "Content-Type": "application/json"}, verify=verify_ssl, proxy=proxy)

    def _get_dt_feeds(
        self,
        session_id: str | None = None,
        domain: str | None = None,
        after: str | None = None,
        before: str | None = None,
        top: int | None = None,
    ) -> list[str]:
        feed_type_name = self.feed_type.upper()

        query_params = {
            "api_key": self.api_key,
            "api_username": self.api_username,
            "app_partner": self.APP_PARTNER,
            "app_name": self.APP_NAME,
            "top": top,
            "sessionID": session_id,
            "after": after,
            "before": before,
            "domain": domain,
        }

        demisto.info(
            f"Fetching DomainTools {feed_type_name} feed type with params: {query_params}"
        )

        response = self._http_request("GET", url_suffix=f"{self.FEED_URL}/{self.feed_type}/",
                                      params=query_params, resp_type="text", raise_on_status=True)

        results = response.strip().split("\n") if response else []
        return results

    def _format_parameter(self, key: str, value: Any) -> Any:
        """Format the parameter value based on the given key

        Args:
            key (str): The parameter key.
            value (Any): The value of the parameter

        Returns:
            Any: The formatted value.
        """
        if key in ("after", "before") and "-" not in value:
            value = "-" + value

        return value

    def build_iterator(
        self, feed_type: str = "nod", **dt_feed_kwargs
    ) -> Iterator:
        """
        Retrieves all entries from the feed.

        Args:
            feed_type (str): The feed type to fetch. (e.g: "nod", "nad")
        Raises:
            ValueError

        Returns:
            list:  A list of objects, containing the indicators.
        """
        self.feed_type = feed_type

        # DomainTools feeds optional arguments
        session_id = dt_feed_kwargs.get("session_id", "dt-cortex-feeds")
        top = int(dt_feed_kwargs.get("top", "5000"))
        domain = dt_feed_kwargs.get("domain")
        after = dt_feed_kwargs.get("after")
        before = dt_feed_kwargs.get("before")

        demisto.info(f"Start building list of indicators for {self.feed_type} feed.")

        limit_counter = 0
        processed_feeds = 0

        try:
            # format the after parameter first make sure to append "-" if not given
            if after:
                after = self._format_parameter(key="after", value=after)

            if before:
                before = self._format_parameter(key="before", value=before)

            dt_feeds = self._get_dt_feeds(
                session_id=session_id,
                domain=domain,
                after=after,
                before=before,
                top=top,
            )

            total_dt_feeds = len(dt_feeds)
            demisto.info(f"Fetched {total_dt_feeds} of {self.feed_type} feeds.")

            ud_tags = [tag.strip() for tag in self.tags.split(",")]

            for feed in dt_feeds:
                if top and limit_counter >= top:
                    break

                json_feed = json.loads(feed)

                timestamp = json_feed.get("timestamp", "")
                indicator = json_feed.get("domain")
                indicator_type = auto_detect_indicator_type(indicator)

                if indicator and indicator_type:
                    yield {
                        "value": indicator,
                        "type": indicator_type,
                        "timestamp": timestamp,
                        "tags": ["DomainToolsFeeds", self.feed_type] + ud_tags,
                        "tlp_color": self.tlp_color,
                    }

                    limit_counter += 1
                    processed_feeds += 1

            demisto.info(f"Done processing {processed_feeds} out of {total_dt_feeds} {self.feed_type} feeds.")
        except Exception as err:
            demisto.debug(str(err))
            raise ValueError(
                f"Could not parse returned data as indicator. \n\nError massage: {str(err)}"
            )


def fetch_indicators(
    client: DomainToolsClient, feed_type: str = "nod", dt_feed_kwargs: dict[str, Any] = {}
) -> list[dict]:
    """Retrieves indicators from the feed

    Args:
        client (DomainToolsClient): DomainToolsClient object with request.
        feed_type (str): The feed type to fetch.

    Returns:
        Indicators.
    """
    indicators = []
    try:
        # extract values from iterator
        for idx, item in enumerate(client.build_iterator(feed_type=feed_type, **dt_feed_kwargs), start=1):
            value_ = item.get("value")
            type_ = item.get("type")
            timestamp_ = item.get("timestamp")
            tags_ = item.get("tags", [])
            tlp_color_ = item.get("tlp_color")

            indicator_tags = ",".join(tags_)

            raw_data = {
                "value": value_,
                "type": type_,
                "timestamp": timestamp_,
            }

            # Create indicator object for each value.
            indicator_obj = {
                "value": value_,
                "type": type_,
                "fields": {
                    "tags": indicator_tags,
                    "service": "DomainTools Feeds",
                },
                "rawJSON": raw_data,
            }

            if tlp_color_:
                indicator_obj["fields"]["trafficlightprotocol"] = tlp_color_

            indicators.append(indicator_obj)

            if idx % 1000 == 0 or (idx < 1000 and idx % 100 == 0):
                demisto.info(f"Processed {idx} indicator obj from {feed_type.upper()} feeds.")
    except Exception as e:
        raise Exception(f"Unable to fetch feeds from DomainTools. Reason: {str(e)}")

    return indicators


def get_indicators_command(client: DomainToolsClient, args: dict[str, str], params: dict[str, str]) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: DomainToolsClient object with request
        args: demisto.args()
    Returns:
        Outputs.
    """
    feed_type = args.get("feed_type", "nod")
    session_id = args.get("session_id")
    domain = args.get("domain")
    after = args.get("after")
    before = args.get("before")
    top = args.get("top")

    dt_feeds_kwargs = {
        "session_id": session_id,
        "after": after,
        "before": before,
        "domain": domain,
        "top": top,
    }

    demisto.debug(f"Fetching feed indicators by feed_type: {feed_type}")
    indicators = fetch_indicators(
        client, feed_type=feed_type, dt_feed_kwargs=dt_feeds_kwargs
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
        outputs={}
    )


def fetch_indicators_command(client: DomainToolsClient, params: dict[str, Any] = {}) -> list[dict]:
    """
    Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: DomainToolsClient object with request
    Returns:
        Indicators.
    """

    session_id = params.get("session_id")
    after = params.get("after")
    top = params.get("top")

    feed_type_ = params.get("feed_type", "ALL")

    FEEDS_TO_PROCESS = {
        client.NOD_FEED: {"top": top, "after": after, "session_id": session_id},
        client.NAD_FEED: {"top": top, "after": after, "session_id": session_id},
    }

    fetched_indicators = []

    for feed_type, dt_feed_kwargs in FEEDS_TO_PROCESS.items():
        indicators = []
        if feed_type_ == "ALL":
            indicators = fetch_indicators(client, feed_type=feed_type, dt_feed_kwargs=dt_feed_kwargs)
        if feed_type_ == feed_type.upper():
            indicators = fetch_indicators(client, feed_type=feed_type, dt_feed_kwargs=dt_feed_kwargs)

        fetched_indicators.extend(indicators)

    return fetched_indicators


def test_module(client: DomainToolsClient, args: dict[str, str], params: dict[str, str]) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: DomainToolsClient object.
    Returns:
        Outputs.
    """
    try:
        next(client.build_iterator(top=1, after=None))
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
        "domaintools-get-indicators": get_indicators_command,
    }

    api_username = params.get("credentials", {}).get("identifier", "")
    api_key = params.get("credentials", {}).get("password", "")
    insecure = not params.get("insecure", False)
    proxy = params.get('proxy', False)
    user_defined_tags = params.get("feedTags", "")
    tlp_color = params.get("tlp_color")

    try:
        client = DomainToolsClient(api_username=api_username, api_key=api_key, verify_ssl=insecure,
                                   proxy=proxy, tags=user_defined_tags, tlp_color=tlp_color)

        demisto.debug(f"Command being called is {command}")
        if command in commands:
            return_results(commands[command](client, args, params))

        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)
        else:
            raise NotImplementedError(f"Command {command} is not supported")

    except Exception as e:
        # Log exceptions and return errors
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
