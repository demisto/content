from typing import Dict, List

import demistomock as demisto
import urllib3
from CommonServerPython import *

urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client to use in the Cyberint Feed integration.
    """

    def __init__(
        self,
        base_url: str,
        access_token: str,
        verify: bool = False,
        proxy: bool = False,
    ):
        self._cookies = {"access_token": access_token}
        super().__init__(base_url, verify=verify, proxy=proxy)

    def build_iterator(self) -> List:
        """
        Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        date_time = str((datetime.now().strftime("%Y-%m-%d")))

        response = self._http_request(
            method="GET",
            url_suffix=date_time,
            cookies=self._cookies,
            resp_type="text",
            timeout=70,
        )

        result = []
        feeds = response.strip().split("\n")
        ioc_feeds = [json.loads(feed) for feed in feeds]

        for indicator in ioc_feeds:
            indicator_value = indicator["ioc_value"]
            if indicator_type := auto_detect_indicator_type(indicator_value):
                result.append(
                    {
                        "value": indicator_value,
                        "type": indicator_type,
                        "FeedURL": self._base_url,
                        "rawJSON": indicator,
                    }
                )

        return result


def test_module(client: Client) -> str:
    """
    Builds the iterator to check that the feed is accessible.

    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.build_iterator()
    return "ok"


def fetch_indicators(
    client: Client,
    tlp_color: str,
    feed_names: list[str],
    indicator_types: list[str],
    confidence_from: int,
    severity_from: int,
    feed_tags: List = [],
    limit: int = -1,
) -> List[Dict]:
    """
    Retrieves indicators from the feed.

    Args:
        client (Client): Client object with request
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results

    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []

    for item in iterator:
        ioc_value = item.get("value")
        ioc_type = item.get("type")
        raw_data = item.get("rawJSON")
        if (
            ("All" in indicator_types or ioc_type in indicator_types)
            and ("All" in feed_names or raw_data.get("detected_activity") in feed_names)
            and (raw_data.get("confidence") >= confidence_from)
            and (raw_data.get("severity_score") >= severity_from)
        ):
            indicator_obj = {
                "value": ioc_value,
                "type": ioc_type,
                "service": "Cyberint",
                "rawJSON": raw_data,
                "fields": {
                    "reportedby": "Cyberint",
                    "Description": raw_data.get("description"),
                    "FirstSeenBySource": raw_data.get("observation_date"),
                },
            }

            if feed_tags:
                indicator_obj["fields"]["tags"] = feed_tags

            if tlp_color:
                indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

            indicators.append(indicator_obj)

        if len(indicators) >= limit:
            break

    return indicators


def get_indicators_command(client: Client, params: Dict[str, str], args: Dict[str, str]) -> CommandResults:
    """
    Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Cyberint API Client.
        params: Integration parameters.
        args: Command arguments.

    Returns:
        Outputs.
    """

    limit = int(args.get("limit", "10"))
    tlp_color = params.get("tlp_color")
    severity_from = arg_to_number(params.get("severity_from"))
    confidence_from = arg_to_number(params.get("confidence_from"))
    feed_tags = argToList(params.get("feedTags", ""))
    feed_names = argToList(params.get("feed_name"))
    indicator_types = argToList(params.get("indicator_type"))

    indicators = fetch_indicators(
        client=client,
        tlp_color=tlp_color,
        feed_tags=feed_tags,
        limit=limit,
        feed_names=feed_names,
        indicator_types=indicator_types,
        severity_from=severity_from,
        confidence_from=confidence_from,
    )

    human_readable = tableToMarkdown(
        "Indicators from Cyberint Feed:",
        indicators,
        headers=["value", "type"],
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Cyberint",
        outputs_key_field="value",
        raw_response=indicators,
        outputs=indicators,
    )


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """
    Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Cyberint API Client.
        params: Integration parameters.

    Returns:
        Indicators.
    """
    tlp_color = params.get("tlp_color")
    feed_tags = argToList(params.get("feedTags", ""))
    severity_from = arg_to_number(params.get("severity_from"))
    confidence_from = arg_to_number(params.get("confidence_from"))
    feed_names = argToList(params.get("feed_name"))
    indicator_types = argToList(params.get("indicator_type"))

    return fetch_indicators(
        client=client,
        tlp_color=tlp_color,
        feed_tags=feed_tags,
        feed_names=feed_names,
        indicator_types=indicator_types,
        severity_from=severity_from,
        confidence_from=confidence_from,
    )


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()

    base_url = params.get("url")
    access_token = params.get("access_token").get("password")
    insecure = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            access_token=access_token,
            verify=insecure,
            proxy=proxy,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == "cyberint-get-indicators":
            # This is the command that fetches a limited number of indicators from the feed source
            # and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == "fetch-indicators":
            # This is the command that initiates a request to the feed endpoint and create new indicators objects from
            # the data fetched. If the integration instance is configured to fetch indicators, then this is the command
            # that will be executed at the specified feed fetch interval.
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
