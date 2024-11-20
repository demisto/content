import http
from json import JSONDecodeError

import demistomock as demisto
import urllib3
from CommonServerPython import *

import json
from typing import Any, List, Dict

urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%d"
DEFAULT_INTERVAL = 240
PAGE_SIZE = 20000
EXECUTION_TIMEOUT_SECONDS = 1200  # 20 minutes


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
        params = demisto.params()
        self._cookies = {"access_token": access_token}
        self._headers = {
            "X-Integration-Type": "XSOAR",
            "X-Integration-Instance-Name": demisto.integrationInstance(),
            "X-Integration-Instance-Id": "",
            "X-Integration-Customer-Name": params.get("client_name", ""),
            "X-Integration-Version": "1.1.4"
        }
        super().__init__(base_url, verify=verify, proxy=proxy)


    @logger
    def request_daily_feed(self, date_time: str = None, limit: int = 1000, execution_start_time: datetime = datetime.now(), test: bool = False) -> List[Dict[str, Any]]:
        """
        Retrieves all entries from the feed with pagination support.

        Args:
            date_time (str): The date-time value to use in the URL. Defaults to None.
            limit (int): The maximum number of entries to retrieve per request. Defaults to 100.
            execution_start_time (datetime): The start time of the execution. Defaults to now.
            test (bool): If true, only return one page for testing connection.

        Returns:
            A list of objects, containing the indicators.
        """
        result = []
        offset = 0
        has_more = True

        while has_more:
            demisto.debug(f'Fetching feed offset {offset}')

            # if the execution exceeded the timeout we will break
            if not test:
                if is_execution_time_exceeded(start_time=execution_start_time):
                    demisto.debug(f'Execution time exceeded: {EXECUTION_TIMEOUT_SECONDS} seconds from: {execution_start_time}')
                    return result

            start_time = time.time()
            response = self.retrieve_indicators_from_api(date_time, limit, offset)

            try: # if json invalid (for example, non 200), end the loop
                feeds = response.strip().split("\n")
                ioc_feeds = [json.loads(feed) for feed in feeds]
            except JSONDecodeError as e:
                demisto.error(f'Failed to decode JSON: {e}')
                has_more = False
                continue

            if not ioc_feeds:  # if no data is returned, end the loop
                demisto.debug('No more indicators found')
                has_more = False
            else:
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

                end_time = time.time()
                demisto.debug(f'Duration of offset processing {offset}: {end_time - start_time} seconds')
                # Update the offset for the next request
                offset += limit
                has_more = True
                demisto.debug(f'has_more = {has_more}')

            if test:  # if test module, end the loop
                demisto.debug('Test execution')
                has_more = False
                continue

        return result


    @logger
    def retrieve_indicators_from_api(self, date_time, limit, offset):
        url_suffix = f"{date_time or get_today_time()}?limit={limit}&offset={offset}"
        demisto.debug('URL to fetch indicators: {}'.format(url_suffix))
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            cookies=self._cookies,
            resp_type="text",
            timeout=120,
            retries=3,
        )
        return response


def test_module(client: Client) -> str:
    """
    Builds the iterator to check that the feed is accessible.

    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    try:
        client.request_daily_feed(limit=10, test=True)
    except DemistoException as exc:
        if exc.res:
            if exc.res.status_code == http.HTTPStatus.UNAUTHORIZED or exc.res.status_code == http.HTTPStatus.FORBIDDEN:
                return "Authorization Error: invalid `API Token`"

        raise exc

    return "ok"


def fetch_indicators(
    client: Client,
    tlp_color: str,
    feed_names: list[str],
    indicator_types: list[str],
    confidence_from: int,
    severity_from: int,
    date_time: str = None,
    feed_tags: List = [],
    limit: int = -1,
    execution_start_time: datetime = datetime.now(),
) -> list[dict[str, Any]]:
    """
    Retrieves indicators from the feed.

    Args:
        client (Client): API Client.
        tlp_color (str):  The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed.
        feed_names (list): The feed names.
        indicator_types (list): Which indicator types to fetch.
        confidence_from (int): The value of confidence to fetch indicators from.
        severity_from (int): The value of severity to fetch indicators from.
        date_time (str): Date time string to fetch indicators from.
        feed_tags (list): tags to assign fetched indicators.
        limit (int): The maximum number of results to return.
        execution_start_time (datetime): The start time of the execution. Defaults to now.

    Returns:
        Indicators.
    """
    iterator = client.request_daily_feed(date_time, limit = PAGE_SIZE, execution_start_time = execution_start_time)
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
                    "description": raw_data.get("description"),
                    "firstseenbysource": raw_data.get("observation_date"),
                },
            }

            if feed_tags:
                indicator_obj["fields"]["tags"] = feed_tags

            if tlp_color:
                indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

            indicators.append(indicator_obj)

        if limit > 0 and len(indicators) >= limit:
            demisto.debug(f'Indicators limit reached (total): {len(indicators)}')
            break

    return indicators


def get_indicators_command(
    client: Client,
    params: dict[str, Any],
    args: dict[str, Any],
) -> CommandResults:
    """
    Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Cyberint API Client.
        params: Integration parameters.
        args: Command arguments.

    Returns:
        Outputs.
    """

    limit = arg_to_number(args.get("limit")) or 50
    tlp_color = params.get("tlp_color", "")
    severity_from = arg_to_number(params.get("severity_from")) or 0
    confidence_from = arg_to_number(params.get("confidence_from")) or 0
    feed_tags = argToList(params.get("feedTags"))
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


def fetch_indicators_command(
    client: Client,
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Cyberint API Client.
        params: Integration parameters.

    Returns:
        Indicators.
    """
    tlp_color = params.get("tlp_color", "")
    feed_tags = argToList(params.get("feedTags"))
    severity_from = arg_to_number(params.get("severity_from")) or 0
    confidence_from = arg_to_number(params.get("confidence_from")) or 0
    feed_names = argToList(params.get("feed_name"))
    indicator_types = argToList(params.get("indicator_type"))
    fetch_interval = arg_to_number(params.get("feedFetchInterval")) or DEFAULT_INTERVAL

    indicators = []

    # if now-interval is yesterday, call feeds for yesterday too
    if is_x_minutes_ago_yesterday(fetch_interval):
        indicators = fetch_indicators(
            client=client,
            date_time=get_yesterday_time(),
            tlp_color=tlp_color,
            feed_tags=feed_tags,
            feed_names=feed_names,
            indicator_types=indicator_types,
            severity_from=severity_from,
            confidence_from=confidence_from,
        )

    indicators += fetch_indicators(
        client=client,
        tlp_color=tlp_color,
        feed_tags=feed_tags,
        feed_names=feed_names,
        indicator_types=indicator_types,
        severity_from=severity_from,
        confidence_from=confidence_from,
    )
    return indicators


def get_today_time() -> str:
    """Get current date time.

    Returns:
        str: Today date string.
    """
    return datetime.now().strftime(DATE_FORMAT)


def get_yesterday_time() -> str:
    """Get yesterday date time.

    Returns:
        str: Yesterday date string.
    """
    current_time = datetime.now()
    yesterday = current_time - timedelta(days=1)
    return yesterday.strftime(DATE_FORMAT)


def is_x_minutes_ago_yesterday(minutes: int) -> bool:
    """Check if x minutes ago is yesterday.

    Args:
        minutes (int): The amount of minutes to reduce from today.

    Returns:
        bool: True if x minutes ago is yesterday, else False.
    """
    current_time = datetime.now()
    x_minutes_ago = current_time - timedelta(minutes=minutes)
    yesterday = current_time - timedelta(days=1)
    return x_minutes_ago.date() == yesterday.date()


@logger
def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()

    url = params.get("url")
    base_url = f"{url}/ioc/api/v1/feed/daily/"
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
            return_results(test_module(client))

        elif command == "cyberint-get-indicators":
            return_results(get_indicators_command(client, params, args))

        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params)
            demisto.debug(f'Total {len(indicators)} indicators')
            for iter_ in batch(indicators, batch_size=5000):
                demisto.debug(f'About to push {len(iter_)} indicators to XSOAR')
                demisto.createIndicators(iter_)
            demisto.debug(f'{command} operation completed')

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


@logger
def is_execution_time_exceeded(start_time: datetime) -> bool:
    """
    Checks if the execution time so far exceeded the timeout limit.

    Args:
        start_time (datetime): the time when the execution started.

    Returns:
        bool: true, if execution passed timeout settings, false otherwise.
    """
    end_time = datetime.utcnow()
    secs_from_beginning = (end_time - start_time).seconds
    demisto.debug(f'Execution duration is {secs_from_beginning} secs so far')

    return secs_from_beginning > EXECUTION_TIMEOUT_SECONDS


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
