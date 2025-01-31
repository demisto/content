import http
from json import JSONDecodeError

import math

import demistomock as demisto
import urllib3
from CommonServerPython import *

import json
from typing import Any

urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%d"
DEFAULT_INTERVAL = 30  # 30 minutes
EXECUTION_TIMEOUT_SECONDS = 1200  # 20 minutes
MAX_LIMIT_SIZE_PER_EXEC = 100000
PAGE_SIZE = 20000


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
    def request_daily_feed(self, date_time: str = None, limit: int = 1000, execution_start_time: datetime = datetime.now(),
                           test: bool = False) -> list[dict[str, Any]]:
        """
        Retrieves all entries from the feed with pagination support.

        Args:
            date_time (str): The date-time value to use in the URL. Defaults to None.
            limit (int): The maximum number of entries to retrieve per request. Defaults to 1000.
            execution_start_time (datetime): The start time of the execution. Defaults to now.
            test (bool): If true, only return one page for testing connection.

        Returns:
            A list of objects, containing the indicators.
        """
        result = []
        init_offset = offset = demisto.getIntegrationContext().get('offset', 0)
        date_time = date_time or str(datetime.now().strftime(DATE_FORMAT))
        has_more = True

        demisto.debug(f'Fetching feed offset {offset}')

        while has_more:
            if offset >= init_offset + MAX_LIMIT_SIZE_PER_EXEC:
                demisto.setIntegrationContext({'date_time': date_time, 'offset': offset})
                has_more = False
                continue

            demisto.debug(f'Fetching feed offset {offset}')

            # if the execution exceeded the timeout we will break
            if not test and is_execution_time_exceeded(start_time=execution_start_time):
                demisto.debug(f'Execution time exceeded: {EXECUTION_TIMEOUT_SECONDS} seconds from: {execution_start_time}')
                has_more = False
                continue

            start_time = time.time()

            # Using the method to fetch and process the feed response
            indicators = self.process_feed_response(date_time, limit, offset)

            if not indicators:
                # No more data or an error occurred
                demisto.setIntegrationContext({'offset': 0})
                has_more = False
            else:
                result.extend(indicators)  # Append valid indicators to the result

                end_time = time.time()
                demisto.debug(f'Duration of offset processing {offset}: {math.ceil(end_time - start_time)} seconds')
                # Update the offset for the next request
                offset += limit
                has_more = True
                demisto.debug(f'Feed has more incidents for fetching: {has_more}')

            if test:  # if test module, end the loop
                demisto.debug('Test execution')
                has_more = False
                continue

        return result

    def process_feed_response(self, date_time: str, limit: int, offset: int) -> list[dict[str, Any]]:
        """
        Makes the API request to retrieve the indicators, handles JSON decoding, and processes the feed.

        Args:
            date_time (str): The date-time value to use in the URL.
            limit (int): The maximum number of entries to retrieve per request.
            offset (int): The offset to retrieve the correct page of results.

        Returns:
            A list of indicator dictionaries, or an empty list if no valid indicators are found.
        """
        result: List[Any] = []
        response = self.retrieve_indicators_from_api(date_time, limit, offset)

        try:
            # If json is invalid, return empty list (non 200 or invalid JSON)
            feeds = response.strip().split("\n")
            ioc_feeds = [json.loads(feed) for feed in feeds]
        except JSONDecodeError as e:
            demisto.error(f'Failed to decode JSON: {e}')
            return result  # Return empty result on failure

        if not ioc_feeds:  # No data found
            demisto.debug('No more indicators found')
            return result

        # Process valid feeds
        for indicator in ioc_feeds:
            ioc_value = indicator.get('ioc_value')
            if auto_detect_indicator_type(ioc_value):
                result.append(indicator)

        return result

    @logger
    def retrieve_indicators_from_api(self, date_time, limit, offset):
        url_suffix = f"{date_time}?limit={limit}&offset={offset}"
        demisto.debug(f'URL to fetch indicators: {url_suffix}')
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
        if exc.res and (exc.res.status_code == http.HTTPStatus.UNAUTHORIZED or exc.res.status_code == http.HTTPStatus.FORBIDDEN):
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
    demisto.debug("Fetching indicators")
    iterator = client.request_daily_feed(date_time, limit=PAGE_SIZE, execution_start_time=execution_start_time)
    indicators = []

    for item in iterator:
        if (
            ("All" in indicator_types or item.get("ioc_type") in indicator_types)
            and ("All" in feed_names or item.get("detected_activity") in feed_names)
            and (item.get("confidence") >= confidence_from)
            and (item.get("severity_score") >= severity_from)
        ):
            indicator_value = item["ioc_value"]
            if indicator_type := auto_detect_indicator_type(indicator_value):
                indicator_obj = {
                    "type": indicator_type,
                    "value": indicator_value,
                    "service": "Cyberint",
                    "rawJSON": item,
                    "fields": {
                        "reportedby": "Cyberint",
                        "firstseenbysource": item.get("observation_date"),
                        "detected_activity": item.get("detected_activity"),
                        "severity_score": item.get("severity_score"),
                        "confidence": item.get("confidence"),
                        "description": item.get("description")
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
    args: dict[str, Any],
) -> CommandResults:
    """
    Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Cyberint API Client.
        args: Command arguments.

    Returns:
        Outputs indicators.
    """

    date = args.get("date") or datetime.now().strftime("%Y-%m-%d")
    limit = int(args.get("limit", 0))
    offset = int(args.get("offset", 0))

    indicators = client.process_feed_response(date, limit, offset)

    human_readable = tableToMarkdown(
        "Indicators from Cyberint Feed:",
        indicators,
        headers=["detected_activity", "ioc_type", "ioc_value", "observation_date", "severity_score", "confidence", "description"],
        headerTransform=header_transformer,
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
    demisto.debug(f"Command being called is {command}")

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
            return_results(get_indicators_command(client, args))

        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params)
            demisto.debug(f'Total {len(indicators)} indicators to be submitted')
            for iter_ in batch(indicators, batch_size=5000):
                demisto.debug(f'Submit {len(iter_)} indicators to XSOAR')
                demisto.createIndicators(iter_)
            demisto.debug('Fetch indicators operation completed')

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


def header_transformer(header: str) -> str:
    """
    Returns a correct header.
    Args:
        header (Str): header.
    Returns:
        header (Str).
    """
    if header == 'detected_activity':
        return 'Detected activity'
    if header == 'ioc_type':
        return 'IoC type'
    if header == 'ioc_value':
        return 'IoC value'
    if header == 'observation_date':
        return 'Observation date'
    if header == 'severity_score':
        return 'Severity score'
    if header == 'confidence':
        return 'Confidence'
    if header == 'description':
        return 'Description'
    return string_to_table_header(header)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
