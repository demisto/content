import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """
import urllib3
import traceback
from typing import List, Dict, Optional, Tuple, Generator

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = "Cofense Feed"
_RESULTS_PER_PAGE = 50  # Max for Cofense is 100


class Client(BaseClient):
    """Implements class for miners of Cofense feed over http/https."""

    available_fields = ["all", "malware"]

    cofense_to_indicator = {
        "IPv4 Address": FeedIndicatorType.IP,
        "Domain Name": FeedIndicatorType.Domain,
        "URL": FeedIndicatorType.URL,
        "Email": FeedIndicatorType.Email,
    }

    def __init__(
            self,
            url: str,
            auth: Tuple[str, str],
            threat_type: Optional[str] = None,
            verify: bool = False,
            proxy: bool = False,
            read_time_out: Optional[float] = 120.0,
    ):
        """Constructor of Client and BaseClient

        Arguments:
            url {str} -- url for Cofense feed
            auth {Tuple[str, str]} -- (username, password)

        Keyword Arguments:
            threat_type {Optional[str]} -- One of available_fields (default: {None})
            verify {bool} -- Should verify certificate. (default: {False})
            proxy {bool} -- Should use proxy. (default: {False})
            read_time_out {int} -- Read time out in seconds. (default: {30})
        """
        self.read_time_out = read_time_out
        self.threat_type = (
            threat_type if threat_type in self.available_fields else "all"
        )

        # Request related attributes
        self.suffix = "/apiv1/threat/search/"

        super().__init__(url, verify=verify, proxy=proxy, auth=auth)

    def _http_request(self, *args, **kwargs) -> dict:
        if "timeout" not in kwargs:
            kwargs["timeout"] = (5.0, self.read_time_out)
        return super()._http_request(*args, **kwargs)

    def build_iterator(
            self, begin_time: Optional[int] = None, end_time: Optional[int] = None
    ) -> Generator:
        """Builds an iterator from given data filtered by start and end times.

        Keyword Arguments:
            begin_time {Optional[str, int]} --
                Where to start fetching.
                Timestamp represented in unix format. (default: {None})
            end_time {Optional[int]} --
                Time to stop fetching (if not supplied, will be time now).
                Timestamp represented in unix format. (default: {None}).
        Yields:
            Dict -- Threat from Cofense
        """
        # if not getting now
        if not end_time:
            end_time = get_now()

        payload = {
            "beginTimestamp": str(begin_time),
            "endTimestamp": str(end_time),
            "threatType": self.threat_type,
            "resultsPerPage": _RESULTS_PER_PAGE,
        }
        # For first fetch, there is only start time.
        if not begin_time:
            payload["beginTimestamp"] = str(end_time)
            del payload["endTimestamp"]

        demisto.debug(f"{INTEGRATION_NAME} - pulling {begin_time}/{end_time}")
        cur_page = 0
        total_pages = 1
        while cur_page < total_pages:
            payload["page"] = cur_page
            raw_response = self._http_request("post", self.suffix, params=payload)
            data = raw_response.get("data", {})
            if data:
                if total_pages <= 1:
                    # Call to get all pages.
                    total_pages = data.get("page", {}).get("totalPages")
                    if total_pages is None:
                        return_error('No "totalPages" in response')
                    demisto.debug(f"total_pages set to {total_pages}")

                threats = data.get("threats", [])
                for t in threats:
                    yield t
                demisto.debug(f"{INTEGRATION_NAME} - pulling {cur_page+1}/{total_pages}. page size: {_RESULTS_PER_PAGE}")
                cur_page += 1
            else:
                return_error(f'{INTEGRATION_NAME} - no "data" in response')

    @classmethod
    def _convert_block(cls, block: dict) -> Tuple[str, str]:
        """Gets a Cofense block from blockSet and enriches it.

        Args:
            block:

        Returns:
            indicator type, value
        """
        indicator_type = block.get("blockType", "")
        indicator_type = str(cls.cofense_to_indicator.get(indicator_type))
        # Only URL indicator has inside information in data_1
        if indicator_type == FeedIndicatorType.URL:
            value = block.get("data_1", {}).get("url")
        else:
            value = block.get("data_1")
            # If a domain has '*' in the value it is of type domainGlob
            if indicator_type == FeedIndicatorType.Domain and '*' in value:
                indicator_type = FeedIndicatorType.DomainGlob
        return indicator_type, value

    @classmethod
    def process_item(cls, threat: dict) -> List[dict]:
        """Gets a threat and processes them.

        Arguments:
            threat {dict} -- A threat from Cofense ("threats" key)

        Returns:
            list -- List of dicts representing indicators.

        Examples:
            >>> Client.process_item({"id": 123, "blockSet": [{"data_1": "ip", "blockType": "IPv4 Address"}]})
            [{'value': 'ip', 'type': 'IP', 'rawJSON': \
{'data_1': 'ip', 'blockType': 'IPv4 Address', 'value': 'ip', 'type': 'IP', 'threat_id': 123}}]
        """
        results = list()
        block_set: List[dict] = threat.get("blockSet", [])
        threat_id = threat.get("id")
        for block in block_set:
            indicator, value = cls._convert_block(block)
            block["value"] = value
            block["type"] = indicator
            block["threat_id"] = threat_id
            malware_family: dict = block.get("malwarefamily", {})
            ip_detail: dict = block.get("ipDetail", {})
            if indicator:
                results.append({
                    "value": value,
                    "type": indicator,
                    "rawJSON": block,
                    "fields": {
                        "name": threat_id,
                        "malwarefamily": malware_family.get("familyName"),
                        "description": malware_family.get("description"),
                        "sourceoriginalseverity": block.get("impact"),
                        "threattypes": {
                            "threatcategoryconfidence": block.get("confidence"),
                            "threatcategory": block.get("role")
                        },
                        "geocountry": ip_detail.get("countryIsoCode"),
                        "geolocation": f'{ip_detail.get("latitude", "")},{ip_detail.get("longitude", "")}' if ip_detail
                        else ""
                    }
                })

        return results


def test_module(client: Client) -> Tuple[str, dict, dict]:
    """A simple test module

    Arguments:
        client {Client} -- Client derives from BaseClient

    Returns:
        str -- "ok" if succeeded, else raises a error.
    """
    for _ in client.build_iterator():
        return "ok", {}, {}
    return "ok", {}, {}


def fetch_indicators_command(
        client: Client,
        begin_time: Optional[int] = None,
        end_time: Optional[int] = None,
        limit: Optional[int] = None,
) -> List[Dict]:
    """Fetches the indicators from client.

    Arguments:
        client {Client} -- Client derives from BaseClient

    Keyword Arguments:
        begin_time {Optional[int]} -- Time to start fetch from (default: {None})
        end_time {Optional[int]} -- Time to stop fetch to (default: {None})
        limit {Optional[int]} -- Maximum amount of indicators to fetch. (default: {None})

    Returns:
        List[Dict] -- List of indicators from threat
    """
    indicators = list()
    for threat in client.build_iterator(begin_time=begin_time, end_time=end_time):
        # get maximum of limit
        new_indicators = client.process_item(threat)
        indicators.extend(new_indicators)
        if limit and limit < len(indicators):
            indicators = indicators[:limit]
            break
    return indicators


def build_fetch_times(fetch_time: str, last_fetch: Optional[dict] = None) -> Tuple[int, int]:
    """Build the start and end time of the fetch session.

    Args:
        fetch_time: fetch time (for example: "3 days")
        last_fetch: Last fetch object

    Returns:
        begin_time, end_time
    """
    if isinstance(last_fetch, dict) and last_fetch.get("timestamp"):
        begin_time = last_fetch.get("timestamp", 0)  # type: int
        end_time = get_now()
    else:  # First fetch
        begin_time, end_time = parse_date_range_no_milliseconds(fetch_time)
    return begin_time, end_time


def parse_date_range_no_milliseconds(from_time: str) -> Tuple[int, int]:
    """Gets a range back and return time before the string and to now.
    Without milliseconds.

    Args:
        from_time:The date range to be parsed (required)

    Returns:
        start time, now

    Examples:
        >>> parse_date_range_no_milliseconds("3 days")
        (1578729151, 1578988351)
    """
    begin_time, end_time = parse_date_range(from_time, to_timestamp=True)
    return int(begin_time / 1000), int(end_time / 1000)


def get_indicators_command(client: Client, args: dict) -> Tuple[str, list]:
    """Getting indicators into Demisto's incident.

    Arguments:
        client {Client} -- A client object
        args {dict} -- Usually demisto.args()

    Returns:
        Tuple[str, list] -- human_readable, raw_response
    """
    limit = int(args.get("limit", 10))
    from_time = args.get("from_time", "3 days")
    begin_time, end_time = build_fetch_times(from_time)
    indicators = fetch_indicators_command(
        client, begin_time=begin_time, end_time=end_time, limit=limit)
    human_readable = tableToMarkdown(
        f"Results from {INTEGRATION_NAME}:",
        [indicator.get("rawJSON") for indicator in indicators],
        ["threat_id", "type", "value", "impact", "confidence", "roleDescription"],
    )
    return human_readable, indicators


def get_now() -> int:
    """Returns time now without milliseconds

    Returns:
        int -- time now without milliseconds.
    """
    return int(datetime.now().timestamp() / 1000)


def main():
    """Main function
    """
    params = demisto.params()
    # handle params
    url = "https://www.threathq.com"
    credentials = params.get("credentials", {})
    if not credentials:
        raise DemistoException("Credentials are empty. "
                               "Fill up the username/password fields in the integration configuration.")

    auth = (credentials.get("identifier"), credentials.get("password"))
    verify = not params.get("insecure")
    proxy = params.get("proxy")
    threat_type = params.get("threat_type")
    client = Client(url, auth=auth, verify=verify, proxy=proxy, threat_type=threat_type)

    demisto.info(f"Command being called is {demisto.command()}")
    try:
        if demisto.command() == "test-module":
            return_outputs(*test_module(client))

        elif demisto.command() == "fetch-indicators":
            begin_time, end_time = build_fetch_times(params.get("fetch_time", "3 days"))
            indicators = fetch_indicators_command(client, begin_time, end_time)
            # Send indicators to demisto
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif demisto.command() == "cofense-get-indicators":
            # dummy command for testing
            readable_outputs, raw_response = get_indicators_command(client, demisto.args())
            return_outputs(readable_outputs, {}, raw_response=raw_response)

    except Exception as err:
        return_error(f"Error in {INTEGRATION_NAME} integration:\n{str(err)}\n\nTrace:{traceback.format_exc()}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
