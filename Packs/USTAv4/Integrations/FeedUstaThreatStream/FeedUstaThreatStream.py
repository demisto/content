import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

USTA_API_PREFIX = 'api/threat-stream/v4/'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

class Client(BaseClient):
    def __init__(self, base_url, verify, proxy, headers):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def check_auth(self):
        self._http_request('GET', 'malicious-urls', error_handler=self._http_error_handler)

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []

        res = self._http_request(
            "GET",
            url_suffix="",
            full_url=self._base_url,
            resp_type="text",
        )

        # In this case the feed output is in text format, so extracting the indicators from the response requires
        # iterating over it's lines solely. Other feeds could be in other kinds of formats (CSV, MISP, etc.), or might
        # require additional processing as well.
        try:
            indicators = res.split("\n")

            for indicator in indicators:
                # Infer the type of the indicator using 'auto_detect_indicator_type(indicator)' function
                # (defined in CommonServerPython).
                if auto_detect_indicator_type(indicator):
                    result.append(
                        {
                            "value": indicator,
                            "type": auto_detect_indicator_type(indicator),
                            "FeedURL": self._base_url,
                        }
                    )

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(
                f"Could not parse returned data as indicator. \n\nError massage: {err}"
            )
        return result

    @staticmethod
    def _http_error_handler(response):
        # Handle error responses here to proper error messages to the user
        if response.status_code == 401:
            raise DemistoException('Authorization Error: make sure API Key is correctly set')
        if response.status_code == 429:
            raise DemistoException('Rate limit exceeded. Please try again later..!')
def test_module(client: Client) -> str:
    try:
        client.check_auth()
    except DemistoException as e:
        if 'Connection Timeout Error' in str(e):
            return 'Connection error. Unable to connect to the USTA API! Make sure that your IP is whitelisted in the USTA.'
        raise e
    return 'ok'


def fetch_indicators(
    client: Client,
    tlp_color: Optional[str] = None,
    feed_tags: List = [],
    limit: int = -1,
) -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        value_ = item.get("value")
        type_ = item.get("type")
        raw_data = {
            "value": value_,
            "type": type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})
        indicator_obj = {
            # The indicator value.
            "value": value_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            "type": type_,
            # The name of the service supplying this feed.
            "service": "HelloWorld",
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            "fields": {},
            # A dictionary of the raw data returned from the feed source about the indicator.
            "rawJSON": raw_data,
        }

        if feed_tags:
            indicator_obj["fields"]["tags"] = feed_tags

        if tlp_color:
            indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(
    client: Client, params: Dict[str, str], args: Dict[str, str]
) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    limit = int(args.get("limit", "10"))
    tlp_color = params.get("tlp_color")
    feed_tags = argToList(params.get("feedTags", ""))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)
    human_readable = tableToMarkdown(
        "Indicators from HelloWorld Feed:",
        indicators,
        headers=["value", "type"],
        headerTransform=string_to_table_header,
        removeNull=True,
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="",
        outputs_key_field="",
        raw_response=indicators,
        outputs={},
    )


def fetch_indicators_command(client: Client, params: Dict[str, Any]) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = params.get("tlp_color")
    indicators = fetch_indicators(client, tlp_color, feed_tags)
    return indicators

def main():
    # demisto params and args
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()

    # Instance parameters
    verify_certificate: bool = not params.get('insecure', False)
    base_url = urljoin(params['url'], USTA_API_PREFIX)
    proxy = params.get('proxy', False)
    api_key = params.get('api_key')
    cmd = demisto.command()

    demisto.debug(f"Command being called is {cmd}")

    try:
        headers: dict = {
            'Authorization': f'token {api_key}',
            'Content-Type': 'application/json'
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )
        
        commands = {
            #'usta-atp-search-username': compromised_credentials_search_command,
        }

        if cmd == "test-module":
            return_results(test_module(client))

        elif cmd == "helloworld-get-indicators":
            return_results(get_indicators_command(client, params, args))

        elif cmd == "fetch-indicators":
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)
        elif cmd in commands:
            return_results(commands[cmd](client, args))
        else:
            raise NotImplementedError(f"Command {cmd} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f"Failed to execute {cmd} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
