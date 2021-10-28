import demistomock as demisto
from CommonServerPython import *
from typing import Dict, List, Tuple, Any, Callable, Optional

import urllib3


# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = "Zoom Feed"
ZOOM_DOCS_IP_RANGES_URL = "https://assets.zoom.us/docs/ipranges"


class Client(BaseClient):
    """
    Client to use in the Zoom Feed integration. Overrides BaseClient.
    """

    def __init__(self, base_url: str, verify: bool = False, proxy: bool = False):
        """
        Implements class for Zoom feeds.
        :param url: the Zoom endpoint URL
        :verify: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param proxy: boolean, if *false* feed HTTPS server certificate will not use proxies. Default: *false*
        """
        super().__init__(base_url, verify=verify, proxy=proxy)

    def get_indicators(self) -> Set:
        """
        Uses 5 text files which contains zoom endpoints. This files are linked from:
        https://support.zoom.us/hc/en-us/articles/201362683-Network-Firewall-or-Proxy-Server-Settings-for-Zoom
        and contains all the endpoints listed on the zoom firewall rules tables, accept the domains and ipv6 addresses.
        Using the text files instead of parsing the http page ןs due to blockage of the zoom support site.
        """
        params = demisto.params()
        list_ips_txt_files = ['Zoom.txt',
                              'ZoomMeetings.txt',
                              'ZoomCRC.txt',
                              'ZoomPhone.txt',
                              'ZoomCDN.txt']

        indicators = set(argToList(params.get('zoom_clients_certificate_validation', [])))
        indicators.update(set(argToList(params.get('zoom_clients_user_browser', []))))

        for url in list_ips_txt_files:
            res = self._http_request(method='GET', url_suffix=url, resp_type='text')
            for ip in res.split('\n'):
                indicators.add(ip)
        return indicators

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """
        result = []

        try:
            indicators = list(self.get_indicators())

            for indicator in indicators:
                if auto_detect_indicator_type(indicator):
                    result.append(
                        {"value": indicator, "type": auto_detect_indicator_type(indicator), "FeedURL": self._base_url}
                    )

        except requests.exceptions.SSLError as err:
            demisto.debug(str(err))
            raise Exception(
                f"Connection error in the API call to {INTEGRATION_NAME}.\n"
                f"Check your not secure parameter.\n\n{err}"
            )
        except requests.ConnectionError as err:
            demisto.debug(str(err))
            raise Exception(
                f"Connection error in the API call to {INTEGRATION_NAME}.\n"
                f"Check your Server URL parameter.\n\n{err}"
            )
        except requests.exceptions.HTTPError as err:
            demisto.debug(str(err))
            raise Exception(f"Connection error in the API call to {INTEGRATION_NAME}.\n")
        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f"Could not parse returned data to Json. \n\nError massage: {err}")

        return result


def test_module(client: Client, *_) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    client.build_iterator()
    return "ok", {}, {}


def fetch_indicators(client: Client, feed_tags: List = [], tlp_color: Optional[str] = None,
                     limit: int = -1) -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
        tlp_color (str): Traffic Light Protocol color
    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]
    for item in iterator:
        value = item.get("value")
        type_ = item.get("type", FeedIndicatorType.Domain)
        raw_data = {
            "value": value,
            "type": type_,
        }
        for key, val in item.items():
            raw_data.update({key: val})
        indicator_obj = {
            "value": value,
            "type": type_,
            "service": "Zoom Feed",
            "rawJSON": raw_data,
            'fields': {}
        }
        if feed_tags:
            indicator_obj["fields"]['tags'] = feed_tags
        if tlp_color:
            indicator_obj["fields"]['trafficlightprotocol'] = tlp_color

        indicators.append(indicator_obj)
    return indicators


def get_indicators_command(
        client: Client, params: Dict[str, str], args: Dict[str, str]
) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = params.get('tlp_color')
    limit = int(args.get("limit", "10"))
    indicators = fetch_indicators(client, feed_tags, tlp_color, limit)
    human_readable = tableToMarkdown(
        "Indicators from Zoom Feed:", indicators, headers=["value", "type"], removeNull=True
    )

    return human_readable, {}, {"raw_response": indicators}


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = params.get('tlp_color')
    indicators = fetch_indicators(client, feed_tags, tlp_color)
    return indicators


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    insecure = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    try:
        client = Client(base_url=ZOOM_DOCS_IP_RANGES_URL, verify=insecure, proxy=proxy, )

        commands: Dict[
            str, Callable[[Client, Dict[str, str], Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]
        ] = {"test-module": test_module, "zoom-get-indicators": get_indicators_command}
        if command in commands:
            return_outputs(*commands[command](client, demisto.params(), demisto.args()))

        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, demisto.params())
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as err:
        err_msg = f"Error in {INTEGRATION_NAME} Integration. [{err}]"
        return_error(err_msg)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
