import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """
import urllib3
import csv
from typing import Generator, Tuple, Optional, List

# disable insecure warnings
urllib3.disable_warnings()

SOURCE_NAME = "Proofpoint Feed"


class Client(BaseClient):
    def __init__(self, base_url, auth_code, **kwargs):
        base_url = url_concat(base_url, auth_code, "reputation")
        super().__init__(base_url, **kwargs)

    DOMAIN_TYPE = "domain"
    IP_TYPE = "ip"
    IP_URL = "detailed-iprepdata.txt"
    DOMAIN_URL = "detailed-domainrepdata.txt"
    ALL_TYPE = "all"
    TYPES = (DOMAIN_TYPE, IP_TYPE, ALL_TYPE)
    indicator_types_to_endpoint = {
        IP_TYPE: [IP_URL],
        DOMAIN_TYPE: [DOMAIN_URL],
        ALL_TYPE: [DOMAIN_URL, IP_URL],
    }
    _CATEGORY_NAME = [
        "CnC",
        "Bot",
        "Spam",
        "Drop",
        "SpywareCnC",
        "OnlineGaming",
        "DriveBySrc",
        "ChatServer",
        "TorNode",
        "Compromised",
        "P2P",
        "Proxy",
        "IPCheck",
        "Utility",
        "DDoSTarget",
        "Scanner",
        "Brute_Forcer",
        "FakeAV",
        "DynDNS",
        "Undesirable",
        "AbusedTLD",
        "SelfSignedSSL",
        "Blackhole",
        "RemoteAccessService",
        "P2PCnC",
        "Parking",
        "VPN",
        "EXE_Source",
        "Mobile_CnC",
        "Mobile_Spyware_CnC",
        "Skype_SuperNode",
        "Bitcoin_Related",
        "DDoSAttacker"
    ]

    def _build_iterator(
            self, indicator_type: str = ALL_TYPE
    ) -> Generator[dict, None, None]:
        endpoints = self.indicator_types_to_endpoint[indicator_type]
        for endpoint in endpoints:
            resp = self._http_request(
                "GET", endpoint, resp_type="text", timeout=(30, 60)
            )
            resp = resp.splitlines()
            csv_repr = csv.reader(resp)
            headers: list = next(csv_repr)
            headers = [header.replace(" ", "").replace("(|)", "") for header in headers]
            for line in csv_repr:
                item: dict = {headers[i]: line[i] for i in range(len(headers))}
                try:
                    category = item["category"]
                    item["category_name"] = self._CATEGORY_NAME[int(category) - 1]
                except (KeyError, IndexError):
                    item["category_name"] = "Unknown"
                # add type/value to item.
                if "domain" in item:
                    item["type"] = FeedIndicatorType.Domain
                    item["value"] = item.get("domain")
                elif "ip" in item:
                    item["type"] = FeedIndicatorType.IP
                    item["value"] = item.get("ip")
                yield item

    @staticmethod
    def _process_item(item: dict) -> dict:
        return {
            "value": item["value"],
            "type": item["type"],
            "rawJSON": item,
            "CustomFields": {
                "port": item.get("ports", "").split() if isinstance(item.get("ports"), str) else item.get("ports")
            }
        }

    def _build_iterator_domain(self) -> Generator[dict, None, None]:
        """Gets back a dict of domain attributes.

        Returns:
            Generator of dicts.

        """
        return self._build_iterator(self.DOMAIN_TYPE)

    def _build_iterator_ip(self) -> Generator[dict, None, None]:
        """Gets back a dict of ip attributes.

        Returns:
            Generator of dicts.

        """
        return self._build_iterator(self.IP_TYPE)

    def get_indicators_domain(self) -> List[dict]:
        """ Gets indicator's dict of domains

        Returns:
            list of indicators
        """
        return [
            self._process_item(item)
            for item in self._build_iterator_domain()
        ]

    def get_indicators_ip(self) -> List[dict]:
        """ Gets indicator's dict of ips

        Returns:
            list of indicators
        """
        return [
            self._process_item(item)
            for item in self._build_iterator_ip()
        ]

    def get_indicators(self) -> List[dict]:
        """ Gets indicator's dict of domains and ips

        Returns:
            list of indicators
        """
        return self.get_indicators_domain() + self.get_indicators_ip()


def url_concat(*args: str) -> str:
    """ Joining arguments into a url

    Examples:
        >>> url_concat("https://example.com", "apitoken/", "/path_to_thing/", "file.exe")
        'https://example.com/apitoken/path_to_thing/file.exe'

    Args:
        *args: str representing url paths

    Returns:
        url
    """
    if args:
        url = "/".join(element.strip("/") for element in args if element)
        return url + "/" if args[-1].endswith("/") else url
    return ""


def module_test_command(client: Client, indicator_type: str) -> str:
    """ Simple command that checks if the api is working

    Args:
        client: Client object
        indicator_type: one of ['ip', 'domain', 'all']

    Returns:
        'ok' if working, else raises an error
    """
    fetch_indicators_command(client, indicator_type)
    return "ok"


def fetch_indicators_command(client: Client, indicator_type: Optional[str]):
    """ Retrieving indicators from the API

    Args:
        client: Client object
        indicator_type: one of ['ip', 'domain', 'all']

    Returns:

    """
    if indicator_type == client.IP_TYPE:
        return client.get_indicators_ip()
    elif indicator_type == client.DOMAIN_TYPE:
        return client.get_indicators_domain()
    else:
        return client.get_indicators()


def get_indicators_command(client: Client, args: dict) -> Tuple[str, dict, list]:
    """ Gets indicator to context

    Args:
        client: Client object
        args: demisto.args()

    Returns:
        readable_output, context, raw_response
    """
    indicator_type = args.get("indicator_type")
    if indicator_type not in client.TYPES:
        return_error(
            f"{SOURCE_NAME}: Got indicator_type {indicator_type} but expected "
            f"one of {client.TYPES}"
        )
    limit = int(args.get("limit", 50))
    if limit < 1:
        limit = 1
    indicators_list = fetch_indicators_command(client, indicator_type)[:limit]
    hr = tableToMarkdown(
        f"Indicators from {SOURCE_NAME}",
        indicators_list[:limit],
        headers=["type", "value"],
    )
    return hr, {}, indicators_list


def main():
    params = demisto.params()
    args = demisto.args()
    base_url = "https://rules.emergingthreats.net/"
    client = Client(
        base_url=base_url,
        auth_code=params.get("auth_code"),
        verify=not params.get("insecure", False),
        proxy=params.get("proxy"),
    )
    command = demisto.command()
    demisto.info("Command being called is {}".format(command))
    # Switch case
    try:
        if command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params.get("indicator_type"))
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        elif command == "test-module":
            return_outputs(module_test_command(client, params.get("indicator_type")))
        elif command == "proofpoint-get-indicators":
            readable_output, outputs, raw_response = get_indicators_command(
                client, args
            )
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        return_error(
            f"Error in {SOURCE_NAME} Integration - Encountered an issue with createIndicators"
            if "failed to create" in str(e)
            else f"Error in {SOURCE_NAME} Integration [{e}]"
        )


if __name__ == "builtins":
    main()
