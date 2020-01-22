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
    ALL_TYPE = "all"
    TYPES = (DOMAIN_TYPE, IP_TYPE, ALL_TYPE)
    indicator_types_to_endpoint = {
        IP_TYPE: ["detailed-iprepdata.txt"],
        DOMAIN_TYPE: ["detailed-domainrepdata.txt"],
    }

    def _build_iterator(
        self, indicator_type: str = "all"
    ) -> Generator[dict, None, None]:
        endpoints = self.indicator_types_to_endpoint.get(
            indicator_type, self.indicator_types_to_endpoint.values()
        )
        for endpoint in endpoints:
            resp = self._http_request(
                "GET", endpoint, resp_type="text", timeout=(30, 60)
            )
            resp = resp.splitlines()
            csv_repr = csv.reader(resp)
            headers = next(csv_repr, None)
            headers = [header.replace(" ", "").replace("(|)", "") for header in headers]
            for line in csv_repr:
                yield {headers[i]: line[i] for i in range(len(headers))}

    def _build_iterator_domain(self) -> Generator[dict, None, None]:
        """Gives the user an

        Returns:

        """
        return self._build_iterator(self.DOMAIN_TYPE)

    def _build_iterator_ip(self) -> Generator[dict, None, None]:
        return self._build_iterator("ip")

    def get_indicators_domain(self) -> List[dict]:
        return [
            {
                "value": item["domain"],
                "type": FeedIndicatorType.Domain,
                "port": item["ports"],
                "rawJSON": item,
            }
            for item in self._build_iterator_domain()
        ]

    def get_indicators_ip(self) -> List[dict]:
        return [
            {
                "value": item["ip"],
                "type": FeedIndicatorType.IP,
                "port": item["ports"],
                "rawJSON": item,
            }
            for item in self._build_iterator_ip()
        ]

    def get_indicators(self) -> List[dict]:
        return self.get_indicators_domain() + self.get_indicators_ip()


def url_concat(*args) -> str:
    if args:
        url = "/".join(element.strip("/") for element in args if element)
        return url + "/" if args[-1].endswith("/") else url
    return ""


def module_test_command(client: Client, indicator_type: str) -> str:
    fetch_indicators_command(client, indicator_type)
    return "ok"


def fetch_indicators_command(client: Client, indicator_type: Optional[str]):
    if indicator_type == client.IP_TYPE:
        return client.get_indicators_ip()
    elif indicator_type == client.DOMAIN_TYPE:
        return client.get_indicators_domain()
    else:
        return client.get_indicators()


def get_indicators_command(client, args) -> Tuple[str, dict, list]:
    indicator_type = args.get("indicator_type")
    if indicator_type not in client.TYPES:
        return_error(
            f"{SOURCE_NAME}: Got indicator_type {indicator_type} but expected "
            f"one of {client.TYPES}"
        )
    limit = int(args.get("limit"))
    if indicator_type == client.ALL_TYPE:
        inside_limit = int((limit + 1) / 2)
        indicators_list = (
            client.get_indicators_ip()[:inside_limit]
            + client.get_indicators_domain()[:inside_limit]
        )
    else:
        indicators_list = fetch_indicators_command(client, indicator_type)
    hr = tableToMarkdown(
        f"Indicators from {SOURCE_NAME}",
        indicators_list[:limit],
        headers=["type", "value", "port"],
    )
    return hr, {}, indicators_list


def main():
    params = demisto.params()
    args = demisto.args()
    base_url = params.get("url", "https://rules.emergingthreats.net/")
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
