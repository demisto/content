from CommonServerPython import *
import demistomock as demisto
import requests
import re

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type:ignore


class Client(BaseClient):
    """Client for Augur Feed - gets indicator lists from Daily threat feeds

    Attributes:
        api_key(str): The API key for Augur.
        insecure(bool): Use SSH on http request.
        proxy(str): Use system proxy.
    """

    def __init__(self, api_key, insecure):
        self.verify = not insecure
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        handle_proxy()

    def api_request(self, endpoint):
        """Construct an api request to Augur's endpoint.

        Args:
            endpoint: the api endpoint

        Returns:
            response from api.
        """
        return requests.request(
            method="GET",
            url=f"https://api.seclytics.com{endpoint}",
            verify=self.verify,
            headers=self.headers,
            timeout=60,
        )

    def ip_request(self, ip) -> CommandResults:
        """Request ip context on Augur's API.

        Args:
            ip: ipv4 string

        Returns:
            Context in dict object.
        """
        endpoint = f"/ips/{ip}?fields=context,prediction,asn,cidr,country,accessed_by_files"
        res = self.api_request(endpoint)
        res.raise_for_status()
        return res.json()

    def host_request(self, host) -> CommandResults:
        """Request host context on Augur's API.

        Args:
            host: host name string

        Returns:
            Context in dict object.
        """
        endpoint = f"/hosts/{host}?fields=context,accessed_by_files"
        res = self.api_request(endpoint)
        res.raise_for_status()
        return res.json()

    def hash_request(self, fhash) -> CommandResults:
        """Request file hash context on Augur's API.

        Args:
            fhash: file hash string

        Returns:
            Context in dict object.
        """
        endpoint = f"/files/{fhash}?fields=context"
        res = self.api_request(endpoint)
        res.raise_for_status()
        return res.json()

    def daily_intel_request(self, limit=None, offset=0) -> list:
        """The HTTP request for daily feeds.
        Returns:
            list. A list of indicators fetched from the feed.
        """
        endpoint = "/bulk/private/palo_alto_xsoar_iocs.csv"
        res = self.api_request(endpoint)
        res.raise_for_status()
        indicators = res.text.split("\n")
        if limit:
            return indicators[offset : offset + limit]
        return indicators

    @staticmethod
    def find_indicator_type(indicator: str) -> str:
        """
        Get the type of the indicator.

        Args:
            indicator (str): The indicator whose type we want to check.

        Returns:
            str: The type of the indicator.
        """
        if re.match(urlRegex, indicator):
            return FeedIndicatorType.URL
        elif ip_type := FeedIndicatorType.ip_to_indicator_type(indicator):
            return ip_type
        elif re.match(sha256Regex, indicator):
            return FeedIndicatorType.File
        else:
            return FeedIndicatorType.Domain

    def create_indicators_from_response(self, response: list, feed_tags: list, tlp_color: str | None) -> list:
        """
        Creates a list of indicators from a given response
        Args:
            response: List of dict that represent the response from the api
            feed_tags: The indicator tags
            tlp_color: Traffic Light Protocol color

        Returns:
            List of indicators with the correct indicator type.
        """
        parsed_indicators = []  # type:List

        for indicator in response:
            if indicator:
                indicator_type = self.find_indicator_type(indicator)

                # catch ip of the form X.X.X.X:portNum and extract the IP without the port.
                if (
                    indicator_type
                    in [
                        FeedIndicatorType.IP,
                        FeedIndicatorType.CIDR,
                        FeedIndicatorType.IPv6CIDR,
                        FeedIndicatorType.IPv6,
                    ]
                    and ":" in indicator
                ):
                    indicator = indicator.split(":", 1)[0]

                indicator_obj = {
                    "type": indicator_type,
                    "value": indicator,
                    "rawJSON": {
                        "value": indicator,
                        "type": indicator_type,
                        "service": "Daily Threat Feed",
                    },
                    "fields": {"service": "Daily Threat Feed", "tags": feed_tags},
                }
                if tlp_color:
                    indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

                parsed_indicators.append(indicator_obj)

        return parsed_indicators

    def build_iterator(self, feed_tags: list, tlp_color: str | None, limit=None, offset=0):
        """Builds a list of indicators.
        Returns:
            list. A list of JSON objects representing indicators fetched from a feed.
        """
        response = self.daily_intel_request(limit=limit, offset=offset)
        parsed_indicators = self.create_indicators_from_response(response, feed_tags, tlp_color)  # list of dict of indicators

        # for get_indicator_command only
        return parsed_indicators


def module_test_command(client: Client, args: dict, feed_tags: list, tlp_color: str | None) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client(Client): Augur Feed client
        args(Dict): The instance parameters
        feed_tags: The indicator tags
        tlp_color: Traffic Light Protocol color

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.ip_request("45.138.16.230")
    except Exception:
        raise Exception("Unable to fetch ip context from Augur!\n" "\nPlease check your API key and your connection to Augur.")
    return "ok"


def get_indicators_command(client: Client, args: dict, feed_tags: list, tlp_color: str | None) -> CommandResults:
    """Initiate a single fetch-indicators

    Args:
        client(Client): The Augur Client.
        args(dict): Command arguments.
        feed_tags: The indicator tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        str, dict, list. the markdown table, context JSON and list of indicators
    """
    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 1000))

    indicators = fetch_indicators_command(client, feed_tags, tlp_color, limit, offset)

    hr_indicators = []
    for indicator in indicators:
        hr_indicators.append(
            {
                "Value": indicator.get("value"),
                "Type": indicator.get("type"),
                "rawJSON": indicator.get("rawJSON"),
                "fields": indicator.get("fields"),
            }
        )

    human_readable = tableToMarkdown(
        "Indicators from Augur:",
        hr_indicators,
        headers=["Value", "Type", "rawJSON", "fields"],
        removeNull=True,
    )

    if args.get("limit"):
        human_readable = (
            human_readable + f"\nTo bring the next batch of indicators "
            f"run:\n!augur-get-daily-indicators "
            f"limit={args.get('limit')} "
            f"offset={int(str(args.get('limit'))) + int(str(args.get('offset')))}"
        )

    return CommandResults(
        readable_output=human_readable,
        raw_response=indicators,
        outputs_prefix="",
        outputs={},
        outputs_key_field="",
    )


def get_ip_context_command(client: Client, args: dict, feed_tags: list, tlp_color: str | None) -> CommandResults:
    """Initiate a call to Augur ip endpoint for context.

    Args:
        client(Client): The Augur Client.
        args(dict): Command arguments.
        feed_tags: The indicator tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        CommandResults object with IP context data.
    """
    ip = args.get("ip")
    if not ip:
        raise ValueError("IP is not defined.")

    data = client.ip_request(ip)
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Augur ip context for {ip}",
            data,
            headers=["asn", "cidr", "country", "context", "prediction", "accessed_by_files"],
            is_auto_json_transform=True,
        ),
        raw_response=data,
        outputs_prefix="Augur.IP",
        outputs={"Address": ip},
        outputs_key_field="Address",
    )


def get_host_context_command(client: Client, args: dict, feed_tags: list, tlp_color: str | None) -> CommandResults:
    """Initiate a call to Augur ip endpoint for context.

    Args:
        client(Client): The Augur Client.
        args(dict): Command arguments.
        feed_tags: The indicator tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        CommandResults object with host context data.
    """
    host = args.get("host")
    if not host:
        raise ValueError("host name is not defined.")

    data = client.host_request(host)
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Augur host context for {host}", data, headers=["context", "accessed_by_files"], is_auto_json_transform=True
        ),
        raw_response=data,
        outputs_prefix="Augur.hostname",
        outputs={"hostname": host},
        outputs_key_field="hostname",
    )


def get_file_hash_context_command(client: Client, args: dict, feed_tags: list, tlp_color: str | None) -> CommandResults:
    """Initiate a call to Augur files endpoint for context.

    Args:
        client(Client): The Augur Client.
        args(dict): Command arguments.
        feed_tags: The indicator tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        CommandResults object with file context data.
    """
    fhash = args.get("hash")
    if not fhash:
        raise ValueError("file hash string is not defined.  Require md5/sha1/sha256")

    data = client.hash_request(fhash)
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Augur file hash context for {fhash}", data, headers=["hash", "hash_type", "context"], is_auto_json_transform=True
        ),
        raw_response=data,
        outputs_prefix="Augur.hash",
        outputs={"hash": fhash},
        outputs_key_field="hash",
    )


def fetch_indicators_command(client: Client, feed_tags: list, tlp_color: str | None, limit=None, offset=None) -> list:
    """Fetch-indicators command from Augur Feeds

    Args:
        client(Client): Augur Feed client.
        feed_tags: The indicator tags.
        tlp_color: Traffic Light Protocol color.
        limit: limit the amount of indicators fetched.
        offset: the index of the first index to fetch.

    Returns:
        list. List of indicators.
    """
    indicators = client.build_iterator(feed_tags, tlp_color, limit, offset)

    return indicators


def main():
    params = demisto.params()
    feed_tags = argToList(params.get("feedTags"))
    tlp_color = params.get("tlp_color")

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    commands = {
        "test-module": module_test_command,
        "augur-get-daily-indicators": get_indicators_command,
        "augur-get-ip-context": get_ip_context_command,
        "augur-get-host-context": get_host_context_command,
        "augur-get-file-hash-context": get_file_hash_context_command,
    }
    try:
        augur_key = params.get("api_key").strip()
        client = Client(api_key=augur_key, insecure=params.get("insecure"))

        if demisto.command() == "fetch-indicators":
            indicators = fetch_indicators_command(client, feed_tags, tlp_color)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            results = commands[command](client, demisto.args(), feed_tags, tlp_color)  # type: ignore
            return_results(results)
            # readable_output, outputs, raw_response = commands[command](
            #    client, demisto.args(), feed_tags, tlp_color)
            # return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f"Error in AugurFeed Daily Integration [{e}]")


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
