"""HelloWorld v3 Integration for Cortex.

A dummy integration demonstrating a Client that inherits from `ContentClient`,
indicator fetching, and a test-module connectivity check.
All data returned is mocked locally.
"""

from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

from ContentClientApiModule import *  # noqa: F401
from BaseContentApiModule import *  # noqa: F401

''' CONSTANTS '''

DEFAULT_INDICATORS_LIMIT = 100



''' AUTHENTICATION HANDLER '''


class HelloWorldV3AuthHandler(APIKeyAuthHandler):
    """Authentication handler for the HelloWorld v3 service.

    Uses an API key sent via a custom header. Inherits from
    `APIKeyAuthHandler`, defined in `ContentClientApiModule`.
    """

    def __init__(self, api_key: str):
        """Initialize the authentication handler.

        Args:
            api_key (str): The API key for authentication.
        """
        super().__init__(key=api_key, header_name="X-HelloWorldV3-API-Key")


''' CLIENT CLASS '''



class HelloWorldV3Client(ContentClient):
    """HelloWorld v3 client that extends `ContentClient` for API interactions.

    Inheriting from `ContentClient` provides built-in retry logic, rate limit
    handling, authentication, system proxy settings, SSL verification, and
    thread safety. The methods below return mocked data for demonstration.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, api_key: str):
        """Initialize the HelloWorld v3 client.

        Args:
            base_url (str): The server base URL.
            verify (bool): Whether to verify SSL certificates.
            proxy (bool): Whether to use system proxy settings.
            api_key (str): The API key for authentication.
        """
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=HelloWorldV3AuthHandler(api_key),
            client_name="HelloWorldV3Client",
            diagnostic_mode=is_debug_mode(),
        )

    def get_indicators(self, limit: int = DEFAULT_INDICATORS_LIMIT) -> list[dict[str, Any]]:
        """Return a list of mocked threat-intelligence indicators.

        In a real implementation this would page through the feed endpoint:
        # return self.get(url_suffix="/api/v1/indicators", resp_type="json")

        Args:
            limit (int): Maximum number of indicators to return.

        Returns:
            list[dict[str, Any]]: The collected raw indicators.
        """
        return [
            {
                "value": f"203.0.113.{index}",
                "score": index % 100,
            }
            for index in range(1, limit + 1)
        ]


''' HELPER FUNCTIONS '''

OUTPUTS_PREFIX = "HelloWorldV3"

def test_module(client: HelloWorldV3Client) -> str:
    """Validate connectivity by performing a simple client call."""
    try:
        client.get_indicators(limit=1)
    except ContentClientAuthenticationError:
        return "AuthenticationError: make sure the API Key is correctly set."
    return "ok"


''' COMMAND FUNCTIONS '''


def fetch_indicators_command(
    client: HelloWorldV3Client,
    tlp_color: str | None,
    feed_reliability: str,
    limit: int = DEFAULT_INDICATORS_LIMIT,
) -> list[dict[str, Any]]:
    """Fetch indicators from the feed and build them for the Threat Intel module.

    Args:
        client (HelloWorldV3Client): The client used to query the feed.
        tlp_color (str | None): Optional Traffic Light Protocol color to tag
            each indicator with.
        feed_reliability (str): The reliability of the feed source.
        limit (int): Maximum number of indicators to fetch.

    Returns:
        list[dict[str, Any]]: The indicators formatted for ``createIndicators``.
    """
    raw_indicators = client.get_indicators(limit=limit)

    indicators: list[dict[str, Any]] = []
    for raw_indicator in raw_indicators:
        value = raw_indicator.get("value")
        if not value:
            continue

        fields: dict[str, Any] = {}
        if tlp_color:
            fields["trafficlightprotocol"] = tlp_color

        indicators.append(
            {
                "value": value,
                "type": raw_indicator.get("type", FeedIndicatorType.IP),
                "rawJSON": raw_indicator,
                "fields": fields,
                "score": raw_indicator.get("score", 0),
                "reliability": feed_reliability,
            }
        )

    return indicators


''' MAIN FUNCTION '''


def main() -> None:
    """Parse params/args and route the command to its handler."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", "https://api.dummy-example.com")
    credentials = params.get("credentials") or {}
    api_key = str(credentials.get("password", "")) if isinstance(credentials, dict) else ""
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    tlp_color = params.get("tlp_color")
    feed_reliability = params.get("feedReliability") or DBotScoreReliability.C
    indicators_limit = arg_to_number(params.get("max_indicator_fetch")) or DEFAULT_INDICATORS_LIMIT

    demisto.debug(f"Command being called is {command}")
    try:
        client = HelloWorldV3Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, tlp_color, feed_reliability, limit=indicators_limit)
            for indicator_batch in batch(indicators, batch_size=INDICATOR_BATCH_SIZE):
                demisto.createIndicators(indicator_batch)
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


''' ENTRY POINT '''

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
