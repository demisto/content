"""HelloWorld v3 Integration for Cortex.

A dummy integration demonstrating a Client that inherits from `ContentClient`,
three commands with inputs and outputs, and a test-module connectivity check.
All data returned is mocked locally.
"""

from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

from ContentClientApiModule import *  # noqa: F401
from BaseContentApiModule import *  # noqa: F401

''' CONSTANTS '''

DEFAULT_LIMIT = 10
DEFAULT_PAGE_SIZE = 50
DEFAULT_IP_THRESHOLD = 65


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

    def say_hello(self, name: str) -> dict[str, Any]:
        """Return a greeting payload for the given name.

        Implements a manual retry mechanism with exponential backoff when the
        server responds with HTTP 429 (Too Many Requests).
        """

        res =  self._http_request(
            method="GET",
            url_suffix="/api/v1/hello",
            params={"name": demisto.args().get("name")},
            resp_type="json",
            retries=3,
            backoff_factor=1,
            status_list=[429],
        )

        return res

    def list_alerts(
        self,
        severity: str | None,
        limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        """Return a list of alerts, optionally filtered by severity.

        Repeatedly requests pages from the server until ``limit`` alerts have
        been collected or the server returns no more results. Each request
        fetches at most ``page_size`` alerts (capped at the number still
        needed to reach ``limit``).

        Args:
            severity (str | None): Optional severity to filter alerts by.
            limit (int): Maximum total number of alerts to return.

        Returns:
            list[dict[str, Any]]: The collected alerts, at most ``limit`` items.
        """
        alerts: list[dict[str, Any]] = []
        page = 1
        next_token=None
        while len(alerts) < limit:
            current_page_size = min(DEFAULT_PAGE_SIZE, limit - len(alerts))
            params = assign_params(
                limit=current_page_size,
                page=page,
                severity=severity,
                next_token=next_token
            )
            response = self._http_request(url_suffix="/api/v1/alerts", params=params, resp_type="json")
            page_alerts = response.get("alerts", []) if isinstance(response, dict) else response
            next_token = response.get("next_token")
            if not page_alerts:
                break
            alerts.extend(page_alerts)
            # A short page (fewer than requested) means there is no more data.
            if len(page_alerts) < current_page_size:
                break
            page += 1
        return alerts[:limit]



    def get_alert(self, alert_id: int) -> dict[str, Any]:
        """Return a single mocked alert by its ID."""
        # In a real implementation:
        # return self.get(url_suffix=f"/api/v1/alerts/{alert_id}", resp_type="json")
        return {
            "id": alert_id,
            "name": f"Alert {alert_id}",
            "severity": "high" if alert_id % 2 == 0 else "low",
            "status": "open",
        }

    def get_ip_reputation(self, ip: str) -> dict[str, Any]:
        """Return a mocked reputation payload for the given IP address."""
        # In a real implementation:
        # return self.get(url_suffix=f"/api/v1/ip/{ip}", resp_type="json")
        # The mocked score is derived deterministically from the IP so the same
        # input always yields the same reputation, which keeps demos predictable.
        score = sum(int(octet) for octet in ip.split(".") if octet.isdigit()) % 100
        return {
            "ip": ip,
            "score": score,
            "asn": "AS12345",
            "as_owner": "Dummy AS Owner",
            "country": "US",
        }


''' HELPER FUNCTIONS '''

OUTPUTS_PREFIX = "HelloWorldV3"

def test_module(client: HelloWorldV3Client) -> str:
    """Validate connectivity by performing a simple client call."""
    try:
        client.say_hello("Test")
    except ContentClientAuthenticationError:
        return "AuthenticationError: make sure the API Key is correctly set."
    return "ok"


''' COMMAND FUNCTIONS '''


def say_hello_command(client: HelloWorldV3Client, args: dict[str, Any]):
    """Greet a specified person."""

    name = args.get("name", "World")
    res =  client.say_hello(name)

    return CommandResults(
        outputs_prefix=f"{OUTPUTS_PREFIX}.Hello",
        outputs_key_field="name",
        outputs=res,
        readable_output=res["message"],
        raw_response=res,
    )


def list_alerts_command(client: HelloWorldV3Client, args: dict[str, Any]) -> CommandResults:
    """List mocked alerts with optional severity filtering."""
    severity = args.get("severity")
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    alerts = client.list_alerts(severity, limit=limit)
    return CommandResults(
        outputs_prefix=f"{OUTPUTS_PREFIX}.Alert",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=tableToMarkdown("alerts", alerts),
        raw_response=alerts,
    )


def get_alert_command(client: HelloWorldV3Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve a single mocked alert by ID."""
    alert_id = arg_to_number(args.get("alert_id"))

    if alert_id is None:
        raise ValueError("alert_id is a required argument.")
    alert = client.get_alert(alert_id)
    return CommandResults(
        outputs_prefix=f"{OUTPUTS_PREFIX}.Alert",
        outputs_key_field="id",
        outputs=alert,
        readable_output=tableToMarkdown("alert", alert),
        raw_response=alert,
    )


def ip_reputation_command(
    client: HelloWorldV3Client,
    args: dict[str, Any],
    threshold: int,
    reliability: DBotScoreReliability | str,
) -> list[CommandResults]:
    """Run the reputation (enrichment) command for one or more IP addresses.

    Args:
        client (HelloWorldV3Client): The client used to query reputation data.
        args (dict[str, Any]): The command arguments. Supports a comma-separated
            ``ip`` argument and an optional ``threshold`` override.
        threshold (int): The default score above which an IP is considered
            malicious.
        reliability (DBotScoreReliability | str): The reliability of the source
            providing the intelligence data.

    Returns:
        list[CommandResults]: One CommandResults entry per IP address.
    """
    ips = argToList(args.get("ip"))
    if not ips:
        raise ValueError("ip is a required argument.")
    threshold = arg_to_number(args.get("threshold")) or threshold

    command_results: list[CommandResults] = []
    for ip in ips:
        ip_data = client.get_ip_reputation(ip)
        score = ip_data.get("score", 0)

        reputation = Common.DBotScore.NONE
        if score == 0:
            reputation = Common.DBotScore.GOOD
        elif score >= threshold:
            reputation = Common.DBotScore.BAD
        elif score >= threshold / 2:
            reputation = Common.DBotScore.SUSPICIOUS

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name="HelloWorldV3",
            score=reputation,
            malicious_description=f"Score above {threshold}" if reputation == Common.DBotScore.BAD else None,
            reliability=reliability,
        )

        ip_standard_context = Common.IP(
            ip=ip,
            asn=ip_data.get("asn"),
            geo_country=ip_data.get("country"),
            dbot_score=dbot_score,
        )

        command_results.append(
            CommandResults(
                outputs_prefix=f"{OUTPUTS_PREFIX}.IP",
                outputs_key_field="ip",
                outputs=ip_data,
                readable_output=tableToMarkdown(f"IP {ip} reputation", ip_data),
                indicator=ip_standard_context,
                raw_response=ip_data,
                ignore_auto_extract=True
            )
        )

    return command_results


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
    ip_threshold = arg_to_number(params.get("ip_threshold")) or DEFAULT_IP_THRESHOLD
    reliability = params.get("integrationReliability") or DBotScoreReliability.C

    demisto.debug(f"Command being called is {command}")
    try:
        client = HelloWorldV3Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
        )

        commands = {
            "helloworldv3-say-hello": say_hello_command,
            "helloworldv3-alert-list": list_alerts_command,
            "helloworldv3-alert-get": get_alert_command,
        }

        if command == "test-module":
            return_results(test_module(client))
        elif command == "ip":
            return_results(ip_reputation_command(client, args, ip_threshold, reliability))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


''' ENTRY POINT '''

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
