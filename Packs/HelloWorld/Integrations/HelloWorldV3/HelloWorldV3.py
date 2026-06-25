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

default_limit = 10


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

PARAMS = demisto.params()

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

    def SayHello(self, name: str) -> dict[str, Any]:
        """Return a greeting payload for the given name."""
        # In a real implementation:
        # return self.get(url_suffix="/api/v1/hello", params={"name": name}, resp_type="json")
        return {"name": name, "message": f"Hello {name}"}

    def list_alerts(self, limit: int, SEVERITY: str | None) -> list[dict[str, Any]]:
        """Return a mocked list of alerts, optionally filtered by severity."""
        # In a real implementation:
        # return self.get(url_suffix="/api/v1/alerts", params=assign_params(limit=limit, severity=severity),
        #                 resp_type="json")
        alerts = [
            {"id": i, "name": f"Alert {i}", "severity": "high" if i % 2 == 0 else "low"}
            for i in range(1, limit + 1)
        ]
        if SEVERITY:
            alerts = [alert for alert in alerts if alert["severity"] == SEVERITY]
        return alerts

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


''' HELPER FUNCTIONS '''

OUTPUTS_PREFIX = "HelloWorldV3"


def AlertToMD(alerts: list[dict[str, Any]]) -> str:
    """Convert a list of alert dictionaries into a Markdown-formatted table.

    Each dictionary represents a single row in the table.

    Args:
        alerts (list[dict[str, Any]]): The alert rows to render.

    Returns:
        str: A Markdown table string representing the alert data.
    """
    if not alerts:
        return ""

    headers: list[str] = []
    for alert in alerts:
        for key in alert:
            if key not in headers:
                headers.append(key)

    header_row = "| " + " | ".join(headers) + " |"
    separator_row = "| " + " | ".join("---" for _ in headers) + " |"
    value_rows = [
        "| " + " | ".join(str(alert.get(header, "")) for header in headers) + " |"
        for alert in alerts
    ]
    return "\n".join([header_row, separator_row, *value_rows])


def test_module(Client: HelloWorldV3Client) -> str:
    """Validate connectivity by performing a simple client call."""
    try:
        Client.SayHello("Test")
    except ContentClientAuthenticationError:
        return "AuthenticationError: make sure the API Key is correctly set."
    return "ok"


''' COMMAND FUNCTIONS '''


def say_hello_command(client: HelloWorldV3Client, args: dict[str, Any]) -> CommandResults:
    """Greet a specified person."""
    name = args.get("name", "World")
    result = client.SayHello(name)
    return CommandResults(
        outputs_prefix=f"{OUTPUTS_PREFIX}.Hello",
        outputs_key_field="name",
        outputs=result,
        readable_output=result["message"],
        ignore_auto_extract=False
    )


def list_alerts_command(client: HelloWorldV3Client, args: dict[str, Any]) -> CommandResults:
    """List mocked alerts with optional severity filtering."""
    limit = arg_to_number(args.get("limit")) or default_limit
    severity = args.get("severity")
    alerts = client.list_alerts(limit, severity)
    return CommandResults(
        outputs_prefix=f"{OUTPUTS_PREFIX}.Alert",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=AlertToMD(alerts),
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
        readable_output=AlertToMD( [alert]),
    )


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
        elif command in commands:
            return_results(commands[command](client, **args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


''' ENTRY POINT '''

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
