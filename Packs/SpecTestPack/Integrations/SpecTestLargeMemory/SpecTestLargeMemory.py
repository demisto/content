import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Spec Test Large Memory Integration

This integration is a test fixture for validating the new 'spec' field
on Integration content items. The 'spec' field determines the memory
allocation size for the dedicated worker running this integration.

This integration has spec: L (large) set in its YAML configuration,
indicating it requires extra memory (e.g., for heavy data processing).
"""

import urllib3

urllib3.disable_warnings()

INTEGRATION_NAME = "Spec Test Large Memory"
INTEGRATION_COMMAND_NAME = "spec-test-large"
INTEGRATION_CONTEXT_NAME = "SpecTestLargeMemory"


class Client(BaseClient):
    """Client class for interacting with the test API."""

    def test_connection(self) -> dict:
        """Tests connectivity to the API.

        Returns:
            dict: API version response.
        """
        return self._http_request("GET", "health")

    def list_resources(self, limit: int = 50) -> list[dict]:
        """Lists available resources.

        Args:
            limit: Maximum number of resources to return.

        Returns:
            list[dict]: List of resource objects.
        """
        params = {"limit": limit}
        return self._http_request("GET", "resources", params=params)

    def process_resource(self, resource_id: str) -> dict:
        """Processes a resource (memory-intensive operation).

        Args:
            resource_id: The ID of the resource to process.

        Returns:
            dict: Processing result.
        """
        return self._http_request("POST", f"resources/{resource_id}/process")


def test_module(client: Client) -> str:
    """Tests API connectivity.

    Args:
        client: Client instance.

    Returns:
        'ok' if successful.

    Raises:
        DemistoException: If the API response is unexpected.
    """
    result = client.test_connection()
    if result:
        return "ok"
    raise DemistoException("Unexpected response from API")


def list_resources_command(client: Client, args: dict) -> CommandResults:
    """Lists all available resources.

    Args:
        client: Client instance.
        args: Command arguments.

    Returns:
        CommandResults with resource list.
    """
    limit = arg_to_number(args.get("limit", "50")) or 50
    resources = client.list_resources(limit=limit)

    readable_output = tableToMarkdown(
        name=f"{INTEGRATION_NAME} - Resources",
        t=resources,
        headers=["id", "name"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Resource",
        outputs_key_field="ID",
        outputs=[
            {"ID": r.get("id"), "Name": r.get("name")}
            for r in resources
        ],
    )


def process_resource_command(client: Client, args: dict) -> CommandResults:
    """Processes a resource that requires large memory allocation.

    Args:
        client: Client instance.
        args: Command arguments containing resource_id.

    Returns:
        CommandResults with processing result.
    """
    resource_id = args.get("resource_id", "")
    if not resource_id:
        raise DemistoException("resource_id is required")

    result = client.process_resource(resource_id)

    readable_output = tableToMarkdown(
        name=f"{INTEGRATION_NAME} - Process Result",
        t=result,
        headers=["id", "status", "size_bytes"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Resource",
        outputs_key_field="ID",
        outputs={
            "ID": result.get("id"),
            "Status": result.get("status"),
            "SizeBytes": result.get("size_bytes"),
        },
    )


def main() -> None:  # pragma: no cover
    """Main entry point for the integration."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", "").rstrip("/")
    api_key = params.get("api_key", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers={"Authorization": f"Bearer {api_key}"},
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == f"{INTEGRATION_COMMAND_NAME}-list-resources":
            return_results(list_resources_command(client, args))

        elif command == f"{INTEGRATION_COMMAND_NAME}-process-resource":
            return_results(process_resource_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"Failed to execute {command} command. Error: {str(e)}")
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
