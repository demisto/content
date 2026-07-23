import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Spec Test Default Integration

This integration is a test fixture for validating that integrations
WITHOUT the 'spec' field continue to work normally with the default
worker memory allocation.

No 'spec' field is set in this integration's YAML configuration,
meaning it will use the platform's default memory allocation (1 GB).
"""

import urllib3

urllib3.disable_warnings()

INTEGRATION_NAME = "Spec Test Default"
INTEGRATION_COMMAND_NAME = "spec-test-default"
INTEGRATION_CONTEXT_NAME = "SpecTestDefault"


class Client(BaseClient):
    """Client class for interacting with the test API."""

    def test_connection(self) -> dict:
        """Tests connectivity to the API.

        Returns:
            dict: API health response.
        """
        return self._http_request("GET", "health")

    def list_items(self, limit: int = 50) -> list[dict]:
        """Lists available items.

        Args:
            limit: Maximum number of items to return.

        Returns:
            list[dict]: List of item objects.
        """
        params = {"limit": limit}
        return self._http_request("GET", "items", params=params)

    def get_item(self, item_id: str) -> dict:
        """Retrieves a specific item by ID.

        Args:
            item_id: The ID of the item to retrieve.

        Returns:
            dict: Item details.
        """
        return self._http_request("GET", f"items/{item_id}")


def test_module(client: Client) -> str:
    """Tests connectivity.

    This is a test-only integration for validating the absence of the 'spec' field.
    The test-module always returns 'ok' since no real API backend exists.

    Args:
        client: Client instance (unused for test-module).

    Returns:
        'ok' always.
    """
    demisto.debug("test-module called — spec test integration (default), returning ok")
    return "ok"


def list_items_command(client: Client, args: dict) -> CommandResults:
    """Lists all available items.

    Args:
        client: Client instance.
        args: Command arguments.

    Returns:
        CommandResults with item list.
    """
    limit = arg_to_number(args.get("limit", "50")) or 50
    items = client.list_items(limit=limit)

    readable_output = tableToMarkdown(
        name=f"{INTEGRATION_NAME} - Items",
        t=items,
        headers=["id", "name"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Item",
        outputs_key_field="ID",
        outputs=[
            {"ID": item.get("id"), "Name": item.get("name")}
            for item in items
        ],
    )


def get_item_command(client: Client, args: dict) -> CommandResults:
    """Retrieves a specific item by ID.

    Args:
        client: Client instance.
        args: Command arguments containing item_id.

    Returns:
        CommandResults with item details.
    """
    item_id = args.get("item_id", "")
    if not item_id:
        raise DemistoException("item_id is required")

    item = client.get_item(item_id)

    readable_output = tableToMarkdown(
        name=f"{INTEGRATION_NAME} - Item Details",
        t=item,
        headers=["id", "name", "created_at"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Item",
        outputs_key_field="ID",
        outputs={
            "ID": item.get("id"),
            "Name": item.get("name"),
            "CreatedAt": item.get("created_at"),
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

        elif command == f"{INTEGRATION_COMMAND_NAME}-list-items":
            return_results(list_items_command(client, args))

        elif command == f"{INTEGRATION_COMMAND_NAME}-get-item":
            return_results(get_item_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"Failed to execute {command} command. Error: {str(e)}")
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
