from dataclasses import dataclass, asdict
from typing import Any
import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

SERVICENOW_CMDB_RECORD_GET_BY_ID = "servicenow-cmdb-record-get-by-id"
CMDB_CI_NETWORK_ADAPTER = "cmdb_ci_network_adapter"
DEFAULT_INSTANCE_URL_SUFFIX = "/api/now/table/sys_user_group/global"


@dataclass
class NetworkAdapter:
    """Represents a network adapter from ServiceNow CMDB."""

    sys_id: str
    name: str | None = None
    ip: str | None = None
    owner: str = ""
    owner_id: str = ""
    related_configuration_item_name: str | None = None
    related_configuration_item_id: str | None = None
    instance_url: str = ""
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ConfigurationItem:
    """Represents a related configuration item from ServiceNow CMDB."""

    sys_id: str
    name: str | None = None
    ip: str | None = None
    owner: str | None = None
    owner_id: str | None = None
    hostname: str | None = None
    os: str | None = None
    os_version: str | None = None
    ci_class: str = ""
    use: str | None = None
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def get_command_results(command: str, args: dict[str, Any]) -> Union[dict[str, Any], list]:
    """Execute a Demisto command and return the parsed result.

    Args:
        command (str): The Demisto command to execute.
        args (dict[str, Any]): The arguments to pass to the command.

    Returns:
        Union[dict[str, Any], list]: The parsed result of the command, or an empty dict if no valid result is found.

    Raises:
        Exception: If the command execution returns an error.
    """
    results = demisto.executeCommand(command, args)

    if not results or not isinstance(results, list):
        return {}

    result = results[0]
    if not isinstance(result, dict):
        return {}

    if result.get("Type") == EntryType.ERROR:
        raise Exception(result.get("Contents", "Unknown error occurred."))

    contents = result.get("Contents")
    if isinstance(contents, dict):
        return contents.get("result", {})

    return {}


def build_servicenow_url(instance_url: str, table: str, sys_id: str) -> str:
    """Build ServiceNow navigation URL."""
    return f"{instance_url}/nav_to.do?uri={table}.do?sys_id={sys_id}" if instance_url else ""


def get_network_adapter(sid: str) -> NetworkAdapter:
    """Fetch and parse network adapter details from ServiceNow."""
    result = get_command_results(SERVICENOW_CMDB_RECORD_GET_BY_ID, {"class": CMDB_CI_NETWORK_ADAPTER, "sys_id": sid})
    if not isinstance(result, dict):
        result = {}

    attributes = result.get("attributes", {})
    sys_domain = attributes.get("sys_domain", {})
    instance_url = sys_domain.get("link", "").replace(DEFAULT_INSTANCE_URL_SUFFIX, "")

    assigned_to = attributes.get("assigned_to", {}) if isinstance(attributes.get("assigned_to"), dict) else {}
    cmdb_ci = attributes.get("cmdb_ci", {}) if isinstance(attributes.get("cmdb_ci"), dict) else {}

    return NetworkAdapter(
        sys_id=sid,
        name=attributes.get("name"),
        ip=attributes.get("ip_address"),
        owner=assigned_to.get("display_value", ""),
        owner_id=assigned_to.get("value", ""),
        related_configuration_item_name=cmdb_ci.get("display_value"),
        related_configuration_item_id=cmdb_ci.get("value"),
        instance_url=instance_url,
        url=build_servicenow_url(instance_url=instance_url, table="cmdb_ci_network_adapter", sys_id=sid) if instance_url else "",
    )


def get_related_configuration_item(sid: str, instance_url: str) -> ConfigurationItem:
    """Fetch and parse related configuration item details from ServiceNow."""
    # First get the CI class
    result = get_command_results(SERVICENOW_CMDB_RECORD_GET_BY_ID, {"class": "cmdb_ci", "sys_id": sid})
    if not isinstance(result, dict):
        result = {}

    ci_class = result.get("attributes", {}).get("sys_class_name", "")
    if not ci_class:
        return ConfigurationItem(
            sys_id=sid, url=build_servicenow_url(instance_url=instance_url, table="cmdb_ci", sys_id=sid) if instance_url else ""
        )

    # Get full CI details with the specific class
    result = get_command_results(SERVICENOW_CMDB_RECORD_GET_BY_ID, {"class": ci_class, "sys_id": sid})
    if not isinstance(result, dict):
        result = {}

    attributes = result.get("attributes", {})
    assigned_to = attributes.get("assigned_to", {}) if isinstance(attributes.get("assigned_to"), dict) else {}

    return ConfigurationItem(
        sys_id=sid,
        name=attributes.get("name"),
        ip=attributes.get("ip_address"),
        owner=assigned_to.get("display_value"),
        owner_id=assigned_to.get("value"),
        hostname=attributes.get("host_name"),
        os=attributes.get("os"),
        os_version=attributes.get("os_version"),
        ci_class=ci_class,
        use=attributes.get("used_for"),
        url=build_servicenow_url(instance_url=instance_url, table=ci_class, sys_id=sid) if instance_url else "",
    )


def main():
    """
    Main function to resolve network adapters and related configuration items from ServiceNow CMDB.

    This script queries ServiceNow CMDB for network adapters matching the provided IP address,
    then retrieves related configuration items and returns enriched information.
    """
    try:
        args = demisto.args()
        ip_address = args.get("ip_address")

        if not ip_address:
            raise ValueError("IP address is required")

        # Get network adapters for the given IP
        result = get_command_results(
            "servicenow-cmdb-records-list", {"class": CMDB_CI_NETWORK_ADAPTER, "query": f"ip_address={ip_address}"}
        )

        if not isinstance(result, list):
            result = []

        network_adapters = [get_network_adapter(item["sys_id"]) for item in result if item.get("sys_id")]

        # Get related configuration items
        related_items = []
        for adapter in network_adapters:
            if adapter.related_configuration_item_id and adapter.instance_url:
                related_item = get_related_configuration_item(adapter.related_configuration_item_id, adapter.instance_url)
                related_items.append(related_item)

        outputs = {
            "summary": (
                f"Found {len(network_adapters)} related network adapters and "
                f"{len(related_items)} related configuration items in ServiceNow for ip {ip_address}."
            ),
            "network_adapters": [adapter.to_dict() for adapter in network_adapters],
            "related_configuration_items": [item.to_dict() for item in related_items],
        }

        # Prepare human-readable output
        human_readable = (
            f"### {outputs['summary']}\n"
            f"```json\n{json.dumps(outputs['related_configuration_items'], indent=2, default=str)}\n```"
        )

        return_results(
            CommandResults(
                outputs=outputs,
                outputs_prefix="ServiceNowCMDBAssetEnrichment",
                readable_output=human_readable,
                raw_response=outputs,
            )
        )

    except Exception as e:
        error_msg = f"Failed to execute ResolveNetworkAdapters: {str(e)}"
        return_error(error_msg)


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
