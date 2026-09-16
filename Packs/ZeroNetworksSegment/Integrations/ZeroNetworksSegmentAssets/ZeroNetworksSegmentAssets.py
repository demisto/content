import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

from typing import Any

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

API_VERSION = "/api/v1"
DEFAULT_SERVER_URL = "https://portal.zeronetworks.com"

# The numeric enums below mirror the Zero Networks API reference. Values the API adds later fall
# back to "Unknown (<value>)" rather than being dropped, so the raw value stays visible.
ASSET_TYPES = {
    0: "Unknown",
    1: "Client",
    2: "Server",
    3: "Virtual Cluster",
    4: "IP Camera",
    5: "Smart TV",
    6: "Factory Controller",
    7: "Medical Device",
    8: "Printer",
    9: "Scanner",
    10: "Smart Card Reader",
    11: "Router",
    12: "Hypervisor",
    13: "PLC",
    14: "HMI",
    15: "Switch",
    16: "Terminal Station",
    17: "RTU",
    18: "Wireless Access Point",
    19: "Historian",
    20: "Game Console",
    21: "Fire Alarm",
    22: "UPS",
    23: "Storage Appliance",
    24: "Virtualization Appliance",
    25: "Firewall Appliance",
    26: "Security Scanner",
    27: "Security Controller",
    28: "Door Lock",
    29: "Biometric Entry System",
    30: "HVAC",
    31: "Room Scheduler",
    32: "Load Balancer Appliance",
    33: "WAN Concentrator",
    34: "IPAM Appliance",
    35: "Temperature Sensor Gateway",
    36: "Power Meter",
}

OS_TYPES = {
    1: "Unmanageable",
    2: "Windows",
    3: "Linux",
    4: "Mac",
}

PROTECTION_STATES = {
    0: "Unspecified",
    1: "Unsegmented",
    2: "Unsegmenting",
    3: "Segmented",
    4: "Segmenting",
    5: "Learning",
    6: "Forced Unprotected",
    7: "Unsegmenting (Due To Policy)",
    8: "Segmented (Due To Policy)",
    9: "Segmenting (Due To Policy)",
    10: "Learning (Due To Policy)",
    11: "Learning Done",
    12: "Learning Done (Due To Policy)",
    13: "Applying Queue With Blocks",
    14: "Applying Queue With Blocks (Due To Policy)",
    15: "Queued With Blocks",
    16: "Queued With Blocks (Due To Policy)",
    17: "Queued With Blocks Done",
    18: "Queued With Blocks Done (Due To Policy)",
}

ASSET_SOURCES = {
    0: "Unspecified",
    1: "Access Portal",
    2: "SSP",
    3: "Active Directory",
    4: "Custom",
    5: "System",
    6: "Ansible",
    7: "Manual OT/IoT",
    8: "Workgroup",
    9: "Azure Active Directory",
    10: "Azure",
    11: "AWS",
    12: "GCP",
    13: "Tag",
    14: "Jamf",
    15: "Manual Linux",
    16: "IBM Cloud",
    17: "Oracle Cloud",
    18: "VMware Cloud",
    19: "Alibaba Cloud",
    20: "Lumen Cloud",
    21: "OVH Cloud",
    22: "Connect",
    23: "AI",
    24: "SNOW",
    25: "Google Workspace",
    26: "OU",
    27: "Environment",
    28: "Conditional",
    29: "Claroty OT",
    30: "Manual Mac",
}

HEALTH_STATUSES = {
    0: "Unspecified",
    1: "Healthy",
    2: "Error",
    3: "Warning",
    4: "N/A",
    5: "Retrying",
    6: "Blocker",
}

# The war room table columns, mapped from their context key to their display name. pascalToSpace is
# not used here because it renders IPv4Addresses as "I Pv 4 Addresses".
ASSET_TABLE_HEADERS = {
    "ID": "ID",
    "Name": "Name",
    "FQDN": "FQDN",
    "AssetType": "Asset Type",
    "OperatingSystem": "Operating System",
    "IPv4Addresses": "IPv4 Addresses",
    "ProtectionState": "Protection State",
    "IsQuarantined": "Is Quarantined",
    "RiskScore": "Risk Score",
}

""" CLIENT CLASS """


class Client(BaseClient):
    """Client for the Zero Networks Segment API."""

    def __init__(self, server_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(
            base_url=urljoin(server_url, API_VERSION),
            verify=verify,
            proxy=proxy,
            headers={"Authorization": api_key, "accept": "application/json"},
        )

    def list_assets(self, limit: int = 1) -> dict[str, Any]:
        """Retrieve a page of assets. Used by the connectivity test as the cheapest authenticated call."""
        return self._http_request("GET", "/assets", params={"_limit": limit})

    def search_asset_id(self, fqdn: str) -> str | None:
        """
        Look up an asset ID by fully qualified domain name.

        Zero Networks answers a miss either with 200 and an object that carries no assetId, or with
        404, so both are treated as "not found" and return None.
        """
        response = self._http_request(
            "GET",
            "/assets/searchId",
            params={"fqdn": fqdn},
            ok_codes=(200, 404),
            resp_type="response",
        )
        if response.status_code == 404:
            return None
        return (response.json() or {}).get("assetId") or None

    def get_asset(self, asset_id: str) -> dict[str, Any]:
        """Retrieve the properties of a single asset."""
        return self._http_request("GET", f"/assets/{asset_id}")

    def set_asset_quarantine(self, asset_id: str, quarantine: bool) -> None:
        """Enable or disable quarantine for an asset. The API answers with an empty object."""
        self._http_request(
            "PUT",
            f"/assets/{asset_id}/actions/quarantine",
            json_data={"quarantine": quarantine},
            return_empty_response=True,
        )


""" HELPER FUNCTIONS """


def enum_label(mapping: dict[int, str], value: Any) -> str | None:
    """Translate a Zero Networks numeric enum into its display name."""
    if value is None:
        return None
    return mapping.get(value, f"Unknown ({value})")


def epoch_to_date_string(value: Any) -> str | None:
    """Convert a Zero Networks epoch-milliseconds timestamp into an ISO 8601 string."""
    if not value:
        return None
    return timestamp_to_datestring(value, is_utc=True)


def asset_to_context(asset: dict[str, Any]) -> dict[str, Any]:
    """Map a Zero Networks asset object onto the integration context format."""
    health_state = asset.get("healthState") or {}
    labels = [label.get("name") for label in asset.get("labels") or [] if label.get("name")]

    return remove_empty_elements(
        {
            "ID": asset.get("id"),
            "Name": asset.get("name"),
            "FQDN": asset.get("fqdn"),
            "Domain": asset.get("domain"),
            "AssetType": enum_label(ASSET_TYPES, asset.get("assetType")),
            "OSType": enum_label(OS_TYPES, asset.get("osType")),
            "OperatingSystem": asset.get("operatingSystem"),
            "IPv4Addresses": asset.get("ipV4Addresses"),
            "IPv6Addresses": asset.get("ipV6Addresses"),
            "ProtectionState": enum_label(PROTECTION_STATES, asset.get("protectionState")),
            "IdentityProtectionState": enum_label(PROTECTION_STATES, asset.get("identityProtectionState")),
            "RPCProtectionState": enum_label(PROTECTION_STATES, asset.get("rpcProtectionState")),
            "IsQuarantined": asset.get("isQuarantined"),
            "RiskScore": asset.get("riskScore"),
            "Source": enum_label(ASSET_SOURCES, asset.get("source")),
            "HealthStatus": enum_label(HEALTH_STATUSES, health_state.get("healthStatus")),
            "Labels": labels,
            "LastLogon": epoch_to_date_string(asset.get("lastLogon")),
            "ProtectedAt": epoch_to_date_string(asset.get("protectedAt")),
            "InactiveSince": epoch_to_date_string(asset.get("inactiveSince")),
        }
    )


def resolve_asset_id(client: Client, args: dict[str, Any]) -> tuple[str, str | None]:
    """
    Resolve the asset to act on from either an explicit asset ID or an FQDN.

    Returns the asset ID together with the FQDN it was resolved from, when one was used.
    """
    asset_id = args.get("asset_id")
    fqdn = args.get("fqdn")

    if asset_id and fqdn:
        raise DemistoException("Provide either the 'asset_id' or the 'fqdn' argument, not both.")
    if asset_id:
        return asset_id, None
    if not fqdn:
        raise DemistoException("One of the 'asset_id' or 'fqdn' arguments must be provided.")

    resolved_id = client.search_asset_id(fqdn)
    if not resolved_id:
        raise DemistoException(f"No asset was found in Zero Networks for the FQDN '{fqdn}'.")
    return resolved_id, fqdn


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Verify that the server URL and API key are usable."""
    try:
        client.list_assets(limit=1)
    except DemistoException as error:
        if "401" in str(error) or "403" in str(error):
            return "Authorization Error: make sure the API Key is correctly set and has not expired."
        raise
    return "ok"


def asset_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Search for an asset by FQDN and return its properties."""
    fqdn = args.get("fqdn")
    asset_id = client.search_asset_id(fqdn)

    if not asset_id:
        return CommandResults(readable_output=f"No asset was found in Zero Networks for the FQDN '{fqdn}'.")

    asset = client.get_asset(asset_id).get("entity") or {}
    # The search endpoint is authoritative for the ID, and the FQDN is what the user asked for, so
    # keep both even when the asset object itself omits them.
    asset.setdefault("id", asset_id)
    asset.setdefault("fqdn", fqdn)
    outputs = asset_to_context(asset)

    return CommandResults(
        outputs_prefix="ZeroNetworks.Asset",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=asset,
        readable_output=tableToMarkdown(
            f"Zero Networks asset for {fqdn}",
            outputs,
            headers=list(ASSET_TABLE_HEADERS),
            headerTransform=lambda header: ASSET_TABLE_HEADERS.get(header, header),
            removeNull=True,
        ),
    )


def asset_quarantine_command(client: Client, args: dict[str, Any], quarantine: bool) -> CommandResults:
    """Enable or disable quarantine for an asset, resolving the FQDN first when one was given."""
    asset_id, fqdn = resolve_asset_id(client, args)
    client.set_asset_quarantine(asset_id, quarantine)

    outputs = remove_empty_elements({"ID": asset_id, "FQDN": fqdn, "IsQuarantined": quarantine})
    action = "quarantined" if quarantine else "released from quarantine"

    return CommandResults(
        outputs_prefix="ZeroNetworks.Asset",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=f"Asset {fqdn or asset_id} was successfully {action}.",
    )


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    server_url = params.get("url") or DEFAULT_SERVER_URL
    api_key = (params.get("credentials") or {}).get("password", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(server_url=server_url, api_key=api_key, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "zero-networks-segment-asset-search":
            return_results(asset_search_command(client, args))
        elif command == "zero-networks-segment-asset-quarantine":
            return_results(asset_quarantine_command(client, args, quarantine=True))
        elif command == "zero-networks-segment-asset-unquarantine":
            return_results(asset_quarantine_command(client, args, quarantine=False))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
