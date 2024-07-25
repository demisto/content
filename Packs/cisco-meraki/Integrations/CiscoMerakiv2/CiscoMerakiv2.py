import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" Imports """
import dataclasses
import http
import inspect
from enum import Enum
from typing import Any, Callable, Type, TypeVar

""" Global Variables """

DEFAULT_PAGE_SIZE = 50

INTEGRATION_NAME = "meraki"

INTEGRATION_PREFIX = "CiscoMeraki"
ORGANIZATION_PREFIX = "Organization"
NETWORK_PREFIX = "Network"
INVENTORY_PREFIX = "Inventory"
DEVICE_PREFIX = "Device"
NETWORK_DEVICE_PREFIX = "NetworkDevice"
DEVICE_STATUS_PREFIX = "DeviceStatus"
ORGANIZATION_UPLINK_STATUS_PREFIX = "UplinkStatus"
CLIENT_PREFIX = "Client"
NETWORK_CLIENT_PREFIX = "NetworkClient"
DEVICE_CLIENT_PREFIX = "DeviceClient"
SSID_PREFIX = "SSID"
APPLIANCE_PREFIX = "Appliance"
WIRELESS_PREFIX = "Wireless"
L3FIREWALL_RULE_PREFIX = "L3FirewallRule"
L7FIREWALL_RULE_PREFIX = "L7FirewallRule"
ADAPTIVE_POLICY_PREFIX = "AdaptivePolicy"
ADAPTIVE_POLICY_ACL_PREFIX = "AdaptivePolicyACL"
ADAPTIVE_POLICY_GROUP_PREFIX = "AdaptivePolicyGroup"
ADAPTIVE_POLICY_SETTINGS_PREFIX = "AdaptivePolicySettings"
BRANDING_POLICY_PREFIX = "BrandingPolicy"
GROUP_POLICY_PREFIX = "GroupPolicy"
CLIENT_POLICY_PREFIX = "ClientPolicy"
VLAN_PROFILE_PREFIX = "VlanProfile"
APPLIANCE_VLAN_PREFIX = "ApplianceVlan"

ORGANIZATION_TABLE_HEADERS = [
    "ID",
    "Name",
    "URL",
    "Cloud Region Name",
    "Cloud Region Host Name",
]
NETWORK_TABLE_HEADERS = [
    "ID",
    "Name",
    "Organization ID",
    "URL",
]
INVENTORY_TABLE_HEADERS = [
    "Serial",
    "Name",
    "Network ID",
    "MAC",
    "Model",
    "Claimed At",
    "Product Type",
    "License Expiration Date",
]
DEVICE_TABLE_HEADERS = [
    "Serial",
    "Name",
    "Network ID",
    "Address",
    "Model",
    "Firmware",
    "Lan IP",
]
DEVICE_STATUS_TABLE_HEADERS = [
    "Serial",
    "Name",
    "Network ID",
    "Status",
    "Model",
    "IP Type",
    "Gateway",
    "Public IP",
    "Lan IP",
    "Last Reported At",
]
ORGANIZATION_UPLINK_STATUS_TABLE_HEADERS = [
    "Serial",
    "Network ID",
    "Model",
    "Last Reported At",
    "Uplink ICCID",
    "Uplink Interface",
    "Uplink IP",
    "Uplink Public IP",
    "Uplink Signal Type",
    "Uplink Status",
]
CLIENT_TABLE_HEADERS = [
    "Description",
    "IP",
    "OS",
    "Status",
    "User",
    "Network ID",
    "Network Name",
]
NETWORK_CLIENT_TABLE_HEADERS = [
    "ID",
    "Description",
    "IP",
    "OS",
    "Recent Device Name",
    "SSID",
    "Status",
    "User",
    "Usage Received",
    "Usage Sent",
]
DEVICE_CLIENT_TABLE_HEADERS = [
    "ID",
    "Description",
    "IP",
    "MAC",
    "MDNS Name",
    "Switch Port",
    "User",
    "Usage Received",
    "Usage Sent",
]
SSID_APPLIANCE_TABLE_HEADERS = [
    "Number",
    "Name",
    "Default VLAN ID",
    "SSID Enabled",
    "Visible",
]
SSID_WIRELESS_TABLE_HEADERS = [
    "Number",
    "Name",
    "Admin Splash URL",
    "IP Assignment Mode",
    "Enable",
    "Radius Enabled",
    "Visible",
    "Availability Tags",
]
L3FIREWALL_RULE_TABLE_HEADERS = [
    "Comment",
    "Policy",
    "Protocol",
    "Destination Port",
    "Destination CIDR",
    "Source Port",
    "Source CIDR",
    "Syslog Enabled",
]
L7FIREWALL_RULE_TABLE_HEADERS = [
    "Policy",
    "Type",
    "Value",
]
ADAPTIVE_POLICY_ACL_TABLE_HEADERS = [
    "ACL ID",
    "Name",
    "Description",
    "Created At",
    "Rules Policy",
    "Rules Protocol",
    "Rules Destination Port",
    "Rules Source Port",
]
ADAPTIVE_POLICY_TABLE_HEADERS = [
    "Adaptive Policy ID",
    "Destination Group ID",
    "Destination Group Name",
    "Source Group ID",
    "Source Group Name",
    "ACL IDS",
    "ACL Names",
]
ADAPTIVE_POLICY_GROUP_TABLE_HEADERS = [
    "Group ID",
    "Name",
    "Description",
    "Security Group Tag",
    "Policy Object IDs",
    "Policy Object Names",
]
BRANDING_POLICY_TABLE_HEADERS = [
    "Name",
    "Enabled",
    "Admin Settings Applies to",
    "Admin Settings Values",
]
GROUP_POLICY_TABLE_HEADERS = [
    "Group Policy ID",
    "Group Policy Name",
    "Group Splash Auth Settings",
    "Bonjour Forwarding Rules VLAN ID",
    "Bonjour Forwarding Rules Services",
    "Blocked URL Categories",
    "Blocked URL Patterns",
]
CLIENT_POLICY_TABLE_HEADERS = [
    "Client ID",
    "Name",
    "Assigned Group Policy ID",
    "Assigned Name",
    "Assigned Type",
    "Assigned SSID",
]
VLAN_PROFILE_TABLE_HEADERS = [
    "IName",
    "Name",
    "Is Default",
    "VLAN Group Names",
    "VLAN Names",
    "VLAN Names Adaptive Policy Group Names",
]
APPLIANCE_VLAN_TABLE_HEADERS = [
    "ID",
    "Name",
    "Group Policy ID",
    "Interface ID",
    "Appliance IP",
    "Mask",
    "CIDR",
    "Subnet",
]


class TagFilterType(str, Enum):
    ALL = "withAllTags"
    ANY = "withAnyTags"


class UsedState(str, Enum):
    USED = "used"
    UNUSED = "unused"


class ProductType(str, Enum):
    APPLIANCE = "appliance"
    CAMERA = "camera"
    CELLULAR_GATEWAY = "cellularGateway"
    SENSOR = "sensor"
    SWITCH = "switch"
    SYSTEMS_MANAGER = "systemsManager"
    WIRELESS = "wireless"


class Status(str, Enum):
    ONLINE = "online"
    ALERTING = "alerting"
    OFFLINE = "offline"
    DORMANT = "dormant"


class StatusSubset(str, Enum):
    ONLINE = Status.ONLINE.value.capitalize()
    OFFLINE = Status.OFFLINE.value.capitalize()


class RecentDeviceConnection(str, Enum):
    WIRED = "Wired"
    WIRELESS = "Wireless"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMP6 = "icmp6"
    ANY = "any"


class Policy(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class PolicySubset(str, Enum):
    DENY = Policy.DENY.value


class L7FirewallRuleType(str, Enum):
    APPLICATION = "application"
    APPLICATION_CATEGORY = "applicationCategory"
    HOST = "host"
    PORT = "port"
    IP_RANGE = "ipRange"


T = TypeVar("T", bound="FirewallRuleBase")


@dataclasses.dataclass
class FirewallRuleBase:
    @classmethod
    def from_dict(cls: Type[T], env: dict) -> T:
        return cls(**{k: v for k, v in env.items() if k in inspect.signature(cls).parameters})


@dataclasses.dataclass
class L3FirewallRule(FirewallRuleBase):
    srcCidr: str
    destCidr: str
    policy: Policy
    protocol: Protocol
    comment: str | None = None
    srcPort: str | None = None
    destPort: str | None = None
    syslogEnabled: bool | None = None


@dataclasses.dataclass
class L7FirewallRule(FirewallRuleBase):
    value: str
    type: L7FirewallRuleType
    policy: PolicySubset


RuleType = TypeVar("RuleType", L3FirewallRule, L7FirewallRule)


""" Client """


class Client(BaseClient):
    """Client class to interact with the API."""

    API_V1 = "api/v1"
    MIN_PAGE_SIZE = 3
    ORGANIZATION_MAX_PER_PAGE = 9000
    NETWORK_MAX_PER_PAGE = 100000
    INVENTORY_MAX_PER_PAGE = 1000
    DEVICE_MAX_PER_PAGE = 1000
    DEVICE_STATUS_MAX_PER_PAGE = 1000
    ORGANIZATION_UPLINK_STATUS_MAX_PER_PAGE = 1000
    CLIENT_MAX_PER_PAGE = 5
    MONITOR_CLIENT_MAX_PER_PAGE = 5000
    CLIENT_POLICY_MAX_PER_PAGE = 1000

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool = True,
        proxy: bool = False,
    ) -> None:
        """Initialize the Client class.

        Args:
            base_url (str): The base URL of the API.
            api_key (str): The API bearer token.
            verify (bool, optional): Whether to verify the SSL certificate.
                Defaults to True.
            proxy (bool, optional): Whether to use a proxy.
                Defaults to False.
        """
        super().__init__(
            base_url=urljoin(base_url, self.API_V1),
            verify=verify,
            proxy=proxy,
            headers={"Authorization": f"Bearer {api_key}"},
        )

    def call_link(self, url: str) -> tuple[Any, dict[str, Any]]:
        """Call the given relationship link from a previous request.

        Args:
            url (str): URL received from a relationship link within a prior response.

        Raises:
            DemistoException: Incase the `base_url` isn't part of the given URL.

        Returns:
            tuple[Any, dict[str, Any]]: The JSON body and links response from the API.
        """
        if not url.startswith(self._base_url):
            raise DemistoException(f"Mismatch between the 'Base URL' and `next_token`. '{self._base_url}' != '{url}'")

        response: requests.Response = self._http_request(
            method="GET",
            full_url=url,
            resp_type="response",
        )

        return response.json(), response.links

    def list_organization(self, per_page: int | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """List the organizations that the user has privileges on.

        Args:
            per_page (int | None, optional): The number of entries per page returned.
                Acceptable range is 3 - 9000. If nothing is given, up to 9000 results will be returned.
                Defaults to None.

        Returns:
            tuple[list[dict[str, Any]], dict[str, Any]]: The JSON body and links response from the API.
        """
        response: requests.Response = self._http_request(
            method="GET",
            url_suffix="organizations",
            params=remove_empty_elements({"perPage": per_page}),
            resp_type="response",
        )

        return response.json(), response.links

    def get_organization(self, organization_id: str) -> dict[str, Any]:
        """Return an organization.

        Args:
            organization_id (str): ID of a specific organization to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}",
        )

    def list_network(
        self,
        organization_id: str,
        config_template_id: str | None = None,
        is_bound_to_config_template: bool | None = None,
        tags: list[str] | None = None,
        tags_filter_type: TagFilterType | None = None,
        per_page: int | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """List the networks that the user has privileges on in an organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            config_template_id (str | None, optional): ID of a config template.
                Will return all networks bound to that template.
                Defaults to None.
            is_bound_to_config_template (bool | None, optional): Filter config template bound networks.
                If config_template_id is set, this cannot be false.
                Defaults to None.
            tags (list[str] | None, optional): List of tags to filter networks by. The filtering is case-sensitive.
                If tags are included, 'tags_filter_type' should also be included.
                Defaults to None.
            tags_filter_type (TAGS_FILTER_TYPE | None, optional): Indicate whether to return networks which contain ANY
                or ALL of the included tags. If no type is included, 'withAnyTags' will be selected.
                Defaults to None.
            per_page (int | None, optional): The number of entries per page returned.
                Acceptable range is 3 - 100000. If nothing is given, up to 1000 results will be returned.
                Defaults to None.

        Returns:
            tuple[list[dict[str, Any]], dict[str, Any]]: The JSON body and links response from the API.
        """
        response: requests.Response = self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/networks",
            params=remove_empty_elements(
                {
                    "configTemplateId": config_template_id,
                    "isBoundToConfigTemplate": is_bound_to_config_template,
                    "tags[]": tags,
                    "tagsFilterType": tags_filter_type and tags_filter_type.value,
                    "perPage": per_page,
                }
            ),
            resp_type="response",
        )

        return response.json(), response.links

    def get_network(self, network_id: str) -> dict[str, Any]:
        """Return a network.

        Args:
            network_id (str): ID of a specific network to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}",
        )

    def list_organization_license_state(self, organization_id: str) -> dict[str, Any]:
        """List the license states overview of an organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/licenses/overview",
        )

    def list_organization_inventory(
        self,
        organization_id: str,
        used_state: UsedState | None = None,
        search: str | None = None,
        macs: list[str] | None = None,
        network_ids: list[str] | None = None,
        serials: list[str] | None = None,
        models: list[str] | None = None,
        order_numbers: list[str] | None = None,
        tags: list[str] | None = None,
        tags_filter_type: TagFilterType | None = None,
        product_types: list[ProductType] | None = None,
        per_page: int | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """List the device inventories for an organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            used_state (USED_STATE | None, optional): Filter results by used or unused inventory.
                Defaults to None.
            search (str | None, optional): Search for devices in inventory based on serial number,
                mac address, or model.
                Defaults to None.
            macs (list[str] | None, optional): List of mac addresses to search for in inventory.
                Defaults to None.
            network_ids (list[str] | None, optional): List of network ids to search for in inventory.
                Use explicit 'null' value to get available devices only.
                Defaults to None.
            serials (list[str] | None, optional): List of serials to search for in inventory.
                Defaults to None.
            models (list[str] | None, optional): List of models to search for in inventory.
                Defaults to None.
            order_numbers (list[str] | None, optional): List of  order numbers to search for in inventory.
                Defaults to None.
            tags (list[str] | None, optional): List of tags to filter networks by. The filtering is case-sensitive.
                If tags are included, 'tags_filter_type' should also be included.
                Defaults to None.
            tags_filter_type (TAGS_FILTER_TYPE | None, optional): Indicate whether to return networks which contain ANY
                or ALL of the included tags. If no type is included, 'withAnyTags' will be selected.
                Defaults to None.
            product_types (list[PRODUCT_TYPE] | None, optional): List of product types to search for in inventory.
                Defaults to None.
            per_page (int | None, optional): The number of entries per page returned.
                Acceptable range is 3 - 1000. If nothing is given, up to 1000 results will be returned.
                Defaults to None.

        Returns:
            tuple[list[dict[str, Any]], dict[str, Any]]: The JSON body and links response from the API.
        """
        params = remove_empty_elements(
            {
                "usedState": used_state and used_state.value,
                "search": search,
                "macs[]": macs,
                "networkIds[]": network_ids,
                "serials[]": serials,
                "models[]": models,
                "orderNumbers[]": order_numbers,
                "tags[]": tags,
                "tagsFilterType": tags_filter_type and tags_filter_type.value,
                "productTypes[]": [product_type.value for product_type in product_types or []],
                "perPage": per_page,
            }
        )

        if network_ids and network_ids[0] == "null":
            params["networkIds"] = None

        response: requests.Response = self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/inventory/devices",
            params=params,
            resp_type="response",
        )

        return response.json(), response.links

    def get_organization_inventory(self, organization_id: str, serial: str) -> dict[str, Any]:
        """Return a device inventory from an organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            serial (str): Serial number of a specific device to retrieve.


        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/inventory/devices/{serial}",
        )

    def claim_device(self, network_id: str, serials: list[str]) -> dict[str, Any]:
        """Claim devices into a network.

        (Note: for recently claimed devices, it may take a few minutes for API requests against that device to succeed).
        This operation can be used up to ten times within a single five minute window.

        Args:
            network_id (str): ID of the network to claim the devices into.
            serials (list[str]): List of serials of the devices to claim.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="POST",
            url_suffix=f"networks/{network_id}/devices/claim",
            json_data={"serials": serials},
            ok_codes=(http.HTTPStatus.OK, http.HTTPStatus.BAD_REQUEST),
        )

    def search_organization_device(
        self,
        organization_id: str,
        configuration_updated_after: str | None = None,
        network_ids: list[str] | None = None,
        product_types: list[ProductType] | None = None,
        tags: list[str] | None = None,
        tags_filter_type: TagFilterType | None = None,
        name: str | None = None,
        mac: str | None = None,
        serial: str | None = None,
        model: str | None = None,
        macs: list[str] | None = None,
        serials: list[str] | None = None,
        sensor_metrics: list[str] | None = None,
        sensor_alert_profile_ids: list[str] | None = None,
        models: list[str] | None = None,
        per_page: int | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Search for devices in an organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            configuration_updated_after (str | None, optional): Filter results by whether or not the device's
                configuration has been updated after the given epoch timestamp
                Defaults to None.
            network_ids (list[str] | None, optional): List of network IDs to retrieve from.
                Defaults to None.
            product_types (list[PRODUCT_TYPE] | None, optional): List of product types to search for in inventory.
                Defaults to None.
            tags (list[str] | None, optional): List of tags to filter networks by. The filtering is case-sensitive.
                If tags are included, 'tags_filter_type' should also be included.
                Defaults to None.
            tags_filter_type (TAGS_FILTER_TYPE | None, optional): Indicate whether to return networks which contain ANY
                or ALL of the included tags. If no type is included, 'withAnyTags' will be selected.
                Defaults to None.
            name (str | None, optional): Filter devices by name.
                All returned devices will have a name that contains the search term or is an exact match.
                Defaults to None.
            mac (str | None, optional): Filter devices by MAC address.
                All returned devices will have a MAC address that contains the search term or is an exact match.
                Defaults to None.
            serial (str | None, optional): Filter devices by serial number.
                All returned devices will have a serial number that contains the search term or is an exact match.
                Defaults to None.
            model (str | None, optional): Filter devices by model.
                All returned devices will have a model that contains the search term or is an exact match.
                Defaults to None.
            macs (list[str] | None, optional): List of MAC addresses to search.
                All returned devices will have a MAC address that is an exact match.
                Defaults to None.
            serials (list[str] | None, optional): List of serials to search.
                All returned devices will have a serial number that is an exact match.
                Defaults to None.
            sensor_metrics (list[str] | None, optional): List of metrics that they provide.
                Only applies to sensor devices.
                Defaults to None.
            sensor_alert_profile_ids (list[str] | None, optional): List of alert profiles that are bound to them.
                Only applies to sensor devices.
                Defaults to None.
            models (list[str] | None, optional): List of models to search.
                All returned devices will have a model that is an exact match.
                Defaults to None.
            per_page (int | None, optional): The number of entries per page returned.
                Acceptable range is 3 - 1000. If nothing is given, up to 1000 results will be returned.
                Defaults to None.

        Returns:
            tuple[list[dict[str, Any]], dict[str, Any]]: The JSON body and links response from the API.
        """
        response: requests.Response = self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/devices",
            params=remove_empty_elements(
                {
                    "configurationUpdatedAfter": configuration_updated_after,
                    "networkIds[]": network_ids,
                    "productTypes[]": [product_type.value for product_type in product_types or []],
                    "tags[]": tags,
                    "tagsFilterType": tags_filter_type and tags_filter_type.value,
                    "name": name,
                    "mac": mac,
                    "serial": serial,
                    "model": model,
                    "macs[]": macs,
                    "serials[]": serials,
                    "sensorMetrics[]": sensor_metrics,
                    "sensorAlertProfileIds[]": sensor_alert_profile_ids,
                    "models[]": models,
                    "perPage": per_page,
                }
            ),
            resp_type="response",
        )

        return response.json(), response.links

    def list_device(self, network_id: str) -> list[dict[str, Any]]:
        """List the devices in an network.

        Args:
            network_id (str): ID of a specific network to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/devices",
        )

    def get_device(self, serial: str) -> dict[str, Any]:
        """Return a single device

        Args:
            serial (str): Serial of a specific device to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"devices/{serial}",
        )

    def update_device(
        self,
        serial: str,
        address: str | None = None,
        floor_plan_id: str | None = None,
        name: str | None = None,
        notes: str | None = None,
        switch_profile_id: str | None = None,
        move_map_marker: bool | None = None,
        lat: float | None = None,
        lng: float | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Update the attributes of a device.

        Args:
            serial (str): Serial of a specific device to retrieve.
            address (str | None, optional): The address of a device.
                Defaults to None.
            floor_plan_id (str | None, optional): The floor plan to associate to this device.
                Use explicit 'null' value to disassociate the device from the floor plan.
                Defaults to None.
            name (str | None, optional): The name of a device.
                Defaults to None.
            notes (str | None, optional): The notes for the device. String. Limited to 255 characters.
                Defaults to None.
            switch_profile_id (str | None, optional): The ID of a switch template to bind to the device
                (for available switch templates, see the 'Switch Templates' endpoint).
                Use explicit 'null' value to unbind the switch device from the current profile.
                For a device to be bindable to a switch template,
                it must (1) be a switch, and (2) belong to a network that is bound to a configuration template.
                Defaults to None.
            move_map_marker (bool | None, optional): Whether or not to set the latitude and longitude of a device
                based on the new address. Only applies when lat and lng are not specified.
                Defaults to None.
            lat (float | None, optional): The latitude of a device.
                Defaults to None.
            lng (float | None, optional): The longitude of a device.
                Defaults to None.
            tags (list[str] | None, optional): List of tags for the device.
                Defaults to None.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        json_data = remove_empty_elements(
            {
                "address": address,
                "floorPlanId": floor_plan_id,
                "name": name,
                "notes": notes,
                "switchProfileId": switch_profile_id,
                "moveMapMarker": move_map_marker,
                "lat": lat,
                "lng": lng,
                "tags": tags,
            }
        )

        if floor_plan_id == "null":
            json_data["floorPlanId"] = None

        if switch_profile_id == "null":
            json_data["switchProfileId"] = None

        return self._http_request(
            method="PUT",
            url_suffix=f"devices/{serial}",
            json_data=json_data,
        )

    def remove_device(self, network_id: str, serial: str) -> None:
        """Remove a single device from a network.

        Args:
            network_id (str): ID of the network to remove the device from.
            serial (str): Serial of the device to remove.
        """
        self._http_request(
            method="POST",
            url_suffix=f"networks/{network_id}/devices/remove",
            json_data={"serial": serial},
            resp_type="response",
        )

    def list_device_status(
        self,
        organization_id: str,
        network_ids: list[str] | None = None,
        serials: list[str] | None = None,
        statuses: list[Status] | None = None,
        product_types: list[ProductType] | None = None,
        models: list[str] | None = None,
        tags: list[str] | None = None,
        tags_filter_type: TagFilterType | None = None,
        per_page: int | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """List the status of every Meraki device in the organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            network_ids (list[str] | None, optional): List of network ids to search for.
                Defaults to None.
            serials (list[str] | None, optional): List of serial numbers to search for.
                Defaults to None.
            statuses (list[STATUS] | None, optional): List of statuses to search for.
                Defaults to None.
            product_types (list[PRODUCT_TYPE] | None, optional): List of product types to search for.
                Defaults to None.
            models (list[str] | None, optional): List of models to search for.
                Defaults to None.
            tags (list[str] | None, optional): List of tags to filter networks by.
                The filtering is case-sensitive. If tags are included, 'tags_filter_type' should also be included.
                Defaults to None.
            tags_filter_type (TAG_FILTER_TYPE | None, optional): Indicate whether to return networks which contain ANY
                or ALL of the included tags. If no type is included, 'withAnyTags' will be selected.
                Defaults to None.
            per_page (int | None, optional): The number of entries per page returned.
                Acceptable range is 3 - 1000. If nothing is given, up to 1000 results will be returned.
                Defaults to None.

        Returns:
            tuple[list[dict[str, Any]], dict[str, Any]]: The JSON body and links response from the API.
        """
        response: requests.Response = self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/devices/statuses",
            params=remove_empty_elements(
                {
                    "networkIds[]": network_ids,
                    "serials[]": serials,
                    "statuses[]": statuses,
                    "productTypes[]": [product_type.value for product_type in product_types or []],
                    "models[]": models,
                    "tags[]": tags,
                    "tagsFilterType": tags_filter_type and tags_filter_type.value,
                    "perPage": per_page,
                }
            ),
            resp_type="response",
        )

        return response.json(), response.links

    def list_organization_uplink_status(
        self,
        organization_id: str,
        network_ids: list[str] | None = None,
        serials: list[str] | None = None,
        iccids: list[str] | None = None,
        per_page: int | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """List the uplink status of every Meraki MX, MG and Z series devices in the organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            network_ids (list[str] | None, optional): List of network ids to search for.
                Defaults to None.
            serials (list[str] | None, optional): List of serials to search for.
                Defaults to None.
            iccids (list[str] | None, optional): List of ICCIDs to search for.
                Defaults to None.
            per_page (int | None, optional): The number of entries per page returned.
                Acceptable range is 3 - 1000. If nothing is given, up to 1000 results will be returned.
                Defaults to None.

        Returns:
            tuple[list[dict[str, Any]], dict[str, Any]]: The JSON body and links response from the API.
        """
        response: requests.Response = self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/uplinks/statuses",
            params=remove_empty_elements(
                {
                    "networkIds[]": network_ids,
                    "serials[]": serials,
                    "iccids[]": iccids,
                    "perPage": per_page,
                }
            ),
            resp_type="response",
        )

        return response.json(), response.links

    def list_organization_client(
        self,
        organization_id: str,
        mac: str,
        per_page: int | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """List the client details in an organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            mac (str): The MAC address of the client.
            per_page (int | None, optional): The number of entries per page returned.
                Acceptable range is 3 - 5. If nothing is given, up to 5 results will be returned.
                Defaults to None.

        Raises:
            DemistoException: If the MAC doesn't exist within the given organization.

        Returns:
            tuple[dict[str, Any], dict[str, Any]]: The JSON body and links response from the API.
        """
        response: requests.Response = self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/clients/search",
            params=remove_empty_elements(
                {
                    "mac": mac,
                    "perPage": per_page,
                }
            ),
            resp_type="response",
        )

        if response.status_code == http.HTTPStatus.NO_CONTENT:
            raise DemistoException(
                f"The MAC '{mac}' doesn't exist or have any records in the organization '{organization_id}'."
            )

        return response.json(), response.links

    def list_network_client(
        self,
        network_id: str,
        t0: str | None = None,
        time_span: int | None = None,
        statuses: list[StatusSubset] | None = None,
        ip: str | None = None,
        ip6: str | None = None,
        ip6_local: str | None = None,
        mac: str | None = None,
        os_: str | None = None,
        psk_group: str | None = None,
        description: str | None = None,
        vlan: str | None = None,
        named_vlan: str | None = None,
        recent_device_connections: list[RecentDeviceConnection] | None = None,
        per_page: int | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """List the clients that have used this network in the time span.

        The data is updated at most once every five minutes.

        Args:
            network_id (str): ID of the network to retrieve from.
            t0 (str | None, optional): The beginning of the time span for the data.
                The maximum look back period is 31 days from today.
                Defaults to None.
            time_span (int | None, optional): The time span in seconds for which the information will be fetched.
                If specifying time span, do not specify parameter t0.
                The value must be in seconds and be less than or equal to 31 days (2678400 seconds).
                The default is 1 day.
                Defaults to None.
            statuses (list[StatusSubset] | None, optional): List of statuses.
                Defaults to None.
            ip (str | None, optional): Filters clients based on a partial or full match for the ip address field.
                Defaults to None.
            ip6 (str | None, optional): Filters clients based on a partial or full match for the ip6 address field.
                Defaults to None.
            ip6_local (str | None, optional): Filters clients based on a partial or
                full match for the ip6_local address field.
                Defaults to None.
            mac (str | None, optional): Filters clients based on a partial or full match for the mac address field.
                Defaults to None.
            os (str | None, optional): Filters clients based on a partial or
                full match for the os (operating system) field.
                Defaults to None.
            psk_group (str | None, optional): Filters clients based on partial or full match for the iPSK name field.
                Defaults to None.
            description (str | None, optional): Filters clients based on a partial or
                full match for the description field.
                Defaults to None.
            vlan (str | None, optional): Filters clients based on the full match for the VLAN field.
                Defaults to None.
            named_vlan (str | None, optional): Filters clients based on the partial or
                full match for the named VLAN field.
                Defaults to None.
            recent_device_connections (list[RecentDeviceConnection] | None, optional): List of recent connection types.
                Defaults to None.
            per_page (int | None, optional): The number of entries per page returned.
                Acceptable range is 3 - 5000. If nothing is given, up to 10 results will be returned.
                Defaults to None.

        Returns:
            tuple[list[dict[str, Any]], dict[str, Any]]: The JSON body and links response from the API.
        """
        response: requests.Response = self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/clients",
            params=remove_empty_elements(
                {
                    "t0": t0,
                    "timespan": time_span,
                    "statuses[]": [status.value for status in statuses or []],
                    "ip": ip,
                    "ip6": ip6,
                    "ip6_local": ip6_local,
                    "mac": mac,
                    "os": os_,
                    "psk_group": psk_group,
                    "description": description,
                    "vlan": vlan,
                    "named_vlan": named_vlan,
                    "recent_device_connections[]": [rdc.value for rdc in recent_device_connections or []],
                    "perPage": per_page,
                }
            ),
            resp_type="response",
        )

        return response.json(), response.links

    def get_network_client(
        self,
        network_id: str,
        client_id: str,
    ) -> dict[str, Any]:
        """Return the client associated with the given identifier.

        Args:
            network_id (str): ID of the network to retrieve from.
            client_id (str): ID of a specific client to retrieve.
                Clients can be identified by a client key or either the MAC or IP depending
                on whether the network uses Track-by-IP.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/clients/{client_id}",
        )

    def list_device_client(
        self,
        serial: str,
        t0: str | None = None,
        time_span: int | None = None,
    ) -> list[dict[str, Any]]:
        """List the clients of a device, up to a maximum of a month ago.

        The usage of each client is returned in kilobytes.
        If the device is a switch, the switchport is returned; otherwise the switchport field is null.

        Args:
            serial (str): Serial number of the device to retrieve from.
            t0 (str | None, optional): The beginning of the time_span for the data.
                The maximum look back period is 31 days from today.
                Defaults to None.
            time_span (int | None, optional): The time span in seconds for which the information will be fetched.
                If specifying time span, do not specify parameter t0.
                The value must be in seconds and be less than or equal to 31 days (2678400 seconds).
                The default is 1 day.
                Defaults to None.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"devices/{serial}/clients",
            params=remove_empty_elements(
                {
                    "t0": t0,
                    "timespan": time_span,
                }
            ),
        )

    def list_ssid_appliance(self, network_id: str) -> list[dict[str, Any]]:
        """List the MX SSIDs in a network.

        Args:
            network_id (str): ID of the network to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/appliance/ssids",
        )

    def get_network_appliance_ssid(self, network_id: str, number: str) -> dict[str, Any]:
        """Return a single MX SSID.

        Args:
            network_id (str): ID of the network to retrieve from.
            number (str): Number of a specific SSID to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/appliance/ssids/{number}",
        )

    def list_ssid_wireless(self, network_id: str) -> list[dict[str, Any]]:
        """List the MR SSIDs in a network.

        Args:
            network_id (str): ID of the network to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/wireless/ssids",
        )

    def get_network_wireless_ssid(self, network_id: str, number: str) -> dict[str, Any]:
        """Return a single MR SSID.

        Args:
            network_id (str): ID of the network to retrieve from.
            number (str): Number of a specific SSID to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/wireless/ssids/{number}",
        )

    def list_network_l3firewall_rule(self, network_id: str) -> dict[str, Any]:
        """List the L3 firewall rules for an MX network.

        Args:
            network_id (str): ID of the network to retrieve from.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/appliance/firewall/l3FirewallRules",
        )

    def update_network_l3firewall_rule(
        self,
        network_id: str,
        syslog_default_rule: bool | None = None,
        l3firewall_rules: list[L3FirewallRule] | None = None,
    ) -> dict[str, Any]:
        """Update the L3 firewall rules of an MX network.

        Args:
            network_id (str): ID of the network to update from.
            allow_lan_access (bool | None, optional): Log the special default rule,
                enable only if you've configured a syslog server.
                Defaults to None.
            l3firewall_rules: (list[L3FirewallRule] | None, optional): A list of the updated L3 firewall rules.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        if l3firewall_rules:
            payload = remove_empty_elements(
                {
                    "syslogDefaultRule": syslog_default_rule,
                    "rules": [dataclasses.asdict(l3firewall_rule) for l3firewall_rule in l3firewall_rules],
                }
            )
        else:
            payload = {"rules": None}

        return self._http_request(
            method="PUT",
            url_suffix=f"networks/{network_id}/appliance/firewall/l3FirewallRules",
            json_data=payload,
        )

    def list_network_l7firewall_rule(self, network_id: str) -> dict[str, Any]:
        """List the MX L7 firewall rules for an MX network.

        Args:
            network_id (str): ID of the network to retrieve from.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/appliance/firewall/l7FirewallRules",
        )

    def update_network_l7firewall_rule(
        self,
        network_id: str,
        l7firewall_rules: list[L7FirewallRule] | None = None,
    ) -> dict[str, Any]:
        """Update the MX L7 firewall rules for an MX network.

        Args:
            network_id (str): ID of the network to update from.
            l7firewall_rules: (list[L7FirewallRule] | None, optional): A list of the updated L7 firewall rules.
                Defaults to None.


        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="PUT",
            url_suffix=f"networks/{network_id}/appliance/firewall/l7FirewallRules",
            json_data={
                "rules": (
                    [dataclasses.asdict(l7firewall_rule) for l7firewall_rule in l7firewall_rules]
                    if l7firewall_rules
                    else None
                ),
            },
        )

    def list_organization_adaptive_policy_acl(self, organization_id: str) -> list[dict[str, Any]]:
        """List adaptive policy ACLs in a organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/adaptivePolicy/acls",
        )

    def get_organization_adaptive_policy_acl(self, organization_id: str, acl_id: str) -> dict[str, Any]:
        """Returns the adaptive policy ACL information.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            acl_id (str): ID of a specific ACL to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/adaptivePolicy/acls/{acl_id}",
        )

    def list_organization_adaptive_policy(self, organization_id: str) -> list[dict[str, Any]]:
        """List adaptive policies in an organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/adaptivePolicy/policies",
        )

    def get_organization_adaptivepolicy(self, organization_id: str, adaptive_policy_id: str) -> dict[str, Any]:
        """Return an adaptive policy.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            adaptive_policy_id (str): ID of a specific adaptive policy to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/adaptivePolicy/policies/{adaptive_policy_id}",
        )

    def list_organization_adaptive_policy_group(self, organization_id: str) -> list[dict[str, Any]]:
        """List adaptive policy groups in a organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/organizations/{organization_id}/adaptivePolicy/groups",
        )

    def get_organization_adaptive_policy_group(
        self,
        organization_id: str,
        adaptive_policy_group_id: str,
    ) -> dict[str, Any]:
        """Returns an adaptive policy group.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            adaptive_policy_group_id (str): ID of a specific adaptive policy group to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/organizations/{organization_id}/adaptivePolicy/groups/{adaptive_policy_group_id}",
        )

    def list_organization_adaptive_policy_settings(self, organization_id: str) -> dict[str, Any]:
        """Returns global adaptive policy settings in an organization.

        Args:
            organization_id (str): ID of the organization to retrieve from.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/adaptivePolicy/settings",
        )

    def list_organization_branding_policy(self, organization_id: str) -> list[dict[str, Any]]:
        """List the branding policies of an organization.

        This allows MSPs to view and monitor certain aspects of Dashboard for their users and customers.

        Args:
            organization_id (str): ID of the organization to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """

        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/brandingPolicies",
        )

    def get_organization_branding_policy(self, organization_id: str, branding_policy_id: str) -> dict[str, Any]:
        """Return a branding policy.

        Args:
            organization_id (str): ID of the organization to retrieve from.
            branding_policy_id (str): ID of a specific branding policy to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"organizations/{organization_id}/brandingPolicies/{branding_policy_id}",
        )

    def list_network_grouppolicy(self, network_id: str) -> list[dict[str, Any]]:
        """List the group policies in a network.

        Args:
            network_id (str): ID of the network to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/groupPolicies",
        )

    def get_network_grouppolicy(self, network_id: str, group_policy_id: str) -> dict[str, Any]:
        """Return a group policy.

        Args:
            network_id (str): ID of the network to retrieve from.
            group_policy_id (str): ID of a specific group policy to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/groupPolicies/{group_policy_id}",
        )

    def list_network_client_policy(
        self,
        network_id: str,
        t0: str | None = None,
        time_span: int | None = None,
        per_page: int | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """List policies for all clients with policies.

        Args:
            network_id (str): ID of the network to retrieve from.
            t0 (str | None, optional): The beginning of the time_span for the data.
                The maximum look back period is 31 days from today.
                Defaults to None.
            time_span (int | None, optional): The time span in seconds for which the information will be fetched.
                If specifying time span, do not specify parameter t0.
                The value must be in seconds and be less than or equal to 31 days (2678400 seconds).
                The default is 1 day.
                Defaults to None.
            per_page (int | None, optional): The number of entries per page returned.
                Acceptable range is 3 - 1000. If nothing is given, up to 50 results will be returned.
                Defaults to None.

        Returns:
            tuple[list[dict[str, Any]], dict[str, Any]]: The JSON body and links response from the API.
        """
        response: requests.Response = self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/policies/byClient",
            params=remove_empty_elements(
                {
                    "t0": t0,
                    "timespan": time_span,
                    "perPage": per_page,
                }
            ),
            resp_type="response",
        )

        return response.json(), response.links

    def list_network_vlan_profile(self, network_id: str) -> list[dict[str, Any]]:
        """List VLAN profiles for a network.

        Args:
            network_id (str): ID of the network to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/vlanProfiles",
        )

    def get_network_vlan_profile(self, network_id: str, iname: str) -> dict[str, Any]:
        """Get an existing VLAN profile of a network

        Args:
            network_id (str): ID of the network to retrieve from.
            iname (str): Iname of a specific VLAN profile to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/vlanProfiles/{iname}",
        )

    def list_network_appliance_vlan(self, network_id: str) -> list[dict[str, Any]]:
        """List the VLANs for an MX network.

        Args:
            network_id (str): ID of the network to retrieve from.

        Returns:
            list[dict[str, Any]]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/appliance/vlans",
        )

    def get_network_appliance_vlan(self, network_id: str, vlan_id: str) -> dict[str, Any]:
        """Return a VLAN.

        Args:
            network_id (str): ID of the network to retrieve from.
            vlan_id (str): ID of a specific VLAN profile to retrieve.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"networks/{network_id}/appliance/vlans/{vlan_id}",
        )


""" Helper Commands  """


def automatic_pagination(
    client: Client,
    limit: int,
    max_per_page: int,
    list_request: Callable[..., tuple[list[dict[str, Any]], dict[str, Any]]],
    request_args: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Automatically paginates through API responses until a specified limit is reached.

    Args:
        client (Client): Session to the API to run HTTP requests.
        limit (int): The maximum number of items to retrieve.
        max_per_page (int): The maximum number of items to retrieve per page.
        list_request (Callable[..., tuple[list[dict[str, Any]], dict[str, Any]]]):
            A callable that returns a tuple containing a list of data and a dictionary of links for pagination.
        request_args (dict[str, Any] | None, optional): Arguments to be passed to the list_request function.
            Defaults to None.

    Returns:
        list[dict[str, Any]]: A list of items retrieved from the API, up to the specified limit.
    """
    result, links = list_request(
        **(request_args if request_args else {}),
        per_page=min(max(limit, Client.MIN_PAGE_SIZE), max_per_page),
    )

    # Loop until the desired limit has been reached or the API has been exhausted.
    while len(result) < limit and (next_url := dict_safe_get(links, ["next", "url"])):
        response, links = client.call_link(next_url)
        result += response

    return result[:limit]


def get_relationship_link_command_result(outputs_prefix: str, links: dict[str, Any]) -> CommandResults:
    """Generates a CommandResults object containing relationship link tokens.

    Args:
        outputs_prefix (str): The prefix to be used for the outputs.
        links (dict[str, Any]): A dictionary containing pagination links.

    Returns:
        CommandResults: An object containing the processed link tokens.
    """
    headers = [
        "Prev",
        "Next",
        "First",
        "Last",
    ]

    outputs = {header: dict_safe_get(links, [header.lower(), "url"]) for header in headers}

    if next_token := outputs.get("Next"):
        readable_output = f"{outputs_prefix} Link Tokens for {next_token=}."
    else:
        readable_output = "Done paginating through the records."

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{outputs_prefix}LinkTokens",
        outputs=outputs,
        readable_output=readable_output,
    )


def arg_to_optional_bool(arg: Any | None) -> None | bool:
    """Converts an argument to an optional boolean value.

    Args:
        arg (Any | None): The argument to be converted. Can be of any type or None.

    Returns:
        None | bool: Returns None if the argument is None; otherwise, returns the boolean representation of the arg.
    """
    return None if arg is None else argToBoolean(arg)


def create_organization_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "ID": item.get("id"),
            "Name": item.get("name"),
            "URL": item.get("url"),
            "Cloud Region Name": dict_safe_get(item, ["cloud", "region", "name"]),
            "Cloud Region Host Name": dict_safe_get(item, ["cloud", "region", "host", "name"]),
        }
        for item in obj
    ]


def create_network_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "ID": item.get("id"),
            "Name": item.get("name"),
            "Organization ID": item.get("organizationId"),
            "URL": item.get("url"),
        }
        for item in obj
    ]


def create_organization_license_state_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    table = []

    for item in obj:
        states = item.get("states", {})
        expiring = states.get("expiring", {})

        table.append(
            {
                "License Count": item.get("licenseCount"),
                "Expiration Date": item.get("expirationDate"),
                "Status": item.get("status"),
                "License Types": [license_type.get("licenseType") for license_type in item.get("licenseTypes", [])],
                "States Expired Count": dict_safe_get(states, ["expired", "count"]),
                "States Expiring Count": expiring.get("count"),
                "States Critical Expiring Count": dict_safe_get(expiring, ["critical", "expiringCount"]),
                "States Critical Expiring Threshold in Days": dict_safe_get(expiring, ["critical", "thresholdInDays"]),
                "States Warning Expiring count": dict_safe_get(expiring, ["warning", "expiringCount"]),
                "States Warning Expiring Threshold in Days": dict_safe_get(expiring, ["warning", "thresholdInDays"]),
            }
        )

    return table


def create_organization_inventory_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Claimed At": item.get("claimedAt"),
            "License Expiration Date": item.get("licenseExpirationDate"),
            "MAC": item.get("mac"),
            "Model": item.get("model"),
            "Name": item.get("name"),
            "Network ID": item.get("networkId"),
            "Product Type": item.get("productType"),
            "Serial": item.get("serial"),
        }
        for item in obj
    ]


def create_device_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Address": item.get("address"),
            "Firmware": item.get("firmware"),
            "Lan IP": item.get("lanIp"),
            "Model": item.get("model"),
            "Name": item.get("name"),
            "Network ID": item.get("networkId"),
            "Serial": item.get("serial"),
        }
        for item in obj
    ]


def create_device_status_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Gateway": item.get("gateway"),
            "IP Type": item.get("ipType"),
            "Lan IP": item.get("lanIp"),
            "Last Reported At": item.get("lastReportedAt"),
            "Model": item.get("model"),
            "Name": item.get("name"),
            "Network ID": item.get("networkId"),
            "Public IP": item.get("publicIp"),
            "Serial": item.get("serial"),
            "Status": item.get("status"),
        }
        for item in obj
    ]


def create_organization_uplink_status_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    table = []

    for item in obj:
        row: dict[str, Any] = {
            "Last Reported At": item.get("lastReportedAt"),
            "Model": item.get("model"),
            "Network ID": item.get("networkId"),
            "Serial": item.get("serial"),
            "Uplink ICCID": [],
            "Uplink Interface": [],
            "Uplink IP": [],
            "Uplink Public IP": [],
            "Uplink Signal Type": [],
            "Uplink Status": [],
        }

        for uplink in item.get("uplinks", []):
            if val := uplink.get("iccid"):
                row["Uplink ICCID"].append(val)

            if val := uplink.get("interface"):
                row["Uplink Interface"].append(val)

            if val := uplink.get("ip"):
                row["Uplink IP"].append(val)

            if val := uplink.get("publicIp"):
                row["Uplink Public IP"].append(val)

            if val := uplink.get("signalType"):
                row["Uplink Signal Type"].append(val)

            if val := uplink.get("status"):
                row["Uplink Status"].append(val)

        table.append(row)

    return table


def create_client_table(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Description": item.get("description"),
            "IP": item.get("ip"),
            "OS": item.get("os"),
            "Status": item.get("status"),
            "User": item.get("user"),
            "Network ID": dict_safe_get(item, ["network", "id"]),
            "Network Name": dict_safe_get(item, ["network", "name"]),
        }
        for item in obj.get("records", [])
    ]


def create_monitor_client_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Description": item.get("description"),
            "ID": item.get("id"),
            "IP": item.get("ip"),
            "OS": item.get("os"),
            "Recent Device Name": item.get("recentDeviceName"),
            "SSID": item.get("ssid"),
            "Status": item.get("status"),
            "User": item.get("user"),
            "Usage Received": dict_safe_get(item, ["usage", "recv"]),
            "Usage Sent": dict_safe_get(item, ["usage", "sent"]),
        }
        for item in obj
    ]


def create_device_monitor_client_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Description": item.get("description"),
            "ID": item.get("id"),
            "IP": item.get("ip"),
            "MAC": item.get("mac"),
            "MDNS Name": item.get("mdnsName"),
            "Switch Port": item.get("switchPort"),
            "User": item.get("user"),
            "Usage Received": dict_safe_get(item, ["usage", "recv"]),
            "Usage Sent": dict_safe_get(item, ["usage", "sent"]),
        }
        for item in obj
    ]


def create_ssid_appliance_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Default VLAN ID": item.get("defaultVlanId"),
            "Number": item.get("number"),
            "Name": item.get("name"),
            "SSID Enabled": item.get("enabled"),
            "Visible": item.get("visible"),
        }
        for item in obj
    ]


def create_ssid_wireless_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Number": item.get("number"),
            "Name": item.get("name"),
            "Admin Splash URL": item.get("adminSplashUrl"),
            "IP Assignment Mode": item.get("ipAssignmentMode"),
            "Enable": item.get("enabled"),
            "Radius Enabled": item.get("radiusEnabled"),
            "Visible": item.get("visible"),
            "Availability Tags": item.get("availabilityTags"),
        }
        for item in obj
    ]


def create_l3firewall_rule_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Comment": item.get("comment"),
            "Policy": item.get("policy"),
            "Protocol": item.get("protocol"),
            "Destination Port": item.get("destPort"),
            "Destination CIDR": item.get("destCidr"),
            "Source Port": item.get("srcPort"),
            "Source CIDR": item.get("srcCidr"),
            "Syslog Enabled": item.get("syslogEnabled"),
        }
        for item in obj
    ]


def create_l7firewall_rule_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Policy": item.get("policy"),
            "Type": item.get("type"),
            "Value": item.get("value"),
        }
        for item in obj
    ]


def create_adaptive_policy_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    table = []

    for item in obj:
        destination_group = item.get("destinationGroup", {})
        source_group = item.get("sourceGroup", {})

        row: dict[str, Any] = {
            "Adaptive Policy ID": item.get("adaptivePolicyId"),
            "Destination Group ID": destination_group.get("id"),
            "Destination Group Name": destination_group.get("name"),
            "Source Group ID": source_group.get("id"),
            "Source Group Name": source_group.get("name"),
            "ACL IDS": [],
            "ACL Names": [],
        }

        for acl in item.get("acls", []):
            if val := acl.get("id"):
                row["ACL IDS"].append(val)

            if val := acl.get("name"):
                row["ACL Names"].append(val)

        table.append(row)

    return table


def create_adaptive_policy_acl_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    table = []

    for item in obj:
        row: dict[str, Any] = {
            "ACL ID": item.get("aclId"),
            "Created At": item.get("createdAt"),
            "Description": item.get("description"),
            "Name": item.get("name"),
            "Rules Policy": [],
            "Rules Protocol": [],
            "Rules Destination Port": [],
            "Rules Source Port": [],
        }

        for rule in item.get("rules", []):
            if val := rule.get("dstPort"):
                row["Rules Destination Port"].append(val)

            if val := rule.get("srcPort"):
                row["Rules Source Port"].append(val)

            if val := rule.get("protocol"):
                row["Rules Protocol"].append(val)

            if val := rule.get("policy"):
                row["Rules Policy"].append(val)

        table.append(row)

    return table


def create_adaptive_policy_group_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    table = []

    for item in obj:
        row: dict[str, Any] = {
            "Security Group Tag": item.get("sgt"),
            "Description": item.get("description"),
            "Group ID": item.get("groupId"),
            "Name": item.get("name"),
            "Policy Object IDs": [],
            "Policy Object Names": [],
        }

        for policy_object in item.get("policyObjects", []):
            if val := policy_object.get("id"):
                row["Policy Object IDs"].append(val)

            if val := policy_object.get("name"):
                row["Policy Object Names"].append(val)

        table.append(row)

    return table


def create_branding_policy_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    table = []

    for item in obj:
        admin_settings = item.get("adminSettings", {})
        table.append(
            {
                "Name": item.get("name"),
                "Enabled": item.get("enabled"),
                "Admin Settings Applies To": admin_settings.get("appliesTo"),
                "Admin Settings Values": admin_settings.get("values"),
            }
        )

    return table


def create_group_policy_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    table = []

    for item in obj:
        content_filtering = item.get("contentFiltering", {})
        row = {
            "Group Policy ID": item.get("groupPolicyId"),
            "Group Policy Name": item.get("name"),
            "Group Splash Auth Settings": item.get("splashAuthSettings"),
            "Bonjour Forwarding Rules VLAN ID": [],
            "Bonjour Forwarding Rules Services": [],
            "Blocked URL Categories": dict_safe_get(content_filtering, ["blockedUrlCategories", "categories"]),
            "Blocked URL Patterns": dict_safe_get(content_filtering, ["blockedUrlPatterns", "patterns"]),
        }

        for rule in dict_safe_get(item, ["bonjourForwarding", "rules"], []):
            if val := rule.get("vlanId"):
                row["Bonjour Forwarding Rules VLAN ID"].append(val)

            if val := rule.get("services"):
                row["Bonjour Forwarding Rules Services"].append(val)

        table.append(row)

    return table


def create_client_policy_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    table = []

    for item in obj:
        row: dict[str, Any] = {
            "Client ID": item.get("clientId"),
            "Name": item.get("name"),
            "Assigned Group Policy ID": [],
            "Assigned Name": [],
            "Assigned Type": [],
            "Assigned SSID": [],
        }

        for assigned in item.get("assigned", []):
            if val := assigned.get("groupPolicyId"):
                row["Assigned Group Policy ID"].append(val)

            if val := assigned.get("name"):
                row["Assigned Name"].append(val)

            if val := assigned.get("type"):
                row["Assigned Type"].append(val)

            if val := assigned.get("ssid"):
                row["Assigned SSID"].append([v.get("ssidNumber") for v in val])

        table.append(row)

    return table


def create_vlan_profile_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    table = []

    for item in obj:
        row: dict[str, Any] = {
            "IName": item.get("iname"),
            "Name": item.get("name"),
            "Is Default": item.get("isDefault"),
            "VLAN Group Names": [],
            "VLAN Names": [],
            "VLAN Names Adaptive Policy Group Names": [],
        }

        for vlan_name in item.get("vlanGroups", []):
            if val := vlan_name.get("name"):
                row["VLAN Group Names"].append(val)

        for vlan_name in item.get("vlanNames", []):
            if val := vlan_name.get("name"):
                row["VLAN Names"].append(val)

            if val := dict_safe_get(vlan_name, ["adaptivePolicyGroup", "name"]):
                row["VLAN Names Adaptive Policy Group Names"].append(val)

        table.append(row)

    return table


def create_appliance_vlan_table(obj: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a table in a list of dicts form from the given object.

    Args:
        obj (list[dict[str, Any]]): The object to create extract the data from for the rows.

    Returns:
        list[dict[str, Any]]: The converted table.
    """
    return [
        {
            "Mask": item.get("mask"),
            "Appliance IP": item.get("applianceIp"),
            "CIDR": item.get("cidr"),
            "Group Policy ID": item.get("groupPolicyId"),
            "ID": item.get("id"),
            "Interface ID": item.get("interfaceId"),
            "Name": item.get("name"),
            "Subnet": item.get("subnet"),
        }
        for item in obj
    ]


def get_valid_arg(args: dict[str, Any], key: str) -> str:
    """Get the value of a key from the arguments.

    Args:
        args (dict[str, Any]): The arguments to get the value from.
        key (str): The key to get the value of.

    Raises:
        ValueError: If the key is not found and no default value is provided.

    Returns:
        str: The value of the key.
    """
    if not (value := args.get(key)):
        raise DemistoException(f"Missing required argument: {key}")

    return value


def create_firewall_rules(entry_id: str, rule_type: Type[RuleType]) -> list[RuleType]:
    """Create a list of rules from a file.

    Args:
        entry_id (str): The entry ID of the file to read.
        rule_type (Type[RuleType]): The type of rule to create.

    Returns:
        list[RuleType]: The list of rules created from the file.
    """
    file_entry = demisto.getFilePath(entry_id)

    with open(file_entry["path"], "rb") as handler:
        content = handler.read()

    return [rule_type.from_dict(rule) for rule in json.loads(content)]


""" Command Handlers """


@logger
def test_module(client: Client) -> str:
    """Test the connection to the API.

    Args:
        client (Client): Session to the API to run HTTP requests.

    Raises:
        DemistoException: When an unknown HTTP error has occurred.

    Returns:
        str: returns "ok" which represents that the test connection to the client was successful.
            Otherwise, return an informative message based on the user's input.
    """
    try:
        client.list_organization()
    except DemistoException as exc:
        if exc.res is not None:
            if exc.res.status_code == http.HTTPStatus.UNAUTHORIZED:
                return "Authorization Error: invalid `API Key`"

            if exc.res.status_code == http.HTTPStatus.NOT_FOUND:
                return "The input `Base URL` is invalid"

        raise exc

    return "ok"


@logger
def list_organization_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """List the organizations that the user has privileges on.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        list[CommandResults]: Outputs of the command that represent an entry in warroom.
    """
    links = None

    # Handle relationship link request.
    if next_token := args.get("next_token"):
        raw_response, links = client.call_link(next_token)
    # Handle GET request.
    elif organization_id := args.get("organization_id"):
        raw_response = [client.get_organization(organization_id)]
    # Handle LIST request.
    else:
        if page_size := arg_to_number(args.get("page_size")):
            raw_response, links = client.list_organization(page_size)
        else:
            limit = arg_to_number(args["limit"]) or DEFAULT_PAGE_SIZE

            raw_response = automatic_pagination(
                client=client,
                limit=limit,
                max_per_page=Client.ORGANIZATION_MAX_PER_PAGE,
                list_request=client.list_organization,
            )

    readable_output = tableToMarkdown(
        name="Organization(s)",
        t=create_organization_table(raw_response),
        headers=ORGANIZATION_TABLE_HEADERS,
        removeNull=True,
    )
    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_PREFIX}.{ORGANIZATION_PREFIX}",
            outputs_key_field="id",
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response,
        )
    ]

    if links:
        command_results.append(get_relationship_link_command_result(ORGANIZATION_PREFIX, links))

    return command_results


@logger
def list_network_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """List the networks that the user has privileges on in an organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If none of the required arguments is present.

    Returns:
        list[CommandResults]: Outputs of the command that represent an entry in warroom.
    """
    links = None

    # Handle relationship link request.
    if next_token := args.get("next_token"):
        raw_response, links = client.call_link(next_token)
    # Handle GET request.
    elif network_id := args.get("network_id"):
        raw_response = [client.get_network(network_id)]
    # Handle LIST request.
    elif organization_id := args.get("organization_id"):
        tags_filter_type = args.get("tags_filter_type")
        request_args = remove_empty_elements(
            {
                "organization_id": organization_id,
                "config_template_id": args.get("config_template_id"),
                "is_bound_to_config_template": arg_to_optional_bool(args.get("is_bound_to_config_template")),
                "tags": argToList(args.get("tags")),
                "tags_filter_type": tags_filter_type and TagFilterType(tags_filter_type),
            }
        )

        if page_size := arg_to_number(args.get("page_size")):
            raw_response, links = client.list_network(
                **request_args,
                per_page=page_size,
            )
        else:
            raw_response = automatic_pagination(
                client=client,
                limit=arg_to_number(args["limit"]) or DEFAULT_PAGE_SIZE,
                max_per_page=Client.NETWORK_MAX_PER_PAGE,
                list_request=client.list_network,
                request_args=request_args,
            )
    else:
        raise DemistoException("Must input one of: `network_id`, `next_token` or `organization_id`.")

    readable_output = tableToMarkdown(
        name="Network(s)",
        t=create_network_table(raw_response),
        headers=NETWORK_TABLE_HEADERS,
        removeNull=True,
    )

    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_PREFIX}.{NETWORK_PREFIX}",
            outputs_key_field="id",
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response,
        )
    ]

    if links:
        command_results.append(get_relationship_link_command_result(NETWORK_PREFIX, links))

    return command_results


@logger
def list_organization_license_state_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the license states overview of an organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    organization_id = get_valid_arg(args, "organization_id")

    raw_response = client.list_organization_license_state(organization_id)
    raw_response["organizationId"] = organization_id

    readable_output = tableToMarkdown(
        name="License State(s)",
        t=create_organization_license_state_table([raw_response]),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.LicenseState",
        outputs_key_field="organizationId",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_organization_inventory_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """List the device inventories for an organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If none of the required combinations are present.

    Returns:
        list[CommandResults]: Outputs of the command that represent an entry in warroom.
    """
    links = None

    # Handle relationship link request.
    if next_token := args.get("next_token"):
        raw_response, links = client.call_link(next_token)
    # Handle LIST request.
    elif organization_id := args.get("organization_id"):
        # Handle GET request.
        if serial := args.get("serial"):
            raw_response = [client.get_organization_inventory(organization_id, serial)]
        else:
            used_state = args.get("used_state")
            tags_filter_type = args.get("tags_filter_type")
            request_args = remove_empty_elements(
                {
                    "organization_id": organization_id,
                    "used_state": used_state and UsedState(used_state),
                    "search": args.get("search"),
                    "macs": argToList(args.get("macs")),
                    "network_ids": argToList(args.get("network_ids")),
                    "serials": argToList(args.get("serials")),
                    "models": argToList(args.get("models")),
                    "order_numbers": argToList(args.get("order_numbers")),
                    "tags": argToList(args.get("tags")),
                    "tags_filter_type": tags_filter_type and TagFilterType(tags_filter_type),
                    "product_types": [
                        ProductType(product_type) for product_type in argToList(args.get("product_types"))
                    ],
                }
            )

            if page_size := arg_to_number(args.get("page_size")):
                raw_response, links = client.list_organization_inventory(
                    **request_args,
                    per_page=page_size,
                )
            else:
                raw_response = automatic_pagination(
                    client=client,
                    limit=arg_to_number(args["limit"]) or DEFAULT_PAGE_SIZE,
                    max_per_page=Client.INVENTORY_MAX_PER_PAGE,
                    list_request=client.list_organization_inventory,
                    request_args=request_args,
                )
    else:
        raise DemistoException("Must input one of: `network_id`,`next_token` or `organization_id`.")

    readable_output = tableToMarkdown(
        name="Inventory Device(s)",
        t=create_organization_inventory_table(raw_response),
        headers=INVENTORY_TABLE_HEADERS,
        removeNull=True,
    )

    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_PREFIX}.{INVENTORY_PREFIX}",
            outputs_key_field="serial",
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response,
        )
    ]

    if links:
        command_results.append(get_relationship_link_command_result(INVENTORY_PREFIX, links))

    return command_results


@logger
def claim_device_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Claim devices into a network.

    (Note: for recently claimed devices, it may take a few minutes for API requests against that device to succeed).
    This operation can be used up to ten times within a single five minute window.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    raw_response = client.claim_device(network_id, argToList(args["serials"]))
    readable_output = ""

    if claimed_devices := "\n- ".join(raw_response.get("serials", [])):
        readable_output += f"## The device(s) were successfully claimed into the network '{network_id}':"
        readable_output += f"\n- {claimed_devices}"

    if errors := raw_response.get("errors", []):
        readable_output += "\n## The device(s) couldn't be claimed for the following reason(s):"

        if isinstance(errors[0], dict):
            readable_output += "".join(
                [f"\n- {error.get('serial')} failed due to: {error.get('errors')}." for error in errors]
            )
        else:
            readable_output += "".join([f"\n- {error}" for error in errors])

    return CommandResults(readable_output=readable_output)


@logger
def search_organization_device_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Search for devices in an organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If none of the required combinations is present.
    Returns:
        list[CommandResults]: Outputs of the command that represent an entry in warroom.
    """
    links = None

    # Handle relationship link request.
    if next_token := args.get("next_token"):
        raw_response, links = client.call_link(next_token)
    # Handle LIST request.
    elif organization_id := args.get("organization_id"):
        tags_filter_type = args.get("tags_filter_type")
        request_args = remove_empty_elements(
            {
                "organization_id": organization_id,
                "configuration_updated_after": arg_to_datetime(args.get("configuration_updated_after")),
                "network_ids": argToList(args.get("network_ids")),
                "product_types": [ProductType(product_type) for product_type in argToList(args.get("product_types"))],
                "tags": argToList(args.get("tags")),
                "tags_filter_type": tags_filter_type and TagFilterType(tags_filter_type),
                "name": args.get("name"),
                "mac": args.get("mac"),
                "serial": args.get("serial"),
                "model": args.get("model"),
                "macs": argToList(args.get("macs")),
                "serials": argToList(args.get("serials")),
                "sensor_metrics": argToList(args.get("sensor_metrics")),
                "sensor_alert_profile_ids": argToList(args.get("sensor_alert_profile_ids")),
                "models": argToList(args.get("models")),
            }
        )

        if page_size := arg_to_number(args.get("page_size")):
            raw_response, links = client.search_organization_device(
                **request_args,
                per_page=page_size,
            )
        else:
            raw_response = automatic_pagination(
                client=client,
                limit=arg_to_number(args["limit"]) or DEFAULT_PAGE_SIZE,
                max_per_page=Client.DEVICE_MAX_PER_PAGE,
                list_request=client.search_organization_device,
                request_args=request_args,
            )
    else:
        raise DemistoException("Must input one of: `next_token` or `organization_id`.")

    readable_output = tableToMarkdown(
        name="Device(s)",
        t=create_device_table(raw_response),
        headers=DEVICE_TABLE_HEADERS,
        removeNull=True,
    )

    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_PREFIX}.{DEVICE_PREFIX}",
            outputs_key_field="serial",
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response,
        )
    ]

    if links:
        command_results.append(get_relationship_link_command_result(DEVICE_PREFIX, links))

    return command_results


@logger
def list_device_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the devices in an network or fetch a specific with a serial number. Input must contain 1 parameter.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    if serial := args.get("serial"):
        raw_response = [client.get_device(serial)]
    elif network_id := args.get("network_id"):
        raw_response = client.list_device(network_id)
    else:
        raise DemistoException("Must input one of: `network_id` or `serial`.")

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="Device(s)",
        t=create_device_table(raw_response),
        headers=DEVICE_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{DEVICE_PREFIX}",
        outputs_key_field="serial",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def update_device_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update the attributes of a device.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    serial = args["serial"]

    raw_response = client.update_device(
        serial=serial,
        address=args.get("address"),
        floor_plan_id=args.get("floor_plan_id"),
        name=args.get("name"),
        notes=args.get("notes"),
        switch_profile_id=args.get("switch_profile_id"),
        move_map_marker=arg_to_optional_bool(args.get("move_map_marker")),
        lat=arg_to_number(args.get("lat")),
        lng=arg_to_number(args.get("lng")),
        tags=argToList(args.get("tags")),
    )

    readable_output = tableToMarkdown(
        name=f"The device '{serial}' was successfully updated.",
        t=create_device_table([raw_response]),
        headers=DEVICE_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{DEVICE_PREFIX}",
        outputs_key_field="serial",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def remove_device_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Remove a single device from a network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")
    serial = args["serial"]

    client.remove_device(network_id, serial)

    return CommandResults(
        readable_output=(
            f"## The device with the serial number: '{serial}'"
            f" was successfully removed from the network '{network_id}'."
        )
    )


@logger
def list_device_status_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """List the status of every Meraki device in the organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If none of the required combinations is present.

    Returns:
        list[CommandResults]: Outputs of the command that represent an entry in warroom.
    """
    links = None

    # Handle relationship link request.
    if next_token := args.get("next_token"):
        raw_response, links = client.call_link(next_token)
    # Handle LIST request.
    elif organization_id := args.get("organization_id"):
        tags_filter_type = args.get("tags_filter_type")
        request_args = remove_empty_elements(
            {
                "organization_id": organization_id,
                "network_ids": argToList(args.get("network_ids")),
                "serials": argToList(args.get("serials")),
                "statuses": [Status(status) for status in argToList(args.get("statuses"))],
                "product_types": [ProductType(product_type) for product_type in argToList(args.get("product_types"))],
                "models": argToList(args.get("models")),
                "tags": argToList(args.get("tags")),
                "tags_filter_type": tags_filter_type and TagFilterType(tags_filter_type),
            }
        )

        if page_size := arg_to_number(args.get("page_size")):
            raw_response, links = client.list_device_status(
                **request_args,
                per_page=page_size,
            )
        else:
            raw_response = automatic_pagination(
                client=client,
                limit=arg_to_number(args["limit"]) or DEFAULT_PAGE_SIZE,
                max_per_page=Client.DEVICE_STATUS_MAX_PER_PAGE,
                list_request=client.list_device_status,
                request_args=request_args,
            )
    else:
        raise DemistoException("Must input one of: `next_token` or `organization_id`.")

    readable_output = tableToMarkdown(
        name="Device Status(es)",
        t=create_device_status_table(raw_response),
        headers=DEVICE_STATUS_TABLE_HEADERS,
        removeNull=True,
    )

    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_PREFIX}.{DEVICE_STATUS_PREFIX}",
            outputs_key_field="serial",
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response,
        )
    ]

    if links:
        command_results.append(get_relationship_link_command_result(DEVICE_STATUS_PREFIX, links))

    return command_results


@logger
def list_organization_uplink_status_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """List the uplink status of every Meraki MX, MG and Z series devices in the organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If none of the required combinations is present.

    Returns:
        list[CommandResults]: Outputs of the command that represent an entry in warroom.
    """
    links = None

    # Handle relationship link request.
    if next_token := args.get("next_token"):
        raw_response, links = client.call_link(next_token)
    # Handle LIST request.
    elif organization_id := args.get("organization_id"):
        request_args = remove_empty_elements(
            {
                "organization_id": organization_id,
                "network_ids": argToList(args.get("network_ids")),
                "serials": argToList(args.get("serials")),
                "iccids": argToList(args.get("iccids")),
            }
        )

        if page_size := arg_to_number(args.get("page_size")):
            raw_response, links = client.list_organization_uplink_status(
                **request_args,
                per_page=page_size,
            )
        else:
            raw_response = automatic_pagination(
                client=client,
                limit=arg_to_number(args["limit"]) or DEFAULT_PAGE_SIZE,
                max_per_page=Client.ORGANIZATION_UPLINK_STATUS_MAX_PER_PAGE,
                list_request=client.list_organization_uplink_status,
                request_args=request_args,
            )
    else:
        raise DemistoException("Must input one of: `next_token` or `organization_id`.")

    readable_output = tableToMarkdown(
        name="Uplink Status(es)",
        t=create_organization_uplink_status_table(raw_response),
        headers=ORGANIZATION_UPLINK_STATUS_TABLE_HEADERS,
        removeNull=True,
    )

    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_PREFIX}.{ORGANIZATION_UPLINK_STATUS_PREFIX}",
            outputs_key_field="serial",
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response,
        )
    ]

    if links:
        command_results.append(get_relationship_link_command_result(ORGANIZATION_UPLINK_STATUS_PREFIX, links))

    return command_results


@logger
def list_organization_client_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """List the clients in an organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If none of the required combinations is present.

    Returns:
        list[CommandResults]: Outputs of the command that represent an entry in warroom.
    """
    links = None

    # Handle relationship link request.
    if next_token := args.get("next_token"):
        raw_response, links = client.call_link(next_token)
    # Handle LIST request.
    elif (organization_id := args.get("organization_id")) and (mac := args.get("mac")):
        request_args = {
            "organization_id": organization_id,
            "mac": mac,
        }

        if page_size := arg_to_number(args.get("page_size")):
            raw_response, links = client.list_organization_client(
                **request_args,
                per_page=page_size,
            )
        else:
            limit = arg_to_number(args["limit"]) or Client.CLIENT_MAX_PER_PAGE
            result, links = client.list_organization_client(
                **(request_args if request_args else {}),
                per_page=min(max(limit, Client.MIN_PAGE_SIZE), Client.CLIENT_MAX_PER_PAGE),
            )

            if "records" not in result:
                result["records"] = []

            # Loop until the desired limit has been reached or the API has been exhausted.
            while len(result["records"]) < limit and (next_url := dict_safe_get(links, ["next", "url"])):
                response, links = client.call_link(next_url)
                result["records"] += response.get("records", [])

            raw_response = result
            raw_response["records"] = raw_response["records"][:limit]
            links = None
    else:
        raise DemistoException("Must input one of: `next_token` or `organization_id` and `mac`.")

    readable_output = tableToMarkdown(
        name=f"Client {raw_response.get('clientId')} MAC {raw_response.get('mac')} Record(s)",
        t=create_client_table(raw_response),
        headers=CLIENT_TABLE_HEADERS,
        removeNull=True,
    )

    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_PREFIX}.{CLIENT_PREFIX}",
            outputs_key_field="clientId",
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response,
        )
    ]

    if links:
        command_results.append(get_relationship_link_command_result(CLIENT_PREFIX, links))

    return command_results


@logger
def list_network_client_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """List the clients that have used this network in the time span.

    The data is updated at most once every five minutes.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If one of the required combinations are present.

    Returns:
        list[CommandResults]: Outputs of the command that represent an entry in warroom.
    """
    links = None

    # Handle relationship link request.
    if next_token := args.get("next_token"):
        raw_response, links = client.call_link(next_token)
    # Handle LIST request.
    elif network_id := args.get("network_id"):
        # Handle GET request.
        if client_id := args.get("client_id"):
            raw_response = [client.get_network_client(network_id, client_id)]
        else:
            request_args = remove_empty_elements(
                {
                    "network_id": network_id,
                    "t0": arg_to_datetime(args.get("t0")),
                    "time_span": arg_to_number(args.get("time_span")),
                    "statuses": [StatusSubset(status.capitalize()) for status in argToList(args.get("statuses"))],
                    "ip": args.get("ip"),
                    "ip6": args.get("ip6"),
                    "ip6_local": args.get("ip6_local"),
                    "mac": args.get("mac"),
                    "os": args.get("os"),
                    "psk_group": args.get("psk_group"),
                    "description": args.get("description"),
                    "vlan": args.get("vlan"),
                    "named_vlan": args.get("named_vlan"),
                    "recent_device_connections": [
                        RecentDeviceConnection(recent_device_connection)
                        for recent_device_connection in args.get("recent_device_connections", [])
                    ],
                }
            )

            if page_size := arg_to_number(args.get("page_size")):
                raw_response, links = client.list_network_client(
                    **request_args,
                    per_page=page_size,
                )
            else:
                raw_response = automatic_pagination(
                    client=client,
                    limit=arg_to_number(args["limit"]) or DEFAULT_PAGE_SIZE,
                    max_per_page=Client.MONITOR_CLIENT_MAX_PER_PAGE,
                    list_request=client.list_network_client,
                    request_args=request_args,
                )
    else:
        raise DemistoException("Must input one of: `next_token`, `network_id` or `network_id` and `client_id`.")

    readable_output = tableToMarkdown(
        name="Network Monitor Client(s)",
        t=create_monitor_client_table(raw_response),
        headers=NETWORK_CLIENT_TABLE_HEADERS,
        removeNull=True,
    )

    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_PREFIX}.{NETWORK_CLIENT_PREFIX}",
            outputs_key_field="id",
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response,
        )
    ]

    if links:
        command_results.append(get_relationship_link_command_result(NETWORK_CLIENT_PREFIX, links))

    return command_results


@logger
def list_device_client_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the clients of a device, up to a maximum of a month ago.

    The usage of each client is returned in kilobytes.
    If the device is a switch, the switchport is returned; otherwise the switchport field is null.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    dt = arg_to_datetime(args.get("t0"))
    t0 = str(dt) if dt else None

    raw_response = client.list_device_client(
        serial=args["serial"],
        t0=t0,
        time_span=arg_to_number(args.get("time_span")),
    )

    readable_output = tableToMarkdown(
        name="Device Monitored Client(s)",
        t=create_device_monitor_client_table(raw_response),
        headers=DEVICE_CLIENT_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{DEVICE_CLIENT_PREFIX}",
        outputs_key_field="id",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_ssid_appliance_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the MX SSIDs in a network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    if number := args.get("number"):
        raw_response = [client.get_network_appliance_ssid(network_id, number)]
    else:
        raw_response = client.list_ssid_appliance(network_id)

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="MX SSID(s)",
        t=create_ssid_appliance_table(raw_response),
        headers=SSID_APPLIANCE_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{SSID_PREFIX}.{APPLIANCE_PREFIX}",
        outputs_key_field="number",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_ssid_wireless_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the MR SSIDs in a network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    if number := args.get("number"):
        raw_response = [client.get_network_wireless_ssid(network_id, number)]
    else:
        raw_response = client.list_ssid_wireless(network_id)

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="MR SSID(s)",
        t=create_ssid_wireless_table(raw_response),
        headers=SSID_WIRELESS_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{SSID_PREFIX}.{WIRELESS_PREFIX}",
        outputs_key_field="number",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_network_l3firewall_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the L3 firewall rules for an MX network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    raw_response = client.list_network_l3firewall_rule(network_id)
    readable_output = tableToMarkdown(
        name="L3 Firewall Rule(s)",
        t=create_l3firewall_rule_table(raw_response.get("rules", [])),
        headers=L3FIREWALL_RULE_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{L3FIREWALL_RULE_PREFIX}",
        outputs_key_field="networkId",
        outputs={"networkId": network_id} | raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def update_network_l3firewall_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update the L3 firewall rules of an MX network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException:
            - If a required argument is missing.
            - If neither `entry_id` nor `dest_cidr`, `src_cidr`, `protocol` and `policy` are provided.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    syslog_default_rule = arg_to_optional_bool(args.get("syslog_default_rule"))

    l3firewall_rules: list[L3FirewallRule] = []

    if entry_id := args.get("entry_id"):
        l3firewall_rules = create_firewall_rules(entry_id, L3FirewallRule)
    elif (
        (dest_cidr := args.get("dest_cidr"))
        and (protocol := args.get("protocol"))
        and (policy := args.get("policy"))
        and (src_cidr := args.get("src_cidr"))
    ):
        l3firewall_rules.append(
            L3FirewallRule(
                comment=args.get("comment"),
                destCidr=dest_cidr,
                destPort=args.get("dest_port"),
                protocol=Protocol(protocol),
                policy=Policy(policy),
                srcCidr=src_cidr,
                srcPort=args.get("src_port"),
                syslogEnabled=arg_to_optional_bool(args.get("syslog_enabled")),
            )
        )
    else:
        raise DemistoException("Must input either an `entry_id` or a `dest_cidr`, `src_cidr`, `protocol` and `policy`")

    if not argToBoolean(args.get("override", True)):
        raw_response = client.list_network_l3firewall_rule(network_id)
        l3firewall_rules = [L3FirewallRule.from_dict(rule) for rule in raw_response.get("rules", [])] + l3firewall_rules

    raw_response = client.update_network_l3firewall_rule(
        network_id=network_id,
        syslog_default_rule=syslog_default_rule,
        l3firewall_rules=l3firewall_rules,
    )
    readable_output = tableToMarkdown(
        name=f"The L3 firewall rules for the network '{network_id}' were successfully updated.",
        t=create_l3firewall_rule_table(raw_response.get("rules", [])),
        headers=L3FIREWALL_RULE_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{L3FIREWALL_RULE_PREFIX}",
        outputs_key_field="networkId",
        outputs={"networkId": network_id} | raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def delete_network_l3firewall_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete the L3 firewall rules from an MX network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    client.update_network_l3firewall_rule(network_id)

    return CommandResults(
        readable_output=f"## The L3 firewall rules of the network '{network_id}' were successfully deleted.",
    )


@logger
def list_network_l7firewall_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the MX L7 firewall rules for an MX network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    raw_response = client.list_network_l7firewall_rule(network_id)
    readable_output = tableToMarkdown(
        name="L7 Firewall Rule(s)",
        t=create_l7firewall_rule_table(raw_response.get("rules", [])),
        headers=L7FIREWALL_RULE_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{L7FIREWALL_RULE_PREFIX}",
        outputs_key_field="networkId",
        outputs={"networkId": network_id} | raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def update_network_l7firewall_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update the MX L7 firewall rules for an MX network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException:
            - If neither an entry ID nor a value, type and policy are provided.
            - If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    l7firewall_rules: list[L7FirewallRule] = []

    if entry_id := args.get("entry_id"):
        l7firewall_rules = create_firewall_rules(entry_id, L7FirewallRule)
    elif (value := args.get("value")) and (type_ := args.get("type")) and (policy := args.get("policy")):
        l7firewall_rules.append(
            L7FirewallRule(
                value=value,
                type=L7FirewallRuleType(type_),
                policy=PolicySubset(policy),
            )
        )
    else:
        raise DemistoException("Must input either an `entry_id` or a `value`, `type` and `policy`.")

    if not argToBoolean(args.get("override", True)):
        raw_response = client.list_network_l7firewall_rule(network_id)
        l7firewall_rules = [L7FirewallRule.from_dict(rule) for rule in raw_response.get("rules", [])] + l7firewall_rules

    raw_response = client.update_network_l7firewall_rule(
        network_id=network_id,
        l7firewall_rules=l7firewall_rules,
    )
    readable_output = tableToMarkdown(
        name=f"The L7 firewall rules for the network '{network_id}' were successfully updated.",
        t=create_l7firewall_rule_table(raw_response.get("rules", [])),
        headers=L7FIREWALL_RULE_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{L7FIREWALL_RULE_PREFIX}",
        outputs_key_field="networkId",
        outputs={"networkId": network_id} | raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def delete_network_l7firewall_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete the L7 firewall rules from an MX network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    client.update_network_l7firewall_rule(network_id)

    return CommandResults(
        readable_output=f"## The L7 firewall rules of the network '{network_id}' were successfully deleted.",
    )


@logger
def list_organization_adaptive_policy_acl_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List adaptive policy ACLs in a organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    organization_id = get_valid_arg(args, "organization_id")

    if acl_id := args.get("acl_id"):
        raw_response = [client.get_organization_adaptive_policy_acl(organization_id, acl_id)]
    else:
        raw_response = client.list_organization_adaptive_policy_acl(organization_id)

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="Adaptive Policy ACL(s)",
        t=create_adaptive_policy_acl_table(raw_response),
        headers=ADAPTIVE_POLICY_ACL_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{ADAPTIVE_POLICY_ACL_PREFIX}",
        outputs_key_field="aclId",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_organization_adaptive_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List adaptive policies in an organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    organization_id = get_valid_arg(args, "organization_id")

    if adaptive_policy_id := args.get("adaptive_policy_id"):
        raw_response = [client.get_organization_adaptivepolicy(organization_id, adaptive_policy_id)]
    else:
        raw_response = client.list_organization_adaptive_policy(organization_id)

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="Adaptive Policy(ies)",
        t=create_adaptive_policy_table(raw_response),
        headers=ADAPTIVE_POLICY_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{ADAPTIVE_POLICY_PREFIX}",
        outputs_key_field="adaptivePolicyId",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_organization_adaptive_policy_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List adaptive policy groups in a organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    organization_id = get_valid_arg(args, "organization_id")

    if adaptive_policy_group_id := args.get("adaptive_policy_group_id"):
        raw_response = [client.get_organization_adaptive_policy_group(organization_id, adaptive_policy_group_id)]
    else:
        raw_response = client.list_organization_adaptive_policy_group(organization_id)

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="Adaptive Policy Group(s)",
        t=create_adaptive_policy_group_table(raw_response),
        headers=ADAPTIVE_POLICY_GROUP_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{ADAPTIVE_POLICY_GROUP_PREFIX}",
        outputs_key_field="groupId",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_organization_adaptive_policy_settings_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Returns global adaptive policy settings in an organization.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    organization_id = get_valid_arg(args, "organization_id")

    raw_response = client.list_organization_adaptive_policy_settings(organization_id)

    outputs = {"organizationId": organization_id} | raw_response
    readable_output = tableToMarkdown(
        name="Adaptive Policy Settings",
        t={"Enabled Networks": raw_response.get("enabledNetworks") or None},
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{ADAPTIVE_POLICY_SETTINGS_PREFIX}",
        outputs_key_field="organizationId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_organization_branding_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the branding policies of an organization.

    This allows MSPs to view and monitor certain aspects of Dashboard for their users and customers.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    organization_id = get_valid_arg(args, "organization_id")

    if branding_policy_id := args.get("branding_policy_id"):
        raw_response = [client.get_organization_branding_policy(organization_id, branding_policy_id)]
    else:
        raw_response = client.list_organization_branding_policy(organization_id)

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="Branding Policy(ies)",
        t=create_branding_policy_table(raw_response),
        headers=BRANDING_POLICY_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{BRANDING_POLICY_PREFIX}",
        outputs_key_field="name",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_network_group_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the group policies in a network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    if group_policy_id := args.get("group_policy_id"):
        raw_response = [client.get_network_grouppolicy(network_id, group_policy_id)]
    else:
        raw_response = client.list_network_grouppolicy(network_id)

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="Group Policy(ies)",
        t=create_group_policy_table(raw_response),
        headers=GROUP_POLICY_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{GROUP_POLICY_PREFIX}",
        outputs_key_field="name",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_network_client_policy_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """List policies for all clients with policies.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        list[CommandResults]: Outputs of the command that represent an entry in warroom.
    """
    links = None

    # Handle relationship link request.
    if next_token := args.get("next_token"):
        raw_response, links = client.call_link(next_token)
    # Handle LIST request.
    elif network_id := args.get("network_id"):
        request_args = remove_empty_elements(
            {
                "network_id": network_id,
                "t0": arg_to_datetime(args.get("t0")),
                "time_span": args.get("time_span"),
            }
        )

        if page_size := arg_to_number(args.get("page_size")):
            raw_response, links = client.list_network_client_policy(
                **request_args,
                per_page=page_size,
            )
        else:
            raw_response = automatic_pagination(
                client=client,
                limit=arg_to_number(args["limit"]) or DEFAULT_PAGE_SIZE,
                max_per_page=Client.CLIENT_POLICY_MAX_PER_PAGE,
                list_request=client.list_network_client_policy,
                request_args=request_args,
            )
    else:
        raise DemistoException("Must input one of: `next_token` or `network_id`.")

    readable_output = tableToMarkdown(
        name="Client's Policies",
        t=create_client_policy_table(raw_response),
        headers=CLIENT_POLICY_TABLE_HEADERS,
        removeNull=True,
    )

    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_PREFIX}.{CLIENT_POLICY_PREFIX}",
            outputs_key_field="clientId",
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response,
        )
    ]

    if links:
        command_results.append(get_relationship_link_command_result(CLIENT_POLICY_PREFIX, links))

    return command_results


@logger
def list_network_vlan_profile_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List VLAN profiles for a network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    if iname := args.get("iname"):
        raw_response = [client.get_network_vlan_profile(network_id, iname)]
    else:
        raw_response = client.list_network_vlan_profile(network_id)

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="VLAN Profile(s)",
        t=create_vlan_profile_table(raw_response),
        headers=VLAN_PROFILE_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{VLAN_PROFILE_PREFIX}",
        outputs_key_field="iname",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_network_appliance_vlan_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the VLANs for an MX network.

    Args:
        client (Client): Session to the API to run HTTP requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If a required argument is missing.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    network_id = get_valid_arg(args, "network_id")

    if vlan_id := args.get("vlan_id"):
        raw_response = [client.get_network_appliance_vlan(network_id, vlan_id)]
    else:
        raw_response = client.list_network_appliance_vlan(network_id)

    if not arg_to_optional_bool(args.get("all_result")):
        raw_response = raw_response[: arg_to_number(args.get("limit"))]

    readable_output = tableToMarkdown(
        name="MX VLAN(s)",
        t=create_appliance_vlan_table(raw_response),
        headers=APPLIANCE_VLAN_TABLE_HEADERS,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{APPLIANCE_VLAN_PREFIX}",
        outputs_key_field="id",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


""" Entry Point """


def main() -> None:
    """Initialize Client and run a given command.

    Raises:
        NotImplementedError: If the given command isn't implemented.
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url: str = params["base_url"]
    api_key: str = dict_safe_get(params, keys=["api_key", "password"], return_type=str)
    verify_certificate: bool = not argToBoolean(params.get("insecure", False))
    proxy: bool = argToBoolean(params.get("proxy", False))

    if not args.get("organization_id"):
        args["organization_id"] = params.get("organization_id")

    if not args.get("network_id"):
        args["network_id"] = params.get("network_id")

    demisto.debug(f"Command being called is {command}")

    commands = {
        f"{INTEGRATION_NAME}-organization-list": list_organization_command,
        f"{INTEGRATION_NAME}-network-list": list_network_command,
        f"{INTEGRATION_NAME}-organization-license-state-list": list_organization_license_state_command,
        f"{INTEGRATION_NAME}-organization-inventory-list": list_organization_inventory_command,
        f"{INTEGRATION_NAME}-device-claim": claim_device_command,
        f"{INTEGRATION_NAME}-organization-device-search": search_organization_device_command,
        f"{INTEGRATION_NAME}-device-list": list_device_command,
        f"{INTEGRATION_NAME}-device-update": update_device_command,
        f"{INTEGRATION_NAME}-device-remove": remove_device_command,
        f"{INTEGRATION_NAME}-device-status-list": list_device_status_command,
        f"{INTEGRATION_NAME}-organization-uplink-status-list": list_organization_uplink_status_command,
        f"{INTEGRATION_NAME}-organization-client-list": list_organization_client_command,
        f"{INTEGRATION_NAME}-network-client-list": list_network_client_command,
        f"{INTEGRATION_NAME}-device-client-list": list_device_client_command,
        f"{INTEGRATION_NAME}-ssid-appliance-list": list_ssid_appliance_command,
        f"{INTEGRATION_NAME}-ssid-wireless-list": list_ssid_wireless_command,
        f"{INTEGRATION_NAME}-network-l3firewall-rule-list": list_network_l3firewall_rule_command,
        f"{INTEGRATION_NAME}-network-l3firewall-rule-update": update_network_l3firewall_rule_command,
        f"{INTEGRATION_NAME}-network-l3firewall-rule-delete": delete_network_l3firewall_rule_command,
        f"{INTEGRATION_NAME}-network-l7firewall-rule-list": list_network_l7firewall_rule_command,
        f"{INTEGRATION_NAME}-network-l7firewall-rule-update": update_network_l7firewall_rule_command,
        f"{INTEGRATION_NAME}-network-l7firewall-rule-delete": delete_network_l7firewall_rule_command,
        f"{INTEGRATION_NAME}-organization-adaptive-policy-acl-list": list_organization_adaptive_policy_acl_command,
        f"{INTEGRATION_NAME}-organization-adaptive-policy-list": list_organization_adaptive_policy_command,
        f"{INTEGRATION_NAME}-organization-adaptive-policy-group-list": list_organization_adaptive_policy_group_command,
        f"{INTEGRATION_NAME}-organization-adaptive-policy-settings-list": (
            list_organization_adaptive_policy_settings_command
        ),
        f"{INTEGRATION_NAME}-organization-branding-policy-list": list_organization_branding_policy_command,
        f"{INTEGRATION_NAME}-network-group-policy-list": list_network_group_policy_command,
        f"{INTEGRATION_NAME}-network-client-policy-list": list_network_client_policy_command,
        f"{INTEGRATION_NAME}-network-vlan-profile-list": list_network_vlan_profile_command,
        f"{INTEGRATION_NAME}-network-appliance-vlan-list": list_network_appliance_vlan_command,
    }

    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            results = test_module(client)
        elif command in commands:
            results = commands[command](client, args)
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

        return_results(results)

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
