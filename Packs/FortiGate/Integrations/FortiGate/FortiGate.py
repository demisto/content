import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" Imports """
import copy
import functools
import http
import ipaddress
import json
import re
from typing import Any, Callable, NamedTuple, TypeVar

import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" Global Variables """


CAMEL_CASE_PATTERN = re.compile(r"(?<=[a-z])([A-Z])")
UPPER_FOLLOWED_BY_MIXED_PATTERN = re.compile(r"([A-Z])(?=[A-Z][a-z])")


# Commands key words
FORTIGATE = "fortigate"
FIREWALL = "firewall"
ADDRESS = "address"
ADDRESSES = "addresses"
IPV4 = "ipv4"
IPV6 = "ipv6"
MULTICAST = "multicast"
GROUP = "group"
SERVICE = "service"
POLICY = "policy"

# Context outputs
FORTIGATE_CONTEXT = "Fortigate"
ADDRESS_CONTEXT = f"{FORTIGATE_CONTEXT}.Address"
ADDRESS6_CONTEXT = f"{FORTIGATE_CONTEXT}.Address6"
ADDRESS_MULTICAST_CONTEXT = f"{FORTIGATE_CONTEXT}.AddressMulticast"
ADDRESS6_MULTICAST_CONTEXT = f"{FORTIGATE_CONTEXT}.Address6Multicast"
ADDRESS_GROUP_CONTEXT = f"{FORTIGATE_CONTEXT}.AddressGroup"
ADDRESS6_GROUP_CONTEXT = f"{FORTIGATE_CONTEXT}.Address6Group"
SERVICE_CONTEXT = f"{FORTIGATE_CONTEXT}.Service"
SERVICE_GROUP_CONTEXT = f"{FORTIGATE_CONTEXT}.ServiceGroup"
POLICY_CONTEXT = f"{FORTIGATE_CONTEXT}.Policy"
VDOM_CONTEXT = f"{FORTIGATE_CONTEXT}.VDOM"
BANNED_IP_CONTEXT = f"{FORTIGATE_CONTEXT}.BannedIP"

AUTHORIZATION_ERROR = "Authorization Error: invalid username or password"

ADDRESS_GUI_TO_API_TYPE = {
    "Subnet": "ipmask",
    "IP Range": "iprange",
    "FQDN": "fqdn",
    "Geography": "geography",
    "Device (Mac Address)": "mac",
}
ADDRESS6_GUI_TO_API_TYPE = copy.copy(ADDRESS_GUI_TO_API_TYPE)
ADDRESS6_GUI_TO_API_TYPE |= {
    "Subnet": "ipprefix",
    "Fabric Connector Address": "dynamic",
}

ADDRESS_MULTICAST_GUI_TO_API_TYPE = {
    "Broadcast Subnet": "broadcastmask",
    "Multicast IP Range": "multicastrange",
}

VDOM_DEFAULT = "root"
MIN_MASK = 0
MAX_MASK = 128


class Mapping(NamedTuple):
    old_keys: list[str]
    new_keys: list[str]
    default_value: Any | None = None
    value_changer: Callable | None = None


""" Client """


class Client(BaseClient):
    """Client class to interact with the FortiGate API."""

    IS_ONLINE = False

    FIREWALL_SUFFIX = "cmdb/firewall"
    ADDRESS_IPV4_ENDPOINT = urljoin(FIREWALL_SUFFIX, "address")
    ADDRESS_IPV6_ENDPOINT = urljoin(FIREWALL_SUFFIX, "address6")
    ADDRESS_IPV4_MULTICAST_ENDPOINT = urljoin(FIREWALL_SUFFIX, "multicast-address")
    ADDRESS_IPV6_MULTICAST_ENDPOINT = urljoin(FIREWALL_SUFFIX, "multicast-address6")
    ADDRESS_IPV4_GROUP_ENDPOINT = urljoin(FIREWALL_SUFFIX, "addrgrp")
    ADDRESS_IPV6_GROUP_ENDPOINT = urljoin(FIREWALL_SUFFIX, "addrgrp6")
    SERVICE_ENDPOINT = f"{FIREWALL_SUFFIX}.service/custom"
    SERVICE_GROUP_ENDPOINT = f"{FIREWALL_SUFFIX}.service/group"
    POLICY_ENDPOINT = urljoin(FIREWALL_SUFFIX, "policy")
    BANNED_IP_ENDPOINT = "monitor/user/banned"

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = True,
        proxy: bool = False,
    ) -> None:
        """Initialize the Client class.

        Args:
            base_url (str): The base URL of the API.
            username (str): The account username.
            password (str): The account password.
            verify (bool, optional): Whether to verify the SSL certificate.
                Defaults to True.
            proxy (bool, optional): Whether to use a proxy.
                Defaults to False.
        """
        self.server = base_url
        self.username = username
        self.password = password

        super().__init__(
            base_url=urljoin(base_url, "api/v2"),
            verify=verify,
            proxy=proxy,
        )

    @staticmethod
    def _error_handler(response: requests.Response):
        """Handle API errors with a generic message.

        Args:
            response (requests.Response): The API response.

        Raises:
            DemistoException: If the API call failed.
        """
        message = f"Error in API call [{response.status_code}] - {response.reason}"

        try:
            entry = response.json()
            message += (
                f"\nVDOM: {entry.get('vdom')}"
                f"\nIdentifier: {entry.get('mkey')}"
                f"\nMessage: {entry.get('cli_error')}"
                f"\nError Code: {entry.get('error')}"
                f"\nRaw: {json.dumps(entry)}"
            )

            raise DemistoException(message, res=response)
        except ValueError:
            message += "\n{}".format(response.text)
            raise DemistoException(message, res=response)

    def login(self) -> None:
        """Login to FortiGate API.

        This method is not intended for Rest API admins, but regular admins.

        Raises:
            DemistoException: Incase the credentials are wrong or too many attempts were made.
        """
        response: requests.Response = self._http_request(
            method="POST",
            full_url=urljoin(self.server, "logincheck"),
            data={
                "username": self.username,
                "secretkey": self.password,
                "ajax": "1",
            },
            resp_type="response",
            error_handler=Client._error_handler,
        )

        if response.text == "0":
            raise DemistoException(AUTHORIZATION_ERROR)

        if response.text == "2":
            raise DemistoException("Too many login attempts. Please wait and try again.")

        login_disclaimer = "logindisclaimer"

        if login_disclaimer in response.text:
            self._http_request(
                method="POST",
                full_url=urljoin(self.server, login_disclaimer),
                data={"confirm": "1"},
                error_handler=Client._error_handler,
            )

        Client.IS_ONLINE = True

    def logout(self) -> None:
        """Due to limited amount of simultaneous connections we log out."""
        if Client.IS_ONLINE:
            self._http_request(
                method="POST",
                full_url=urljoin(self.server, "logout"),
                resp_type="response",
                error_handler=Client._error_handler,
            )

    def _get_filter(self, field: str | None, value: str | None) -> str | None:
        """Formats the filter to be used in the API call.

        Args:
            field (str | None): "name"
            value (str | None): "@value"

        Returns:
            str | None: name=@value
        """
        if not any([field, value]):
            return None

        return f"{to_kebab_case(field)}=@{value}"

    def _get_format(self, fields: list[str]) -> str | None:
        """Formats the fields to be used in the API call.

        Args:
            fields (list[str]): ["name", "type"]

        Returns:
            str | None: name|type
        """
        if not fields:
            return None

        return "|".join(map(to_kebab_case, fields))

    def list_firewall_address_ipv4s(
        self,
        name: str | None = None,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all IPv4 addresses.

        Args:
            name (str, optional): A name of a specific object to return.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.ADDRESS_IPV4_ENDPOINT, name) if name else self.ADDRESS_IPV4_ENDPOINT,
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def create_firewall_address_ipv4(
        self,
        name: str,
        type_: str,
        vdom: str = VDOM_DEFAULT,
        comment: str | None = None,
        associated_interface: str | None = None,
        address: str | None = None,
        mask: str | None = None,
        allow_routing: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        fqdn: str | None = None,
        country: str | None = None,
        mac_addresses: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a IPv4 address.

        Args:
            name (str): The name of the address to create.
            type_ (str): The type of the IPv4 address to create.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            comment (str | None, optional): A comment for the address.
                Defaults to None.
            associated_interface (str | None, optional): Network interface associated with address.
                Defaults to None.
            address (str | None, optional): The IP address.
                Defaults to None.
            mask (str | None, optional): The subnet mask of the address.
                Defaults to None.
            allow_routing (str | None, optional): Enable/disable use of this address in the static route configuration.
                Defaults to None.
            start_ip (str | None, optional): First IP address (inclusive) in the range for the address.
                Defaults to None.
            end_ip (str | None, optional): Final IP address (inclusive) in the range for the address.
                Defaults to None.
            fqdn (str | None, optional): Fully Qualified Domain Name address.
                Defaults to None.
            country (str | None, optional): IP addresses associated to a specific country.
                Input must be according to the two-letter counter codes, for example: `IL`.
                Defaults to None.
            mac_addresses (list[str] | None, optional): list of MAC addresses.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=self.ADDRESS_IPV4_ENDPOINT,
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "type": type_,
                    "associated-interface": {
                        "q_origin_key": associated_interface,
                    },
                    "subnet": f"{address} {mask}" if address and mask else None,
                    "allow-routing": allow_routing,
                    "start-ip": start_ip,
                    "end-ip": end_ip,
                    "fqdn": fqdn,
                    "country": country,
                    "macaddr": [{"macaddr": mac_address} for mac_address in mac_addresses],
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_address_ipv4(
        self,
        name: str,
        type_: str | None = None,
        vdom: str = VDOM_DEFAULT,
        comment: str | None = None,
        associated_interface: str | None = None,
        address: str | None = None,
        mask: str | None = None,
        allow_routing: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        fqdn: str | None = None,
        country: str | None = None,
        mac_addresses: list[str] | None = None,
    ) -> dict[str, Any]:
        """Update a IPv4 address.

        Args:
            name (str): The name of the address to update.
            type_ (str | None, optional): The type of the IPv4 address to update.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            comment (str | None, optional): A comment for the address.
                Defaults to None.
            associated_interface (str | None, optional): Network interface associated with address.
                Defaults to None.
            address (str | None, optional): The IP address.
                Defaults to None.
            mask (str | None, optional): The subnet mask of the address.
                Defaults to None.
            allow_routing (str | None, optional): Enable/disable use of this address in the static route configuration.
                Defaults to None.
            start_ip (str | None, optional): First IP address (inclusive) in the range for the address.
                Defaults to None.
            end_ip (str | None, optional): Final IP address (inclusive) in the range for the address.
                Defaults to None.
            fqdn (str | None, optional): Fully Qualified Domain Name address.
                Defaults to None.
            country (str | None, optional): IP addresses associated to a specific country.
                Input must be according to the two-letter counter codes, for example: `IL`.
                Defaults to None.
            mac_addresses (list[str] | None, optional): list of MAC addresses.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.ADDRESS_IPV4_ENDPOINT, name),
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "type": type_,
                    "associated-interface": {
                        "q_origin_key": associated_interface,
                    },
                    "subnet": f"{address} {mask}" if address and mask else None,
                    "allow-routing": allow_routing,
                    "start-ip": start_ip,
                    "end-ip": end_ip,
                    "fqdn": fqdn,
                    "country": country,
                    "macaddr": [{"macaddr": mac_address} for mac_address in mac_addresses],
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_address_ipv4(self, name: str, vdom: str = VDOM_DEFAULT) -> dict[str, Any]:
        """Delete a IPv4 address.

        Args:
            name (str): The name of the address to delete.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=urljoin(self.ADDRESS_IPV4_ENDPOINT, name),
            params={"vdom": vdom},
            error_handler=Client._error_handler,
        )

    def list_firewall_address_ipv6s(
        self,
        name: str | None = None,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all IPv6 addresses.

        Args:
            name (str, optional): A name of a specific object to return.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.ADDRESS_IPV6_ENDPOINT, name) if name else self.ADDRESS_IPV6_ENDPOINT,
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def create_firewall_address_ipv6(
        self,
        name: str,
        type_: str,
        vdom: str = VDOM_DEFAULT,
        comment: str | None = None,
        subnet: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        fqdn: str | None = None,
        country: str | None = None,
        mac_addresses: list[str] | None = None,
        sdn_connector: str | None = None,
    ) -> dict[str, Any]:
        """Create a IPv6 address.

        Args:
            name (str): The name of the address to create.
            type_ (str): The type of the IPv6 address to create.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            comment (str | None, optional): A comment for the address.
                Defaults to None.
            subnet (str | None, optional): IPv6 address prefix (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx).
                Defaults to None.
            start_ip (str | None, optional): First IP address (inclusive) in the range for the address.
                Defaults to None.
            end_ip (str | None, optional): Final IP address (inclusive) in the range for the address.
                Defaults to None.
            fqdn (str | None, optional): Fully Qualified Domain Name address.
                Defaults to None.
            country (str | None, optional): IP addresses associated to a specific country.
                Input must be according to the two-letter counter codes, for example: `IL`.
                Defaults to None.
            mac_addresses (list[str] | None, optional): list of MAC addresses.
                Defaults to None.
            sdn_connector (str | None, optional): Software-defined networking connector
                enables to interact with SDN controllers.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=self.ADDRESS_IPV6_ENDPOINT,
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "type": type_,
                    "ip6": subnet,
                    "start-ip": start_ip,
                    "end-ip": end_ip,
                    "fqdn": fqdn,
                    "country": country,
                    "macaddr": [{"macaddr": mac_address} for mac_address in mac_addresses],
                    "sdn": sdn_connector,
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_address_ipv6(
        self,
        name: str,
        type_: str | None = None,
        vdom: str = VDOM_DEFAULT,
        comment: str | None = None,
        subnet: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        fqdn: str | None = None,
        country: str | None = None,
        mac_addresses: list[str] | None = None,
        sdn_connector: str | None = None,
    ) -> dict[str, Any]:
        """Update a IPv6 address.

        Args:
            name (str): The name of the address to update.
            type_ (str | None, optional): The type of the IPv6 address to update.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            comment (str | None, optional): A comment for the address.
                Defaults to None.
            subnet (str | None, optional): IPv6 address prefix (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx).
                Defaults to None.
            start_ip (str | None, optional): First IP address (inclusive) in the range for the address.
                Defaults to None.
            end_ip (str | None, optional): Final IP address (inclusive) in the range for the address.
                Defaults to None.
            fqdn (str | None, optional): Fully Qualified Domain Name address.
                Defaults to None.
            country (str | None, optional): IP addresses associated to a specific country.
                Input must be according to the two-letter counter codes, for example: `IL`.
                Defaults to None.
            mac_addresses (list[str] | None, optional): list of MAC addresses.
                Defaults to None.
            sdn_connector (str | None, optional): Software-defined networking connector
                enables to interact with SDN controllers.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.ADDRESS_IPV6_ENDPOINT, name),
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "type": type_,
                    "ip6": subnet,
                    "start-ip": start_ip,
                    "end-ip": end_ip,
                    "fqdn": fqdn,
                    "country": country,
                    "macaddr": [{"macaddr": mac_address} for mac_address in mac_addresses],
                    "sdn": sdn_connector,
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_address_ipv6(self, name: str, vdom: str = VDOM_DEFAULT) -> dict[str, Any]:
        """Delete a IPv6 address.

        Args:
            name (str): The name of the address to delete.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=urljoin(self.ADDRESS_IPV6_ENDPOINT, name),
            params={"vdom": vdom},
            error_handler=Client._error_handler,
        )

    def list_firewall_address_ipv4_multicasts(
        self,
        name: str | None = None,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all IPv4 multicast addresses.

        Args:
            name (str, optional): A name of a specific object to return.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.ADDRESS_IPV4_MULTICAST_ENDPOINT, name)
            if name
            else self.ADDRESS_IPV4_MULTICAST_ENDPOINT,
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def create_firewall_address_ipv4_multicast(
        self,
        name: str,
        type_: str,
        vdom: str = VDOM_DEFAULT,
        comment: str | None = None,
        associated_interface: str | None = None,
        subnet: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
    ) -> dict[str, Any]:
        """Create a IPv4 multicast address.

        Args:
            name (str): The name of the address to create.
            type_ (str): The type of the IPv4 multicast address to create, can be `multicastrange` or `broadcastmask`.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            comment (str | None, optional): A comment for the address.
                Defaults to None.
            associated_interface (str | None, optional): Network interface associated with address.
                Defaults to None.
            subnet (str | None, optional): Broadcast address and subnet.
                Defaults to None.
            start_ip (str | None, optional): First IP address (inclusive) in the range for the address.
                Defaults to None.
            end_ip (str | None, optional): Final IP address (inclusive) in the range for the address.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=self.ADDRESS_IPV4_MULTICAST_ENDPOINT,
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "associated-interface": {
                        "q_origin_key": associated_interface,
                    },
                    "type": type_,
                    "subnet": subnet,
                    "start-ip": start_ip,
                    "end-ip": end_ip,
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_address_ipv4_multicast(
        self,
        name: str,
        vdom: str = VDOM_DEFAULT,
        comment: str | None = None,
        associated_interface: str | None = None,
        type_: str | None = None,
        subnet: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
    ) -> dict[str, Any]:
        """Update a IPv4 multicast address.

        Args:
            name (str): The name of the address to update.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            comment (str | None, optional): A comment for the address.
                Defaults to None.
            associated_interface (str | None, optional): Network interface associated with address.
                Defaults to None.
            type_ (str | None, optional): The type of the IPv4 multicast address to create,
                can be `multicastrange` or `broadcastmask`.
                Defaults to None.
            subnet (str | None, optional): Broadcast address and subnet.
                Defaults to None.
            start_ip (str | None, optional): First IP address (inclusive) in the range for the address.
                Defaults to None.
            end_ip (str | None, optional): Final IP address (inclusive) in the range for the address.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.ADDRESS_IPV4_MULTICAST_ENDPOINT, name),
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "associated-interface": {
                        "q_origin_key": associated_interface,
                    },
                    "type": type_,
                    "subnet": subnet,
                    "start-ip": start_ip,
                    "end-ip": end_ip,
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_address_ipv4_multicast(self, name: str, vdom: str = VDOM_DEFAULT) -> dict[str, Any]:
        """Delete a IPv6 multicast address.

        Args:
            name (str): The name of the address to delete.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=urljoin(self.ADDRESS_IPV4_MULTICAST_ENDPOINT, name),
            params={"vdom": vdom},
            error_handler=Client._error_handler,
        )

    def list_firewall_address_ipv6_multicasts(
        self,
        name: str | None = None,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all IPv6 multicast addresses.

        Args:
            name (str, optional): A name of a specific object to return.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.ADDRESS_IPV6_MULTICAST_ENDPOINT, name)
            if name
            else self.ADDRESS_IPV6_MULTICAST_ENDPOINT,
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def create_firewall_address_ipv6_multicast(
        self,
        name: str,
        subnet: str,
        vdom: str = VDOM_DEFAULT,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Create a IPv6 multicast address.

        Args:
            name (str): The name of the address to create.
            subnet (str | None, optional): IPv6 address prefix (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx).
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            comment (str | None, optional): A comment for the address.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=self.ADDRESS_IPV6_MULTICAST_ENDPOINT,
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "ip6": subnet,
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_address_ipv6_multicast(
        self,
        name: str,
        vdom: str = VDOM_DEFAULT,
        comment: str | None = None,
        subnet: str | None = None,
    ) -> dict[str, Any]:
        """Update a IPv6 multicast address.

        Args:
            name (str): The name of the address to create.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            comment (str | None, optional): A comment for the address.
                Defaults to None.
            subnet (str | None, optional): IPv6 address prefix (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx).
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.ADDRESS_IPV6_MULTICAST_ENDPOINT, name),
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "ip6": subnet,
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_address_ipv6_multicast(self, name: str, vdom: str = VDOM_DEFAULT) -> dict[str, Any]:
        """Delete a IPv6 multicast address.

        Args:
            name (str): The name of the address to delete.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=urljoin(self.ADDRESS_IPV6_MULTICAST_ENDPOINT, name),
            params={"vdom": vdom},
            error_handler=Client._error_handler,
        )

    def list_firewall_address_ipv4_groups(
        self,
        name: str | None = None,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all IPv4 address groups.

        Args:
            name (str, optional): A name of a specific object to return.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.ADDRESS_IPV4_GROUP_ENDPOINT, name) if name else self.ADDRESS_IPV4_GROUP_ENDPOINT,
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def create_firewall_address_ipv4_group(self) -> dict[str, Any]:
        pass

    def update_firewall_address_ipv4_group(self) -> dict[str, Any]:
        pass

    def delete_firewall_address_ipv4_group(self, name: str, vdom: str = VDOM_DEFAULT) -> dict[str, Any]:
        """Delete a IPv4 address group.

        Args:
            name (str): The name of the address group to delete.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=urljoin(self.ADDRESS_IPV4_GROUP_ENDPOINT, name),
            params={"vdom": vdom},
            error_handler=Client._error_handler,
        )

    def list_firewall_address_ipv6_groups(
        self,
        name: str | None = None,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all IPv6 address groups.

        Args:
            name (str, optional): A name of a specific object to return.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.ADDRESS_IPV6_GROUP_ENDPOINT, name) if name else self.ADDRESS_IPV6_GROUP_ENDPOINT,
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def create_firewall_address_ipv6_group(self) -> dict[str, Any]:
        pass

    def update_firewall_address_ipv6_group(self) -> dict[str, Any]:
        pass

    def delete_firewall_address_ipv6_group(self, name: str, vdom: str = VDOM_DEFAULT) -> dict[str, Any]:
        """Delete a IPv6 address group.

        Args:
            name (str): The name of the address group to delete.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=urljoin(self.ADDRESS_IPV6_GROUP_ENDPOINT, name),
            params={"vdom": vdom},
            error_handler=Client._error_handler,
        )

    def list_firewall_services(
        self,
        name: str | None = None,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all services.

        Args:
            name (str, optional): A name of a specific object to return.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.SERVICE_ENDPOINT, name) if name else self.SERVICE_ENDPOINT,
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def create_firewall_service(self) -> dict[str, Any]:
        pass

    def update_firewall_service(self) -> dict[str, Any]:
        pass

    def delete_firewall_service(self, name: str, vdom: str = VDOM_DEFAULT) -> dict[str, Any]:
        """Delete a service.

        Args:
            name (str): The name of the service to delete.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=urljoin(self.SERVICE_ENDPOINT, name),
            params={"vdom": vdom},
            error_handler=Client._error_handler,
        )

    def list_firewall_service_groups(
        self,
        name: str | None = None,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all service groups.

        Args:
            name (str, optional): A name of a specific object to return.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.SERVICE_GROUP_ENDPOINT, name) if name else self.SERVICE_GROUP_ENDPOINT,
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def create_firewall_service_group(self) -> dict[str, Any]:
        pass

    def update_firewall_service_group(self) -> dict[str, Any]:
        pass

    def delete_firewall_service_group(self, name: str, vdom: str = VDOM_DEFAULT) -> dict[str, Any]:
        """Delete a service group.

        Args:
            name (str): The name of the service group to delete.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=urljoin(self.SERVICE_GROUP_ENDPOINT, name),
            params={"vdom": vdom},
            error_handler=Client._error_handler,
        )

    def list_firewall_policies(
        self,
        id_: str | None = None,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all policies.

        Args:
            id_ (str, optional): A ID of a specific object to return.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.POLICY_ENDPOINT, id_) if id_ else self.POLICY_ENDPOINT,
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def create_firewall_policy(self) -> dict[str, Any]:
        pass

    def update_firewall_policy(self) -> dict[str, Any]:
        pass

    def move_firewall_policy(self) -> dict[str, Any]:
        pass

    def delete_firewall_policy(self, id_: str, vdom: str = VDOM_DEFAULT) -> dict[str, Any]:
        """Delete a policy.

        Args:
            id_ (str): The ID of the policy to delete.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=urljoin(self.POLICY_ENDPOINT, id_),
            params={"vdom": vdom},
            error_handler=Client._error_handler,
        )

    def list_system_vdoms(
        self,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all virtual domains.

        Args:
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix="cmdb/system/vdom",
            params=remove_empty_elements(
                {
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def list_banned_ips(
        self,
        vdom: str = VDOM_DEFAULT,
        filter_field: str | None = None,
        filter_value: str | None = None,
        format_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """List all banned IPv4 and IPv6 addresses.

        Args:
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.
            filter_field (str | None, optional): The field to filter by.
                Defaults to None.
            filter_value (str | None, optional): The value to filter by.
                Defaults to None.
            format_fields (list[str], optional): The fields to format.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="GET",
            url_suffix=urljoin(self.BANNED_IP_ENDPOINT, "select"),
            params=remove_empty_elements(
                {
                    "vdom": vdom,
                    "filter": self._get_filter(filter_field, filter_value),
                    "format": self._get_format(format_fields),
                }
            ),
            error_handler=Client._error_handler,
        )

    def ban_ip(self) -> dict[str, Any]:
        pass

    def unban_ip(self) -> dict[str, Any]:
        pass


""" Helper Commands  """


def map_keys(old_dict: dict[str, Any], mappings: list[Mapping]) -> dict[str, Any]:
    """Maps keys from an old dictionary to a new dictionary based on the provided mappings.

    Args:
        old_dict (dict[str, Any]): The original dictionary whose keys are to be mapped.
        mappings (list[Mapping]): NamedTuples specifying:
            - old_keys (list[str]): required.
            - new_keys (list[str]): required.
            - default_value (Any): defaults to None.
            - value_changer (Optional[Callable]): defaults to None.

    Returns:
        dict[str, Any]: A new dictionary with the mapped keys and modified values.
    """
    new_dict = {}

    for mapping in mappings:
        current_dict = new_dict

        value = dict_safe_get(
            dict_object=old_dict,
            keys=mapping.old_keys,
            default_return_value=mapping.default_value,
        )

        if mapping.value_changer:
            value = mapping.value_changer(value)

        for new_key in mapping.new_keys:
            if new_key == mapping.new_keys[-1]:
                current_dict[new_key] = value
            else:
                current_dict[new_key] = current_dict.get(new_key, {})

            current_dict = current_dict[new_key]

    return new_dict


def extract_key_from_items(key: str, items: list[dict[str, Any]] | None = None) -> list[str]:
    """Extracts a list of values from a list of dictionaries.

    Args:
        key (str): The key to extract.
        items (list[dict[str, Any]] | None, optional): The list of dictionaries to extract from.
            Defaults to None.

    Returns:
        list[str]: The extracted values.
    """
    return [item[key] for item in items or []]


def space_to_hyphen(value: str | None = None) -> str | None:
    """Replaces all spaces with hyphens in a string.

    Args:
        value (str | None, optional): The string to modify.
            Defaults to None.

    Returns:
        str | None: The modified string.
    """
    return value and value.replace(" ", "-")


def get_address_type(args: dict[str, Any], include_ipv6: bool = False) -> str:
    """Identifies the type of argument group provided based on the arguments.

    Each group must have all of its arguments provided, except for the `allow_routing` argument,
    which is optional and shared between the `Subnet` and `FQDN` groups.

    Args:
        args (dict[str, Any]): The arguments to check.
        include_ipv6 (bool, optional): Whether to include IPv6 address types.
            Defaults to True.

    Returns:
        str: The type of argument group provided.
            Possible values are: "ipmask"/"ipprefix", "iprange", "fqdn", "geography", "mac", and "dynamic".

    Raises:
        DemistoException:
            - If arguments from more than one group are provided.
            - If not all arguments from a single group are provided.
            - If no group of arguments is fully set.
    """
    group_to_arg_names = {
        "Subnet": ["address", "mask"],
        "IP Range": ["start_ip", "end_ip"],
        "FQDN": ["fqdn"],
        "Geography": ["country"],
        "Device (Mac Address)": ["mac_addresses"],
    }

    if include_ipv6:
        group_to_arg_names["Fabric Connector Address"] = ["sdn_connector"]

    # Count the number of not None arguments for each group
    group_to_arg_counts = {
        group: sum(1 for arg in arg_names if args.get(arg) is not None)
        for group, arg_names in group_to_arg_names.items()
    }

    # Special handling for allow_routing argument
    if args.get("allow_routing") is not None:
        if group_to_arg_counts["Subnet"] > 0:
            group_to_arg_counts["Subnet"] += 1

        if group_to_arg_counts["FQDN"] > 0:
            group_to_arg_counts["FQDN"] += 1

    # Set Default value for IPv4 mask argument.
    if all([not include_ipv6, args.get("address"), not args.get("mask")]):
        group_to_arg_counts["Subnet"] += 1
        args["mask"] = "255.255.255.255"

    # Identify fully set, partially set, and mixed groups
    fully_set_groups = []
    partially_set_groups = []

    for group, count in group_to_arg_counts.items():
        if count >= len(group_to_arg_names[group]):
            fully_set_groups.append(group)
        elif 0 < count < len(group_to_arg_names[group]):
            partially_set_groups.append(group)

    mixed_groups = fully_set_groups + partially_set_groups

    # If arguments are from more than one group, raise an error
    if len(mixed_groups) > 1:
        mixed_groups_str = ", ".join(mixed_groups)
        raise DemistoException(f"Arguments must only come from one group. Mixed groups: {mixed_groups_str}")

    # If no group is fully set, raise an error
    if not fully_set_groups:
        if partially_set_groups:
            raise DemistoException(
                f"Missing arguments for the group {partially_set_groups[0]}, "
                f"please provide all: {group_to_arg_names[partially_set_groups[0]]}"
            )

        raise DemistoException(
            "No group of arguments is fully set. "
            f"Please provide arguments from one of the following groups: {list(group_to_arg_names)}"
        )

    gui_to_api = ADDRESS6_GUI_TO_API_TYPE if include_ipv6 else ADDRESS_GUI_TO_API_TYPE

    return gui_to_api[fully_set_groups[0]]


def is_ipv6_network_valid(network: str) -> bool:
    """Checks if the given string represents a valid IPv6 network.

    Args:
        network: (str): The string to check.

    Returns:
        bool: True if the given string represents a valid IPv6 network.
    """
    try:
        ipaddress.IPv6Network(network)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False

    return True


def build_security(policy: dict[str, Any]) -> dict[str, Any]:
    """Builds the security section of the policy.

    Args:
        policy (dict[str, Any]): The policy to build the security section for.

    Returns:
        dict[str, Any]: The security section of the policy.
    """
    return {
        "Security": [
            policy.get("webfilter-profile"),
            policy.get("ssl-ssh-profile"),
            policy.get("dnsfilter-profile"),
            policy.get("profile-protocol-options"),
            policy.get("profile-type"),
            policy.get("av-profile"),
        ]
    }


@logger
def create_addr_string(list_of_addr_data_dicts):
    addr_string = ""
    for addr_index in range(0, len(list_of_addr_data_dicts)):
        cur_addr_data = list_of_addr_data_dicts[addr_index]
        cur_addr_name = cur_addr_data.get("name")
        if addr_index == len(list_of_addr_data_dicts) - 1:
            addr_string += f"{cur_addr_name}"
        else:
            addr_string += f"{cur_addr_name}\n"
    return addr_string


def validate_mac_addresses(mac_addresses: list[str | None] | None = None) -> None:
    """Validates the given list of MAC addresses.

    Args:
        mac_addresses (list[str | None] | None, optional): The list of MAC addresses to validate.
            Defaults to None.

    Raises:
        DemistoException: If any of the MAC addresses is invalid.
    """
    for mac_address_range in mac_addresses or []:
        if mac_address_range:
            for mac_address in mac_address_range.split("-"):
                if not is_mac_address(mac_address):
                    raise DemistoException(f"Invalid MAC address: {mac_address}")


def validate_ipv4_addresses(ipv4_addresses: list[str | None] | None = None) -> None:
    """Validates the given list of IPv4 addresses.

    Args:
        ipv4_addresses (list[str | None] | None, optional): The list of IPv4 addresses to validate.
            Defaults to None.

    Raises:
        DemistoException: If any of the IPv4 addresses is invalid.
    """
    for ipv4_address in ipv4_addresses or []:
        if ipv4_address and not is_ip_valid(ipv4_address):
            raise DemistoException(f"Invalid IPv4 address: {ipv4_address}")


def validate_ipv6_networks(ipv6_networks: list[str | None] | None = None) -> None:
    """Validates the given list of IPv6 networks.

    Args:
        ipv6_networks (list[str | None] | None, optional): The list of IPv6 networks to validate.
            Defaults to None.

    Raises:
        DemistoException: If any of the IPv6 networks is invalid.
    """
    for ipv6_network in ipv6_networks or []:
        if ipv6_network and not is_ipv6_network_valid(ipv6_network):
            raise DemistoException(f"Invalid IPv6 address: {ipv6_network}")


def validate_mask(mask: int | None = None) -> None:
    """Validates the given mask.

    Args:
        mask (int | None, optional): The mask to validate.
            Defaults to None.

    Raises:
        DemistoException: If a mask was provided and its value isn't 0-128.
    """
    if mask is not None and not (MIN_MASK <= mask <= MAX_MASK):
        raise DemistoException(f"Invalid mask: {mask}, valid mask range is: {MIN_MASK}-{MAX_MASK}")


def to_optional_boolean(arg: Any) -> bool:
    """Converts the given argument to a boolean.

    Args:
        arg (Any): The argument to convert.

    Returns:
        bool: The converted argument.
    """
    if arg is None:
        return False

    return argToBoolean(arg)


def build_address_outputs(args: dict[str, Any]) -> dict[str, Any]:
    return remove_empty_elements(
        {
            "Name": args.get("name"),
            "IPAddress": args.get("address"),
            "Mask": args.get("mask"),
            "FQDN": args.get("fqdn"),
            "StartIP": args.get("start_ip"),
            "EndIP": args.get("end_ip"),
            "Country": args.get("country"),
            "MAC": args.get("mac_addresses"),
            "SDN": args.get("sdn_connector"),
        }
    )


def normalize_styling(value: str) -> str:
    """Standardizes the input string for case conversion.

    Args:
        value (str): The input string.

    Returns:
        str: The standardized string with spaces separating words.
    """
    value = value.replace("-", " ").replace("_", " ")  # Replace hyphens and underscores with spaces
    value = CAMEL_CASE_PATTERN.sub(r" \1", value)  # Separate camelCase
    value = UPPER_FOLLOWED_BY_MIXED_PATTERN.sub(r"\1 ", value)  # Separate consecutive uppercase followed by lowercase

    return value.lower()


def to_kebab_case(value: str) -> str:
    """Converts a string to kebab-case.

    Args:
        value (str): The input string.

    Returns:
        str: The converted string in kebab-case.
    """
    value = normalize_styling(value)
    return value.replace(" ", "-")


def extract_first_match(item: dict[str, Any], keys: list[str]) -> dict[str, Any] | None:
    """Extracts the first value from the given item for the given keys.

    Args:
        item (dict[str, Any]): The item to extract the value from.
        keys (list[str]): The keys to extract the value from.

    Returns:
        dict[str, Any] | None: The extracted value, or None if no value was found.
    """
    for key in keys:
        if value := item.get(key):
            return value

    return None


def build_address_table(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Builds the address table from the given items.

    Args:
        items (list[dict[str, Any]]): The items to build the address table from.

    Returns:
        list[dict[str, Any]]: The address table.
    """
    address_table = []
    keys = [
        "Subnet",
        "FQDN",
        "Country",
        "MACAddresses",
        "SDN",
        "IPv6",
    ]
    header_to_key = {
        "Name": "Name",
        "Interface": "AssociatedInterface",
        "Type": "Type",
        "Comment": "Comment",
        "Routable": "Routable",
    }

    for item in items:
        if (start_ip := item.get("StartIP")) and (end_ip := item.get("EndIP")):
            value = f"{start_ip}-{end_ip}"
        else:
            value = extract_first_match(item, keys)

        row = {header: item.get(key) for header, key in header_to_key.items()}
        row["Details"] = value

        address_table.append(row)

    return address_table


def validate_address_type(
    get_request: Callable[..., dict[str, Any]],
    name: str,
    input_type: str,
    api_to_gui: dict[str, Any],
    vdom: str = "root",
) -> None:
    """Validates the input type of the address to the one in the API.

    Args:
        get_request (Callable[..., dict[str, Any]]): The function to use to get the address.
        name (str): The name of the address.
        input_type (str): The type of the address to validate.
        vdom (str, optional): The VDOM to use.
            Defaults to "root".
        is_ipv6 (bool, optional): Whether the address is IPv6.
            Defaults to False.

    Raises:
        DemistoException: If the type of the address is not compatible with the requested type.
    """
    response = get_request(name=name, vdom=vdom, format_fields=["type"])
    result = next(iter(response.get("results", [])), {})
    expected_type = result.get("type")

    if input_type != expected_type:
        raise DemistoException(
            f"The address '{name}' is of type '{api_to_gui.get(expected_type, expected_type)}',"
            f" which is not compatible with the requested type '{api_to_gui[input_type]}'."
        )


def reverse_dict(d: dict) -> dict:
    """Reverses the given dictionary.

    Args:
        d (dict): The dictionary to reverse.

    Returns:
        dict: The reversed dictionary.
    """
    return {v: k for k, v in d.items()}


""" Mappings + Params with helpers """

API_TYPE_TO_ADDRESS_GUI = reverse_dict(ADDRESS_GUI_TO_API_TYPE)
API_TYPE_TO_ADDRESS6_GUI = reverse_dict(ADDRESS6_GUI_TO_API_TYPE)

ALLOW_ROUTING_MAPPING = Mapping(["allow-routing"], ["AllowRouting"])
ASSOCIATED_INTERFACE_MAPPING = Mapping(["associated-interface"], ["AssociatedInterface"])
CACHE_TTL_MAPPING = Mapping(["cache-ttl"], ["CacheTTL"])
CATEGORY_MAPPING = Mapping(["category"], ["Category"])
CLEARPASS_SPT_MAPPING = Mapping(["clearpass-spt"], ["ClearpassSPT"])
COMMENT_MAPPING = Mapping(["comment"], ["Comment"])
COUNTRY_MAPPING = Mapping(["country"], ["Country"])
DIRTY_MAPPING = Mapping(["dirty"], ["Dirty"])
END_IP_MAPPING = Mapping(["end-ip"], ["EndIP"])
EXCLUDE_MAPPING = Mapping(["exclude"], ["Exclude"])
EXCLUDE_MEMBER_MAPPING = Mapping(
    ["exclude-member"], ["ExcludeMember"], None, functools.partial(extract_key_from_items, "name")
)
FABRIC_OBJECT_MAPPING = Mapping(["fabric-object"], ["FabricObject"])
FQDN_MAPPING = Mapping(["fqdn"], ["FQDN"])
FSSO_GROUP_MAPPING = Mapping(["fsso-group"], ["FSSOGroup"])
HOST_MAPPING = Mapping(["host"], ["Host"])
HOST_TYPE_MAPPING = Mapping(["host-type"], ["HostType"])
INTERFACE_MAPPING = Mapping(["interface"], ["Interface"])
IP6_MAPPING = Mapping(["ip6"], ["IPv6"])
LIST_MAPPING = Mapping(["list"], ["IPs"])
MACADDR_MAPPING = Mapping(["macaddr"], ["MACAddresses"], None, functools.partial(extract_key_from_items, "macaddr"))
MEMBER_NAME_MAPPING = Mapping(["member"], ["Member", "Name"], None, functools.partial(extract_key_from_items, "name"))
NAME_MAPPING = Mapping(["name"], ["Name"])
OBJ_TAG_MAPPING = Mapping(["obj-tag"], ["ObjectTag"])
OBJ_TYPE_MAPPING = Mapping(["obj-type"], ["ObjectType"])
PROXY_MAPPING = Mapping(["proxy"], ["Proxy"])
SDN_MAPPING = Mapping(["sdn"], ["SDN"])
SDN_ADDR_TYPE_MAPPING = Mapping(["sdn-addr-type"], ["SDNAddressType"])
SDN_TAG_MAPPING = Mapping(["sdn-tag"], ["SDNTag"])
START_IP_MAPPING = Mapping(["start-ip"], ["StartIP"])
SUBNET_MAPPING = Mapping(["subnet"], ["Subnet"], None, space_to_hyphen)
SUBNET_SEGMENT_NAME_MAPPING = Mapping(["subnet-segment", "name"], ["SubnetSegment", "Name"])
SUBNET_SEGMENT_TYPE_MAPPING = Mapping(["subnet-segment", "type"], ["SubnetSegment", "Type"])
SUBNET_SEGMENT_VALUE_MAPPING = Mapping(["subnet-segment", "value"], ["SubnetSegment", "Value"])
SUB_TYPE_MAPPING = Mapping(["sub-type"], ["SubType"])
TAG_DETECTION_LEVEL_MAPPING = Mapping(["tag-detection-level"], ["TagDetectionLevel"])
TAG_TYPE_MAPPING = Mapping(["tag-type"], ["TagType"])
TAGGING_MAPPING = Mapping(["tagging"], ["Tagging"])
TEMPLATE_MAPPING = Mapping(["template"], ["Template"])
TENANT_MAPPING = Mapping(["tenant"], ["Tenant"])
TYPE_MAPPING = Mapping(["type"], ["Type"])
UUID_MAPPING = Mapping(["uuid"], ["UUID"])


""" Command Handlers """


@logger
def handle_list_command(
    list_command: Callable[..., dict[str, Any]],
    args: dict[str, Any],
    mappings: list[Mapping],
    title: str,
    outputs_prefix: str,
    headers: list[str],
    custom_table_builder: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = None,
    outputs_key_field: str = "Name",
    identifier_field: str = "name",
) -> CommandResults:
    """Handles the list command.

    Args:
        list_command (Callable[..., dict[str, Any]]): The list command to handle.
        args (dict[str, Any]): The arguments to pass to the list command.
        mappings (list[Mapping]): Mappings for adjust the response specifying:
            - old_keys (list[str]): required.
            - new_keys (list[str]): required.
            - default_value (Any): defaults to None.
            - value_changer (Optional[Callable]): defaults to None.
        title (str): The title of the table to display.
        outputs_prefix (str): The prefix to use for the outputs.
        headers (list[str]): The headers of the table to display.
        custom_table_builder (Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None): A custom table builder
            to use for the outputs.
            Defaults to None.
        outputs_key_field (str): The key field to use for the outputs.
            Defaults to "Name".
        identifier_field (str): The identifier key of the firewall object to delete.
            Defaults to "name".

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    vdom = args.get("vdom", VDOM_DEFAULT)
    format_fields = argToList(args.get("format_fields"))

    raw_response = list_command(
        args.get(identifier_field),
        vdom=vdom,
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    # Handle VDOM == *
    responses = raw_response if isinstance(raw_response, list) else [raw_response]
    outputs = []

    for response in responses:
        response_results = response.get("results", [])
        response_vdom = response.get("vdom")
        outputs = [map_keys(result, mappings) | {"VDOM": response_vdom} for result in response_results]

    outputs = remove_empty_elements(outputs)

    if format_fields:
        readable_output = tableToMarkdown(
            name=title,
            t=outputs,
            removeNull=True,
        )
    else:
        readable_output = tableToMarkdown(
            name=title,
            t=custom_table_builder(outputs) if custom_table_builder else outputs,
            headers=headers,
            removeNull=True,
        )

    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def handle_delete_command(
    delete_command: Callable[..., dict[str, Any]],
    args: dict[str, Any],
    firewall_object: str,
    outputs_prefix: str,
    outputs_key_field: str = "Name",
    identifier_field: str = "name",
) -> CommandResults:
    """Handles the delete command.

    Args:
        delete_command (Callable[..., dict[str, Any]]): The delete command to handle.
        vdom (str, optional): The vdom to use for the delete command.
        firewall_object (str): The name of the firewall object.
        outputs_prefix (str): The prefix to use for the outputs.
        outputs_key_field (str): The key field to use for the outputs.
            Defaults to "Name".
        identifier_field (str): The identifier key of the firewall object to delete.
            Defaults to "name".

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    identifier = args.get(identifier_field)
    vdom = args.get("vdom", VDOM_DEFAULT)

    response = delete_command(identifier, vdom=vdom)
    output = {outputs_key_field: identifier, "Deleted": True}
    readable_output = f"The firewall {firewall_object} '{identifier}' was successfully deleted."

    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


""" Commands """


@logger
def test_module(client: Client) -> str:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Session to Fortigate to run API requests.

    Raises:
        DemistoException: Incase there is an unknown error.

    Returns:
        str: : 'ok' if test passed, or an error message if the credentials are incorrect.
    """
    try:
        client.list_system_vdoms()

    except DemistoException as exc:
        if exc.res is not None and exc.res.status_code == http.HTTPStatus.FORBIDDEN:
            return AUTHORIZATION_ERROR

        raise exc

    return "ok"


@logger
def list_firewall_address_ipv4s_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve firewall IPv4 addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_list_command(
        list_command=client.list_firewall_address_ipv4s,
        args=args,
        mappings=[
            ALLOW_ROUTING_MAPPING,
            ASSOCIATED_INTERFACE_MAPPING,
            CACHE_TTL_MAPPING,
            CLEARPASS_SPT_MAPPING,
            COMMENT_MAPPING,
            COUNTRY_MAPPING,
            DIRTY_MAPPING,
            END_IP_MAPPING,
            FABRIC_OBJECT_MAPPING,
            FQDN_MAPPING,
            FSSO_GROUP_MAPPING,
            INTERFACE_MAPPING,
            LIST_MAPPING,
            MACADDR_MAPPING,
            NAME_MAPPING,
            OBJ_TAG_MAPPING,
            OBJ_TYPE_MAPPING,
            SDN_MAPPING,
            SDN_ADDR_TYPE_MAPPING,
            SDN_TAG_MAPPING,
            START_IP_MAPPING,
            SUBNET_MAPPING,
            SUB_TYPE_MAPPING,
            TAG_DETECTION_LEVEL_MAPPING,
            TAG_TYPE_MAPPING,
            TAGGING_MAPPING,
            TYPE_MAPPING,
            UUID_MAPPING,
        ],
        title="Firewall Address IPv4s",
        headers=[
            "Name",
            "Details",
            "Interface",
            "Type",
            "Comment",
            "Routable",
        ],
        custom_table_builder=build_address_table,
        outputs_prefix=ADDRESS_CONTEXT,
    )


@logger
def create_firewall_address_ipv4_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create firewall IPv4 addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.

    """
    type_ = get_address_type(args)

    name = args.get("name")
    vdom = args.get("vdom", VDOM_DEFAULT)
    comment = args.get("comment")
    associated_interface = args.get("associated_interface")
    address = args.get("address")
    mask = args.get("mask")
    allow_routing = args.get("allow_routing")
    start_ip = args.get("start_ip")
    end_ip = args.get("end_ip")
    fqdn = args.get("fqdn")
    country = country.upper() if (country := args.get("country")) else None
    mac_addresses = argToList(args.get("mac_addresses"))

    validate_ipv4_addresses([address, mask, start_ip, end_ip])
    validate_mac_addresses(mac_addresses)
    response = client.create_firewall_address_ipv4(
        name=name,
        type_=type_,
        vdom=vdom,
        comment=comment,
        associated_interface=associated_interface,
        address=address,
        mask=mask,
        allow_routing=allow_routing,
        start_ip=start_ip,
        end_ip=end_ip,
        fqdn=fqdn,
        country=country,
        mac_addresses=mac_addresses,
    )
    output = build_address_outputs(args)
    readable_output = f"The firewall address '{name}' was successfully created."

    return CommandResults(
        outputs_prefix=ADDRESS_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def update_firewall_address_ipv4_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall IPv4 addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name")
    type_ = ADDRESS_GUI_TO_API_TYPE.get(args.get("type"))
    vdom = args.get("vdom", VDOM_DEFAULT)
    comment = args.get("comment")
    associated_interface = args.get("associated_interface")
    address = args.get("address")
    mask = args.get("mask")
    allow_routing = args.get("allow_routing")
    start_ip = args.get("start_ip")
    end_ip = args.get("end_ip")
    fqdn = args.get("fqdn")
    country = country.upper() if (country := args.get("country")) else None
    mac_addresses = argToList(args.get("mac_addresses"))

    if not type_ and any(
        [
            address,
            mask,
            allow_routing,
            start_ip,
            end_ip,
            fqdn,
            country,
            mac_addresses,
        ]
    ):
        type_ = get_address_type(args)

    if type_:
        validate_address_type(
            get_request=client.list_firewall_address_ipv4s,
            name=name,
            input_type=type_,
            api_to_gui=API_TYPE_TO_ADDRESS_GUI,
            vdom=vdom,
        )

    validate_ipv4_addresses([address, mask, start_ip, end_ip])
    validate_mac_addresses(mac_addresses)

    response = client.update_firewall_address_ipv4(
        name=name,
        type_=type_,
        vdom=vdom,
        comment=comment,
        associated_interface=associated_interface,
        address=address,
        mask=mask,
        allow_routing=allow_routing,
        start_ip=start_ip,
        end_ip=end_ip,
        fqdn=fqdn,
        country=country,
        mac_addresses=mac_addresses,
    )
    output = build_address_outputs(args)
    readable_output = f"The firewall address '{name}' was successfully updated."

    return CommandResults(
        outputs_prefix=ADDRESS_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def delete_firewall_address_ipv4_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall IPv4 addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_delete_command(
        delete_command=client.delete_firewall_address_ipv4,
        args=args,
        firewall_object="address",
        outputs_prefix=ADDRESS_CONTEXT,
    )


@logger
def list_firewall_address_ipv6s_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve firewall IPv6 addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_list_command(
        list_command=client.list_firewall_address_ipv6s,
        args=args,
        mappings=[
            CACHE_TTL_MAPPING,
            COMMENT_MAPPING,
            COUNTRY_MAPPING,
            END_IP_MAPPING,
            FABRIC_OBJECT_MAPPING,
            FQDN_MAPPING,
            HOST_MAPPING,
            HOST_TYPE_MAPPING,
            IP6_MAPPING,
            LIST_MAPPING,
            MACADDR_MAPPING,
            NAME_MAPPING,
            SDN_MAPPING,
            SDN_TAG_MAPPING,
            START_IP_MAPPING,
            SUBNET_SEGMENT_NAME_MAPPING,
            SUBNET_SEGMENT_TYPE_MAPPING,
            SUBNET_SEGMENT_VALUE_MAPPING,
            TAGGING_MAPPING,
            TEMPLATE_MAPPING,
            TENANT_MAPPING,
            TYPE_MAPPING,
            UUID_MAPPING,
        ],
        title="Firewall Address IPv6s",
        headers=[
            "Name",
            "Details",
            "Type",
            "Comment",
        ],
        custom_table_builder=build_address_table,
        outputs_prefix=ADDRESS6_CONTEXT,
    )


@logger
def create_firewall_address_ipv6_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create firewall IPv6 addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    type_ = get_address_type(args, True)

    name = args.get("name")
    vdom = args.get("vdom", VDOM_DEFAULT)
    comment = args.get("comment")
    address = args.get("address")
    mask = arg_to_number(args.get("mask"))
    start_ip = args.get("start_ip")
    end_ip = args.get("end_ip")
    fqdn = args.get("fqdn")
    country = country.upper() if (country := args.get("country")) else None
    mac_addresses = argToList(args.get("mac_addresses"))
    sdn_connector = args.get("sdn_connector")

    validate_mask(mask)
    subnet = f"{address}/{mask}" if address and mask is not None else None
    validate_ipv6_networks([subnet, start_ip, end_ip])
    validate_mac_addresses(mac_addresses)

    response = client.create_firewall_address_ipv6(
        name=name,
        type_=type_,
        vdom=vdom,
        comment=comment,
        subnet=subnet,
        start_ip=start_ip,
        end_ip=end_ip,
        fqdn=fqdn,
        country=country,
        mac_addresses=mac_addresses,
        sdn_connector=sdn_connector,
    )
    output = build_address_outputs(args)
    readable_output = f"The firewall address '{name}' was successfully created."

    return CommandResults(
        outputs_prefix=ADDRESS6_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def update_firewall_address_ipv6_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall IPv6 addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException:
            - If a mask was provided and its value isn't 0-128.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name")
    type_ = ADDRESS6_GUI_TO_API_TYPE.get(args.get("type"))
    vdom = args.get("vdom", VDOM_DEFAULT)
    comment = args.get("comment")
    address = args.get("address")
    mask = arg_to_number(args.get("mask"))
    start_ip = args.get("start_ip")
    end_ip = args.get("end_ip")
    fqdn = args.get("fqdn")
    country = country.upper() if (country := args.get("country")) else None
    mac_addresses = argToList(args.get("mac_addresses"))
    sdn_connector = args.get("sdn_connector")

    if not type_ and any(
        [
            address,
            mask is not None,
            start_ip,
            end_ip,
            fqdn,
            country,
            mac_addresses,
            sdn_connector,
        ]
    ):
        type_ = get_address_type(args, True)

    if type_:
        validate_address_type(
            get_request=client.list_firewall_address_ipv6s,
            name=name,
            input_type=type_,
            api_to_gui=API_TYPE_TO_ADDRESS6_GUI,
            vdom=vdom,
        )

    validate_mask(mask)
    subnet = f"{address}/{mask}" if address and mask is not None else None
    validate_ipv6_networks([subnet, start_ip, end_ip])
    validate_mac_addresses(mac_addresses)

    response = client.update_firewall_address_ipv6(
        name=name,
        type_=type_,
        vdom=vdom,
        comment=comment,
        subnet=subnet,
        start_ip=start_ip,
        end_ip=end_ip,
        fqdn=fqdn,
        country=country,
        mac_addresses=mac_addresses,
        sdn_connector=sdn_connector,
    )
    output = build_address_outputs(args)
    readable_output = f"The firewall address '{name}' was successfully updated."

    return CommandResults(
        outputs_prefix=ADDRESS6_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def delete_firewall_address_ipv6_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall IPv6 addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_delete_command(
        delete_command=client.delete_firewall_address_ipv6,
        args=args,
        firewall_object="address",
        outputs_prefix=ADDRESS6_CONTEXT,
    )


@logger
def list_firewall_address_ipv4_multicasts_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve firewall IPv4 multicast addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_list_command(
        list_command=client.list_firewall_address_ipv4_multicasts,
        args=args,
        mappings=[
            ASSOCIATED_INTERFACE_MAPPING,
            COMMENT_MAPPING,
            END_IP_MAPPING,
            NAME_MAPPING,
            START_IP_MAPPING,
            SUBNET_MAPPING,
            TAGGING_MAPPING,
            TYPE_MAPPING,
        ],
        title="Firewall Address IPv4 Multicasts",
        headers=[
            "Name",
            "Details",
            "Interface",
            "Type",
            "Comment",
            "Routable",
        ],
        custom_table_builder=build_address_table,
        outputs_prefix=ADDRESS_MULTICAST_CONTEXT,
    )


@logger
def create_firewall_address_ipv4_multicast_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create firewall IPv4 multicast addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name")
    vdom = args.get("vdom", VDOM_DEFAULT)
    comment = args.get("comment")
    associated_interface = args.get("associated_interface")
    type_ = ADDRESS_MULTICAST_GUI_TO_API_TYPE.get(args.get("type"))
    first_ip = args.get("first_ip")
    final_ip = args.get("final_ip")

    validate_ipv4_addresses([first_ip, final_ip])
    subnet = f"{first_ip} {final_ip}" if type_ == "broadcastmask" else None

    response = client.create_firewall_address_ipv4_multicast(
        name=name,
        vdom=vdom,
        comment=comment,
        associated_interface=associated_interface,
        type_=type_,
        subnet=subnet,
        start_ip=first_ip,
        end_ip=final_ip,
    )
    output = {
        "Name": name,
        "Type": args.get("type"),
        "FirstIP": first_ip,
        "FinalIP": final_ip,
    }
    readable_output = f"The firewall address multicast IPv4 '{name}' was successfully created."

    return CommandResults(
        outputs_prefix=ADDRESS_MULTICAST_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def update_firewall_address_ipv4_multicast_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall IPv4 multicast addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name")
    vdom = args.get("vdom", VDOM_DEFAULT)
    comment = args.get("comment")
    associated_interface = args.get("associated_interface")
    type_ = ADDRESS_MULTICAST_GUI_TO_API_TYPE.get(args.get("type"))
    first_ip = args.get("first_ip")
    final_ip = args.get("final_ip")

    multicast_fields = [type_, first_ip, final_ip]

    if any(multicast_fields):
        if all(multicast_fields):
            validate_address_type(
                get_request=client.list_firewall_address_ipv4_multicasts,
                name=name,
                input_type=type_,
                api_to_gui=reverse_dict(ADDRESS_MULTICAST_GUI_TO_API_TYPE),
                vdom=vdom,
            )
        else:
            raise DemistoException(
                "All multicast fields (`type`, `first_ip`, `final_ip`) must be provided to update any."
            )

    validate_ipv4_addresses([first_ip, final_ip])
    subnet = f"{first_ip} {final_ip}" if type_ == "broadcastmask" else None

    response = client.update_firewall_address_ipv4_multicast(
        name=name,
        vdom=vdom,
        comment=comment,
        associated_interface=associated_interface,
        type_=type_,
        subnet=subnet,
        start_ip=first_ip,
        end_ip=final_ip,
    )
    output = remove_empty_elements(
        {
            "Name": name,
            "Type": args.get("type"),
            "FirstIP": first_ip,
            "FinalIP": final_ip,
        }
    )
    readable_output = f"The firewall address multicast IPv4 '{name}' was successfully updated."

    return CommandResults(
        outputs_prefix=ADDRESS_MULTICAST_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def delete_firewall_address_ipv4_multicast_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall IPv4 multicast addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_delete_command(
        delete_command=client.delete_firewall_address_ipv4_multicast,
        args=args,
        firewall_object="address multicast IPv4",
        outputs_prefix=ADDRESS_MULTICAST_CONTEXT,
    )


@logger
def list_firewall_address_ipv6_multicasts_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve firewall IPv6 multicast addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_list_command(
        list_command=client.list_firewall_address_ipv6_multicasts,
        args=args,
        mappings=[
            COMMENT_MAPPING,
            IP6_MAPPING,
            NAME_MAPPING,
            TAGGING_MAPPING,
        ],
        title="Firewall Address IPv6 Multicasts",
        headers=[
            "Name",
            "Details",
            "Comment",
        ],
        custom_table_builder=build_address_table,
        outputs_prefix=ADDRESS6_MULTICAST_CONTEXT,
    )


@logger
def create_firewall_address_ipv6_multicast_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create firewall IPv6 multicast addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name")
    vdom = args.get("vdom", VDOM_DEFAULT)
    comment = args.get("comment")
    address = args.get("address")
    mask = arg_to_number(args.get("mask"))

    validate_mask(mask)
    subnet = f"{address}/{mask}" if address and mask is not None else None
    validate_ipv6_networks([subnet])

    response = client.create_firewall_address_ipv6_multicast(
        name=name,
        vdom=vdom,
        comment=comment,
        subnet=subnet,
    )
    output = build_address_outputs(args)
    readable_output = f"The firewall address multicast IPv6 '{name}' was successfully created."

    return CommandResults(
        outputs_prefix=ADDRESS6_MULTICAST_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def update_firewall_address_ipv6_multicast_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall IPv6 multicast addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If `address` and `mask` are not provided together.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name")
    vdom = args.get("vdom", VDOM_DEFAULT)
    comment = args.get("comment")
    address = args.get("address")
    mask = arg_to_number(args.get("mask"))

    subnet = None
    address_provided = bool(address)
    mask_provided = mask is not None

    if address_provided and mask_provided:
        validate_mask(mask)
        subnet = f"{address}/{mask}"
        validate_ipv6_networks([subnet])
    elif address_provided != mask_provided:
        raise DemistoException("Either both or none of `address` and `mask` must be provided.")

    response = client.update_firewall_address_ipv6_multicast(
        name=name,
        vdom=vdom,
        comment=comment,
        subnet=subnet,
    )
    output = build_address_outputs(args)
    readable_output = f"The firewall address multicast IPv6 '{name}' was successfully updated."

    return CommandResults(
        outputs_prefix=ADDRESS6_MULTICAST_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def delete_firewall_address_ipv6_multicast_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall IPv6 multicast addresses.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_delete_command(
        delete_command=client.delete_firewall_address_ipv6_multicast,
        args=args,
        firewall_object="address multicast IPv6",
        outputs_prefix=ADDRESS6_MULTICAST_CONTEXT,
    )


@logger
def list_firewall_address_ipv4_groups_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve firewall IPv4 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_list_command(
        list_command=client.list_firewall_address_ipv4_groups,
        args=args,
        mappings=[
            ALLOW_ROUTING_MAPPING,
            CATEGORY_MAPPING,
            COMMENT_MAPPING,
            EXCLUDE_MAPPING,
            EXCLUDE_MEMBER_MAPPING,
            FABRIC_OBJECT_MAPPING,
            MEMBER_NAME_MAPPING,
            NAME_MAPPING,
            TAGGING_MAPPING,
            TYPE_MAPPING,
            UUID_MAPPING,
        ],
        title="Firewall Address IPv4 Groups",
        headers=[
            "Name",
            "Comment",
            "Type",
            "Member",
            "ExcludeMember",
        ],
        outputs_prefix=ADDRESS_GROUP_CONTEXT,
        identifier_field="groupName",
    )


@logger
def create_firewall_address_ipv4_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create firewall IPv4 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.create_firewall_address_ipv4_group()


@logger
def update_firewall_address_ipv4_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall IPv4 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.update_firewall_address_ipv4_group()


@logger
def delete_firewall_address_ipv4_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall IPv4 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_delete_command(
        delete_command=client.delete_firewall_address_ipv4_group,
        args=args,
        firewall_object="address IPv4 group",
        outputs_prefix=ADDRESS_GROUP_CONTEXT,
    )


@logger
def list_firewall_address_ipv6_groups_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve firewall IPv6 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_list_command(
        list_command=client.list_firewall_address_ipv6_groups,
        args=args,
        mappings=[
            COMMENT_MAPPING,
            FABRIC_OBJECT_MAPPING,
            MEMBER_NAME_MAPPING,
            NAME_MAPPING,
            TAGGING_MAPPING,
            UUID_MAPPING,
        ],
        title="Firewall Address IPv6 Groups",
        headers=[
            "Name",
            "UUID",
            "Comment",
            "Type",
            "Member",
        ],
        outputs_prefix=ADDRESS6_GROUP_CONTEXT,
    )


@logger
def create_firewall_address_ipv6_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create firewall IPv6 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.create_firewall_address_ipv6_group()


@logger
def update_firewall_address_ipv6_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall IPv6 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.update_firewall_address_ipv6_group()


@logger
def delete_firewall_address_ipv6_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall IPv6 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_delete_command(
        delete_command=client.delete_firewall_address_ipv6_group,
        args=args,
        firewall_object="address IPv6 group",
        outputs_prefix=ADDRESS6_GROUP_CONTEXT,
    )


@logger
def list_firewall_services_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve firewall services.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_list_command(
        list_command=client.list_firewall_services,
        args=args,
        mappings=[
            Mapping(["application "], ["Application"]),
            Mapping(["app-category"], ["AppCategory"]),
            Mapping(["app-service-type"], ["AppServiceType"]),
            CATEGORY_MAPPING,
            Mapping(["check-reset-range"], ["CheckResetRange"]),
            COMMENT_MAPPING,
            FABRIC_OBJECT_MAPPING,
            FQDN_MAPPING,
            Mapping(["helper"], ["Helper"]),
            Mapping(["icmpcode"], ["ICMPCode"]),
            Mapping(["icmptype"], ["ICMPType"]),
            Mapping(["iprange"], ["IPRange"]),
            NAME_MAPPING,
            Mapping(["sctp-portrange"], ["Ports", "SCTP"]),
            Mapping(["tcp-portrange"], ["Ports", "TCP"]),
            Mapping(["udp-portrange"], ["Ports", "UDP"]),
            Mapping(["protocol-number"], ["ProtocolNumber"]),
            Mapping(["protocol"], ["Protocol"]),
            PROXY_MAPPING,
            Mapping(["session-ttl"], ["SessionTTL"]),
            Mapping(["tcp-halfopen-timer"], ["TCPHalfopenTimer"]),
            Mapping(["tcp-halfclose-timer"], ["TCPHalfcloseTimer"]),
            Mapping(["tcp-timewait-timer"], ["TCPTimewaitTimer"]),
            Mapping(["tcp-rst-timer"], ["TCPRSTTimer"]),
            Mapping(["udp-idle-timer"], ["UDPIdleTimer"]),
        ],
        title="Firewall Services",
        headers=[
            "Name",
            "Comment",
            "IPRange",
            "Ports",
            "FQDN",
            "Protocol",
            "ProtocolNumber",
            "ICMPCode",
            "ICMPType",
        ],
        outputs_prefix=SERVICE_CONTEXT,
        identifier_field="serviceName",
    )


@logger
def create_firewall_service_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create firewall services.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.create_firewall_service()


@logger
def update_firewall_service_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall services.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.update_firewall_service()


@logger
def delete_firewall_service_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall services.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_delete_command(
        delete_command=client.delete_firewall_service,
        args=args,
        firewall_object="service",
        outputs_prefix=SERVICE_CONTEXT,
    )


@logger
def list_firewall_service_groups_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve firewall service groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_list_command(
        list_command=client.list_firewall_service_groups,
        args=args,
        mappings=[
            COMMENT_MAPPING,
            FABRIC_OBJECT_MAPPING,
            MEMBER_NAME_MAPPING,
            NAME_MAPPING,
            PROXY_MAPPING,
        ],
        title="Firewall Service Groups",
        headers=[
            "Name",
            "Comment",
            "Proxy",
            "Members",
        ],
        outputs_prefix=SERVICE_GROUP_CONTEXT,
    )


@logger
def create_firewall_service_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create firewall service groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.create_firewall_service_group()


@logger
def update_firewall_service_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall service groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.update_firewall_service_group()


@logger
def delete_firewall_service_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall service groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_delete_command(
        delete_command=client.delete_firewall_service_group,
        args=args,
        firewall_object="service group",
        outputs_prefix=SERVICE_GROUP_CONTEXT,
        identifier_field="groupName",
    )


@logger
def list_firewall_policies_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve firewall policies.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    raw_response = client.list_firewall_policies(
        id_=args.get("policyID"),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=argToList(args.get("format_fields")),
    )

    mappings = [
        Mapping(["action"], ["Action"]),
        Mapping(["comments"], ["Description"]),
        Mapping(["dstaddr"], ["Destination"], None, create_addr_string),
        Mapping(["dstaddr6"], ["Destination6"], None, functools.partial(extract_key_from_items, "name")),
        Mapping(["dstaddr-negate"], ["DestinationNegate"]),
        Mapping(["dstaddr6-negate"], ["Destination6Negate"]),
        Mapping(["dstintf"], ["DestinationInterface"], None, functools.partial(extract_key_from_items, "name")),
        Mapping(["logtraffic"], ["Log"]),
        Mapping(["logtraffic-start"], ["LogStart"]),
        NAME_MAPPING,
        Mapping(["nat"], ["NAT"]),
        Mapping(["policyid"], ["ID"]),
        Mapping(["service"], ["Service"], None, functools.partial(extract_key_from_items, "name")),
        Mapping(["service-negate"], ["ServiceNegate"]),
        Mapping(["srcaddr"], ["Source"], None, create_addr_string),
        Mapping(["srcaddr6"], ["Source6"], None, functools.partial(extract_key_from_items, "name")),
        Mapping(["srcaddr-negate"], ["SourceNegate"]),
        Mapping(["srcaddr6-negate"], ["Source6Negate"]),
        Mapping(["srcintf"], ["SourceInterface"], None, functools.partial(extract_key_from_items, "name")),
        Mapping(["status"], ["Status"]),
        UUID_MAPPING,
    ]
    name: Any | None = args.get("policyName")
    outputs = []

    # Handle VDOM == *
    responses = raw_response if isinstance(raw_response, list) else [raw_response]
    outputs = []

    for response in responses:
        response_results = response.get("results", [])
        response_vdom = response.get("vdom")

        for result in response_results:
            output = map_keys(result, mappings) | build_security(result) | {"VDOM": response_vdom}

            if name == result.get("name"):
                outputs = output
                break

            outputs.append(output)

    outputs = remove_empty_elements(outputs)

    readable_output = tableToMarkdown(
        name="Firewall Policies",
        t=outputs,
        headers=[
            "ID",
            "Description",
            "Status",
            "Action",
            "Source",
            "Destination",
            "Source6",
            "Destination6",
            "SourceInterface",
            "DestinationInterface",
        ],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=POLICY_CONTEXT,
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def create_firewall_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create firewall policies.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.create_firewall_policy()


@logger
def update_firewall_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall policies.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.update_firewall_policy()


@logger
def move_firewall_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Move the position of firewall policies.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.move_firewall_policy()


@logger
def delete_firewall_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall policies.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    return handle_delete_command(
        delete_command=client.delete_firewall_policy,
        args=args,
        firewall_object="policy",
        outputs_prefix=POLICY_CONTEXT,
        identifier_field="policyID",
        outputs_key_field="ID",
    )


@logger
def list_system_vdoms_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve system VDOMs.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    response = client.list_system_vdoms(
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=argToList(args.get("format_fields")),
    )
    mappings = [
        NAME_MAPPING,
        Mapping(["short-name"], ["ShortName"]),
        Mapping(["vcluster-id"], ["VClusterID"]),
    ]
    output = remove_empty_elements([map_keys(result, mappings) for result in response["results"]])
    readable_output = tableToMarkdown(
        name="Virtual Domains",
        t=output,
        headers=[
            "Name",
            "ShortName",
            "VClusterID",
        ],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=VDOM_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def list_banned_ips_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve Banned IPs.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.list_banned_ips()


@logger
def ban_ip_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Ban IPs.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.ban_ip()


@logger
def unban_ip_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Unban IPs.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # response = client.unban_ip()


""" Deprecated Commands """


@logger
def get_addresses_command(client: Client, args: dict[str, Any]):
    contents = []
    context = {}
    addresses_context = []
    address = args.get("address")
    name = args.get("name", "")

    response = client.list_firewall_address_ipv4s(name, address)
    addresses = response[0].get("results") if address == "*" else response.get("results")

    for address in addresses:
        subnet = address.get("subnet")
        if subnet:
            subnet = subnet.replace(" ", "-")
        contents.append(
            {
                "Name": address.get("name"),
                "Subnet": subnet,
                "StartIP": address.get("start-ip"),
                "EndIP": address.get("end-ip"),
            }
        )
        addresses_context.append(
            {
                "Name": address.get("name"),
                "Subnet": subnet,
                "StartIP": address.get("start-ip"),
                "EndIP": address.get("end-ip"),
            }
        )

    context["Fortigate.Address(val.Name && val.Name === obj.Name)"] = addresses_context
    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate addresses", contents),
            "EntryContext": context,
        }
    )


@logger
def create_address_command(client: Client, args: dict[str, Any]):
    contents = []
    context = {}
    address_context = []
    address_name = args.get("name", "")
    address = args.get("address", "")
    mask = args.get("mask", "")
    fqdn = args.get("fqdn", "")

    if fqdn and address:
        return_error("Please provide only one of the two arguments: fqdn or address")

    client.create_firewall_address_ipv4(
        name=address_name,
        type_="" if address else "fqdn",
        address=address,
        mask=mask,
        fqdn=fqdn,
    )

    if address:
        address_dict = {"Name": address_name, "IPAddress": address}
        contents.append(address_dict)
        address_context.append(address_dict)
    elif fqdn:
        fqdn_dict = {"Name": address_name, "FQDN": fqdn}
        contents.append(fqdn_dict)
        address_context.append(fqdn_dict)

    context["Fortigate.Address(val.Name && val.Name === obj.Name)"] = address_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate address " + address_name + " created successfully", contents),
            "EntryContext": context,
        }
    )


@logger
def delete_address_command(client: Client, args: dict[str, Any]):
    contents = []
    context = {}
    address_context = []
    name = args.get("name", "")

    client.delete_firewall_address_ipv4(name)

    address_dict = {"Name": name, "Deleted": True}
    contents.append(address_dict)
    address_context.append(address_dict)

    context["Fortigate.Address(val.Name && val.Name === obj.Name)"] = address_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate address " + name + " deleted successfully", contents),
            "EntryContext": context,
        }
    )


@logger
def get_address_groups_command(client: Client, args: dict[str, Any]):
    contents = []
    context = {}
    address_groups_context = []
    address_group_name = args.get("groupName", "")
    title = address_group_name if address_group_name else "all"

    address_groups = client.list_firewall_address_ipv4_groups(address_group_name).get("results")

    for address_group in address_groups:
        members = address_group.get("member")
        members_list = []
        for member in members:
            members_list.append(member.get("name"))
        contents.append({"Name": address_group.get("name"), "Members": members_list, "UUID": address_group.get("uuid")})
        address_groups_context.append(
            {"Name": address_group.get("name"), "Member": {"Name": members_list}, "UUID": address_group.get("uuid")}
        )

    context["Fortigate.AddressGroup(val.Name && val.Name === obj.Name)"] = address_groups_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate address groups " + title, contents),
            "EntryContext": context,
        }
    )


@logger
def delete_address_group_command(client: Client, args: dict[str, Any]):
    contents = []
    context = {}
    address_group_context = []
    name = args.get("name", "")

    client.delete_firewall_address_ipv4_group(name)

    contents.append({"Name": name, "Deleted": True})
    address_group_context.append({"Name": name, "Deleted": True})

    context["Fortigate.AddressGroup(val.Name && val.Name === obj.Name)"] = address_group_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate address group " + name + " deleted successfully", contents),
            "EntryContext": context,
        }
    )


@logger
def get_firewall_service_command(client: Client, args: dict[str, Any]):
    contents = []
    context = {}
    service_context = []
    service_name = args.get("serviceName", "")
    service_title = service_name
    if not service_name:
        service_title = "all services"

    services = client.list_firewall_services(service_name).get("results")

    for service in services:
        contents.append(
            {
                "Name": service.get("name"),
                "Ports": {"TCP": service.get("tcp-portrange"), "UDP": service.get("udp-portrange")},
            }
        )
        service_context.append(
            {
                "Name": service.get("name"),
                "Ports": {"TCP": service.get("tcp-portrange"), "UDP": service.get("udp-portrange")},
            }
        )

    context["Fortigate.Service(val.Name && val.Name === obj.Name)"] = service_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate firewall services " + service_title, contents),
            "EntryContext": context,
        }
    )


@logger
def get_service_groups_command(client: Client, args: dict[str, Any]):
    contents = []
    context = {}
    service_groups_context = []
    name = args.get("name", "")

    service_groups = client.list_firewall_service_groups(name).get("results")

    for service_group in service_groups:
        service_group_members = []
        members = service_group.get("member")
        for member in members:
            service_group_members.append(member.get("name"))
        contents.append({"Name": service_group.get("name"), "Members": service_group_members})
        service_groups_context.append({"Name": service_group.get("name"), "Member": {"Name": service_group_members}})

    context["Fortigate.ServiceGroup(val.Name && val.Name === obj.Name)"] = service_groups_context
    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate service groups", contents),
            "EntryContext": context,
        }
    )


@logger
def delete_service_group_command(client: Client, args: dict[str, Any]):
    context = {}
    group_name = args.get("groupName").encode("utf-8")

    client.delete_firewall_service_group(group_name)

    service_group_context = {"Name": group_name, "Deleted": True}

    contents = service_group_context
    context["Fortigate.ServiceGroup(val.Name && val.Name === obj.Name)"] = service_group_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "FortiGate service group: " + group_name + " was deleted successfully", contents
            ),
            "EntryContext": context,
        }
    )


@logger
def get_policy_command(client: Client, args: dict[str, Any]):
    contents = []
    context = {}
    policy_context = []
    policy_name = args.get("policyName")
    policy_id = args.get("policyID")
    policy_title = "all policies"

    format_fields = [
        "policyid",
        "action",
        "name",
        "comments",
        "status",
        "service",
        "logtraffic",
        "srcaddr",
        "dstaddr",
        "webfilter-profile",
        "ssl-ssh-profile",
        "dnsfilter-profile",
        "profile-protocol-options",
        "profile-type",
        "av-profile",
        "nat",
    ]
    policies = client.list_firewall_policies(id_=policy_id, format_fields=format_fields).get("results")

    for policy in policies:
        if policy_name == policy.get("name") or not policy_name:
            if policy_name or policy_id:
                policy_title = policy.get("name")
            security_profiles = []
            all_security_profiles = [
                policy.get("webfilter-profile"),
                policy.get("ssl-ssh-profile"),
                policy.get("dnsfilter-profile"),
                policy.get("profile-protocol-options"),
                policy.get("profile-type"),
                policy.get("av-profile"),
            ]
            for security_profile in all_security_profiles:
                if security_profile:
                    security_profiles.append(security_profile)

            src_address = policy.get("srcaddr")
            if src_address and isinstance(src_address, list) and isinstance(src_address[0], dict):
                src_address = create_addr_string(src_address)
            dest_address = policy.get("dstaddr")
            if dest_address and isinstance(dest_address, list) and isinstance(dest_address[0], dict):
                dest_address = create_addr_string(dest_address)
            service = policy.get("service")
            if service and isinstance(service, list) and isinstance(service[0], dict):
                service = service[0].get("name")

            contents.append(
                {
                    "Name": policy.get("name"),
                    "ID": int(policy.get("policyid")),
                    "Description": policy.get("comments"),
                    "Status": policy.get("status"),
                    "Source": src_address,
                    "Destination": dest_address,
                    "Service": service,
                    "Action": policy.get("action"),
                    "Log": policy.get("logtraffic"),
                    "Security": security_profiles,
                    "NAT": policy.get("nat"),
                }
            )
            policy_context.append(
                {
                    "Name": policy.get("name"),
                    "ID": int(policy.get("policyid")),
                    "Description": policy.get("comments"),
                    "Status": policy.get("status"),
                    "Source": src_address,
                    "Destination": dest_address,
                    "Service": service,
                    "Action": policy.get("action"),
                    "Log": policy.get("logtraffic"),
                    "Security": security_profiles,
                    "NAT": policy.get("nat"),
                }
            )

    context["Fortigate.Policy(val.ID && val.ID === obj.ID)"] = policy_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate policy details for " + policy_title, contents),
            "EntryContext": context,
        }
    )


@logger
def delete_policy_command(client: Client, args: dict[str, Any]):
    contents = []
    context = {}
    policy_id = args.get("policyID")

    client.delete_firewall_policy(policy_id)

    policy_context = {"ID": policy_id, "Deleted": True}
    contents.append({"ID": policy_id, "Deleted": True})

    context["Fortigate.Policy(val.ID && val.ID === obj.ID)"] = policy_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "FortiGate policy with ID " + policy_id + " deleted successfully", contents
            ),
            "EntryContext": context,
        }
    )


""" Entry Point """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url: str = params["server"]
    username: str = params["credentials"]["identifier"]
    password: str = params["credentials"]["password"]

    verify_certificate: bool = not to_optional_boolean(params.get("unsecure", False))
    proxy: bool = to_optional_boolean(params.get("proxy", False))

    demisto.debug(f"Command being called is {command}")

    commands = {
        f"{FORTIGATE}-list-{FIREWALL}-{ADDRESS}-{IPV4}s": list_firewall_address_ipv4s_command,
        f"{FORTIGATE}-create-{FIREWALL}-{ADDRESS}-{IPV4}": create_firewall_address_ipv4_command,
        f"{FORTIGATE}-update-{FIREWALL}-{ADDRESS}-{IPV4}": update_firewall_address_ipv4_command,
        f"{FORTIGATE}-delete-{FIREWALL}-{ADDRESS}-{IPV4}": delete_firewall_address_ipv4_command,
        f"{FORTIGATE}-list-{FIREWALL}-{ADDRESS}-{IPV6}s": list_firewall_address_ipv6s_command,
        f"{FORTIGATE}-create-{FIREWALL}-{ADDRESS}-{IPV6}": create_firewall_address_ipv6_command,
        f"{FORTIGATE}-update-{FIREWALL}-{ADDRESS}-{IPV6}": update_firewall_address_ipv6_command,
        f"{FORTIGATE}-delete-{FIREWALL}-{ADDRESS}-{IPV6}": delete_firewall_address_ipv6_command,
        f"{FORTIGATE}-list-{FIREWALL}-{ADDRESS}-{IPV4}-{MULTICAST}s": list_firewall_address_ipv4_multicasts_command,
        f"{FORTIGATE}-create-{FIREWALL}-{ADDRESS}-{IPV4}-{MULTICAST}": create_firewall_address_ipv4_multicast_command,
        f"{FORTIGATE}-update-{FIREWALL}-{ADDRESS}-{IPV4}-{MULTICAST}": update_firewall_address_ipv4_multicast_command,
        f"{FORTIGATE}-delete-{FIREWALL}-{ADDRESS}-{IPV4}-{MULTICAST}": delete_firewall_address_ipv4_multicast_command,
        f"{FORTIGATE}-list-{FIREWALL}-{ADDRESS}-{IPV6}-{MULTICAST}s": list_firewall_address_ipv6_multicasts_command,
        f"{FORTIGATE}-create-{FIREWALL}-{ADDRESS}-{IPV6}-{MULTICAST}": create_firewall_address_ipv6_multicast_command,
        f"{FORTIGATE}-update-{FIREWALL}-{ADDRESS}-{IPV6}-{MULTICAST}": update_firewall_address_ipv6_multicast_command,
        f"{FORTIGATE}-delete-{FIREWALL}-{ADDRESS}-{IPV6}-{MULTICAST}": delete_firewall_address_ipv6_multicast_command,
        f"{FORTIGATE}-list-{FIREWALL}-{ADDRESS}-{IPV4}-{GROUP}s": list_firewall_address_ipv4_groups_command,
        f"{FORTIGATE}-create-{FIREWALL}-{ADDRESS}-{IPV4}-{GROUP}": create_firewall_address_ipv4_group_command,
        f"{FORTIGATE}-update-{FIREWALL}-{ADDRESS}-{IPV4}-{GROUP}": update_firewall_address_ipv4_group_command,
        f"{FORTIGATE}-delete-{FIREWALL}-{ADDRESS}-{IPV4}-{GROUP}": delete_firewall_address_ipv4_group_command,
        f"{FORTIGATE}-list-{FIREWALL}-{ADDRESS}-{IPV6}-{GROUP}s": list_firewall_address_ipv6_groups_command,
        f"{FORTIGATE}-create-{FIREWALL}-{ADDRESS}-{IPV6}-{GROUP}": create_firewall_address_ipv6_group_command,
        f"{FORTIGATE}-update-{FIREWALL}-{ADDRESS}-{IPV6}-{GROUP}": update_firewall_address_ipv6_group_command,
        f"{FORTIGATE}-delete-{FIREWALL}-{ADDRESS}-{IPV6}-{GROUP}": delete_firewall_address_ipv6_group_command,
        f"{FORTIGATE}-list-{FIREWALL}-{SERVICE}s": list_firewall_services_command,
        f"{FORTIGATE}-create-{FIREWALL}-{SERVICE}": create_firewall_service_command,
        f"{FORTIGATE}-update-{FIREWALL}-{SERVICE}": update_firewall_service_command,
        f"{FORTIGATE}-delete-{FIREWALL}-{SERVICE}": delete_firewall_service_command,
        f"{FORTIGATE}-list-{FIREWALL}-{SERVICE}-{GROUP}s": list_firewall_service_groups_command,
        f"{FORTIGATE}-create-{FIREWALL}-{SERVICE}-{GROUP}": create_firewall_service_group_command,
        f"{FORTIGATE}-update-{FIREWALL}-{SERVICE}-{GROUP}": update_firewall_service_group_command,
        f"{FORTIGATE}-delete-{FIREWALL}-{SERVICE}-{GROUP}": delete_firewall_service_group_command,
        f"{FORTIGATE}-list-{FIREWALL}-policies": list_firewall_policies_command,
        f"{FORTIGATE}-create-{FIREWALL}-{POLICY}": create_firewall_policy_command,
        f"{FORTIGATE}-update-{FIREWALL}-{POLICY}": update_firewall_policy_command,
        f"{FORTIGATE}-move-{FIREWALL}-{POLICY}": move_firewall_policy_command,
        f"{FORTIGATE}-delete-{FIREWALL}-{POLICY}": delete_firewall_policy_command,
        f"{FORTIGATE}-list-system-vdoms": list_system_vdoms_command,
        f"{FORTIGATE}-list-banned-ips": list_banned_ips_command,
        f"{FORTIGATE}-ban-ip": ban_ip_command,
        f"{FORTIGATE}-unban-ip": unban_ip_command,
    }

    commands_deprecated = {
        f"{FORTIGATE}-create-{ADDRESS}": create_address_command,
        f"{FORTIGATE}-get-{ADDRESSES}": get_addresses_command,
        f"{FORTIGATE}-delete-{ADDRESS}": delete_address_command,
        # f"{FORTIGATE}-create-{ADDRESS}-{GROUP}": create_address_group_command,
        f"{FORTIGATE}-get-{ADDRESS}-{GROUP}s": get_address_groups_command,
        # f"{FORTIGATE}-update-{ADDRESS}-{GROUP}": update_address_group_command,
        f"{FORTIGATE}-delete-{ADDRESS}-{GROUP}": delete_address_group_command,
        f"{FORTIGATE}-get-{SERVICE}": get_firewall_service_command,
        f"{FORTIGATE}-get-{SERVICE}-{GROUP}s": get_service_groups_command,
        # f"{FORTIGATE}-update-{SERVICE}-{GROUP}": update_service_group_command,
        f"{FORTIGATE}-delete-{SERVICE}-{GROUP}": delete_service_group_command,
        # f"{FORTIGATE}-create-{POLICY}": create_policy_command,
        f"{FORTIGATE}-get-{POLICY}": get_policy_command,
        # f"{FORTIGATE}-update-{POLICY}": update_policy_command,
        # f"{FORTIGATE}-move-{POLICY}": move_policy_command,
        f"{FORTIGATE}-delete-{POLICY}": delete_policy_command,
        # f"{FORTIGATE}-get-banned-ips": get_banned_ips_command,
    }

    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=verify_certificate,
            proxy=proxy,
        )
        client.login()

        results = None

        if command == "test-module":
            results = test_module(client)
        elif command in commands:
            results = commands[command](client, args)
        elif command in commands_deprecated:
            commands_deprecated[command](client, args)
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

        if results:
            return_results(results)

    except Exception as e:
        return_error(str(e))
    finally:
        client.logout()


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
