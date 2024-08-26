import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" Imports """
import copy
import functools
import http
import ipaddress
import json
import re
from typing import Any, Callable, NamedTuple

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

AUTHORIZATION_ERROR = "Authorization Error: invalid `Account username` or `Password`"

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

DEFAULT_VDOM = "root"
MIN_MASK = 0
MAX_MASK = 128

TCP_UDP_SCTP = "TCP/UDP/SCTP"
IP = "IP"
ICMP = "ICMP"
ICMP6 = f"{ICMP}6"


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
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        verify: bool = True,
        proxy: bool = False,
    ) -> None:
        """Initialize the Client class.

        Args:
            base_url (str): The base URL of the API.
            username (str | None, optional): The account username.
                Defaults to None.
            password (str | None, optional): The account password.
                Defaults to None.
            api_key (str | None, optional): An API key.
                Defaults to None.
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
            headers={"Authorization": f"Bearer {api_key}"} if api_key else None,
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
            message += f"\n{response.text}"
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

        # Extract the cookie and inject it into the headers, without the header only GET requests available.
        # The X-CSRFTOKEN header is required for POST/PUT/DELETE requests.
        # https://community.fortinet.com/t5/FortiGate/Technical-Tip-About-REST-API/ta-p/195425
        for cookie in response.cookies:
            if cookie.name.startswith("ccsrftoken") and cookie.value:
                csrftoken = cookie.value[1:-1]
                self._session.headers.update({"X-CSRFTOKEN": csrftoken})

        # Bypass the login disclaimer page after logging in to the system to finalize the authentication.
        login_disclaimer = "logindisclaimer"

        if login_disclaimer in response.text:
            self._http_request(
                method="POST",
                full_url=urljoin(self.server, login_disclaimer),
                data={"confirm": "1"},
                resp_type="response",
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

        The filter is used to decide what objects to include in the response
        according to a specific criteria when making API calls.

        Args:
            field (str | None): "name"
            value (str | None): "@value"

        Returns:
            str | None: name=@value
        """
        if field and value:
            return f"{to_kebab_case(field)}=@{value}"

        if field or value:
            raise DemistoException("'filter_field' and 'filter_vlaue' must be set together.")

        return None

    def _get_format(self, fields: list[str] | None) -> str | None:
        """Formats the fields to be returned in the API call.

        The format is used to select what fields are returned in the response when making API calls.

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
        vdom: str | None = DEFAULT_VDOM,
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
        vdom: str | None = DEFAULT_VDOM,
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
                    "macaddr": build_dicts_from_list(mac_addresses, "macaddr"),
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_address_ipv4(
        self,
        name: str,
        type_: str | None = None,
        vdom: str | None = DEFAULT_VDOM,
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
                    "macaddr": build_dicts_from_list(mac_addresses, "macaddr"),
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_address_ipv4(self, name: str, vdom: str = DEFAULT_VDOM) -> dict[str, Any]:
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
        vdom: str | None = DEFAULT_VDOM,
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
        vdom: str | None = DEFAULT_VDOM,
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
                    "macaddr": build_dicts_from_list(mac_addresses, "macaddr"),
                    "sdn": sdn_connector,
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_address_ipv6(
        self,
        name: str,
        type_: str | None = None,
        vdom: str | None = DEFAULT_VDOM,
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
                    "macaddr": build_dicts_from_list(mac_addresses, "macaddr"),
                    "sdn": sdn_connector,
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_address_ipv6(self, name: str, vdom: str = DEFAULT_VDOM) -> dict[str, Any]:
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
        vdom: str | None = DEFAULT_VDOM,
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
        vdom: str | None = DEFAULT_VDOM,
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
        vdom: str | None = DEFAULT_VDOM,
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

    def delete_firewall_address_ipv4_multicast(self, name: str, vdom: str = DEFAULT_VDOM) -> dict[str, Any]:
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
        vdom: str | None = DEFAULT_VDOM,
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
        vdom: str | None = DEFAULT_VDOM,
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
        vdom: str | None = DEFAULT_VDOM,
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

    def delete_firewall_address_ipv6_multicast(self, name: str, vdom: str = DEFAULT_VDOM) -> dict[str, Any]:
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
        vdom: str | None = DEFAULT_VDOM,
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

    def create_firewall_address_ipv4_group(
        self,
        name: str,
        vdom: str | None = DEFAULT_VDOM,
        type_: str | None = "default",
        comment: str | None = None,
        members: list[str] | None = None,
        excluded_members: list[str] | None = None,
        allow_routing: str | None = None,
    ) -> dict[str, Any]:
        """Create a IPv4 address group.

        Args:
            name (str): Name of the address group to create
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.
            type_ (str | None, optional): The type of the address group.
                Defaults to "default".
            comment (str | None, optional): A comment for the address group.
                Defaults to None.
            members (list[str] | None, optional): Members to include in the address group.
                Defaults to None.
            excluded_members (list[str] | None, optional): Members to exclude from the address group.
                Defaults to None.
            allow_routing (str | None, optional): Enable/disable use of this address in the static route configuration.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=self.ADDRESS_IPV4_GROUP_ENDPOINT,
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "type": type_,
                    "comment": comment,
                    "member": build_dicts_from_list(members),
                    "excluded-member": build_dicts_from_list(excluded_members),
                    "exclude": "enable" if excluded_members else "disable",
                    "allow-routing": allow_routing,
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_address_ipv4_group(
        self,
        name: str,
        vdom: str | None = DEFAULT_VDOM,
        type_: str | None = None,
        comment: str | None = None,
        members: list[str] | None = None,
        excluded_members: list[str] | None = None,
        exclude: str | None = None,
        allow_routing: str | None = None,
    ) -> dict[str, Any]:
        """Update a IPv4 address group.

        Args:
            name (str): Name of the address group to update.
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.
            type_ (str | None, optional): The type of the address group.
            comment (str | None, optional): A comment for the address group.
                Defaults to None.
            members (list[str] | None, optional): Members to include in the address group.
                Defaults to None.
            excluded_members (list[str] | None, optional): Members to exclude from the address group.
                Defaults to None.
            exclude (str | None, optional): Enable/disable use of excluded members.
                Defaults to None.
            allow_routing (str | None, optional): Enable/disable use of this address in the static route configuration.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.ADDRESS_IPV4_GROUP_ENDPOINT, name),
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "type": type_,
                    "comment": comment,
                    "member": build_dicts_from_list(members),
                    "excluded-member": build_dicts_from_list(excluded_members),
                    "exclude": exclude,
                    "allow-routing": allow_routing,
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_address_ipv4_group(self, name: str, vdom: str = DEFAULT_VDOM) -> dict[str, Any]:
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
        vdom: str | None = DEFAULT_VDOM,
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

    def create_firewall_address_ipv6_group(
        self,
        name: str,
        vdom: str | None = DEFAULT_VDOM,
        comment: str | None = None,
        members: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a IPv6 address group.

        Args:
            name (str): Name of the address group to create
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.
            comment (str | None, optional): A comment for the address group.
                Defaults to None.
            members (list[str] | None, optional): Members to include in the address group.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=self.ADDRESS_IPV6_GROUP_ENDPOINT,
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "member": build_dicts_from_list(members),
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_address_ipv6_group(
        self,
        name: str,
        vdom: str | None = DEFAULT_VDOM,
        comment: str | None = None,
        members: list[str] | None = None,
    ) -> dict[str, Any]:
        """Update a IPv6 address group.

        Args:
            name (str): Name of the address group to update
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.
            comment (str | None, optional): A comment for the address group.
                Defaults to None.
            members (list[str] | None, optional): Members to include in the address group.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.ADDRESS_IPV6_GROUP_ENDPOINT, name),
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "member": build_dicts_from_list(members),
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_address_ipv6_group(self, name: str, vdom: str = DEFAULT_VDOM) -> dict[str, Any]:
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
        vdom: str | None = DEFAULT_VDOM,
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

    def create_firewall_service(
        self,
        name: str,
        vdom: str | None = DEFAULT_VDOM,
        comment: str | None = None,
        category: str | None = None,
        protocol_type: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        fqdn: str | None = None,
        tcp_port_ranges: list[str] | None = None,
        udp_port_ranges: list[str] | None = None,
        sctp_port_ranges: list[str] | None = None,
        icmp_type: int | None = None,
        icmp_code: int | None = None,
        ip_protocol: int | None = None,
    ) -> dict[str, Any]:
        """Create a service.

        Args:
            name (str): Name of the service to create
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.
            comment (str | None, optional): A comment for the service.
                Defaults to None.
            category (str | None, optional): Service category.
                Defaults to None.
            protocol_type (str | None, optional): The protocol type of the service.
                Defaults to None.
            start_ip (str | None, optional): The start of the IP range.
                Defaults to None.
            end_ip (str | None, optional): The end of the IP range.
                Defaults to None.
            fqdn (str | None, optional): Fully Qualified Domain Name address.
                Defaults to None.
            tcp_port_range (list[str] | None, optional): A list of TCP port ranges.
                Defaults to None.
            udp_port_range (list[str] | None, optional): A list of UDP port ranges.
                Defaults to None.
            sctp_port_range (list[str] | None, optional): A list of SCTP port ranges.
                Defaults to None.
            icmp_type (int | None, optional): The type number of the ICMP.
                Defaults to None.
            icmp_code (int | None, optional): The code number of the ICMP.
                Defaults to None.
            ip_protocol (int | None, optional): The protocol number of the IP.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=self.SERVICE_ENDPOINT,
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "category": {"q_origin_key": category},
                    "protocol": protocol_type,
                    "iprange": f"{start_ip}-{end_ip}" if start_ip and end_ip else start_ip,
                    "fqdn": fqdn,
                    "tcp-portrange": tcp_port_ranges and " ".join(tcp_port_ranges),
                    "udp-portrange": udp_port_ranges and " ".join(udp_port_ranges),
                    "sctp-portrange": sctp_port_ranges and " ".join(sctp_port_ranges),
                    "icmptype": icmp_type,
                    "icmpcode": icmp_code,
                    "protocol-number": ip_protocol,
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_service(
        self,
        name: str,
        vdom: str | None = DEFAULT_VDOM,
        comment: str | None = None,
        category: str | None = None,
        protocol_type: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        fqdn: str | None = None,
        tcp_port_ranges: list[str] | None = None,
        udp_port_ranges: list[str] | None = None,
        sctp_port_ranges: list[str] | None = None,
        icmp_type: int | None = None,
        icmp_code: int | None = None,
        ip_protocol: int | None = None,
    ) -> dict[str, Any]:
        """Update a service.

        Args:
            name (str): Name of the service to update
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.
            comment (str | None, optional): A comment for the service.
                Defaults to None.
            category (str | None, optional): Service category.
                Defaults to None.
            protocol_type (str | None, optional): The protocol type of the service.
                Defaults to None.
            start_ip (str | None, optional): The start of the IP range.
                Defaults to None.
            end_ip (str | None, optional): The end of the IP range.
                Defaults to None.
            fqdn (str | None, optional): Fully Qualified Domain Name address.
                Defaults to None.
            tcp_port_range (list[str] | None, optional): A list of TCP port ranges.
                Defaults to None.
            udp_port_range (list[str] | None, optional): A list of UDP port ranges.
                Defaults to None.
            sctp_port_range (list[str] | None, optional): A list of SCTP port ranges.
                Defaults to None.
            icmp_type (int | None, optional): The type number of the ICMP.
                Defaults to None.
            icmp_code (int | None, optional): The code number of the ICMP.
                Defaults to None.
            ip_protocol (int | None, optional): The protocol number of the IP.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.SERVICE_ENDPOINT, name),
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "category": {"q_origin_key": category},
                    "protocol": protocol_type,
                    "iprange": f"{start_ip}-{end_ip}" if start_ip and end_ip else start_ip,
                    "fqdn": fqdn,
                    "tcp-portrange": tcp_port_ranges and " ".join(tcp_port_ranges),
                    "udp-portrange": udp_port_ranges and " ".join(udp_port_ranges),
                    "sctp-portrange": sctp_port_ranges and " ".join(sctp_port_ranges),
                    "icmptype": icmp_type,
                    "icmpcode": icmp_code,
                    "protocol-number": ip_protocol,
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_service(self, name: str, vdom: str = DEFAULT_VDOM) -> dict[str, Any]:
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
        vdom: str | None = DEFAULT_VDOM,
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

    def create_firewall_service_group(
        self,
        name: str,
        members: list[str],
        vdom: str | None = DEFAULT_VDOM,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Create a service group.

        Args:
            name (str): Name of the service group to create
            members (list[str]): A list of members for the service group.
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.
            comment (str | None, optional): A comment for the service.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=self.SERVICE_GROUP_ENDPOINT,
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "member": build_dicts_from_list(members),
                }
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_service_group(
        self,
        name: str,
        members: list[str],
        vdom: str | None = DEFAULT_VDOM,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Create a service group.

        Args:
            name (str): Name of the service group to create
            members (list[str]): A list of members for the service group.
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.
            comment (str | None, optional): A comment for the service.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.SERVICE_GROUP_ENDPOINT, name),
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comment": comment,
                    "member": build_dicts_from_list(members),
                }
            ),
            error_handler=Client._error_handler,
        )

    def delete_firewall_service_group(self, name: str, vdom: str = DEFAULT_VDOM) -> dict[str, Any]:
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
        vdom: str | None = DEFAULT_VDOM,
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

    def create_firewall_policy(
        self,
        name: str,
        source_interfaces: list[str],
        destination_interfaces: list[str],
        action: str,
        services: list[str],
        vdom: str | None = DEFAULT_VDOM,
        comment: str | None = None,
        source_addresses: list[str] | None = None,
        destination_addresses: list[str] | None = None,
        source_addresses6: list[str] | None = None,
        destination_addresses6: list[str] | None = None,
        negate_source_address: str | None = None,
        negate_destination_address: str | None = None,
        negate_service: str | None = None,
        status: str = "enable",
        log_traffic: str = "enable",
        schedule: str = "always",
        nat: str = "enable",
        is_address_v4: bool = True,
    ) -> dict[str, Any]:
        """Create a policy.

        Args:
            name (str): Name of the policy to create
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.
            comment (str | None, optional): A comment for the service.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=self.POLICY_ENDPOINT,
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "name": name,
                    "comments": comment,
                    "srcintf": build_dicts_from_list(source_interfaces),
                    "dstintf": build_dicts_from_list(destination_interfaces),
                    "service": build_dicts_from_list(services),
                    "service-negate": negate_service,
                    "action": action,
                    "status": status,
                    "logtraffic": log_traffic,
                    "schedule": schedule,
                    "nat": nat,
                }
                | (
                    {
                        "srcaddr": build_dicts_from_list(source_addresses),
                        "dstaddr": build_dicts_from_list(destination_addresses),
                        "srcaddr-negate": negate_source_address,
                        "dstaddr-negate": negate_destination_address,
                    }
                    if is_address_v4
                    else {
                        "srcaddr6": build_dicts_from_list(source_addresses6),
                        "dstaddr6": build_dicts_from_list(destination_addresses6),
                        "srcaddr6-negate": negate_source_address,
                        "dstaddr6-negate": negate_destination_address,
                    }
                )
            ),
            error_handler=Client._error_handler,
        )

    def update_firewall_policy(
        self,
        id_: str,
        field: str,
        value: Any,
        vdom: str | None = DEFAULT_VDOM,
    ) -> dict[str, Any]:
        """Update a policy.

        Args:
            id_ (str): The ID of the policy to update.
            field (str): The field to update.
            value (Any): The value to update.
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.

        Returns:
            dict[str, Any]: The API response.
        """
        policy_id = int(id_)

        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.POLICY_ENDPOINT, id_),
            params={"vdom": vdom},
            json_data={
                "policyid": policy_id,
                "q_origin_key": policy_id,
                field: value,
            },
            error_handler=Client._error_handler,
        )

    def move_firewall_policy(
        self,
        id_: str,
        position: str,
        neighbor: str,
        vdom: str | None = DEFAULT_VDOM,
    ) -> dict[str, Any]:
        """Move a policy.

        Args:
            id_ (str): The ID of the policy to move.
            position (str): The position to move the policy to.
            neighbor (str): The neighbor to move the policy to.
                This can be either "before" or "after".
            vdom (str | None, optional): The VDOM to use.
                Defaults to DEFAULT_VDOM.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="PUT",
            url_suffix=urljoin(self.POLICY_ENDPOINT, id_),
            params={
                "vdom": vdom,
                "action": "move",
                position: neighbor,
            },
            error_handler=Client._error_handler,
        )

    def delete_firewall_policy(self, id_: str, vdom: str = DEFAULT_VDOM) -> dict[str, Any]:
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
        vdom: str | None = DEFAULT_VDOM,
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

    def ban_ip(
        self,
        ip_addresses: list[str],
        expiry: int | None = 0,
        vdom: str | None = DEFAULT_VDOM,
    ) -> dict[str, Any]:
        """Ban IP addresses.

        Args:
            ip_addresses (list[str]): list of IPs to ban. Both IPv4 and IPv6 addresses are supported.
            expiry (int | None, optional): Time until the ban expires in seconds. `0` for indefinite ban.
                Defaults to 0.
            source (str | None, optional): Specifies the origin of the IP ban.
                Defaults to None.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=urljoin(self.BANNED_IP_ENDPOINT, "add_users"),
            params={"vdom": vdom},
            json_data=remove_empty_elements(
                {
                    "ip_addresses": ip_addresses,
                    "expiry": expiry,
                }
            ),
            error_handler=Client._error_handler,
        )

    def unban_ip(self, ip_addresses: list[str], vdom: str | None = DEFAULT_VDOM) -> dict[str, Any]:
        """Unban IP addresses.

        Args:
            ip_addresses (list[str]): list of IPs to unban. Both IPv4 and IPv6 addresses are supported.
            vdom (str, optional): The VDOM to use.
                Defaults to VDOM_DEFAULT.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            method="POST",
            url_suffix=urljoin(self.BANNED_IP_ENDPOINT, "clear_users"),
            params={"vdom": vdom},
            json_data={"ip_addresses": ip_addresses},
            error_handler=Client._error_handler,
        )


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
    new_dict: dict = {}

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
            # If last key add value to dict, else create nested dict
            current_dict[new_key] = value if new_key == mapping.new_keys[-1] else current_dict.get(new_key, {})
            current_dict = current_dict[new_key]

    return new_dict


def extract_key_from_items(key: str, items: list[dict[str, Any]] | None = None) -> list:
    """Extracts a list of values from a list of dictionaries.

    Args:
        key (str): The key to extract.
        items (list[dict[str, Any]] | None, optional): The list of dictionaries to extract from.
            Defaults to None.

    Returns:
        list[str]: The extracted values.
    """
    return [item.get(key) for item in items or []]


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
            "No group of arguments was fully set. "
            f"Please provide arguments from one of the following groups: {list(group_to_arg_names)}"
        )

    gui_to_api = ADDRESS6_GUI_TO_API_TYPE if include_ipv6 else ADDRESS_GUI_TO_API_TYPE

    return gui_to_api[fully_set_groups[0]]


def get_service_type(args: dict[str, Any]) -> str:
    """Identifies the protocol type of argument based on the arguments.

    Args:
        args (dict[str, Any]): The arguments to check.

    Returns:
        str: The type of argument group provided.
            Possible values are: "tcp", "udp", "sctp", "ip", "icmp", and "icmp6".

    Raises:
        DemistoException:
            - If arguments from more than one group are provided.
            - If not all arguments from a single group are provided.
            - If no group of arguments is fully set.
    """
    protocol_type_to_arg_names = {
        TCP_UDP_SCTP: ["start_ip", "end_ip", "fqdn", "tcpRange", "udpRange", "sctpRange"],
        IP: ["ip_protocol"],
        f"{ICMP}/{ICMP6}": ["icmp_version", "icmp_type", "icmp_code"],
    }

    # Count the number of not None arguments for each protocol type
    protocol_type_to_arg_counts = {
        protocol_type: sum(1 for arg in arg_names if args.get(arg) is not None)
        for protocol_type, arg_names in protocol_type_to_arg_names.items()
    }

    # Identify fully set, partially set, and mixed groups
    fully_set_protocol_types = []
    partially_set_protocol_types = []

    for protocol_type, count in protocol_type_to_arg_counts.items():
        total_args = len(protocol_type_to_arg_names[protocol_type])

        if count == total_args:
            fully_set_protocol_types.append(protocol_type)
        elif 0 < count < total_args:
            partially_set_protocol_types.append(protocol_type)

    mixed_groups = fully_set_protocol_types + partially_set_protocol_types

    # If arguments are from more than one group, raise an error
    if len(mixed_groups) > 1:
        mixed_groups_str = ", ".join(mixed_groups)
        raise DemistoException(
            f"Arguments must only come from one protocol type. Mixed protocol types: {mixed_groups_str}"
        )

    if args.get("ip_protocol"):
        return IP

    if icmp_version := args.get("icmp_version"):
        return icmp_version.upper()

    if any(
        (
            args.get("tcpRange"),
            args.get("udpRange"),
            args.get("sctpRange"),
        )
    ):
        return TCP_UDP_SCTP

    # If no protocol type is fully set, raise an error
    if partially_set_protocol_types:
        partially_set = partially_set_protocol_types[0]

        if partially_set == TCP_UDP_SCTP:
            raise DemistoException(
                f"Missing arguments for the protocol type {partially_set}, "
                "please provide at least one of: tcpRange, udpRange, sctpRange."
            )
        elif partially_set == f"{ICMP}/{ICMP6}":
            raise DemistoException(
                f"Missing arguments for the protocol type {partially_set}, please provide: icmp_version"
            )

    raise DemistoException(
        "No protocol type arguments were fully set. "
        f"Please provide arguments from one of the following protocol types: {list(protocol_type_to_arg_names)}"
    )


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
            value
            for key in [
                "webfilter-profile",
                "ssl-ssh-profile",
                "dnsfilter-profile",
                "profile-protocol-options",
                "profile-type",
                "av-profile",
            ]
            if (value := policy.get(key))
        ]
    }


@logger
def create_addr_string(list_of_addr_data_dicts: list) -> str:
    """Builds the address string from the given list of address data dictionaries.

    The address string is a list of address names separated by newlines.
    """
    addr_string = ""
    for addr_index in range(0, len(list_of_addr_data_dicts)):
        cur_addr_data = list_of_addr_data_dicts[addr_index]
        cur_addr_name = cur_addr_data.get("name")
        if addr_index == len(list_of_addr_data_dicts) - 1:
            addr_string += f"{cur_addr_name}"
        else:
            addr_string += f"{cur_addr_name}\n"
    return addr_string


def validate_mac_addresses(mac_addresses: list[str] | None = None) -> None:
    """Validates the given list of MAC addresses.

    Args:
        mac_addresses (list[str] | None, optional): The list of MAC addresses to validate.
            Defaults to None.

    Raises:
        DemistoException: If any of the MAC addresses is invalid.
    """
    for mac_address_range in mac_addresses or []:
        for mac_address in mac_address_range.split("-"):
            if not is_mac_address(mac_address):
                raise DemistoException(f"Invalid MAC address: {mac_address}")


def validate_optional_ipv4_addresses(*ipv4_addresses: str | None) -> None:
    """Validates the given list of IPv4 addresses.

    Args:
        *ipv4_addresses (str | None): The list of IPv4 addresses to validate.
            Defaults to None.

    Raises:
        DemistoException: If any of the IPv4 addresses is invalid.
    """
    for ipv4_address in ipv4_addresses or []:
        if ipv4_address and not is_ip_valid(ipv4_address):
            raise DemistoException(f"Invalid IPv4 address: {ipv4_address}")


def validate_optional_ipv6_networks(*ipv6_networks: str | None) -> None:
    """Validates the given list of IPv6 networks.

    Args:
        *ipv6_networks (str | None): The list of IPv6 networks to validate.
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


def build_address_outputs(args: dict[str, Any]) -> dict[str, Any]:
    """Builds a map of outputs from input values.

    Args:
        args (dict[str, Any]): The input arguments.

    Returns:
        dict[str, Any]: The CommandResults outputs.
    """
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


def build_service_outputs(args: dict[str, Any]) -> dict[str, Any]:
    """Builds a map of outputs from input values.

    Args:
        args (dict[str, Any]): The input arguments.

    Returns:
        dict[str, Any]: The CommandResults outputs.
    """
    return remove_empty_elements(
        {
            "Name": args.get("serviceName", "") or args.get("name", ""),
            "Ports": {
                "TCP": args.get("tcpRange", ""),
                "UDP": args.get("udpRange", ""),
                "SCTP": args.get("sctpRange", ""),
            },
            "FQDN": args.get("fqdn"),
            "StartIP": args.get("start_ip"),
            "EndIP": args.get("end_ip"),
            "ICMPType": args.get("icmp_type"),
            "ICMPCode": args.get("icmp_code"),
            "ProtocolNumber": args.get("ip_protocol"),
        }
    )


def to_kebab_case(value: str) -> str:
    """Converts a string to kebab-case.

    Args:
        value (str): The input string.

    Returns:
        str: The converted string in kebab-case.
    """
    # Normalize any case style of string to words separated by white spaces.
    value = value.replace("-", " ").replace("_", " ")  # Replace hyphens and underscores with spaces
    value = CAMEL_CASE_PATTERN.sub(r" \1", value)  # Separate camelCase
    value = UPPER_FOLLOWED_BY_MIXED_PATTERN.sub(r"\1 ", value)  # Separate consecutive uppercase followed by lowercase
    value = value.lower()

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
    table = []
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
        "Comments": "Comment",
        "Routable": "AllowRouting",
    }

    for item in items:
        row = {header: item.get(key) for header, key in header_to_key.items()}
        row["Details"] = (
            f"{start_ip}-{end_ip}"
            if (start_ip := item.get("StartIP")) and (end_ip := item.get("EndIP"))
            else extract_first_match(item, keys)
        )

        table.append(row)

    return table


def build_address_group_table(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Builds the address group table from the given items.

    Args:
        items (list[dict[str, Any]]): The items to build the address group table from.

    Returns:
        list[dict[str, Any]]: The address group table.
    """
    table = []
    header_to_key = {
        "Name": "Name",
        "Type": "Type",
        "Comments": "Comment",
        "Exclude Members": "ExcludeMember",
        "Routable": "AllowRouting",
    }

    for item in items:
        row = {header: item.get(key) for header, key in header_to_key.items()}
        row["Details"] = dict_safe_get(item, ["Member", "Name"])

        table.append(row)

    return table


def build_service_table(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Builds the service table from the given items.

    Args:
        items (list[dict[str, Any]]): The items to build the service table from.

    Returns:
        list[dict[str, Any]]: The service table.
    """
    table = []
    header_to_key = {
        "Name": "Name",
        "Category": "Category",
        "Protocol": "Protocol",
    }

    protocol_to_handler = {
        TCP_UDP_SCTP: handle_tcp_udp_sctp,
        IP: handle_ip,
        ICMP: handle_icmp_icmp6,
        ICMP6: handle_icmp_icmp6,
    }

    for item in items:
        row = {header: item.get(key) for header, key in header_to_key.items()}
        handler = protocol_to_handler.get(item.get("Protocol", ""))
        row["Details"] = handler and handler(item)
        row["IP/FQDN"] = item.get("IPRange") or item.get("FQDN")

        table.append(row)

    return table


def handle_tcp_udp_sctp(item: dict[str, Any]) -> str:
    """Handles the TCP/UDP/SCTP protocol for  `build_service_table`.

    Args:
        item (dict[str, Any]): The item to handle.

    Returns:
        str: The handled item.
    """
    details = []
    ports = item.get("Ports", {})

    for protocol in TCP_UDP_SCTP.split("/"):
        if port_ranges := ports.get(protocol):
            for port_range in port_ranges.split():
                details.append(f"{protocol}/{port_range}")

    return " ".join(details)


def handle_ip(item: dict[str, Any]) -> str:
    """Handles the IP protocol for `build_service_table`.

    Args:
        item (dict[str, Any]): The item to handle.

    Returns:
        str: The handled item.
    """
    protocol_number = item.get("ProtocolNumber", 0)
    return f"IP/{protocol_number}" if protocol_number else "Any"


def handle_icmp_icmp6(item: dict[str, Any]) -> str:
    """Handles the ICMP/ICMP6 protocol for `build_service_table`.

    Args:
        item (dict[str, Any]): The item to handle.

    Returns:
        str: The handled item.
    """
    protocol_type = item.get("Protocol")
    icmp_type = item.get("ICMPType")
    icmp_code = item.get("ICMPCode")

    if icmp_type and icmp_code:
        return f"{protocol_type}/{icmp_code}"

    if icmp_type:
        return f"{protocol_type}/ANY"

    return "ANY"


def build_service_group_table(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Builds the service group table from the given items.

    Args:
        items (list[dict[str, Any]]): The items to build the service group table from.

    Returns:
        list[dict[str, Any]]: The service group table.
    """
    table = []
    header_to_key = {
        "Name": "Name",
        "Comments": "Comment",
    }

    for item in items:
        row = {header: item.get(key) for header, key in header_to_key.items()}
        row["Members"] = dict_safe_get(item, ["Member", "Name"])

        table.append(row)

    return table


def build_policy_table(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Builds the policy table from the given items.

    Args:
        items (list[dict[str, Any]]): The items to build the policy table from.

    Returns:
        list[dict[str, Any]]: The policy table.
    """
    table = []
    header_to_key = {
        "ID": "ID",
        "Name": "Name",
        "From": "SourceInterface",
        "To": "DestinationInterface",
        "Schedule": "Schedule",
        "Service": "Service",
        "Action": "Action",
        "NAT": "NAT",
        "Security Profiles": "Security",
        "Log": "Log",
    }

    for item in items:
        row = {header: item.get(key) for header, key in header_to_key.items()}
        row["Source"] = item.get("Source") or item.get("Source6")
        row["Destination"] = item.get("Destination") or item.get("Destination6")

        table.append(row)

    return table


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
        api_to_gui (dict[str, Any]): The dictionary mapping the API types to the GUI types.

    Raises:
        DemistoException: If the type of the address is not compatible with the requested type.
    """
    response = get_request(name=name, vdom=vdom, format_fields=["type"])
    result: dict[str, Any] = next(iter(response.get("results", [])), {})
    expected_type = result.get("type", "")

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


def build_dicts_from_list(items: list | None, key: str = "name") -> list[dict[str, Any]]:
    """Builds a list of dictionaries from a list of objects.

    Args:
        items (list | None): The list of objects to build dictionaries from.
        key (str, optional): The key to use for the dictionary.
            Defaults to "name".

    Returns:
        list[dict[str, Any]]: The list of dictionaries.
    """
    return [{key: item} for item in items or []]


@logger
def prettify_date(date: int | str) -> str:
    """
    This function receives a string representing a date, for example 2018-07-28T10:47:55.000Z.
    It returns the same date in a readable format - for example, 2018-07-28 10:47:55.
    """
    creation_in_ms = 1000 * int(date)
    date_string = timestamp_to_datestring(creation_in_ms)
    date_string = date_string[:-5]  # remove the .000z at the end
    return date_string.replace("T", " ")


def extract_first_result(response: dict[str, Any]) -> dict[str, Any]:
    """Extracts the first result from the given response.

    Args:
        response (dict[str, Any]): The response to extract the result from.

    Returns:
        dict[str, Any]: The extracted result.
    """
    return next(iter(response.get("results", [])), {})


def handle_group_items_by_action(input_items: list[str], action: str | None, items: list[str]) -> list[str]:
    """Handle adding or removing items from a group.

    Args:
        input_items (list[str]): The items to add or remove from the group.
        action (str | None): The action to perform on the group, add or remove.
        items (list[str]): The current items in the group.

    Returns:
        list[str]: The updated list of items in the group.
    """
    if action == "add":
        return list(set(items + input_items))

    if action == "remove":
        return [item for item in items if item not in input_items]

    return items


def handle_action_for_port_ranges(
    obj: dict[str, Any],
    action: str,
    tcp_port_ranges: list[str],
    udp_port_ranges: list[str],
    sctp_port_ranges: list[str],
) -> dict[str, Any]:
    """Handle adding or removing the given port ranges in obj.

    Args:
        obj (dict[str, Any]): Object to add or remove port ranges.
        action (str): add or remove.
        tcp_port_ranges (list[str]): TCP port ranges to add or remove.
        udp_port_ranges (list[str]): UDP port ranges to add or remove.
        sctp_port_ranges (list[str]): SCTP port ranges to add or remove.

    Returns:
        dict[str, Any]: Handled port ranges according to the given action.
    """
    port_ranges = {
        "tcp_port_ranges": tcp_port_ranges,
        "udp_port_ranges": udp_port_ranges,
        "sctp_port_ranges": sctp_port_ranges,
    }

    for (key, value), obj_key in zip(
        port_ranges.items(),
        ("tcp-portrange", "udp-portrange", "sctp-portrange"),
    ):
        api_port_range = obj.get(obj_key, "").split()
        port_ranges[key] = handle_group_items_by_action(value, action, api_port_range)

    return port_ranges


def build_policy_outputs(raw_response: list | dict, name: str | None) -> list:
    """Given a raw response build context outputs for policy.

    Args:
        raw_response (list | dict): The response from policy endpoint.
        name (str | None): A name of a specific policy to extract outputs for.

    Returns:
        list: The context outputs.
    """
    outputs: list = []
    # Handle VDOM == *
    responses = raw_response if isinstance(raw_response, list) else [raw_response]

    for response in responses:
        response_results = response.get("results", [])
        response_vdom = response.get("vdom")

        for result in response_results:
            if name and name != result.get("name"):
                continue

            output = map_keys(result, POLICY_MAPPINGS) | build_security(result) | {"VDOM": response_vdom}
            outputs.append(output)

    return remove_empty_elements(outputs)


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

POLICY_MAPPINGS = [
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
    Mapping(["schedule"], ["Schedule"]),
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


""" Command Handlers """


@logger
def handle_list_response(
    raw_response: list[dict[str, Any]] | dict[str, Any],
    mappings: list[Mapping],
    title: str,
    outputs_prefix: str,
    headers: list[str],
    format_fields: list[str] | None = None,
    custom_table_builder: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = None,
    outputs_key_field: str | None = None,
) -> CommandResults:
    """Handles the response from the API of a list command.

    Args:
        raw_response (list[dict[str, Any]] | dict[str, Any]): The raw response from the API.
        mappings (list[Mapping]): Mappings for adjust the response specifying:
            - old_keys (list[str]): required.
            - new_keys (list[str]): required.
            - default_value (Any): defaults to None.
            - value_changer (Optional[Callable]): defaults to None.
        title (str): The title of the table to display.
        outputs_prefix (str): The prefix to use for the outputs.
        headers (list[str]): The headers of the table to display.
        format_fields (list[str] | None, optional): Fields to format the readable output.
            Defaults to None.
        custom_table_builder (Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None): A custom table builder
            to use for the outputs.
            Defaults to None.
        outputs_key_field (str | None, optional): The key field to use for the outputs.
            Defaults to None.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    # Handle VDOM == *
    responses = raw_response if isinstance(raw_response, list) else [raw_response]
    outputs = []

    for response in responses:
        response_results = response.get("results", [])
        response_vdom = response.get("vdom")
        outputs += [map_keys(result, mappings) | {"VDOM": response_vdom} for result in response_results]

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
        if exc.res is not None:
            if exc.res.status_code == http.HTTPStatus.FORBIDDEN:
                return AUTHORIZATION_ERROR

            if exc.res.status_code == http.HTTPStatus.UNAUTHORIZED:
                return "Authorization Error: invalid `API Key`"

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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_firewall_address_ipv4s(
        name=args.get("name", ""),
        vdom=args.get("vdom", DEFAULT_VDOM),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
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
            "Comments",
            "Routable",
        ],
        format_fields=format_fields,
        custom_table_builder=build_address_table,
        outputs_prefix=ADDRESS_CONTEXT,
        outputs_key_field="Name",
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

    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
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

    validate_optional_ipv4_addresses(address, mask, start_ip, end_ip)
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
    readable_output = f"## The firewall address '{name}' was successfully created."

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
    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
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
    type_ = None

    if any(
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
        validate_address_type(
            get_request=client.list_firewall_address_ipv4s,
            name=name,
            input_type=type_,
            api_to_gui=API_TYPE_TO_ADDRESS_GUI,
            vdom=vdom,
        )

    validate_optional_ipv4_addresses(address, mask, start_ip, end_ip)
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
    readable_output = f"## The firewall address '{name}' was successfully updated."

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
    name = args.get("name", "")

    raw_response = client.delete_firewall_address_ipv4(
        name=name,
        vdom=args.get("vdom", DEFAULT_VDOM),
    )
    output = {"Name": name, "Deleted": True}
    readable_output = f"## The firewall address '{name}' was successfully deleted."

    return CommandResults(
        outputs_prefix=ADDRESS_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_response,
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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_firewall_address_ipv6s(
        name=args.get("name", ""),
        vdom=args.get("vdom", DEFAULT_VDOM),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
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
            "Comments",
        ],
        format_fields=format_fields,
        custom_table_builder=build_address_table,
        outputs_prefix=ADDRESS6_CONTEXT,
        outputs_key_field="Name",
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

    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
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
    validate_optional_ipv6_networks(subnet, start_ip, end_ip)
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
    readable_output = f"## The firewall address '{name}' was successfully created."

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
    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("comment")
    address = args.get("address")
    mask = arg_to_number(args.get("mask"))
    start_ip = args.get("start_ip")
    end_ip = args.get("end_ip")
    fqdn = args.get("fqdn")
    country = country.upper() if (country := args.get("country")) else None
    mac_addresses = argToList(args.get("mac_addresses"))
    sdn_connector = args.get("sdn_connector")
    type_ = None

    if any(
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
        validate_address_type(
            get_request=client.list_firewall_address_ipv6s,
            name=name,
            input_type=type_,
            api_to_gui=API_TYPE_TO_ADDRESS6_GUI,
            vdom=vdom,
        )

    validate_mask(mask)
    subnet = f"{address}/{mask}" if address and mask is not None else None
    validate_optional_ipv6_networks(subnet, start_ip, end_ip)
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
    readable_output = f"## The firewall address '{name}' was successfully updated."

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
    name = args.get("name", "")

    raw_response = client.delete_firewall_address_ipv6(
        name=name,
        vdom=args.get("vdom", DEFAULT_VDOM),
    )
    output = {"Name": name, "Deleted": True}
    readable_output = f"## The firewall address '{name}' was successfully deleted."

    return CommandResults(
        outputs_prefix=ADDRESS6_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_response,
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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_firewall_address_ipv4_multicasts(
        name=args.get("name", ""),
        vdom=args.get("vdom", DEFAULT_VDOM),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
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
            "Comments",
            "Routable",
        ],
        format_fields=format_fields,
        custom_table_builder=build_address_table,
        outputs_prefix=ADDRESS_MULTICAST_CONTEXT,
        outputs_key_field="Name",
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
    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("comment")
    associated_interface = args.get("associated_interface")
    type_ = ADDRESS_MULTICAST_GUI_TO_API_TYPE.get(args.get("type", ""), "")
    first_ip = args.get("first_ip")
    final_ip = args.get("final_ip")

    validate_optional_ipv4_addresses(first_ip, final_ip)
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
    readable_output = f"## The firewall address multicast IPv4 '{name}' was successfully created."

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
    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("comment")
    associated_interface = args.get("associated_interface")
    type_ = ADDRESS_MULTICAST_GUI_TO_API_TYPE.get(args.get("type", ""), "")
    first_ip = args.get("first_ip")
    final_ip = args.get("final_ip")

    subnet = None
    multicast_fields = [type_, first_ip, final_ip]

    if all(multicast_fields):
        validate_address_type(
            get_request=client.list_firewall_address_ipv4_multicasts,
            name=name,
            input_type=type_,
            api_to_gui=reverse_dict(ADDRESS_MULTICAST_GUI_TO_API_TYPE),
            vdom=vdom,
        )

        if type_ == "broadcastmask":
            subnet = f"{first_ip} {final_ip}"
    elif any(multicast_fields):
        raise DemistoException("All multicast fields (`type`, `first_ip`, `final_ip`) must be provided to update any.")

    validate_optional_ipv4_addresses(first_ip, final_ip)

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
    readable_output = f"## The firewall address multicast IPv4 '{name}' was successfully updated."

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
    name = args.get("name", "")

    raw_response = client.delete_firewall_address_ipv4_multicast(
        name=name,
        vdom=args.get("vdom", DEFAULT_VDOM),
    )
    output = {"Name": name, "Deleted": True}
    readable_output = f"## The firewall address multicast IPv4 '{name}' was successfully deleted."

    return CommandResults(
        outputs_prefix=ADDRESS_MULTICAST_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_response,
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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_firewall_address_ipv6_multicasts(
        name=args.get("name", ""),
        vdom=args.get("vdom", DEFAULT_VDOM),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
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
            "Comments",
        ],
        format_fields=format_fields,
        custom_table_builder=build_address_table,
        outputs_prefix=ADDRESS6_MULTICAST_CONTEXT,
        outputs_key_field="Name",
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
    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("comment")
    address = args.get("address")
    mask = arg_to_number(args.get("mask"))

    validate_mask(mask)
    subnet = f"{address}/{mask}"
    validate_optional_ipv6_networks(subnet)

    response = client.create_firewall_address_ipv6_multicast(
        name=name,
        vdom=vdom,
        comment=comment,
        subnet=subnet,
    )
    output = build_address_outputs(args)
    readable_output = f"## The firewall address multicast IPv6 '{name}' was successfully created."

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
    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("comment")
    address = args.get("address")
    mask = arg_to_number(args.get("mask"))

    subnet = None
    address_provided = bool(address)
    mask_provided = mask is not None

    if address_provided and mask_provided:
        validate_mask(mask)
        subnet = f"{address}/{mask}"
        validate_optional_ipv6_networks(subnet)
    elif address_provided != mask_provided:
        raise DemistoException("Either both or none of `address` and `mask` must be provided.")

    response = client.update_firewall_address_ipv6_multicast(
        name=name,
        vdom=vdom,
        comment=comment,
        subnet=subnet,
    )
    output = build_address_outputs(args)
    readable_output = f"## The firewall address multicast IPv6 '{name}' was successfully updated."

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
    name = args.get("name", "")

    raw_response = client.delete_firewall_address_ipv6_multicast(
        name=name,
        vdom=args.get("vdom", DEFAULT_VDOM),
    )
    output = {"Name": name, "Deleted": True}
    readable_output = f"## The firewall address multicast IPv6 '{name}' was successfully deleted."

    return CommandResults(
        outputs_prefix=ADDRESS6_MULTICAST_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_response,
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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_firewall_address_ipv4_groups(
        name=args.get("groupName", ""),
        vdom=args.get("vdom", DEFAULT_VDOM),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
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
            "Details",
            "Type",
            "Comments",
            "Exclude Members",
            "Routable",
        ],
        format_fields=format_fields,
        custom_table_builder=build_address_group_table,
        outputs_prefix=ADDRESS_GROUP_CONTEXT,
        outputs_key_field="Name",
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
    vdom = args.get("vdom", DEFAULT_VDOM)
    name = args.get("groupName", "")
    type_ = args.get("type", "group")
    comment = args.get("comment")
    excluded_members = argToList(args.get("excluded_addresses"))
    allow_routing = args.get("allow_routing")
    # Preserve deprecated command outputs.
    address = args.get("address")
    members = argToList(address)

    response = client.create_firewall_address_ipv4_group(
        vdom=vdom,
        name=name,
        type_="default" if type_ == "group" else type_,
        comment=comment,
        members=members,
        excluded_members=excluded_members,
        allow_routing=allow_routing,
    )
    output = {
        "Name": name,
        "Address": address,
    }
    readable_output = f"## The firewall address IPv4 group '{name}' was successfully created."

    return CommandResults(
        outputs_prefix=ADDRESS_GROUP_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def update_firewall_address_ipv4_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall IPv4 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If `address` or `excluded_addresses` were not set with `action`.


    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    vdom = args.get("vdom", DEFAULT_VDOM)
    name = args.get("groupName", "")
    comment = args.get("comment")
    input_members = argToList(args.get("address"))
    input_excluded_members = argToList(args.get("excluded_addresses"))
    allow_routing = args.get("allow_routing")
    action = args.get("action")

    if bool(input_members or input_excluded_members) != bool(action):
        raise DemistoException("`address` or `excluded_addresses` must be set with `action`.")

    response = client.list_firewall_address_ipv4_groups(name, vdom)
    result = extract_first_result(response)
    members = extract_key_from_items("name", result.get("member"))
    excluded_members = extract_key_from_items("name", result.get("exclude-member"))

    members = handle_group_items_by_action(
        input_items=input_members,
        action=action,
        items=members,
    )
    excluded_members = handle_group_items_by_action(
        input_items=input_excluded_members,
        action=action,
        items=excluded_members,
    )

    client.update_firewall_address_ipv4_group(
        vdom=vdom,
        name=name,
        comment=comment,
        members=members,
        excluded_members=excluded_members,
        exclude="enable" if excluded_members else "disable",
        allow_routing=allow_routing,
    )
    response = client.list_firewall_address_ipv4_groups(name, vdom)
    result = extract_first_result(response)
    members = extract_key_from_items("name", result.get("member"))
    uuid = result.get("uuid")

    output = remove_empty_elements(
        {
            "Name": name,
            "Address": {"Name": members},
            "UUID": uuid,
        }
    )
    readable_output = f"## The firewall address IPv4 group '{name}' was successfully updated."

    return CommandResults(
        outputs_prefix=ADDRESS_GROUP_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def delete_firewall_address_ipv4_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall IPv4 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name", "")

    raw_response = client.delete_firewall_address_ipv4_group(
        name=name,
        vdom=args.get("vdom", DEFAULT_VDOM),
    )
    output = {"Name": name, "Deleted": True}
    readable_output = f"## The firewall address IPv4 group '{name}' was successfully deleted."

    return CommandResults(
        outputs_prefix=ADDRESS_GROUP_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_response,
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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_firewall_address_ipv6_groups(
        name=args.get("name", ""),
        vdom=args.get("vdom", DEFAULT_VDOM),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
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
            "Details",
            "Comments",
        ],
        format_fields=format_fields,
        custom_table_builder=build_address_group_table,
        outputs_prefix=ADDRESS6_GROUP_CONTEXT,
        outputs_key_field="Name",
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
    vdom = args.get("vdom", DEFAULT_VDOM)
    name = args.get("name", "")
    comment = args.get("comment")
    # Preserve deprecated command outputs.
    address = args.get("members")
    members = argToList(address)

    response = client.create_firewall_address_ipv6_group(
        vdom=vdom,
        name=name,
        comment=comment,
        members=members,
    )
    output = {
        "Name": name,
        "Address": address,
    }
    readable_output = f"## The firewall address IPv6 group '{name}' was successfully created."

    return CommandResults(
        outputs_prefix=ADDRESS6_GROUP_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def update_firewall_address_ipv6_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall IPv6 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If `members` was not set with `action`.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    vdom = args.get("vdom", DEFAULT_VDOM)
    name = args.get("name", "")
    comment = args.get("comment")
    input_members = argToList(args.get("members"))
    action = args.get("action")

    if bool(input_members) != bool(action):
        raise DemistoException("`members` must be set with `action`.")

    response = client.list_firewall_address_ipv6_groups(name, vdom)
    result = extract_first_result(response)
    members = extract_key_from_items("name", result.get("member"))

    members = handle_group_items_by_action(
        input_items=input_members,
        action=action,
        items=members,
    )

    client.update_firewall_address_ipv6_group(
        vdom=vdom,
        name=name,
        comment=comment,
        members=members,
    )
    response = client.list_firewall_address_ipv6_groups(name, vdom)
    result = extract_first_result(response)
    members = extract_key_from_items("name", result.get("member"))

    output = remove_empty_elements(
        {
            "Name": name,
            "Address": {"Name": members},
        }
    )
    readable_output = f"## The firewall address IPv6 group '{name}' was successfully updated."

    return CommandResults(
        outputs_prefix=ADDRESS6_GROUP_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def delete_firewall_address_ipv6_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall IPv6 address groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name", "")

    raw_response = client.delete_firewall_address_ipv6_group(
        name=name,
        vdom=args.get("vdom", DEFAULT_VDOM),
    )
    output = {"Name": name, "Deleted": True}
    readable_output = f"## The firewall address IPv6 group '{name}' was successfully deleted."

    return CommandResults(
        outputs_prefix=ADDRESS6_GROUP_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_response,
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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_firewall_services(
        name=args.get("serviceName", ""),
        vdom=args.get("vdom", DEFAULT_VDOM),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
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
            "Details",
            "IP/FQDN",
            "Category",
            "Protocol",
        ],
        format_fields=format_fields,
        custom_table_builder=build_service_table,
        outputs_prefix=SERVICE_CONTEXT,
        outputs_key_field="Name",
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
    protocol_type = get_service_type(args)

    name = args.get("serviceName", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("comment")
    category = args.get("category")
    start_ip = args.get("start_ip")
    end_ip = args.get("end_ip")
    fqdn = args.get("fqdn")
    tcp_port_ranges = argToList(args.get("tcpRange"))
    udp_port_ranges = argToList(args.get("udpRange"))
    sctp_port_ranges = argToList(args.get("sctpRange"))
    icmp_type = arg_to_number(args.get("icmp_type"))
    icmp_code = arg_to_number(args.get("icmp_code"))
    ip_protocol = arg_to_number(args.get("ip_protocol"))

    validate_optional_ipv4_addresses(start_ip, end_ip)

    response = client.create_firewall_service(
        name=name,
        vdom=vdom,
        comment=comment,
        category=category,
        protocol_type=protocol_type,
        start_ip=start_ip,
        end_ip=end_ip,
        fqdn=fqdn,
        tcp_port_ranges=tcp_port_ranges,
        udp_port_ranges=udp_port_ranges,
        sctp_port_ranges=sctp_port_ranges,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        ip_protocol=ip_protocol,
    )

    outputs = build_service_outputs(args)
    readable_output = f"## The firewall service '{name}' was successfully created."

    return CommandResults(
        outputs_prefix=SERVICE_CONTEXT,
        outputs_key_field="Name",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def update_firewall_service_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall services.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If the input protocol type is different from the API.
        DemistoException: If `action` was given without arguments TCP/UDP/SCTP parameters.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("comment")
    category = args.get("category")
    start_ip = args.get("start_ip")
    end_ip = args.get("end_ip")
    fqdn = args.get("fqdn")
    tcp_port_ranges = argToList(args.get("tcpRange"))
    udp_port_ranges = argToList(args.get("udpRange"))
    sctp_port_ranges = argToList(args.get("sctpRange"))
    icmp_type = arg_to_number(args.get("icmp_type"))
    icmp_code = arg_to_number(args.get("icmp_code"))
    ip_protocol = arg_to_number(args.get("ip_protocol"))
    action = args.get("action")

    if bool(action) != any((tcp_port_ranges, udp_port_ranges, sctp_port_ranges)):
        raise DemistoException(f"'action' and '{TCP_UDP_SCTP}' must be set together.")

    validate_optional_ipv4_addresses(start_ip, end_ip)

    input_protocol_type = None
    response = client.list_firewall_services(name, vdom)
    result = extract_first_result(response)

    if any(
        (
            start_ip,
            end_ip,
            fqdn,
            tcp_port_ranges,
            udp_port_ranges,
            sctp_port_ranges,
            args.get("icmp_version"),
            icmp_type,
            icmp_code,
            ip_protocol,
        )
    ):
        input_protocol_type = get_service_type(args)
        api_protocol_type = result.get("protocol")

        if input_protocol_type != api_protocol_type:
            raise DemistoException(
                f"The service '{name}' is of type '{api_protocol_type}',"
                f" which is not compatible with the requested type '{input_protocol_type}'."
            )

    port_ranges = {}

    if action:
        port_ranges = handle_action_for_port_ranges(
            obj=result,
            action=action,
            tcp_port_ranges=tcp_port_ranges,
            udp_port_ranges=udp_port_ranges,
            sctp_port_ranges=sctp_port_ranges,
        )

    response = client.update_firewall_service(
        name=name,
        vdom=vdom,
        comment=comment,
        category=category,
        protocol_type=input_protocol_type,
        start_ip=start_ip,
        end_ip=end_ip,
        fqdn=fqdn,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        ip_protocol=ip_protocol,
        tcp_port_ranges=port_ranges.get("tcp_port_ranges"),
        udp_port_ranges=port_ranges.get("udp_port_ranges"),
        sctp_port_ranges=port_ranges.get("sctp_port_ranges"),
    )

    outputs = build_service_outputs(args)
    readable_output = f"## The firewall service '{name}' was successfully updated."

    return CommandResults(
        outputs_prefix=SERVICE_CONTEXT,
        outputs_key_field="Name",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def delete_firewall_service_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall services.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("name", "")

    raw_response = client.delete_firewall_service(
        name=name,
        vdom=args.get("vdom", DEFAULT_VDOM),
    )
    output = {"Name": name, "Deleted": True}
    readable_output = f"## The firewall service '{name}' was successfully deleted."

    return CommandResults(
        outputs_prefix=SERVICE_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_response,
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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_firewall_service_groups(
        name=args.get("name", ""),
        vdom=args.get("vdom", DEFAULT_VDOM),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
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
            "Members",
            "Comments",
        ],
        format_fields=format_fields,
        custom_table_builder=build_service_group_table,
        outputs_prefix=SERVICE_GROUP_CONTEXT,
        outputs_key_field="Name",
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
    name = args.get("name", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("comment")
    # Preserve deprecated command outputs.
    member_str = args.get("members")
    members = argToList(member_str)

    response = client.create_firewall_service_group(
        name=name,
        vdom=vdom,
        comment=comment,
        members=members,
    )

    outputs = {"Name": name, "Members": member_str}
    readable_output = f"## The firewall service group '{name}' was successfully created."

    return CommandResults(
        outputs_prefix=SERVICE_GROUP_CONTEXT,
        outputs_key_field="Name",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def update_firewall_service_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall service groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("groupName", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("comment")
    input_members = argToList(args.get("serviceName"))
    action = args.get("action")

    if bool(input_members) != bool(action):
        raise DemistoException("`serviceName` must be set with `action`.")

    response = client.list_firewall_service_groups(name, vdom)
    result = extract_first_result(response)
    members = extract_key_from_items("name", result.get("member"))
    members = handle_group_items_by_action(
        input_items=input_members,
        action=action,
        items=members,
    )

    client.update_firewall_service_group(
        name=name,
        vdom=vdom,
        comment=comment,
        members=members,
    )

    response = client.list_firewall_service_groups(name, vdom)
    result = extract_first_result(response)
    members = extract_key_from_items("name", result.get("member"))
    outputs = {"Name": name, "Service": {"Name": members}}
    readable_output = f"## The firewall service group '{name}' was successfully updated."

    return CommandResults(
        outputs_prefix=SERVICE_GROUP_CONTEXT,
        outputs_key_field="Name",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def delete_firewall_service_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall service groups.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("groupName", "")

    raw_response = client.delete_firewall_service_group(
        name=name,
        vdom=args.get("vdom", DEFAULT_VDOM),
    )
    output = {"Name": name, "Deleted": True}
    readable_output = f"## The firewall service group '{name}' was successfully deleted."

    return CommandResults(
        outputs_prefix=SERVICE_GROUP_CONTEXT,
        outputs_key_field="Name",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_response,
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
    name = args.get("policyName")
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_firewall_policies(
        id_=args.get("policyID"),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )
    outputs = build_policy_outputs(raw_response, name)

    if format_fields:
        readable_output = tableToMarkdown(
            name="Firewall Policies",
            t=outputs,
            removeNull=True,
        )
    else:
        readable_output = tableToMarkdown(
            name="Firewall Policies",
            t=build_policy_table(outputs),
            headers=[
                "ID",
                "Name",
                "From",
                "To",
                "Source",
                "Destination",
                "Schedule",
                "Service",
                "Action",
                "NAT",
                "Security Profiles",
                "Log",
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

    Raises:
        DemistoException:
            - If both versions of address were provided.
            - If none of the versions of address were provided.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    name = args.get("policyName", "")
    vdom = args.get("vdom", DEFAULT_VDOM)
    comment = args.get("description")
    negate_source_address = args.get("negate_source_address")
    negate_destination_address = args.get("negate_destination_address")
    negate_service = args.get("negate_service")
    action = args.get("action", "")
    status = args.get("status", "enable")
    log_traffic = args.get("log", "enable")
    schedule = args.get("schedule", "always")
    nat = args.get("nat", "enable")
    # Preserve deprecated command outputs.
    source_interface = args.get("sourceIntf")
    destination_interface = args.get("dstIntf")
    source_address = args.get("source", "")
    destination_address = args.get("destination", "")
    source_address6 = args.get("source6", "")
    destination_address6 = args.get("destination6", "")
    service = args.get("service")

    source_interfaces = argToList(source_interface)
    destination_interfaces = argToList(destination_interface)
    source_addresses = argToList(source_address)
    destination_addresses = argToList(destination_address)
    source_addresses6 = argToList(source_address6)
    destination_addresses6 = argToList(destination_address6)
    services = argToList(service)

    is_address_v4 = bool(source_addresses and destination_addresses)
    is_address_v6 = bool(source_addresses6 and destination_addresses6)

    if not (is_address_v4 or is_address_v6):
        raise DemistoException("At least one of the source and destination address versions must be set.")

    if (source_addresses or destination_addresses) and (source_addresses6 or destination_addresses6):
        raise DemistoException("Only one of the source and destination address versions can be set.")

    response = client.create_firewall_policy(
        name=name,
        vdom=vdom,
        comment=comment,
        source_interfaces=source_interfaces,
        destination_interfaces=destination_interfaces,
        source_addresses=source_addresses,
        destination_addresses=destination_addresses,
        source_addresses6=source_addresses6,
        destination_addresses6=destination_addresses6,
        negate_source_address=negate_source_address,
        negate_destination_address=negate_destination_address,
        services=services,
        negate_service=negate_service,
        action="deny" if action == "block" else action,
        status=status,
        log_traffic=log_traffic,
        schedule=schedule,
        nat=nat,
        is_address_v4=is_address_v4,
    )

    outputs = {
        "Name": name,
        "Description": comment,
        "Status": status,
        "Service": service,
        "Action": action,
        "Log": log_traffic,
        "Source": {
            "Interface": source_interface,
            "Address": policy_addr_array_from_arg(source_address),
            "Address6": policy_addr_array_from_arg(source_address6),
        },
        "Destination": {
            "Interface": destination_interface,
            "Address": policy_addr_array_from_arg(destination_address),
            "Address6": policy_addr_array_from_arg(destination_address6),
        },
        "NAT": nat,
    }
    readable_output = f"## The firewall policy '{name}' was successfully created."

    return CommandResults(
        outputs_prefix=POLICY_CONTEXT,
        outputs_key_field="Name",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def update_firewall_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update firewall policies.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If 'keep_original_data' is 'True', but 'add_or_remove' wasn't provided.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    vdom = args.get("vdom", DEFAULT_VDOM)
    id_ = args.get("policyID", "")
    input_field = args.get("field", "")
    value = args.get("value", "")
    keep_original_data = argToBoolean(args.get("keep_original_data", False))
    add_or_remove = args.get("add_or_remove")

    if keep_original_data and not add_or_remove:
        raise DemistoException("If 'keep_original_data' is set to True, 'add_or_remove' must also be set.")

    input_field_to_api_field = {
        "source_interface": "srcintf",
        "destination_interface": "dstintf",
        "description": "comments",
        "source": "srcaddr",
        "destination": "dstaddr",
        "source6": "srcaddr6",
        "destination6": "dstaddr6",
        "log": "logtraffic",
        "negate_source": "srcaddr-negate",
        "negate_destination": "dstaddr-negate",
        "negate_source6": "srcaddr6-negate",
        "negate_destination6": "dstaddr6-negate",
        "negate_service": "service-negate",
    }
    api_field = input_field_to_api_field.get(input_field, input_field)

    if input_field in {
        "source_interface",
        "destination_interface",
        "source",
        "destination",
        "source6",
        "destination6",
        "service",
    }:
        value = argToList(value)

        if keep_original_data:
            response = client.list_firewall_policies(id_, vdom)
            result = extract_first_result(response)
            api_addresses = extract_key_from_items("name", result.get(api_field))

            value = handle_group_items_by_action(
                input_items=value,
                action=add_or_remove,
                items=api_addresses,
            )

    client.update_firewall_policy(id_=id_, vdom=vdom, field=api_field, value=value)
    response = client.list_firewall_policies(id_, vdom)
    result = extract_first_result(response)

    outputs = remove_empty_elements(map_keys(result, POLICY_MAPPINGS) | build_security(result))
    readable_output = f"## The firewall policy '{id_}' was successfully updated."

    return CommandResults(
        outputs_prefix=POLICY_CONTEXT,
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def move_firewall_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Move the position of firewall policies.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    vdom = args.get("vdom", DEFAULT_VDOM)
    id_ = args.get("policyID", "")
    position = args.get("position", "")
    neighbor = args.get("neighbor", "")

    response = client.move_firewall_policy(
        id_=id_,
        vdom=vdom,
        position=position,
        neighbor=neighbor,
    )

    outputs = {"ID": id_, "Moved": True}
    readable_output = f"## The firewall policy '{id_}' was successfully moved."

    return CommandResults(
        outputs_prefix=POLICY_CONTEXT,
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def delete_firewall_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete firewall policies.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    id_ = args.get("policyID", "")

    raw_response = client.delete_firewall_policy(
        id_=id_,
        vdom=args.get("vdom", DEFAULT_VDOM),
    )
    output = {"ID": id_, "Deleted": True}
    readable_output = f"## The firewall policy '{id_}' was successfully deleted."

    return CommandResults(
        outputs_prefix=POLICY_CONTEXT,
        outputs_key_field="ID",
        outputs=output,
        readable_output=readable_output,
        raw_response=raw_response,
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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_system_vdoms(
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
        mappings=[
            NAME_MAPPING,
            Mapping(["short-name"], ["ShortName"]),
            Mapping(["vcluster-id"], ["VClusterID"]),
        ],
        title="Virtual Domains",
        headers=[
            "Name",
            "ShortName",
            "VClusterID",
        ],
        format_fields=format_fields,
        outputs_prefix=VDOM_CONTEXT,
        outputs_key_field="Name",
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
    format_fields = argToList(args.get("format_fields"))

    raw_response = client.list_banned_ips(
        vdom=args.get("vdom", DEFAULT_VDOM),
        filter_field=args.get("filter_field"),
        filter_value=args.get("filter_value"),
        format_fields=format_fields,
    )

    return handle_list_response(
        raw_response=raw_response,
        mappings=[
            Mapping(["created"], ["Created"], 0, prettify_date),
            Mapping(["expires"], ["Expires"], 0, prettify_date),
            Mapping(["ip_address"], ["IP"]),
            Mapping(["ipv6"], ["IsV6"]),
            Mapping(["source"], ["Source"]),
        ],
        title="Banned IPs",
        headers=[
            "IP",
            "IsV6",
            "Created",
            "Expires",
            "Source",
        ],
        format_fields=format_fields,
        outputs_prefix=BANNED_IP_CONTEXT,
        outputs_key_field="IP",
    )


@logger
def ban_ip_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Ban IPs.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If an IP address is invalid.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    vdom = args.get("vdom", DEFAULT_VDOM)
    ip_addresses_str = args.get("ip_address")
    ip_addresses = argToList(ip_addresses_str)
    expiry = arg_to_number(args.get("expiry", 0))

    for ip_address in ip_addresses:
        if not is_ip_valid(ip_address, True):
            raise DemistoException(f"Invalid IP address: {ip_address}")

    response = client.ban_ip(
        ip_addresses=ip_addresses,
        expiry=expiry,
        vdom=vdom,
    )

    readable_output = f"## The IPs '{ip_addresses_str}' were successfully banned."

    return CommandResults(
        outputs_prefix=BANNED_IP_CONTEXT,
        readable_output=readable_output,
        raw_response=response,
    )


@logger
def unban_ip_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Unban IPs.

    Args:
        client (Client): Session to Fortigate to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        DemistoException: If an IP address is invalid.

    Returns:
        CommandResults: Outputs of the command that represent an entry in warroom.
    """
    vdom = args.get("vdom", DEFAULT_VDOM)
    ip_addresses_str = args.get("ip_address")
    ip_addresses = argToList(ip_addresses_str)

    for ip_address in ip_addresses:
        if not is_ip_valid(ip_address, True):
            raise DemistoException(f"Invalid IP address: {ip_address}")

    response = client.unban_ip(
        ip_addresses=ip_addresses,
        vdom=vdom,
    )

    readable_output = f"## The IPs '{ip_addresses_str}' were successfully unbanned."

    return CommandResults(
        outputs_prefix=BANNED_IP_CONTEXT,
        readable_output=readable_output,
        raw_response=response,
    )


""" Deprecated Commands """


@logger
def get_addresses_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    addresses_context = []
    address = args.get("address", DEFAULT_VDOM)
    name = args.get("name", "")

    response = client.list_firewall_address_ipv4s(name)

    if isinstance(response, list):
        response = response[0]

    addresses = response.get("results", [])

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
    """DEPRECATED COMMAND"""
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
    """DEPRECATED COMMAND"""
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
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    address_groups_context = []
    address_group_name = args.get("groupName", "")
    title = address_group_name if address_group_name else "all"

    address_groups = client.list_firewall_address_ipv4_groups(address_group_name).get("results")

    for address_group in address_groups or []:
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
def create_address_group_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    address_group_context = []
    group_name = args.get("groupName", "")
    address = args.get("address", "")

    client.create_firewall_address_ipv4_group(group_name, members=[address])

    contents.append(
        {
            "Name": group_name,
            "Address": address,
        }
    )
    address_group_context.append({"Name": group_name, "Address": address})

    context["Fortigate.AddressGroup(val.Name && val.Name === obj.Name)"] = address_group_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "FortiGate address group " + group_name + " created successfully", contents
            ),
            "EntryContext": context,
        }
    )


@logger
def update_address_group_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    address_group_context = []
    group_name = args.get("groupName", "")
    address = args.get("address", "")
    action = args.get("action")
    if action not in ["add", "remove"]:
        return_error("Action must be add or remove")

    old_address_groups = client.list_firewall_address_ipv4_groups(group_name).get("results")
    address_group_members = []  # type: list
    new_address_group_members = []  # type: list

    if isinstance(old_address_groups, list):
        old_address_group = old_address_groups[0]
        address_group_members = extract_key_from_items("name", old_address_group.get("member"))
    if action == "add":
        address_group_members.append(address)
        new_address_group_members = address_group_members
    if action == "remove":
        for address_group_member in address_group_members:
            if address_group_member != address:
                new_address_group_members.append(address_group_member)

    client.update_firewall_address_ipv4_group(group_name, members=new_address_group_members)
    address_group = client.list_firewall_address_ipv4_groups(group_name).get("results", [])[0]
    members = address_group.get("member")
    members_list = []
    for member in members:
        members_list.append(member.get("name"))
    contents.append({"Name": address_group.get("name"), "Members": members_list, "UUID": address_group.get("uuid")})
    address_group_context.append(
        {"Name": address_group.get("name"), "Address": {"Name": members_list}, "UUID": address_group.get("uuid")}
    )

    context["Fortigate.AddressGroup(val.Name && val.Name === obj.Name)"] = address_group_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "FortiGate address group " + group_name + " updated successfully", contents
            ),
            "EntryContext": context,
        }
    )


@logger
def delete_address_group_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
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
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    service_context = []
    service_name = args.get("serviceName", "")
    service_title = service_name
    if not service_name:
        service_title = "all services"

    services = client.list_firewall_services(service_name).get("results", [])

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
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    service_groups_context = []
    name = args.get("name", "")

    service_groups = client.list_firewall_service_groups(name).get("results", [])

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
def update_service_group_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    context = {}

    group_name = args.get("groupName", "")
    service_name = args.get("serviceName")
    action = args.get("action")
    if action not in ["add", "remove"]:
        return_error("Action must be add or remove")

    old_service_groups = client.list_firewall_service_groups(group_name).get("results", [])
    service_group_members = []  # type: list
    new_service_group_members = []  # type: list

    if isinstance(old_service_groups, list):
        old_service_group = old_service_groups[0]
        service_group_members = extract_key_from_items("name", old_service_group.get("member"))
    if action == "add":
        service_group_members.append(service_name)
        new_service_group_members = service_group_members
    if action == "remove":
        for service_group_member in service_group_members:
            if service_group_member != service_name:
                new_service_group_members.append(service_group_member)

    client.update_firewall_service_group(group_name, new_service_group_members)
    service_group = client.list_firewall_service_groups(group_name).get("results", [])[0]

    service_group_members = []
    members = service_group.get("member")
    for member in members:
        service_group_members.append(member.get("name"))

    contents = {"Name": service_group.get("name"), "Services": service_group_members}

    service_group_context = {"Name": service_group.get("name"), "Service": {"Name": service_group_members}}

    context["Fortigate.ServiceGroup(val.Name && val.Name === obj.Name)"] = service_group_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "FortiGate service group: " + group_name + " was successfully updated", contents
            ),
            "EntryContext": context,
        }
    )


@logger
def delete_service_group_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    context = {}
    group_name = args.get("groupName", "")

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
    """DEPRECATED COMMAND"""
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
    policies = client.list_firewall_policies(id_=policy_id, format_fields=format_fields).get("results", [])

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
def policy_addr_array_from_arg(policy_addr_data, is_data_string=True):
    """Builds the a list of dicts from the given string
    If the data isn't in string format, it's already an array and requires no formatting
    """
    policy_adr_str_array = policy_addr_data.split(",") if is_data_string else policy_addr_data
    policy_addr_dict_array = []
    for src_addr_name in policy_adr_str_array:
        cur_addr_dict = {"name": src_addr_name}
        policy_addr_dict_array.append(cur_addr_dict)
    return policy_addr_dict_array


@logger
def create_policy_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    policy_context = []

    policy_name = args.get("policyName", "")
    policy_description = args.get("description", "")
    policy_srcintf = args.get("sourceIntf")
    policy_dstintf = args.get("dstIntf")
    policy_source_address = args.get("source", "")
    policy_destination_address = args.get("destination", "")
    policy_service = args.get("service")
    policy_action = args.get("action", "")
    policy_status = args.get("status", "enable")
    policy_log = args.get("log", "enable")
    policy_nat = args.get("nat", "enable")

    client.create_firewall_policy(
        name=policy_name,
        comment=policy_description,
        source_interfaces=argToList(policy_srcintf),
        destination_interfaces=argToList(policy_dstintf),
        source_addresses=argToList(policy_source_address),
        destination_addresses=argToList(policy_destination_address),
        services=argToList(policy_service),
        action="deny" if policy_action == "block" else policy_action,
        status=policy_status,
        log_traffic=policy_log,
        nat=policy_nat,
    )

    policy_source_address = policy_addr_array_from_arg(policy_source_address)
    policy_destination_address = policy_addr_array_from_arg(policy_destination_address)

    contents.append(
        {
            "Name": policy_name,
            "Description": policy_description,
            "Status": policy_status,
            "Service": policy_service,
            "Action": policy_action,
            "Log": policy_log,
            "Source": {"Interface": policy_srcintf, "Address": policy_source_address},
            "Destination": {"Interface": policy_dstintf, "Address": policy_destination_address},
            "NAT": policy_nat,
        }
    )

    policy_context.append(
        {
            "Name": policy_name,
            "Description": policy_description,
            "Status": policy_status,
            "Service": policy_service,
            "Action": policy_action,
            "Log": policy_log,
            "Source": {"Interface": policy_srcintf, "Address": policy_source_address},
            "Destination": {"Interface": policy_dstintf, "Address": policy_destination_address},
            "NAT": policy_nat,
        }
    )

    context["Fortigate.Policy(val.Name && val.Name === obj.Name)"] = policy_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate policy " + policy_name + " created successfully", contents),
            "EntryContext": context,
        }
    )


@logger
def generate_src_or_dst_request_data(
    policy_id,
    policy_field,
    policy_field_value,
    keep_original_data,
    add_or_remove,
    list_firewall_policies,
):
    """DEPRECATED COMMAND"""
    address_list_for_request = policy_field_value.split(",")
    if argToBoolean(keep_original_data):
        policy_data = list_firewall_policies(policy_id).get("results", [])[0]
        existing_adresses_list = policy_data.get(policy_field)
        existing_adresses_list = [address_data["name"] for address_data in existing_adresses_list]
        if add_or_remove.lower() == "add":
            for address in existing_adresses_list:
                if address not in address_list_for_request:
                    address_list_for_request.append(address)
        else:
            address_list_for_request = [
                address for address in existing_adresses_list if address not in address_list_for_request
            ]

    address_data_dicts_for_request = policy_addr_array_from_arg(address_list_for_request, False)
    return address_data_dicts_for_request


@logger
def update_policy_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    policy_context = []
    security_profiles = []

    policy_id = args.get("policyID", "")
    policy_field = args.get("field", "")
    policy_field_value = args.get("value", "")
    keep_original_data = args.get("keep_original_data")
    add_or_remove = args.get("add_or_remove")

    if keep_original_data and keep_original_data.lower() == "true" and not add_or_remove:
        return_error("Error: add_or_remove must be specified if keep_original_data is true.")

    field_to_api_key = {"description": "comments", "source": "srcaddr", "destination": "dstaddr", "log": "logtraffic"}

    if policy_field in field_to_api_key:
        policy_field = field_to_api_key[policy_field]

    if policy_field in {"srcaddr", "dstaddr"}:
        policy_field_value = generate_src_or_dst_request_data(
            policy_id,
            policy_field,
            policy_field_value,
            keep_original_data,
            add_or_remove,
            client.list_firewall_policies,
        )

    client.update_firewall_policy(policy_id, policy_field, policy_field_value)
    policy = client.list_firewall_policies(policy_id).get("results", [])[0]
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
        src_address = src_address[0].get("name")
    dest_address = policy.get("dstaddr")
    if dest_address and isinstance(dest_address, list) and isinstance(dest_address[0], dict):
        dest_address = dest_address[0].get("name")
    service = policy.get("service")
    if service and isinstance(service, list) and isinstance(service[0], dict):
        service = service[0].get("name")

    contents.append(
        {
            "Name": policy.get("name"),
            "ID": policy.get("policyid"),
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
            "ID": policy.get("policyid"),
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
            "HumanReadable": tableToMarkdown(
                "FortiGate policy ID " + policy_id + " has been updated successfully.", contents
            ),
            "EntryContext": context,
        }
    )


@logger
def move_policy_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    policy_id = args.get("policyID", "")
    position = args.get("position", "")
    neighbour = args.get("neighbor", "")

    client.move_firewall_policy(policy_id, position, neighbour)

    policy_context = {"ID": int(policy_id), "Moved": True}
    contents.append({"ID": policy_id, "Moved": True})

    context["Fortigate.Policy(val.ID && val.ID === obj.ID)"] = policy_context

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": contents,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("FortiGate policy with ID " + policy_id + " moved successfully", contents),
            "EntryContext": context,
        }
    )


@logger
def delete_policy_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    contents = []
    context = {}
    policy_id = args.get("policyID", "")

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


@logger
def create_banned_ips_entry_context(ips_data_array):
    """DEPRECATED COMMAND"""
    ips_contexts_array = []
    for ip_data in ips_data_array:
        current_ip_context = {"IP": ip_data.get("ip_address"), "Source": ip_data.get("source")}
        if ip_data.get("expires"):
            expiration_in_ms = prettify_date(ip_data.get("expires", 0))
            current_ip_context["Expires"] = expiration_in_ms
        if ip_data.get("created"):
            creation_in_ms = prettify_date(ip_data.get("created", 0))
            current_ip_context["Created"] = creation_in_ms
        ips_contexts_array.append(current_ip_context)
    return ips_contexts_array


@logger
def create_banned_ips_human_readable(entry_context):
    """DEPRECATED COMMAND"""
    banned_ip_headers = ["IP", "Created", "Expires", "Source"]
    human_readable = tableToMarkdown("Banned IP Addresses", entry_context, banned_ip_headers)
    return human_readable


@logger
def get_banned_ips_command(client: Client, args: dict[str, Any]):
    """DEPRECATED COMMAND"""
    response = client.list_banned_ips()
    ips_data_array = response.get("results")
    entry_context = create_banned_ips_entry_context(ips_data_array)
    human_readable = create_banned_ips_human_readable(entry_context)
    return_outputs(
        raw_response=response,
        readable_output=human_readable,
        outputs={"Fortigate.BannedIP(val.IP===obj.IP)": entry_context},
    )


""" Entry Point """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url: str = params["server"]

    username = dict_safe_get(params, ["credentials", "identifier"])
    password = dict_safe_get(params, ["credentials", "password"])
    api_key = dict_safe_get(params, ["api_key", "password"])

    if not any([username, password, api_key]):
        raise DemistoException(
            "Please provide an authentication method. Either 'API Key' or 'Account username' and 'Password'."
        )

    if api_key and (username or password):
        raise DemistoException("Please don't mix 'API Key' with 'Account username' or 'Password'.")

    if bool(username) != bool(password):
        raise DemistoException("Please provide both 'Account username' and 'Password' or none of them.")

    verify_certificate: bool = not argToBoolean(params.get("unsecure", False))
    proxy: bool = argToBoolean(params.get("proxy", False))

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
        f"{FORTIGATE}-get-{ADDRESSES}": get_addresses_command,
        f"{FORTIGATE}-create-{ADDRESS}": create_address_command,
        f"{FORTIGATE}-delete-{ADDRESS}": delete_address_command,
        f"{FORTIGATE}-get-{ADDRESS}-{GROUP}s": get_address_groups_command,
        f"{FORTIGATE}-create-{ADDRESS}-{GROUP}": create_address_group_command,
        f"{FORTIGATE}-update-{ADDRESS}-{GROUP}": update_address_group_command,
        f"{FORTIGATE}-delete-{ADDRESS}-{GROUP}": delete_address_group_command,
        f"{FORTIGATE}-get-{FIREWALL}-{SERVICE}": get_firewall_service_command,
        f"{FORTIGATE}-get-{SERVICE}-{GROUP}s": get_service_groups_command,
        f"{FORTIGATE}-update-{SERVICE}-{GROUP}": update_service_group_command,
        f"{FORTIGATE}-delete-{SERVICE}-{GROUP}": delete_service_group_command,
        f"{FORTIGATE}-get-{POLICY}": get_policy_command,
        f"{FORTIGATE}-create-{POLICY}": create_policy_command,
        f"{FORTIGATE}-update-{POLICY}": update_policy_command,
        f"{FORTIGATE}-move-{POLICY}": move_policy_command,
        f"{FORTIGATE}-delete-{POLICY}": delete_policy_command,
        f"{FORTIGATE}-get-banned-ips": get_banned_ips_command,
    }

    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        if username and password:
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
