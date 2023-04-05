import re
from abc import abstractmethod
from collections.abc import Callable
from enum import Enum
from http import HTTPStatus
from typing import Any

from CommonServerPython import *
from requests import Response

LIMIT_SIZE = 50


class OutputTitle(Enum):
    PROTECTED_HOSTNAME_GROUP = "Protected Hostname group"
    PROTECTED_HOSTNAME_MEMBER = "Protected Hostname member"
    IP_LIST_GROUP = "IP List group"
    IP_LIST_MEMBER = "IP List member"
    HTTP_CONTENT_ROUTING_MEMBER = "HTTP content routing member"
    GEO_IP_GROUP = "Geo IP group"
    GEO_IP_MEMBER = "Geo IP member"
    SERVER_POLICY = "Server Policy"
    CUSTOM_WHITELIST_URL = "Custom whitelist URL member"
    CUSTOM_WHITELIST_PARAMETER = "Custom whitelist Parameter member"
    CUSTOM_WHITELIST_COOKIE = "Custom whitelist Cookie member"
    CUSTOM_WHITELIST_HEADER_FIELD = "Custom whitelist Header Field member"
    CUSTOM_WHITELIST_MEMBER = "Custom whitelist member"
    CUSTOM_PREDIFINED = "Custom predifined member"
    CREATED = "successfully created!"
    UPDATED = "successfully updated!"
    DELETED = "successfully deleted!"
    PROTECTED_HOSTNAME_GROUP_LIST = "Protected Hostnames Groups:"
    PROTECTED_HOSTNAME_MEMBER_CREATE = "Hostname member successfully created!"
    PROTECTED_HOSTNAME_MEMBER_LIST = "Protected Hostnames Members:"
    IP_LIST_GROUP_LIST = "IP Lists Groups:"
    IP_LIST_MEMBER_CREATE = "IP List member successfully created!"
    IP_LIST_MEMBER_LIST = "IP Lists Members:"
    HTTP_CONTENT_ROUTING_MEMBER_CREATE = (
        "HTTP content routing member succesfuly created!"
    )
    HTTP_CONTENT_ROUTING_MEMBER_LIST = "HTTP Content Routing Policy Members:"
    GEO_IP_GROUP_LIST = "Geo IP group:"
    GEO_IP_MEMBER_ADD = "Geo IP member successfully added!"
    GEO_IP_MEMBER_LIST = "Geo IP member:"
    SERVER_POLICY_LIST = "Server Policies:"
    CUSTOM_WHITELIST_URL_CREATE = "Custom whitelist URL member succesfuly created!"
    CUSTOM_WHITELIST_PARAMETER_CREATE = (
        "Custom whitelist Parameter member succesfuly created!"
    )
    CUSTOM_WHITELIST_COOKIE_CREATE = (
        "Custom whitelist Cookie member succesfuly created!"
    )
    CUSTOM_WHITELIST_HEADER_FIELD_CREATE = (
        "Custom whitelist Header Field member succesfuly created!"
    )
    CUSTOM_WHITELIST_LIST = "Custom whitelist members:"
    CUSTOM_PREDIFINED_LIST = "Custom whitelist members:"

    PROTECTED_HOSTNAME_GROUP_CREATE = "Protected Hostname group successfully created!"
    PROTECTED_HOSTNAME_GROUP_UPDATE = "Hostname group successfully updated!"
    PROTECTED_HOSTNAME_GROUP_DELETE = "Hostname group successfully deleted!"
    PROTECTED_HOSTNAME_MEMBER_UPDATE = "Hostname member successfully updated!"
    PROTECTED_HOSTNAME_MEMBER_DELETE = "Hostname member successfully deleted!"
    IP_LIST_GROUP_CREATE = "IP List group successfully created!"
    IP_LIST_GROUP_UPDATE = "IP List group successfully updated!"
    IP_LIST_GROUP_DELETE = "IP List group successfully deleted!"
    IP_LIST_MEMBER_UPDATE = "IP List member successfully updated!"
    IP_LIST_MEMBER_DELETE = "IP List member successfully deleted!"
    HTTP_CONTENT_ROUTING_MEMBER_UPDATE = (
        "HTTP content routing member succesfuly updated!"
    )
    HTTP_CONTENT_ROUTING_MEMBER_DELETE = (
        "HTTP content routing member succesfuly deleted!"
    )
    GEO_IP_GROUP_CREATE = "Geo IP group successfully created!"
    GEO_IP_GROUP_UPDATE = "Geo IP group successfully updated!"
    GEO_IP_GROUP_DELETE = "Geo IP group successfully deleted!"
    GEO_IP_MEMBER_DELETE = "Geo IP member succesfuly deleted!"
    SERVER_POLICY_CREATE = "Server Policy succesfuly created!"
    SERVER_POLICY_UPDATE = "Server Policy succesfuly updated!"
    SERVER_POLICY_DELETE = "Server Policy succesfuly deleted!"
    CUSTOM_WHITELIST_URL_UPDATE = "Custom whitelist URL member succesfuly updated!"
    CUSTOM_WHITELIST_PARAMETER_UPDATE = (
        "Custom whitelist Parameter member succesfuly updated!"
    )
    CUSTOM_WHITELIST_COOKIE_UPDATE = (
        "Custom whitelist Cookie member succesfuly updated!"
    )
    CUSTOM_WHITELIST_HEADER_FIELD_UPDATE = (
        "Custom whitelist Header Field member succesfuly updated!"
    )
    CUSTOM_WHITELIST_DELETE = "Custom whitelist member successfully deleted!"
    CUSTOM_PREDIFINED_UPDATE = (
        "Custom predifined whitelist member successfully updated!"
    )


class ErrorMessage(Enum):
    NOT_EXIST = "The object does not exist."
    ALREADY_EXIST = "The object already exist."
    ARGUMENTS = "There is a problem with one or more arguments."
    DEFAULT_ACTION = "The default action should be Allow/Deny/Deny (no log)"
    ACTION = "The action should be Allow/Deny/Deny (no log)"
    IGNORE_PORT = "ignore_port should be enable/disable"
    INCLUDE_SUBDOMAINS = "include_subdomains should be enable/disable"
    BLOCK_PERIOD = "Block period should be a number in range of 1-600."
    IP_ACTION = 'The action should be "Alert deny"/"Block period"/"Deny (no log)"'
    SEVERITY = "The severity should be High/Medium/Low/Info"
    IGNORE_X_FORWARDED_FOR = "ignore_x_forwarded_for should be enable/disable"
    V1_NOT_SUPPORTED = "Command not supported in version 1."
    TYPE = 'The type should be "Allow Only Ip"/"Black IP"/"Trust IP"'
    IP = "is not a valid IPv4/IPv6 address."
    ALLOW_IP_V1 = "Allow only ip not supported by version 1."
    IS_DEFAULT = "is_default should be yes/no"
    INHERIT_WEB_PROTECTION_PROFILE = (
        "inherit_web_protection_profile should be enable/disable"
    )
    STATUS = "status should be enable/disable"
    PROTOCOL = "It must to insert at least one HTTP or HTTPS service."
    DEPLOYMENT_MODE = 'deployment_mode should be "HTTP Content Routing"/"Single Server/Server Balance"'
    SERVER_POOL = 'Server pool is requierd argument while deployment_mode is "Single Server/Server Balance".'
    SCRIPTING = "scripting should be enable/disable"
    SCRIPTING_LIST = "At Least one scripting is required."
    CERTIFICATE_TYPE = (
        'certificate_type should be "Local"/"Multi Certificate"/"Letsencrypt"'
    )
    REQUEST_URL = "Request URL must start with  / ."
    REQUEST_URL_INSERT = "Please insert request_url."
    REQUEST_TYPE = 'request_type should be "Simple String"/"Regular Expression"'
    DOMAIN_TYPE = 'domain_type should be "Simple String"/"Regular Expression"'
    NAME_TYPE = 'name_type should be "Simple String"/"Regular Expression"'
    HEADER_NAME_TYPE = 'header_name_type should be "Simple String"/"Regular Expression"'
    HEADER_VALUE_TYPE = (
        'header_value_type should be "Simple String"/"Regular Expression"'
    )
    DOMAIN_INSERT = "Please insert domain."
    VALUE_INSERT = "Please insert value."
    COUNTRIES = "Please insert counries from the list."
    NAME_INSERT = "Please insert name."
    DEPLOYMENT_MODE_INSERT = "Please insert deployment mode."
    VIRTUAL_SERVER = "Please insert virtual server."
    CLIENT_REAL_IP = "client_real_ip should be enable/disable"
    MATCH_ONCE = "match_once should be enable/disable"
    MONITOR_MODE = "monitor_mode should be enable/disable"
    REDIRECT_2_HTTPS = "redirect_to_https should be enable/disable"
    RETRY_ON = "retry_on should be enable/disable"
    RETRY_ON_HTTP_LAYER = "retry_on_http_layer should be enable/disable"
    RETRY_ON_CONNECT_FAILURE = "retry_on_connect_failure should be enable/disable"
    SYN_COOKIE = "syn_cookie should be enable/disable"
    URL_CASE_SENSITIVITY = "url_case_sensitivity should be enable/disable"
    HALF_OPEN_THRESH = "half_open_thresh should be a number in range of 10-10,000."
    RETRY_TIMES_ON_CONNECT = (
        "retry_times_on_connect_failure should be a number in range of 1-5."
    )
    RETRY_TIMES_ON_HTTP = (
        "retry_times_on_http_layer should be a number in range of 1-5."
    )
    RETRY_ON_HTTP_RESPONSE_CODES = "Please insert codes from the list."


class Parser:
    @abstractmethod
    def create_output_headers(
        self,
        version: str,
        common_headers: List[str],
        v1_only_headers: List[str],
        v2_only_headers: List[str],
    ) -> List[str]:
        pass

    @abstractmethod
    def parse_protected_hostname_group(
        self, protected_hostname_group: dict[str, Any]
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_protected_hostname_member(
        self, protected_hostname_member: dict[str, Any]
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_ip_list_group(self, ip_list_group: dict[str, Any]) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_ip_list_member(self, ip_list_member: dict[str, Any]) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_http_content_routing_member(
        self, http_content_routing_member: dict[str, Any]
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_geo_ip_group(self, geo_ip_group: dict[str, Any]) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_geo_ip_member(self, geo_ip_member: dict[str, Any]) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_policy_status(self, policy: dict[str, Any]) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_system_status(self, policy: dict[str, Any]) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_simple_id(self, data_dict: dict[str, Any]) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_server_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        pass

    @abstractmethod
    def parse_custom_whitelist(
        self, custom_whitelist: dict[str, Any]
    ) -> dict[str, Any]:
        pass

    def parse_custom_predifined_whitelist(self, data: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": data["_id"],
            "name": data["name"],
            "path": data["path"],
            "domain": data["domain"],
            "status": data["value"],
        }

    def parse_http_service(self, policy: dict[str, Any]) -> dict[str, Any]:
        return {"id": policy["name"]}

    def parse_operation_status(
        self, operation_network: dict[str, Any]
    ) -> dict[str, Any]:
        """Parse for operation status.

        Args:
            client (Client): Fortiweb VM client.
            ip_list_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": operation_network["id"],
            "name": operation_network["name"],
            "label": operation_network["label"],
            "alias": operation_network["alias"],
            "ip_netmask": operation_network["ip_netmask"],
            "speed_duplex": operation_network["speedDuplex"],
            "tx": operation_network["tx"],
            "rx": operation_network["rx"],
            "link": operation_network["link"],
        }
        return parsed_data

    def parse_simple_name(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse a simple output with id.

        Args:
            data (Dict[str, Any]): Data to parse.

        Returns:
            dict[str,Any]: Parsed data.
        """
        return {"id": data["name"]}

    @property
    @abstractmethod
    def sub_object_id_key(self) -> str:
        pass

    @property
    @abstractmethod
    def action_user_to_api_mapper(self) -> dict[str, int] | dict[str, str]:
        pass

    @property
    @abstractmethod
    def action_api_to_user_mapper(self) -> dict[int, str] | dict[str, str]:
        pass

    @property
    @abstractmethod
    def type_user_to_api_mapper(self) -> dict[str, int] | dict[str, str]:
        pass

    @property
    @abstractmethod
    def type_api_to_user_mapper(self) -> dict[int, str] | dict[str, str]:
        pass

    @property
    @abstractmethod
    def severity_user_to_api_mapper(self) -> dict[str, int] | dict[str, str]:
        pass

    @property
    @abstractmethod
    def severity_api_to_user_mapper(self) -> dict[int, str] | dict[str, str]:
        pass

    @property
    def boolean_user_to_api_mapper(self) -> dict[str, bool]:
        return {"enable": True, "disable": False, "yes": True, "no": False}

    @property
    @abstractmethod
    def deployment_mode_user_to_api_mapper(self) -> dict[str, str]:
        pass

    @property
    @abstractmethod
    def deployment_mode_api_to_user_mapper(self) -> dict[int, str] | dict[str, str]:
        pass

    @property
    @abstractmethod
    def request_type_user_to_api_mapper(self) -> dict[str, int] | dict[str, str]:
        pass

    @property
    @abstractmethod
    def request_type_api_to_user_mapper(self) -> dict[int, str] | dict[str, str]:
        pass

    @property
    @abstractmethod
    def custom_whitelist_user_to_api_mapper(self) -> dict[str, int] | dict[str, str]:
        pass

    @property
    @abstractmethod
    def custom_whitelist_api_to_user_mapper(self) -> dict[int, str] | dict[str, str]:
        pass


class ParserV1(Parser):
    def create_output_headers(
        self,
        version: str,
        common_headers: List[str],
        v1_only_headers: List[str],
        v2_only_headers: List[str],
    ) -> List[str]:
        """Create headers for xsoar output.

        Args:
            version (str): Client version.
            common_headers (List[str]): Common headers field for both versions.
            v1_only_headers (List[str]): Headers for V1 only.
            v2_only_headers (List[str]): Header for V2 only.

        Returns:
            List[str]: List of headers.
        """
        return common_headers + v1_only_headers

    def parse_protected_hostname_group(
        self, protected_hostname_group: dict[str, Any]
    ) -> dict[str, Any]:
        """Parse for protected hostname group.

        Args:
            client (Client): Fortiweb VM client.
            protected_hostname_group (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        action_val = self.action_api_to_user_mapper[
            protected_hostname_group["defaultAction"]
        ]
        group = {
            "id": protected_hostname_group["_id"],
            "can_delete": protected_hostname_group["can_delete"],
            "default_action": action_val,
            "protected_hostname_count": protected_hostname_group[
                "protectedHostnameCount"
            ],
        }
        return group

    def parse_protected_hostname_member(
        self, protected_hostname_member: dict[str, Any]
    ) -> dict[str, Any]:
        """Parse for protected hostname member.

        Args:
            client (Client): Fortiweb VM client.
            protected_hostname_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        group = {
            "id": protected_hostname_member["_id"],
            "action": self.action_api_to_user_mapper[
                protected_hostname_member["action"]
            ],
            "host": protected_hostname_member["host"],
        }
        return group

    def parse_ip_list_group(self, ip_list_group: dict[str, Any]) -> dict[str, Any]:
        """Parse for protected hostname group.

        Args:
            client (Client): Fortiweb VM client.
            ip_list_group (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        group = {
            "id": ip_list_group["_id"],
            "ip_list_count": ip_list_group["ipListCount"],
            "can_delete": ip_list_group["can_delete"],
        }
        return group

    def parse_ip_list_member(self, ip_list_member: dict[str, Any]) -> dict[str, Any]:
        """Parse for IP list member.

        Args:
            client (Client): Fortiweb VM client.
            ip_list_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": ip_list_member["_id"],
            "type": self.type_api_to_user_mapper[ip_list_member["type"]],
            "severity": self.severity_api_to_user_mapper[ip_list_member["severity"]],
            "trigger_policy": ip_list_member["triggerPolicy"],
            "ip": ip_list_member["iPv4IPv6"],
        }
        return parsed_data

    def parse_http_content_routing_member(
        self, http_content_routing_member: dict[str, Any]
    ) -> dict[str, Any]:
        """Parse for HTTP content routing member.

        Args:
            client (Client): Fortiweb VM client.
            http_content_routing_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        id_default = http_content_routing_member["default"]
        inherit_web_protection_profile = http_content_routing_member[
            "inheritWebProtectionProfile"
        ]
        parsed_data = {
            "id": http_content_routing_member["_id"],
            "default": id_default,
            "http_content_routing_policy": http_content_routing_member[
                "http_content_routing_policy"
            ],
            "inherit_web_protection_profile": inherit_web_protection_profile,
            "profile": http_content_routing_member["profile"],
        }
        return parsed_data

    def parse_geo_ip_group(self, geo_ip_group: dict[str, Any]) -> dict[str, Any]:
        """Parse for Geo IP Group.

        Args:
            client (Client): Fortiweb VM client.
            geo_ip_group (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": geo_ip_group["_id"],
            "count": geo_ip_group["count"],
            "trigger_policy": geo_ip_group["triggerPolicy"],
            "severity": self.severity_api_to_user_mapper[geo_ip_group["severity"]],
            "except": geo_ip_group["except"],
            "can_delete": geo_ip_group["can_delete"],
        }

        return parsed_data

    def parse_geo_ip_member(self, geo_ip_member: dict[str, Any]) -> dict[str, Any]:
        """Parse for Geo IP member.

        Args:
            client (Client): Fortiweb VM client.
            geo_ip_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": geo_ip_member["_id"],
            "country": geo_ip_member["value"],
        }
        return parsed_data

    def parse_policy_status(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Parse for operation status.

        Args:
            client (Client): Fortiweb VM client.
            ip_list_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": policy["_id"],
            "name": policy["name"],
            "status": policy["status"],
            "vserver": policy["vserver"],
            "http_port": policy.get("httpPort"),
            "https_port": policy.get("httpsPort"),
            "mode": policy["mode"],
            "session_count": policy["sessionCount"],
            "connction_per_second": policy["connCntPerSec"],
        }
        return parsed_data

    def parse_system_status(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Parse for system status.

        Args:
            client (Client): Fortiweb VM client.
            ip_list_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "high_ability_status": policy["haStatus"],
            "host_name": policy["hostName"],
            "serial_number": policy["serialNumber"],
            "operation_mode": policy["operationMode"],
            "system_time": policy["systemTime"],
            "firmware_version": policy["firmwareVersion"],
            "system_uptime": policy["systemUptime"],
            "administrative_domain": policy["administrativeDomain"],
            "fips_and_cc_mode": policy["fipcc"],
            "log_disk": policy["logDisk"],
        }
        return parsed_data

    def parse_simple_id(self, data_dict: dict[str, Any]) -> dict[str, Any]:
        return {"id": data_dict["_id"]}

    def parse_server_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Parse for server policy dict.

        Args:
            client (Client): Fortiweb VM client.
            policy (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "name": policy["_id"],
            "deployment_mode": self.deployment_mode_api_to_user_mapper[
                policy["depInMode"]
            ],
            "virtual_server": policy["virtualServer"],
            "protocol": ",".join(
                remove_empty_elements(
                    [policy.get("HTTPService"), policy.get("HTTPSService")]
                )
            ),
            "web_protection_profile": policy.get("InlineProtectionProfile") or "",
            "monitor_mode": policy["MonitorMode"],
            "http_service": policy.get("HTTPService") or "",
            "https_service": policy.get("HTTPSService") or "",
            "certificate": policy.get("local") or "",
            "certificate_intermediate_group": policy.get("intergroup") or "",
            "server_pool": policy.get("serverPool") or "",
            "protected_hostnames": policy.get("protectedHostnames") or "",
            "client_real_ip": policy["clientRealIP"],
            "half_open_thresh": policy["halfopenThresh"],
            "syn_cookie": policy["syncookie"],
            "redirect_to_https": policy["hRedirectoHttps"],
            "http2": policy["http2"],
            "url_case_sensitivity": policy["URLCaseSensitivity"],
            "comments": policy["comments"],
        }
        return parsed_data

    def parse_custom_whitelist(
        self, custom_whitelist: dict[str, Any]
    ) -> dict[str, Any]:
        """Parse for custom whitelist member dict.

        Args:
            custom_whitelist (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": custom_whitelist["_id"],
            "type": self.custom_whitelist_api_to_user_mapper[custom_whitelist["type"]],
            "name": custom_whitelist.get("itemName") or "",
            "status": custom_whitelist["enable"],
            "request_type": dict_safe_get(
                self.request_type_api_to_user_mapper,
                [custom_whitelist.get("requestType")],
            )
            or "",
            "request_url": custom_whitelist.get("requestURL") or "",
            "domain": custom_whitelist.get("domain") or "",
            "path": custom_whitelist.get("path") or "",
        }
        return parsed_data

    @property
    def sub_object_id_key(self) -> str:
        """Hold sub object id key in Fortiweb V1

        Returns:
            str: Sub object id key
        """
        return "_id"

    @property
    def action_user_to_api_mapper(self) -> dict[str, int]:
        """Mapping the user input for action to the API input
        Returns:
            dict[str, int]: Mapped dictionary.
        """
        return {"Allow": 1, "Deny": 6, "Deny (no log)": 4}

    @property
    def action_api_to_user_mapper(self) -> dict[int, str]:
        """Mapping the API output for action to the user output
        Returns:
            dict[int, str]: Mapped dictionary.
        """
        return reverse_dict(self.action_user_to_api_mapper)

    @property
    def type_user_to_api_mapper(self) -> dict[str, int]:
        """Mapping the user input for type to the API input
        Returns:
            dict[str, int]: Mapped dictionary.
        """
        return {"Trust IP": 1, "Black IP": 2}

    @property
    def type_api_to_user_mapper(self) -> dict[int, str]:
        """Mapping the API output for type to the user output
        Returns:
            dict[int, str]: Mapped dictionary.
        """
        return reverse_dict(self.type_user_to_api_mapper)

    @property
    def severity_user_to_api_mapper(self) -> dict[str, int]:
        """Mapping the user input for severity to the API input
        Returns:
            dict[str, int]: Mapped dictionary.
        """
        return {"High": 1, "Medium": 2, "Low": 3, "Informative": 4}

    @property
    def severity_api_to_user_mapper(self) -> dict[int, str]:
        """Mapping the API output for severity to the user output
        Returns:
            dict[int, str]: Mapped dictionary.
        """
        return reverse_dict(self.severity_user_to_api_mapper)

    @property
    def deployment_mode_user_to_api_mapper(self) -> dict[str, str]:
        """Mapping the user input for deployment mode to the API input
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return {
            "Single Server/Server Balance": "server_pool",
            "HTTP Content Routing": "http_content_routing",
        }

    @property
    def deployment_mode_api_to_user_mapper(self) -> dict[str, str]:
        """Mapping the API output for deployment mode to the user output
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return reverse_dict(self.deployment_mode_user_to_api_mapper)

    @property
    def request_type_user_to_api_mapper(self) -> dict[str, int]:
        """Mapping the user input for request type to the API input
        Returns:
            dict[str, int]: Mapped dictionary.
        """
        return {"Simple String": 1, "Regular Expression": 2}

    @property
    def request_type_api_to_user_mapper(self) -> dict[int, str]:
        """Mapping the API output for request type to the user output
        Returns:
            dict[int, str]: Mapped dictionary.
        """
        return reverse_dict(self.request_type_user_to_api_mapper)

    @property
    def custom_whitelist_user_to_api_mapper(self) -> dict[str, int]:
        """Mapping the user input for custom whitelist types to the API input
        Returns:
            dict[str, int]: Mapped dictionary.
        """
        return {"URL": 1, "Parameter": 2, "Cookie": 3}

    @property
    def custom_whitelist_api_to_user_mapper(self) -> dict[int, str]:
        """Mapping the API output for custom whitelist types to the user output
        Returns:
            dict[int, str]: Mapped dictionary.
        """
        return reverse_dict(self.custom_whitelist_user_to_api_mapper)


class ParserV2(Parser):
    def create_output_headers(
        self,
        version: str,
        common_headers: List[str],
        v1_only_headers: List[str],
        v2_only_headers: List[str],
    ) -> List[str]:
        """Create headers for xsoar output.

        Args:
            version (str): Client version.
            common_headers (List[str]): Common headers field for both versions.
            v1_only_headers (List[str]): Headers for V1 only.
            v2_only_headers (List[str]): Header for V2 only.

        Returns:
            List[str]: List of headers.
        """
        return common_headers + v2_only_headers

    def parse_protected_hostname_group(
        self, protected_hostname_group: dict[str, Any]
    ) -> dict[str, Any]:
        """Parse for protected hostname group.

        Args:
            client (Client): Fortiweb VM client.
            protected_hostname_group (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        action_val = self.action_api_to_user_mapper[
            protected_hostname_group["default-action"]
        ]
        group = {
            "id": protected_hostname_group["name"],
            "default_action": action_val,
            "protected_hostname_count": protected_hostname_group["sz_host-list"],
        }
        return group

    def parse_protected_hostname_member(
        self, protected_hostname_member: dict[str, Any]
    ) -> dict[str, Any]:
        """Parse for protected hostname member.

        Args:
            client (Client): Fortiweb VM client.
            protected_hostname_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed disctionary.
        """
        group = {
            "id": protected_hostname_member["id"],
            "action": self.action_api_to_user_mapper[
                protected_hostname_member["action"]
            ],
            "host": protected_hostname_member["host"],
            "ignore_port": protected_hostname_member["ignore-port"],
            "include_subdomains": protected_hostname_member["include-subdomains"],
        }
        return group

    def parse_ip_list_group(self, ip_list_group: dict[str, Any]) -> dict[str, Any]:
        """Parse for protected hostname group.

        Args:
            client (Client): Fortiweb VM client.
            ip_list_group (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        group = {
            "id": ip_list_group["name"],
            "ip_list_count": ip_list_group["sz_members"],
            "can_view": ip_list_group["can_view"],
            "q_ref": ip_list_group["q_ref"],
            "can_clone": ip_list_group["can_clone"],
            "q_type": ip_list_group["q_type"],
            "action": ip_list_group["action"],
            "block_period": ip_list_group["block-period"],
            "severity": ip_list_group["severity"],
            "trigger_policy": ip_list_group["trigger-policy"],
        }
        return group

    def parse_ip_list_member(self, ip_list_member: dict[str, Any]) -> dict[str, Any]:
        """Parse for IP list member.

        Args:
            client (Client): Fortiweb VM client.
            ip_list_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": ip_list_member["id"],
            "type": self.type_api_to_user_mapper[ip_list_member["type"]],
            "ip": ip_list_member["ip"],
        }
        return parsed_data

    def parse_http_content_routing_member(
        self, http_content_routing_member: dict[str, Any]
    ) -> dict[str, Any]:
        """Parse for HTTP content routing member.

        Args:
            client (Client): Fortiweb VM client.
            http_content_routing_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": http_content_routing_member["id"],
            "default": http_content_routing_member["is-default"],
            "http_content_routing_policy": http_content_routing_member[
                "content-routing-policy-name"
            ],
            "inherit_web_protection_profile": http_content_routing_member[
                "profile-inherit"
            ],
            "profile": http_content_routing_member["web-protection-profile"],
            "status": http_content_routing_member["status"],
        }
        return parsed_data

    def parse_geo_ip_group(self, geo_ip_group: dict[str, Any]) -> dict[str, Any]:
        """Parse for Geo IP Group.

        Args:
            client (Client): Fortiweb VM client.
            geo_ip_group (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        action = self.action_api_to_user_mapper[geo_ip_group["action"]]
        parsed_data = {
            "id": geo_ip_group["name"],
            "count": geo_ip_group["sz_country-list"],
            "trigger_policy": geo_ip_group["trigger"],
            "severity": geo_ip_group["severity"],
            "except": geo_ip_group["exception-rule"],
            "action": action,
            "block_period": geo_ip_group["block-period"],
            "ignore_x_forwarded_for": geo_ip_group["ignore-x-forwarded-for"],
        }
        return parsed_data

    def parse_geo_ip_member(self, geo_ip_member: dict[str, Any]) -> dict[str, Any]:
        """Parse for Geo IP member.

        Args:
            client (Client): Fortiweb VM client.
            geo_ip_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": geo_ip_member["id"],
            "country": geo_ip_member["country-name"],
        }
        return parsed_data

    def parse_policy_status(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Parse for operation status.

        Args:
            client (Client): Fortiweb VM client.
            ip_list_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": policy["_id"],
            "policy": policy["policy"],
            "name": policy["name"],
            "status": policy["status"],
            "protocol": policy["protocol"],
            "vserver": policy["vserver"],
            "http_port": policy.get("httpPort"),
            "https_port": policy.get("httpsPort"),
            "mode": policy["mode"],
            "session_count": policy["sessionCount"],
            "connction_per_second": policy["connCntPerSec"],
            "client_rtt": policy["client_rtt"],
            "server_rtt": policy["server_rtt"],
            "app_response_time": policy["app_response_time"],
        }
        return parsed_data

    def parse_system_status(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Parse for operation status.

        Args:
            client (Client): Fortiweb VM client.
            ip_list_member (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "high_ability_status": policy["haStatus"],
            "host_name": policy["hostName"],
            "manager_status": policy["managerMode"],
            "serial_number": policy["serialNumber"],
            "operation_mode": policy["operationMode"],
            "system_time": policy["systemTime"],
            "firmware_version": policy["firmwareVersion"],
            "sysyem_up_days": policy["up_days"],
            "sysyem_up_hrs": policy["up_hrs"],
            "sysyem_up_mins": policy["up_mins"],
            "administrative_domain": policy["administrativeDomain"],
        }
        return parsed_data

    def parse_simple_id(self, data_dict: dict[str, Any]) -> dict[str, Any]:
        """Parse for simple dict.

        Args:
            client (Client): Fortiweb VM client.
            data_dict (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        return {"id": data_dict["name"]}

    def parse_server_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Parse for server policy dict.

        Args:
            client (Client): Fortiweb VM client.
            policy (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "name": policy["name"],
            "deployment_mode": self.deployment_mode_api_to_user_mapper[
                policy["deployment-mode"]
            ],
            "virtual_server": policy["vserver"],
            "protocol": ",".join(
                [
                    service
                    for service in [policy["service"], policy["https-service"]]
                    if service
                ]
            ),
            "web_protection_profile": policy["web-protection-profile"],
            "monitor_mode": policy["monitor-mode"],
            "http_service": policy["service"],
            "https_service": policy["https-service"],
            "certificate": policy["certificate"],
            "certificate_intermediate_group": policy["intermediate-certificate-group"],
            "server_pool": policy["server-pool"],
            "protected_hostnames": policy["allow-hosts"],
            "client_real_ip": policy["client-real-ip"],
            "half_open_thresh": policy["half-open-threshold"],
            "syn_cookie": policy["syncookie"],
            "redirect_to_https": policy["http-to-https"],
            "http2": policy["http2"],
            "url_case_sensitivity": policy["case-sensitive"],
            "comments": policy["comment"],
            "retry_on": policy["retry-on"],
            "retry_on_cache_size": policy["retry-on-cache-size"],
            "retry_on_connect_failure": policy["retry-on-connect-failure"],
            "retry_times_on_connect_failure": policy["retry-times-on-connect-failure"],
            "retry_on_http_layer": policy["retry-on-http-layer"],
            "retry_times_on_http_layer": policy["retry-times-on-http-layer"],
            "retry_on_http_response_codes": policy["retry-on-http-response-codes"],
            "scripting": policy["scripting"],
            "scripting_list": policy["scripting-list"],
            "allow_list": policy["allow-list"],
            "replace_msg": policy["replacemsg"],
        }
        return parsed_data

    def parse_custom_whitelist(
        self, custom_whitelist: dict[str, Any]
    ) -> dict[str, Any]:
        """Parse for custom whitelist member dict.

        Args:
            client (Client): Fortiweb VM client.
            custom_whitelist (Dict[str, Any]): A dictionary output from API.

        Returns:
            Dict[str, Any]: Parsed dictionary.
        """
        parsed_data = {
            "id": custom_whitelist["id"],
            "type": self.custom_whitelist_api_to_user_mapper[custom_whitelist["type"]],
            "name": custom_whitelist["name"],
            "status": custom_whitelist["status"],
            "name_type": self.request_type_user_to_api_mapper.get(
                custom_whitelist.get("name-type", ""), ""
            ),
            "request_url_status": custom_whitelist["request-file-status"],
            "request_type": self.request_type_user_to_api_mapper.get(
                custom_whitelist.get("request-type", ""), ""
            ),
            "request_url": custom_whitelist["request-file"],
            "domain_status": custom_whitelist["domain-status"],
            "domain_type": self.request_type_user_to_api_mapper.get(
                custom_whitelist.get("domain-type", ""), ""
            ),
            "domain": custom_whitelist["domain"],
            "path": custom_whitelist["path"],
            "header_name_type": self.request_type_user_to_api_mapper.get(
                custom_whitelist.get("header-type", ""), ""
            ),
            "value_status": custom_whitelist["value-status"],
            "header_value_type": self.request_type_user_to_api_mapper.get(
                custom_whitelist.get("value-type", ""), ""
            ),
            "value": custom_whitelist["value"],
        }
        return parsed_data

    @property
    def sub_object_id_key(self) -> str:
        """Hold sub object id key in Fortiweb V2

        Returns:
            str: Sub object id key
        """
        return "name"

    @property
    def action_user_to_api_mapper(self) -> dict[str, str]:
        """Mapping the user input for action to the API input
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return {
            "Allow": "allow",
            "Deny": "deny",
            "Deny (no log)": "deny_no_log",
            "Alert deny": "alert_deny",
            "Block period": "block-period",
        }

    @property
    def action_api_to_user_mapper(self) -> dict[str, str]:
        """Mapping the API output for action to the user output
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return reverse_dict(self.action_user_to_api_mapper)

    @property
    def type_user_to_api_mapper(self) -> dict[str, str]:
        """Mapping the user input for type to the API input
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return {
            "Trust IP": "trust-ip",
            "Black IP": "black-ip",
            "Allow Only Ip": "allow-only-ip",
        }

    @property
    def type_api_to_user_mapper(self) -> dict[str, str]:
        """Mapping the API output for type to the user output
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return reverse_dict(self.type_user_to_api_mapper)

    @property
    def severity_user_to_api_mapper(self) -> dict[str, int]:
        """Mapping the user input for severity to the API input
        Returns:
            dict[str, int]: Mapped dictionary.
        """
        return {"High": 1, "Medium": 2, "Low": 3, "Informative": 4}

    @property
    def severity_api_to_user_mapper(self) -> dict[int, str]:
        """Mapping the API output for severity to the user output
        Returns:
            dict[int, str]: Mapped dictionary.
        """
        return reverse_dict(self.severity_user_to_api_mapper)

    @property
    def deployment_mode_user_to_api_mapper(self) -> dict[str, Any]:
        """Mapping the user input for deployment mode to the API input
        Returns:
            dict[str, Any]: Mapped dictionary.
        """
        return {
            "Single Server/Server Balance": "server-pool",
            "HTTP Content Routing": "http-content-routing",
        }

    @property
    def deployment_mode_api_to_user_mapper(self) -> dict[str, str]:
        """Mapping the API output for deployment mode to the user output
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return reverse_dict(self.deployment_mode_user_to_api_mapper)

    @property
    def request_type_user_to_api_mapper(self) -> dict[str, Any]:
        """Mapping the user input for request type to the API input
        Returns:
            dict[str, Any]: Mapped dictionary.
        """
        return {"Simple String": "plain", "Regular Expression": "regular"}

    @property
    def request_type_api_to_user_mapper(self) -> dict[str, str]:
        """Mapping the API output for request type to the user output
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return reverse_dict(self.request_type_user_to_api_mapper)

    @property
    def custom_whitelist_user_to_api_mapper(self) -> dict[str, str]:
        """Mapping the user input for custom whitelist types to the API input
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return {
            "URL": "URL",
            "Parameter": "Parameter",
            "Cookie": "Cookie",
            "Header Field": "Header_Field",
        }

    @property
    def custom_whitelist_api_to_user_mapper(self) -> dict[str, str]:
        """Mapping the API output for custom whitelist types to the user output
        Returns:
            dict[str, str]: Mapped dictionary.
        """
        return reverse_dict(self.custom_whitelist_user_to_api_mapper)


class Client(BaseClient):
    """Fortiweb VM Client

    Args:
        BaseClient (BaseClient): Demisto base client parameters.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        version: str,
        endpoint_prefix: str,
        proxy: bool,
        verify: bool,
    ):
        self.base_url = urljoin(base_url, endpoint_prefix)
        self.version = version
        parser_class = {"V1": ParserV1, "V2": ParserV2}[version]
        self.parser: Parser = parser_class()
        headers = {"Content-Type": "application/json", "Authorization": api_key}
        super().__init__(
            base_url=self.base_url, verify=verify, headers=headers, proxy=proxy
        )

    def _http_request(self, *args, **kwargs):
        kwargs["error_handler"] = self.error_handler
        return super()._http_request(*args, **kwargs)

    @abstractmethod
    def encode_api_key(self, username: str, password: str):
        pass

    @abstractmethod
    def get_error_data(self, error: dict):
        pass

    @property
    @abstractmethod
    def not_exist_error_list(self) -> Union[List[str], List[int]]:
        pass

    @property
    @abstractmethod
    def exist_error_list(self) -> Union[List[str], List[int]]:
        pass

    @property
    @abstractmethod
    def wrong_parameter_error_list(self) -> Union[List[str], List[int]]:
        pass

    def error_handler(self, res: Response):
        """Error handler for Fortiweb response.

        Args:
            res (Response): Error response.

        Raises:
            DemistoException: The object does not exist.
            DemistoException: The object already exist.
            DemistoException: There is a problem with one or more arguments.
            DemistoException: One or more of the specified fields are invalid. Please validate them.
        """
        error_code = res.status_code
        if res.status_code == HTTPStatus.UNAUTHORIZED:
            raise DemistoException(
                "Authorization Error: make sure Username and Password are set correctly."
            )
        if res.status_code == HTTPStatus.NOT_FOUND:
            raise DemistoException(
                "Connection Error: Make sure server URL is set correctly."
            )
        output: str = None
        try:
            output = res.json()
        except requests.exceptions.JSONDecodeError:
            raise DemistoException(
                res,
                res=res)
        error = self.get_error_data(output)
        if error_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            # update & delete
            if error in self.not_exist_error_list:
                raise DemistoException(
                    f"{ErrorMessage.NOT_EXIST.value} {output}", res=res
                )
            # create
            elif error in self.exist_error_list:
                raise DemistoException(
                    f"{ErrorMessage.ALREADY_EXIST.value} {output}", res=res
                )
            elif error in self.wrong_parameter_error_list:
                raise DemistoException(
                    f"{ErrorMessage.ARGUMENTS.value} {output}", res=res
                )

            else:
                raise DemistoException(
                    f"One or more of the specified fields are invalid. Please validate them. {output}",
                    res=res,
                )

        else:
            raise DemistoException(
                f"One or more of the specified fields are invalid. Please validate them. {output}",
                res=res,
            )

    def validate_protected_hostname_group(self, args: dict[str, Any]):
        """Protected hostname group args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            DemistoException: Errors.
        """
        if args.get("default_action") and args["default_action"] not in [
            "Allow",
            "Deny",
            "Deny (no log)",
        ]:
            raise ValueError(ErrorMessage.DEFAULT_ACTION.value)

    def validate_protected_hostname_member(self, args: dict[str, Any]):
        """Protected hostname member args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            DemistoException: Errors.
        """
        if args.get("action") and args["action"] not in [
            "Allow",
            "Deny",
            "Deny (no log)",
        ]:
            raise ValueError(ErrorMessage.ACTION.value)
        if args.get("ignore_port") and args["ignore_port"] not in ["enable", "disable"]:
            raise ValueError(ErrorMessage.IGNORE_PORT.value)
        if args.get("include_subdomains") and args["include_subdomains"] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.INCLUDE_SUBDOMAINS.value)

    def validate_ip_list_group(self, args: dict[str, Any]):
        """IP list group args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            ValueError: Errors.
        """

        if args.get("action") and args["action"] not in [
            "Alert deny",
            "Block period",
            "Deny (no log)",
        ]:
            raise ValueError(ErrorMessage.IP_ACTION.value)
        if args.get("severity") and args["severity"] not in [
            "High",
            "Medium",
            "Low",
            "Info",
        ]:
            raise ValueError(ErrorMessage.SEVERITY.value)
        if args.get("ignore_x_forwarded_for") and args[
            "ignore_x_forwarded_for"
        ] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.IGNORE_X_FORWARDED_FOR.value)

    def validate_update_ip_list_group(self, args: dict[str, Any]):
        """IP list group args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            ValueError: Errors.
        """
        self.validate_ip_list_group(args)

    def validate_ip_list_member(self, args: dict[str, Any]):
        """IP list member args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            ValueError: Errors.
        """
        if args.get("type") and args["type"] not in [
            "Allow Only Ip",
            "Black IP",
            "Trust IP",
        ]:
            raise ValueError(ErrorMessage.TYPE.value)
        if args.get("severity") and args["severity"] not in [
            "High",
            "Medium",
            "Low",
            "Info",
        ]:
            raise ValueError(ErrorMessage.SEVERITY.value)
        ip: str = args.get("ip_address", "")
        ips = ip.split("-")
        if (
            len(ips) == 2
            and not re.match(ipv4Regex, ips[0])
            and not re.match(ipv4Regex, ips[1])
            and not re.match(ipv6Regex, ips[0])
            and not re.match(ipv6Regex, ips[1])
        ):
            raise ValueError(f"{ip} {ErrorMessage.IP.value}")
        if ip and not re.match(ipv4Regex, ip) and not re.match(ipv6Regex, ip):
            raise ValueError(f"{ip} {ErrorMessage.IP.value}")

    def validate_http_content_routing_member(self, args: dict[str, Any]):
        """HTTP content routing member args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            DemistoException: Errors.
        """
        if args.get("is_default") and args["is_default"] not in ["yes", "no"]:
            raise ValueError(ErrorMessage.IS_DEFAULT.value)
        if args.get("inherit_web_protection_profile") and args[
            "inherit_web_protection_profile"
        ] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.INHERIT_WEB_PROTECTION_PROFILE.value)
        if args.get("status") and args["status"] not in ["enable", "disable"]:
            raise ValueError(ErrorMessage.STATUS.value)

    def validate_geo_ip_group(self, args: dict[str, Any]):
        """Geo IP Group args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            ValueError: Errors.
        """
        if args.get("action") and args["action"] not in [
            "Alert deny",
            "Block period",
            "Deny (no log)",
        ]:
            raise ValueError(ErrorMessage.IP_ACTION.value)
        if args.get("severity") and args["severity"] not in [
            "High",
            "Medium",
            "Low",
            "Info",
        ]:
            raise ValueError(ErrorMessage.SEVERITY.value)
        if args.get("ignore_x_forwarded_for") and args[
            "ignore_x_forwarded_for"
        ] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.IGNORE_X_FORWARDED_FOR.value)

    def validate_geo_ip_member(self, args: dict[str, Any]):
        """Geo IP Group args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            DemistoException: Errors.
        """
        data = [
            "Afghanistan",
            "Aland Islands",
            "Albania",
            "Algeria",
            "American Samoa",
            "Andorra",
            "Angola",
            "Anguilla",
            "Antarctica",
            "Antigua And Barbuda",
            "Argentina",
            "Armenia",
            "Aruba",
            "Australia",
            "Austria",
            "Azerbaijan",
            "Bahamas",
            "Bahrain",
            "Bangladesh",
            "Barbados",
            "Belarus",
            "Belgium",
            "Belize",
            "Benin",
            "Bermuda",
            "Bhutan",
            "Bolivia",
            "Bonaire Saint Eustatius And Saba",
            "Bosnia And Herzegovina",
            "Botswana",
            "Brazil",
            "British Indian Ocean Territory",
            "British Virgin Islands",
            "Brunei Darussalam",
            "Bulgaria",
            "Burkina Faso",
            "Burundi",
            "Cambodia",
            "Cameroon",
            "Canada",
            "Cape Verde",
            "Cayman Islands",
            "Central African Republic",
            "Chad",
            "Chile",
            "China",
            "Colombia",
            "Comoros",
            "Congo",
            "Cook Islands",
            "Costa Rica",
            "Cote D Ivoire",
            "Croatia",
            "Cuba",
            "Curacao",
            "Cyprus",
            "Czech Republic",
            "Democratic People S Republic Of Korea",
            "Democratic Republic Of The Congo",
            "Denmark",
            "Djibouti",
            "Dominica",
            "Dominican Republic",
            "Ecuador",
            "Egypt",
            "El Salvador",
            "Equatorial Guinea",
            "Eritrea",
            "Estonia",
            "Ethiopia",
            "Falkland Islands  Malvinas",
            "Faroe Islands",
            "Federated States Of Micronesia",
            "Fiji",
            "Finland",
            "France",
            "French Guiana",
            "French Polynesia",
            "Gabon",
            "Gambia",
            "Georgia",
            "Germany",
            "Ghana",
            "Gibraltar",
            "Greece",
            "Greenland",
            "Grenada",
            "Guadeloupe",
            "Guam",
            "Guatemala",
            "Guernsey",
            "Guinea",
            "Guinea'issau",
            "Guyana",
            "Haiti",
            "Honduras",
            "Hong Kong",
            "Hungary",
            "Iceland",
            "India",
            "Indonesia",
            "Iran",
            "Iraq",
            "Ireland",
            "Isle Of Man",
            "Israel",
            "Italy",
            "Jamaica",
            "Japan",
            "Jersey",
            "Jordan",
            "Kazakhstan",
            "Kenya",
            "Kiribati",
            "Kosovo",
            "Kuwait",
            "Kyrgyzstan",
            "Lao People S Democratic Republic",
            "Latvia",
            "Lebanon",
            "Lesotho",
            "Liberia",
            "Libya",
            "Liechtenstein",
            "Lithuania",
            "Luxembourg",
            "Macao",
            "Macedonia",
            "Madagascar",
            "Malawi",
            "Malaysia",
            "Maldives",
            "Mali",
            "Malta",
            "Marshall Islands",
            "Martinique",
            "Mauritania",
            "Mauritius",
            "Mayotte",
            "Mexico",
            "Moldova",
            "Monaco",
            "Mongolia",
            "Montenegro",
            "Montserrat",
            "Morocco",
            "Mozambique",
            "Myanmar",
            "Namibia",
            "Nauru",
            "Nepal",
            "Netherlands",
            "New Caledonia",
            "New Zealand",
            "Nicaragua",
            "Niger",
            "Nigeria",
            "Niue",
            "Norfolk Island",
            "Northern Mariana Islands",
            "Norway",
            "Oman",
            "Pakistan",
            "Palau",
            "Palestine",
            "Panama",
            "Papua New Guinea",
            "Paraguay",
            "Peru",
            "Philippines",
            "Poland",
            "Portugal",
            "Puerto Rico",
            "Qatar",
            "Republic Of Korea",
            "Reunion",
            "Romania",
            "Russian Federation",
            "Rwanda",
            "Saint Bartelemey",
            "Saint Kitts And Nevis",
            "Saint Lucia",
            "Saint Martin",
            "Saint Pierre And Miquelon",
            "Saint Vincent And The Grenadines",
            "Samoa",
            "San Marino",
            "Sao Tome And Principe",
            "Saudi Arabia",
            "Senegal",
            "Serbia",
            "Seychelles",
            "Sierra Leone",
            "Singapore",
            "Sint Maarten",
            "Slovakia",
            "Slovenia",
            "Solomon Islands",
            "Somalia",
            "South Africa",
            "South Georgia And The South Sandwich Islands",
            "South Sudan",
            "Spain",
            "Sri Lanka",
            "Sudan",
            "Suriname",
            "Swaziland",
            "Sweden",
            "Switzerland",
            "Syria",
            "Taiwan",
            "Tajikistan",
            "Tanzania",
            "Thailand",
            "Timor'este",
            "Togo",
            "Tokelau",
            "Tonga",
            "Trinidad And Tobago",
            "Tunisia",
            "Turkey",
            "Turkmenistan",
            "Turks And Caicos Islands",
            "Tuvalu",
            "Uganda",
            "Ukraine",
            "United Arab Emirates",
            "United Kingdom",
            "United States",
            "Uruguay",
            "U S  Virgin Islands",
            "Uzbekistan",
            "Vanuatu",
            "Vatican",
            "Venezuela",
            "Vietnam",
            "Wallis And Futuna",
            "Yemen",
            "Zambia",
            "Zimbabwe",
        ]
        countries = argToList(args["countries"])
        if not set(countries).issubset(data):
            raise DemistoException(ErrorMessage.COUNTRIES.value)

    def validate_server_policy(self, args: dict[str, Any]):
        """Validate argument for server policy.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Returns:
            CommandResults: outputs, readable outputs and raw response for XSOAR.
        """
        if not args.get("name"):
            raise ValueError(ErrorMessage.NAME_INSERT.value)
        if not args.get("deployment_mode"):
            raise ValueError(ErrorMessage.DEPLOYMENT_MODE_INSERT.value)
        if not args.get("virtual_server"):
            raise ValueError(ErrorMessage.VIRTUAL_SERVER.value)

        http_service = args.get("http_service")
        https_service = args.get("https_service")
        if not (http_service or https_service):
            raise ValueError(ErrorMessage.PROTOCOL.value)
        if args.get("deployment_mode") and args["deployment_mode"] not in [
            "HTTP Content Routing",
            "Single Server/Server Balance",
        ]:
            raise ValueError(ErrorMessage.DEPLOYMENT_MODE.value)
        if args["deployment_mode"] == "Single Server/Server Balance" and not args.get(
            "server_pool"
        ):
            raise ValueError(ErrorMessage.SERVER_POOL.value)

    def validate_custom_whitelist(
        self, args: dict[str, Any], member_type: str | None = None
    ):
        """Custom whitelist member args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            DemistoException: Errors.
        """
        if args.get("type") and args["type"] != member_type:
            raise ValueError(
                f"You can't update {args['type']} member with {member_type} update command."
            )
        if member_type == "URL":
            if (
                args.get("request_type") == "Simple String"
                and args.get("request_url")
                and args["request_url"][0] != "/"
            ):
                raise ValueError(ErrorMessage.REQUEST_URL.value)
            if args.get("request_type") and args["request_type"] not in [
                "Simple String",
                "Regular Expression",
            ]:
                raise ValueError(ErrorMessage.REQUEST_TYPE.value)

    def validate_block_period(self, block_period: int | None):
        """Validate the block period argument.

        Args:
            block_period (Optional[int]): Block period input value.
        """
        if block_period is not None and not 1 <= block_period <= 600:
            raise DemistoException(ErrorMessage.BLOCK_PERIOD.value)

    @abstractmethod
    def protected_hostname_create_request(
        self, name: str, default_action: str
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_update_request(
        self, name: str, default_action: str | None
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def get_object_id(
        self,
        create_response: dict[str, Any],
        by_key: str,
        value: str,
        get_request: Callable,
        object_id: str | None = None,
    ) -> str:
        pass

    @abstractmethod
    def protected_hostname_delete_request(self, name: str) -> dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_list_request(self, **kwargs) -> dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_member_create_request(
        self, name: str, host: str, action: str, **kwargs
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_member_update_request(
        self, group_name: str, member_id: str, host: str | None, **kwargs
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_member_delete_request(
        self, group_name: str, member_id: str
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_member_list_request(
        self, group_name: str, **kwargs
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_group_create_request(self, group_name: str, **kwargs) -> dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_group_update_request(self, group_name: str, **kwargs) -> dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_group_delete_request(self, group_name: str) -> dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_group_list_request(self, **kwargs) -> dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_member_create_request(
        self, group_name: str, member_type: str, ip_address: str, **kwargs
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_member_update_request(
        self,
        group_name: str,
        member_id: str,
        member_type: str | None,
        ip_address: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_member_delete_request(
        self, group_name: str, member_id: str
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_member_list_request(self, group_name: str, **kwargs) -> dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_member_add_request(
        self,
        policy_name: str,
        http_content_routing_policy: str,
        is_default: str,
        inherit_webprotection_profile: str,
        **kwargs,
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_member_update_request(
        self,
        policy_name: str,
        member_id: str,
        http_content_routing_policy: str | None,
        is_default: str | None,
        inherit_webprotection_profile: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_member_delete_request(
        self, policy_name: str, member_id: str
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_member_list_request(
        self, policy_name: str, **kwargs
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_group_create_request(
        self,
        name: str,
        severity: str,
        trigger_policy: str | None,
        exception: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_group_update_request(
        self,
        name: str,
        severity: str | None,
        trigger_policy: str | None,
        exception: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_group_delete_request(self, name: str) -> dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_group_list_request(self, **kwargs) -> dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_member_add_request(
        self, group_name: str, countries_list: List[str]
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_member_delete_request(
        self, group_name: str, member_id: str
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_member_list_request(
        self, group_name: str
    ) -> Union[dict[str, Any], List[dict[str, Any]]]:
        pass

    @abstractmethod
    def operation_status_get_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def policy_status_get_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def system_status_get_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def server_pool_list_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def http_service_list_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def inline_protction_profile_list_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def virtual_server_list_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_poicy_list_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def server_policy_create_request(
        self,
        name: str,
        deployment_mode: str,
        virtual_server: str,
        server_pool: str | None,
        protected_hostnames: str | None,
        client_real_ip: str | None,
        syn_cookie: str | None,
        half_open_thresh: str | None,
        http_service: str | None,
        https_service: str | None,
        redirect_to_https: str | None,
        inline_protection_profile: str | None,
        monitor_mode: str | None,
        url_case_sensitivity: str | None,
        comments: str | None,
        match_once: str | None,
        **kwards,
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def server_policy_update_request(
        self,
        name: str,
        deployment_mode: str | None,
        virtual_server: str | None,
        server_pool: str | None,
        protected_hostnames: str | None,
        client_real_ip: str | None,
        syn_cookie: str | None,
        half_open_thresh: str | None,
        http_service: str | None,
        https_service: str | None,
        http2: str | None,
        certificate: str | None,
        intergroup: str | None,
        redirect_to_https: str | None,
        inline_protection_profile: str | None,
        monitor_mode: str | None,
        url_case_sensitivity: str | None,
        comments: str | None,
        match_once: str | None,
        **kwards,
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def server_policy_delete_request(self, policy_name: str) -> dict[str, Any]:
        pass

    @abstractmethod
    def server_policy_list_request(self, **kwargs) -> dict[str, Any]:
        pass

    @abstractmethod
    def custom_whitelist_url_create_request(
        self, request_type: str, request_url: str
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def custom_whitelist_url_update_request(
        self,
        id: str,
        request_type: str | None,
        request_url: str | None,
        status: str | None,
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def custom_whitelist_parameter_create_request(
        self, name: str, **kwargs
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def custom_whitelist_parameter_update_request(
        self, id: str, name: str | None, status: str | None, **kwargs
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def custom_whitelist_cookie_create_request(
        self, name: str, domain: str | None, path: str | None
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def custom_whitelist_cookie_update_request(
        self,
        id: str,
        name: str | None,
        domain: str | None,
        path: str | None,
        status: str | None,
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def custom_whitelist_delete_request(self, id: str) -> dict[str, Any]:
        pass

    @abstractmethod
    def custom_whitelist_list_request(self, **kwargs) -> dict[str, Any]:
        pass

    @abstractmethod
    def geo_exception_list_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def trigger_policy_list_request(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def custom_predifined_whitelist_list_handler(
        self,
        response: Union[dict[str, Any], List[dict[str, Any]]],
        object_type: str | None = None,
    ) -> Union[dict[str, Any], List[dict[str, Any]]]:
        pass

    @abstractmethod
    def custom_predifined_whitelist_list_request(
        self,
    ) -> Union[dict[str, Any], List[dict[str, Any]]]:
        pass

    @abstractmethod
    def custom_predifined_whitelist_update_request(
        self, data: dict[str, Any]
    ) -> dict[str, Any]:
        pass

    @abstractmethod
    def certificate_intermediate_group_list_request(self) -> dict[str, Any]:
        pass


class ClientV1(Client):
    """Fortiweb VM V1 Client

    Args:
        Client (Client): Client class with abstract functions.
    """

    API_VER = "V1"

    URL_TYPE = 1
    PARAMETER_TYPE = 2
    COOKIE_TYPE = 3

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        version: str,
        proxy: bool,
        verify: bool,
    ):
        endpoint_prefix = "api/v1.0/"
        api_key = self.encode_api_key(username=username, password=password)
        super().__init__(
            base_url=base_url,
            api_key=api_key,
            version=version,
            endpoint_prefix=endpoint_prefix,
            proxy=proxy,
            verify=verify,
        )


    def encode_api_key(self, username: str, password: str):
        to_encode = f"{username}:{password}:root"
        return b64_encode(to_encode)

    @property
    def not_exist_error_list(self) -> List[str]:
        """Sends not exists errors in Fortiweb V1.

        Returns:
            List[str]: Fortiweb V1 error messages when values do not exist in the system.
        """
        return ["Entry not found.", "Invalid length of value."]

    @property
    def exist_error_list(self) -> List[str]:
        """Sends exists errors in Fortiweb V1.

        Returns:
            List[str]: Fortiweb V1 error messages when values exist in the system.
        """
        return [
            "A duplicate entry already exists.",
            "The IP has already existed in the table.",
            "The name of the policy has already existed",
        ]

    @property
    def wrong_parameter_error_list(self) -> List[str]:
        """Sends wrong parameters errors in Fortiweb V1.

        Returns:
            List[str]: Fortiweb V1 error messages when parameter are wrong.
        """
        return ["Empty values are not allowed."]

    def get_error_data(self, error: dict) -> Union[int, str]:
        """Extracts error value from Fortiweb V1 error response.

        Args:
            error (dict): Error response from Fortiweb V1.

        Returns:
            Union[int,str]: Error value.
        """
        return error["msg"]

    def validate_update_ip_list_group(self, args: dict[str, Any]):
        """IP list group args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            ValueError: Errors.
        """
        raise ValueError(ErrorMessage.V1_NOT_SUPPORTED.value)

    def validate_ip_list_member(self, args: dict[str, Any]):
        """IP list member args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            ValueError: Errors.
        """
        super().validate_ip_list_member(args)
        if args.get("type") and args["type"] == "Allow Only Ip":
            raise ValueError(ErrorMessage.ALLOW_IP_V1.value)

    def get_object_id(
        self,
        create_response: dict[str, Any],
        by_key: str,
        value: str,
        get_request: Callable,
        object_id: str | None = None,
    ) -> str:
        """Get object / sub object id for Fortiweb V1.

        Args:
            client (Client): Fortiweb VM Client. (For Fortiweb V1)
            create_response (Dict[str, Any]): Response from create request. (For Fortiweb V2)
            by_key (str): Unique key to search the sub object. (For Fortiweb V1)
            value (str): The sub object value to the key. (For Fortiweb V1)
            get_request (Callable): Get request (for Fortiweb VM 1)
            object_id (Optional[str]): Object ID (not sub object)! (For Fortiweb V1)

        Returns:
            str: Member ID
        """
        member_data = get_object_data(
            self.version, by_key, value, get_request, object_id
        )
        return member_data["_id"] if member_data else "Can not find the id"

    def protected_hostname_create_request(
        self, name: str, default_action: str
    ) -> dict[str, Any]:
        """Create a new protected hostname.

        Args:
            name (str): Protected hostname name.
            default_action (int): Http requests action. (allow,deny and no log,deny)

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        data = {
            "name": name,
            "defaultAction": self.parser.action_user_to_api_mapper[default_action],
        }
        return self._http_request(
            method="POST",
            url_suffix="ServerObjects/ProtectedHostnames/ProtectedHostnames",
            json_data=data,
        )

    def protected_hostname_update_request(
        self, name: str, default_action: str | None
    ) -> dict[str, Any]:
        """Update a protected hostname.

        Args:
            name (str): Protected hostname name.
            action (int): Http requests action. (allow,deny and no log,deny)

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        data = remove_empty_elements(
            {
                "name": name,
                "defaultAction": dict_safe_get(
                    self.parser.action_user_to_api_mapper.get,
                    [default_action],
                ),
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix=f"ServerObjects/ProtectedHostnames/ProtectedHostnames/{name}",
            json_data=data,
        )

    def protected_hostname_delete_request(self, name: str) -> dict[str, Any]:
        """Delete a protected hostname.

        Args:
            name (str): Protected hostname name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        return self._http_request(
            method="DELETE",
            url_suffix=f"ServerObjects/ProtectedHostnames/ProtectedHostnames/{name}",
        )

    def protected_hostname_list_request(self, **kwargs) -> dict[str, Any]:
        """Get protected hostnames.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        return self._http_request(
            method="GET",
            url_suffix="ServerObjects/ProtectedHostnames/ProtectedHostnames",
        )

    def protected_hostname_member_create_request(
        self, name: str, host: str, action: str, **kwargs
    ) -> dict[str, Any]:
        """Create a new protected hostname member.

        Args:
            protected_hostname_group (str): Protected hostname group.
            host (str): IP address or FQDN of a virtual or real web host.
            action (str): Select whether to accept or deny HTTP requests whose Host.
        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        endpoint = f"ServerObjects/ProtectedHostnames/ProtectedHostnames/{name}/ProtectedHostnamesNewHost"
        data = {
            "action": self.parser.action_user_to_api_mapper[action],
            "host": host,
        }
        return self._http_request(method="POST", url_suffix=endpoint, json_data=data)

    def protected_hostname_member_update_request(
        self, group_name: str, member_id: str, host: str | None, **kwargs
    ) -> dict[str, Any]:
        """Update a protected hostname member.

        Args:
            group_name (str): Protected hostname group id.
            member_id (str): Protected hostname member id
            host (Optional[str]): IP address or FQDN of a virtual or real web host.
            kwargs (optional): action (str): Action.
        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        edp = f"ServerObjects/ProtectedHostnames/ProtectedHostnames/{group_name}/ProtectedHostnamesNewHost/{member_id}"

        data = remove_empty_elements(
            {
                "host": host,
                "action": dict_safe_get(
                    self.parser.action_user_to_api_mapper,
                    [kwargs.get("action")],
                ),
            }
        )
        return self._http_request(method="PUT", url_suffix=edp, json_data=data)

    def protected_hostname_member_delete_request(
        self, group_name: str, member_id: str
    ) -> dict[str, Any]:
        """Delete a protected hostname member.

        Args:
            group_name (str): Protected hostname group id.
            member_id (str): Protected hostname member id.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        endpoint = f"ServerObjects/ProtectedHostnames/ProtectedHostnames/{group_name}/ProtectedHostnamesNewHost/{member_id}"
        return self._http_request(method="DELETE", url_suffix=endpoint)

    def protected_hostname_member_list_request(
        self, group_name: str, **kwargs
    ) -> dict[str, Any]:
        """List protected hostname members.

        Args:
            group_name (str): Protected hostname group id.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"ServerObjects/ProtectedHostnames/ProtectedHostnames/{group_name}/ProtectedHostnamesNewHost",
        )

    def ip_list_group_create_request(self, group_name: str, **kwargs) -> dict[str, Any]:
        """Create a new ip list group.

        Args:
            group_name (str): IP list group name.
            kwargs: page: Page Number.
            kwargs: page_size: Page Size Number.
            kwargs: Limit: Limit Number.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        data = {"name": group_name}
        return self._http_request(
            method="POST", url_suffix="WebProtection/Access/IPList", json_data=data
        )

    def ip_list_group_update_request(self, group_name: str, **kwargs) -> dict[str, Any]:
        """Update an ip list group.

        Args:
            group_name (str): IP list group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        raise NotImplementedError(ErrorMessage.V1_NOT_SUPPORTED.value)

    def ip_list_group_delete_request(self, group_name: str) -> dict[str, Any]:
        """Delete a ip list group.

        Args:
            group_name (str): IP List group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f"WebProtection/Access/IPList/{group_name}"
        return self._http_request(method="DELETE", url_suffix=endpoint)

    def ip_list_group_list_request(self, **kwargs) -> dict[str, Any]:
        """List the IP list groups.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="WebProtection/Access/IPList"
        )

    def ip_list_member_create_request(
        self, group_name: str, member_type: str, ip_address: str, **kwargs
    ) -> dict[str, Any]:
        """Create an IP list member.

        Args:
            group_name (str): IP list group name.
            member_type (str): IP list member type.
            ip_address (str): IP address.
            kwargs: severity: Severity.
            kwargs: trigger_policy: Trigger Policy.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = {
            "type": dict_safe_get(self.parser.type_user_to_api_mapper, [member_type]),
            "iPv4IPv6": ip_address,
        }
        if member_type == "Black IP":
            data.update(
                remove_empty_elements(
                    {
                        "severity": dict_safe_get(
                            self.parser.severity_user_to_api_mapper,
                            [kwargs.get("severity")],
                        ),
                        "triggerPolicy": kwargs.get("trigger_policy"),
                    }
                )
            )
        return self._http_request(
            method="POST",
            url_suffix=f"WebProtection/Access/IPList/{group_name}/IPListCreateIPListPolicyMember",
            json_data=data,
        )

    def ip_list_member_update_request(
        self,
        group_name: str,
        member_id: str,
        member_type: str | None,
        ip_address: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        """Update an IP list member.

        Args:
            group_name (str): IP list group name.
            member_id (str): IP list member ID.
            member_type (str): IP list member type.
            ip_address (str): IP address.
            kwargs: severity: Severity.
            kwargs: trigger_policy: Trigger Policy.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements(
            {
                "iPv4IPv6": ip_address,
                "type": dict_safe_get(
                    self.parser.type_user_to_api_mapper,
                    [member_type],
                ),
            }
        )
        if member_type == "Black IP":
            data.update(
                remove_empty_elements(
                    {
                        "severity": dict_safe_get(
                            self.parser.severity_user_to_api_mapper,
                            [kwargs.get("severity")],
                        ),
                        "triggerPolicy": kwargs.get("trigger_policy"),
                    }
                )
            )
        return self._http_request(
            method="PUT",
            url_suffix=f"WebProtection/Access/IPList/{group_name}/IPListCreateIPListPolicyMember/{member_id}",
            json_data=data,
        )

    def ip_list_member_delete_request(
        self, group_name: str, member_id: str
    ) -> dict[str, Any]:
        """Delete an IP list member.

        Args:
            group_name (str): IP list group name.
            member_id (str): IP list member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f"WebProtection/Access/IPList/{group_name}/IPListCreateIPListPolicyMember/{member_id}"
        return self._http_request(method="DELETE", url_suffix=endpoint)

    def ip_list_member_list_request(self, group_name: str, **kwargs) -> dict[str, Any]:
        """List IP list members.

        Args:
            group_name (str): IP list group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET",
            url_suffix=f"WebProtection/Access/IPList/{group_name}/IPListCreateIPListPolicyMember",
        )

    def http_content_routing_member_add_request(
        self,
        policy_name: str,
        http_content_routing_policy: str,
        is_default: str,
        inherit_webprotection_profile: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Add a new HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            http_content_routing_policy (str): HTTP content routing policy name.
            is_default (str): Is default flag.
            inherit_webprotection_profile (str): Enable inherit web protection profile.
            kwargs: profile (str): Web protection profile.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements(
            {
                "http_content_routing_policy": http_content_routing_policy,
                "defaultpage": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [is_default]
                ),
                "inheritWebProtectionProfile": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper,
                    [inherit_webprotection_profile],
                ),
                "profile": kwargs.get("profile"),
            }
        )
        return self._http_request(
            method="POST",
            url_suffix=f"Policy/ServerPolicy/ServerPolicy/{policy_name}/EditContentRouting",
            json_data=data,
        )

    def http_content_routing_member_update_request(
        self,
        policy_name: str,
        member_id: str,
        http_content_routing_policy: str | None,
        is_default: str | None,
        inherit_webprotection_profile: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        """Update an HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            member_id (str): Member ID.
            http_content_routing_policy (str): HTTP content routing policy name.
            is_default (str): Is default flag.
            specified in the HTTP content routing policies?
            inherit_webprotection_profile (str): Enable inherit web protection profile..
            kwargs: profile (str): Web protection profile.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements(
            {
                "http_content_routing_policy": http_content_routing_policy,
                "defaultpage": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [is_default]
                ),
                "inheritWebProtectionProfile": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper,
                    [inherit_webprotection_profile],
                ),
                "profile": kwargs.get("profile"),
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix=f"Policy/ServerPolicy/ServerPolicy/{policy_name}/EditContentRouting/{member_id}",
            json_data=data,
        )

    def http_content_routing_member_delete_request(
        self, policy_name: str, member_id: str
    ) -> dict[str, Any]:
        """Delete an HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            member_id (str): Member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="DELETE",
            url_suffix=f"Policy/ServerPolicy/ServerPolicy/{policy_name}/EditContentRouting/{member_id}",
        )

    def http_content_routing_member_list_request(
        self, policy_name: str, **kwargs
    ) -> dict[str, Any]:
        """List HTTP content routing members.

        Args:
            policy_name (str): Server policy name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET",
            url_suffix=f"Policy/ServerPolicy/ServerPolicy/{policy_name}/EditContentRouting",
        )

    def geo_ip_group_create_request(
        self,
        name: str,
        severity: str,
        trigger_policy: str | None,
        exception: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        """Create a new Geo IP group.

        Args:
            name (str): Geo IP group name.
            severity (str): Severity.
            trigger_policy (Optional[str]): Trigger policy.
            exception (Optional[str]): Exception rule.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements(
            {
                "name": name,
                "severity": dict_safe_get(
                    self.parser.severity_user_to_api_mapper, [severity]
                ),
                "triggerPolicy": trigger_policy,
                "except": exception,
            }
        )
        return self._http_request(
            method="POST", url_suffix="WebProtection/Access/GeoIP", json_data=data
        )

    def geo_ip_group_update_request(
        self,
        name: str,
        severity: str | None,
        trigger_policy: str | None,
        exception: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        """Update a Geo IP group.

        Args:
            name (str): Geo IP group name.
            severity (Optional[str]): Severity.
            trigger_policy (Optional[str]): Trigger policy.
            exception (Optional[str]): Exception rule.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements(
            {
                "severity": dict_safe_get(
                    self.parser.severity_user_to_api_mapper, [severity]
                ),
                "triggerPolicy": trigger_policy,
                "except": exception,
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix=f"WebProtection/Access/GeoIP/{name}",
            json_data=data,
        )

    def geo_ip_group_delete_request(self, name: str) -> dict[str, Any]:
        """Delete Geo IP group.

        Args:
            name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """

        endpoint = f"WebProtection/Access/GeoIP/{name}"
        return self._http_request(method="DELETE", url_suffix=endpoint)

    def geo_ip_group_list_request(self, **kwargs) -> dict[str, Any]:
        """List the Geo IP groups.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method="GET", url_suffix="WebProtection/Access/GeoIP")

    def geo_ip_member_add_request(
        self, group_name: str, countries_list: List[str]
    ) -> dict[str, Any]:
        """Add a new Geo IP member.

        Args:
            group_name (str): Geo IP group name.
            countries_list (List[str]): List of countries to add.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = {"picker": countries_list}
        return self._http_request(
            method="POST",
            url_suffix=f"WebProtection/Access/GeoIP/{group_name}/AddCountry",
            json_data=data,
        )

    def geo_ip_member_delete_request(
        self, group_name: str, member_id: str
    ) -> dict[str, Any]:
        """Delete a new Geo IP member.

        Args:
            group_name (str): Geo IP group name.
            member_id (str): Geo IP member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f"WebProtection/Access/GeoIP/{group_name}/AddCountry/{member_id}"
        return self._http_request(method="DELETE", url_suffix=endpoint)

    def geo_ip_member_list_request(self, group_name: str) -> List[dict[str, Any]]:
        """List the Geo IP members.

        Args:
            group_name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f"WebProtection/Access/GeoIP/{group_name}/AddCountry"
        return self._http_request(method="GET", url_suffix=endpoint)

    def operation_status_get_request(self) -> dict[str, Any]:
        """Gets operation status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="System/Status/StatusOperation"
        )

    def policy_status_get_request(self) -> dict[str, Any]:
        """Gets policy status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method="GET", url_suffix="System/Status/PolicyStatus")

    def system_status_get_request(self) -> dict[str, Any]:
        """Gets system status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method="GET", url_suffix="System/Status/Status")

    def server_pool_list_request(self) -> dict[str, Any]:
        """List the Server pools.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="ServerObjects/Server/ServerPool"
        )

    def http_service_list_request(self) -> dict[str, Any]:
        """List the HTTP services.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="ServerObjects/Service/HttpServiceList"
        )

    def inline_protction_profile_list_request(self) -> dict[str, Any]:
        """List the Inline protection profiles.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET",
            url_suffix="Policy/WebProtectionProfile/InlineProtectionProfile",
        )

    def virtual_server_list_request(self) -> dict[str, Any]:
        """List the Virtual servers.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="ServerObjects/Server/VirtualServer"
        )

    def http_content_routing_poicy_list_request(self) -> dict[str, Any]:
        """List the HTTP content routing policies.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="ServerObjects/Server/HTTPContentRoutingPolicy"
        )

    def server_policy_data_builder(
        self,
        name: str,
        deployment_mode: str | None,
        virtual_server: str | None,
        server_pool: str | None,
        protected_hostnames: str | None,
        client_real_ip: str | None,
        syn_cookie: str | None,
        half_open_thresh: str | None,
        http_service: str | None,
        https_service: str | None,
        redirect_to_https: str | None,
        inline_protection_profile: str | None,
        monitor_mode: str | None,
        url_case_sensitivity: str | None,
        comments: str | None,
        match_once: str | None,
        http2: str | None = None,
        intergroup: str | None = None,
        certificate: str | None = None,
    ) -> dict[str, Any]:
        data = remove_empty_elements(
            {
                "name": name,
                "depInMode": dict_safe_get(
                    self.parser.deployment_mode_user_to_api_mapper, [deployment_mode]
                ),
                "virtualServer": virtual_server,
                "serverPool": server_pool,
                "protectedHostnames": protected_hostnames,
                "clientRealIP": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [client_real_ip]
                ),
                "syncookie": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [syn_cookie]
                ),
                "halfopenThresh": half_open_thresh,
                "HTTPService": http_service,
                "HTTPSService": https_service,
                "http2": dict_safe_get(self.parser.boolean_user_to_api_mapper, [http2]),
                "sslprotocols": {"tls_v10": 0, "tls_v11": 0, "tls_v12": 1},
                "local": certificate,
                "hRedirectoHttps": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [redirect_to_https]
                ),
                "InlineProtectionProfile": inline_protection_profile,
                "MonitorMode": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [monitor_mode]
                ),
                "URLCaseSensitivity": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [url_case_sensitivity]
                ),
                "comments": comments,
                # HTTP content routing deployment mode
                "prefer_cur_session": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [match_once]
                ),
                "intergroup": intergroup,
            }
        )
        return data

    def server_policy_create_request(
        self,
        name: str,
        deployment_mode: str,
        virtual_server: str,
        server_pool: str | None,
        protected_hostnames: str | None,
        client_real_ip: str | None,
        syn_cookie: str | None,
        half_open_thresh: str | None,
        http_service: str | None,
        https_service: str | None,
        redirect_to_https: str | None,
        inline_protection_profile: str | None,
        monitor_mode: str | None,
        url_case_sensitivity: str | None,
        comments: str | None,
        match_once: str | None,
        **kwards,
    ) -> dict[str, Any]:
        """Create server policy.

        Args:
            name (str): Server policy name.
            deployment_mode (str): Deployment mode.
            virtual_server (str): Virtual server name.
            server_pool (Optional[str]): Server pool name.
            protected_hostnames (Optional[str]): Protected hostname group name.
            client_real_ip (Optional[str]): Client real IP.
            syn_cookie (Optional[str]): Sync cookie.
            half_open_thresh (Optional[str]): Half open threshold number.
            http_service (Optional[str]): HTTP service name.
            https_service (Optional[str]): HTTPS service name.
            http2 (Optional[str]): HTTP2 flag.
            redirect_to_https (Optional[str]): Redirect to HTTPS.
            inline_protection_profile (Optional[str]): Profile.
            monitor_mode (Optional[str]): Monitor mode flag.
            url_case_sensitivity (Optional[str]): URL case sensitivity flag.
            comments (Optional[str]): Comments.
            match_once (Optional[str]): Match once flag.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = self.server_policy_data_builder(
            name=name,
            deployment_mode=deployment_mode,
            virtual_server=virtual_server,
            server_pool=server_pool,
            protected_hostnames=protected_hostnames,
            client_real_ip=client_real_ip,
            syn_cookie=syn_cookie,
            half_open_thresh=half_open_thresh,
            http_service=http_service,
            https_service=https_service,
            redirect_to_https=redirect_to_https,
            inline_protection_profile=inline_protection_profile,
            monitor_mode=monitor_mode,
            url_case_sensitivity=url_case_sensitivity,
            comments=comments,
            match_once=match_once,
        )
        return self._http_request(
            method="POST", url_suffix="Policy/ServerPolicy/ServerPolicy", json_data=data
        )

    def server_policy_update_request(
        self,
        name: str,
        deployment_mode: str | None,
        virtual_server: str | None,
        server_pool: str | None,
        protected_hostnames: str | None,
        client_real_ip: str | None,
        syn_cookie: str | None,
        half_open_thresh: str | None,
        http_service: str | None,
        https_service: str | None,
        http2: str | None,
        certificate: str | None,
        intergroup: str | None,
        redirect_to_https: str | None,
        inline_protection_profile: str | None,
        monitor_mode: str | None,
        url_case_sensitivity: str | None,
        comments: str | None,
        match_once: str | None,
        **kwards,
    ) -> dict[str, Any]:
        """Create server policy.

        Args:
            name (str): Server policy name.
            deployment_mode (str): Deployment mode.
            virtual_server (str): Virtual server name.
            server_pool (Optional[str]): Server pool name.
            protected_hostnames (Optional[str]): Protected hostname group name.
            client_real_ip (Optional[str]): Client real IP.
            syn_cookie (Optional[str]): Sync cookie.
            half_open_thresh (Optional[str]): Half open threshold number.
            http_service (Optional[str]): HTTP service name.
            https_service (Optional[str]): HTTPS service name.
            http2 (Optional[str]): HTTP2 flag.
            multi_certificate (Optional[str]): Multi certificate name.
            certificate_group (Optional[str]): Certificate group name.
            certificate (Optional[str]): certificate name.
            intergroup (Optional[str]): Certificate Intermediate Group name
            proxy (Optional[str]): Proxy boolean.
            redirect_to_https (Optional[str]): Redirect to HTTPS.
            inline_protection_profile (Optional[str]): Profile.
            monitor_mode (Optional[str]): Monitor mode flag.
            url_case_sensitivity (Optional[str]): URL case sensitivity flag.
            comments (Optional[str]): Comments.
            match_once (Optional[str]): Match once flag.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = self.server_policy_data_builder(
            name=name,
            deployment_mode=deployment_mode,
            virtual_server=virtual_server,
            server_pool=server_pool,
            protected_hostnames=protected_hostnames,
            client_real_ip=client_real_ip,
            syn_cookie=syn_cookie,
            half_open_thresh=half_open_thresh,
            http_service=http_service,
            https_service=https_service,
            http2=http2,
            redirect_to_https=redirect_to_https,
            inline_protection_profile=inline_protection_profile,
            monitor_mode=monitor_mode,
            url_case_sensitivity=url_case_sensitivity,
            comments=comments,
            match_once=match_once,
            certificate=certificate,
            intergroup=intergroup,
        )
        return self._http_request(
            method="PUT",
            url_suffix=f"Policy/ServerPolicy/ServerPolicy/{name}",
            json_data=data,
        )

    def server_policy_delete_request(self, policy_name: str) -> dict[str, Any]:
        """Delete server policy.

        Args:
            policy_name (str): Server policy name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f"Policy/ServerPolicy/ServerPolicy/{policy_name}"
        return self._http_request(method="DELETE", url_suffix=endpoint)

    def server_policy_list_request(self, **kwargs) -> dict[str, Any]:
        """List server policies.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="Policy/ServerPolicy/ServerPolicy"
        )

    def custom_whitelist_url_create_request(
        self, request_type: str, request_url: str
    ) -> dict[str, Any]:
        """Create Custom whitelist url member.

        Args:
            request_type (str): Request type.
            request_url (str): Request url.
            status (str): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = {
            "type": self.URL_TYPE,
            "requestType": dict_safe_get(
                self.parser.request_type_user_to_api_mapper, [request_type]
            ),
            "requestURL": request_url,
            "enable": True,
        }
        return self._http_request(
            method="POST",
            url_suffix="ServerObjects/Global/CustomGlobalWhiteList",
            json_data=data,
        )

    def custom_whitelist_url_update_request(
        self,
        id: str,
        request_type: str | None,
        request_url: str | None,
        status: str | None,
    ) -> dict[str, Any]:
        """Create Custom whitelist url member.

        Args:
            id (str): Custom whitelist url member.
            request_type (str): Request type.
            request_url (str): Request url.
            status (str): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements(
            {
                "type": 1,
                "requestType": dict_safe_get(
                    self.parser.request_type_user_to_api_mapper, [request_type]
                ),
                "requestURL": request_url,
                "status": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [status]
                ),
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix=f"ServerObjects/Global/CustomGlobalWhiteList/{id}",
            json_data=data,
        )

    def custom_whitelist_list_request(self, **kwargs) -> dict[str, Any]:
        """List custom whitelist members.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="ServerObjects/Global/CustomGlobalWhiteList"
        )

    def custom_whitelist_parameter_create_request(
        self, name: str, **kwargs
    ) -> dict[str, Any]:
        """Create custom whitelist parameter member.

        Args:
            name (str): Name.
            status (str): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = {
            "type": 2,
            "itemName": name,
        }
        return self._http_request(
            method="POST",
            url_suffix="ServerObjects/Global/CustomGlobalWhiteList",
            json_data=data,
        )

    def custom_whitelist_parameter_update_request(
        self, id: str, name: str | None, status: str | None, **kwargs
    ) -> dict[str, Any]:
        """Update a custom whitelist parameter member.

        Args:
            id (str): Custom whitelist parameter member.
            name (Optional[str]): Name.
            status (Optional[str]): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements(
            {
                "type": self.PARAMETER_TYPE,
                "itemName": name,
                "status": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [status]
                ),
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix=f"ServerObjects/Global/CustomGlobalWhiteList/{id}",
            json_data=data,
        )

    def custom_whitelist_cookie_create_request(
        self, name: str, domain: str | None, path: str | None
    ) -> dict[str, Any]:
        """Create custom whitelist cookie member.

        Args:
            name (str): Name.
            domain (Optional[str]): Domain.
            path (Optional[str]): Path.
            status (str): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements(
            {
                "type": self.COOKIE_TYPE,
                "itemName": name,
                "domain": domain,
                "path": path,
            }
        )
        return self._http_request(
            method="POST",
            url_suffix="ServerObjects/Global/CustomGlobalWhiteList",
            json_data=data,
        )

    def custom_whitelist_cookie_update_request(
        self,
        id: str,
        name: str | None,
        domain: str | None,
        path: str | None,
        status: str | None,
    ) -> dict[str, Any]:
        """Update a custom whitelist cookie member.

        Args:
            id (str): Custom whitelist cookie member.
            name (Optional[str]): Name.
            domain (Optional[str]): Domain.
            path (Optional[str]): Path.
            status (Optional[str]): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        data = remove_empty_elements(
            {
                "type": 3,
                "itemName": name,
                "domain": domain,
                "path": path,
                "status": dict_safe_get(
                    self.parser.boolean_user_to_api_mapper, [status]
                ),
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix=f"ServerObjects/Global/CustomGlobalWhiteList/{id}",
            json_data=data,
        )

    def custom_whitelist_delete_request(self, id: str) -> dict[str, Any]:
        """Delete a custom whitelist member.

        Args:
            id (str): Delete a custom whitelist member.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f"ServerObjects/Global/CustomGlobalWhiteList/{id}"
        return self._http_request(method="DELETE", url_suffix=endpoint)

    def geo_exception_list_request(self) -> dict[str, Any]:
        """List the Geo IP Exception.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="WebProtection/Access/GeoIPExceptionsList"
        )

    def trigger_policy_list_request(self) -> dict[str, Any]:
        """List the Trigger Policies.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="LogReport/LogPolicy/TriggerList"
        )

    def custom_predifined_whitelist_list_handler(
        self,
        response: Union[dict[str, Any], List[dict[str, Any]]],
        object_type: str | None = None,
    ) -> Union[dict[str, Any], List[dict[str, Any]]]:
        if isinstance(response, list):
            data = response
            if object_type:
                return dict_safe_get(
                    find_dict_in_array(data, "type", object_type), ["details"]
                )
            else:
                return [
                    member for object_type in data for member in object_type["details"]
                ]
        return []

    def custom_predifined_whitelist_list_request(self) -> List[dict[str, Any]]:
        """List the Custom Predifined members.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET",
            url_suffix="ServerObjects/Global/CustomPredefinedGlobalWhiteList",
        )

    def custom_predifined_whitelist_update_request(
        self, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Update a Custom Predifined members.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="PUT",
            url_suffix="ServerObjects/Global/CustomPredefinedGlobalWhiteList",
            json_data=data,
        )

    def certificate_intermediate_group_list_request(self) -> dict[str, Any]:
        """List the Certificate intermediate groups.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET", url_suffix="System/Certificates/InterCAGroupList"
        )


class ClientV2(Client):
    """Fortiweb VM V2 Client

    Args:
        Client (Client): Client class with abstract functions.
    """

    API_VER = "V2"

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        version: str,
        proxy: bool,
        verify: bool,
    ):
        api_key = self.encode_api_key(username=username, password=password)
        super().__init__(
            base_url=base_url,
            api_key=api_key,
            version=version,
            endpoint_prefix="api/v2.0/",
            proxy=proxy,
            verify=verify,
        )

    def encode_api_key(self, username: str, password: str) -> str:
        """Encode username, password to Fortiweb V2 API key.

        Args:
            username (str): Username.
            password (str): Password.

        Returns:
            str: API key.
        """
        to_encode = (
            "{" + f'"username":"{username}","password":"{password}","vdom":"root"' + "}"
        )
        return b64_encode(to_encode)

    @property
    def not_exist_error_list(self) -> List[int]:
        """Sends not exists errors in Fortiweb V2.

        Returns:
            List[int]: Fortiweb V2 error codes for when values do not exist in the system.
        """
        return [-3, 0, -1, -23]

    @property
    def exist_error_list(self) -> List[int]:
        """Sends exists errors in Fortiweb V2.

        Returns:
            List[int]: Fortiweb V2 error codes for when values exist in the system.
        """
        return [-5, -6014]

    @property
    def wrong_parameter_error_list(self) -> List[int]:
        """Sends wrong parameters errors in Fortiweb V2.

        Returns:
            List[int]: Fortiweb V2 error codes for when parameter are wrong.
        """
        return [-651]

    def get_error_data(self, error: dict) -> Union[int, str]:
        """Extracts error value from Fortiweb V2 error response.

        Args:
            error (dict): Error response from Fortiweb V2.

        Returns:
            Union[int,str]: Error value.
        """
        return dict_safe_get(error, ["results", "errcode"]) or dict_safe_get(
            error, ["results", "pingResult"]
        )

    def get_object_id(
        self,
        create_response: dict[str, Any],
        by_key: str,
        value: str,
        get_request: Callable,
        object_id: str | None = None,
    ) -> str:
        """Get object / sub object id for Fortiweb V2.

        Args:
            client (Client): Fortiweb VM Client. (For Fortiweb V1)
            create_response (Dict[str, Any]): Response from create request. (For Fortiweb V2)
            by_key (str): Unique key to search the sub object. (For Fortiweb V1)
            value (str): The sub object value to the key. (For Fortiweb V1)
            get_request (Callable): Get request (for Fortiweb VM 1)
            object_id (Optional[str]): Object ID (not sub object)! (For Fortiweb V1)

        Returns:
            str: Member ID
        """
        return create_response["results"]["id"]

    def validate_ip_list_group(self, args: dict[str, Any]):
        """IP list group args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            ValueError: Errors.
        """
        super().validate_ip_list_group(args)
        block_period = arg_to_number(args.get("block_period"))
        if block_period is not None and block_period and not 1 <= block_period <= 600:
            raise ValueError(ErrorMessage.BLOCK_PERIOD.value)

    def validate_geo_ip_group(self, args: dict[str, Any]):
        """Geo IP Group args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            ValueError: Errors.
        """
        super().validate_geo_ip_group(args)
        block_period = arg_to_number(args.get("block_period"))
        if block_period and not 1 <= block_period <= 600:
            raise ValueError(ErrorMessage.BLOCK_PERIOD.value)

    def validate_server_policy(self, args: dict[str, Any]):
        """Validate argument for server policy.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Returns:
            CommandResults: outputs, readable outputs and raw response for XSOAR.
        """
        super().validate_server_policy(args)
        scripting = args.get("scripting")
        if args.get("scripting") and args["scripting"] not in ["enable", "disable"]:
            raise ValueError(ErrorMessage.SCRIPTING.value)
        scripting_list = args.get("scripting_list")
        if scripting == "enable" and not scripting_list:
            raise ValueError(ErrorMessage.SCRIPTING_LIST.value)
        if args.get("certificate_type") and args["certificate_type"] not in [
            "Local",
            "Multi Certificate",
            "Letsencrypt",
        ]:
            raise ValueError(ErrorMessage.CERTIFICATE_TYPE.value)
        if args.get("client_real_ip") and args["client_real_ip"] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.CLIENT_REAL_IP.value)
        if args.get("match_once") and args["match_once"] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.MATCH_ONCE.value)
        if args.get("monitor_mode") and args["monitor_mode"] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.MONITOR_MODE.value)
        if args.get("redirect_to_https") and args["redirect_to_https"] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.REDIRECT_2_HTTPS.value)
        if args.get("retry_on") and args["retry_on"] not in ["enable", "disable"]:
            raise ValueError(ErrorMessage.RETRY_ON.value)
        if args.get("retry_on_http_layer") and args["retry_on_http_layer"] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.RETRY_ON_HTTP_LAYER.value)
        if args.get("retry_on_connect_failure") and args[
            "retry_on_connect_failure"
        ] not in ["enable", "disable"]:
            raise ValueError(ErrorMessage.RETRY_ON_CONNECT_FAILURE.value)
        if args.get("syn_cookie") and args["syn_cookie"] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.SYN_COOKIE.value)
        if args.get("url_case_sensitivity") and args["url_case_sensitivity"] not in [
            "enable",
            "disable",
        ]:
            raise ValueError(ErrorMessage.URL_CASE_SENSITIVITY.value)
        half_open_thresh = arg_to_number(args.get("half_open_thresh"))
        if half_open_thresh and not 10 <= half_open_thresh <= 10000:
            raise ValueError(ErrorMessage.HALF_OPEN_THRESH.value)
        arg_to_number(args.get("retry_on_cache_size"))
        retry_times_on_connect_failure = arg_to_number(
            args.get("retry_times_on_connect_failure")
        )
        if (
            retry_times_on_connect_failure
            and not 1 <= retry_times_on_connect_failure <= 5
        ):
            raise ValueError(ErrorMessage.RETRY_TIMES_ON_CONNECT.value)
        retry_times_on_http_layer = arg_to_number(args.get("retry_times_on_http_layer"))
        if retry_times_on_http_layer and not 1 <= retry_times_on_http_layer <= 5:
            raise ValueError(ErrorMessage.RETRY_TIMES_ON_HTTP.value)
        retry_on_http_response_codes = [
            arg_to_number(code)
            for code in argToList(args.get("retry_on_http_response_codes"))
        ]
        if not set(retry_on_http_response_codes).issubset(
            [404, 408, 500, 501, 502, 503, 504]
        ):
            raise ValueError(ErrorMessage.RETRY_ON_HTTP_RESPONSE_CODES.value)

    def validate_custom_whitelist(
        self, args: dict[str, Any], member_type: str | None = None
    ):
        """Custom whitelist member args validator.

        Args:
            args (Dict[str, Any]): Command arguments from XSOAR.

        Raises:
            DemistoException: Errors.
        """
        super().validate_custom_whitelist(args, member_type)
        if args.get("request_url_status") == "enable" and not args.get("request_url"):
            raise ValueError(ErrorMessage.REQUEST_URL_INSERT.value)
        if args.get("domain_status") == "enable" and not args.get("domain"):
            raise ValueError(ErrorMessage.DOMAIN_INSERT.value)
        if args.get("value_status") == "enable" and not args.get("value"):
            raise ValueError(ErrorMessage.VALUE_INSERT.value)

        if member_type == "Parameter":
            if args.get("name_type") and args["name_type"] not in [
                "Simple String",
                "Regular Expression",
            ]:
                raise ValueError(ErrorMessage.NAME_TYPE.value)
            if args.get("request_status") and args["request_status"] == "enable":
                if args.get("request_type") and args["request_type"] not in [
                    "Simple String",
                    "Regular Expression",
                ]:
                    raise ValueError(ErrorMessage.REQUEST_TYPE.value)
                if (
                    args.get("request_type") == "Simple String"
                    and args.get("request_url")
                    and args["request_url"][0] != "/"
                ):
                    raise ValueError(ErrorMessage.REQUEST_URL.value)
            if args.get("domain_status") and args["domain_status"] == "enable":
                if args.get("domain_type") and args["domain_type"] not in [
                    "Simple String",
                    "Regular Expression",
                ]:
                    raise ValueError(ErrorMessage.DOMAIN_TYPE.value)
        if member_type == "Header Field":
            if args.get("header_name_type") and args["header_name_type"] not in [
                "Simple String",
                "Regular Expression",
            ]:
                raise ValueError(ErrorMessage.HEADER_NAME_TYPE.value)
            if args.get("value_status") and args["value_status"] == "enable":
                if args.get("header_value_type") and args["header_value_type"] not in [
                    "Simple String",
                    "Regular Expression",
                ]:
                    raise ValueError(ErrorMessage.HEADER_VALUE_TYPE.value)

    def protected_hostname_create_request(
        self, name: str, default_action: str
    ) -> dict[str, Any]:
        """Create a new protected hostname.

        Args:
            name (str): Protected hostname name.
            default_action (int): Http requests action. (allow,deny and no log,deny)

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """

        action_val = dict_safe_get(
            self.parser.action_user_to_api_mapper, [default_action]
        )
        data = {
            "data": {
                "name": name,
                "default-action": action_val,
            }
        }
        return self._http_request(
            method="POST", url_suffix="cmdb/server-policy/allow-hosts", json_data=data
        )

    def protected_hostname_update_request(
        self, name: str, default_action: str | None
    ) -> dict[str, Any]:
        """Update a protected hostname.

        Args:
            name (str): Protected hostname name.
            action (int): Http requests action. (allow,deny and no log,deny)

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = {"mkey": name}
        data = {
            "data": remove_empty_elements(
                {
                    "name": name,
                    "default-action": dict_safe_get(
                        self.parser.action_user_to_api_mapper, [default_action]
                    ),
                }
            )
        }

        return self._http_request(
            method="PUT",
            url_suffix="cmdb/server-policy/allow-hosts",
            json_data=data,
            params=params,
        )

    def protected_hostname_delete_request(self, name: str) -> dict[str, Any]:
        """Delete a protected hostname.

        Args:
            name (str): Protected hostname name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = {"mkey": name}
        return self._http_request(
            method="DELETE", url_suffix="cmdb/server-policy/allow-hosts", params=params
        )

    def protected_hostname_list_request(self, **kwargs) -> dict[str, Any]:
        """Get protected hostnames.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = remove_empty_elements({"mkey": kwargs.get("name")})
        return self._http_request(
            method="GET", url_suffix="cmdb/server-policy/allow-hosts", params=params
        )

    def protected_hostname_member_create_request(
        self, name: str, host: str, action: str, **kwargs
    ) -> dict[str, Any]:
        """Create a new protected hostname member.

        Args:
            protected_hostname_group (str): Protected hostname group.
            host (str): IP address or FQDN of a virtual or real web host.
            action (str): Select whether to accept or deny HTTP requests whose Host.
            kwargs (optional): ignore_port (str): Ignore Port.
            kwargs (optional): include_subdomains (str): Include Subdomains.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        endpoint = "cmdb/server-policy/allow-hosts/host-list"
        params = {"mkey": name}
        action_val = dict_safe_get(self.parser.action_user_to_api_mapper, [action])
        data = {
            "data": {
                "action": action_val,
                "ignore-port": kwargs["ignore_port"],
                "include-subdomains": kwargs["include_subdomains"],
                "host": host,
            }
        }
        return self._http_request(
            method="POST", url_suffix=endpoint, json_data=data, params=params
        )

    def protected_hostname_member_update_request(
        self, group_name: str, member_id: str, host: str | None, **kwargs
    ) -> dict[str, Any]:
        """Update a protected hostname member.

        Args:
            group_name (str): Protected hostname group id.
            member_id (str): Protected hostname member id
            host (Optional[str]): IP address or FQDN of a virtual or real web host.
            kwargs (optional): action (str): Action.
            kwargs (optional): ignore_port (str): Ignore Port.
            kwargs (optional): include_subdomains (str): Include Subdomains.
        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        endpoint = "cmdb/server-policy/allow-hosts/host-list"
        params = {
            "mkey": group_name,
            "sub_mkey": member_id,
        }
        data = {
            "data": remove_empty_elements(
                {
                    "host": host,
                    "action": dict_safe_get(
                        self.parser.action_user_to_api_mapper, [kwargs.get("action")]
                    ),
                    "ignore-port": kwargs.get("ignore_port"),
                    "include-subdomains": kwargs.get("include_subdomains"),
                }
            )
        }
        return self._http_request(
            method="PUT", url_suffix=endpoint, json_data=data, params=params
        )

    def protected_hostname_member_delete_request(
        self, group_name: str, member_id: str
    ) -> dict[str, Any]:
        """Delete a protected hostname member.

        Args:
            group_name (str): Protected hostname group id.
            member_id (str): Protected hostname member id.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        endpoint = "cmdb/server-policy/allow-hosts/host-list"
        params = {
            "mkey": group_name,
            "sub_mkey": member_id,
        }
        return self._http_request(method="DELETE", url_suffix=endpoint, params=params)

    def protected_hostname_member_list_request(
        self, group_name: str, **kwargs
    ) -> dict[str, Any]:
        """List protected hostname members.

        Args:
            group_name (str): Protected hostname group id.
            kwargs (optional): member_id (str) Protected hostname member id.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = {"mkey": group_name}
        if member_id := kwargs.get("member_id"):
            params.update({"sub_mkey": member_id})
        return self._http_request(
            method="GET",
            url_suffix="cmdb/server-policy/allow-hosts/host-list",
            params=params,
        )

    def ip_list_group_create_request(self, group_name: str, **kwargs) -> dict[str, Any]:
        """Create a new IP list group.

        Args:
            name (str): Protected hostname name.
            kwargs (optional): action-period (str): Action.
            kwargs (optional): block-period (str): Block Period.
            kwargs (optional): severity (str): Severity.
            kwargs (optional): ignore_x_forwarded_for (str): ignore_x_forwarded_for.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        action_val = dict_safe_get(
            self.parser.action_user_to_api_mapper, [kwargs["action"]]
        )
        data = {
            "data": {
                "name": group_name,
                "action": action_val,
                "block-period": kwargs["block_period"],
                "severity": kwargs["severity"],
                "ignore-x-forwarded-for": kwargs["ignore_x_forwarded_for"],
                "trigger-policy": kwargs.get("trigger_policy"),
            }
        }
        response = self._http_request(
            method="POST", url_suffix="cmdb/waf/ip-list", json_data=data
        )
        return response

    def ip_list_group_update_request(self, group_name: str, **kwargs) -> dict[str, Any]:
        """Update an ip list group.

        Args:
            group_name (str): IP list group name.
            kwargs: action - Action.
            kwargs: block_period - Block period.
            kwargs: severity - Severity.
            kwargs: ignore_x_forwarded_for - Ignore X Forwarded For.
            kwargs: trigger_policy - Trigger Policy.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = {"mkey": group_name}
        data = {
            "data": remove_empty_elements(
                {
                    "name": group_name,
                    "action": dict_safe_get(
                        self.parser.action_user_to_api_mapper, [kwargs.get("action")]
                    ),
                    "block-period": kwargs.get("block_period"),
                    "severity": kwargs.get("severity"),
                    "ignore-x-forwarded-for": kwargs.get("ignore_x_forwarded_for"),
                    "trigger-policy": kwargs.get("trigger_policy"),
                }
            )
        }
        return self._http_request(
            method="PUT", url_suffix="cmdb/waf/ip-list", json_data=data, params=params
        )

    def ip_list_group_delete_request(self, group_name: str) -> dict[str, Any]:
        """Delete an IP list group.

        Args:
            group_name (str): IP list group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = {"mkey": group_name}
        return self._http_request(
            method="DELETE", url_suffix="cmdb/waf/ip-list", params=params
        )

    def ip_list_group_list_request(self, **kwargs) -> dict[str, Any]:
        """List the IP list groups.

        Args:
            kwargs: group_name (str): IP list group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        group_name = kwargs.get("group_name")
        params = {"mkey": group_name} if group_name else {}
        return self._http_request(
            method="GET", url_suffix="cmdb/waf/ip-list", params=params
        )

    def ip_list_member_create_request(
        self, group_name: str, member_type: str, ip_address: str, **kwargs
    ) -> dict[str, Any]:
        """Create an IP list member.

        Args:
            group_name (str): IP list group name.
            member_type (str): IP list member type.
            ip_address (str): IP address.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": group_name}
        type_val = dict_safe_get(self.parser.type_user_to_api_mapper, [member_type])
        data = {
            "data": {
                "type": type_val,
                "ip": ip_address,
            }
        }
        return self._http_request(
            method="POST",
            url_suffix="cmdb/waf/ip-list/members",
            json_data=data,
            params=params,
        )

    def ip_list_member_update_request(
        self,
        group_name: str,
        member_id: str,
        member_type: str | None,
        ip_address: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        """Update an IP list member.

        Args:
            group_name (str): IP list group name.
            member_id (str): IP list member ID.
            member_type (str): IP list member type.
            ip_address (str): IP address.

        Returns:
            Dict[str, Any]: API response from FortiwebVM 2
        """
        params = {"mkey": group_name, "sub_mkey": member_id}
        data: dict[str, Any] = {
            "data": remove_empty_elements(
                {
                    "type": dict_safe_get(
                        self.parser.type_user_to_api_mapper, [member_type]
                    ),
                    "ip": ip_address,
                }
            )
        }
        return self._http_request(
            method="PUT",
            url_suffix="cmdb/waf/ip-list/members",
            json_data=data,
            params=params,
        )

    def ip_list_member_delete_request(
        self, group_name: str, member_id: str
    ) -> dict[str, Any]:
        """Delete an IP list member.

        Args:
            group_name (str): IP list group name.
            member_id (str): IP list member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        endpoint = "cmdb/waf/ip-list/members"
        params = {"mkey": group_name, "sub_mkey": member_id}
        return self._http_request(method="DELETE", url_suffix=endpoint, params=params)

    def ip_list_member_list_request(self, group_name: str, **kwargs) -> dict[str, Any]:
        """List IP list members.

        Args:
            group_name (str): IP list group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": group_name}
        if member_id := kwargs.get("member_id"):
            params.update({"sub_mkey": member_id})
        return self._http_request(
            method="GET", url_suffix="cmdb/waf/ip-list/members", params=params
        )

    def http_content_routing_member_add_request(
        self,
        policy_name: str,
        http_content_routing_policy: str,
        is_default: str,
        inherit_webprotection_profile: str,
        **kwargs,
    ):
        """Add a new HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            http_content_routing_policy (str): HTTP content routing policy name.
            is_default (str): Is default flag.
            specified in the HTTP content routing policies?
            inherit_webprotection_profile (str): Enable inherit web protection profile.
            kwargs: status (str): Status.
            kwargs: profile (str): Profile.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": policy_name}
        data = {
            "data": remove_empty_elements(
                {
                    "content-routing-policy-name": http_content_routing_policy,
                    "is-default": is_default,
                    "profile-inherit": inherit_webprotection_profile,
                    "status": kwargs.get("status"),
                    "web-protection-profile": kwargs.get("profile"),
                }
            )
        }
        return self._http_request(
            method="POST",
            url_suffix="cmdb/server-policy/policy/http-content-routing-list",
            json_data=data,
            params=params,
        )

    def http_content_routing_member_update_request(
        self,
        policy_name: str,
        member_id: str,
        http_content_routing_policy: str | None,
        is_default: str | None,
        inherit_webprotection_profile: str | None,
        **kwargs,
    ):
        """Update an HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            member_id (str): Member ID.
            http_content_routing_policy (str): HTTP content routing policy name.
            is_default (str): Is default flag.
            specified in the HTTP content routing policies?
            inherit_webprotection_profile (str): Enable inherit web protection profile.
            kwargs: profile (str): Web protection profile.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": policy_name, "sub_mkey": member_id}
        data = {
            "data": remove_empty_elements(
                {
                    "is-default": is_default,
                    "profile-inherit": inherit_webprotection_profile,
                    "status": kwargs.get("status"),
                }
            )
        }
        return self._http_request(
            method="PUT",
            url_suffix="cmdb/server-policy/policy/http-content-routing-list",
            json_data=data,
            params=params,
        )

    def http_content_routing_member_delete_request(
        self, policy_name: str, member_id: str
    ) -> dict[str, Any]:
        """Delete an HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            member_id (str): Member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": policy_name, "sub_mkey": member_id}
        return self._http_request(
            method="DELETE",
            url_suffix="cmdb/server-policy/policy/http-content-routing-list",
            params=params,
        )

    def http_content_routing_member_list_request(
        self, policy_name: str, **kwargs
    ) -> dict[str, Any]:
        """List HTTP content routing members.

        Args:
            policy_name (str): Server policy name.
            kwargs: member_id (str): Member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": policy_name}
        if member_id := kwargs.get("member_id"):
            params.update({"sub_mkey": member_id})
        return self._http_request(
            method="GET",
            url_suffix="cmdb/server-policy/policy/http-content-routing-list",
            params=params,
        )

    def geo_ip_group_create_request(
        self,
        name: str,
        severity: str,
        trigger_policy: str | None,
        exception: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        """Create a new Geo IP group.

        Args:
            name (str): Geo IP group name.
            severity (str): Severity.
            trigger_policy (Optional[str]): Trigger policy.
            exception (Optional[str]): Exception rule.
            kwargs: action (str): Action
            kwargs: block_period (str): Block period.
            kwargs: ignore_x_forwarded_for (str): Ignore x forward for.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """

        data = {
            "data": {
                "name": name,
                "action": dict_safe_get(
                    self.parser.action_user_to_api_mapper, [kwargs["action"]]
                ),
                "block-period": kwargs["block_period"],
                "severity": severity,
                "trigger": trigger_policy,
                "exception-rule": exception,
                "ignore-x-forwarded-for": kwargs["ignore_x_forwarded_for"],
            }
        }
        return self._http_request(
            method="POST", url_suffix="cmdb/waf/geo-block-list", json_data=data
        )

    def geo_ip_group_update_request(
        self,
        name: str,
        severity: str | None,
        trigger_policy: str | None,
        exception: str | None,
        **kwargs,
    ) -> dict[str, Any]:
        """Create a Geo IP group.

        Args:
            name (str): Geo IP group name.
            severity (Optional[str]): Severity.
            trigger_policy (Optional[str]): Trigger policy.
            exception (Optional[str]): Exception rule.
            kwargs: action (str): Action
            kwargs: block_period (str): Block period.
            kwargs: ignore_x_forwarded_for (str): Ignore x forward for.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """

        params = {"mkey": name}
        data = {
            "data": remove_empty_elements(
                {
                    "action": dict_safe_get(
                        self.parser.action_user_to_api_mapper, [kwargs.get("action")]
                    ),
                    "block-period": kwargs.get("block_period"),
                    "ignore-x-forwarded-for": kwargs.get("ignore_x_forwarded_for"),
                    "severity": severity,
                    "trigger-policy": trigger_policy,
                    "exception-rule": exception,
                }
            )
        }
        return self._http_request(
            method="PUT",
            url_suffix="cmdb/waf/geo-block-list",
            json_data=data,
            params=params,
        )

    def geo_ip_group_delete_request(self, name: str) -> dict[str, Any]:
        """Delete a Geo IP group.

        Args:
            name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """

        params = {"mkey": name}
        return self._http_request(
            method="DELETE", url_suffix="cmdb/waf/geo-block-list", params=params
        )

    def geo_ip_group_list_request(self, **kwargs) -> dict[str, Any]:
        """List the Geo IP groups.

        Args:
            kwargs: name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """

        name = kwargs.get("name")
        params = {"mkey": name} if name else {}
        return self._http_request(
            method="GET", url_suffix="cmdb/waf/geo-block-list", params=params
        )

    def geo_ip_member_add_request(
        self, group_name: str, countries_list: List[str]
    ) -> dict[str, Any]:
        """Add a new Geo IP member.

        Args:
            group_name (str): Geo IP group name.
            countries_list (List[str]): List of countries.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": group_name}
        data = {
            "data": {
                "add": countries_list,
            }
        }
        return self._http_request(
            method="POST",
            url_suffix="waf/geoip.setCountrys",
            json_data=data,
            params=params,
        )

    def geo_ip_member_delete_request(
        self, group_name: str, member_id: str
    ) -> dict[str, Any]:
        """Delete a Geo IP member.

        Args:
            group_name (str): Geo IP group name.
            member_id (str): Geo IP member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """

        endpoint = "cmdb/waf/geo-block-list/country-list"
        params = {
            "mkey": group_name,
            "sub_mkey": member_id,
        }
        return self._http_request(method="DELETE", url_suffix=endpoint, params=params)

    def geo_ip_member_list_request(self, group_name: str) -> dict[str, Any]:
        """List the Geo IP members.

        Args:
            group_name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": group_name}
        return self._http_request(
            method="GET",
            url_suffix="cmdb/waf/geo-block-list/country-list",
            params=params,
        )

    def operation_status_get_request(self) -> dict[str, Any]:
        """Gets operation status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(
            method="GET", url_suffix="system/status.systemoperation"
        )

    def policy_status_get_request(self) -> dict[str, Any]:
        """Gets policy status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method="GET", url_suffix="policy/policystatus")

    def system_status_get_request(self) -> dict[str, Any]:
        """Gets system status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method="GET", url_suffix="system/status.systemstatus")

    def server_pool_list_request(self) -> dict[str, Any]:
        """List the server pools.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(
            method="GET", url_suffix="cmdb/server-policy/server-pool"
        )

    def http_service_list_request(self) -> dict[str, Any]:
        """List the HTTP services.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(
            method="GET", url_suffix="cmdb/server-policy/service.predefined"
        )

    def inline_protction_profile_list_request(self) -> dict[str, Any]:
        """List the Inline protection profiles.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(
            method="GET", url_suffix="cmdb/waf/web-protection-profile.inline-protection"
        )

    def virtual_server_list_request(self) -> dict[str, Any]:
        """List the virtual servers.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method="GET", url_suffix="cmdb/server-policy/vserver")

    def http_content_routing_poicy_list_request(self) -> dict[str, Any]:
        """List the HTTP content routing policies.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(
            method="GET", url_suffix="cmdb/server-policy/http-content-routing-policy"
        )

    def handle_certificates(
        self,
        certificate_type: str,
        certificate: str | None,
        multi_certificate: str | None,
        lets_certificate: str | None,
    ) -> dict[str, Any]:
        """Hadle certificates for Fortiweb V2 server policy.

        Args:
            certificate_type (str): Certificate type.
            certificate (str): Certificate name.
            multi_certificate (str): Multi certificate name.
            lets_certificate (str): Lets Certificate name.

        Returns:
            Dict[str,Any]: Certificate data to server policy.
        """
        data = {}
        match certificate_type:
            case "Letsencrypt":
                data.update(
                    remove_empty_elements(
                        {
                            "multi-certificate": "disable",
                            "certificate-type": "enable",
                            "lets-certificate": lets_certificate,
                            "certificate-group": "",
                        }
                    )
                )
            case "Multi Certificate":
                data.update(
                    remove_empty_elements(
                        {
                            "multi-certificate": "enable",
                            "certificate-type": "disable",
                            "lets-certificate": "",
                            "certificate-group": multi_certificate,
                        }
                    )
                )
            case "Local":
                data.update(
                    remove_empty_elements(
                        {
                            "certificate": certificate,
                            "certificate-type": "disable",
                            "lets-certificate": "",
                            "multi-certificate": "disable",
                            "certificate-group": "",
                        }
                    )
                )
            case "":
                pass
        return data

    def server_policy_data_builder(
        self,
        name: str,
        deployment_mode: str | None,
        virtual_server: str | None,
        server_pool: str | None,
        protected_hostnames: str | None,
        client_real_ip: str | None,
        syn_cookie: str | None,
        half_open_thresh: str | None,
        http_service: str | None,
        https_service: str | None,
        protocol: str | None,
        multi_certificate: str | None,
        proxy: str | None,
        redirect_to_https: str | None,
        inline_protection_profile: str | None,
        monitor_mode: str | None,
        url_case_sensitivity: str | None,
        comments: str | None,
        match_once: str | None,
        ip_range: str | None,
        retry_on: str | None,
        retry_on_cache_size: str | None,
        retry_on_connect_failure: str | None,
        retry_times_on_connect_failure: str | None,
        retry_on_http_layer: str | None,
        retry_times_on_http_layer: str | None,
        retry_on_http_response_codes: list | None,
        scripting: str | None,
        scripting_list: str | None,
        allow_list: str | None,
        replace_msg: str | None,
        certificate_type: str,
        lets_certificate: str | None,
        http2: str | None = None,
        certificate: str | None = None,
        intergroup: str | None = None,
    ) -> dict[str, Any]:
        data = {
            "data": remove_empty_elements(
                {
                    "name": name,
                    "deployment-mode": dict_safe_get(
                        self.parser.deployment_mode_user_to_api_mapper,
                        [deployment_mode],
                    ),
                    "vserver": virtual_server,
                    "server-pool": server_pool,
                    "allow-hosts": protected_hostnames,
                    "client-real-ip": client_real_ip,
                    "real-ip-addr": ip_range,
                    "protocol": protocol,
                    "service": http_service,
                    "https-service": https_service,
                    "http2": http2,
                    "intermediate-certificate-group": intergroup,
                    "http-to-https": redirect_to_https,
                    "proxy-protocol": proxy,
                    "retry-on": retry_on,
                    "retry-on-cache-size": retry_on_cache_size,
                    "retry-on-connect-failure": retry_on_connect_failure,
                    "retry-times-on-connect-failure": retry_times_on_connect_failure,
                    "retry-on-http-layer": retry_on_http_layer,
                    "retry-times-on-http-layer": retry_times_on_http_layer,
                    "retry-on-http-response-codes": " ".join(
                        retry_on_http_response_codes
                    )
                    if retry_on_http_response_codes
                    else None,
                    "scripting": scripting,
                    "scripting-list": scripting_list,
                    "monitor-mode": monitor_mode,
                    "syncookie": syn_cookie,
                    "half-open-threshold": half_open_thresh,
                    "web-protection-profile": inline_protection_profile,
                    "allow-list": allow_list,
                    "replacemsg": replace_msg,
                    "case-sensitive": url_case_sensitivity,
                    "comment": comments,
                    "prefer-current-session": match_once,
                }
            )
        }
        data.update(
            self.handle_certificates(
                certificate_type, certificate, multi_certificate, lets_certificate
            )
        )
        return data

    def server_policy_create_request(
        self,
        name: str,
        deployment_mode: str,
        virtual_server: str,
        server_pool: str | None,
        protected_hostnames: str | None,
        client_real_ip: str | None,
        syn_cookie: str | None,
        half_open_thresh: str | None,
        http_service: str | None,
        https_service: str | None,
        redirect_to_https: str | None,
        inline_protection_profile: str | None,
        monitor_mode: str | None,
        url_case_sensitivity: str | None,
        comments: str | None,
        match_once: str | None,
        **kwards,
    ) -> dict[str, Any]:
        """Create a new server policy.

        Args:
            name (str): Server policy name.
            deployment_mode (str): Deployment mode.
            virtual_server (str): Virtual server name.
            server_pool (Optional[str]): Server pool name.
            protected_hostnames (Optional[str]): Protected hostname group name.
            client_real_ip (Optional[str]): Client real IP.
            syn_cookie (Optional[str]): Sync cookie.
            half_open_thresh (Optional[str]): Half open threshold number.
            http_service (Optional[str]): HTTP service name.
            https_service (Optional[str]): HTTPS service name.
            http2 (Optional[str]): HTTP2 flag.
            redirect_to_https (Optional[str]): Redirect to HTTPS.
            inline_protection_profile (Optional[str]): Profile.
            monitor_mode (Optional[str]): Monitor mode flag.
            url_case_sensitivity (Optional[str]): URL case sensitivity flag.
            comments (Optional[str]): Comments.
            match_once (Optional[str]): Match once flag.
            kwargs :
                multi_certificate (Optional[str]): Enable Multi certificate.
                certificate_group (Optional[str]): Certificate group name.
                proxy (Optional[str]): Proxy flag.
                ip_range (str): IP Range.
                retry_on (str): Retry on flag.
                retry_on_cache_size (Optional[str]): Retry on chache size:
                retry_on_connect_failure (Optional[str]): Retry on connect failure status.
                retry_times_on_connect_failure (Optional[str]): Retry on connect failure times.
                retry_on_http_layer (Optional[str]): Retry on http layer status.
                retry_times_on_http_layer (Optional[str]): Retry on http layer times.
                retry_on_http_response_codes (Optional[str]): Retry on HTTP response codes.
                scripting (Optional[str]): Scripting status.
                scripting_list (Optional[str]): Scripting list.
                allow_list (Optional[str]): Allow list.
                replace_msg (Optional[str]): Replace message.
        Returns
            Dict[str, Any]: API response from FortiwebVM V2
        """

        data = self.server_policy_data_builder(
            name=name,
            deployment_mode=deployment_mode,
            virtual_server=virtual_server,
            server_pool=server_pool,
            protected_hostnames=protected_hostnames,
            client_real_ip=client_real_ip,
            ip_range=kwards.get("ip_range"),
            protocol="HTTP",
            http_service=http_service,
            https_service=https_service,
            redirect_to_https=redirect_to_https,
            proxy=kwards.get("proxy"),
            retry_on=kwards.get("retry_on"),
            retry_on_cache_size=kwards.get("retry_on_cache_size"),
            retry_on_connect_failure=kwards.get("retry_on_connect_failure"),
            retry_times_on_connect_failure=kwards.get("retry_times_on_connect_failure"),
            retry_on_http_layer=kwards.get("retry_on_http_layer"),
            retry_times_on_http_layer=kwards.get("retry_times_on_http_layer"),
            retry_on_http_response_codes=kwards.get("retry_on_http_response_codes"),
            scripting=kwards.get("scripting"),
            scripting_list=kwards.get("scripting_list"),
            monitor_mode=monitor_mode,
            syn_cookie=syn_cookie,
            half_open_thresh=half_open_thresh,
            inline_protection_profile=inline_protection_profile,
            allow_list=kwards.get("allow_list"),
            replace_msg=kwards.get("replace_msg"),
            url_case_sensitivity=url_case_sensitivity,
            comments=comments,
            match_once=match_once,
            certificate_type=kwards["certificate_type"],
            lets_certificate=kwards.get("lets_certificate"),
            multi_certificate=kwards.get("multi_certificate"),
        )
        return self._http_request(
            method="POST", url_suffix="cmdb/server-policy/policy", json_data=data
        )

    def server_policy_update_request(
        self,
        name: str,
        deployment_mode: str | None,
        virtual_server: str | None,
        server_pool: str | None,
        protected_hostnames: str | None,
        client_real_ip: str | None,
        syn_cookie: str | None,
        half_open_thresh: str | None,
        http_service: str | None,
        https_service: str | None,
        http2: str | None,
        certificate: str | None,
        intergroup: str | None,
        redirect_to_https: str | None,
        inline_protection_profile: str | None,
        monitor_mode: str | None,
        url_case_sensitivity: str | None,
        comments: str | None,
        match_once: str | None,
        **kwards,
    ) -> dict[str, Any]:
        """Update a server policy.

        Args:
            name (str): Server policy name.
            deployment_mode (str): Deployment mode.
            virtual_server (str): Virtual server name.
            server_pool (Optional[str]): Server pool name.
            protected_hostnames (Optional[str]): Protected hostname group name.
            client_real_ip (Optional[str]): Client real IP.
            kwargs : ip_range (str): IP Range.
            syn_cookie (Optional[str]): Sync cookie.
            half_open_thresh (Optional[str]): Half open threshold number.
            http_service (Optional[str]): HTTP service name.
            https_service (Optional[str]): HTTPS service name.
            http2 (Optional[str]): HTTP2 flag.
            multi_certificate (Optional[str]): Multi cartificate name.
            certificate_group (Optional[str]): Certificate group name.
            certificate (Optional[str]): Certificate name.
            intergroup (Optional[str]): Certificate Intermediate Group
            proxy (Optional[str]): Proxy boolean.
            redirect_to_https (Optional[str]): Redirect to HTTPS.
            inline_protection_profile (Optional[str]): Profile.
            monitor_mode (Optional[str]): Monitor mode flag.
            url_case_sensitivity (Optional[str]): URL case sensitivity flag.
            comments (Optional[str]): Comments.
            match_once (Optional[str]): Match once flag.
            kwargs: retry_on (str): Retry on flag.
            kwargs: retry_on_cache_size (Optional[str]): Retry on chache size:
            kwargs : retry_on_connect_failure (Optional[str]): Retry on connect failure status.
            kwargs : retry_times_on_connect_failure (Optional[str]): Retry on connect failure times.
            kwargs : retry_on_http_layer (Optional[str]): Retry on http layer status.
            kwargs : retry_times_on_http_layer (Optional[str]): Retry on http layer times.
            kwargs : retry_on_http_response_codes (Optional[str]): Retry on HTTP response codes.
            kwargs : scripting (Optional[str]): Scripting status.
            kwargs : scripting_list (Optional[str]): Scripting list.
            kwargs : allow_list (Optional[str]): Allow list.
            kwargs : replace_msg (Optional[str]): Replace message.
        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """

        params = {"mkey": name}
        data = self.server_policy_data_builder(
            name=name,
            deployment_mode=dict_safe_get(
                self.parser.deployment_mode_user_to_api_mapper, [deployment_mode]
            ),
            virtual_server=virtual_server,
            server_pool=server_pool,
            protected_hostnames=protected_hostnames,
            client_real_ip=client_real_ip,
            ip_range=kwards.get("ip_range"),
            protocol="HTTP",
            http_service=http_service,
            https_service=https_service,
            http2=http2,
            intergroup=intergroup,
            redirect_to_https=redirect_to_https,
            proxy=kwards.get("proxy"),
            retry_on=kwards.get("retry_on"),
            retry_on_cache_size=kwards.get("retry_on_cache_size"),
            retry_on_connect_failure=kwards.get("retry_on_connect_failure"),
            retry_times_on_connect_failure=kwards.get("retry_times_on_connect_failure"),
            retry_on_http_layer=kwards.get("retry_on_http_layer"),
            retry_times_on_http_layer=kwards.get("retry_times_on_http_layer"),
            retry_on_http_response_codes=kwards.get("retry_on_http_response_codes"),
            scripting=kwards.get("scripting"),
            scripting_list=kwards.get("scripting_list"),
            monitor_mode=monitor_mode,
            syn_cookie=syn_cookie,
            half_open_thresh=half_open_thresh,
            inline_protection_profile=inline_protection_profile,
            allow_list=kwards.get("allow_list"),
            replace_msg=kwards.get("replace_msg"),
            url_case_sensitivity=url_case_sensitivity,
            comments=comments,
            match_once=match_once,
            certificate_type=kwards["certificate_type"],
            lets_certificate=kwards.get("lets_certificate"),
            multi_certificate=kwards.get("multi_certificate"),
            certificate=certificate,
        )
        return self._http_request(
            method="PUT",
            url_suffix="cmdb/server-policy/policy",
            json_data=data,
            params=params,
        )

    def server_policy_delete_request(self, policy_name: str) -> dict[str, Any]:
        """Delete a server policy.

        Args:
            policy_name (str): Policy name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": policy_name}
        return self._http_request(
            method="DELETE", url_suffix="cmdb/server-policy/policy", params=params
        )

    def server_policy_list_request(self, **kwargs) -> dict[str, Any]:
        """List the server policies.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        name = kwargs.get("name")
        params = {"mkey": name} if name else {}
        return self._http_request(
            method="GET", url_suffix="cmdb/server-policy/policy", params=params
        )

    def custom_whitelist_url_create_request(
        self, request_type: str, request_url: str
    ) -> dict[str, Any]:
        """Create Custom whitelist url member.

        Args:
            request_type (str): Request type.
            request_url (str): Request url.
            status (str): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = {
            "data": {
                "type": "URL",
                "request-type": dict_safe_get(
                    self.parser.request_type_user_to_api_mapper, [request_type]
                ),
                "request-file": request_url,
            }
        }
        return self._http_request(
            method="POST",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            json_data=data,
        )

    def custom_whitelist_url_update_request(
        self,
        id: str,
        request_type: str | None,
        request_url: str | None,
        status: str | None,
    ) -> dict[str, Any]:
        """Update Custom whitelist url member.

        Args:
            request_type (str): Request type.
            request_url (str): Request url.
            status (str): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": id}
        data = remove_empty_elements(
            {
                "data": {
                    "type": "URL",
                    "request-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper, [request_type]
                    ),
                    "request-file": request_url,
                    "status": status,
                }
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            json_data=data,
            params=params,
        )

    def custom_whitelist_list_request(self, **kwargs) -> dict[str, Any]:
        """List custom whitelist members.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        name = kwargs.get("id")
        params = {"mkey": name} if name else {}
        return self._http_request(
            method="GET",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            params=params,
        )

    def custom_whitelist_parameter_create_request(
        self, name: str, **kwargs
    ) -> dict[str, Any]:
        """Create custom whitelist parameter member.

        Args:
            name (str): Name.
            status (str): Status.
            kwargs: name_type (str) : Name type.
            kwargs: request_url_status (str): Request URL status.
            kwargs: request_type (str): Request Type.
            kwargs: request_url (str): Request URL.
            kwargs: domain_status (str): Domain Status.
            kwargs: domain_type (str): Domain type.
            kwargs: domain (str): Domain.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        data = remove_empty_elements(
            {
                "data": {
                    "type": "Parameter",
                    "name": name,
                    "name-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper,
                        [kwargs["name_type"]],
                    ),
                    "request-file-status": kwargs.get("request_url_status"),
                    "request-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper,
                        [kwargs.get("request_type")],
                    ),
                    "request-file": kwargs.get("request_url"),
                    "domain-status": kwargs.get("domain_status"),
                    "domain-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper,
                        [kwargs.get("domain_type")],
                    ),
                    "domain": kwargs.get("domain"),
                }
            }
        )
        return self._http_request(
            method="POST",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            json_data=data,
        )

    def custom_whitelist_parameter_update_request(
        self, id: str, name: str | None, status: str | None, **kwargs
    ) -> dict[str, Any]:
        """Update custom whitelist parameter member.

        Args:
            id (str): ID.
            name (str): Name.
            status (str): Status.
            kwargs: name_type (str) : Name type.
            kwargs: request_url_status (str): Request URL status.
            kwargs: request_type (str): Request Type.
            kwargs: request_url (str): Request URL.
            kwargs: domain_status (str): Domain Status.
            kwargs: domain_type (str): Domain type.
            kwargs: domain (str): Domain.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": id}
        data = remove_empty_elements(
            {
                "data": {
                    "type": "Parameter",
                    "name": name,
                    "status": status,
                    "name-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper,
                        [kwargs["name_type"]],
                    ),
                    "request-file-status": kwargs.get("request_url_status"),
                    "request-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper,
                        [kwargs.get("request_type")],
                    ),
                    "request-file": kwargs.get("request_url"),
                    "domain-status": kwargs.get("domain_status"),
                    "domain-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper,
                        [kwargs.get("domain_type")],
                    ),
                    "domain": kwargs.get("domain"),
                }
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            json_data=data,
            params=params,
        )

    def custom_whitelist_cookie_create_request(
        self, name: str, domain: str | None, path: str | None
    ) -> dict[str, Any]:
        """Create custom whitelist cookie member.

        Args:
            name (str): Name.
            domain (Optional[str]): Domain.
            path (Optional[str]): Path.
            status (str): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        data = remove_empty_elements(
            {
                "data": {
                    "type": "Cookie",
                    "name": name,
                    "domain": domain,
                    "path": path,
                }
            }
        )
        return self._http_request(
            method="POST",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            json_data=data,
        )

    def custom_whitelist_cookie_update_request(
        self,
        id: str,
        name: str | None,
        domain: str | None,
        path: str | None,
        status: str | None,
    ) -> dict[str, Any]:
        """Update a custom whitelist cookie member.

        Args:
            id (str): Custom whitelist cookie member.
            name (Optional[str]): Name.
            domain (Optional[str]): Domain.
            path (Optional[str]): Path.
            status (Optional[str]): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """

        params = {"mkey": id}
        data = remove_empty_elements(
            {
                "data": {
                    "type": "Cookie",
                    "name": name,
                    "domain": domain,
                    "path": path,
                    "status": status,
                }
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            json_data=data,
            params=params,
        )

    def custom_whitelist_header_field_create_request(
        self,
        header_name_type: str,
        name: str,
        value_status: str | None,
        header_value_type: str | None,
        value: str | None,
    ) -> dict[str, Any]:
        """Create a custom whitelist header field.

        Args:
            header_name_type (str): Header name.
            name (str): Name.
            value_status (Optional[str]): Value status.
            header_value_type (Optional[str]): Header value type.
            value (Optional[str]): Value.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        data = remove_empty_elements(
            {
                "data": {
                    "type": "Header_Field",
                    "header-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper, [header_name_type]
                    ),
                    "name": name,
                    "value-status": value_status,
                    "value-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper, [header_value_type]
                    ),
                    "value": value,
                }
            }
        )
        return self._http_request(
            method="POST",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            json_data=data,
        )

    def custom_whitelist_header_field_update_request(
        self,
        id: str,
        header_name_type: str | None,
        name: str | None,
        value_status: str | None,
        header_value_type: str | None,
        value: str | None,
        status: str | None,
    ) -> dict[str, Any]:
        """Update a custom whitelist header field.

        Args:
            id (str) : Custom whitelist header field member ID.
            header_name_type (Optional[str]): Header name.
            name (Optional[str]): Name.
            value_status (Optional[str]): Value status.
            header_value_type (Optional[str]): Header value type.
            value (Optional[str]): Value.
            status (Optional[str]): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {"mkey": id}
        data = remove_empty_elements(
            {
                "data": {
                    "type": "Header_Field",
                    "header-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper, [header_name_type]
                    ),
                    "name": name,
                    "value-status": value_status,
                    "value-type": dict_safe_get(
                        self.parser.request_type_user_to_api_mapper, [header_value_type]
                    ),
                    "value": value,
                    "status": status,
                }
            }
        )
        return self._http_request(
            method="PUT",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            json_data=data,
            params=params,
        )

    def custom_whitelist_delete_request(self, id: str) -> dict[str, Any]:
        """Delete a custom whitelist member.

        Args:
            id (str): Delete a custom whitelist member.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        params = {"mkey": id}
        return self._http_request(
            method="DELETE",
            url_suffix="cmdb/server-policy/pattern.custom-global-white-list-group",
            params=params,
        )

    def geo_exception_list_request(self) -> dict[str, Any]:
        """List the Geo IP Exception.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        return self._http_request(method="GET", url_suffix="cmdb/waf/geo-ip-except")

    def trigger_policy_list_request(self) -> dict[str, Any]:
        """List the Trigger Policies.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        return self._http_request(method="GET", url_suffix="cmdb/log/trigger-policy")

    def custom_predifined_whitelist_list_handler(
        self,
        response: Union[dict[str, Any], List[dict[str, Any]]],
        object_type: str | None = None,
    ) -> Union[dict[str, Any], List[dict[str, Any]]]:
        if isinstance(response, dict):
            data = response["results"]
            if object_type:
                rel_data = dict_safe_get(
                    find_dict_in_array(data, "type", object_type), ["details"]
                )
                return {"results": rel_data}
            else:
                rel_data = [
                    member for object_type in data for member in object_type["details"]
                ]
                return {"results": rel_data}
        return {}

    def custom_predifined_whitelist_list_request(self) -> dict[str, Any]:
        """List the Custom Predifined members.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        return self._http_request(
            method="GET",
            url_suffix="policy/serverobjects.global.predefinedglobalwhitelist",
        )

    def custom_predifined_whitelist_update_request(
        self, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Update a Custom Predifined members.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        return self._http_request(
            method="PUT",
            url_suffix="policy/serverobjects.global.predefinedglobalwhitelist",
            json_data=data,
        )

    def certificate_intermediate_group_list_request(self) -> dict[str, Any]:
        """List the Certificate intermediate groups.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(
            method="GET",
            url_suffix="cmdb/system/certificate.intermediate-certificate-group",
        )


def protected_hostname_group_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Create a new protected hostname.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_protected_hostname_group(args=args)
    name = args["name"]
    response = client.protected_hostname_create_request(
        name=name, default_action=args["default_action"]
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.PROTECTED_HOSTNAME_GROUP.value,
        object_name=name,
        action=OutputTitle.CREATED.value,
        response=response,
    )
    return command_results


def protected_hostname_group_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update a protected hostname.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_protected_hostname_group(args=args)
    name = args["name"]
    response = client.protected_hostname_update_request(
        name=name, default_action=args.get("default_action")
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.PROTECTED_HOSTNAME_GROUP.value,
        object_name=name,
        action=OutputTitle.UPDATED.value,
        response=response,
    )
    return command_results


def protected_hostname_group_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Delete a protected hostname.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args["name"]
    response = client.protected_hostname_delete_request(name)
    command_results = generate_simple_command_results(
        object_type=OutputTitle.PROTECTED_HOSTNAME_GROUP.value,
        object_name=name,
        action=OutputTitle.DELETED.value,
        response=response,
    )
    return command_results


def protected_hostname_group_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Get protected hostname list / object.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    protected_hostname = args.get("name")
    response = client.protected_hostname_list_request(name=protected_hostname)
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_protected_hostname_group,
        args=args,
        sub_object_id=protected_hostname,
        sub_object_key=client.parser.sub_object_id_key,
    )
    headers = client.parser.create_output_headers(
        client.version,
        ["id", "default_action", "protected_hostname_count"],
        ["can_delete"],
        [],
    )
    readable_output = tableToMarkdown(
        name=OutputTitle.PROTECTED_HOSTNAME_GROUP_LIST.value,
        metadata=pagination_message,
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.ProtectedHostnameGroup",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def protected_hostname_member_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Create a new protected hostname member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_protected_hostname_member(args=args)
    name = args["group_name"]
    host = args["host"]
    response = client.protected_hostname_member_create_request(
        name=name,
        host=host,
        action=args["action"],
        ignore_port=args.get("ignore_port"),
        include_subdomains=args.get("include_subdomains"),
    )
    member_id = client.get_object_id(
        response,
        "host",
        host,
        client.protected_hostname_member_list_request,
        name,
    )
    command_results = generate_simple_context_data_command_results(
        "id",
        member_id,
        response,
        OutputTitle.PROTECTED_HOSTNAME_MEMBER_CREATE.value,
        "FortiwebVM.ProtectedHostnameMember",
    )
    return command_results


def protected_hostname_member_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update a protected hostname member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_protected_hostname_member(args=args)
    group_name = args["group_name"]
    member_id = args["member_id"]
    # Get exist settings from API version 1
    args = get_object_data_before_update(
        client=client,
        value=member_id,
        get_request=client.protected_hostname_member_list_request,
        args=args,
        _parser=client.parser.parse_protected_hostname_member,
        requested_version=ClientV1.API_VER,
        object_id=group_name,
    )
    response = client.protected_hostname_member_update_request(
        group_name=group_name,
        member_id=member_id,
        action=args.get("action"),
        host=args.get("host"),
        ignore_port=args.get("ignore_port"),
        include_subdomains=args.get("include_subdomains"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.PROTECTED_HOSTNAME_MEMBER.value,
        object_name=member_id,
        action=OutputTitle.UPDATED.value,
        response=response,
    )

    return command_results


def protected_hostname_member_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Delete a protected hostname member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    protected_hostname = args["group_name"]
    member_id = args["member_id"]
    response = client.protected_hostname_member_delete_request(
        protected_hostname, member_id
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.PROTECTED_HOSTNAME_MEMBER.value,
        object_name=member_id,
        action=OutputTitle.DELETED.value,
        response=response,
    )
    return command_results


def protected_hostname_member_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """List protected hostname members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    group_name = args["group_name"]
    member_id = args.get("member_id")
    response = client.protected_hostname_member_list_request(
        group_name=group_name, member_id=member_id
    )
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_protected_hostname_member,
        args=args,
        sub_object_id=member_id,
        sub_object_key="id",
    )
    outputs = {"group_name": group_name, "Members": parsed_data}
    headers = client.parser.create_output_headers(
        client.version,
        ["id", "action", "host"],
        [],
        ["ignore_port", "include_subdomains"],
    )
    readable_output = tableToMarkdown(
        name=OutputTitle.PROTECTED_HOSTNAME_MEMBER_LIST.value,
        metadata=pagination_message,
        t=outputs["Members"],
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.ProtectedHostnameMember",
        outputs_key_field="group_name",
        outputs=outputs,
        raw_response=response,
    )
    return command_results


def ip_list_group_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Create an IP list group.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_ip_list_group(args)
    group_name = args["name"]
    response = client.ip_list_group_create_request(
        group_name=group_name,
        action=args.get("action"),
        block_period=arg_to_number(args.get("block_period")),
        severity=args.get("severity"),
        ignore_x_forwarded_for=args.get("ignore_x_forwarded_for"),
        trigger_policy=args.get("trigger_policy"),
    )

    command_results = generate_simple_command_results(
        object_type=OutputTitle.IP_LIST_GROUP.value,
        object_name=group_name,
        action=OutputTitle.CREATED.value,
        response=response,
    )

    return command_results


def ip_list_group_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update an IP list group.

    Args:
        client (Client): FortiwebVM V2 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_update_ip_list_group(args)
    group_name = args["name"]
    response = client.ip_list_group_update_request(
        group_name=group_name,
        action=args.get("action"),
        block_period=arg_to_number(args.get("block_period")),
        severity=args.get("severity"),
        ignore_x_forwarded_for=args.get("ignore_x_forwarded_for"),
        trigger_policy=args.get("trigger_policy"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.IP_LIST_GROUP.value,
        object_name=group_name,
        action=OutputTitle.UPDATED.value,
        response=response,
    )

    return command_results


def ip_list_group_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    group_name = args["name"]
    response = client.ip_list_group_delete_request(group_name)
    command_results = generate_simple_command_results(
        object_type=OutputTitle.IP_LIST_GROUP.value,
        object_name=group_name,
        action=OutputTitle.DELETED.value,
        response=response,
    )

    return command_results


def ip_list_group_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List IP list groups.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    group_name = args.get("name")
    response = client.ip_list_group_list_request(group_name=group_name)
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_ip_list_group,
        args=args,
        sub_object_id=group_name,
        sub_object_key=client.parser.sub_object_id_key,
    )
    headers = client.parser.create_output_headers(
        client.version,
        ["id", "ip_list_count"],
        [],
        ["action", "block_period", "severity", "trigger_policy"],
    )
    readable_output = tableToMarkdown(
        name=OutputTitle.IP_LIST_GROUP_LIST.value,
        metadata=pagination_message,
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.IpListGroup",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def ip_list_member_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Create a new IP list member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_ip_list_member(args)
    group_name = args["group_name"]
    ip_address = args["ip_address"]
    response = client.ip_list_member_create_request(
        group_name=group_name,
        member_type=args["type"],
        ip_address=ip_address,
        severity=args["severity"],
        trigger_policy=args.get("trigger_policy"),
    )
    member_id = client.get_object_id(
        response,
        "iPv4IPv6",
        ip_address,
        client.ip_list_member_list_request,
        group_name,
    )
    command_results = generate_simple_context_data_command_results(
        "id",
        member_id,
        response,
        OutputTitle.IP_LIST_MEMBER_CREATE.value,
        "FortiwebVM.IpListMember",
    )
    return command_results


def ip_list_member_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update an IP list member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    client.validate_ip_list_member(args)
    group_name = args["group_name"]
    member_id = args["member_id"]
    # Get exist settings from API version 1
    args = get_object_data_before_update(
        client=client,
        value=member_id,
        get_request=client.ip_list_member_list_request,
        args=args,
        _parser=client.parser.parse_ip_list_member,
        object_id=group_name,
        requested_version=ClientV1.API_VER,
    )
    severity = args.get("severity")
    severity = "Medium" if args.get("type") == "Black IP" and not severity else severity
    response = client.ip_list_member_update_request(
        group_name=group_name,
        member_id=member_id,
        member_type=args.get("type"),
        ip_address=args.get("ip_address"),
        severity=severity,
        trigger_policy=args.get("trigger_policy"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.IP_LIST_MEMBER.value,
        object_name=member_id,
        action=OutputTitle.UPDATED.value,
        response=response,
    )
    return command_results


def ip_list_member_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Delete an IP list member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    group_name = args["group_name"]
    member_id = args["member_id"]
    response = client.ip_list_member_delete_request(group_name, member_id)
    command_results = generate_simple_command_results(
        object_type=OutputTitle.IP_LIST_MEMBER.value,
        object_name=member_id,
        action=OutputTitle.DELETED.value,
        response=response,
    )
    return command_results


def ip_list_member_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List IP list members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    group_name = args["group_name"]
    member_id = args.get("member_id")
    response = client.ip_list_member_list_request(
        group_name=group_name, member_id=member_id
    )
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, response, client.parser.parse_ip_list_member, args, member_id
    )
    outputs = {"group_name": group_name, "Members": parsed_data}
    headers = client.parser.create_output_headers(
        client.version, ["id", "type", "ip"], ["severity", "trigger_policy"], []
    )
    readable_output = tableToMarkdown(
        name=OutputTitle.IP_LIST_MEMBER_LIST.value,
        metadata=pagination_message,
        t=outputs["Members"],
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.IpListMember",
        outputs_key_field="group_name",
        outputs=outputs,
        raw_response=response,
    )
    return command_results


def http_content_routing_member_add_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Add an HTTP content routing members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_http_content_routing_member(args=args)
    policy_name = args["policy_name"]
    http_content_routing_policy = args["http_content_routing_policy"]
    response = client.http_content_routing_member_add_request(
        policy_name=policy_name,
        http_content_routing_policy=http_content_routing_policy,
        is_default=args["is_default"],
        inherit_webprotection_profile=args["inherit_web_protection_profile"],
        profile=args.get("profile"),
        status=args["status"],
    )
    member_id = client.get_object_id(
        response,
        "http_content_routing_policy",
        http_content_routing_policy,
        client.http_content_routing_member_list_request,
        policy_name,
    )
    command_results = generate_simple_context_data_command_results(
        "id",
        member_id,
        response,
        OutputTitle.HTTP_CONTENT_ROUTING_MEMBER_CREATE.value,
        "FortiwebVM.HttpContentRoutingMember",
    )
    return command_results


def http_content_routing_member_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update an HTTP content routing members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_http_content_routing_member(args=args)
    policy_name = args["policy_name"]
    id = args["id"]
    # Get exist settings from API version 1
    args = get_object_data_before_update(
        client=client,
        value=id,
        get_request=client.http_content_routing_member_list_request,
        args=args,
        _parser=client.parser.parse_http_content_routing_member,
        requested_version=ClientV1.API_VER,
        object_id=policy_name,
    )
    response = client.http_content_routing_member_update_request(
        policy_name=policy_name,
        member_id=id,
        http_content_routing_policy=args.get("http_content_routing_policy"),
        is_default=args.get("is_default"),
        inherit_webprotection_profile=args.get("inherit_web_protection_profile"),
        profile=args.get("profile"),
        status=args.get("status"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.HTTP_CONTENT_ROUTING_MEMBER.value,
        object_name=id,
        action=OutputTitle.UPDATED.value,
        response=response,
    )
    return command_results


def http_content_routing_member_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Delete an HTTP content routing members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    policy_name = args["policy_name"]
    id = args["id"]
    response = client.http_content_routing_member_delete_request(policy_name, id)
    command_results = generate_simple_command_results(
        object_type=OutputTitle.HTTP_CONTENT_ROUTING_MEMBER.value,
        object_name=id,
        action=OutputTitle.DELETED.value,
        response=response,
    )
    return command_results


def http_content_routing_member_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """List HTTP content routing members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    policy_name = args["policy_name"]
    member_id = args.get("id")
    response = client.http_content_routing_member_list_request(
        policy_name, member_id=member_id
    )
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client,
        response,
        client.parser.parse_http_content_routing_member,
        args,
        member_id,
    )
    outputs = {"policy_name": policy_name, "Members": parsed_data}
    headers = client.parser.create_output_headers(
        client.version,
        [
            "id",
            "default",
            "http_content_routing_policy",
            "inherit_web_protection_profile",
            "profile",
        ],
        [],
        ["status"],
    )
    readable_output = tableToMarkdown(
        name=OutputTitle.HTTP_CONTENT_ROUTING_MEMBER_LIST.value,
        metadata=pagination_message,
        t=outputs["Members"],
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.HttpContentRoutingMember",
        outputs_key_field="policy_name",
        outputs=outputs,
        raw_response=response,
    )
    return command_results


def geo_ip_group_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a Geo IP group.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    client.validate_geo_ip_group(args)
    name = args["name"]
    trigger_policy = args.get("trigger_policy")
    severity = args.get("severity", "Low")
    exception_rule = args.get("exception_rule")
    action = args.get("action", "Block Period")
    block_period = arg_to_number(args.get("block_period", 600))
    ignore_x_forwarded_for = args.get("ignore_x_forwarded_for", "disable")
    response = client.geo_ip_group_create_request(
        name=name,
        trigger_policy=trigger_policy,
        severity=severity,
        exception=exception_rule,
        action=action,
        block_period=block_period,
        ignore_x_forwarded_for=ignore_x_forwarded_for,
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.GEO_IP_GROUP.value,
        object_name=name,
        action=OutputTitle.CREATED.value,
        response=response,
    )

    return command_results


def geo_ip_group_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a Geo IP group.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_geo_ip_group(args)
    name = args["name"]
    # Get exist settings from API version 1
    args = get_object_data_before_update(
        client=client,
        value=name,
        get_request=client.geo_ip_group_list_request,
        args=args,
        _parser=client.parser.parse_geo_ip_group,
        requested_version=ClientV1.API_VER,
    )
    block_period = arg_to_number(args.get("block_period"))
    client.validate_block_period(block_period)
    response = client.geo_ip_group_update_request(
        name=name,
        trigger_policy=args.get("trigger_policy"),
        severity=args.get("severity"),
        exception=args.get("exception_rule"),
        action=args.get("action"),
        block_period=block_period,
        ignore_x_forwarded_for=args.get("ignore_x_forwarded_for"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.GEO_IP_GROUP.value,
        object_name=name,
        action=OutputTitle.UPDATED.value,
        response=response,
    )

    return command_results


def geo_ip_group_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a Geo IP group.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    name = args["name"]
    response = client.geo_ip_group_delete_request(name)
    command_results = generate_simple_command_results(
        object_type=OutputTitle.GEO_IP_GROUP.value,
        object_name=name,
        action=OutputTitle.DELETED.value,
        response=response,
    )

    return command_results


def geo_ip_group_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the Geo IP groups.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args.get("name")
    response = client.geo_ip_group_list_request(name=name)
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_geo_ip_group,
        args=args,
        sub_object_id=name,
        sub_object_key=client.parser.sub_object_id_key,
    )
    headers = client.parser.create_output_headers(
        client.version,
        ["id", "count", "trigger_policy", "severity", "except"],
        [],
        ["action", "block_period", "ignore_x_forwarded_for"],
    )
    readable_output = tableToMarkdown(
        name=OutputTitle.GEO_IP_GROUP_LIST.value,
        metadata=pagination_message,
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.GeoIpGroup",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def geo_ip_member_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Add a Geo IP member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_geo_ip_member(args=args)
    group_name = args["group_name"]
    countries = argToList(args["countries"])
    all_countries = countries
    if isinstance(client, ClientV1):
        # Get last countries
        old_countries_list: List[str] = client.geo_ip_member_list_request(
            group_name=group_name
        )[0]["SSet"]
        all_countries = set(countries)
        all_countries = list(all_countries.union(old_countries_list))
    response = client.geo_ip_member_add_request(
        group_name=group_name, countries_list=all_countries
    )
    # Get the new IDs
    get_response = client.geo_ip_member_list_request(group_name=group_name)
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, get_response, client.parser.parse_geo_ip_member, {}
    )
    countries_data = find_dicts_in_array(parsed_data, "country", countries)

    readable_output = tableToMarkdown(
        name=OutputTitle.GEO_IP_MEMBER_ADD.value,
        t=countries_data,
        headers=["id", "country"],
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.GeoIpMember",
        outputs_key_field="id",
        outputs=countries_data,
        raw_response=response,
    )
    return command_results


def geo_ip_member_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Delete a Geo IP member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    group_name = args["group_name"]
    member_id = args["member_id"]
    response = client.geo_ip_member_delete_request(
        group_name=group_name, member_id=member_id
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.GEO_IP_MEMBER.value,
        object_name=member_id,
        action=OutputTitle.DELETED.value,
        response=response,
    )
    return command_results


def geo_ip_member_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the Geo IP members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    group_name = args["group_name"]
    response = client.geo_ip_member_list_request(group_name=group_name)
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, response, client.parser.parse_geo_ip_member, args
    )
    outputs = {"group_name": group_name, "countries": parsed_data}
    headers = ["id", "country"]
    readable_output = tableToMarkdown(
        name=OutputTitle.GEO_IP_MEMBER_LIST.value,
        metadata=pagination_message,
        t=outputs["countries"],
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.GeoIpMember",
        outputs_key_field="group_name",
        outputs=outputs,
        raw_response=response,
    )
    return command_results


def operation_status_get_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Get operation status.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    response = client.operation_status_get_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_operation_status,
        args=args,
        internal_path=["network"],
    )
    headers = [
        "id",
        "name",
        "label",
        "alias",
        "ip_netmask",
        "speed_duplex",
        "tx",
        "rx",
        "link",
    ]
    readable_output = tableToMarkdown(
        name="Operation networks:",
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.SystemOperation",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def policy_status_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get policy status.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    response = client.policy_status_get_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, response, client.parser.parse_policy_status, args
    )
    headers = client.parser.create_output_headers(
        client.version,
        [
            "id",
            "name",
            "status",
            "vserver",
            "http_port",
            "https_port",
            "mode",
            "session_count",
            "connction_per_second",
        ],
        [],
        ["policy", "client_rtt", "server_rtt", "app_response_time"],
    )
    readable_output = tableToMarkdown(
        name="Policy status:",
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.SystemPolicy",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def system_status_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get system status.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    response = client.system_status_get_request()
    results = response["results"] if client.version == ClientV2.API_VER else response
    parsed_data = client.parser.parse_system_status(results)
    headers = client.parser.create_output_headers(
        client.version,
        common_headers=[
            "high_ability_status",
            "host_name",
            "serial_number",
            "operation_mode",
            "system_time",
            "firmware_version",
            "administrative_domain",
        ],
        v1_only_headers=["system_uptime", "fips_and_cc_mode", "log_disk"],
        v2_only_headers=[
            "manager_status",
            "sysyem_up_days",
            "sysyem_up_hrs",
            "sysyem_up_mins",
        ],
    )
    readable_output = tableToMarkdown(
        name="System Status:",
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.SystemStatus",
        outputs_key_field="id",
        outputs=results,
        raw_response=response,
    )
    return command_results


def server_pool_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the Server pools.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.server_pool_list_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, response, client.parser.parse_simple_id, args
    )
    headers = ["id"]
    readable_output = tableToMarkdown(
        name="Server pool:",
        metadata=pagination_message,
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.ServerPool",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def http_service_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the HTTP services.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.http_service_list_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, response, client.parser.parse_http_service, args
    )
    headers = ["id"]
    readable_output = tableToMarkdown(
        name="HTTP services:",
        metadata=pagination_message,
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.HttpServiceList",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def inline_protection_profile_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """List the Inline protection profiles.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.inline_protction_profile_list_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, response, client.parser.parse_simple_id, args
    )
    headers = ["id"]
    readable_output = tableToMarkdown(
        name="Inline Protection Profile:",
        metadata=pagination_message,
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.InlineProtectionProfile",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def virtual_server_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the Virtual servers.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.virtual_server_list_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, response, client.parser.parse_simple_id, args
    )
    headers = ["id"]
    readable_output = tableToMarkdown(
        name="Virtual Servers:",
        metadata=pagination_message,
        t=parsed_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.VirtualServer",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def http_content_routing_policy_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """List the HTTP content routing policies.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.http_content_routing_poicy_list_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_simple_id,
        args=args,
    )
    readable_output = tableToMarkdown(
        name="Content Routing Policy:",
        metadata=pagination_message,
        t=parsed_data,
        headers=["id"],
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.HttpContentRoutingPolicy",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def geo_exception_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the Geo IP Exception groups.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.geo_exception_list_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_simple_name,
        args=args,
    )
    readable_output = tableToMarkdown(
        name="Geo exception:",
        metadata=pagination_message,
        t=parsed_data,
        headers=["id"],
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.GeoExceptionGroup",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def trigger_policy_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the Trigger Policies.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.trigger_policy_list_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_simple_name,
        args=args,
    )
    readable_output = tableToMarkdown(
        name="Content Routing Policy:",
        metadata=pagination_message,
        t=parsed_data,
        headers=["id"],
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.TriggerPolicy",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def certificate_intermediate_group_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """List the Certificate intermediate groups.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.certificate_intermediate_group_list_request()
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, response, client.parser.parse_simple_name, args
    )
    readable_output = tableToMarkdown(
        name="Content Routing Policy:",
        metadata=pagination_message,
        t=parsed_data,
        headers=["id"],
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.CertificateIntermediateGroup",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def read_json_policy(json_template_id: str, name: str) -> dict[str, Any]:
    """Read JSON file by json id.

    Args:
        json_template_id (str): JSON file id.
        name (str): Server Policy name.

    Returns:
        Dict[str, Any]: New
    """
    file_data = demisto.getFilePath(json_template_id)
    with open(file_data["path"], "rb") as f:
        args = json.load(f)
    args["name"] = name
    return args


def server_policy_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Create a server policy.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args["name"]
    if json_template_id := args.get("json_template_id"):
        args.update(read_json_policy(json_template_id, name))
    client.validate_server_policy(args)
    response = client.server_policy_create_request(
        name=args["name"],
        deployment_mode=args["deployment_mode"],
        virtual_server=args["virtual_server"],
        server_pool=args.get("server_pool"),
        protected_hostnames=args.get("protected_hostnames"),
        client_real_ip=args.get("client_real_ip"),
        syn_cookie=args.get("syn_cookie"),
        half_open_thresh=args.get("half_open_thresh"),
        http_service=args.get("http_service"),
        https_service=args.get("https_service"),
        http2=args.get("http2"),
        proxy=args.get("proxy"),
        redirect_to_https=args.get("redirect_to_https"),
        inline_protection_profile=args.get("inline_protection_profile"),
        monitor_mode=args.get("monitor_mode"),
        url_case_sensitivity=args.get("url_case_sensitivity"),
        comments=args.get("comments"),
        match_once=args.get("match_once"),
        allow_list=args.get("allow_list"),
        replace_msg=args.get("replace_msg"),
        scripting=args.get("scripting"),
        scripting_list=args.get("scripting_list"),
        retry_on=args.get("retry_on"),
        retry_on_cache_size=arg_to_number(args.get("retry_on_cache_size")),
        retry_on_connect_failure=args.get("retry_on_connect_failure"),
        retry_times_on_connect_failure=arg_to_number(
            args.get("retry_times_on_connect_failure")
        ),
        retry_on_http_layer=args.get("retry_on_http_layer"),
        retry_times_on_http_layer=arg_to_number(args.get("retry_times_on_http_layer")),
        retry_on_http_response_codes=argToList(
            args.get("retry_on_http_response_codes")
        ),
        certificate_type=args.get("certificate_type"),
        lets_certificate=args.get("lets_certificate"),
        multi_certificate=args.get("multi_certificate"),
        certificate_group=args.get("certificate_group"),
        certificate=args.get("certificate"),
        intergroup=args.get("intergroup"),
        ip_range=args.get("ip_range"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.SERVER_POLICY.value,
        object_name=name,
        action=OutputTitle.CREATED.value,
        response=response,
    )

    return command_results


def server_policy_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update a server policy.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args["name"]
    if json_template_id := args.get("json_template_id"):
        args = read_json_policy(json_template_id, name)
    # Get exist settings from Fortiweb for validation
    args = get_object_data_before_update(
        client=client,
        value=name,
        get_request=client.server_policy_list_request,
        args=args,
        _parser=client.parser.parse_server_policy,
        by_key="name" if client.version == ClientV2.API_VER else None,
    )
    client.validate_server_policy(args)
    response = client.server_policy_update_request(
        name=args["name"],
        deployment_mode=args.get("deployment_mode"),
        virtual_server=args.get("virtual_server"),
        server_pool=args.get("server_pool"),
        protected_hostnames=args.get("protected_hostnames"),
        client_real_ip=args.get("client_real_ip"),
        syn_cookie=args.get("syn_cookie"),
        half_open_thresh=args.get("half_open_thresh"),
        http_service=args.get("http_service"),
        https_service=args.get("https_service"),
        http2=args.get("http2"),
        proxy=args.get("proxy"),
        redirect_to_https=args.get("redirect_to_https"),
        inline_protection_profile=args.get("inline_protection_profile"),
        monitor_mode=args.get("monitor_mode"),
        url_case_sensitivity=args.get("url_case_sensitivity"),
        comments=args.get("comments"),
        match_once=args.get("match_once"),
        allow_list=args.get("allow_list"),
        replace_msg=args.get("replace_msg"),
        scripting=args.get("scripting"),
        scripting_list=args.get("scripting_list"),
        retry_on=args.get("retry_on"),
        retry_on_cache_size=args.get("retry_on_cache_size"),
        retry_on_connect_failure=args.get("retry_on_connect_failure"),
        retry_times_on_connect_failure=args.get("retry_times_on_connect_failure"),
        retry_on_http_layer=args.get("retry_on_http_layer"),
        retry_times_on_http_layer=args.get("retry_times_on_http_layer"),
        retry_on_http_response_codes=argToList(
            args.get("retry_on_http_response_codes")
        ),
        certificate_type=args.get("certificate_type"),
        lets_certificate=args.get("lets_certificate"),
        multi_certificate=args.get("multi_certificate"),
        certificate_group=args.get("certificate_group"),
        certificate=args.get("certificate"),
        intergroup=args.get("intergroup"),
        ip_range=args.get("ip_range"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.SERVER_POLICY.value,
        object_name=name,
        action=OutputTitle.UPDATED.value,
        response=response,
    )

    return command_results


def server_policy_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Delete a server policy.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args["name"]
    response = client.server_policy_delete_request(name)
    command_results = generate_simple_command_results(
        object_type=OutputTitle.SERVER_POLICY.value,
        object_name=name,
        action=OutputTitle.DELETED.value,
        response=response,
    )

    return command_results


def server_policy_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List server policies.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args.get("name")
    response = client.server_policy_list_request(name=name)
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_server_policy,
        args=args,
        sub_object_id=name,
        sub_object_key="name",
    )
    readable_output = tableToMarkdown(
        name=OutputTitle.SERVER_POLICY_LIST.value,
        metadata=pagination_message,
        t=parsed_data,
        headers=[
            "name",
            "deployment_mode",
            "virtual_server",
            "protocol",
            "web_protection_profile",
            "monitor_mode",
        ],
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.ServerPolicy",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def custom_whitelist_url_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Create a custom whitelist url member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    client.validate_custom_whitelist(args=args, member_type="URL")
    request_url = args["request_url"]
    response = client.custom_whitelist_url_create_request(
        request_type=args["request_type"], request_url=request_url
    )
    member_id = client.get_object_id(
        response,
        "requestURL",
        request_url,
        client.custom_whitelist_list_request,
    )

    command_results = generate_simple_context_data_command_results(
        "id",
        member_id,
        response,
        OutputTitle.CUSTOM_WHITELIST_URL_CREATE.value,
        "FortiwebVM.CustomGlobalWhitelist",
    )

    return command_results


def custom_whitelist_url_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update a custom whitelist url member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    id = args["id"]
    # Get exist settings from Fortiweb for validation
    args = get_object_data_before_update(
        client=client,
        value=id,
        get_request=client.custom_whitelist_list_request,
        args=args,
        _parser=client.parser.parse_custom_whitelist,
    )
    client.validate_custom_whitelist(args=args, member_type="URL")
    response = client.custom_whitelist_url_update_request(
        id=id,
        request_type=args.get("request_type"),
        request_url=args.get("request_url"),
        status=args.get("status"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.CUSTOM_WHITELIST_URL.value,
        object_name=id,
        action=OutputTitle.UPDATED.value,
        response=response,
    )

    return command_results


def custom_whitelist_parameter_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Create a custom whitelist parameter member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    client.validate_custom_whitelist(args=args, member_type="Parameter")
    name = args["name"]
    response = client.custom_whitelist_parameter_create_request(
        name=name,
        name_type=args.get("name_type"),
        request_url_status=args.get("request_url_status"),
        request_type=args.get("request_type"),
        request_url=args.get("request_url"),
        domain_status=args.get("domain_status"),
        domain_type=args.get("domain_type"),
        domain=args.get("domain"),
    )
    member_id = client.get_object_id(
        response, "itemName", name, client.custom_whitelist_list_request
    )

    command_results = generate_simple_context_data_command_results(
        "id",
        member_id,
        response,
        OutputTitle.CUSTOM_WHITELIST_PARAMETER_CREATE.value,
        "FortiwebVM.CustomGlobalWhitelist",
    )

    return command_results


def get_object_data_before_update(
    client: Client,
    value: str,
    get_request: Callable,
    args: dict[str, Any],
    _parser: Callable,
    requested_version: str = None,
    object_id: str | None = None,
    by_key: str = None,
) -> dict[str, Any]:
    """Get object data that relevant to update.

    Args:
        client (Client): Fortiweb client.
        requested_version (str): Requested fortiweb client.
        value (str): The object value to the key.
        get_request (Callable): Get request.
        args (Dict[str, Any]): Xsoar args.
        parser_command (Callable): Parser command.
        object_id (Optional[str], optional): Object ID (not sub object)!. Defaults to None.
        by_key (Optional[str], optional): Key for search object in special cases. Defaults to None.

    Returns:
        Dict[str, Any]: The object data from the get response.
    """
    if not requested_version or (
        requested_version and client.version == requested_version
    ):
        by_key = (
            "_id"
            if client.version == ClientV1.API_VER
            else "id"
            if not by_key
            else by_key
        )
        old_args = get_object_data(
            client.version, by_key, value, get_request, object_id
        )
        if not old_args:
            return args
        parsed_data: dict[str, Any] = _parser(old_args)
        parsed_data.update(args)
        return parsed_data
    return args


def custom_whitelist_parameter_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update a custom whitelist parameter member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    id = args["id"]
    # Get exist settings from Fortiweb for validation
    args = get_object_data_before_update(
        client=client,
        value=id,
        get_request=client.custom_whitelist_list_request,
        args=args,
        _parser=client.parser.parse_custom_whitelist,
    )
    client.validate_custom_whitelist(args=args, member_type="Parameter")
    response = client.custom_whitelist_parameter_update_request(
        id=id,
        name=args.get("name"),
        status=args.get("status"),
        name_type=args.get("name_type"),
        request_url_status=args.get("request_url_status"),
        request_type=args.get("request_type"),
        request_url=args.get("request_url"),
        domain_status=args.get("domain_status"),
        domain_type=args.get("domain_type"),
        domain=args.get("domain"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.CUSTOM_WHITELIST_PARAMETER.value,
        object_name=id,
        action=OutputTitle.UPDATED.value,
        response=response,
    )

    return command_results


def custom_whitelist_cookie_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Create a custom whitelist cookie member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.validate_custom_whitelist(args=args, member_type="Cookie")
    name = args["name"]
    response = client.custom_whitelist_cookie_create_request(
        name=name, domain=args.get("domain"), path=args.get("path")
    )
    member_id = client.get_object_id(
        response, "itemName", name, client.custom_whitelist_list_request
    )

    command_results = generate_simple_context_data_command_results(
        "id",
        member_id,
        response,
        OutputTitle.CUSTOM_WHITELIST_COOKIE_CREATE.value,
        "FortiwebVM.CustomGlobalWhitelist",
    )

    return command_results


def custom_whitelist_cookie_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update a custom whitelist cookie member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    id = args["id"]
    # Get exist settings from Fortiweb for validation
    args = get_object_data_before_update(
        client=client,
        value=id,
        get_request=client.custom_whitelist_list_request,
        args=args,
        _parser=client.parser.parse_custom_whitelist,
    )
    client.validate_custom_whitelist(args=args, member_type="Cookie")
    response = client.custom_whitelist_cookie_update_request(
        id=id,
        name=args.get("name"),
        domain=args.get("domain"),
        path=args.get("path"),
        status=args.get("status"),
    )
    command_results = generate_simple_command_results(
        object_type=OutputTitle.CUSTOM_WHITELIST_COOKIE.value,
        object_name=id,
        action=OutputTitle.UPDATED.value,
        response=response,
    )

    return command_results


def custom_whitelist_header_field_create_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Create a custom whitelist header field member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    if not isinstance(client, ClientV2):
        raise ValueError(ErrorMessage.V1_NOT_SUPPORTED.value)
    client.validate_custom_whitelist(args=args, member_type="Header Field")
    name = args["name"]
    response = client.custom_whitelist_header_field_create_request(
        header_name_type=args["header_name_type"],
        name=name,
        value_status=args.get("value_status"),
        header_value_type=args.get("header_value_type"),
        value=args.get("value"),
    )
    member_id = client.get_object_id(
        response, "itemName", name, client.custom_whitelist_list_request
    )

    command_results = generate_simple_context_data_command_results(
        "id",
        member_id,
        response,
        OutputTitle.CUSTOM_WHITELIST_HEADER_FIELD_CREATE.value,
        "FortiwebVM.CustomGlobalWhitelist",
    )

    return command_results


def custom_whitelist_header_field_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update a custom whitelist header field member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    if not isinstance(client, ClientV2):
        raise ValueError(ErrorMessage.V1_NOT_SUPPORTED.value)
    id = args["id"]
    # Get exist settings from Fortiweb for validation
    args = get_object_data_before_update(
        client=client,
        value=id,
        get_request=client.custom_whitelist_list_request,
        args=args,
        _parser=client.parser.parse_custom_whitelist,
    )
    client.validate_custom_whitelist(args=args, member_type="Header Field")
    response = client.custom_whitelist_header_field_update_request(
        id=id,
        header_name_type=args.get("header_name_type"),
        name=args.get("name"),
        status=args.get("status"),
        value_status=args.get("value_status"),
        header_value_type=args.get("header_value_type"),
        value=args.get("value"),
    )

    command_results = generate_simple_command_results(
        object_type=OutputTitle.CUSTOM_WHITELIST_HEADER_FIELD.value,
        object_name=id,
        action=OutputTitle.UPDATED.value,
        response=response,
    )
    return command_results


def custom_whitelist_delete_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Delete a custom whitelist member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    id = args["id"]
    response = client.custom_whitelist_delete_request(id=id)
    command_results = generate_simple_command_results(
        object_type=OutputTitle.CUSTOM_WHITELIST_MEMBER.value,
        object_name=id,
        action=OutputTitle.DELETED.value,
        response=response,
    )
    return command_results


def custom_whitelist_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """List custom whitelist members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    id = args.get("id")
    response = client.custom_whitelist_list_request(id=id)
    # formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data, pagination_message, formatted_response = list_response_handler(
        client, response, client.parser.parse_custom_whitelist, args, id
    )
    readable_output = tableToMarkdown(
        name=OutputTitle.CUSTOM_WHITELIST_LIST.value,
        metadata=pagination_message,
        t=parsed_data,
        headers=["id", "name", "request_url", "path", "domain", "status"],
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.CustomGlobalWhitelist",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def custom_predifined_whitelist_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """List the Custom Predifined members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    id = args.get("id")
    object_type = args.get("type")
    response = client.custom_predifined_whitelist_list_request()

    response = client.custom_predifined_whitelist_list_handler(
        response=response, object_type=object_type
    )

    parsed_data, pagination_message, formatted_response = list_response_handler(
        client=client,
        response=response,
        data_parser=client.parser.parse_custom_predifined_whitelist,
        args=args,
        sub_object_id=id,
    )
    readable_output = tableToMarkdown(
        name=OutputTitle.CUSTOM_PREDIFINED_LIST.value,
        metadata=pagination_message,
        t=parsed_data,
        headers=["id", "name", "path", "domain", "status"],
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiwebVM.CustomPredefinedGlobalWhitelist",
        outputs_key_field="id",
        outputs=parsed_data,
        raw_response=response,
    )
    return command_results


def custom_predifined_whitelist_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Update a Custom Predifined member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    id = args["id"]
    status = args["status"]
    rel_data = {}
    # Get exist data
    response = client.custom_predifined_whitelist_list_request()
    data = (
        response["results"]  # type: ignore # [call-overload] response is dict if client is ClientV2.
        if isinstance(client, ClientV2)
        else response
    )
    for type in data:
        for member in type["details"]:
            if member["value"]:
                id = member["id"]
                rel_data.update({f"{id}_enable": "on"})
    id = args["id"]
    if status == "enable":
        rel_data.update({f"{id}_enable": "on"})
    elif status == "disable":
        rel_data.pop(f"{id}_enable", None)
    response = client.custom_predifined_whitelist_update_request(data=rel_data)

    command_results = generate_simple_command_results(
        object_type=OutputTitle.CUSTOM_PREDIFINED.value,
        object_name=id,
        action=OutputTitle.UPDATED.value,
        response=response,
    )
    return command_results


def list_response_handler(
    client: Client,
    response: Union[List[dict[str, Any]], dict[str, Any]],
    data_parser: Callable,
    args: dict[str, Any],
    sub_object_id: str | None = None,
    internal_path: List[str] | None = None,
    sub_object_key: str = "_id",
) -> tuple[List[dict[str, Any]], str, List[dict[str, Any]]]:
    """Handle the list output response to xsoar output.
    Args:
        client (Client): Fortiweb VM client.
        response (Union[List[Dict[str, Any]], Dict[str, Any]]): Response from list request.
        data_parser (_type_): Parser command.
        args (Dict[str, Any]): Command arguments from XSOAR.
        sub_object_id (Optional[str]): Sub Object ID.
        internal_path (Optional[List[str]]): Internal path inside the response.
        sub_object_key (Optional[str]): Sub Object key.

    Raises:
        DemistoException: The object does not exist.

    Returns:
        Tuple[List[Dict[str, Any]], str, List[Dict[str, Any]]]: Filtered output to xsoar,
        pagination message and response output.
    """
    if isinstance(client, ClientV2) and isinstance(response, dict):
        response = response["results"]
    if internal_path:
        response = dict_safe_get(response, internal_path)
    elif not isinstance(response, list):
        response = [response]
    if sub_object_id and isinstance(response, list):
        group_dict = find_dict_in_array(response, sub_object_key, sub_object_id)
        response = [group_dict] if group_dict else []
        if not response:
            raise DemistoException(ErrorMessage.NOT_EXIST.value)
    response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = parser_handler(response, data_parser)
    return parsed_data, pagination_message, response


def parser_handler(
    data: List[dict[str, Any]], data_parser: Callable
) -> List[dict[str, Any]]:
    """Parse the data by parser command.

    Args:
        data (List[Dict[str, Any]]): The data to parse.
        data_parser (Callable): Parser command.

    Returns:
        List[Dict[str, Any]]: Filtered output to xsoar.
    """
    parsed_data = []
    for obj in data:
        parsed_obj = data_parser(obj)
        parsed_data.append(parsed_obj)
    return parsed_data


def paginate_results(
    version: str, response: Union[List, dict[str, Any]], args: dict[str, Any]
) -> tuple[list, str]:
    """Executing Manual paginate_results  (using the page and page size arguments)
        or Automatic paginate_results  (display a number of total results).
    Args:
        response (Union[Dict[str, Any], List[Dict[str, Any]]]): API response.
        page (int, optional): Page number of paginated results.
        page_size (int, optional): Number of ip-list per page.
        limit (int, optional): The maximum number of records to retrieve.
    Returns:
        Tuple[dict,str]: Output and paginate_results  message for Command Results.
    """
    response = response if isinstance(response, list) else [response]
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit", LIMIT_SIZE))

    output = response

    if page and page_size:
        if page_size < len(response):
            first_item = page_size * (page - 1)
            output = response[first_item: (first_item + page_size)]
        else:
            output = response[:page_size]
        pagination_message = f"Showing page {page}. \n Current page size: {page_size}"
    else:
        output = response[:limit]
        pagination_message = f"Showing {len(output)} rows out of {len(response)}."

    return output, pagination_message


def find_dict_in_array(
    container: List[dict[str, Any]], key: str, value: str
) -> dict[str, Any] | None:
    """Gets dictionary object in list of dictionaries.The search is by key that exist in each dictionary.

    Args:
        container (list): List of dictionaries.
        key (str): Key to recognize the correct dictionary.
        value (str]): The value for the key.

    Returns:
        Optional[Dict[str, Any]]: The dictionary / The dictionaries / None if there is no match.
    """

    for obj in container:
        if key in obj and str(obj[key]) == value:
            return obj
    return None


def find_dicts_in_array(
    container: List[dict[str, Any]], key: str, value: List[str]
) -> List[dict[str, Any]]:
    """Gets dictionaries object in list of dictionaries.The search is by key that exist in each dictionary.

    Args:
        container (list): List of dictionaries.
        key (str): Key to recognize the correct dictionary.
        value (List[str]): The values for the key.

    Returns:
        List[Dict[str, Any]]: List of the dictionaries.
    """

    return [obj for obj in container if obj[key] in value]


def get_object_data(
    version: str,
    by_key: str,
    value: str,
    get_request: Callable,
    object_id: str | None = None,
) -> dict[str, Any] | None:
    """Get object data.

    Args:
        version (str): Client version.
        by_key (str): Unique key to search the object.
        value (str): The object value to the key.
        get_request (Callable): Get request.
        object_id (Optional[str]): Object ID (not sub object)!

    Returns:
        Optional[Dict[str, Any]]: The object data from the get response.
    """
    if members_list := get_request(object_id) if object_id else get_request():
        members_list = (
            members_list if version == ClientV1.API_VER else members_list["results"]
        )
        return find_dict_in_array(members_list, by_key, value)
    return None


def test_module(client: Client) -> str:
    """Test module.

    Args:
        client (Client): Fortiweb VM client.

    Raises:
        error: In case that there are problem with the connection.

    Returns:
        str: Output message.
    """
    try:
        client.protected_hostname_list_request()
    except DemistoException as error:
        if (
            error.res
            and error.res.status_code
            and error.res.status_code == HTTPStatus.UNAUTHORIZED
        ):
            return "Authorization Error: make sure API key is correctly set"
        raise error
    except Exception as error:
        return f"Error: {error}"
    return "ok"


def reverse_dict(dict_: dict[str, str] | dict[str, int]) -> dict:
    """Reverse dictionary.

    Args:
        dict_ (dict[str, Any]): Dictionary to reverse.

    Returns:
        dict[Any, str]: Reversed dictionary.
    """
    return {v: k for k, v in dict_.items()}


def generate_simple_command_results(
    object_type: str, object_name: str, action: str, response: dict[str, Any]
) -> CommandResults:
    """Genarte a simple command result with output (without context data).

    Args:
        key (str): Output key.
        value (str): Output value.
        response (Dict[str, Any]): Response dictionary from Fortiweb VM
        message (str): Output message.

    Returns:
        CommandResults: CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    message = f"{object_type} {object_name} {action}"
    command_results = CommandResults(readable_output=message, raw_response=response)
    return command_results


def generate_simple_context_data_command_results(
    key: str, value: str, response: dict[str, Any], message: str, outputs_prefix: str
) -> CommandResults:
    """Genarte a simple command result with output (with context data).

    Args:
        key (str): Output key.
        value (str): Output value.
        response (Dict[str, Any]): Response dictionary from Fortiweb VM
        message (str): Output message.
        outputs_prefix (str): Command result outputs prefix.

    Returns:
        CommandResults: CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    outputs = {key: value}
    readable_output = tableToMarkdown(
        message, outputs, headerTransform=string_to_table_header
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix=outputs_prefix,
        outputs_key_field=key,
        outputs=outputs,
        raw_response=response,
    )

    return command_results


def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    base_url = str(params.get("url"))
    username = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")
    version = params["api_version"]
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    commands = {
        "fortiwebvm-protected-hostname-group-create": protected_hostname_group_create_command,
        "fortiwebvm-protected-hostname-group-update": protected_hostname_group_update_command,
        "fortiwebvm-protected-hostname-group-delete": protected_hostname_group_delete_command,
        "fortiwebvm-protected-hostname-group-list": protected_hostname_group_list_command,
        "fortiwebvm-protected-hostname-member-create": protected_hostname_member_create_command,
        "fortiwebvm-protected-hostname-member-update": protected_hostname_member_update_command,
        "fortiwebvm-protected-hostname-member-delete": protected_hostname_member_delete_command,
        "fortiwebvm-protected-hostname-member-list": protected_hostname_member_list_command,
        "fortiwebvm-ip-list-group-create": ip_list_group_create_command,
        "fortiwebvm-ip-list-group-update": ip_list_group_update_command,
        "fortiwebvm-ip-list-group-delete": ip_list_group_delete_command,
        "fortiwebvm-ip-list-group-list": ip_list_group_list_command,
        "fortiwebvm-ip-list-member-create": ip_list_member_create_command,
        "fortiwebvm-ip-list-member-update": ip_list_member_update_command,
        "fortiwebvm-ip-list-member-delete": ip_list_member_delete_command,
        "fortiwebvm-ip-list-member-list": ip_list_member_list_command,
        "fortiwebvm-http-content-routing-member-add": http_content_routing_member_add_command,
        "fortiwebvm-http-content-routing-member-update": http_content_routing_member_update_command,
        "fortiwebvm-http-content-routing-member-delete": http_content_routing_member_delete_command,
        "fortiwebvm-http-content-routing-member-list": http_content_routing_member_list_command,
        "fortiwebvm-geo-ip-group-create": geo_ip_group_create_command,
        "fortiwebvm-geo-ip-group-update": geo_ip_group_update_command,
        "fortiwebvm-geo-ip-group-delete": geo_ip_group_delete_command,
        "fortiwebvm-geo-ip-group-list": geo_ip_group_list_command,
        "fortiwebvm-geo-ip-member-add": geo_ip_member_add_command,
        "fortiwebvm-geo-ip-member-delete": geo_ip_member_delete_command,
        "fortiwebvm-geo-ip-member-list": geo_ip_member_list_command,
        "fortiwebvm-system-operation-status-get": operation_status_get_command,
        "fortiwebvm-system-policy-status-get": policy_status_get_command,
        "fortiwebvm-system-status-get": system_status_get_command,
        "fortiwebvm-server-pool-list": server_pool_list_command,
        "fortiwebvm-http-service-list": http_service_list_command,
        "fortiwebvm-inline-protection-profile-list": inline_protection_profile_list_command,
        "fortiwebvm-virtual-server-list": virtual_server_list_command,
        "fortiwebvm-content-routing-policy-list": http_content_routing_policy_list_command,
        "fortiwebvm-server-policy-create": server_policy_create_command,
        "fortiwebvm-server-policy-update": server_policy_update_command,
        "fortiwebvm-server-policy-delete": server_policy_delete_command,
        "fortiwebvm-server-policy-list": server_policy_list_command,
        "fortiwebvm-custom-whitelist-url-create": custom_whitelist_url_create_command,
        "fortiwebvm-custom-whitelist-url-update": custom_whitelist_url_update_command,
        "fortiwebvm-custom-whitelist-parameter-create": custom_whitelist_parameter_create_command,
        "fortiwebvm-custom-whitelist-parameter-update": custom_whitelist_parameter_update_command,
        "fortiwebvm-custom-whitelist-cookie-create": custom_whitelist_cookie_create_command,
        "fortiwebvm-custom-whitelist-cookie-update": custom_whitelist_cookie_update_command,
        "fortiwebvm-custom-whitelist-header-field-create": custom_whitelist_header_field_create_command,
        "fortiwebvm-custom-whitelist-header-field-update": custom_whitelist_header_field_update_command,
        "fortiwebvm-custom-whitelist-delete": custom_whitelist_delete_command,
        "fortiwebvm-custom-whitelist-list": custom_whitelist_list_command,
        "fortiwebvm-geo-exception-list": geo_exception_list_command,
        "fortiwebvm-trigger-policy-list": trigger_policy_list_command,
        "fortiwebvm-custom-predefined-whitelist-list": custom_predifined_whitelist_list_command,
        "fortiwebvm-custom-predefined-whitelist-update": custom_predifined_whitelist_update_command,
        "fortiwebvm-certificate-intermediate-group-list": certificate_intermediate_group_list_command,
    }
    try:
        client_class = {"V1": ClientV1, "V2": ClientV2}[version]
        client: Client = client_class(
            base_url=base_url,
            username=username,
            password=password,
            version=version,
            proxy=proxy,
            verify=verify_certificate,
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as error:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(error)}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
