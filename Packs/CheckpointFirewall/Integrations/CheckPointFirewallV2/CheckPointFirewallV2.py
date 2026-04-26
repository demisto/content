import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_LIST_FIELD = [
    "name",
    "uid",
    "type",
    "ipv4-address",
    "ipv6-address",
    "domain-name",
    "domain-uid",
    "groups",
    "read-only",
    "creator",
    "last-modifier",
]


class Client(BaseClient):
    """
    Client for CheckPoint RESTful API.
    Args:
          base_url (str): the URL of CheckPoint.
          sid (str): CheckPoint session ID of the current user session. [Optional]
          use_ssl (bool): specifies whether to verify the SSL certificate or not.
          use_proxy (bool): specifies if to use Demisto proxy settings.
    """

    def __init__(self, base_url: str, use_ssl: bool, use_proxy: bool, sid: Optional[str] = None, **kwargs):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, **kwargs)
        self.verify = use_ssl
        self.sid = sid if sid != "None" else None
        self.has_performed_login = False  # set to True once username and password are used to login.
        """ Note that Client is "disposable", and will not be the same object on the next command,
        has_performed_login is used to decide whether to logout after running the command."""

    @property
    def headers(self):
        if self.sid is None:  # for logging in, before self.sid is set
            return {"Content-Type": "application/json"}
        return {"Content-Type": "application/json", "X-chkp-sid": self.sid}

    def login(self, username: str, password: str, session_timeout: int, domain_arg: str = None) -> CommandResults:
        """login to a checkpoint admin account using username and password."""

        json_body = {"user": username, "password": password, "session-timeout": session_timeout}
        if domain_arg:
            json_body["domain"] = domain_arg

        response = self._http_request(method="POST", url_suffix="login", json_data=json_body, headers=self.headers)
        sid = response.get("sid", "")

        if sid:
            self.sid = sid
            self.has_performed_login = True
            demisto.debug(f"login: success, saving sid={sid} to integrationContext")
            demisto.setIntegrationContext({"cp_sid": sid})
        else:
            demisto.debug("login: failed, clearing integrationContext")
            demisto.setIntegrationContext({})

        printable_result = {"session-id": sid}
        readable_output = tableToMarkdown("CheckPoint session data:", printable_result)

        return CommandResults(
            outputs_prefix="CheckPoint.Login",
            outputs_key_field="uid",
            readable_output=readable_output,
            outputs=printable_result,
            raw_response=response,
        )

    def restore_sid_from_context_or_login(self, username: str, password: str, session_timeout: int, domain_arg: str = None):
        if sid_from_context := demisto.getIntegrationContext().get("cp_sid"):
            demisto.debug(f"restore sid: success, setting restored sid on Client (sid={sid_from_context})")
            self.sid = sid_from_context
        else:
            demisto.debug("restore sid: failed to restore, logging in")
            self.login(username, password, session_timeout, domain_arg)

    def test_connection(self):
        """
        Returns ok on a successful connection to the CheckPoint Firewall API.
        Otherwise, an exception should be raised by self._http_request()
        """
        response = self._http_request(
            method="POST",
            url_suffix="show-api-versions",
            headers=self.headers,
            ok_codes=(200, 500),
            resp_type="response",
            json_data={},
        )
        if response.status_code == 500:
            return "Server Error: make sure Server URL and Server Port are correctly set"

        if response.json() and response.json().get("message") == "Missing header: [X-chkp-sid]":
            return "\nWrong credentials! Please check the username and password you entered and try again."

        return "ok"

    def logout(self) -> str:
        """logout from current session, returning the response message"""
        response = self._http_request(method="POST", url_suffix="logout", headers=self.headers, json_data={})
        self.sid = None
        demisto.setIntegrationContext({})
        self.has_performed_login = False

        message = response.get("message")
        demisto.debug(f"logout: sid={self.sid}, message={message}")
        return message

    def list_hosts(self, limit: int, offset: int):
        return self._http_request(
            method="POST",
            url_suffix="show-hosts",
            headers=self.headers,
            resp_type="json",
            json_data={"limit": limit, "offset": offset},
        )

    def get_host(self, identifier: str):
        return self._http_request(method="POST", url_suffix="show-host", headers=self.headers, json_data={"name": identifier})

    def add_host(self, name, ip_address, ignore_warnings: bool, ignore_errors: bool, groups):
        return self._http_request(
            method="POST",
            url_suffix="add-host",
            headers=self.headers,
            json_data={
                "name": name,
                "ip-address": ip_address,
                "ignore-warnings": ignore_warnings,
                "ignore-errors": ignore_errors,
                "groups": groups,
            },
        )

    def update_host(
        self,
        identifier: str,
        ignore_warnings: bool,
        ignore_errors: bool,
        ip_address: Optional[str],
        new_name: Optional[str],
        comments: Optional[str],
        groups,
    ):
        body = {
            "name": identifier,
            "ip-address": ip_address,
            "new-name": new_name,
            "comments": comments,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
            "groups": groups,
        }
        response = self._http_request(method="POST", url_suffix="set-host", headers=self.headers, json_data=body)
        return response

    def delete_host(self, identifier: str, ignore_warnings: bool, ignore_errors: bool):
        return self._http_request(
            method="POST",
            url_suffix="delete-host",
            headers=self.headers,
            json_data={"name": identifier, "ignore-warnings": ignore_warnings, "ignore-errors": ignore_errors},
        )

    def list_groups(self, limit: int, offset: int):
        return self._http_request(
            method="POST", url_suffix="show-groups", headers=self.headers, json_data={"limit": limit, "offset": offset}
        )

    def get_group(self, identifier: str):
        return self._http_request(method="POST", url_suffix="show-group", headers=self.headers, json_data={"name": identifier})

    def add_group(self, name: str):
        return self._http_request(method="POST", url_suffix="add-group", headers=self.headers, json_data={"name": name})

    def update_group(
        self,
        identifier: str,
        ignore_warnings: bool,
        ignore_errors: bool,
        action: str,
        members,
        new_name: Optional[str],
        comments: Optional[str],
    ):
        # If the desired action is to add or remove members, they should be specified differently.
        members_value = {action: members} if action in ["add", "remove"] else members
        body = {
            "name": identifier,
            "new-name": new_name,
            "members": members_value,
            "comments": comments,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
        }

        response = self._http_request(method="POST", url_suffix="set-group", headers=self.headers, json_data=body)
        return response

    def delete_group(self, identifier: str):
        return self._http_request(method="POST", url_suffix="delete-group", headers=self.headers, json_data={"name": identifier})

    def list_address_ranges(self, limit: int, offset: int):
        return self._http_request(
            method="POST", url_suffix="show-address-ranges", headers=self.headers, json_data={"limit": limit, "offset": offset}
        )

    def get_address_range(self, identifier: str):
        return self._http_request(
            method="POST", url_suffix="show-address-range", headers=self.headers, json_data={"name": identifier}
        )

    def add_address_range(
        self,
        name: str,
        ip_address_first: str,
        ip_address_last: str,
        set_if_exists: bool,
        ignore_warnings: bool,
        ignore_errors: bool,
        groups,
    ):
        body = {
            "name": name,
            "ip-address-first": ip_address_first,
            "ip-address-last": ip_address_last,
            "set-if-exists": set_if_exists,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
            "groups": groups,
        }
        return self._http_request(method="POST", url_suffix="add-address-range", headers=self.headers, json_data=body)

    def update_address_range(
        self,
        identifier: str,
        ignore_warnings: bool,
        ignore_errors: bool,
        ip_address_first: Optional[str],
        ip_address_last: Optional[str],
        new_name: Optional[str],
        comments: Optional[str],
        groups,
    ):
        body = {
            "name": identifier,
            "ip-address-first": ip_address_first,
            "ip-address-last": ip_address_last,
            "new-name": new_name,
            "comments": comments,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
            "groups": groups,
        }
        return self._http_request(method="POST", url_suffix="set-address-range", headers=self.headers, json_data=body)

    def delete_address_range(self, identifier: str):
        return self._http_request(
            method="POST", url_suffix="delete-address-range", headers=self.headers, json_data={"name": identifier}
        )

    def list_threat_indicators(self, limit: int, offset: int):
        return self._http_request(
            method="POST", url_suffix="show-threat-indicators", headers=self.headers, json_data={"limit": limit, "offset": offset}
        )

    def get_threat_indicator(self, identifier):
        return self._http_request(
            method="POST", url_suffix="show-threat-indicator", headers=self.headers, json_data={"name": identifier}
        )

    def add_threat_indicator(self, name: str, observables: list):
        return self._http_request(
            method="POST",
            url_suffix="add-threat-indicator",
            headers=self.headers,
            json_data={"name": name, "observables": observables},
        )

    def update_threat_indicator(self, identifier: str, action: str = None, new_name: str = None, comments: str = None):
        body = {"name": identifier, "action": action, "new-name": new_name, "comments": comments}
        return self._http_request(method="POST", url_suffix="set-threat-indicator", headers=self.headers, json_data=body)

    def delete_threat_indicator(self, identifier: str):
        return self._http_request(
            method="POST", url_suffix="delete-threat-indicator", headers=self.headers, json_data={"name": identifier}
        )

    def list_access_rule(self, identifier: str, limit: int, offset: int):
        body = {"name": identifier, "limit": limit, "offset": offset}
        return self._http_request(method="POST", url_suffix="show-access-rulebase", headers=self.headers, json_data=body)

    def add_rule(self, layer: str, position, action: str, name: Optional[str], vpn: Optional[str], destination, service, source):
        body = {
            "layer": layer,
            "position": position,
            "name": name,
            "action": action,
            "destination": destination,
            "service": service,
            "source": source,
            "vpn": vpn,
        }
        return self._http_request(method="POST", url_suffix="add-access-rule", headers=self.headers, json_data=body)

    def update_rule(
        self,
        identifier: str,
        layer: str,
        ignore_warnings: bool,
        ignore_errors: bool,
        enabled: bool,
        action: Optional[str],
        new_name: Optional[str],
        new_position,
    ):
        body = {
            "name": identifier,
            "layer": layer,
            "action": action,
            "enabled": enabled,
            "new-name": new_name,
            "new-position": new_position,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
        }
        return self._http_request(method="POST", url_suffix="set-access-rule", headers=self.headers, json_data=body)

    def delete_rule(self, identifier: str, layer: str):
        return self._http_request(
            method="POST", url_suffix="delete-access-rule", headers=self.headers, json_data={"name": identifier, "layer": layer}
        )

    def list_application_site(self, limit: int, offset: int):
        body = {"limit": limit, "offset": offset}
        return self._http_request(method="POST", url_suffix="show-application-sites", headers=self.headers, json_data=body)

    def add_application_site(self, name: str, primary_category: str, identifier, groups):
        body = {"name": name, "primary-category": primary_category, "url-list": identifier, "groups": groups}
        return self._http_request(method="POST", url_suffix="add-application-site", headers=self.headers, json_data=body)

    def update_application_site(
        self,
        identifier: str,
        urls_defined_as_regular_expression: bool,
        groups,
        url_list,
        description: Optional[str],
        new_name: Optional[str],
        primary_category: Optional[str],
        application_signature: Optional[str],
    ):
        body = {
            "name": identifier,
            "description": description,
            "new-name": new_name,
            "primary-category": primary_category,
            "urls-defined-as-regular-expression": urls_defined_as_regular_expression,
            "groups": groups,
            "application-signature": application_signature,
            "url-list": url_list,
        }
        return self._http_request(method="POST", url_suffix="set-application-site", headers=self.headers, json_data=body)

    def add_objects_batch(self, object_type, add_list):
        body = {"objects": [{"type": object_type, "list": add_list}]}
        return self._http_request(method="POST", url_suffix="add-objects-batch", headers=self.headers, json_data=body)

    def delete_objects_batch(self, object_type, delete_list):
        body = {"objects": [{"type": object_type, "list": delete_list}]}
        return self._http_request(method="POST", url_suffix="delete-objects-batch", headers=self.headers, json_data=body)

    def delete_application_site(self, identifier: str):
        return self._http_request(
            method="POST", url_suffix="delete-application-site", headers=self.headers, json_data={"name": identifier}
        )

    def show_network(self, identifier: str, details_level: Optional[str] = None):
        body: dict = {"name": identifier}
        if details_level:
            body["details-level"] = details_level
        demisto.debug(f"show-network request body: {body}")
        return self._http_request(method="POST", url_suffix="show-network", headers=self.headers, json_data=body)

    def list_networks(self, limit: int, offset: int, details_level: Optional[str] = None):
        body: dict = {"limit": limit, "offset": offset}
        if details_level:
            body["details-level"] = details_level
        demisto.debug(f"show-networks request body: {body}")
        return self._http_request(method="POST", url_suffix="show-networks", headers=self.headers, json_data=body)

    def add_network(
        self,
        identifier: str,
        subnet: str,
        mask_length: Optional[int] = None,
        subnet_mask: Optional[str] = None,
        comments: Optional[str] = None,
        color: Optional[str] = None,
        tags: Optional[list] = None,
        broadcast: Optional[str] = None,
        nat_settings: Optional[dict] = None,
    ):
        body: dict = {"name": identifier, "subnet4": subnet}
        if mask_length is not None:
            body["mask-length4"] = mask_length
        if subnet_mask:
            body["subnet-mask"] = subnet_mask
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        if broadcast:
            body["broadcast"] = broadcast
        if nat_settings:
            body["nat-settings"] = nat_settings
        demisto.debug(f"add-network request body: {body}")
        return self._http_request(method="POST", url_suffix="add-network", headers=self.headers, json_data=body)

    def update_network(
        self,
        identifier: str,
        new_identifier: Optional[str] = None,
        subnet: Optional[str] = None,
        subnet_mask: Optional[str] = None,
        comments: Optional[str] = None,
        color: Optional[str] = None,
        tags: Optional[list] = None,
        broadcast: Optional[str] = None,
        nat_settings: Optional[dict] = None,
    ):
        body: dict = {"name": identifier}
        if new_identifier:
            body["new-name"] = new_identifier
        if subnet:
            body["subnet4"] = subnet
        if subnet_mask:
            body["subnet-mask"] = subnet_mask
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        if broadcast:
            body["broadcast"] = broadcast
        if nat_settings:
            body["nat-settings"] = nat_settings
        demisto.debug(f"set-network request body: {body}")
        return self._http_request(method="POST", url_suffix="set-network", headers=self.headers, json_data=body)

    def delete_network(self, identifier: str, ignore_warnings: bool = True):
        body: dict = {"name": identifier, "ignore-warnings": ignore_warnings}
        demisto.debug(f"delete-network request body: {body}")
        return self._http_request(
            method="POST",
            url_suffix="delete-network",
            headers=self.headers,
            json_data=body,
        )

    def show_service(self, identifier: str, service_type: str):
        body: dict = {"name": identifier}
        demisto.debug(f"show-service-{service_type} request body: {body}")
        return self._http_request(method="POST", url_suffix=f"show-service-{service_type}", headers=self.headers, json_data=body)

    def list_services(self, limit: int, offset: int, service_type: str):
        body: dict = {"limit": limit, "offset": offset}
        demisto.debug(f"show-services-{service_type} request body: {body}")
        return self._http_request(
            method="POST",
            url_suffix=f"show-services-{service_type}",
            headers=self.headers,
            json_data=body,
        )

    def add_service_tcp(
        self,
        identifier: str,
        port: Optional[str] = None,
        comments: Optional[str] = None,
        color: Optional[str] = None,
        session_timeout: Optional[int] = None,
        tags: Optional[list] = None,
    ):
        body: dict = {"name": identifier}
        if port:
            body["port"] = port
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if session_timeout is not None:
            body["session-timeout"] = session_timeout
        if tags:
            body["tags"] = tags
        demisto.debug(f"add-service-tcp request body: {body}")
        return self._http_request(method="POST", url_suffix="add-service-tcp", headers=self.headers, json_data=body)

    def add_service_udp(
        self,
        identifier: str,
        port: Optional[str] = None,
        comments: Optional[str] = None,
        color: Optional[str] = None,
        session_timeout: Optional[int] = None,
        tags: Optional[list] = None,
    ):
        body: dict = {"name": identifier}
        if port:
            body["port"] = port
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if session_timeout is not None:
            body["session-timeout"] = session_timeout
        if tags:
            body["tags"] = tags
        demisto.debug(f"add-service-udp request body: {body}")
        return self._http_request(method="POST", url_suffix="add-service-udp", headers=self.headers, json_data=body)

    def add_service_icmp(
        self,
        identifier: str,
        icmp_type: Optional[int] = None,
        icmp_code: Optional[int] = None,
        comments: Optional[str] = None,
        color: Optional[str] = None,
        tags: Optional[list] = None,
    ):
        body: dict = {"name": identifier}
        if icmp_type is not None:
            body["icmp-type"] = icmp_type
        if icmp_code is not None:
            body["icmp-code"] = icmp_code
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        demisto.debug(f"add-service-icmp request body: {body}")
        return self._http_request(method="POST", url_suffix="add-service-icmp", headers=self.headers, json_data=body)

    def update_service_tcp(
        self,
        identifier: str,
        new_identifier: Optional[str] = None,
        port: Optional[str] = None,
        comments: Optional[str] = None,
        color: Optional[str] = None,
        tags: Optional[list] = None,
    ):
        body: dict = {"name": identifier}
        if new_identifier:
            body["new-name"] = new_identifier
        if port:
            body["port"] = port
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        demisto.debug(f"set-service-tcp request body: {body}")
        return self._http_request(method="POST", url_suffix="set-service-tcp", headers=self.headers, json_data=body)

    def update_service_udp(
        self,
        identifier: str,
        new_identifier: Optional[str] = None,
        port: Optional[str] = None,
        comments: Optional[str] = None,
        color: Optional[str] = None,
        tags: Optional[list] = None,
    ):
        body: dict = {"name": identifier}
        if new_identifier:
            body["new-name"] = new_identifier
        if port:
            body["port"] = port
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        demisto.debug(f"set-service-udp request body: {body}")
        return self._http_request(method="POST", url_suffix="set-service-udp", headers=self.headers, json_data=body)

    def update_service_icmp(
        self,
        identifier: str,
        new_identifier: Optional[str] = None,
        icmp_type: Optional[int] = None,
        icmp_code: Optional[int] = None,
        comments: Optional[str] = None,
        color: Optional[str] = None,
        tags: Optional[list] = None,
    ):
        body: dict = {"name": identifier}
        if new_identifier:
            body["new-name"] = new_identifier
        if icmp_type is not None:
            body["icmp-type"] = icmp_type
        if icmp_code is not None:
            body["icmp-code"] = icmp_code
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        demisto.debug(f"set-service-icmp request body: {body}")
        return self._http_request(method="POST", url_suffix="set-service-icmp", headers=self.headers, json_data=body)

    def delete_service(self, identifier: str, service_type: str, ignore_warnings: bool = False):
        body: dict = {"name": identifier}
        if ignore_warnings:
            body["ignore-warnings"] = ignore_warnings
        demisto.debug(f"delete-service-{service_type} request body: {body}")
        return self._http_request(
            method="POST", url_suffix=f"delete-service-{service_type}", headers=self.headers, json_data=body
        )

    def show_nat_rule(self, identifier: str, package: str):
        identifier_key = "rule-number" if str(identifier).isdigit() else "name"
        body: dict = {identifier_key: identifier, "package": package}
        demisto.debug(f"show-nat-rule request body: {body}")
        return self._http_request(
            method="POST",
            url_suffix="show-nat-rule",
            headers=self.headers,
            json_data=body,
        )

    def list_nat_rulebase(self, package: str, limit: int, offset: int, filter_str: Optional[str] = None):
        body: dict = {"package": package, "limit": limit, "offset": offset}
        if filter_str:
            body["filter"] = filter_str
        demisto.debug(f"show-nat-rulebase request body: {body}")
        return self._http_request(method="POST", url_suffix="show-nat-rulebase", headers=self.headers, json_data=body)

    def add_nat_rule(
        self,
        package: str,
        position: str,
        name: Optional[str] = None,
        original_source: Optional[str] = None,
        original_destination: Optional[str] = None,
        original_service: Optional[str] = None,
        translated_source: Optional[str] = None,
        translated_destination: Optional[str] = None,
        translated_service: Optional[str] = None,
        install_on: Optional[list] = None,
        comments: Optional[str] = None,
        enabled: Optional[bool] = None,
        method: Optional[str] = None,
        tags: Optional[list] = None,
    ):
        body: dict = {"package": package, "position": position}
        if name:
            body["name"] = name
        if original_source:
            body["original-source"] = original_source
        if original_destination:
            body["original-destination"] = original_destination
        if original_service:
            body["original-service"] = original_service
        if translated_source:
            body["translated-source"] = translated_source
        if translated_destination:
            body["translated-destination"] = translated_destination
        if translated_service:
            body["translated-service"] = translated_service
        if install_on:
            body["install-on"] = install_on
        if comments:
            body["comments"] = comments
        if enabled is not None:
            body["enabled"] = enabled
        if method:
            body["method"] = method
        if tags:
            body["tags"] = tags
        demisto.debug(f"add-nat-rule request body: {body}")
        return self._http_request(method="POST", url_suffix="add-nat-rule", headers=self.headers, json_data=body)

    def update_nat_rule(
        self,
        identifier: str,
        package: str,
        original_source: Optional[str] = None,
        original_destination: Optional[str] = None,
        translated_source: Optional[str] = None,
        translated_destination: Optional[str] = None,
        original_service: Optional[str] = None,
        translated_service: Optional[str] = None,
        comments: Optional[str] = None,
        enabled: Optional[bool] = None,
        method: Optional[str] = None,
        tags: Optional[list] = None,
    ):
        identifier_key = "rule-number" if str(identifier).isdigit() else "name"
        body: dict = {identifier_key: identifier, "package": package}
        if original_source:
            body["original-source"] = original_source
        if original_destination:
            body["original-destination"] = original_destination
        if translated_source:
            body["translated-source"] = translated_source
        if translated_destination:
            body["translated-destination"] = translated_destination
        if original_service:
            body["original-service"] = original_service
        if translated_service:
            body["translated-service"] = translated_service
        if comments:
            body["comments"] = comments
        if enabled is not None:
            body["enabled"] = enabled
        if method:
            body["method"] = method
        if tags:
            body["tags"] = tags
        demisto.debug(f"set-nat-rule request body: {body}")
        return self._http_request(method="POST", url_suffix="set-nat-rule", headers=self.headers, json_data=body)

    def delete_nat_rule(self, identifier: str, package: str):
        identifier_key = "rule-number" if str(identifier).isdigit() else "name"
        body: dict = {identifier_key: identifier, "package": package}
        demisto.debug(f"delete-nat-rule request body: {body}")
        return self._http_request(method="POST", url_suffix="delete-nat-rule", headers=self.headers, json_data=body)

    def show_task(self, task_id):
        return self._http_request(method="POST", url_suffix="show-task", headers=self.headers, json_data={"task-id": task_id})

    def list_objects(self, limit: int, offset: int, filter_search: str, ip_only: bool, object_type: str):
        body = {"limit": limit, "offset": offset, "filter": filter_search, "ip-only": ip_only, "type": object_type}
        return self._http_request(method="POST", url_suffix="show-objects", headers=self.headers, json_data=body)

    def list_application_site_categories(self, limit: int, offset: int):
        body = {"limit": limit, "offset": offset}
        return self._http_request(
            method="POST", url_suffix="show-application-site-categories", headers=self.headers, json_data=body
        )

    def get_application_site_category(self, identifier: str):
        return self._http_request(
            method="POST", url_suffix="show-application-site-category", headers=self.headers, json_data={"name": identifier}
        )

    def add_application_site_category(self, identifier: str, groups):
        body = {"name": identifier, "groups": groups}
        return self._http_request(method="POST", url_suffix="add-application-site-category", headers=self.headers, json_data=body)

    def list_packages(self, limit: int, offset: int):
        response = self._http_request(
            method="POST", url_suffix="show-packages", headers=self.headers, json_data={"limit": limit, "offset": offset}
        )
        return response.get("packages")

    def list_package(self, identifier: str):
        return self._http_request(method="POST", url_suffix="show-package", headers=self.headers, json_data={"name": identifier})

    def list_gateways(self, limit: int, offset: int):
        response = self._http_request(
            method="POST",
            url_suffix="show-gateways-and-servers",
            headers=self.headers,
            json_data={"limit": limit, "offset": offset, "details-level": "full"},
        )
        return response.get("objects")

    def publish(self):
        return self._http_request(method="POST", url_suffix="publish", headers=self.headers, json_data={})

    def install_policy(self, policy_package: str, targets, access: bool):
        body = {
            "policy-package": policy_package,
            "targets": targets,
            "access": access,
        }
        return self._http_request(method="POST", url_suffix="install-policy", headers=self.headers, json_data=body)

    def verify_policy(self, policy_package: str):
        body = {
            "policy-package": policy_package,
        }
        return self._http_request(method="POST", url_suffix="verify-policy", headers=self.headers, json_data=body)

    def show_threat_protection(self, uid: str, name: str, properties: bool, profiles: bool):
        body = {"show-ips-additional-properties": properties, "show-profiles": profiles}
        if uid:
            body["uid"] = uid  # type: ignore

        elif name:
            body["name"] = name  # type: ignore
        return self._http_request(method="POST", url_suffix="show-threat-protection", headers=self.headers, json_data=body)

    def show_threat_protections(self, args):
        return self._http_request(method="POST", url_suffix="show-threat-protections", headers=self.headers, json_data=args)

    def add_threat_profile(self, args):
        return self._http_request(method="POST", url_suffix="add-threat-profile", headers=self.headers, json_data=args)

    def delete_threat_protections(self, args):
        return self._http_request(method="POST", url_suffix="delete-threat-protections", headers=self.headers, json_data=args)

    def set_threat_protection(self, args):
        return self._http_request(method="POST", url_suffix="set-threat-protection", headers=self.headers, json_data=args)


def checkpoint_list_hosts_command(client: Client, limit: int, offset: int) -> CommandResults:
    """
    Retrieve all host objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
    """
    printable_result = []
    readable_output = ""

    result = client.list_hosts(limit, offset)
    demisto.info(result)
    if result:
        if result.get("total") == 0:
            readable_output = "No hosts objects were found."
        else:
            result = result.get("objects")
            for element in result:
                current_printable_result = {}
                for endpoint in DEFAULT_LIST_FIELD:
                    current_printable_result[endpoint] = element.get(endpoint)
                printable_result.extend([current_printable_result])

            readable_output = tableToMarkdown(
                "CheckPoint data for all hosts:", printable_result, DEFAULT_LIST_FIELD, removeNull=True
            )
    command_results = CommandResults(
        outputs_prefix="CheckPoint.Host",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_get_host_command(client: Client, identifier: str) -> CommandResults:
    """
    Show existing host object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
    """
    result = client.get_host(identifier)
    printable_result = build_printable_result(DEFAULT_LIST_FIELD, result)
    readable_output = tableToMarkdown(
        f"CheckPoint data of host object {identifier}:", printable_result, headers=DEFAULT_LIST_FIELD, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.Host",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_add_host_command(
    client: Client, name, ip_address, ignore_warnings: Union[bool, str], ignore_errors: Union[bool, str], groups: str = None
) -> CommandResults:
    """
    Add new host object.

    Args:
        client (Client): CheckPoint client.
        name(str): host name.
        ip_address: ip address linked to the host.
        groups (str or list): Collection of group identifiers.
        ignore_warnings (str): Whether to ignore warnings when adding a host.
        ignore_errors (str): Whether to ignore errors when adding a host.
    """
    name = argToList(name)
    ip_address = argToList(ip_address)
    groups = argToList(groups)
    ignore_warnings = argToBoolean(ignore_warnings)
    ignore_errors = argToBoolean(ignore_errors)

    result = []
    context = []
    readable_output = ""
    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "last-modifier",
        "ipv4-address",
        "ipv6-address",
        "read-only",
        "groups",
    ]

    if len(name) != len(ip_address):
        raise ValueError("Number of host-names and host-IP has to be equal")
    else:
        for index, item in enumerate(name):
            current_result = client.add_host(item, ip_address[index], ignore_warnings, ignore_errors, groups)
            printable_result = build_printable_result(headers, current_result)
            current_readable_output = tableToMarkdown(
                "CheckPoint data for adding host:", printable_result, headers=headers, removeNull=True
            )
            readable_output = readable_output + current_readable_output
            result.append(current_result)
            context.append(printable_result)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.Host",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=context,
        raw_response=result,
    )
    return command_results


def checkpoint_update_host_command(
    client: Client,
    identifier: str,
    ignore_warnings: bool,
    ignore_errors: bool,
    ip_address: str = None,
    new_name: str = None,
    comments: str = None,
    groups=None,
) -> CommandResults:
    """
    Edit existing host using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
        ignore_warnings(bool):Apply changes ignoring warnings.
        ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such
                             a changes. If ignore-warnings flag was omitted- warnings will also
                             be ignored
        ip_address (object): ip address linked to the host.
        new_name(str): New name of the object.
        comments(str): Comments string.
        groups (str or list): Collection of group identifiers.

    """
    groups = argToList(groups)
    result = client.update_host(identifier, ignore_warnings, ignore_errors, ip_address, new_name, comments, groups)

    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "comments",
        "ipv4-address",
        "last-modifier",
        "read-only",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown("CheckPoint data for updating a host:", printable_result, headers=headers, removeNull=True)

    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.Host",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_delete_host_command(client: Client, identifier, ignore_warnings: bool, ignore_errors: bool) -> CommandResults:
    """
    delete host object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid or name.
        ignore_warnings (bool): Whether to ignore warnings when adding a host.
        ignore_errors (bool): Whether to ignore errors when adding a host.
    """
    identifiers_list = argToList(identifier)
    readable_output = ""
    printable_result = {}
    result = []
    for item in identifiers_list:
        current_result = client.delete_host(item, ignore_warnings, ignore_errors)
        result.append(current_result)
        printable_result = {"message": current_result.get("message")}
        current_readable_output = tableToMarkdown("CheckPoint data for deleting host:", printable_result)
        readable_output = readable_output + current_readable_output

    command_results = CommandResults(
        outputs_prefix="CheckPoint.Host",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_groups_command(client: Client, limit: int, offset: int) -> CommandResults:
    """
    Retrieve all group objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
    """
    result = client.list_groups(limit, offset)
    result = result.get("objects")

    printable_result = []
    readable_output = ""

    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in DEFAULT_LIST_FIELD:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)

        readable_output = tableToMarkdown(
            "CheckPoint data for all groups:", printable_result, DEFAULT_LIST_FIELD, removeNull=True
        )

    command_results = CommandResults(
        outputs_prefix="CheckPoint.Group",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_get_group_command(client: Client, identifier: str) -> CommandResults:
    """
    Show existing group object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
    """
    result = client.get_group(identifier)
    printable_result = build_printable_result(DEFAULT_LIST_FIELD, result)
    readable_output = tableToMarkdown(
        f"CheckPoint for {identifier} group:", printable_result, headers=DEFAULT_LIST_FIELD, removeNull=True
    )
    readable_output, printable_result = build_member_data(result, readable_output, printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.Group",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_add_group_command(client: Client, name) -> CommandResults:
    """
    add group objects.

    Args:
        client (Client): CheckPoint client.
        name(str): Object name. Must be unique in the domain.
    """
    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "last-modifier",
        "ipv4-address",
        "ipv6-address",
        "read-only",
        "groups",
    ]
    name = argToList(name)
    result = []
    printable_result = {}
    readable_output = ""

    for item in enumerate(name):
        current_result = client.add_group(item[1])
        printable_result = build_printable_result(headers, current_result)
        current_readable_output = tableToMarkdown(
            "CheckPoint data for adding group:", printable_result, headers=headers, removeNull=True
        )
        readable_output = readable_output + current_readable_output
        result.append(current_result)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.Group",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_update_group_command(
    client: Client,
    identifier: str,
    ignore_warnings: bool,
    ignore_errors: bool,
    action: str = "",
    members=None,
    new_name: str = None,
    comments: str = None,
) -> CommandResults:
    """
    Edit existing group using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
        ignore_warnings(bool):Apply changes ignoring warnings.
        action(str): The action to take towards the modified objects.
        ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such
                             a changes. If ignore-warnings flag was omitted- warnings will also
                             be ignored
        members(object): Collection of Network objects identified by the name or UID.
        new_name(str): New name of the object.
        comments(str): Comments string.
    """
    if members:
        # noinspection PyTypeChecker
        members = argToList(members)
    result = client.update_group(identifier, ignore_warnings, ignore_errors, action, members, new_name, comments)
    headers = ["name", "uid", "type", "domain-name", "domain-type", "domain-uid", "creator", "last-modifier", "read-only"]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown("CheckPoint data for updating a group:", printable_result, headers=headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.Group",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_delete_group_command(client: Client, identifier) -> CommandResults:
    """
    delete group object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
    """
    identifier = argToList(identifier)
    readable_output = ""
    printable_result = {}
    result = {}

    for item in enumerate(identifier):
        current_result = client.delete_group(item[1])
        result.update(current_result)
        printable_result = {"message": current_result.get("message")}
        current_readable_output = tableToMarkdown(f"CheckPoint data for deleting {item[1]}:", printable_result)
        readable_output = readable_output + current_readable_output

    command_results = CommandResults(
        outputs_prefix="CheckPoint.Group",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_address_range_command(client: Client, limit: int, offset: int) -> CommandResults:
    """
    Retrieve all address range objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
    """
    result = client.list_address_ranges(limit, offset)
    result = result.get("objects")

    printable_result = []
    readable_output = ""

    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in DEFAULT_LIST_FIELD:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)

        readable_output = tableToMarkdown(
            "CheckPoint data for all address ranges:", printable_result, DEFAULT_LIST_FIELD, removeNull=True
        )
    command_results = CommandResults(
        outputs_prefix="CheckPoint.AddressRange",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_get_address_range_command(client: Client, identifier: str) -> CommandResults:
    """
    Show existing address range object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
    """
    result = client.get_address_range(identifier)
    printable_result = build_printable_result(DEFAULT_LIST_FIELD, result)
    readable_output = tableToMarkdown(
        f"CheckPoint data for {identifier} address range:", printable_result, headers=DEFAULT_LIST_FIELD, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.AddressRange",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_add_address_range_command(
    client: Client,
    name: str,
    ip_address_first: str,
    ip_address_last: str,
    set_if_exists: bool,
    ignore_warnings: bool,
    ignore_errors: bool,
    groups=None,
) -> CommandResults:
    """
    add address range object.

    Args:
        client (Client): CheckPoint client.
        name(str): Object name. Must be unique in the domain.
        ip_address_first(str): First IP address in the range. IPv4 or IPv6 address.
        ip_address_last(str): Last IP address in the range. IPv4 or IPv6 address.
        set_if_exists(bool): If another object with the same identifier already exists,
                             it will be updated.
        ignore_warnings(bool): Apply changes ignoring warnings.
        ignore_errors(bool): Apply changes ignoring errors
        groups(str or list): Collection of group identifiers.
    """
    if groups:
        groups = argToList(groups)
    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "ipv4-address-first",
        "ipv4-address-last",
        "ipv6-address-first",
        "ipv6-address-last",
        "last-modifier",
        "read-only",
    ]

    result = client.add_address_range(
        name, ip_address_first, ip_address_last, set_if_exists, ignore_warnings, ignore_errors, groups
    )
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for adding an address range:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.AddressRange",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_update_address_range_command(
    client: Client,
    identifier: str,
    ignore_warnings: bool,
    ignore_errors: bool,
    ip_address_first: str = None,
    ip_address_last: str = None,
    new_name: str = None,
    comments: str = None,
    groups=None,
) -> CommandResults:
    """
    Edit existing address range object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
        ignore_warnings(bool):Apply changes ignoring warnings.
        ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such
                            a changes.
                             If ignore-warnings flag was omitted- warnings will also be ignored
        ip_address_first(str): First IP address in the range. IPv4 or IPv6 address.
        ip_address_last(str): Last IP address in the range. IPv4 or IPv6 address.
        new_name(str): New name of the object.
        comments(str): Comments string.
        groups(str or list): Collection of group identifiers.
    """
    if groups:
        groups = argToList(groups)
    result = client.update_address_range(
        identifier, ignore_warnings, ignore_errors, ip_address_first, ip_address_last, new_name, comments, groups
    )
    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "comments",
        "ipv4-address",
        "last-modifier",
        "read-only",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for updating an address range:", printable_result, headers=headers, removeNull=True
    )

    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.AddressRange",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_delete_address_range_command(client: Client, identifier) -> CommandResults:
    """
    delete address range object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
    """
    identifier = argToList(identifier)
    readable_output = ""
    printable_result = {}
    result = {}
    for item in enumerate(identifier):
        current_result = client.delete_address_range(item[1])
        result.update(current_result)
        printable_result = {"message": current_result.get("message")}
        current_readable_output = tableToMarkdown("CheckPoint data for deleting address range:", printable_result)
        readable_output = readable_output + current_readable_output

    command_results = CommandResults(
        outputs_prefix="CheckPoint.AddressRange",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_threat_indicator_command(client: Client, limit: int, offset: int) -> CommandResults:
    """
    Retrieve all threat indicator objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
    """
    result = client.list_threat_indicators(limit, offset)
    result["objects"] = result.pop("indicators")
    printable_result = []
    readable_output = ""

    result = result.get("objects")
    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in DEFAULT_LIST_FIELD:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)

        readable_output = tableToMarkdown(
            "CheckPoint data for all threat indicators:", printable_result, DEFAULT_LIST_FIELD, removeNull=True
        )
    command_results = CommandResults(
        outputs_prefix="CheckPoint.ThreatIndicator",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_get_threat_indicator_command(client: Client, identifier: str) -> CommandResults:
    """
    Show existing threat indicator object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
    """
    result = client.get_threat_indicator(identifier)
    headers = DEFAULT_LIST_FIELD + ["number-of-observables"]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        f"CheckPoint data for {identifier} threat indicator:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.ThreatIndicator",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_add_threat_indicator_command(client: Client, name: str, observables: list) -> CommandResults:
    """
    Create new threat indicator.

    Args:
        client (Client): CheckPoint client.
        name(str): Object name. Must be unique in the domain.
        observables(list): The indicator's observables.
    """
    observables = argToList(observables)
    result = client.add_threat_indicator(name, observables)
    printable_result = {"task-id": result.get("task-id")}
    readable_output = tableToMarkdown("CheckPoint data for adding an threat indicator:", printable_result)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.ThreatIndicator",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_update_threat_indicator_command(
    client: Client, identifier: str, action: str = None, new_name: str = None, comments: str = None
) -> CommandResults:
    """
    Edit existing threat indicator object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
        action (str): the action to set. available options:
                            "Accept", "Drop", "Ask", "Inform", "Reject", "User Auth",
                            "Client Auth", "Apply Layer".
        new_name(str): New name of the object.
        comments(str): Comments string.
    """

    result = client.update_threat_indicator(identifier, action, new_name, comments)
    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "comments",
        "ipv4-address",
        "last-modifier",
        "read-only",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        f"CheckPoint data for update {identifier} threat indicator", printable_result, headers=headers, removeNull=True
    )

    command_results = CommandResults(
        outputs_prefix="CheckPoint.ThreatIndicator",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_delete_threat_indicator_command(client: Client, identifier) -> CommandResults:
    """
    delete threat indicator object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
    """
    identifier = argToList(identifier)
    readable_output = ""
    printable_result = {}
    result = {}
    for item in enumerate(identifier):
        current_result = client.delete_threat_indicator(item[1])
        result.update(current_result)
        printable_result = {"message": current_result.get("message")}
        current_readable_output = tableToMarkdown(f"CheckPoint status for deleting {item[1]}threat indicator:", printable_result)
        readable_output = readable_output + current_readable_output

    command_results = CommandResults(
        outputs_prefix="CheckPoint.ThreatIndicator",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_access_rule_command(client: Client, identifier: str, limit: int, offset: int) -> CommandResults:
    """
    Show existing access rule base objects using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
        limit (int): The maximal number of returned results.
        offset (int): Number of the results to initially skip.
    """
    printable_result = []
    readable_output = ""

    result = client.list_access_rule(identifier, limit, offset)
    result = result.get("rulebase")

    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in DEFAULT_LIST_FIELD:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)

        readable_output = tableToMarkdown(
            "CheckPoint data for all access rule bases:", printable_result, DEFAULT_LIST_FIELD, removeNull=True
        )
    command_results = CommandResults(
        outputs_prefix="CheckPoint.AccessRule",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_add_access_rule_command(
    client: Client,
    layer: str,
    position,
    action: str,
    name: str = None,
    vpn: str = None,
    destination=None,
    service=None,
    source=None,
) -> CommandResults:
    """
    Add new access rule object.

    Args:
        client (Client): CheckPoint client.
        layer(str): Layer that the rule belongs to identified by the name or UID.
        position(int or str): IPosition in the rulebase.
                              int - add rule at a specific position
                              str - add rule at the position. vaild value: top, bottom
        name(str): rule name
        action(str): Action settings. valid values are: Accept, Drop, Apply Layer, Ask and Info
                     default value is Drop.

        vpn(str): Communities or Directional. Valid values: Any, All_GwToGw.
        destination(str or list): Collection of Network objects identified by the name or UID.
        service(str or list): Collection of Network objects identified by the name or UID.
        source(str or list): Collection of Network objects identified by the name or UID.
    """
    headers = ["name", "uid", "type", "domain-name", "domain-type", "domain-uid", "enabled", "layer", "creator", "last-modifier"]

    result = client.add_rule(layer, position, action, name, vpn, destination, service, source)
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for adding access rule:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.AccessRule",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_update_access_rule_command(
    client: Client,
    identifier: str,
    layer: str,
    ignore_warnings: bool,
    ignore_errors: bool,
    enabled: bool,
    action: str = None,
    new_name: str = None,
    new_position=None,
) -> CommandResults:
    """
    Edit existing access rule object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid, name or rule-number.
        layer (str): Layer that the rule belongs to identified by the name or UID.
        ignore_warnings(bool):Apply changes ignoring warnings.
        ignore_errors(bool): Apply changes ignoring errors. You won't be able to publish such
        a changes. If ignore-warnings flag was omitted- warnings will also be ignored
        enabled(bool): Enable/Disable the rule
        action (str): the action to set. available options:
                                    "Accept", "Drop", "Ask", "Inform", "Reject", "User Auth",
                                    "Client Auth", "Apply Layer".
        new_name(str): New name of the object.
        new_position(int or str): New position in the rulebase. value can be int or str:
                                int- add rule at the specific position
                                str- add rule at the position. valid values: top, bottom.
    """

    result = client.update_rule(identifier, layer, ignore_warnings, ignore_errors, enabled, action, new_name, new_position)
    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "action-name",
        "action-uid",
        "action-type",
        "content-direction",
        "creator",
        "enabled",
        "last-modifier",
    ]
    printable_result = build_printable_result(headers, result)

    action_data = result.get("action")
    if action_data:
        printable_result["action-name"] = action_data.get("name")
        printable_result["action-uid"] = action_data.get("uid")
        printable_result["action-type"] = action_data.get("type")

    readable_output = tableToMarkdown(
        "CheckPoint data for updating an access rule:", printable_result, headers=headers, removeNull=True
    )

    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.AccessRule",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_delete_access_rule_command(client: Client, identifier, layer: str) -> CommandResults:
    """
    Delete existing rule object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid, name or rule-number.
        layer(str): Layer that the rule belongs to identified by the name or UID.
    """
    identifier = argToList(identifier)
    readable_output = ""
    printable_result = {}
    result = {}
    for item in enumerate(identifier):
        current_result = client.delete_rule(item[1], layer)
        result.update(current_result)
        printable_result = {"message": current_result.get("message")}
        current_readable_output = tableToMarkdown(f"CheckPoint data for deleting access rule range: {item[1]}", printable_result)
        readable_output = readable_output + current_readable_output

    command_results = CommandResults(
        outputs_prefix="CheckPoint.AccessRule",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_application_site_command(client: Client, limit: int, offset: int) -> CommandResults:
    """
    Show existing application site objects using object name or uid.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results.
        offset (int): Number of the results to initially skip.
    """
    printable_result = []
    readable_output = ""

    result = client.list_application_site(limit, offset)
    result = result.get("objects")
    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in DEFAULT_LIST_FIELD:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)
        readable_output = tableToMarkdown(
            "CheckPoint data for all access rule bases:", printable_result, DEFAULT_LIST_FIELD, removeNull=True
        )
    command_results = CommandResults(
        outputs_prefix="CheckPoint.ApplicationSite",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_add_application_site_command(client: Client, name: str, primary_category: str, identifier, groups=None):
    """
    Add application site objects.

    Args:
        client (Client): CheckPoint client.
        name(str): Object name. Must be unique in the domain.
        primary_category(str): Each application is assigned to one primary category
                                based on its most defining aspect.
        identifier(str or list): can be-
                               url-list(str or list): URLs that determine this particular
                               application
                               application-signature(str): Application signature generated by
                                                            Signature Tool.
        groups(str or list): Collection of group identifiers.
    """
    identifier = argToList(identifier)
    groups = argToList(groups)
    headers = [
        "name",
        "uid",
        "type",
        "url-list",
        "application-id",
        "domain-name",
        "domain-type",
        "domain-uid",
        "description",
        "creator",
        "last-modifier",
        "groups",
    ]

    result = client.add_application_site(name, primary_category, identifier, groups)
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for adding application site:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.ApplicationSite",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_update_application_site_command(
    client: Client,
    identifier: str,
    urls_defined_as_regular_expression: bool,
    groups=None,
    url_list=None,
    url_list_to_add=None,
    url_list_to_remove=None,
    description: str = None,
    new_name: str = None,
    primary_category: str = None,
    application_signature: str = None,
):
    """
    Edit existing application site object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier: uid or name.
        url_list(str or list): URLs that determine this particular application.
                                can be a string of a URL or a list of URLs.
        url_list_to_add (str or list): Adds to collection of values.
        url_list_to_remove (str or list): Removes from collection of values.
        urls_defined_as_regular_expression(bool): States whether the URL is defined as a
                                                  Regular Expression or not.
        groups(str or list): Collection of group identifiers.
        description(str): A description for the application.
        new_name(str): New name of the object.
        primary_category (str): Each application is assigned to one primary category based on
                                its most defining aspect
        application_signature(str): Application signature generated by Signature Tool
    """

    url_list_object = None
    if url_list:
        url_list_object = argToList(url_list)

    elif url_list_to_add:
        url_list_to_add = argToList(url_list_to_add)
        url_list_object = {"add": url_list_to_add}

    elif url_list_to_remove:
        url_list_to_remove = argToList(url_list_to_remove)
        url_list_object = {"remove": url_list_to_remove}

    if groups:
        groups = argToList(groups)
    result = client.update_application_site(
        identifier,
        urls_defined_as_regular_expression,
        groups,
        url_list_object,
        description,
        new_name,
        primary_category,
        application_signature,
    )
    headers = [
        "name",
        "uid",
        "type",
        "application-id",
        "primary-category",
        "url-list",
        "domain-name",
        "domain-type",
        "domain-uid",
        "description",
        "groups",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for updating an application site:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.ApplicationSite",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_delete_application_site_command(client: Client, identifier) -> CommandResults:
    """
    Delete existing application site object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid, name or rule-number.
    """
    identifier = argToList(identifier)
    readable_output = ""
    printable_result = {}
    result = {}
    for item in enumerate(identifier):
        current_result = client.delete_application_site(item[1])
        result.update(current_result)
        printable_result = {"message": current_result.get("message")}
        current_readable_output = tableToMarkdown(f"CheckPoint data for deleting application site : {item[1]}", printable_result)
        readable_output = readable_output + current_readable_output

    command_results = CommandResults(
        outputs_prefix="CheckPoint.ApplicationSite",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_application_site_categories_command(client: Client, limit: int, offset: int) -> CommandResults:
    """
    Retrieve all application site categories objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
    """
    result = client.list_application_site_categories(limit, offset)
    result = result.get("objects")

    printable_result = []
    readable_output = ""

    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in DEFAULT_LIST_FIELD:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)

        readable_output = tableToMarkdown(
            "CheckPoint data for all application site category:", printable_result, DEFAULT_LIST_FIELD, removeNull=True
        )
    command_results = CommandResults(
        outputs_prefix="CheckPoint.ApplicationSiteCategory",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_get_application_site_category_command(client: Client, identifier: str) -> CommandResults:
    """
    Show existing application site category object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
    """
    result = client.get_application_site_category(identifier)
    printable_result = build_printable_result(DEFAULT_LIST_FIELD, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for adding application site category:", printable_result, headers=DEFAULT_LIST_FIELD, removeNull=True
    )

    command_results = CommandResults(
        outputs_prefix="CheckPoint.ApplicationSiteCategory",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_add_application_site_category_command(client: Client, identifier: str, groups=None) -> CommandResults:
    """
    Add application site objects.

    Args:
        client (Client): CheckPoint client.
        identifier (str or list): Object name or unique identifier.
        groups (str or list): Collection of group identifiers.
    """
    identifier = argToList(identifier)
    groups = argToList(groups)

    headers = [
        "name",
        "uid",
        "type",
        "url-list",
        "application-id",
        "domain-name",
        "domain-type",
        "domain-uid",
        "description",
        "creator",
        "last-modifier",
        "groups",
    ]
    readable_output = ""
    printable_result = {}
    result = {}
    for item in enumerate(identifier):
        current_result = client.add_application_site_category(item[1], groups)
        result.update(current_result)

        printable_result = build_printable_result(headers, current_result)
        current_readable_output = tableToMarkdown(
            f"CheckPoint data for adding application site category {item[1]}:",
            printable_result,
            headers=headers,
            removeNull=True,
        )
        readable_output = readable_output + current_readable_output
        readable_output, printable_result = build_group_data(current_result, readable_output, printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.ApplicationSite",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_objects_command(
    client: Client, limit: int, offset: int, filter_search: str, ip_only: bool, object_type: str
) -> CommandResults:
    """
    Retrieve data about objects.

        Args:
            client (Client): CheckPoint client.
            limit (int): The maximal number of returned results.
            offset (int): Number of the results to initially skip.
            filter_search(str): Search expression to filter objects by. To use IP search only,
                                set the "ip-only" parameter to true.
            ip_only(bool): If using "filter", use this field to search objects by their IP address
                           only, without involving the textual search. Default value is False.
            object_type(str): The objects' type, e.g.: host, service-tcp, network, address-range.
                       Default value is object.
    """

    printable_result = []
    readable_output = ""

    result = client.list_objects(limit, offset, filter_search, ip_only, object_type)
    result = result.get("objects")
    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in DEFAULT_LIST_FIELD:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)
        readable_output = tableToMarkdown("CheckPoint data for objects:", printable_result, DEFAULT_LIST_FIELD, removeNull=True)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.Objects",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_packages_command(client: Client, limit: int, offset: int) -> CommandResults:
    """
    Retrieve all policy packages.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results.
        offset (int): Number of the results to initially skip.
    """
    printable_result = []
    readable_output = ""
    headers = ["name", "uid", "type"]
    result = client.list_packages(limit, offset)
    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in headers:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)
        readable_output = tableToMarkdown("CheckPoint data for all packages:", printable_result, headers, removeNull=True)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.Packages",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_package_command(client: Client, identifier: str) -> CommandResults:
    """
    Show existing package object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
    """
    printable_result = []
    readable_output = ""
    headers = ["target-name", "target-uid", "revision"]
    result = client.list_package(identifier)
    if result:
        gwinfo = result.get("installation-targets-revision")
        if gwinfo:
            for element in gwinfo:
                current_printable_result = {}
                current_printable_result["name"] = result.get("name")
                for endpoint in headers:
                    current_printable_result[endpoint] = element.get(endpoint)
                printable_result.append(current_printable_result)
            readable_output = tableToMarkdown("CheckPoint data for package:", printable_result, headers, removeNull=True)
        else:
            readable_output = "No package objects were found."

    command_results = CommandResults(
        outputs_prefix="CheckPoint.Package",
        outputs_key_field="target-uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_list_gateways_command(client: Client, limit: int, offset: int) -> CommandResults:
    """
    Retrieve all policy gateways.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results.
        offset (int): Number of the results to initially skip.
    """
    printable_result = []
    readable_output = ""
    headers = ["name", "uid", "type", "version", "network-security-blades", "management-blades"]
    result = client.list_gateways(limit, offset)
    if result:
        for element in result:
            current_printable_result = {}
            for endpoint in headers:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)
        readable_output = tableToMarkdown("CheckPoint data for all gateways:", printable_result, headers, removeNull=True)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.Gateways",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_publish_command(client: Client) -> CommandResults:
    """
    publish changes. All the changes done by this user will be seen by all users only after publish
    is called.
    Args:
        client (Client): CheckPoint client.
    """
    printable_result = {}
    readable_output = ""

    result = client.publish()
    if result:
        printable_result = {"task-id": result.get("task-id")}
        readable_output = tableToMarkdown("CheckPoint data for publishing current session:", printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.Publish",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_show_task_command(client: Client, task_id: str) -> CommandResults:
    """
    Show task status with the given task id

    Args:
        client (Client): CheckPoint client.
        task_id (str): task id.
    """
    printable_result = []
    result = client.show_task(task_id)
    task_list = result.get("tasks")
    if task_list:
        for task in task_list:
            current_object_data = {
                "task-id": task.get("task-id"),
                "task-name": task.get("task-name"),
                "status": task.get("status"),
                "suppressed": task.get("suppressed"),
                "progress-percentage": task.get("progress-percentage"),
            }
            printable_result.append(current_object_data)

    readable_output = tableToMarkdown(
        "CheckPoint data for tasks:",
        printable_result,
        ["task-name", "task-id", "status", "suppressed", "progress-percentage"],
        removeNull=True,
    )
    command_results = CommandResults(
        outputs_prefix="CheckPoint.ShowTask",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_add_objects_batch_command(client: Client, object_type: str, ipaddress, name):
    context_data = {}
    readable_output = ""

    ip_addresses = argToList(ipaddress, ",")
    ip_object_names = argToList(name, ",")
    add_list = []
    for ip, name in zip(ip_addresses, ip_object_names):
        tmp_dict = {"name": name, "ip-address": ip}
        add_list.append(tmp_dict)

    result = client.add_objects_batch(object_type, add_list)

    if result:
        context_data = {"task-id": result.get("task-id")}
        readable_output = tableToMarkdown("CheckPoint data for add-objects-batch command:", context_data)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.AddObjectBatch",
        outputs_key_field="task-id",
        readable_output=readable_output,
        outputs=context_data,
        raw_response=result,
    )
    return command_results


def checkpoint_delete_objects_batch_command(client: Client, object_type: str, name):
    context_data = {}
    readable_output = ""

    object_names = argToList(name)
    objects_to_delete = [{"name": object_name} for object_name in object_names]

    result = client.delete_objects_batch(object_type, objects_to_delete)

    if result:
        context_data = {"task-id": result.get("task-id")}
        readable_output = tableToMarkdown("CheckPoint data for delete-objects-batch command:", context_data)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.DeleteObjectsBatch",
        outputs_key_field="task-id",
        readable_output=readable_output,
        outputs=context_data,
        raw_response=result,
    )
    return command_results


def checkpoint_show_threat_protection_command(client: Client, args):
    context_data = {}
    readable_output = ""
    uid = args.get("uid", "")
    name = args.get("name")
    properties = args.get("properties") != "false"
    profiles = args.get("profiles") != "false"
    result = client.show_threat_protection(uid, name, properties, profiles)

    if result:
        context_data = {"uid": result}
        readable_output = tableToMarkdown("CheckPoint data for show threat protection command:", result)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.ShowThreatProtection",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=context_data,
        raw_response=result,
    )
    return command_results


def checkpoint_show_threat_protections_command(client: Client, args):
    context_data = {}
    readable_output = ""
    result = client.show_threat_protections(args)

    if result:
        context_data = result.get("protections", [])
        readable_output = tableToMarkdown("CheckPoint data for show threat protections command:", result.get("protections", []))
    command_results = CommandResults(
        outputs_prefix="CheckPoint.ShowThreatProtections",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=context_data,
        raw_response=result,
    )
    return command_results


def ip_settings(args):
    keys = args.keys()
    args["ips-settings"] = {}
    if "exclude-protection-with-performance-impact" in keys:
        args["ips-settings"]["exclude-protection-with-performance-impact"] = args["exclude-protection-with-performance-impact"]
        args.pop("exclude-protection-with-performance-impact")

    if "exclude-protection-with-performance-impact-mode" in keys:
        args["ips-settings"]["exclude-protection-with-performance-impact-mode"] = args[
            "exclude-protection-with-performance-impact-mode"
        ]
        args.pop("exclude-protection-with-performance-impact-mode")

    if "exclude-protection-with-severity" in keys:
        args["ips-settings"]["exclude-protection-with-severity"] = args["exclude-protection-with-severity"]
        args.pop("exclude-protection-with-severity")

    if "exclude-protection-with-severity-mode" in keys:
        args["ips-settings"]["exclude-protection-with-severity-mode"] = args["exclude-protection-with-severity-mode"]
        args.pop("exclude-protection-with-severity-mode")

    if "newly-updated-protections" in keys:
        args["ips-settings"]["newly-updated-protections"] = args["newly-updated-protections"]
        args.pop("newly-updated-protections")

    return args


def checkpoint_add_threat_profile_command(client: Client, args):
    body = {f'{k.replace("_", "-")}': v for k, v in args.items()}

    body = ip_settings(body)
    readable_output = ""

    result = client.add_threat_profile(body)

    if result:
        readable_output = tableToMarkdown("CheckPoint data for add threat profile command:", result)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.AddedThreatProfiles",
        outputs_key_field="task-id",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )
    return command_results


def checkpoint_delete_threat_protections_command(client: Client, args):
    body = {}
    body["package-format"] = args.get("packageFormat")
    result = client.delete_threat_protections(body)

    if result:
        readable_output = tableToMarkdown("CheckPoint data for delete threat protections command:", result)
    else:
        readable_output = "No result was found."
    command_results = CommandResults(
        outputs_prefix="CheckPoint.DeletedThreatProtections",
        outputs_key_field="task-id",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )
    return command_results


def create_override_data(args):
    profiles = args.get("profiles").split(",")
    profiles = [x.rstrip() for x in profiles]

    if args.get("track"):
        args["track"] = args["track"].replace("-", " ")
    obj = []

    for profile in profiles:
        obj.append(
            {
                "profile": profile,
                "action": args.get("action"),
                "track": args.get("track"),
                "capture-packets": args.get("caputurePackets"),
            }
        )
    args["overrides"] = obj
    args.pop("profiles", None)
    args.pop("action", None)
    args.pop("track", None)
    args.pop("capturePackets", None)
    return args


def checkpoint_set_threat_protections_command(client: Client, args):
    readable_output = ""

    if args.get("profiles"):
        args = create_override_data(args)

    body = {f'{k.replace("_", "-")}': v for k, v in args.items()}
    result = client.set_threat_protection(body)

    if result:
        readable_output = tableToMarkdown("CheckPoint data for set threat protection command:", result)
    command_results = CommandResults(
        outputs_prefix="CheckPoint.SetThreatProtections",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )
    return command_results


def checkpoint_install_policy_command(client: Client, policy_package: str, targets, access: bool) -> CommandResults:
    """
    installing policy.

    Args:
        client (Client): CheckPoint client.
        policy_package(str): The name of the Policy Package to be installed.
        targets(str or list):On what targets to execute this command. Targets may be identified
                            by their name, or object unique identifier.
        access(bool): Set to be true in order to install the Access Control policy.
                        By default, the value is true if Access Control policy is enabled
                        on the input policy package, otherwise false.
    """
    printable_result = {}
    readable_output = ""

    result = client.install_policy(policy_package, targets, access)
    if result:
        printable_result = {"task-id": result.get("task-id")}
        readable_output = tableToMarkdown("CheckPoint data for installing policy:", printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.InstallPolicy",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def checkpoint_verify_policy_command(client: Client, policy_package: str) -> CommandResults:
    """
    Verifies the policy of the selected package.

    Args:
        client (Client): CheckPoint client.
        policy_package(str): The name of the Policy Package to be installed.
    """
    printable_result = {}
    readable_output = ""

    result = client.verify_policy(policy_package)
    if result:
        printable_result = {"task-id": result.get("task-id")}
        readable_output = tableToMarkdown("CheckPoint data for verifying policy", printable_result)

    command_results = CommandResults(
        outputs_prefix="CheckPoint.VerifyPolicy",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=printable_result,
        raw_response=result,
    )
    return command_results


def build_nat_settings(
    nat_settings_auto_rule: Optional[bool],
    nat_method: Optional[str],
    nat_hide_behind: Optional[str],
    nat_install_on: Optional[str],
    nat_settings_ip: Optional[str],
) -> Optional[dict]:
    """Helper function. Builds the nat-settings dict from individual arguments."""
    if all(v is None for v in [nat_settings_auto_rule, nat_method, nat_hide_behind, nat_install_on, nat_settings_ip]):
        return None

    # nat_hide_behind is forbidden when nat_method is 'static'
    if nat_hide_behind and nat_method == "static":
        raise ValueError(
            "The 'nat_hide_behind' argument is forbidden when 'nat_method' is 'static'. "
            "Please remove 'nat_hide_behind' or change 'nat_method'."
        )
    # When nat_method is 'hide' and nat_hide_behind is 'gateway', nat_ip must not be provided
    if nat_method == "hide" and nat_hide_behind == "gateway" and nat_settings_ip:
        raise ValueError(
            "The 'nat_settings_ip' argument must not be provided when 'nat_method' is 'hide' and "
            "'nat_hide_behind' is 'gateway'. Please remove 'nat_settings_ip' or change 'nat_hide_behind'."
            " This prevents ambiguity and matches SmartConsole behavior."
        )

    nat_settings: dict = {}
    if nat_settings_auto_rule is not None:
        nat_settings["auto-rule"] = nat_settings_auto_rule
    if nat_method:
        nat_settings["method"] = nat_method
    if nat_hide_behind:
        nat_settings["hide-behind"] = nat_hide_behind
    if nat_install_on:
        nat_settings["install-on"] = nat_install_on
    if nat_settings_ip:
        nat_settings["ipv4-address"] = nat_settings_ip
    return nat_settings


def checkpoint_network_get_command(client: Client, identifier: str, details_level: str = None) -> CommandResults:
    """
    Show existing network object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid or name.
        details_level (str): The level of detail for some of the fields in the response.
    """
    demisto.debug(f"checkpoint-network-get command called with args: {demisto.args()}")
    result = client.show_network(identifier, details_level)
    printable_result = build_printable_result(DEFAULT_LIST_FIELD, result)
    readable_output = tableToMarkdown(
        f"CheckPoint data for network object {identifier}:", printable_result, headers=DEFAULT_LIST_FIELD, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-network-get command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.Network",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_network_list_command(
    client: Client, limit: int = 50, offset: int = 0, details_level: str = None
) -> CommandResults:
    """
    Retrieve all network objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
        details_level (str): The level of detail for some of the fields in the response.
    """
    demisto.debug(f"checkpoint-network-list command called with args: {demisto.args()}")
    limit = arg_to_number(limit) or 50
    offset = arg_to_number(offset) or 0

    result = client.list_networks(limit, offset, details_level)

    printable_result: list = []
    readable_output = ""

    if result:
        if result.get("total") == 0:
            readable_output = "No network objects were found."
        else:
            objects = result.get("objects", [])
            for element in objects:
                current_printable_result = {}
                for endpoint in DEFAULT_LIST_FIELD:
                    current_printable_result[endpoint] = element.get(endpoint)
                printable_result.append(current_printable_result)

            readable_output = tableToMarkdown(
                "CheckPoint data for all networks:", printable_result, DEFAULT_LIST_FIELD, removeNull=True
            )

    demisto.debug("checkpoint-network-list command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.Network",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result.get("objects", []) if result else [],
        raw_response=result,
    )


def checkpoint_network_add_command(
    client: Client,
    identifier: str,
    subnet: str,
    mask_length: str = None,
    subnet_mask: str = None,
    comments: str = None,
    color: str = None,
    tags=None,
    broadcast: str = None,
    nat_install_on: str = None,
    nat_hide_behind: str = None,
    nat_settings_auto_rule: str = None,
    nat_settings_ip: str = None,
    nat_method: str = None,
) -> CommandResults:
    """
    Create a new network object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): Object name. Must be unique in the domain.
        subnet (str): IPv4 network address.
        mask_length (str): IPv4 network mask length.
        subnet_mask (str): IPv4 network mask.
        comments (str): Comments string.
        color (str): Color of the object.
        tags: Collection of tag identifiers.
        broadcast (str): Allow broadcast address inclusion.
        nat_install_on (str): Gateway for NAT rule.
        nat_hide_behind (str): Hide behind method.
        nat_settings_auto_rule (str): Whether to add automatic address translation rules.
        nat_settings_ip (str): IPv4 address for NAT.
        nat_method (str): NAT translation method.
    """
    demisto.debug(f"checkpoint-network-add command called with args: {demisto.args()}")
    tags = argToList(tags)

    nat_settings = build_nat_settings(
        nat_settings_auto_rule=argToBoolean(nat_settings_auto_rule) if nat_settings_auto_rule else None,
        nat_method=nat_method,
        nat_hide_behind=nat_hide_behind,
        nat_install_on=nat_install_on,
        nat_settings_ip=nat_settings_ip,
    )

    result = client.add_network(
        identifier=identifier,
        subnet=subnet,
        mask_length=arg_to_number(mask_length),
        subnet_mask=subnet_mask,
        comments=comments,
        color=color,
        tags=tags or None,
        broadcast=broadcast,
        nat_settings=nat_settings,
    )

    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "last-modifier",
        "read-only",
        "groups",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown("CheckPoint data for adding a network:", printable_result, headers=headers, removeNull=True)
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-network-add command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.Network",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_network_update_command(
    client: Client,
    identifier: str,
    new_identifier: str = None,
    subnet: str = None,
    subnet_mask: str = None,
    comments: str = None,
    color: str = None,
    tags=None,
    broadcast: str = None,
    nat_install_on: str = None,
    nat_hide_behind: str = None,
    nat_settings_auto_rule: str = None,
    nat_settings_ip: str = None,
    nat_method: str = None,
) -> CommandResults:
    """
    Update an existing network object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid or name.
        new_identifier (str): New name of the object.
        subnet (str): IPv4 network address.
        subnet_mask (str): IPv4 network mask.
        comments (str): Comments string.
        color (str): Color of the object.
        tags: Collection of tag identifiers.
        broadcast (str): Allow broadcast address inclusion.
        nat_install_on (str): Gateway for NAT rule.
        nat_hide_behind (str): Hide behind method.
        nat_settings_auto_rule (str): Whether to add automatic address translation rules.
        nat_settings_ip (str): IPv4 address for NAT.
        nat_method (str): NAT translation method.
    """
    demisto.debug(f"checkpoint-network-update command called with args: {demisto.args()}")
    tags = argToList(tags)

    nat_settings = build_nat_settings(
        nat_settings_auto_rule=argToBoolean(nat_settings_auto_rule) if nat_settings_auto_rule else None,
        nat_method=nat_method,
        nat_hide_behind=nat_hide_behind,
        nat_install_on=nat_install_on,
        nat_settings_ip=nat_settings_ip,
    )

    result = client.update_network(
        identifier=identifier,
        new_identifier=new_identifier,
        subnet=subnet,
        subnet_mask=subnet_mask,
        comments=comments,
        color=color,
        tags=tags or None,
        broadcast=broadcast,
        nat_settings=nat_settings,
    )

    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "comments",
        "last-modifier",
        "read-only",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for updating a network:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-network-update command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.Network",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_network_delete_command(
    client: Client, identifier: str, ignore_warnings: Union[bool, str] = True
) -> CommandResults:
    """
    Delete a network object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid or name.
        ignore_warnings (bool): Whether to ignore warnings when deleting the network object.
    """
    demisto.debug(f"checkpoint-network-delete command called with args: {demisto.args()}")
    ignore_warnings = argToBoolean(ignore_warnings)

    client.delete_network(identifier, ignore_warnings)

    demisto.debug("checkpoint-network-delete command completed successfully")
    return CommandResults(
        readable_output="Object deleted successfully.",
    )


SERVICE_TYPE_CONTEXT_MAP = {
    "tcp": "CheckPoint.TCPService",
    "udp": "CheckPoint.UDPService",
    "icmp": "CheckPoint.ICMPService",
}


def checkpoint_service_get_command(client: Client, identifier: str, service_type: str) -> CommandResults:
    """
    Show existing service object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid or name.
        service_type (str): The service type (tcp, udp, or icmp).
    """
    demisto.debug(f"checkpoint-service-get command called with args: {demisto.args()}")
    result = client.show_service(identifier, service_type)
    printable_result = build_printable_result(DEFAULT_LIST_FIELD, result)
    readable_output = tableToMarkdown(
        f"CheckPoint data for {service_type} service object {identifier}:",
        printable_result,
        headers=DEFAULT_LIST_FIELD,
        removeNull=True,
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-service-get command completed successfully")
    return CommandResults(
        outputs_prefix=SERVICE_TYPE_CONTEXT_MAP[service_type],
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_service_list_command(
    client: Client, service_type: str, identifier: str = None, limit: int = 50, offset: int = 0
) -> CommandResults:
    """
    Retrieve service objects. When identifier is provided, calls the single-object endpoint.

    Args:
        client (Client): CheckPoint client.
        service_type (str): The service type (tcp, udp, or icmp).
        identifier (str): uid or name. When provided, calls show-service-* instead of show-services-*.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
    """
    demisto.debug(f"checkpoint-service-list command called with args: {demisto.args()}")
    if identifier:
        result = client.show_service(identifier, service_type)
        printable_result = build_printable_result(DEFAULT_LIST_FIELD, result)
        readable_output = tableToMarkdown(
            f"CheckPoint data for {service_type} service object {identifier}:",
            printable_result,
            headers=DEFAULT_LIST_FIELD,
            removeNull=True,
        )
        demisto.debug("checkpoint-service-list command completed successfully")
        return CommandResults(
            outputs_prefix=SERVICE_TYPE_CONTEXT_MAP[service_type],
            outputs_key_field="uid",
            readable_output=readable_output,
            outputs=result,
            raw_response=result,
        )

    limit = arg_to_number(limit) or 50
    offset = arg_to_number(offset) or 0

    result = client.list_services(limit, offset, service_type)

    printable_results: list = []
    readable_output = ""

    if result:
        if result.get("total") == 0:
            readable_output = f"No {service_type} service objects were found."
        else:
            objects = result.get("objects", [])
            for element in objects:
                current_printable_result = {}
                for endpoint in DEFAULT_LIST_FIELD:
                    current_printable_result[endpoint] = element.get(endpoint)
                printable_results.append(current_printable_result)

            readable_output = tableToMarkdown(
                f"CheckPoint data for all {service_type} services:", printable_results, DEFAULT_LIST_FIELD, removeNull=True
            )

    demisto.debug("checkpoint-service-list command completed successfully")
    return CommandResults(
        outputs_prefix=SERVICE_TYPE_CONTEXT_MAP[service_type],
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result.get("objects", []) if result else [],
        raw_response=result,
    )


def checkpoint_tcp_service_add_command(
    client: Client,
    identifier: str,
    port: str = None,
    comments: str = None,
    color: str = None,
    session_timeout: str = None,
    tags=None,
) -> CommandResults:
    """
    Create a new TCP service object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): Object name. Must be unique in the domain.
        port (str): The number of the port used to provide this service.
        comments (str): Comments string.
        color (str): Color of the object.
        session_timeout (str): Time (in seconds) before the session times out.
        tags: Collection of tag identifiers.
    """
    demisto.debug(f"checkpoint-tcp-service-add command called with args: {demisto.args()}")
    tags = argToList(tags)

    result = client.add_service_tcp(
        identifier=identifier,
        port=port,
        comments=comments,
        color=color,
        session_timeout=arg_to_number(session_timeout),
        tags=tags or None,
    )

    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "last-modifier",
        "read-only",
        "groups",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for adding a TCP service:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-tcp-service-add command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.TCPService",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_udp_service_add_command(
    client: Client,
    identifier: str,
    port: str = None,
    comments: str = None,
    color: str = None,
    session_timeout: str = None,
    tags=None,
) -> CommandResults:
    """
    Create a new UDP service object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): Object name. Must be unique in the domain.
        port (str): The number of the port used to provide this service.
        comments (str): Comments string.
        color (str): Color of the object.
        session_timeout (str): Time (in seconds) before the session times out.
        tags: Collection of tag identifiers.
    """
    demisto.debug(f"checkpoint-udp-service-add command called with args: {demisto.args()}")
    tags = argToList(tags)

    result = client.add_service_udp(
        identifier=identifier,
        port=port,
        comments=comments,
        color=color,
        session_timeout=arg_to_number(session_timeout),
        tags=tags or None,
    )

    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "last-modifier",
        "read-only",
        "groups",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for adding a UDP service:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-udp-service-add command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.UDPService",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_icmp_service_add_command(
    client: Client,
    identifier: str,
    icmp_type: str = None,
    icmp_code: str = None,
    comments: str = None,
    color: str = None,
    tags=None,
) -> CommandResults:
    """
    Create a new ICMP service object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): Object name. Must be unique in the domain.
        icmp_type (str): ICMP type as listed in RFC 792.
        icmp_code (str): ICMP code as listed in RFC 792.
        comments (str): Comments string.
        color (str): Color of the object.
        tags: Collection of tag identifiers.
    """
    demisto.debug(f"checkpoint-icmp-service-add command called with args: {demisto.args()}")
    tags = argToList(tags)

    result = client.add_service_icmp(
        identifier=identifier,
        icmp_type=arg_to_number(icmp_type),
        icmp_code=arg_to_number(icmp_code),
        comments=comments,
        color=color,
        tags=tags or None,
    )

    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "last-modifier",
        "read-only",
        "groups",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for adding an ICMP service:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-icmp-service-add command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.ICMPService",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_tcp_service_update_command(
    client: Client,
    identifier: str,
    new_identifier: str = None,
    port: str = None,
    comments: str = None,
    color: str = None,
    tags=None,
) -> CommandResults:
    """
    Update an existing TCP service object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid or name.
        new_identifier (str): New name of the object.
        port (str): The number of the port used to provide this service.
        comments (str): Comments string.
        color (str): Color of the object.
        tags: Collection of tag identifiers.
    """
    demisto.debug(f"checkpoint-tcp-service-update command called with args: {demisto.args()}")
    tags = argToList(tags)

    result = client.update_service_tcp(
        identifier=identifier,
        new_identifier=new_identifier,
        port=port,
        comments=comments,
        color=color,
        tags=tags or None,
    )

    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "comments",
        "last-modifier",
        "read-only",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for updating a TCP service:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-tcp-service-update command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.TCPService",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_udp_service_update_command(
    client: Client,
    identifier: str,
    new_identifier: str = None,
    port: str = None,
    comments: str = None,
    color: str = None,
    tags=None,
) -> CommandResults:
    """
    Update an existing UDP service object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid or name.
        new_identifier (str): New name of the object.
        port (str): The number of the port used to provide this service.
        comments (str): Comments string.
        color (str): Color of the object.
        tags: Collection of tag identifiers.
    """
    demisto.debug(f"checkpoint-udp-service-update command called with args: {demisto.args()}")
    tags = argToList(tags)

    result = client.update_service_udp(
        identifier=identifier,
        new_identifier=new_identifier,
        port=port,
        comments=comments,
        color=color,
        tags=tags or None,
    )

    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "comments",
        "last-modifier",
        "read-only",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for updating a UDP service:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-udp-service-update command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.UDPService",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_icmp_service_update_command(
    client: Client,
    identifier: str,
    new_identifier: str = None,
    icmp_type: str = None,
    icmp_code: str = None,
    comments: str = None,
    color: str = None,
    tags=None,
) -> CommandResults:
    """
    Update an existing ICMP service object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid or name.
        new_identifier (str): New name of the object.
        port (str): The number of the port used to provide this service.
        icmp_type (str): ICMP type as listed in RFC 792.
        icmp_code (str): ICMP code as listed in RFC 792.
        comments (str): Comments string.
        color (str): Color of the object.
        tags: Collection of tag identifiers.
    """
    demisto.debug(f"checkpoint-icmp-service-update command called with args: {demisto.args()}")
    tags = argToList(tags)

    result = client.update_service_icmp(
        identifier=identifier,
        new_identifier=new_identifier,
        icmp_type=arg_to_number(icmp_type),
        icmp_code=arg_to_number(icmp_code),
        comments=comments,
        color=color,
        tags=tags or None,
    )

    headers = [
        "name",
        "uid",
        "type",
        "domain-name",
        "domain-type",
        "domain-uid",
        "creator",
        "comments",
        "last-modifier",
        "read-only",
    ]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for updating an ICMP service:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-icmp-service-update command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.ICMPService",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_service_delete_command(
    client: Client, identifier: str, service_type: str, ignore_warnings: Union[bool, str] = False
) -> CommandResults:
    """
    Delete a service object.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid or name.
        service_type (str): The service type (tcp, udp, or icmp).
        ignore_warnings (bool): Whether to ignore warnings when deleting the service object.
    """
    demisto.debug(f"checkpoint-service-delete command called with args: {demisto.args()}")
    ignore_warnings = argToBoolean(ignore_warnings)

    client.delete_service(identifier, service_type, ignore_warnings)

    demisto.debug("checkpoint-service-delete command completed successfully")
    return CommandResults(
        readable_output="Service deleted successfully.",
    )


def checkpoint_nat_rule_get_command(client: Client, identifier: str, package: str) -> CommandResults:
    """
    Show existing NAT rule using object unique identifier or name.

    Args:
        client (Client): CheckPoint client.
        identifier (str): Object unique identifier or name.
        package (str): Name of the package.
    """
    demisto.debug(f"checkpoint-nat-rule-get command called with args: {demisto.args()}")
    result = client.show_nat_rule(identifier, package)

    readable_output = tableToMarkdown(f"CheckPoint data for NAT rule {identifier}:", result, removeNull=True)

    demisto.debug("checkpoint-nat-rule-get command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.NatRule",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_nat_rule_list_command(
    client: Client,
    package: str,
    limit: str = "50",
    offset: str = "0",
    filter: str = None,  # noqa: A002
) -> CommandResults:
    """
    Retrieve all NAT rules from the rulebase.

    Args:
        client (Client): CheckPoint client.
        package (str): Name of the package.
        limit (str): The maximal number of returned results. default is 50.
        offset (str): Number of the results to initially skip. default is 0.
        filter (str): Search expression to filter the rulebase.
    """
    demisto.debug(f"checkpoint-nat-rule-list command called with args: {demisto.args()}")
    limit_int = arg_to_number(limit) or 50
    offset_int = arg_to_number(offset) or 0

    result = client.list_nat_rulebase(package, limit_int, offset_int, filter)

    rules: list = []
    readable_output = ""

    if result:
        if result.get("total") == 0:
            readable_output = "No NAT rules were found."
        else:
            rulebase = result.get("rulebase", [])
            for entry in rulebase:
                if entry.get("type") == "nat-rule":
                    rules.append(entry)
                elif entry.get("rulebase"):
                    for sub_entry in entry.get("rulebase", []):
                        if sub_entry.get("type") == "nat-rule":
                            rules.append(sub_entry)

            readable_output = tableToMarkdown("CheckPoint NAT rules:", rules, removeNull=True)

    demisto.debug("checkpoint-nat-rule-list command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.NatRule",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=rules,
        raw_response=result,
    )


def checkpoint_nat_rule_add_command(
    client: Client,
    package: str,
    position: str,
    name: str = None,
    original_source: str = None,
    original_destination: str = None,
    original_service: str = None,
    translated_source: str = None,
    translated_destination: str = None,
    translated_service: str = None,
    install_on=None,
    comments: str = None,
    enabled: str = None,
    nat_method: str = None,
    tags=None,
) -> CommandResults:
    """
    Add a new NAT rule.

    Args:
        client (Client): CheckPoint client.
        package (str): Name of the package.
        position (str): Position in the rulebase. Can be 'top'/'bottom'.
        name (str): Rule name.
        original_source (str): Original source.
        original_destination (str): Original destination.
        original_service (str): Original service.
        translated_source (str): Translated source.
        translated_destination (str): Translated destination.
        translated_service (str): Translated service.
        install_on: Which Gateways to install the policy on.
        comments (str): Comments string.
        enabled (str): Enable/Disable the rule.
        nat_method (str): NAT translation method.
        tags: Collection of tag identifiers.
    """
    demisto.debug(f"checkpoint-nat-rule-add command called with args: {demisto.args()}")
    install_on = argToList(install_on)
    tags = argToList(tags)

    result = client.add_nat_rule(
        package=package,
        position=position,
        name=name,
        original_source=original_source,
        original_destination=original_destination,
        original_service=original_service,
        translated_source=translated_source,
        translated_destination=translated_destination,
        translated_service=translated_service,
        install_on=install_on or None,
        comments=comments,
        enabled=argToBoolean(enabled) if enabled else None,
        method=nat_method,
        tags=tags or None,
    )

    readable_output = tableToMarkdown("CheckPoint data for adding a NAT rule:", result, removeNull=True)

    demisto.debug("checkpoint-nat-rule-add command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.NatRule",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_nat_rule_update_command(
    client: Client,
    identifier: str,
    package: str,
    original_source: str = None,
    original_destination: str = None,
    translated_source: str = None,
    translated_destination: str = None,
    original_service: str = None,
    translated_service: str = None,
    comments: str = None,
    enabled: str = None,
    nat_method: str = None,
    tags=None,
) -> CommandResults:
    """
    Update an existing NAT rule.

    Args:
        client (Client): CheckPoint client.
        identifier (str): Object unique identifier or name.
        package (str): Name of the package.
        original_source (str): Original source.
        original_destination (str): Original destination.
        translated_source (str): Translated source.
        translated_destination (str): Translated destination.
        original_service (str): Original service.
        translated_service (str): Translated service.
        comments (str): Comments string.
        enabled (str): Enable/Disable the rule.
        nat_method (str): NAT translation method.
        tags: Collection of tag identifiers.
    """
    demisto.debug(f"checkpoint-nat-rule-update command called with args: {demisto.args()}")
    tags = argToList(tags)

    result = client.update_nat_rule(
        identifier=identifier,
        package=package,
        original_source=original_source,
        original_destination=original_destination,
        translated_source=translated_source,
        translated_destination=translated_destination,
        original_service=original_service,
        translated_service=translated_service,
        comments=comments,
        enabled=argToBoolean(enabled) if enabled else None,
        method=nat_method,
        tags=tags or None,
    )

    readable_output = tableToMarkdown("CheckPoint data for updating a NAT rule:", result, removeNull=True)

    demisto.debug("checkpoint-nat-rule-update command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.NatRule",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_nat_rule_delete_command(client: Client, identifier: str, package: str) -> CommandResults:
    """
    Delete a NAT rule.

    Args:
        client (Client): CheckPoint client.
        identifier (str): Object unique identifier or name.
        package (str): Name of the package.
    """
    demisto.debug(f"checkpoint-nat-rule-delete command called with args: {demisto.args()}")
    client.delete_nat_rule(
        identifier=identifier,
        package=package,
    )

    demisto.debug("checkpoint-nat-rule-delete command completed successfully")
    return CommandResults(
        readable_output="Nat Rule deleted successfully.",
    )


def build_member_data(result: dict, readable_output: str, printable_result: dict):
    """helper function. Builds the member data for group endpoints."""
    members = result.get("members")
    members_printable_result = []

    if members:
        for member in members:
            current_object_data = {
                "member-name": member.get("name"),
                "member-uid": member.get("uid"),
                "member-type": member.get("type"),
            }
            if member.get("ipv4-address"):
                current_object_data["member-ipv4-address"] = member.get("ipv4-address")
            if member.get("ipv6-address"):
                current_object_data["member-ipv6-address"] = member.get("ipv6-address")

            member_domain = member.get("domain")
            if member_domain:
                current_object_data.update(
                    {
                        "member-domain-name": member_domain.get("name"),
                        "member-domain-uid": member_domain.get("uid"),
                        "member-domain-type": member_domain.get("type"),
                    }
                )

            members_printable_result.append(current_object_data)
        printable_result["members"] = members_printable_result
        member_readable_output = tableToMarkdown(
            "CheckPoint member data:",
            members_printable_result,
            [
                "member-name",
                "member-uid",
                "member-type",
                "member-ipv4-address",
                "member-ipv6-address",
                "member-domain-name",
                "member-domain-uid",
            ],
            removeNull=True,
        )
        readable_output = readable_output + member_readable_output
    return readable_output, printable_result


def build_printable_result(headers: list, result: dict) -> dict:
    """helper function. Builds the printable results."""

    printable_result = {}
    for endpoint in headers:
        printable_result[endpoint] = result.get(endpoint)

        domain_data = result.get("domain")
        if domain_data:
            printable_result.update(
                {
                    "domain-name": domain_data.get("name"),
                    "domain-uid": domain_data.get("uid"),
                    "domain-type": domain_data.get("type"),
                }
            )

        meta_info = result.get("meta-info")
        if meta_info:
            result.update(
                {
                    "creator": meta_info.get("creator"),
                    "last-modifier": meta_info.get("last-modifier"),
                }
            )

        groups = result.get("groups")
        if groups:
            group_list = []
            for group_object in groups:
                group_list.append(group_object.get("name"))
            printable_result["groups"] = group_list

    return printable_result


def build_group_data(result: dict, readable_output: str, printable_result: dict):
    """helper function. Builds new table of group objects related to an object."""
    groups_printable_result = []
    groups_info = result.get("groups")
    if groups_info:
        for group in groups_info:
            current_object_data = {
                "name": group.get("name"),
                "uid": group.get("uid"),
            }
            groups_printable_result.append(current_object_data)
        printable_result["groups"] = groups_printable_result
        groups_readable_output = tableToMarkdown("Additional group data:", groups_printable_result, removeNull=True)
        readable_output = readable_output + groups_readable_output

    return readable_output, printable_result


def checkpoint_logout_command(client: Client, sid: str = None) -> str:
    """logout from given session"""
    if sid is not None:
        client.sid = sid

    return client.logout()


def main():  # pragma: no cover
    """
    Client is created with a session id. if a session id was given as argument
    use it, else use the session id from the integration context.
    """
    params = demisto.params()
    args = demisto.args()

    username = demisto.get(params, "username.identifier")
    password = demisto.get(params, "username.password")
    domain_arg = params.get("domain", "")
    sid_arg = args.pop("session_id", None)

    login_args = {
        "username": username,
        "password": password,
        "session_timeout": args.get("session_timeout", 600),
        "domain_arg": domain_arg,
    }

    server = params.get("server")
    port = params.get("port")
    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)

    if server.startswith("https://"):
        server = server[len("https://") :]

    if server.endswith("/"):
        server = server[:-1]

    client = Client(base_url=f"https://{server}:{port}/web_api/", use_ssl=verify_certificate, use_proxy=proxy, sid=sid_arg)

    try:
        # commands that perform login
        command = demisto.command()
        if demisto.command() == "test-module":
            client.login(**login_args)
            return_results(client.test_connection())
            client.logout()
            return

        elif command == "checkpoint-login-and-get-session-id":
            return_results(client.login(**login_args))
            # note that the "if client.has_logged in: client.logout()" mechanism is NOT used here, to allow sid reuse
            return

        elif command == "checkpoint-logout":
            return_results(checkpoint_logout_command(client, sid_arg))
            return

        else:
            if not client.sid:  # client.sid is None if `sid_arg in {None, "None"}`
                client.restore_sid_from_context_or_login(**login_args)

        demisto.info(f"Command being called is {demisto.command()}")

        if command == "checkpoint-host-list":
            return_results(checkpoint_list_hosts_command(client, **args))

        elif command == "checkpoint-host-get":
            return_results(checkpoint_get_host_command(client, **args))

        elif command == "checkpoint-host-add":
            return_results(checkpoint_add_host_command(client, **args))

        elif command == "checkpoint-host-update":
            return_results(checkpoint_update_host_command(client, **args))

        elif command == "checkpoint-host-delete":
            return_results(checkpoint_delete_host_command(client, **args))

        elif command == "checkpoint-group-list":
            return_results(checkpoint_list_groups_command(client, **args))

        elif command == "checkpoint-group-get":
            return_results(checkpoint_get_group_command(client, **args))

        elif command == "checkpoint-group-add":
            return_results(checkpoint_add_group_command(client, **args))

        elif command == "checkpoint-group-update":
            return_results(checkpoint_update_group_command(client, **args))

        elif command == "checkpoint-group-delete":
            return_results(checkpoint_delete_group_command(client, **args))

        elif command == "checkpoint-address-range-list":
            return_results(checkpoint_list_address_range_command(client, **args))

        elif command == "checkpoint-address-range-get":
            return_results(checkpoint_get_address_range_command(client, **args))

        elif command == "checkpoint-address-range-add":
            return_results(checkpoint_add_address_range_command(client, **args))

        elif command == "checkpoint-address-range-update":
            return_results(checkpoint_update_address_range_command(client, **args))

        elif command == "checkpoint-address-range-delete":
            return_results(checkpoint_delete_address_range_command(client, **args))

        elif command == "checkpoint-threat-indicator-list":
            return_results(checkpoint_list_threat_indicator_command(client, **args))

        elif command == "checkpoint-threat-indicator-get":
            return_results(checkpoint_get_threat_indicator_command(client, **args))

        elif command == "checkpoint-threat-indicator-add":
            return_results(checkpoint_add_threat_indicator_command(client, **args))

        elif command == "checkpoint-threat-indicator-update":
            return_results(checkpoint_update_threat_indicator_command(client, **args))

        elif command == "checkpoint-threat-indicator-delete":
            return_results(checkpoint_delete_threat_indicator_command(client, **args))

        elif command == "checkpoint-access-rule-list":
            return_results(checkpoint_list_access_rule_command(client, **args))

        elif command == "checkpoint-access-rule-add":
            return_results(checkpoint_add_access_rule_command(client, **args))

        elif command == "checkpoint-access-rule-update":
            return_results(checkpoint_update_access_rule_command(client, **args))

        elif command == "checkpoint-access-rule-delete":
            return_results(checkpoint_delete_access_rule_command(client, **args))

        elif command == "checkpoint-application-site-list":
            return_results(checkpoint_list_application_site_command(client, **args))

        elif command == "checkpoint-application-site-add":
            return_results(checkpoint_add_application_site_command(client, **args))

        elif command == "checkpoint-application-site-update":
            return_results(checkpoint_update_application_site_command(client, **args))

        elif command == "checkpoint-application-site-delete":
            return_results(checkpoint_delete_application_site_command(client, **args))

        elif command == "checkpoint-application-site-category-list":
            return_results(checkpoint_list_application_site_categories_command(client, **args))

        elif command == "checkpoint-application-site-category-get":
            return_results(checkpoint_get_application_site_category_command(client, **args))

        elif command == "checkpoint-application-site-category-add":
            return_results(checkpoint_add_application_site_category_command(client, **args))

        elif command == "checkpoint-packages-list":
            return_results(checkpoint_list_packages_command(client, **args))

        elif command == "checkpoint-gateways-list":
            return_results(checkpoint_list_gateways_command(client, **args))

        elif command == "checkpoint-show-objects":
            return_results(checkpoint_list_objects_command(client, **args))

        elif command == "checkpoint-show-task":
            return_results(checkpoint_show_task_command(client, **args))

        elif command == "checkpoint-publish":
            return_results(checkpoint_publish_command(client))

        elif command == "checkpoint-install-policy":
            return_results(checkpoint_install_policy_command(client, **args))

        elif command == "checkpoint-verify-policy":
            return_results(checkpoint_verify_policy_command(client, **args))

        elif command == "checkpoint-package-list":
            return_results(checkpoint_list_package_command(client, **args))

        elif command == "checkpoint-add-objects-batch":
            return_results(checkpoint_add_objects_batch_command(client, **args))

        elif command == "checkpoint-delete-objects-batch":
            return_results(checkpoint_delete_objects_batch_command(client, **args))

        elif command == "checkpoint-show-threat-protection":
            return_results(checkpoint_show_threat_protection_command(client, args))

        elif command == "checkpoint-show-threat-protections":
            return_results(checkpoint_show_threat_protections_command(client, args))

        elif command == "checkpoint-add-threat-profile":
            return_results(checkpoint_add_threat_profile_command(client, args))

        elif command == "checkpoint-delete-threat-protections":
            return_results(checkpoint_delete_threat_protections_command(client, args))

        elif command == "checkpoint-set-threat-protection":
            return_results(checkpoint_set_threat_protections_command(client, args))

        elif command == "checkpoint-network-get":
            return_results(checkpoint_network_get_command(client, **args))

        elif command == "checkpoint-network-list":
            return_results(checkpoint_network_list_command(client, **args))

        elif command == "checkpoint-network-add":
            return_results(checkpoint_network_add_command(client, **args))

        elif command == "checkpoint-network-update":
            return_results(checkpoint_network_update_command(client, **args))

        elif command == "checkpoint-network-delete":
            return_results(checkpoint_network_delete_command(client, **args))

        elif command == "checkpoint-service-get":
            return_results(checkpoint_service_get_command(client, **args))

        elif command == "checkpoint-service-list":
            return_results(checkpoint_service_list_command(client, **args))

        elif command == "checkpoint-tcp-service-add":
            return_results(checkpoint_tcp_service_add_command(client, **args))

        elif command == "checkpoint-udp-service-add":
            return_results(checkpoint_udp_service_add_command(client, **args))

        elif command == "checkpoint-icmp-service-add":
            return_results(checkpoint_icmp_service_add_command(client, **args))

        elif command == "checkpoint-tcp-service-update":
            return_results(checkpoint_tcp_service_update_command(client, **args))

        elif command == "checkpoint-udp-service-update":
            return_results(checkpoint_udp_service_update_command(client, **args))

        elif command == "checkpoint-icmp-service-update":
            return_results(checkpoint_icmp_service_update_command(client, **args))

        elif command == "checkpoint-service-delete":
            return_results(checkpoint_service_delete_command(client, **args))

        elif command == "checkpoint-nat-rule-get":
            return_results(checkpoint_nat_rule_get_command(client, **args))

        elif command == "checkpoint-nat-rule-list":
            return_results(checkpoint_nat_rule_list_command(client, **args))

        elif command == "checkpoint-nat-rule-add":
            return_results(checkpoint_nat_rule_add_command(client, **args))

        elif command == "checkpoint-nat-rule-update":
            return_results(checkpoint_nat_rule_update_command(client, **args))

        elif command == "checkpoint-nat-rule-delete":
            return_results(checkpoint_nat_rule_delete_command(client, **args))
        else:
            raise NotImplementedError(f"Unknown command {command}.")

        if client.has_performed_login:
            # this part is not reached when login() is explicitly called
            demisto.debug("main: client.has_performed_login==True, logging out.")
            client.logout()

    except DemistoException as e:
        error_text_parts = [f"Failed to execute {demisto.command()} command."]
        e_message = e.args[0]

        if e.res:
            status = e.res.http_status
            if status == 401:
                error_text_parts.extend(
                    (
                        "The current session is unreachable.  All changes done after last publish are saved.",
                        "Please contact IT for more information.",
                    )
                )
                demisto.setIntegrationContext({})

            elif status == 500:
                error_text_parts.append("Server Error: make sure Server URL and Server Port are correctly set")
                demisto.setIntegrationContext({})

        elif "Missing header: [X-chkp-sid]" in e_message or "Authentication to server failed" in e_message:
            error_text_parts.append("Wrong credentials! Please check the username and password you entered and try again.")
            demisto.setIntegrationContext({})

        error_text_parts.append(f"\nError: {e!s}")
        return_error("\n".join(error_text_parts))

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
