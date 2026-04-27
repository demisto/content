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
    "domain-type",
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

    def list_hosts(
        self,
        limit: int,
        offset: int,
        details_level: str | None = None,
        domains_to_process: list | None = None,
    ):
        body: dict = {"limit": limit, "offset": offset}
        if details_level:
            body["details-level"] = details_level
        if domains_to_process:
            body["domains-to-process"] = domains_to_process
        demisto.debug(
            f"{demisto.command()}: endpoint='show-hosts', "
            f"args=({limit=}, {offset=}, {details_level=}, "
            f"{domains_to_process=}), body={body}"
        )
        return self._http_request(
            method="POST",
            url_suffix="show-hosts",
            headers=self.headers,
            resp_type="json",
            json_data=body,
        )

    def get_host(self, identifier: str, details_level: str | None = None):
        body: dict = {"name": identifier}
        if details_level:
            body["details-level"] = details_level
        demisto.debug(f"{demisto.command()}: endpoint='show-host', " f"args=({identifier=}, {details_level=}), body={body}")
        return self._http_request(method="POST", url_suffix="show-host", headers=self.headers, json_data=body)

    def add_host(
        self,
        name: str,
        ip_address: str,
        ignore_warnings: bool,
        ignore_errors: bool,
        groups: list | None = None,
        comments: str | None = None,
        color: str | None = None,
        nat_settings: dict | None = None,
        interfaces: list | None = None,
        tags: list | None = None,
    ):
        body: dict = {
            "name": name,
            "ip-address": ip_address,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
        }
        if groups:
            body["groups"] = groups
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if nat_settings:
            body["nat-settings"] = nat_settings
        if interfaces:
            body["interfaces"] = interfaces
        if tags:
            body["tags"] = tags
        demisto.debug(
            f"{demisto.command()}: endpoint='add-host', "
            f"args=({name=}, {ip_address=}, {ignore_warnings=}, "
            f"{ignore_errors=}, {groups=}, {comments=}, {color=}, "
            f"{nat_settings=}, {interfaces=}, {tags=}), body={body}"
        )
        return self._http_request(
            method="POST",
            url_suffix="add-host",
            headers=self.headers,
            json_data=body,
        )

    def update_host(
        self,
        identifier: str,
        ignore_warnings: bool,
        ignore_errors: bool,
        ip_address: str | None = None,
        new_name: str | None = None,
        comments: str | None = None,
        groups: list | None = None,
        color: str | None = None,
        nat_settings: dict | None = None,
        interfaces: list | None = None,
        tags: list | None = None,
    ):
        body: dict = {
            "name": identifier,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
        }
        if ip_address:
            body["ip-address"] = ip_address
        if new_name:
            body["new-name"] = new_name
        if comments:
            body["comments"] = comments
        if groups:
            body["groups"] = groups
        if color:
            body["color"] = color
        if nat_settings:
            body["nat-settings"] = nat_settings
        if interfaces:
            body["interfaces"] = interfaces
        if tags:
            body["tags"] = tags
        demisto.debug(
            f"{demisto.command()}: endpoint='set-host', "
            f"args=({identifier=}, {ignore_warnings=}, {ignore_errors=}, "
            f"{ip_address=}, {new_name=}, {comments=}, {groups=}, "
            f"{color=}, {nat_settings=}, {interfaces=}, {tags=}), body={body}"
        )
        response = self._http_request(method="POST", url_suffix="set-host", headers=self.headers, json_data=body)
        return response

    def delete_host(self, identifier: str, ignore_warnings: bool, ignore_errors: bool):
        return self._http_request(
            method="POST",
            url_suffix="delete-host",
            headers=self.headers,
            json_data={"name": identifier, "ignore-warnings": ignore_warnings, "ignore-errors": ignore_errors},
        )

    def list_groups(
        self,
        limit: int,
        offset: int,
        details_level: str | None = None,
        domains_to_process: list | None = None,
        filter_exp: str | None = None,
    ):
        body: dict = {"limit": limit, "offset": offset}
        if details_level:
            body["details-level"] = details_level
        if domains_to_process:
            body["domains-to-process"] = domains_to_process
        if filter_exp:
            body["filter"] = filter_exp
        demisto.debug(
            f"{demisto.command()}: endpoint='show-groups', "
            f"args=({limit=}, {offset=}, {details_level=}, "
            f"{domains_to_process=}, {filter_exp=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="show-groups", headers=self.headers, json_data=body)

    def get_group(self, identifier: str, details_level: str | None = None):
        body: dict = {"name": identifier}
        if details_level:
            body["details-level"] = details_level
        demisto.debug(f"{demisto.command()}: endpoint='show-group', " f"args=({identifier=}, {details_level=}), body={body}")
        return self._http_request(method="POST", url_suffix="show-group", headers=self.headers, json_data=body)

    def add_group(
        self,
        name: str,
        members: list | None = None,
        comments: str | None = None,
        color: str | None = None,
        tags: list | None = None,
        ignore_warnings: bool = False,
        ignore_errors: bool = False,
    ):
        body: dict = {
            "name": name,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
        }
        if members:
            body["members"] = members
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        demisto.debug(
            f"{demisto.command()}: endpoint='add-group', "
            f"args=({name=}, {members=}, {comments=}, {color=}, "
            f"{tags=}, {ignore_warnings=}, {ignore_errors=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="add-group", headers=self.headers, json_data=body)

    def update_group(
        self,
        identifier: str,
        ignore_warnings: bool,
        ignore_errors: bool,
        action: str,
        members,
        new_name: Optional[str] = None,
        comments: Optional[str] = None,
        color: str | None = None,
        tags: list | None = None,
        details_level: str | None = None,
    ):
        # If the desired action is to add or remove members, they should be specified differently.
        members_value = {action: members} if action in ["add", "remove"] else members
        body: dict = {
            "name": identifier,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
        }
        if new_name:
            body["new-name"] = new_name
        if members_value:
            body["members"] = members_value
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        if details_level:
            body["details-level"] = details_level

        demisto.debug(
            f"{demisto.command()}: endpoint='set-group', "
            f"args=({identifier=}, {ignore_warnings=}, {ignore_errors=}, "
            f"{action=}, {members=}, {new_name=}, {comments=}, "
            f"{color=}, {tags=}, {details_level=}), body={body}"
        )
        response = self._http_request(method="POST", url_suffix="set-group", headers=self.headers, json_data=body)
        return response

    def delete_group(self, identifier: str):
        return self._http_request(method="POST", url_suffix="delete-group", headers=self.headers, json_data={"name": identifier})

    def list_address_ranges(
        self,
        limit: int,
        offset: int,
        details_level: str | None = None,
        domains_to_process: list | None = None,
    ):
        body: dict = {"limit": limit, "offset": offset}
        if details_level:
            body["details-level"] = details_level
        if domains_to_process:
            body["domains-to-process"] = domains_to_process
        demisto.debug(
            f"{demisto.command()}: endpoint='show-address-ranges', "
            f"args=({limit=}, {offset=}, {details_level=}, "
            f"{domains_to_process=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="show-address-ranges", headers=self.headers, json_data=body)

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
        groups=None,
        comments: str | None = None,
        color: str | None = None,
        nat_settings: dict | None = None,
        tags: list | None = None,
    ):
        body: dict = {
            "name": name,
            "ip-address-first": ip_address_first,
            "ip-address-last": ip_address_last,
            "set-if-exists": set_if_exists,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
        }
        if groups:
            body["groups"] = groups
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if nat_settings:
            body["nat-settings"] = nat_settings
        if tags:
            body["tags"] = tags
        demisto.debug(
            f"{demisto.command()}: endpoint='add-address-range', "
            f"args=({name=}, {ip_address_first=}, {ip_address_last=}, "
            f"{set_if_exists=}, {ignore_warnings=}, {ignore_errors=}, "
            f"{groups=}, {comments=}, {color=}, {nat_settings=}, {tags=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="add-address-range", headers=self.headers, json_data=body)

    def update_address_range(
        self,
        identifier: str,
        ignore_warnings: bool,
        ignore_errors: bool,
        ip_address_first: Optional[str] = None,
        ip_address_last: Optional[str] = None,
        new_name: Optional[str] = None,
        comments: Optional[str] = None,
        groups=None,
        color: str | None = None,
        nat_settings: dict | None = None,
        tags: list | None = None,
    ):
        body: dict = {
            "name": identifier,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
        }
        if ip_address_first:
            body["ip-address-first"] = ip_address_first
        if ip_address_last:
            body["ip-address-last"] = ip_address_last
        if new_name:
            body["new-name"] = new_name
        if comments:
            body["comments"] = comments
        if groups:
            body["groups"] = groups
        if color:
            body["color"] = color
        if nat_settings:
            body["nat-settings"] = nat_settings
        if tags:
            body["tags"] = tags
        demisto.debug(
            f"{demisto.command()}: endpoint='set-address-range', "
            f"args=({identifier=}, {ignore_warnings=}, {ignore_errors=}, "
            f"{ip_address_first=}, {ip_address_last=}, {new_name=}, "
            f"{comments=}, {groups=}, {color=}, {nat_settings=}, {tags=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="set-address-range", headers=self.headers, json_data=body)

    def delete_address_range(self, identifier: str):
        return self._http_request(
            method="POST", url_suffix="delete-address-range", headers=self.headers, json_data={"name": identifier}
        )

    def list_threat_indicators(
        self,
        limit: int,
        offset: int,
        domain_names: list | None = None,
        details_level: str | None = None,
        filter_exp: str | None = None,
    ):
        body: dict = {"limit": limit, "offset": offset}
        if domain_names:
            body["domains-to-process"] = domain_names
        if details_level:
            body["details-level"] = details_level
        if filter_exp:
            body["filter"] = filter_exp
        demisto.debug(
            f"{demisto.command()}: endpoint='show-threat-indicators', "
            f"args=({limit=}, {offset=}, {domain_names=}, "
            f"{details_level=}, {filter_exp=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="show-threat-indicators", headers=self.headers, json_data=body)

    def get_threat_indicator(self, identifier):
        return self._http_request(
            method="POST", url_suffix="show-threat-indicator", headers=self.headers, json_data={"name": identifier}
        )

    def add_threat_indicator(
        self,
        name: str,
        observables: list,
        comments: str | None = None,
        color: str | None = None,
        tags: list | None = None,
        ignore_warnings: bool = False,
        action: str | None = None,
        profile_overrides: list | None = None,
    ):
        body: dict = {"name": name, "observables": observables}
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        if ignore_warnings:
            body["ignore-warnings"] = ignore_warnings
        if action:
            body["action"] = action
        if profile_overrides:
            body["profile-overrides"] = profile_overrides
        demisto.debug(
            f"{demisto.command()}: endpoint='add-threat-indicator', "
            f"args=({name=}, {observables=}, {comments=}, {color=}, "
            f"{tags=}, {ignore_warnings=}, {action=}, {profile_overrides=}), body={body}"
        )
        return self._http_request(
            method="POST",
            url_suffix="add-threat-indicator",
            headers=self.headers,
            json_data=body,
        )

    def update_threat_indicator(
        self,
        identifier: str,
        action: str | None = None,
        new_name: str | None = None,
        comments: str | None = None,
        profile_overrides: list | None = None,
        color: str | None = None,
        tags: list | None = None,
    ):
        body: dict = {"name": identifier}
        if action:
            body["action"] = action
        if new_name:
            body["new-name"] = new_name
        if comments:
            body["comments"] = comments
        if profile_overrides:
            body["profile-overrides"] = profile_overrides
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        demisto.debug(
            f"{demisto.command()}: endpoint='set-threat-indicator', "
            f"args=({identifier=}, {action=}, {new_name=}, {comments=}, "
            f"{profile_overrides=}, {color=}, {tags=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="set-threat-indicator", headers=self.headers, json_data=body)

    def delete_threat_indicator(self, identifier: str):
        return self._http_request(
            method="POST", url_suffix="delete-threat-indicator", headers=self.headers, json_data={"name": identifier}
        )

    def list_access_rule(
        self,
        identifier: str,
        limit: int,
        offset: int,
        details_level: str | None = None,
        show_hits: bool | None = None,
    ):
        body: dict = {"name": identifier, "limit": limit, "offset": offset}
        if details_level:
            body["details-level"] = details_level
        if show_hits is not None:
            body["show-hits"] = show_hits
        demisto.debug(
            f"{demisto.command()}: endpoint='show-access-rulebase', "
            f"args=({identifier=}, {limit=}, {offset=}, "
            f"{details_level=}, {show_hits=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="show-access-rulebase", headers=self.headers, json_data=body)

    def add_rule(
        self,
        layer: str,
        position,
        action: str,
        name: Optional[str] = None,
        vpn: Optional[str] = None,
        destination=None,
        service=None,
        source=None,
        comments: str | None = None,
        install_on: list | None = None,
        enabled: bool | None = None,
        track: dict | None = None,
    ):
        body: dict = {
            "layer": layer,
            "position": position,
            "action": action,
        }
        if name:
            body["name"] = name
        if vpn:
            body["vpn"] = vpn
        if destination:
            body["destination"] = destination
        if service:
            body["service"] = service
        if source:
            body["source"] = source
        if comments:
            body["comments"] = comments
        if install_on:
            body["install-on"] = install_on
        if enabled is not None:
            body["enabled"] = enabled
        if track:
            body["track"] = track
        demisto.debug(
            f"{demisto.command()}: endpoint='add-access-rule', "
            f"args=({layer=}, {position=}, {action=}, {name=}, {vpn=}, "
            f"{destination=}, {service=}, {source=}, {comments=}, "
            f"{install_on=}, {enabled=}, {track=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="add-access-rule", headers=self.headers, json_data=body)

    def update_rule(
        self,
        identifier: str,
        layer: str,
        ignore_warnings: bool,
        ignore_errors: bool,
        enabled: bool | None = None,
        action: Optional[str] = None,
        new_name: Optional[str] = None,
        new_position=None,
        comments: str | None = None,
        track: dict | None = None,
        install_on: list | None = None,
        source: dict | None = None,
        destination: dict | None = None,
        service: dict | None = None,
    ):
        body: dict = {
            "name": identifier,
            "layer": layer,
            "ignore-warnings": ignore_warnings,
            "ignore-errors": ignore_errors,
        }
        if action:
            body["action"] = action
        if enabled is not None:
            body["enabled"] = enabled
        if new_name:
            body["new-name"] = new_name
        if new_position:
            body["new-position"] = new_position
        if comments:
            body["comments"] = comments
        if track:
            body["track"] = track
        if install_on:
            body["install-on"] = install_on
        if source:
            body["source"] = source
        if destination:
            body["destination"] = destination
        if service:
            body["service"] = service
        demisto.debug(
            f"{demisto.command()}: endpoint='set-access-rule', "
            f"args=({identifier=}, {layer=}, {ignore_warnings=}, {ignore_errors=}, "
            f"{enabled=}, {action=}, {new_name=}, {new_position=}, {comments=}, "
            f"{track=}, {install_on=}, {source=}, {destination=}, {service=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="set-access-rule", headers=self.headers, json_data=body)

    def delete_rule(self, identifier: str, layer: str):
        return self._http_request(
            method="POST", url_suffix="delete-access-rule", headers=self.headers, json_data={"name": identifier, "layer": layer}
        )

    def list_application_site(
        self,
        limit: int,
        offset: int,
        details_level: str | None = None,
        domains_to_process: list | None = None,
    ):
        body: dict = {"limit": limit, "offset": offset}
        if details_level:
            body["details-level"] = details_level
        if domains_to_process:
            body["domains-to-process"] = domains_to_process
        demisto.debug(
            f"{demisto.command()}: endpoint='show-application-sites', "
            f"args=({limit=}, {offset=}, {details_level=}, "
            f"{domains_to_process=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="show-application-sites", headers=self.headers, json_data=body)

    def add_application_site(
        self,
        name: str,
        primary_category: str,
        identifier,
        groups=None,
        description: str | None = None,
        comments: str | None = None,
        color: str | None = None,
        tags: list | None = None,
    ):
        body: dict = {"name": name, "primary-category": primary_category, "url-list": identifier}
        if groups:
            body["groups"] = groups
        if description:
            body["description"] = description
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        demisto.debug(
            f"{demisto.command()}: endpoint='add-application-site', "
            f"args=({name=}, {primary_category=}, {identifier=}, "
            f"{groups=}, {description=}, {comments=}, {color=}, {tags=}), body={body}"
        )
        return self._http_request(method="POST", url_suffix="add-application-site", headers=self.headers, json_data=body)

    def update_application_site(
        self,
        identifier: str,
        urls_defined_as_regular_expression: bool,
        groups=None,
        url_list=None,
        description: Optional[str] = None,
        new_name: Optional[str] = None,
        primary_category: Optional[str] = None,
        application_signature: Optional[str] = None,
        comments: str | None = None,
        color: str | None = None,
        tags: list | None = None,
    ):
        body: dict = {
            "name": identifier,
            "urls-defined-as-regular-expression": urls_defined_as_regular_expression,
        }
        if description:
            body["description"] = description
        if new_name:
            body["new-name"] = new_name
        if primary_category:
            body["primary-category"] = primary_category
        if groups:
            body["groups"] = groups
        if application_signature:
            body["application-signature"] = application_signature
        if url_list:
            body["url-list"] = url_list
        if comments:
            body["comments"] = comments
        if color:
            body["color"] = color
        if tags:
            body["tags"] = tags
        demisto.debug(
            f"{demisto.command()}: endpoint='set-application-site', "
            f"args=({identifier=}, {urls_defined_as_regular_expression=}, "
            f"{groups=}, {url_list=}, {description=}, {new_name=}, "
            f"{primary_category=}, {application_signature=}, {comments=}, "
            f"{color=}, {tags=}), body={body}"
        )
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

    def add_service_group(
        self,
        name: str,
        members: Optional[list] = None,
        color: Optional[str] = None,
        comments: Optional[str] = None,
        details_level: Optional[str] = None,
        groups: Optional[list] = None,
        tags: Optional[list] = None,
        ignore_warnings: Optional[bool] = None,
        ignore_errors: Optional[bool] = None,
    ) -> dict:
        body: dict = {"name": name}
        if members is not None:
            body["members"] = members
        if color is not None:
            body["color"] = color
        if comments is not None:
            body["comments"] = comments
        if details_level is not None:
            body["details-level"] = details_level
        if groups is not None:
            body["groups"] = groups
        if tags is not None:
            body["tags"] = tags
        if ignore_warnings is not None:
            body["ignore-warnings"] = ignore_warnings
        if ignore_errors is not None:
            body["ignore-errors"] = ignore_errors
        demisto.debug(f"add-service-group request body: {body}")
        return self._http_request(method="POST", url_suffix="add-service-group", headers=self.headers, json_data=body)

    def get_service_group(
        self,
        identifier: str,
        show_as_ranges: Optional[bool] = None,
        details_level: Optional[str] = None,
    ) -> dict:
        body: dict = {"name": identifier}
        if show_as_ranges is not None:
            body["show-as-ranges"] = show_as_ranges
        if details_level is not None:
            body["details-level"] = details_level
        demisto.debug(f"show-service-group request body: {body}")
        return self._http_request(method="POST", url_suffix="show-service-group", headers=self.headers, json_data=body)

    def list_service_groups(
        self,
        filter_search: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        order: Optional[list] = None,
        show_as_ranges: Optional[bool] = None,
        dereference_group_members: Optional[bool] = None,
        show_membership: Optional[bool] = None,
        details_level: Optional[str] = None,
        domains_to_process: Optional[list] = None,
    ) -> dict:
        body: dict = {}
        if filter_search is not None:
            body["filter"] = filter_search
        if limit is not None:
            body["limit"] = limit
        if offset is not None:
            body["offset"] = offset
        if order is not None:
            body["order"] = order
        if show_as_ranges is not None:
            body["show-as-ranges"] = show_as_ranges
        if dereference_group_members is not None:
            body["dereference-group-members"] = dereference_group_members
        if show_membership is not None:
            body["show-membership"] = show_membership
        if details_level is not None:
            body["details-level"] = details_level
        if domains_to_process is not None:
            body["domains-to-process"] = domains_to_process
            # The API requires ignore-warnings=true when querying multiple domains
            body["ignore-warnings"] = True
        demisto.debug(f"show-service-groups request body: {body}")
        return self._http_request(method="POST", url_suffix="show-service-groups", headers=self.headers, json_data=body)

    def update_service_group(
        self,
        identifier: str,
        members: Optional[dict | list] = None,
        new_name: Optional[str] = None,
        color: Optional[str] = None,
        comments: Optional[str] = None,
        ignore_warnings: Optional[bool] = None,
        ignore_errors: Optional[bool] = None,
        details_level: Optional[str] = None,
        groups: Optional[dict | list] = None,
        tags: Optional[dict | list] = None,
    ) -> dict:
        body: dict = {"name": identifier}
        if members is not None:
            body["members"] = members
        if new_name is not None:
            body["new-name"] = new_name
        if color is not None:
            body["color"] = color
        if comments is not None:
            body["comments"] = comments
        if ignore_warnings is not None:
            body["ignore-warnings"] = ignore_warnings
        if ignore_errors is not None:
            body["ignore-errors"] = ignore_errors
        if details_level is not None:
            body["details-level"] = details_level
        if groups is not None:
            body["groups"] = groups
        if tags is not None:
            body["tags"] = tags
        demisto.debug(f"set-service-group request body: {body}")
        return self._http_request(method="POST", url_suffix="set-service-group", headers=self.headers, json_data=body)

    def clone_service_group(
        self,
        identifier: str,
        members: Optional[dict | list] = None,
        new_name: Optional[str] = None,
        color: Optional[str] = None,
        comments: Optional[str] = None,
        ignore_warnings: Optional[bool] = None,
        ignore_errors: Optional[bool] = None,
        details_level: Optional[str] = None,
        groups: Optional[dict | list] = None,
        tags: Optional[dict | list] = None,
    ) -> dict:
        body: dict = {"name": identifier}
        if members is not None:
            body["members"] = members
        if new_name is not None:
            body["new-name"] = new_name
        if color is not None:
            body["color"] = color
        if comments is not None:
            body["comments"] = comments
        if ignore_warnings is not None:
            body["ignore-warnings"] = ignore_warnings
        if ignore_errors is not None:
            body["ignore-errors"] = ignore_errors
        if details_level is not None:
            body["details-level"] = details_level
        if groups is not None:
            body["groups"] = groups
        if tags is not None:
            body["tags"] = tags
        demisto.debug(f"clone-service-group request body: {body}")
        return self._http_request(method="POST", url_suffix="clone-service-group", headers=self.headers, json_data=body)

    def delete_service_group(
        self,
        identifier: str,
        details_level: Optional[str] = None,
        ignore_warnings: Optional[bool] = None,
        ignore_errors: Optional[bool] = None,
    ) -> dict:
        body: dict = {"name": identifier}
        if details_level is not None:
            body["details-level"] = details_level
        if ignore_warnings is not None:
            body["ignore-warnings"] = ignore_warnings
        if ignore_errors is not None:
            body["ignore-errors"] = ignore_errors
        demisto.debug(f"delete-service-group request body: {body}")
        return self._http_request(method="POST", url_suffix="delete-service-group", headers=self.headers, json_data=body)

    def add_access_section(
        self,
        layer: str,
        position: str | dict | int,
        details_level: Optional[str] = None,
        name: Optional[str] = None,
        tags: Optional[list] = None,
        ignore_warnings: Optional[bool] = None,
        ignore_errors: Optional[bool] = None,
    ) -> dict:
        body: dict = {"layer": layer, "position": position}
        if details_level is not None:
            body["details-level"] = details_level
        if name is not None:
            body["name"] = name
        if tags is not None:
            body["tags"] = tags
        if ignore_warnings is not None:
            body["ignore-warnings"] = ignore_warnings
        if ignore_errors is not None:
            body["ignore-errors"] = ignore_errors
        demisto.debug(f"add-access-section request body: {body}")
        return self._http_request(method="POST", url_suffix="add-access-section", headers=self.headers, json_data=body)

    def get_access_section(
        self,
        layer: str,
        identifier: str,
        details_level: Optional[str] = None,
    ) -> dict:
        body: dict = {"layer": layer, "name": identifier}
        if details_level is not None:
            body["details-level"] = details_level
        demisto.debug(f"show-access-section request body: {body}")
        return self._http_request(method="POST", url_suffix="show-access-section", headers=self.headers, json_data=body)

    def update_access_section(
        self,
        identifier: str,
        layer: str,
        new_name: Optional[str] = None,
        details_level: Optional[str] = None,
        tags: Optional[dict | list] = None,
        ignore_warnings: Optional[bool] = None,
        ignore_errors: Optional[bool] = None,
    ) -> dict:
        body: dict = {"name": identifier, "layer": layer}
        if new_name is not None:
            body["new-name"] = new_name
        if details_level is not None:
            body["details-level"] = details_level
        if tags is not None:
            body["tags"] = tags
        if ignore_warnings is not None:
            body["ignore-warnings"] = ignore_warnings
        if ignore_errors is not None:
            body["ignore-errors"] = ignore_errors
        demisto.debug(f"set-access-section request body: {body}")
        return self._http_request(method="POST", url_suffix="set-access-section", headers=self.headers, json_data=body)

    def delete_access_section(
        self,
        identifier: str,
        layer: str,
        details_level: Optional[str] = None,
    ) -> dict:
        body: dict = {"name": identifier, "layer": layer}
        if details_level is not None:
            body["details-level"] = details_level
        demisto.debug(f"delete-access-section request body: {body}")
        return self._http_request(method="POST", url_suffix="delete-access-section", headers=self.headers, json_data=body)


def validate_domains_to_process(domains_to_process: str | None, details_level: str | None) -> None:
    """Validate domains_to_process argument constraints.

    Args:
        domains_to_process: Indicates which domains to process the commands on.
        details_level: The level of detail for returned objects.

    Raises:
        ValueError: If domains_to_process is used with details_level 'full'.
    """
    if domains_to_process and details_level == "full":
        raise ValueError(
            "The 'domains_to_process' argument cannot be used with 'details_level' set to 'full'. "
            "Please change 'details_level' or remove 'domains_to_process'."
        )


def checkpoint_list_hosts_command(
    client: Client,
    limit: int,
    offset: int,
    details_level: str = None,
    domains_to_process: str = None,
) -> CommandResults:
    """
    Retrieve all host objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
        details_level (str): The level of detail for returned objects.
        domains_to_process (str): Indicates which domains to process the commands on.
    """
    validate_domains_to_process(domains_to_process, details_level)
    printable_result = []
    readable_output = ""
    domains_list = argToList(domains_to_process) if domains_to_process else None

    result = client.list_hosts(limit, offset, details_level=details_level, domains_to_process=domains_list)
    demisto.info(result)
    if result:
        if result.get("total") == 0:
            readable_output = "No hosts objects were found."
        else:
            result = result.get("objects")
            for element in result:
                current_printable_result = {}

                domain = element.get("domain", {})
                current_printable_result["domain-name"] = domain.get("name")
                current_printable_result["domain-uid"] = domain.get("uid")
                current_printable_result["domain-type"] = domain.get("domain-type")

                for endpoint in DEFAULT_LIST_FIELD:
                    if endpoint not in ["domain-name", "domain-uid", "domain-type"]:
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


def checkpoint_get_host_command(client: Client, identifier: str, details_level: str = None) -> CommandResults:
    """
    Show existing host object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
        details_level (str): The level of detail for returned objects.
    """
    result = client.get_host(identifier, details_level=details_level)
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
    client: Client,
    name,
    ip_address,
    ignore_warnings: Union[bool, str] = "false",
    ignore_errors: Union[bool, str] = "false",
    groups: str = None,
    comments: str = None,
    color: str = None,
    nat_auto_rule: str = None,
    nat_method: str = None,
    nat_ip: str = None,
    nat_install_on: str = None,
    nat_hide_behind: str = None,
    interfaces_name: str = None,
    interfaces_subnet: str = None,
    interfaces_mask_length: str = None,
    tags: str = None,
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
        comments (str): Comments string.
        color (str): Object color.
        nat_auto_rule (str): Whether to enable automatic NAT rule generation.
        nat_method (str): NAT translation method (hide or static).
        nat_ip (str): NAT IPv4 or IPv6 address.
        nat_install_on (str): Gateway for NAT install-on setting.
        nat_hide_behind (str): Hide behind method (gateway or ip_address).
        interfaces_name (str): Interface name.
        interfaces_subnet (str): Interface subnet address.
        interfaces_mask_length (str): Interface mask length.
        tags (str or list): Collection of tag identifiers.
    """
    name = argToList(name)
    ip_address = argToList(ip_address)
    groups_list = argToList(groups) if groups else None
    tags_list = argToList(tags) if tags else None
    ignore_warnings = argToBoolean(ignore_warnings)
    ignore_errors = argToBoolean(ignore_errors)

    nat_settings = build_nat_settings(nat_auto_rule, nat_method, nat_ip, nat_install_on, nat_hide_behind)
    interfaces = build_interfaces_list(interfaces_name, interfaces_subnet, interfaces_mask_length)

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
        "color",
        "comments",
        "tags",
        "nat-auto-rule",
        "nat-method",
        "nat-ipv4-address",
        "nat-install-on",
        "nat-hide-behind",
    ]

    if len(name) != len(ip_address):
        raise ValueError("Number of host-names and host-IP has to be equal")
    else:
        for index, item in enumerate(name):
            current_result = client.add_host(
                item,
                ip_address[index],
                ignore_warnings,
                ignore_errors,
                groups=groups_list,
                comments=comments,
                color=color,
                nat_settings=nat_settings,
                interfaces=interfaces,
                tags=tags_list,
            )
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
    ignore_warnings: Union[bool, str] = "false",
    ignore_errors: Union[bool, str] = "false",
    ip_address: str = None,
    new_name: str = None,
    comments: str = None,
    groups=None,
    color: str = None,
    nat_auto_rule: str = None,
    nat_method: str = None,
    nat_ip: str = None,
    nat_install_on: str = None,
    nat_hide_behind: str = None,
    interfaces_name: str = None,
    interfaces_subnet: str = None,
    interfaces_mask_length: str = None,
    tags: str = None,
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
        color (str): Object color.
        nat_auto_rule (str): Whether to enable automatic NAT rule generation.
        nat_method (str): NAT translation method (hide or static).
        nat_ip (str): NAT IPv4 or IPv6 address.
        nat_install_on (str): Gateway for NAT install-on setting.
        nat_hide_behind (str): Hide behind method (gateway or ip_address).
        interfaces_name (str): Interface name.
        interfaces_subnet (str): Interface subnet address.
        interfaces_mask_length (str): Interface mask length.
        tags (str or list): Collection of tag identifiers.
    """
    groups_list = argToList(groups) if groups else None
    tags_list = argToList(tags) if tags else None
    ignore_warnings = argToBoolean(ignore_warnings)
    ignore_errors = argToBoolean(ignore_errors)

    nat_settings = build_nat_settings(nat_auto_rule, nat_method, nat_ip, nat_install_on, nat_hide_behind)
    interfaces = build_interfaces_list(interfaces_name, interfaces_subnet, interfaces_mask_length)

    result = client.update_host(
        identifier,
        ignore_warnings,
        ignore_errors,
        ip_address=ip_address,
        new_name=new_name,
        comments=comments,
        groups=groups_list,
        color=color,
        nat_settings=nat_settings,
        interfaces=interfaces,
        tags=tags_list,
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
        "color",
        "comments",
        "tags",
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


def checkpoint_list_groups_command(
    client: Client,
    limit: int,
    offset: int,
    details_level: str = None,
    domains_to_process: str = None,
    filter: str = None,
) -> CommandResults:
    """
    Retrieve all group objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
        details_level (str): The level of detail for returned objects.
        domains_to_process (str): Indicates which domains to process the commands on.
        filter (str): Search expression to filter objects by.
    """
    domains_list = argToList(domains_to_process) if domains_to_process else None
    result = client.list_groups(limit, offset, details_level=details_level, domains_to_process=domains_list, filter_exp=filter)
    result = result.get("objects")

    printable_result = []
    readable_output = ""

    if result:
        for element in result:
            current_printable_result = {}

            domain = element.get("domain", {})
            current_printable_result["domain-name"] = domain.get("name")
            current_printable_result["domain-uid"] = domain.get("uid")
            current_printable_result["domain-type"] = domain.get("domain-type")

            for endpoint in DEFAULT_LIST_FIELD:
                if endpoint not in ["domain-name", "domain-uid", "domain-type"]:
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


def checkpoint_get_group_command(client: Client, identifier: str, details_level: str = None) -> CommandResults:
    """
    Show existing group object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
        details_level (str): The level of detail for returned objects.
    """
    result = client.get_group(identifier, details_level=details_level)
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


def checkpoint_add_group_command(
    client: Client,
    name,
    members: str = None,
    comments: str = None,
    color: str = None,
    tags: str = None,
    ignore_warnings: Union[bool, str] = "false",
    ignore_errors: Union[bool, str] = "false",
) -> CommandResults:
    """
    add group objects.

    Args:
        client (Client): CheckPoint client.
        name(str): Object name. Must be unique in the domain.
        members (str or list): Collection of network objects identified by name or UID.
        comments (str): Comments string.
        color (str): Object color.
        tags (str or list): Collection of tag identifiers.
        ignore_warnings (str): Whether to ignore warnings when adding a group.
        ignore_errors (str): Whether to ignore errors when adding a group.
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
        "color",
        "comments",
    ]
    name = argToList(name)
    members_list = argToList(members) if members else None
    tags_list = argToList(tags) if tags else None
    ignore_warnings_bool = argToBoolean(ignore_warnings)
    ignore_errors_bool = argToBoolean(ignore_errors)
    result = []
    printable_result = {}
    readable_output = ""

    for item in enumerate(name):
        current_result = client.add_group(
            item[1],
            members=members_list,
            comments=comments,
            color=color,
            tags=tags_list,
            ignore_warnings=ignore_warnings_bool,
            ignore_errors=ignore_errors_bool,
        )
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
    ignore_warnings: Union[bool, str] = "true",
    ignore_errors: Union[bool, str] = "false",
    action: str = "",
    members=None,
    new_name: str = None,
    comments: str = None,
    color: str = None,
    tags: str = None,
    details_level: str = None,
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
        color (str): Object color.
        tags (str or list): Collection of tag identifiers.
        details_level (str): The level of detail for returned objects.
    """
    if members:
        # noinspection PyTypeChecker
        members = argToList(members)
    tags_list = argToList(tags) if tags else None
    ignore_warnings_bool = argToBoolean(ignore_warnings)
    ignore_errors_bool = argToBoolean(ignore_errors)

    result = client.update_group(
        identifier,
        ignore_warnings_bool,
        ignore_errors_bool,
        action,
        members,
        new_name=new_name,
        comments=comments,
        color=color,
        tags=tags_list,
        details_level=details_level,
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
        "color",
        "comments",
        "tags",
    ]
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


def checkpoint_list_address_range_command(
    client: Client,
    limit: int,
    offset: int,
    details_level: str = None,
    domains_to_process: str = None,
) -> CommandResults:
    """
    Retrieve all address range objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
        details_level (str): The level of detail for returned objects.
        domains_to_process (str): Indicates which domains to process the commands on.
    """
    domains_list = argToList(domains_to_process) if domains_to_process else None
    result = client.list_address_ranges(limit, offset, details_level=details_level, domains_to_process=domains_list)
    result = result.get("objects")

    printable_result = []
    readable_output = ""

    if result:
        for element in result:
            current_printable_result = {}

            domain = element.get("domain", {})
            current_printable_result["domain-name"] = domain.get("name")
            current_printable_result["domain-uid"] = domain.get("uid")
            current_printable_result["domain-type"] = domain.get("domain-type")

            for endpoint in DEFAULT_LIST_FIELD:
                if endpoint not in ["domain-name", "domain-uid", "domain-type"]:
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
    set_if_exists: Union[bool, str] = "false",
    ignore_warnings: Union[bool, str] = "true",
    ignore_errors: Union[bool, str] = "false",
    groups=None,
    comments: str = None,
    color: str = None,
    nat_auto_rule: str = None,
    nat_method: str = None,
    nat_ip: str = None,
    nat_install_on: str = None,
    nat_hide_behind: str = None,
    tags: str = None,
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
        comments (str): Comments string.
        color (str): Object color.
        nat_auto_rule (str): Whether to enable automatic NAT rule generation.
        nat_method (str): NAT translation method (hide or static).
        nat_ip (str): NAT IPv4 or IPv6 address.
        nat_install_on (str): Gateway for NAT install-on setting.
        nat_hide_behind (str): Hide behind method (gateway or ip_address).
        tags (str or list): Collection of tag identifiers.
    """
    groups_list = argToList(groups) if groups else None
    tags_list = argToList(tags) if tags else None
    set_if_exists_bool = argToBoolean(set_if_exists)
    ignore_warnings_bool = argToBoolean(ignore_warnings)
    ignore_errors_bool = argToBoolean(ignore_errors)
    nat_settings = build_nat_settings(nat_auto_rule, nat_method, nat_ip, nat_install_on, nat_hide_behind)

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
        "color",
        "comments",
        "tags",
        "nat-auto-rule",
        "nat-method",
        "nat-ipv4-address",
        "nat-install-on",
        "nat-hide-behind",
    ]

    result = client.add_address_range(
        name,
        ip_address_first,
        ip_address_last,
        set_if_exists_bool,
        ignore_warnings_bool,
        ignore_errors_bool,
        groups=groups_list,
        comments=comments,
        color=color,
        nat_settings=nat_settings,
        tags=tags_list,
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
    ignore_warnings: Union[bool, str] = "true",
    ignore_errors: Union[bool, str] = "false",
    ip_address_first: str = None,
    ip_address_last: str = None,
    new_name: str = None,
    comments: str = None,
    groups=None,
    color: str = None,
    nat_method: str = None,
    nat_ip: str = None,
    nat_install_on: str = None,
    nat_hide_behind: str = None,
    tags: str = None,
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
        color (str): Object color.
        nat_method (str): NAT translation method (hide or static).
        nat_ip (str): NAT IPv4 or IPv6 address.
        nat_install_on (str): Gateway for NAT install-on setting.
        nat_hide_behind (str): Hide behind method (gateway or ip_address).
        tags (str or list): Collection of tag identifiers.
    """
    groups_list = argToList(groups) if groups else None
    tags_list = argToList(tags) if tags else None
    ignore_warnings_bool = argToBoolean(ignore_warnings)
    ignore_errors_bool = argToBoolean(ignore_errors)
    nat_settings = build_nat_settings(None, nat_method, nat_ip, nat_install_on, nat_hide_behind, require_auto_rule=False)

    result = client.update_address_range(
        identifier,
        ignore_warnings_bool,
        ignore_errors_bool,
        ip_address_first=ip_address_first,
        ip_address_last=ip_address_last,
        new_name=new_name,
        comments=comments,
        groups=groups_list,
        color=color,
        nat_settings=nat_settings,
        tags=tags_list,
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
        "color",
        "tags",
        "nat-auto-rule",
        "nat-method",
        "nat-ipv4-address",
        "nat-install-on",
        "nat-hide-behind",
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


def checkpoint_list_threat_indicator_command(
    client: Client,
    limit: int,
    offset: int,
    domain_names: str = None,
    details_level: str = None,
    filter: str = None,
) -> CommandResults:
    """
    Retrieve all threat indicator objects.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results. default is 50.
        offset (int): Number of the results to initially skip. default is 0.
        domain_names (str): Indicates which domains to process.
        details_level (str): The level of detail for returned objects.
        filter (str): Search expression to filter objects by.
    """
    domains_list = argToList(domain_names) if domain_names else None
    result = client.list_threat_indicators(
        limit, offset, domain_names=domains_list, details_level=details_level, filter_exp=filter
    )
    result["objects"] = result.pop("indicators")
    printable_result = []
    readable_output = ""

    result = result.get("objects")
    if result:
        for element in result:
            current_printable_result = {}

            domain = element.get("domain", {})
            current_printable_result["domain-name"] = domain.get("name")
            current_printable_result["domain-uid"] = domain.get("uid")
            current_printable_result["domain-type"] = domain.get("domain-type")

            for endpoint in DEFAULT_LIST_FIELD:
                if endpoint not in ["domain-name", "domain-uid", "domain-type"]:
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


def checkpoint_add_threat_indicator_command(
    client: Client,
    name: str,
    profile_action: str,
    observables: list = None,
    action: str = None,
    comments: str = None,
    color: str = None,
    tags: str = None,
    ignore_warnings: Union[bool, str] = "false",
) -> CommandResults:
    """
    Create new threat indicator.

    Args:
        client (Client): CheckPoint client.
        name(str): Object name. Must be unique in the domain.
        profile_action (str or list): List of profile-action pairs in the format 'profile_action'.
            Each item is split by '_' to create a profile override with 'profile' and 'action' keys.
            example: ["p1_a1", "p2_a2", "p3_a3"]
        observables(list): The indicator's observables.
        action (str): Action for the indicator.
        comments (str): Comments string.
        color (str): Object color.
        tags (str or list): Collection of tag identifiers.
        ignore_warnings (str): Whether to ignore warnings.
    """
    observables_list = argToList(observables) if observables else []
    tags_list = argToList(tags) if tags else None
    profile_action_list = argToList(profile_action)
    profile_overrides = []
    for item in profile_action_list:
        parts = item.split("_", 1)
        if len(parts) == 2:
            profile_overrides.append({"profile": parts[0], "action": parts[1]})
        else:
            profile_overrides.append({"profile": parts[0], "action": ""})
    ignore_warnings_bool = argToBoolean(ignore_warnings)

    result = client.add_threat_indicator(
        name,
        observables_list,
        comments=comments,
        color=color,
        tags=tags_list,
        ignore_warnings=ignore_warnings_bool,
        action=action,
        profile_overrides=profile_overrides,
    )
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
    client: Client,
    identifier: str,
    profile_action: str,
    action: str = None,
    new_name: str = None,
    comments: str = None,
    color: str = None,
    tags: str = None,
) -> CommandResults:
    """
    Edit existing threat indicator object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
        profile_action (str or list): List of profile-action pairs in the format 'profile_action'.
            Each item is split by '_' to create a profile override with 'profile' and 'action' keys.
            example: ["p1_a1", "p2_a2", "p3_a3"]
        action (str): the action to set. available options:
                            "Inactive", "Ask", "Prevent", "Detect".
        new_name(str): New name of the object.
        comments(str): Comments string.
        color (str): Object color.
        tags (str or list): Collection of tag identifiers.
    """
    profile_action_list = argToList(profile_action)
    profile_overrides = []
    for item in profile_action_list:
        parts = item.split("_", 1)
        if len(parts) == 2:
            profile_overrides.append({"profile": parts[0], "action": parts[1]})
        else:
            profile_overrides.append({"profile": parts[0], "action": ""})
    tags_list = argToList(tags) if tags else None

    result = client.update_threat_indicator(
        identifier,
        action=action,
        new_name=new_name,
        comments=comments,
        profile_overrides=profile_overrides,
        color=color,
        tags=tags_list,
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
        "color",
        "tags",
        "profile-overrides",
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


def checkpoint_list_access_rule_command(
    client: Client,
    identifier: str,
    limit: int,
    offset: int,
    details_level: str = None,
    show_hits: str = None,
) -> CommandResults:
    """
    Show existing access rule base objects using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier(str): uid or name.
        limit (int): The maximal number of returned results.
        offset (int): Number of the results to initially skip.
        details_level (str): The level of detail for returned objects.
        show_hits (str): Whether to include hit count data in the output.
    """
    printable_result = []
    readable_output = ""
    show_hits_bool = argToBoolean(show_hits) if show_hits is not None else None

    result = client.list_access_rule(identifier, limit, offset, details_level=details_level, show_hits=show_hits_bool)
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
    action: str = "Drop",
    name: str = None,
    vpn: str = None,
    destination=None,
    service=None,
    source=None,
    comments: str = None,
    install_on: str = None,
    enabled: str = None,
    track_type: str = None,
    track_accounting: str = None,
    track_per_session: str = None,
) -> CommandResults:
    """
    Add new access rule object.

    Args:
        client (Client): CheckPoint client.
        layer(str): Layer that the rule belongs to identified by the name or UID.
        position(int or str): Position in the rulebase.
        name(str): rule name
        action(str): Action settings. valid values are: Accept, Drop, Apply Layer, Ask and Info
        vpn(str): Communities or Directional. Valid values: Any, All_GwToGw.
        destination(str or list): Collection of Network objects identified by the name or UID.
        service(str or list): Collection of Network objects identified by the name or UID.
        source(str or list): Collection of Network objects identified by the name or UID.
        comments (str): Comments string.
        install_on (str or list): Which gateways to install the policy on.
        enabled (str): Enable/Disable the rule.
        track_type (str): Track settings (Log, Extended Log, Detailed Log, None).
        track_accounting (str): Turns accounting for track on and off.
        track_per_session (str): Determines whether to perform the log per session.
    """
    install_on_list = argToList(install_on) if install_on else None
    enabled_bool = argToBoolean(enabled) if enabled is not None else None

    # Build track settings dict
    track = None
    if track_type or track_accounting or track_per_session:
        track = {}
        if track_type:
            track["type"] = track_type
        if track_accounting is not None:
            track["accounting"] = argToBoolean(track_accounting)
        if track_per_session is not None:
            track["per-session"] = argToBoolean(track_per_session)

    headers = ["name", "uid", "type", "domain-name", "domain-type", "domain-uid", "enabled", "layer", "creator", "last-modifier"]

    result = client.add_rule(
        layer,
        position,
        action,
        name=name,
        vpn=vpn,
        destination=destination,
        service=service,
        source=source,
        comments=comments,
        install_on=install_on_list,
        enabled=enabled_bool,
        track=track,
    )
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
    ignore_warnings: Union[bool, str] = "true",
    ignore_errors: Union[bool, str] = "false",
    enabled: str = None,
    action: str = None,
    new_name: str = None,
    new_position=None,
    comments: str = None,
    track_type: str = None,
    track_accounting: str = None,
    track_per_session: str = None,
    install_on: str = None,
    source_add: str = None,
    source_remove: str = None,
    service_add: str = None,
    service_remove: str = None,
    destination_add: str = None,
    destination_remove: str = None,
) -> CommandResults:
    """
    Edit existing access rule object using object name or uid.

    Args:
        client (Client): CheckPoint client.
        identifier (str): uid, name or rule-number.
        layer (str): Layer that the rule belongs to identified by the name or UID.
        ignore_warnings(bool): Apply changes ignoring warnings.
        ignore_errors(bool): Apply changes ignoring errors.
        enabled(str): Enable/Disable the rule.
        action (str): the action to set.
        new_name(str): New name of the object.
        new_position: New position in the rulebase.
        comments (str): Comments string.
        track_type (str): Track settings (Log, Extended Log, Detailed Log, None).
        track_accounting (str): Turns accounting for track on and off.
        track_per_session (str): Determines whether to perform the log per session.
        install_on (str or list): Which gateways to install the policy on.
        source_add (str or list): Adds to the collection of source network objects.
        source_remove (str or list): Removes from the collection of source network objects.
        service_add (str or list): Adds to the collection of service objects.
        service_remove (str or list): Removes from the collection of service objects.
        destination_add (str or list): Adds to the collection of destination network objects.
        destination_remove (str or list): Removes from the collection of destination network objects.
    """
    ignore_warnings_bool = argToBoolean(ignore_warnings)
    ignore_errors_bool = argToBoolean(ignore_errors)
    enabled_bool = argToBoolean(enabled) if enabled is not None else None
    install_on_list = argToList(install_on) if install_on else None

    # Build track settings dict
    track = None
    if track_type or track_accounting or track_per_session:
        track = {}
        if track_type:
            track["type"] = track_type
        if track_accounting is not None:
            track["accounting"] = argToBoolean(track_accounting)
        if track_per_session is not None:
            track["per-session"] = argToBoolean(track_per_session)

    # Build incremental source/destination/service dicts
    source_obj = None
    if source_add or source_remove:
        source_obj = {}
        if source_add:
            source_obj["add"] = argToList(source_add)
        if source_remove:
            source_obj["remove"] = argToList(source_remove)

    destination_obj = None
    if destination_add or destination_remove:
        destination_obj = {}
        if destination_add:
            destination_obj["add"] = argToList(destination_add)
        if destination_remove:
            destination_obj["remove"] = argToList(destination_remove)

    service_obj = None
    if service_add or service_remove:
        service_obj = {}
        if service_add:
            service_obj["add"] = argToList(service_add)
        if service_remove:
            service_obj["remove"] = argToList(service_remove)

    result = client.update_rule(
        identifier,
        layer,
        ignore_warnings_bool,
        ignore_errors_bool,
        enabled=enabled_bool,
        action=action,
        new_name=new_name,
        new_position=new_position,
        comments=comments,
        track=track,
        install_on=install_on_list,
        source=source_obj,
        destination=destination_obj,
        service=service_obj,
    )
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


def checkpoint_list_application_site_command(
    client: Client,
    limit: int,
    offset: int,
    details_level: str = None,
    domains_to_process: str = None,
) -> CommandResults:
    """
    Show existing application site objects using object name or uid.

    Args:
        client (Client): CheckPoint client.
        limit (int): The maximal number of returned results.
        offset (int): Number of the results to initially skip.
        details_level (str): The level of detail for returned objects.
        domains_to_process (str): Indicates which domains to process the commands on.
    """
    printable_result = []
    readable_output = ""
    domains_list = argToList(domains_to_process) if domains_to_process else None

    result = client.list_application_site(limit, offset, details_level=details_level, domains_to_process=domains_list)
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


def checkpoint_add_application_site_command(
    client: Client,
    name: str,
    primary_category: str,
    identifier=None,
    groups=None,
    description: str = None,
    comments: str = None,
    color: str = None,
    tags: str = None,
):
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
        description (str): A description of the application site.
        comments (str): Comments string.
        color (str): Object color.
        tags (str or list): Collection of tag identifiers.
    """
    identifier = argToList(identifier)
    groups = argToList(groups) if groups else None
    tags_list = argToList(tags) if tags else None
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

    result = client.add_application_site(
        name,
        primary_category,
        identifier,
        groups=groups,
        description=description,
        comments=comments,
        color=color,
        tags=tags_list,
    )
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
    urls_defined_as_regular_expression: bool = True,
    groups=None,
    url_list=None,
    url_list_to_add=None,
    url_list_to_remove=None,
    description: str = None,
    new_name: str = None,
    primary_category: str = None,
    application_signature: str = None,
    comments: str = None,
    color: str = None,
    tags: str = None,
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
    tags_list = argToList(tags) if tags else None
    result = client.update_application_site(
        identifier,
        urls_defined_as_regular_expression,
        groups=groups,
        url_list=url_list_object,
        description=description,
        new_name=new_name,
        primary_category=primary_category,
        application_signature=application_signature,
        comments=comments,
        color=color,
        tags=tags_list,
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


def build_nat_settings(
    nat_auto_rule: str | None = None,
    nat_method: str | None = None,
    nat_ip: str | None = None,
    nat_install_on: str | None = None,
    nat_hide_behind: str | None = None,
    require_auto_rule: bool = True,
) -> dict | None:
    """Build the nat-settings dict for the Check Point API from individual arguments.

    Returns None if no NAT arguments are provided.

    Args:
        require_auto_rule: When True, raises ValueError if nat_auto_rule is missing
            when other nat_* arguments are provided. Set to False for commands that
            do not expose nat_auto_rule (e.g. checkpoint-address-range-update).

    Raises:
        ValueError: If nat_auto_rule is missing when other nat_* arguments are provided
            and require_auto_rule is True.
        ValueError: If nat_hide_behind is provided when nat_method is 'static'.
        ValueError: If nat_ip is missing when nat_method is 'hide' and nat_hide_behind is 'ip_address'.
        ValueError: If nat_ip is provided when nat_method is 'hide' and nat_hide_behind is 'gateway'.
    """
    has_any_nat_arg = any([nat_method, nat_ip, nat_install_on, nat_hide_behind])

    # nat_auto_rule is required when any other nat_* argument is provided
    if require_auto_rule and has_any_nat_arg and nat_auto_rule is None:
        raise ValueError(
            "The 'nat_auto_rule' argument is required when any NAT argument "
            "(nat_method, nat_ip, nat_install_on, nat_hide_behind) is provided. "
            "Please provide 'nat_auto_rule'."
        )

    # nat_hide_behind is forbidden when nat_method is 'static'
    if nat_method == "static" and nat_hide_behind:
        raise ValueError(
            "The 'nat_hide_behind' argument is forbidden when 'nat_method' is 'static'. "
            "Please remove 'nat_hide_behind' or change 'nat_method'."
        )

    # When nat_method is 'hide' and nat_hide_behind is 'gateway', nat_ip must not be provided
    if nat_method == "hide" and nat_hide_behind == "gateway" and nat_ip:
        raise ValueError(
            "The 'nat_ip' argument must not be provided when 'nat_method' is 'hide' and "
            "'nat_hide_behind' is 'gateway'. Please remove 'nat_ip' or change 'nat_hide_behind'."
            " This prevents ambiguity and matches SmartConsole behavior"
        )

    # When nat_method is 'hide' and nat_hide_behind is 'ip_address', nat_ip is required
    if nat_method == "hide" and nat_hide_behind == "ip_address" and not nat_ip:
        raise ValueError(
            "The 'nat_ip' argument is required when 'nat_method' is 'hide' and "
            "'nat_hide_behind' is 'ip_address'. Please provide 'nat_ip'."
            " This prevents ambiguity and matches SmartConsole behavior."
        )

    nat_settings: dict = {}
    if nat_auto_rule is not None:
        nat_settings["auto-rule"] = argToBoolean(nat_auto_rule)
    if nat_method:
        nat_settings["method"] = nat_method
    if nat_ip:
        nat_settings["ipv4-address"] = nat_ip
    if nat_install_on:
        nat_settings["install-on"] = nat_install_on
    if nat_hide_behind:
        nat_settings["hide-behind"] = nat_hide_behind
    return nat_settings if nat_settings else None


def build_interfaces_list(
    interfaces_name: str | None = None,
    interfaces_subnet: str | None = None,
    interfaces_mask_length: str | None = None,
) -> list | None:
    """Build the interfaces list for the Check Point API from individual arguments.

    Returns None if no interface arguments are provided.

    Raises:
        ValueError: If any interfaces_* argument is provided but interfaces_name,
            interfaces_subnet, or interfaces_mask_length is missing.
    """
    has_any_interface_arg = any([interfaces_name, interfaces_subnet, interfaces_mask_length])
    if not has_any_interface_arg:
        return None

    missing = []
    if not interfaces_name:
        missing.append("interfaces_name")
    if not interfaces_subnet:
        missing.append("interfaces_subnet")
    if not interfaces_mask_length:
        missing.append("interfaces_mask_length")
    if missing:
        raise ValueError(f"When defining interfaces, all interface arguments are required. " f"Missing: {', '.join(missing)}.")

    interface: dict = {}
    if interfaces_name:
        interface["name"] = interfaces_name
    if interfaces_subnet:
        interface["subnet4"] = interfaces_subnet
    if interfaces_mask_length:
        interface["mask-length4"] = int(interfaces_mask_length)
    return [interface]


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
                    "domain-type": domain_data.get("type") or domain_data.get("domain-type"),
                }
            )

        profile_overrides_data = result.get("profile-overrides")
        if profile_overrides_data:
            printable_result.update({"profile-overrides": profile_overrides_data})

        nat_data = result.get("nat-settings")
        if nat_data:
            printable_result.update(
                {
                    "nat-auto-rule": nat_data.get("auto-rule"),
                    "nat-method": nat_data.get("method"),
                    "nat-ipv4-address": nat_data.get("ipv4-address"),
                    "nat-install-on": nat_data.get("install-on"),
                    "nat-hide-behind": nat_data.get("hide-behind"),
                }
            )

        interface_data = result.get("interfaces")
        if interface_data:
            printable_result.update({"interfaces": interface_data})

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


def parse_order_argument(order: str) -> list[dict]:
    """Parse a comma-separated order string into the API's expected format.

    Args:
        order: Comma-separated direction:field pairs (e.g., "ASC:name" or "ASC:type,DESC:uid").

    Returns:
        list[dict]: List of order objects (e.g., [{"ASC": "name"}, {"DESC": "uid"}]).

    Raises:
        DemistoException: If the order format is invalid or direction is not ASC/DESC.
    """
    order_list: list[dict] = []
    for pair in argToList(order):
        if ":" not in pair:
            raise DemistoException(
                f"Invalid order format: '{pair}'. Expected 'direction:field' format "
                f"(e.g., 'ASC:name'). Direction must be ASC or DESC."
            )
        direction, field = pair.split(":", 1)
        direction = direction.strip().upper()
        if direction not in ("ASC", "DESC"):
            raise DemistoException(f"Invalid order direction: '{direction}'. Must be 'ASC' or 'DESC'.")
        order_list.append({direction: field.strip()})
    return order_list


def checkpoint_service_group_add_command(
    client: Client,
    name: str,
    members=None,
    color: str = None,
    comments: str = None,
    details_level: str = None,
    groups=None,
    tags=None,
    ignore_warnings: str = None,
    ignore_errors: str = None,
) -> CommandResults:
    """Add a new service group object.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-service-group-add command called with args: {demisto.args()}")

    members_list = argToList(members) or None
    groups_list = argToList(groups) or None
    tags_list = argToList(tags) or None
    ignore_warnings_bool = argToBoolean(ignore_warnings) if ignore_warnings is not None else None
    ignore_errors_bool = argToBoolean(ignore_errors) if ignore_errors is not None else None

    result = client.add_service_group(
        name=name,
        members=members_list,
        color=color,
        comments=comments,
        details_level=details_level,
        groups=groups_list,
        tags=tags_list,
        ignore_warnings=ignore_warnings_bool,
        ignore_errors=ignore_errors_bool,
    )

    headers = ["name", "uid", "type", "domain-name", "domain-uid", "domain-type", "creator", "last-modifier", "read-only"]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for adding a service group:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_member_data(result, readable_output, printable_result)
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-service-group-add command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.ServiceGroup",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_service_group_get_command(
    client: Client,
    identifier: str,
    show_as_ranges: str = None,
    details_level: str = None,
) -> CommandResults:
    """Show existing service group object using object name or uid.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-service-group-get command called with args: {demisto.args()}")

    show_as_ranges_bool = argToBoolean(show_as_ranges) if show_as_ranges is not None else None

    result = client.get_service_group(
        identifier=identifier,
        show_as_ranges=show_as_ranges_bool,
        details_level=details_level,
    )

    headers = ["name", "uid", "type", "domain-name", "domain-uid", "domain-type", "creator", "last-modifier", "read-only"]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        f"CheckPoint data for service group {identifier}:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_member_data(result, readable_output, printable_result)
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-service-group-get command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.ServiceGroup",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_service_group_list_command(
    client: Client,
    filter: str = None,
    limit: str = None,
    offset: str = None,
    order: str = None,
    show_as_ranges: str = None,
    dereference_group_members: str = None,
    show_membership: str = None,
    details_level: str = None,
    domains_to_process: str = None,
) -> CommandResults:
    """Retrieve all service group objects.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-service-group-list command called with args: {demisto.args()}")

    limit_int = arg_to_number(limit)
    offset_int = arg_to_number(offset)
    show_as_ranges_bool = argToBoolean(show_as_ranges) if show_as_ranges is not None else None
    dereference_group_members_bool = argToBoolean(dereference_group_members) if dereference_group_members is not None else None
    show_membership_bool = argToBoolean(show_membership) if show_membership is not None else None
    domains_to_process_list = argToList(domains_to_process) or None

    # domains_to_process cannot be used with details-level full
    if domains_to_process_list is not None and details_level == "full":
        raise DemistoException("The 'domains_to_process' argument cannot be used with details_level set to 'full'.")
    order_list = parse_order_argument(order) if order else None

    result = client.list_service_groups(
        filter_search=filter,
        limit=limit_int,
        offset=offset_int,
        order=order_list,
        show_as_ranges=show_as_ranges_bool,
        dereference_group_members=dereference_group_members_bool,
        show_membership=show_membership_bool,
        details_level=details_level,
        domains_to_process=domains_to_process_list,
    )

    printable_result = []
    readable_output = ""

    objects = result.get("objects")
    headers = ["name", "uid", "type"]
    if objects:
        for element in objects:
            current_printable_result = {}
            for endpoint in headers:
                current_printable_result[endpoint] = element.get(endpoint)
            printable_result.append(current_printable_result)

        readable_output = tableToMarkdown("CheckPoint data for all service groups:", printable_result, headers, removeNull=True)
    else:
        readable_output = "No service group objects were found."

    demisto.debug("checkpoint-service-group-list command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.ServiceGroup",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=objects,
        raw_response=result,
    )


def checkpoint_service_group_update_command(
    client: Client,
    identifier: str,
    members_action: str = None,
    members=None,
    new_name: str = None,
    color: str = None,
    comments: str = None,
    ignore_warnings: str = None,
    ignore_errors: str = None,
    details_level: str = None,
    groups_action: str = None,
    groups=None,
    tags_action: str = None,
    tags=None,
) -> CommandResults:
    """Edit existing service group using object name or uid.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-service-group-update command called with args: {demisto.args()}")

    ignore_warnings_bool = argToBoolean(ignore_warnings) if ignore_warnings is not None else None
    ignore_errors_bool = argToBoolean(ignore_errors) if ignore_errors is not None else None

    members_raw = argToList(members) or None
    members_parsed = {members_action: members_raw} if members_raw and members_action else members_raw

    groups_raw = argToList(groups) or None
    groups_parsed = {groups_action: groups_raw} if groups_raw and groups_action else groups_raw

    tags_raw = argToList(tags) or None
    tags_parsed = {tags_action: tags_raw} if tags_raw and tags_action else tags_raw

    result = client.update_service_group(
        identifier=identifier,
        members=members_parsed,
        new_name=new_name,
        color=color,
        comments=comments,
        ignore_warnings=ignore_warnings_bool,
        ignore_errors=ignore_errors_bool,
        details_level=details_level,
        groups=groups_parsed,
        tags=tags_parsed,
    )

    headers = ["name", "uid", "type", "domain-name", "domain-uid", "domain-type", "creator", "last-modifier", "read-only"]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for updating a service group:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_member_data(result, readable_output, printable_result)
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-service-group-update command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.ServiceGroup",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_service_group_clone_command(
    client: Client,
    identifier: str,
    members_action: str = None,
    members=None,
    new_name: str = None,
    color: str = None,
    comments: str = None,
    ignore_warnings: str = None,
    ignore_errors: str = None,
    details_level: str = None,
    groups_action: str = None,
    groups=None,
    tags_action: str = None,
    tags=None,
) -> CommandResults:
    """Clone existing service group object.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-service-group-clone command called with args: {demisto.args()}")

    ignore_warnings_bool = argToBoolean(ignore_warnings) if ignore_warnings is not None else None
    ignore_errors_bool = argToBoolean(ignore_errors) if ignore_errors is not None else None

    members_raw = argToList(members) or None
    members_parsed = {members_action: members_raw} if members_raw and members_action else members_raw

    groups_raw = argToList(groups) or None
    groups_parsed = {groups_action: groups_raw} if groups_raw and groups_action else groups_raw

    tags_raw = argToList(tags) or None
    tags_parsed = {tags_action: tags_raw} if tags_raw and tags_action else tags_raw

    result = client.clone_service_group(
        identifier=identifier,
        members=members_parsed,
        new_name=new_name,
        color=color,
        comments=comments,
        ignore_warnings=ignore_warnings_bool,
        ignore_errors=ignore_errors_bool,
        details_level=details_level,
        groups=groups_parsed,
        tags=tags_parsed,
    )

    headers = ["name", "uid", "type", "domain-name", "domain-uid", "domain-type", "creator", "last-modifier", "read-only"]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for cloning a service group:", printable_result, headers=headers, removeNull=True
    )
    readable_output, printable_result = build_member_data(result, readable_output, printable_result)
    readable_output, printable_result = build_group_data(result, readable_output, printable_result)

    demisto.debug("checkpoint-service-group-clone command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.ServiceGroup",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_service_group_delete_command(
    client: Client,
    identifier: str,
    details_level: str = None,
    ignore_warnings: str = None,
    ignore_errors: str = None,
) -> CommandResults:
    """Delete service group object using object name or uid.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-service-group-delete command called with args: {demisto.args()}")

    ignore_warnings_bool = argToBoolean(ignore_warnings) if ignore_warnings is not None else None
    ignore_errors_bool = argToBoolean(ignore_errors) if ignore_errors is not None else None

    result = client.delete_service_group(
        identifier=identifier,
        details_level=details_level,
        ignore_warnings=ignore_warnings_bool,
        ignore_errors=ignore_errors_bool,
    )

    demisto.debug("checkpoint-service-group-delete command completed successfully")
    return CommandResults(readable_output="Service group deleted successfully", raw_response=result)


def checkpoint_access_section_add_command(
    client: Client,
    layer: str,
    position: str,
    position_rule: str = None,
    details_level: str = None,
    name: str = None,
    tags=None,
    ignore_warnings: str = None,
    ignore_errors: str = None,
) -> CommandResults:
    """Add a new access section.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-access-section-add command called with args: {demisto.args()}")

    """
    According to API docs:
    - "above"/"below" require position_rule (reference rule/section name)
    - "top"/"bottom" can optionally use position_rule (reference section name)
    - integer position is sent as-is (no position_rule needed)
    """
    if position in ("above", "below") and not position_rule:
        raise DemistoException(
            f"The 'position_rule' argument is required when position is '{position}'. "
            f"Provide the name of the rule or section to position relative to."
        )
    if position_rule:
        position_obj: str | int | dict = {position: position_rule}
    elif position.isdigit():
        position_obj = int(position)
    else:
        position_obj = position
    tags_list = argToList(tags) or None
    ignore_warnings_bool = argToBoolean(ignore_warnings) if ignore_warnings is not None else None
    ignore_errors_bool = argToBoolean(ignore_errors) if ignore_errors is not None else None

    result = client.add_access_section(
        layer=layer,
        position=position_obj,
        details_level=details_level,
        name=name,
        tags=tags_list,
        ignore_warnings=ignore_warnings_bool,
        ignore_errors=ignore_errors_bool,
    )

    headers = ["name", "uid", "type", "domain-name", "domain-uid", "domain-type", "creator", "last-modifier"]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for adding an access section:", printable_result, headers=headers, removeNull=True
    )

    demisto.debug("checkpoint-access-section-add command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.AccessSection",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_access_section_get_command(
    client: Client,
    layer: str,
    identifier: str,
    details_level: str = None,
) -> CommandResults:
    """Show existing access section using object name or uid.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-access-section-get command called with args: {demisto.args()}")

    result = client.get_access_section(
        layer=layer,
        identifier=identifier,
        details_level=details_level,
    )

    headers = ["name", "uid", "type", "domain-name", "domain-uid", "domain-type", "creator", "last-modifier"]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        f"CheckPoint data for access section {identifier}:", printable_result, headers=headers, removeNull=True
    )

    demisto.debug("checkpoint-access-section-get command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.AccessSection",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_access_section_update_command(
    client: Client,
    identifier: str,
    layer: str,
    new_name: str = None,
    details_level: str = None,
    tags_action: str = None,
    tags=None,
    ignore_warnings: str = None,
    ignore_errors: str = None,
) -> CommandResults:
    """Edit existing access section using object name or uid.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-access-section-update command called with args: {demisto.args()}")

    tags_raw = argToList(tags) or None
    tags_parsed = {tags_action: tags_raw} if tags_raw and tags_action else tags_raw

    ignore_warnings_bool = argToBoolean(ignore_warnings) if ignore_warnings is not None else None
    ignore_errors_bool = argToBoolean(ignore_errors) if ignore_errors is not None else None

    result = client.update_access_section(
        identifier=identifier,
        layer=layer,
        new_name=new_name,
        details_level=details_level,
        tags=tags_parsed,
        ignore_warnings=ignore_warnings_bool,
        ignore_errors=ignore_errors_bool,
    )

    headers = ["name", "uid", "type", "domain-name", "domain-uid", "domain-type", "creator", "last-modifier"]
    printable_result = build_printable_result(headers, result)
    readable_output = tableToMarkdown(
        "CheckPoint data for updating an access section:", printable_result, headers=headers, removeNull=True
    )

    demisto.debug("checkpoint-access-section-update command completed successfully")
    return CommandResults(
        outputs_prefix="CheckPoint.AccessSection",
        outputs_key_field="uid",
        readable_output=readable_output,
        outputs=result,
        raw_response=result,
    )


def checkpoint_access_section_delete_command(
    client: Client,
    identifier: str,
    layer: str,
    details_level: str = None,
) -> CommandResults:
    """Delete access section using object name or uid.

    Args:
        client (Client): CheckPoint client.

    Returns:
        CommandResults: The command results.
    """
    demisto.debug(f"checkpoint-access-section-delete command called with args: {demisto.args()}")

    result = client.delete_access_section(
        identifier=identifier,
        layer=layer,
        details_level=details_level,
    )

    demisto.debug("checkpoint-access-section-delete command completed successfully")
    return CommandResults(readable_output="Access section deleted successfully.", raw_response=result)


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
        elif command == "checkpoint-service-group-add":
            return_results(checkpoint_service_group_add_command(client, **args))

        elif command == "checkpoint-service-group-get":
            return_results(checkpoint_service_group_get_command(client, **args))

        elif command == "checkpoint-service-group-list":
            return_results(checkpoint_service_group_list_command(client, **args))

        elif command == "checkpoint-service-group-update":
            return_results(checkpoint_service_group_update_command(client, **args))

        elif command == "checkpoint-service-group-clone":
            return_results(checkpoint_service_group_clone_command(client, **args))

        elif command == "checkpoint-service-group-delete":
            return_results(checkpoint_service_group_delete_command(client, **args))

        elif command == "checkpoint-access-section-add":
            return_results(checkpoint_access_section_add_command(client, **args))

        elif command == "checkpoint-access-section-get":
            return_results(checkpoint_access_section_get_command(client, **args))

        elif command == "checkpoint-access-section-update":
            return_results(checkpoint_access_section_update_command(client, **args))

        elif command == "checkpoint-access-section-delete":
            return_results(checkpoint_access_section_delete_command(client, **args))

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
