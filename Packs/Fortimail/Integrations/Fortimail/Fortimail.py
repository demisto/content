import copy
import http
from functools import wraps
from typing import Callable, Tuple

import demistomock as demisto  # noqa: F401
import requests.utils
import urllib3
from CommonServerPython import *

urllib3.disable_warnings()

DEFAULT_COOKIE = {"cookie_name": None, "cookie_value": None}
AUTHORIZATION_ERROR = (
    "Authorization Error: invalid username or password or too many login attempts."
    "Please check credentials or wait and try again."
)
RP_DIRECTION_MAPPER = {"Inbound": 1, "Outbound": 2}
BOOLEAN_MAPPER = {"enable": True, "disable": False}
RP_AUTH_MAPPER = {"radius": 1, "ldap": 2, "pop3": 3, "imap": 4, "samtp": 5}
RP_PATTERN_TYPE_MAPPER = {
    "User (wildcard)": 0,
    "User (regex)": 4,
    "Email address group": 3,
    "LDAP group": 2,
}
AC_PATTERN_TYPE_MAPPER = {
    "External": 5,
    "Internal": 4,
    "Email Group": 2,
    "LDAP Group": 3,
    "LDAP Verification": 6,
    "Regular Expression": 1,
    "User Defined": 0,
}
AC_AUTH_MAPPER = {
    "Any": 0,
    "Not Authenticated": 2,
    "Authenticated": 1,
}
AC_SENDER_IP_TYPE_MAPPER = {
    "IP/Netmask": 0,
    "IP Group": 1,
    "GeoIP Group": 2,
    "ISDB": 3,
}
AC_ACTION_MAPPER = {
    "Safe & Relay": 1,
    "Safe": 5,
    "Relay": 2,
    "Receive": 6,
    "Reject": 3,
    "Discard": 4,
}
IP_ACTION_MAPPER = {
    "Scan": 0,
    "Fail Temporarily": 2,
    "Reject": 1,
    "Proxy bypass": 4,
}
DESTINATION_MAPPER = {
    "IP/Netmask": 1,
    "IP Group": 2,
}
OUTPUT_PREFIX_MAPPER = {
    "antispam_profile": "AntispamProfile",
    "geoip_group": "GeoIPgroup",
    "tls_profile": "TLSprofile",
    "ip_group": "IPGroup",
    "ip_group_member": "IPGroup",
    "email_group": "EmailGroup",
    "email_group_member": "EmailGroup",
    "system_safe_block": "SystemList",
    "ip_policy": "IPPolicy",
    "access_control": "AccessControl",
    "recipient_policy": "RecipientPolicy",
    "ldap_group": "LDAPprofile",
    "antivirus_profile": "AntivirusProfile",
    "content_profile": "ContentProfile",
    "ip_pool": "IPPool",
    "session_profile": "SessionProfile",
    "radius_auth_profile": "RadiusAuthProfile",
    "pop3_auth_profile": "Pop3AuthProfile",
    "imap_auth_profile": "ImapAuthProfile",
    "smtp_auth_profile": "SmtpAuthProfile",
    "resource_profile": "ResourceProfile",
    "pki_user": "PKIuser",
}
MOVE_ACTION = "14"
REPLACE_ACTION = "10"


def validate_authentication(func: Callable) -> Callable:
    """
    Decorator to manage authentication for API requests.
    This decorator first tries to execute the provided function using an existing authentication cookie
    stored in the 'integration_context'.
    If no valid cookie is available, or if the existing cookie is no longer valid (indicated by an
    HTTP FORBIDDEN status), it attempts to re-authenticate with the API and then re-execute the function.
    The 'integration_context' is used to store and retrieve the authentication cookie,
    allowing the decorator to use the latest valid authentication details across different executions.

    Args:
        func (Callable): The API request function to be executed.

    Raises:
        DemistoException:
            - If the API returns an HTTP FORBIDDEN status during the initial request
                attempt and re-authentication also fails.
            - If the API returns any other error during the request.

    Returns:
        Callable: The result from executing 'func' with the provided arguments and keyword arguments.
    """

    @wraps(wrapped=func)
    def wrapper(client: "Client", *args, **kwargs):
        def try_request():
            """
            Attempts to execute the API request function.
            If a 'FORBIDDEN' HTTP status code is encountered, indicating an authentication issue,
            it triggers a re-authentication and retries the request.
            """
            try:
                return func(client, *args, **kwargs)
            except DemistoException as exc:
                if exc.res is not None and exc.res.status_code == http.HTTPStatus.FORBIDDEN:
                    update_cookie()
                    return func(client, *args, **kwargs)
                set_integration_context(DEFAULT_COOKIE)
                raise

        def try_authentication():
            """
            Attempts to authenticate with the API and extract the cookie from the session.
            In case of a 'FORBIDDEN' status code or other exceptions, it handles them appropriately,
            updating the integration context or raising a tailored exception.
            """
            try:
                client.authentication()
                for cookie in client._session.cookies:
                    if cookie.name.startswith("APSCOOKIE"):
                        return cookie.name, cookie.value
                raise DemistoException("Authentication failed: cookie not found.")
            except DemistoException as exc:
                set_integration_context(DEFAULT_COOKIE)
                if exc.res is not None and exc.res.status_code == http.HTTPStatus.FORBIDDEN:
                    raise DemistoException(AUTHORIZATION_ERROR)
                raise

        def update_cookie():
            """Updates the session and integration context with a new cookie."""
            cookie_name, cookie_value = try_authentication()
            cookie = requests.utils.cookiejar_from_dict({cookie_name: cookie_value})
            client._session.cookies.update(cookie)
            set_integration_context({"cookie_name": cookie_name, "cookie_value": cookie_value})

        integration_context = get_integration_context()
        if (
            integration_context
            and (cookie_name := integration_context.get("cookie_name"))
            and (cookie_value := integration_context.get("cookie_value"))
        ):
            instance_cookie = {cookie_name: cookie_value}
            cookie = requests.utils.cookiejar_from_dict(instance_cookie)
            client._session.cookies.update(cookie)
            return try_request()
        # could happen on first run or if previous cookie setup failed or if previous cookie is expired
        update_cookie()
        return func(client, *args, **kwargs)

    return wrapper


class Client(BaseClient):
    def __init__(
        self,
        server_url: str,
        user_name: str,
        password: str,
        verify: bool = True,
        proxy: bool = False,
    ):
        self._base_url = server_url
        self.user_name = user_name
        self.password = password
        super().__init__(base_url=server_url, verify=verify, proxy=proxy)

    def authentication(self) -> None:
        """
        Login to FortiMail API.
        """
        self._session.cookies.clear()
        self._http_request(
            method="POST",
            url_suffix="api/v1/AdminLogin/",
            json_data={"name": self.user_name, "password": self.password},
        )

    @validate_authentication
    def create_ip_group(
        self,
        name: str,
        comment: str = None,
    ) -> Dict[str, Any]:
        """
        Create an IP group. IP group is a container that contains members of IP addresses that can be used
        when configuring access control rules (define the source IP group of the SMTP client attempting to
        send the email message) and IP-based policies (define the IP group of the SMTP source/destination
        to which the policy applies).

        Args:
            name (str): The name of the IP group. The name must contain only alphanumeric characters.
                Spaces are not allowed.
            comment (str | None): A brief comment for the IP group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            f"api/v1/ProfIp_address_group/{name}/",
            json_data=remove_empty_elements({"comment": comment}),
        )

    @validate_authentication
    def update_ip_group(
        self,
        name: str,
        comment: str,
    ) -> Dict[str, Any]:
        """
        Update the comment of an IP group.

        Args:
            name (str): The name of the IP group to update.
            comment (str): A brief comment for the IP group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "PUT",
            f"api/v1/ProfIp_address_group/{name}/",
            json_data={"comment": comment},
        )

    @validate_authentication
    def delete_ip_group(self, name: str) -> Dict[str, Any]:
        """
        Delete an IP group.

        Args:
            name (str | None): The name of the IP group to remove.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request("DELETE", f"api/v1/ProfIp_address_group/{name}")

    @validate_authentication
    def list_ip_group(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List IP groups. if a name is given, return the information about the specify IP group.

        Args:

            name (str, optional): The name of the IP group to retrieve. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            "GET",
            f"api/v1/ProfIp_address_group{url_suffix}",
        )

    @validate_authentication
    def add_ip_group_member(self, group_name: str, ip: str) -> Dict[str, Any]:
        """
        Add an IP group member (IP/Netmask or IP range) to IP group.
        IP group member is an IP addresses that can be used when configuring access control rules
        (define the source IP group of the SMTP client attempting to send the email message) and IP-based policies
        (define the IP group of the SMTP source/destination to which the policy applies).

        Args:
            group_name (str): The name of the IP group.
            ip (str): The IP address and net-mask to include in the IP group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            f"api/v1/ProfIp_address_group/{group_name}/ProfIp_address_groupIpAddressGroupMember/{ip}",
        )

    @validate_authentication
    def replace_ip_group_member(
        self,
        group_name: str,
        ips: dict[str, str],
    ) -> Dict[str, Any]:
        """
        Replace IP group members with new members.
        This overwrites all the IP group members that defined in the IP group.

        Args:
            group_name (str): The name of the IP group.
            ips (dict[str, str]): A list of IP address (separated with a comma) to replace in the IP group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            f"api/v1/ProfIp_address_group/{group_name}/ProfIp_address_groupIpAddressGroupMember",
            json_data={"reqAction": REPLACE_ACTION} | ips,
        )

    @validate_authentication
    def delete_ip_group_member(self, group_name: str, ip: str) -> Dict[str, Any]:
        """
        Delete an IP group member from IP group.

        Args:
            group_name (str): The name of the IP group.
            ip_mask (str): The IP address member to remove from the IP group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "DELETE",
            f"api/v1/ProfIp_address_group/{group_name}/ProfIp_address_groupIpAddressGroupMember/{ip}",
        )

    @validate_authentication
    def list_ip_group_member(
        self,
        group_name: str,
        ip: str = None,
    ) -> Dict[str, Any]:
        """
        List IP group members by specify group member.
        If a IP is given, return the information about the specify IP group member.

        Args:

            ip (str, optional): The IP address to retrieve. Defaults to None.
            group_name (str, optional): The name of the IP group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "GET",
            f"api/v1/ProfIp_address_group/{group_name}/ProfIp_address_groupIpAddressGroupMember/",
            json_data=remove_empty_elements(
                {
                    "ip": ip,
                }
            ),
        )

    @validate_authentication
    def create_email_group(
        self,
        name: str,
        comment: str = None,
    ) -> Dict[str, Any]:
        """
        Create an email group. Email group is a container for a list of email addresses,
        allowing you to use it in configuring access control rules (for defining the sender
        and recipient matching) and recipient-based policies (for defining MAIL FROM addresses
        matching specific policies).

        Args:
            name (str): The name of the email group. The name must contain only alphanumeric characters.
                Spaces are not allowed.
            comment (str | None): A brief comment for the email group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            f"api/v1/ProfEmail_address_group/{name}/",
            json_data=remove_empty_elements({"comment": comment}),
        )

    @validate_authentication
    def update_email_group(
        self,
        name: str,
        comment: str,
    ) -> Dict[str, Any]:
        """
        Update the comment of an email group.

        Args:
            name (str): The name of the email group to update.
            comment (str): A brief comment for the email group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "PUT",
            f"api/v1/ProfEmail_address_group/{name}/",
            json_data={"comment": comment},
        )

    @validate_authentication
    def delete_email_group(self, name: str) -> Dict[str, Any]:
        """
        Delete an email group.

        Args:
            name (str | None): The name of the email group to remove.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request("DELETE", f"api/v1/ProfEmail_address_group/{name}")

    @validate_authentication
    def list_email_group(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List email groups. if a name is given, return the information about the specify email group.

        Args:

            name (str, optional): The name of the email group to retrieve. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            "GET",
            f"api/v1/ProfEmail_address_group{url_suffix}",
        )

    @validate_authentication
    def add_email_group_member(self, group_name: str, email: str) -> Dict[str, Any]:
        """
        Add an email group member (email address) to email group.

        Args:
            group_name (str): The name of the email group.
            email (str): The email address to include in the email group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            f"api/v1/ProfEmail_address_group/{group_name}/ProfEmail_address_groupEmailAddressGroupMember/{email}",
        )

    @validate_authentication
    def replace_email_group_member(
        self,
        group_name: str,
        emails: dict[str, str],
    ) -> Dict[str, Any]:
        """
        Replace Email group members with new members.
        This overwrites all the email group members that defined in the email group.

        Args:
            group_name (str): The name of the email group.
            emails (dict[str, str]): A list of email address (separated with a comma) to replace in the email group.

        Returns:
            Dict[str, Any]: The API response.
        """

        return self._http_request(
            "POST",
            f"api/v1/ProfEmail_address_group/{group_name}/ProfEmail_address_groupEmailAddressGroupMember",
            json_data={"reqAction": REPLACE_ACTION} | emails,
        )

    @validate_authentication
    def delete_email_group_member(self, group_name: str, email: str) -> Dict[str, Any]:
        """
        Delete an email group member from email group.

        Args:
            group_name (str): The name of the email group.
            email (str): The email member to remove from the email group.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "DELETE",
            f"api/v1/ProfEmail_address_group/{group_name}/ProfEmail_address_groupEmailAddressGroupMember/{email}",
        )

    @validate_authentication
    def list_email_group_member(
        self,
        group_name: str,
        email: str = None,
    ) -> Dict[str, Any]:
        """
        List email group members by specify group member.
        If an email is given, return the information about the specify email group member.

        Args:

            email (str, optional): The email member to retrieve. Defaults to None.
            group_name (str, optional): The name of the email group.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{email}" if email else ""
        return self._http_request(
            "GET",
            f"api/v1/ProfEmail_address_group/{group_name}/ProfEmail_address_groupEmailAddressGroupMember{url_suffix}",
        )

    @validate_authentication
    def list_system_safe_block(
        self,
        list_type: str,
    ) -> Dict[str, Any]:
        """
        List the system Block/Safe list. Choose the wanted list by the list_type argument.

        Args:
            list_type (str): The type of the list to retrieve.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            "api/v1/SenderListV2/system/",
            json_data={
                "extraParam": list_type.lower(),
                "reqAction": 1,
            },
        )

    @validate_authentication
    def add_system_safe_block(self, list_type: str, list_items: str) -> Dict[str, Any]:
        """
        Add an email address/ domain name/ IP address to the system white/ block list.

        Args:
            list_type (str): The type of the list to add the values.
            list_items (list[str]): Email address/ domain name/ IP address to add to the system white/ block list.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            "api/v1/SenderListV2/system",
            json_data={"extraParam": list_type.lower(), "listitems": list_items},
        )

    @validate_authentication
    def delete_system_safe_block(self, values: list[str], list_type: str) -> Dict[str, Any]:
        """
        Delete an email address/ domain name/ IP address from the system white/ block list.
        Choose the wanted list by the type argument.

        Args:
            values (list[str]): Email address/ domain name/ IP address (speretaed by comma) to remove
                from the system white/ block list. For example, test@test.com, test2@test.com or 1.1.1.1/0,1.1.1.2/0.
            list_type (str): The type of the list to add the values. Safelist - accept mesage, Blocklist
                invoke block list action that defined int the settings.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            "api/v1/SenderListV2/system/",
            json_data={"reqAction": 3, "extraParam": list_type.lower(), "listitems": values},
        )

    @validate_authentication
    def create_ip_policy(
        self,
        status: bool,
        action: int,
        use_smtp_auth: bool,
        smtp_different: bool,
        smtp_diff_identity_ldap: bool,
        exclusive: bool,
        destination: str = None,
        destination_type: int = None,
        source: str = None,
        source_type: int = None,
        auth_type: int = None,
        comment: str = None,
        antispam_profile: str = None,
        antivirus_profile: str = None,
        content_profile: str = None,
        session_profile: str = None,
        auth_profile: str = None,
        ip_pool_profile: str = None,
        smtp_diff_identity_ldap_profile: str = None,
    ) -> Dict[str, Any]:
        """
        Create an IP policy. IP-based policies lets you control emails based on
        IP/Netmask / IP Group/  GeoIP Group/ ISDB.

        Args:
            status (bool): Whether to apply the policy.
            action (int): An action for the policy.
            use_smtp_auth (bool): Whether to authenticate SMTP connections using the authentication profile configured
                in sensitive-data.
            smtp_different (bool):  Whether to reject different SMTP sender identity for authenticated user.
            smtp_diff_identity_ldap (bool): Whether to verify SMTP sender identity with LDAP for authenticated email.
            exclusive (bool): Whether to take precedence over recipient based policy match.
                Enable to omit use of recipient-based policies for connections matching this IP-based policy.
            destination (str, optional): The destination of the policy. Defaults to None.
            destination_type (int, optional): The type of the destination. Insert the source argument corresponding to
                the type value. Defaults to None.
            source (str, optional): The source of the policy. Defaults to None.
            source_type (int, optional): The type of the source. Insert the source argument corresponding to the type
                value. Defaults to None.
            auth_type (int, optional): The type of the authentication profile that this policy will apply.
                Defaults to None.
            comment (str, optional): A brief comment for the IP policy. Defaults to None.
            antispam_profile (str, optional): The name of an outgoing anti spam profile, if any, that this policy will
                apply. Defaults to None.
            antivirus_profile (str, optional): The name of an antivirus profile, if any, that this policy will apply.
                Defaults to None.
            content_profile (str, optional): The name of the content profile that you want to apply to connections
                matching the policy. Defaults to None.
            session_profile (str, optional): The name of the session profile that you want to apply to connections
                matching the policy. Defaults to None.
            auth_profile (str, optional): The name of an authentication profile for the type. Defaults to None.
            ip_pool_profile (str, optional): The name of an IP pool profile, if any, that this policy will apply.
                Defaults to None.
            smtp_diff_identity_ldap_profile (str, optional): LDAP profile for SMTP sender identity verification.
                Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        data = remove_empty_elements(
            {
                "action": action,
                "antispam_profile": antispam_profile,
                "antivirus_profile": antivirus_profile,
                "auth_type": auth_type,
                "client": source,
                "client_type": source_type,
                "client_geoip_group": source,
                "client_ip_group": source,
                "client_isdb": source,
                "comment": comment,
                "content_profile": content_profile,
                "exclusive": exclusive,
                "imap_auth": auth_profile,
                "ip_pool_profile": ip_pool_profile,
                "ldap_auth": auth_profile,
                "pop3_auth": auth_profile,
                "radius_auth": auth_profile,
                "server": destination,
                "server_type": destination_type,
                "server_ip_group": destination,
                "session_profile": session_profile,
                "smtp_auth": auth_profile,
                "smtp_diff_identity_ldap": smtp_diff_identity_ldap,
                "smtp_diff_identity_ldap_profile": smtp_diff_identity_ldap_profile,
                "smtp_different": smtp_different,
                "status": status,
                "use_smtp_auth": use_smtp_auth,
            }
        )
        return self._http_request("POST", "api/v1/PolicyIp/0", json_data=data)

    @validate_authentication
    def update_ip_policy(
        self,
        ip_policy_id: int,
        status: bool = None,
        destination: str = None,
        destination_type: int = None,
        source: str = None,
        source_type: int = None,
        action: int = None,
        use_smtp_auth: bool = None,
        smtp_different: bool = None,
        smtp_diff_identity_ldap: bool = None,
        exclusive: bool = None,
        auth_type: int = None,
        comment: str = None,
        antispam_profile: str = None,
        antivirus_profile: str = None,
        content_profile: str = None,
        session_profile: str = None,
        auth_profile: str = None,
        ip_pool_profile: str = None,
        smtp_diff_identity_ldap_profile: str = None,
    ) -> Dict[str, Any]:
        """
        Update an IP policy.

        Args:
            ip_policy_id (bool): The IP policy ID.
            status (bool): Whether to apply the policy. Defaults to None.
            action (int): An action for the policy. Defaults to None.
            use_smtp_auth (bool): Whether to authenticate SMTP connections using the authentication profile configured
                in sensitive-data. Defaults to None.
            smtp_different (bool):  Whether to reject different SMTP sender identity for authenticated user.
                Defaults to None.
            smtp_diff_identity_ldap (bool): Whether to verify SMTP sender identity with LDAP for authenticated email.
                Defaults to None.
            exclusive (bool): Whether to take precedence over recipient based policy match.
                Enable to omit use of recipient-based policies for connections matching this IP-based policy.
                Defaults to None.
            destination (str, optional): The destination of the policy. Defaults to None.
            destination_type (int, optional): The type of the destination. Insert the source argument corresponding to
                the type value. Defaults to None.
            source (str, optional): The source of the policy. Defaults to None.
            source_type (int, optional): The type of the source. Insert the source argument corresponding to the type
                value. Defaults to None.
            auth_type (int, optional): The type of the authentication profile that this policy will apply.
                Defaults to None.
            comment (str, optional): A brief comment for the IP policy. Defaults to None.
            antispam_profile (str, optional): The name of an outgoing anti spam profile, if any, that this policy will
                apply. Defaults to None.
            antivirus_profile (str, optional): The name of an antivirus profile, if any, that this policy will apply.
                Defaults to None.
            content_profile (str, optional): The name of the content profile that you want to apply to connections
                matching the policy. Defaults to None.
            session_profile (str, optional): The name of the session profile that you want to apply to connections
                matching the policy. Defaults to None.
            auth_profile (str, optional): The name of an authentication profile for the type. Defaults to None.
            ip_pool_profile (str, optional): The name of an IP pool profile, if any, that this policy will apply.
                Defaults to None.
            smtp_diff_identity_ldap_profile (str, optional): LDAP profile for SMTP sender identity verification.
                Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        data = remove_empty_elements(
            {
                "action": action,
                "antispam_profile": antispam_profile,
                "antivirus_profile": antivirus_profile,
                "auth_type": auth_type,
                "client": source,
                "client_type": source_type,
                "client_geoip_group": source,
                "client_ip_group": source,
                "client_isdb": source,
                "comment": comment,
                "content_profile": content_profile,
                "exclusive": exclusive,
                "imap_auth": auth_profile,
                "ip_pool_profile": ip_pool_profile,
                "ldap_auth": auth_profile,
                "pop3_auth": auth_profile,
                "radius_auth": auth_profile,
                "server": destination,
                "server_type": destination_type,
                "server_ip_group": destination,
                "session_profile": session_profile,
                "smtp_auth": auth_profile,
                "smtp_diff_identity_ldap": smtp_diff_identity_ldap,
                "smtp_diff_identity_ldap_profile": smtp_diff_identity_ldap_profile,
                "smtp_different": smtp_different,
                "status": status,
                "use_smtp_auth": use_smtp_auth,
            }
        )

        return self._http_request("PUT", f"api/v1/PolicyIp/{ip_policy_id}", json_data=data)

    @validate_authentication
    def move_ip_policy(self, policy_id: int, action: str, reference_id: int = None) -> Dict[str, Any]:
        """
        Move an IP policy location in the policy list.
        FortiMail units match the policies in sequence, from the top of the list downwards.
        Therefore, you must put the more specific policies on top of the more generic ones.

        Args:
            policy_id (int): The ID of the IP policy rule to be moved.
            action (str): The move action.
            reference_id (int, optional): The reference ID of the IP policy rule when moving before/after.
                Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            "api/v1/PolicyIp",
            json_data=remove_empty_elements(
                {
                    "mmkey": policy_id,
                    "moveAction": action,
                    "reqAction": MOVE_ACTION,
                    "refMkey": reference_id,
                }
            ),
        )

    @validate_authentication
    def delete_ip_policy(self, policy_id: int) -> Dict[str, Any]:
        """
        Delete an IP policy.

        Args:
            policy_id (int): The ID of the IP policy to remove.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request("DELETE", f"api/v1/PolicyIp/{policy_id}")

    @validate_authentication
    def list_ip_policy(
        self,
        policy_id: str = None,
    ) -> Dict[str, Any]:
        """
        List IP policy. if a ID is given, return the information about the specify IP policy.

        Args:
            policy_id (str, optional): The ID of the IP policy to retrieve. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{policy_id}" if policy_id else ""
        return self._http_request(
            "GET",
            f"api/v1/PolicyIp{url_suffix}",
        )

    @validate_authentication
    def create_access_control(
        self,
        status: bool,
        sender_type: int,
        sender: str,
        recipient_type: int,
        recipient: str,
        action: int,
        source_type: str,
        authentication_status: int,
        sender_ldap_profile: str = None,
        recipient_ldap_profile: str = None,
        source: str = None,
        reverse_dns_pattern: str = None,
        reverse_dns_pattern_regex: bool = None,
        tls_profile: str = None,
        comment: str = None,
    ) -> Dict[str, Any]:
        """
        Create an Access control rule. Access control rules take effect after the FortiMail unit has initiated
        or received an IP and TCP-level connection at the application layer of the network.

        Args:
            status (bool): Whether to activate the access rule.
            sender_type (int): The method of the SMTP client attempting to send the email message.
            sender (str): The sender.
            recipient_type (int): The recipient pattern type.
            recipient (str): The recipient.
            action (int): The delivery action that FortiMail unit will perform for SMTP sessions matching this
                access control rule.
            source_type (str): The method of the SMTP client attempting to send the email message.
            authentication_status (int): Authentication status.
            sender_ldap_profile (str, optional): Sender LDAP profile. Relevant when sender_type= LDAP Group.
                Defaults to None.
            recipient_ldap_profile (str, optional): Recipient LDAP profile. Relevant when recipient_type= LDAP Group.
                Defaults to None.
            source (str, optional): When sender_type = IP/Netmask insert the source IP address and net-mask of the
                SMTP client attempting to send the email message. Defaults to None.
            reverse_dns_pattern (str, optional): A pattern to compare to the result of a reverse DNS look-up of the
                source IP address of the SMTP client attempting to send the email message. Defaults to None.
            reverse_dns_pattern_regex (str, optional): Whether to use regular expression syntax instead of wildcards
                to specify the reverse DNS pattern. Defaults to None.
            tls_profile (str, optional): A TLS profile to allow or reject the connection based on whether the
                communication session attributes match the settings in the TLS profile. Defaults to None.
            comment (str, optional):  A brief comment for the Access control. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        data = remove_empty_elements(
            {
                "status": status,
                "sender_type": sender_type,
                "sender_pattern_group": sender,
                "sender_pattern_ldap_groupname": sender,
                "recipient_type": recipient_type,
                "recipient_pattern_group": recipient,
                "recipient_pattern_ldap_groupname": recipient,
                "sender_ldap_profile": sender_ldap_profile,
                "recipient_ldap_profile": recipient_ldap_profile,
                "source_type": source_type,
                "sender_geoip_group": source,
                "sender_ip_mask": source,
                "sender_ip_group": source,
                "sender_isdb": source,
                "reverse_dns_pattern": reverse_dns_pattern,
                "reverse_dns_pattern_regex": reverse_dns_pattern_regex,
                "authentication_status": authentication_status,
                "tls_profile": tls_profile,
                "action": action,
                "comment": comment,
            }
        )
        return self._http_request("POST", "api/v1/MailSetAccessRule/0", json_data=data)

    @validate_authentication
    def update_access_control(
        self,
        access_control_id: int,
        status: bool = None,
        sender_type: int = None,
        sender: str = None,
        recipient_type: int = None,
        recipient: str = None,
        action: int = None,
        source_type: str = None,
        authentication_status: int = None,
        sender_ldap_profile: str = None,
        recipient_ldap_profile: str = None,
        source: str = None,
        reverse_dns_pattern: str = None,
        reverse_dns_pattern_regex: bool = None,
        tls_profile: str = None,
        comment: str = None,
    ) -> Dict[str, Any]:
        """
        Update an Access control rule. Access control rules take effect after the FortiMail unit has initiated
        or received an IP and TCP-level connection at the application layer of the network.

        Args:
            access_control_id (bool): The access control ID.
            status (bool): Whether to activate the access rule.
            sender_type (int): The method of the SMTP client attempting to send the email message.
            sender (str): The sender.
            recipient_type (int): The recipient pattern type.
            recipient (str): The recipient.
            action (int): The delivery action that FortiMail unit will perform for SMTP sessions matching this
                access control rule.
            source_type (str): The method of the SMTP client attempting to send the email message.
            authentication_status (int): Authentication status.
            sender_ldap_profile (str, optional): Sender LDAP profile. Relevant when sender_type= LDAP Group.
                Defaults to None.
            recipient_ldap_profile (str, optional): Recipient LDAP profile. Relevant when recipient_type= LDAP Group.
                Defaults to None.
            source (str, optional): When sender_type = IP/Netmask insert the source IP address and net-mask of the
                SMTP client attempting to send the email message. Defaults to None.
            reverse_dns_pattern (str, optional): A pattern to compare to the result of a reverse DNS look-up of the
                source IP address of the SMTP client attempting to send the email message. Defaults to None.
            reverse_dns_pattern_regex (str, optional): Whether to use regular expression syntax instead of wildcards
                to specify the reverse DNS pattern. Defaults to None.
            tls_profile (str, optional): A TLS profile to allow or reject the connection based on whether the
                communication session attributes match the settings in the TLS profile. Defaults to None.
            comment (str, optional):  A brief comment for the Access control. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        data = remove_empty_elements(
            {
                "status": status,
                "sender_type": sender_type,
                "sender_pattern_group": sender,
                "sender_pattern_ldap_groupname": sender,
                "recipient_type": recipient_type,
                "recipient_pattern_group": recipient,
                "recipient_pattern_ldap_groupname": recipient,
                "sender_ldap_profile": sender_ldap_profile,
                "recipient_ldap_profile": recipient_ldap_profile,
                "source_type": source_type,
                "sender_geoip_group": source,
                "sender_ip_mask": source,
                "sender_ip_group": source,
                "sender_isdb": source,
                "reverse_dns_pattern": reverse_dns_pattern,
                "reverse_dns_pattern_regex": reverse_dns_pattern_regex,
                "authentication_status": authentication_status,
                "tls_profile": tls_profile,
                "action": action,
                "comment": comment,
            }
        )

        return self._http_request("PUT", f"api/v1/MailSetAccessRule/{access_control_id}", json_data=data)

    @validate_authentication
    def delete_access_control(self, access_control_id: int) -> Dict[str, Any]:
        """
        Delete an access control rule.

        Args:
            access_control_id (int): The ID of the access rule to remove.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request("DELETE", f"api/v1/MailSetAccessRule/{access_control_id}")

    @validate_authentication
    def move_access_control(self, access_control_id: int, action: str, reference_id: int = None) -> Dict[str, Any]:
        """
        Move an Access control rule location in the rules list.
        FortiMail units match the policies in sequence, from the top of the list downwards.
        Therefore, you must put the more specific policies on top of the more generic ones.

        Args:
            access_control_id (int): The ID of the access control to be moved.
            action (str): The move action.
            reference_id (int, optional): The reference ID of the access control rule when moving before/after.
                Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            "api/v1/MailSetAccessRule",
            json_data=remove_empty_elements(
                {
                    "mmkey": access_control_id,
                    "moveAction": action,
                    "reqAction": MOVE_ACTION,
                    "refMkey": reference_id,
                }
            ),
        )

    @validate_authentication
    def list_access_control(
        self,
        access_control_id: int = None,
    ) -> Dict[str, Any]:
        """
        List access control rules. if a ID is given, return the information about the wanted access control rule.

        Args:
            access_control_id (str, optional): The ID of the IP policy to retrieve. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{access_control_id}" if access_control_id else ""
        return self._http_request(
            "GET",
            f"api/v1/MailSetAccessRule{url_suffix}",
        )

    @validate_authentication
    def create_recipient_policy(
        self,
        status: bool,
        direction: int,
        use_smtp_auth: bool,
        smtp_different: bool,
        smtp_diff_identity_ldap: bool,
        enable_pki: bool,
        certificate_validation: bool,
        recipient_email_address_group: str = None,
        sender_email_address_group: str = None,
        auth_type: int = None,
        sender_type: int = None,
        recipient_type: int = None,
        comment: str = None,
        sender_pattern: str = None,
        sender_ldap_profile: str = None,
        recipient_pattern: str = None,
        recipient_ldap_profile: str = None,
        antispam_profile: str = None,
        antivirus_profile: str = None,
        content_profile: str = None,
        resource_profile: str = None,
        auth_profile: str = None,
        pki_profile: str = None,
        smtp_diff_identity_ldap_profile: str = None,
    ) -> Dict[str, Any]:
        """
        Create an Inbound/ Outbound Recipient policy.
        Recipient policies control email based on sender and recipient addresses.
        Recipient-based policies have precedence if an IP-based policy is also applicable but conflicts.

        Args:
            status (bool): Whether to apply the policy.
            direction (int): The mail traffic direction.
            use_smtp_auth (str): Whether to authenticate SMTP connections using the authentication profile
                configured in sensitive-data.
            smtp_different (bool): Whether to reject different SMTP sender identity for authenticated user.
            smtp_diff_identity_ldap (str): Whether to verify SMTP sender identity with LDAP for authenticated email.
            enable_pki (str): Whether to allow email users to log in to their per-recipient spam quarantine by
                presenting a certificate rather than a user name and password.
            certificate_validation (str): Whether to require valid certificates only and disallow password-style
                fallback.
            recipient_email_address_group (str, optional): Recipient Email group.
                Relevant when recipient_type=Email address group. Defaults to None.
            sender_email_address_group (str, optional): Sender Email group.
                Relevant when recipient_type=Email address group. Defaults to None.
            auth_type (int, optional): The type of the authentication profile that this policy will apply.
                Defaults to None.
            sender_type (int, optional): Define sender (MAIL FROM:) email addresses that match this policy.
                Defaults to None.
            recipient_type (int, optional): Define recipient (RCPT TO:) email addresses that match this policy.
                Defaults to None.
            comment (str, optional): A brief comment for the recipient policy. Defaults to None.
            sender_pattern (str, optional): The policy sender pattern. Defaults to None.
            sender_ldap_profile (str, optional): Sender LDAP profile. Relevant when sender_type=LDAP Group.
                Defaults to None.
            recipient_pattern (str, optional): The policy recipient pattern. Defaults to None.
            recipient_ldap_profile (str, optional): Recipient LDAP profile. Relevant when recipient_type=LDAP Group.
                Defaults to None.
            antispam_profile (str, optional): The name of an outgoing anti spam profile, if any, that this policy
                will apply. Defaults to None.
            antivirus_profile (str, optional): The name of an antivirus profile, if any, that this policy will apply.
                Defaults to None.
            content_profile (str, optional): The name of the content profile that you want to apply to connections
                matching the policy. Defaults to None.
            resource_profile (str, optional): The name of the resource profile that you want to apply to connections
                matching the policy. Defaults to None.
            auth_profile (str, optional): The name of an authentication profile for the type. Defaults to None.
            pki_profile (str, optional): The name of a PKI user. Relevant when enable_pki is enable. Defaults to None.
            smtp_diff_identity_ldap_profile (str, optional): LDAP profile for SMTP sender identity verification.
                Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        data = remove_empty_elements(
            {
                "status": status,
                "direction": direction,
                "use_smtp_auth": use_smtp_auth,
                "smtp_different": smtp_different,
                "smtp_diff_identity_ldap": smtp_diff_identity_ldap,
                "enable_pki": enable_pki,
                "certificate_validation": certificate_validation,
                "comment": comment,
                "recipient_email_address_group": recipient_email_address_group,
                "sender_email_address_group": sender_email_address_group,
                "sender_type": sender_type,
                "sender_pattern": sender_pattern,
                "sender_ldap_profile": sender_ldap_profile,
                "recipient_type": recipient_type,
                "recipient_pattern": recipient_pattern,
                "recipient_ldap_profile": recipient_ldap_profile,
                "antispam": antispam_profile,
                "antivirus": antivirus_profile,
                "content": content_profile,
                "misc": resource_profile,
                "auth_profile": auth_profile,
                "pki_profile": pki_profile,
                "auth": auth_type,
                "smtp_diff_identity_ldap_profile": smtp_diff_identity_ldap_profile,
            }
        )

        return self._http_request("POST", "api/v1/PolicyRcpt/0", json_data=data)

    @validate_authentication
    def update_recipient_policy(
        self,
        recipient_policy_id: int,
        status: bool = None,
        direction: int = None,
        use_smtp_auth: bool = None,
        smtp_different: bool = None,
        smtp_diff_identity_ldap: bool = None,
        enable_pki: bool = None,
        certificate_validation: bool = None,
        recipient_email_address_group: str = None,
        sender_email_address_group: str = None,
        auth_type: int = None,
        sender_type: int = None,
        recipient_type: int = None,
        comment: str = None,
        sender_pattern: str = None,
        sender_ldap_profile: str = None,
        recipient_pattern: str = None,
        recipient_ldap_profile: str = None,
        antispam_profile: str = None,
        antivirus_profile: str = None,
        content_profile: str = None,
        resource_profile: str = None,
        auth_profile: str = None,
        pki_profile: str = None,
        smtp_diff_identity_ldap_profile: str = None,
    ) -> Dict[str, Any]:
        """
        Update an Inbound/ Outbound Recipient policy.
        Recipient policies control email based on sender and recipient addresses.
        Recipient-based policies have precedence if an IP-based policy is also applicable but conflicts.

        Args:
            recipient_policy_id (int): The recipient policy ID.
            status (bool): Whether to apply the policy.
            direction (int): The mail traffic direction.
            use_smtp_auth (str): Whether to authenticate SMTP connections using the authentication profile configured
                in sensitive-data.
            smtp_different (bool): Whether to reject different SMTP sender identity for authenticated user.
            smtp_diff_identity_ldap (str): Whether to verify SMTP sender identity with LDAP for authenticated email.
            enable_pki (str): Whether to allow email users to log in to their per-recipient spam quarantine by
                presenting a certificate rather than a user name and password.
            certificate_validation (str): Whether to require valid certificates only and disallow
                password-style fallback.
            recipient_email_address_group (str, optional): Recipient Email group.
                Relevant when recipient_type=Email address group. Defaults to None.
            sender_email_address_group (str, optional): Sender Email group.
                Relevant when recipient_type=Email address group. Defaults to None.
            auth_type (int, optional): The type of the authentication profile that this policy will apply.
                Defaults to None.
            sender_type (int, optional): Define sender (MAIL FROM:) email addresses that match this policy.
                Defaults to None.
            recipient_type (int, optional): Define recipient (RCPT TO:) email addresses that match this policy.
                Defaults to None.
            comment (str, optional): A brief comment for the recipient policy. Defaults to None.
            sender_pattern (str, optional): The policy sender pattern. Defaults to None.
            sender_ldap_profile (str, optional): Sender LDAP profile. Relevant when sender_type=LDAP Group.
                Defaults to None.
            recipient_pattern (str, optional): The policy recipient pattern. Defaults to None.
            recipient_ldap_profile (str, optional): Recipient LDAP profile. Relevant when recipient_type=LDAP Group.
                Defaults to None.
            antispam_profile (str, optional): The name of an outgoing anti spam profile, if any, that this policy
                will apply. Defaults to None.
            antivirus_profile (str, optional): The name of an antivirus profile, if any, that this policy will apply.
                Defaults to None.
            content_profile (str, optional): The name of the content profile that you want to apply to connections
                matching the policy. Defaults to None.
            resource_profile (str, optional): The name of the resource profile that you want to apply to connections
                matching the policy. Defaults to None.
            auth_profile (str, optional): The name of an authentication profile for the type. Defaults to None.
            pki_profile (str, optional): The name of a PKI user. Relevant when enable_pki is enable. Defaults to None.
            smtp_diff_identity_ldap_profile (str, optional): LDAP profile for SMTP sender identity verification.
                Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        data = remove_empty_elements(
            {
                "status": status,
                "direction": direction,
                "use_smtp_auth": use_smtp_auth,
                "smtp_different": smtp_different,
                "smtp_diff_identity_ldap": smtp_diff_identity_ldap,
                "enable_pki": enable_pki,
                "certificate_validation": certificate_validation,
                "comment": comment,
                "recipient_email_address_group": recipient_email_address_group,
                "sender_email_address_group": sender_email_address_group,
                "sender_type": sender_type,
                "sender_pattern": sender_pattern,
                "sender_ldap_profile": sender_ldap_profile,
                "recipient_type": recipient_type,
                "recipient_pattern": recipient_pattern,
                "recipient_ldap_profile": recipient_ldap_profile,
                "antispam_profile": antispam_profile,
                "antivirus_profile": antivirus_profile,
                "content_profile": content_profile,
                "resource_profile": resource_profile,
                "auth_profile": auth_profile,
                "pki_profile": pki_profile,
                "auth_type": auth_type,
                "smtp_diff_identity_ldap_profile": smtp_diff_identity_ldap_profile,
            }
        )
        return self._http_request("PUT", f"api/v1/PolicyRcpt/{recipient_policy_id}", json_data=data)

    @validate_authentication
    def delete_recipient_policy(self, recipient_policy_id: int) -> Dict[str, Any]:
        """
        Delete a recipient policy.

        Args:
            recipient_policy_id (int): The ID of the recipient policy to be remove.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request("DELETE", f"api/v1/domain/system/PolicyRcpt/{recipient_policy_id}")

    @validate_authentication
    def move_recipient_policy(self, recipient_policy_id: int, action: str, reference_id: int = None) -> Dict[str, Any]:
        """
        Move a recipient policy location in the policy list.
        FortiMail units match the policies in sequence, from the top of the list downwards.
        Therefore, you must put the more specific policies on top of the more generic ones

        Args:
            access_control_id (int): The ID of the recipient policy to be moved.
            action (str): The move action.
            reference_id (int, optional): The reference ID of the recipient policy when moving before/after.
                Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            "api/v1/domain/system/PolicyRcpt",
            json_data=remove_empty_elements(
                {
                    "mmkey": recipient_policy_id,
                    "moveAction": action,
                    "reqAction": MOVE_ACTION,
                    "refMkey": reference_id,
                }
            ),
        )

    @validate_authentication
    def list_recipient_policy(
        self,
        recipient_policy_id: str = None,
    ) -> Dict[str, Any]:
        """
        List recipient policies. If a recipient_policy_id is given, return the information about the wanted recipient policy.

        Args:
            recipient_policy_id (str, optional): The ID of the recipient policy. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{recipient_policy_id}" if recipient_policy_id else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/domain/system/PolicyRcpt{url_suffix}",
        )

    @validate_authentication
    def list_tls_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List TLS profiles.
        TLS profiles allow you to selectively disable or enable TLS for specific email recipient patterns,
        IP subnets, and so on.
        A common use of TLS profiles is to enforce TLS transport to a specific domain and verify the certificate
        of the receiving servers.
        if an name is given, return the information about the wanted TLS profile.
        Mainly used in the configuration of Access control rule.

        Args:
            name (str, optional): The name of the TLS profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfTls{url_suffix}",
        )

    @validate_authentication
    def list_ldap_group(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List LDAP profiles. LDAP groups lets to allow match email addresses as sender or recipients
        with the LDAP profile authentication in the Access control rule configuration and is the authentication
        profile in case the authentication type in IP policy is LDAP.
        if an name is given, return the information about the wanted LDAP profile.
        Mainly used in the configuration of Access control rule and the IP policy.

        Args:
            name (str, optional): The name of the anti spam LDAP profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfLdap{url_suffix}",
        )

    @validate_authentication
    def list_geoip_group(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List GeoIP groups.
        FortiMail utilizes the GeoIP database to map the geo locations of client IP addresses.
        You can use GeoIP groups in access control rules and IP-based policies to geo-targeting spam and virus devices.
        if an name is given, return the information about the wanted GeoIP profile.
        Mainly used in the configuration of Access control rule and the IP policy.

        Args:
            name (str, optional): The name of the anti spam GeoIP group. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfGeoip{url_suffix}",
        )

    @validate_authentication
    def list_antispam_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List AntiSpam profiles.
        Antispam profiles are sets of antispam scans that you can apply by selecting one in a policy.
        if an name is given, return the information about the wanted AntiSpam profile.
        Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the anti spam profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfAntispam{url_suffix}",
        )

    @validate_authentication
    def list_antivirus_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List AntiVirus profiles. if the FortiMail unit detects a virus, it will take actions as you define in
        the antivirus action profiles.
        if an name is given, return the information about the wanted AntiVirus profile.
        Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the anti virus profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfAntivirus{url_suffix}",
        )

    @validate_authentication
    def list_content_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List Content profiles.
        Content profile lets to allow match email based upon its subject line, message body, and attachments.
        if an name is given, return the information about the wanted content profile.
        Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the content profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfContent{url_suffix}",
        )

    @validate_authentication
    def list_ip_pool(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List IP pool profiles.
        IP pools define a range of IP addresses, and can be used in multiple ways:
        To define source IP addresses used by the FortiMail unit if you want outgoing email to originate
        from a range of IP addresses.
        To define destination addresses used by the FortiMail unit if you want incoming email to destine
        to the virtual host on a range of IP addresses. if an name is given, return the
        information about the wanted IP pool.  Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the IP pool. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfIp_pool{url_suffix}",
        )

    @validate_authentication
    def list_session_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List IP session profiles. Session profiles focus on the connection and envelope portion of the SMTP session.
        If a name is given, return the information about the wanted session profile.
        Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the session profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfSession{url_suffix}",
        )

    @validate_authentication
    def list_radius_auth_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List RADIUS authentication profiles. if an name is given, return the information about
        the wanted RADIUS authentication profile. Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the RADIUS auth profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfAuthRadius{url_suffix}",
        )

    @validate_authentication
    def list_pop3_auth_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List POP3 authentication profiles.
        if an name is given, return the information about the wanted POP3 authentication profile.
        Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the POP3 auth profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfAuthPop3{url_suffix}",
        )

    @validate_authentication
    def list_imap_auth_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List IMAP authentication profiles.
        if an name is given, return the information about the wanted IMAP authentication profile.
        Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the IMAP auth profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfAuthImap{url_suffix}",
        )

    @validate_authentication
    def list_smtp_auth_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List SMTP authentication profiles.
        if an name is given, return the information about the wanted SMTP authentication profile.
        Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the SMTP auth profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfAuthSmtp{url_suffix}",
        )

    @validate_authentication
    def list_resource_profile(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List resource profiles.
        Resource profile configure miscellaneous aspects of the email user accounts, such as disk space quota.
        If an name is given, return the information about the wanted resource profile.
        Mainly used in the configuration of IP policy.

        Args:
            name (str, optional): The name of the resource profile. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""
        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/ProfMisc{url_suffix}",
        )

    @validate_authentication
    def list_pki_user(
        self,
        name: str = None,
    ) -> Dict[str, Any]:
        """
        List PKI users.
        PKI users can authenticate by presenting a valid client certificate,
        rather than by entering a username and password.
        If an name is given, return the information about the wanted PKI user.
        Mainly used in the configuration of recipient policy.

        Args:
            name (str, optional): The name of the PKI user. Defaults to None.

        Returns:
            Dict[str, Any]: The API response.
        """
        url_suffix = f"/{name}" if name else ""

        return self._http_request(
            method="GET",
            url_suffix=f"api/v1/UserPki{url_suffix}",
        )


# COMMANDS FUNCTIONS #


def add_system_safe_block_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add an email address/ domain name/ IP address to the system white/ block list.

    Args:
        client (Client): Session to FortiMail to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in war room.
    """
    list_type = args.get("list_type", "")
    list_items = args.get("values")

    response = client.add_system_safe_block(list_type, list_items)
    items = argToList(list_items)

    return CommandResults(
        readable_output=f"Items: {items} Were Added Successfully to System {list_type.removesuffix('list')} List",
        raw_response=response,
    )


def ip_policy_create_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create or update IP policy.

    Args:
        client (Client): Session to FortiMail to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in war room.
    """
    command_name: str = args.get("command_name", "")
    command_entity_title, _ = get_command_entity(command_name=command_name)
    # Get the client request function by command name.
    command_request: Callable = get_command_request(command_name=command_name, client=client)

    command_args = handle_ip_policy_command_args(args=args)

    response = command_request(**command_args)
    response = map_api_response_values_to_readable_string(response)
    output_table, _ = prepare_outputs_and_readable_output(output=response, command_args=command_args)

    readable_output = tableToMarkdown(
        name=command_entity_title,
        t=remove_empty_elements(output_table),
        removeNull=True,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiMail.IPPolicy",
        outputs_key_field="mkey",
        outputs=response,
        raw_response=response,
    )


def access_control_create_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create or update access control.

    Args:
        client (Client): Session to FortiMail to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in war room.
    """
    command_name: str = args.get("command_name", "")
    command_entity_title, _ = get_command_entity(command_name=command_name)
    # Get the client request function by command name.
    command_request: Callable = get_command_request(command_name=command_name, client=client)

    command_args = handle_access_control_command_args(args=args)

    response = command_request(**command_args)
    response = map_api_response_values_to_readable_string(response)
    output_table, _ = prepare_outputs_and_readable_output(output=response, command_args=command_args)

    readable_output = tableToMarkdown(
        name=command_entity_title,
        t=remove_empty_elements(output_table),
        removeNull=True,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiMail.AccessControl",
        outputs_key_field="mkey",
        outputs=response,
        raw_response=response,
    )


def recipient_policy_create_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create or update recipient policy.

    Args:
        client (Client): Session to FortiMail to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in war room.
    """
    command_name: str = args.get("command_name", "")
    command_entity_title, _ = get_command_entity(command_name=command_name)
    # Get the client request function by command name.
    command_request: Callable = get_command_request(command_name=command_name, client=client)

    command_args = handle_recipient_policy_command_args(args=args)

    response = command_request(**command_args)
    response = map_api_response_values_to_readable_string(response)
    output_table, _ = prepare_outputs_and_readable_output(output=response, command_args=command_args)

    readable_output = tableToMarkdown(
        name=command_entity_title,
        t=remove_empty_elements(output_table),
        removeNull=True,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="FortiMail.RecipientPolicy",
        outputs_key_field="mkey",
        outputs=response,
        raw_response=response,
    )


def move_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Move a recipient policy/ access control/ IP policy location in the policy list.
    FortiMail units match the policies in sequence, from the top of the list downwards.
    Therefore, you must put the more specific policies on top of the more generic ones.

    Args:
        client (Client): Session to FortiMail to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in war room.
    """
    command_name: str = args.get("command_name", "")
    command_entity_title, _ = get_command_entity(command_name=command_name)
    # Get the client request function by command name.
    command_request: Callable = get_command_request(command_name=command_name, client=client)

    command_args = remove_empty_elements(
        {
            "access_control_id": args.get("access_control_id"),
            "policy_id": args.get("policy_id"),
            "recipient_policy_id": args.get("recipient_policy_id"),
            "action": args.get("action"),
            "reference_id": args.get("reference_id"),
        }
    )

    command_request(**command_args)

    return CommandResults(
        readable_output=command_entity_title,
    )


def list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Return the items list according the command entity name.

    Args:
        client (Client): Session to FortiMail to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in war room.
    """
    command_name: str = args.get("command_name", "")
    command_entity_title, command_outputs_prefix = get_command_entity(command_name=command_name)

    # Get the client request function by command name.
    command_request: Callable = get_command_request(command_name=command_name, client=client)

    # Get the relevant item key to fetch in case user use the command as GET.
    # Those arguments cover 22 list commands.
    command_args = handle_list_command_args(args=args)

    response = command_request(**command_args)
    # Map the response fields values from integer to string to be informative.
    output = map_api_response_values_to_readable_string(response)

    if not argToBoolean(args.get("all_results")):
        output = output[: arg_to_number(args.get("limit"))]

    output_table, output = prepare_outputs_and_readable_output(output=output, command_args=command_args)

    if not command_args:
        # Case list and not a get command.
        command_entity_title = f"{command_entity_title} list"

    readable_output = tableToMarkdown(
        name=command_entity_title,
        t=remove_empty_elements(output_table),
        # Add ordered headers keys by the updated outputs.
        headers=list(output_table[0]) if output_table else [],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"FortiMail.{command_outputs_prefix}",
        # Handle output_key_field for system safe block list command that has a different response structure.
        outputs_key_field="item" if command_args.get("list_type") else "mkey",
        outputs=output,
        raw_response=response,
    )


def group_create_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create or update IP/Email group, according the command entity name and operator.

    Args:
        client (Client): Session to FortiMail to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in war room.
    """
    command_name: str = args.get("command_name", "")
    command_entity_title, command_outputs_prefix = get_command_entity(command_name=command_name)

    command_args = remove_empty_elements(
        {
            "name": args.get("name"),
            "comment": args.get("comment"),
        }
    )
    # Get the client request function by command name.
    command_request: Callable = get_command_request(command_name=command_name, client=client)
    response = command_request(**command_args)
    # Get updated output for created/updated group
    output = {key: response[key] for key in ["mkey", "comment"] if key in response}

    readable_output = tableToMarkdown(
        name=command_entity_title,
        t=output,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"FortiMail.{command_outputs_prefix}",
        outputs_key_field="mkey",
        outputs=output,
        raw_response=response,
    )


def delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete, according the command entity name, one of the following:
    IP group, Email group, IP group member, Email group member,
    System list items, IP policy, Access control, Recipient policy.

    Args:
        client (Client): Session to FortiMail to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in war room.
    """
    command_name: str = args.get("command_name", "")
    command_entity_title, _ = get_command_entity(command_name=command_name)
    # Get the 'delete' request function by command name.
    delete_request: Callable = get_command_request(command_name=command_name, client=client)
    # Get the relevant item key to remove
    command_args = handle_delete_command_args(args=args)

    validate_value_exist_before_delete(client=client, command_args=command_args, command_name=command_name)

    delete_request(**command_args)

    return CommandResults(readable_output=command_entity_title)


def group_member_add_replace_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add or replace, IP/email group member, according the command entity name and operator.

    Args:
        client (Client): Session to FortiMail to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in war room.
    """
    is_valid_email(args.get("email", args.get("emails")))
    command_name: str = args.get("command_name", "")
    command_entity_title, _ = get_command_entity(command_name=command_name)
    # Get the client request function by command name.
    command_request: Callable = get_command_request(command_name=command_name, client=client)
    command_args = remove_empty_elements(
        {
            "group_name": args.get("group_name"),
            "ip": args.get("ip"),
            "email": args.get("email"),
            "ips": argToList(args.get("ips")),
            "emails": argToList(args.get("emails")),
        }
    )

    updated_args = update_group_member_args(command_args=command_args)
    command_request(**updated_args)

    return CommandResults(readable_output=command_entity_title)


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Session to Fortimail to run API requests.

    Raises:
        DemistoException: Incase there is an unknown error.

    Returns:
        str: : 'ok' if test passed, or an error message if were too many login attempts
            or credentials are incorrect.
    """

    client.list_pki_user()
    return "ok"


# Helper Functions #


def is_valid_email(emails: List[str] | str | None):
    """
    Validate email addresses.

    Args:
        emails (List[str] | str): Emails to validate.

    Raises:
        DemistoException: Exception if email is invalid.
    """
    if not emails:
        return

    emails = emails if isinstance(emails, list) else [emails]
    for email in emails:
        if not re.match(emailRegex, email):
            raise DemistoException(f"{email} is not a valid email address.")


def map_api_response_values_to_readable_string(response: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Update the response integer values to readable strings by existing mappers.
    The mapper used to map input arguments from string to integer for the API call
    and the reversed map used to map the response data to human readable.

    Args:
        response (dict[str, Any]): The API response.

    Returns:
        dict[str, Any]: The updated response.
    """
    updated_response = response.get("collection", [response])
    # Remove irrelevant keys from response
    object_id = response.pop("objectID", None)
    response.pop("reqAction", None)
    response.pop("nodePermission", None)

    if object_id:
        boolean_mapper = reverse_dict(BOOLEAN_MAPPER)

        if "MailSetAccessRule" in object_id:
            updated_response = map_access_control_response(
                updated_response=updated_response,
                boolean_mapper=boolean_mapper,
            )

        elif "PolicyRcpt" in object_id:
            updated_response = map_recipient_policy_response(
                updated_response=updated_response,
                boolean_mapper=boolean_mapper,
            )

        elif "PolicyIp" in object_id:
            updated_response = map_ip_policy_response(
                updated_response=updated_response,
                boolean_mapper=boolean_mapper,
            )

    return remove_empty_elements(updated_response)


def map_access_control_response(
    updated_response: list[dict[str, Any]],
    boolean_mapper: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Map access control response values to readable string.

    Args:
        updated_response (list[dict[str, Any]]): The API response.
        boolean_mapper (dict[str, Any]): Boolean mapper for enable and disable values.

    Returns:
        list[dict[str, Any]]: The updated response.
    """
    pattern_type_mapper = reverse_dict(AC_PATTERN_TYPE_MAPPER)
    auth_mapper = reverse_dict(AC_AUTH_MAPPER)
    sender_ip_type_mapper = reverse_dict(AC_SENDER_IP_TYPE_MAPPER)
    action_mapper = reverse_dict(AC_ACTION_MAPPER)

    for item in updated_response:
        item["sender_pattern_type"] = pattern_type_mapper.get(item.get("sender_pattern_type", ""))
        item["recipient_pattern_type"] = pattern_type_mapper.get(item.get("recipient_pattern_type", ""))
        item["sender_ip_type"] = sender_ip_type_mapper.get(item.get("sender_ip_type", ""))
        item["authenticated"] = auth_mapper.get(item.get("authenticated", ""))
        item["action"] = action_mapper.get(item.get("action", ""))
        item["status"] = boolean_mapper.get(item.get("status", ""))

    return updated_response


def map_recipient_policy_response(
    updated_response: list[dict[str, Any]],
    boolean_mapper: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Map recipient policy response values to readable string.

    Args:
        updated_response (list[dict[str, Any]]): The API response.
        boolean_mapper (dict[str, Any]): Boolean mapper for enable and disable values.

    Returns:
        list[dict[str, Any]]: The updated response.
    """
    direction_mapper = reverse_dict(RP_DIRECTION_MAPPER)
    auth_mapper = reverse_dict(RP_AUTH_MAPPER)
    pattern_type = reverse_dict(RP_PATTERN_TYPE_MAPPER)

    for item in updated_response:
        item["direction"] = direction_mapper.get(item.get("direction", ""))
        item["auth"] = auth_mapper.get(item.get("auth", ""))
        item["sender_type"] = pattern_type.get(item.get("sender_type", ""))
        item["status"] = boolean_mapper.get(item.get("status", ""))
        item["use_smtp_auth"] = boolean_mapper.get(item.get("use_smtp_auth", ""))
        item["smtp_different"] = boolean_mapper.get(item.get("smtp_different", ""))
        item["smtp_diff_identity_ldap"] = boolean_mapper.get(item.get("smtp_diff_identity_ldap", ""))
        item["pkiauth"] = boolean_mapper.get(item.get("pkiauth", ""))

    return updated_response


def map_ip_policy_response(
    updated_response: list[dict[str, Any]],
    boolean_mapper: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Map IP policy response values to readable string.

    Args:
        updated_response (list[dict[str, Any]]): The API response.
        boolean_mapper (dict[str, Any]): Boolean mapper for enable and disable values.

    Returns:
        list[dict[str, Any]]: The updated response.
    """
    destination_mapper = reverse_dict(DESTINATION_MAPPER)
    auth_mapper = reverse_dict(RP_AUTH_MAPPER)
    ip_action_mapper = reverse_dict(IP_ACTION_MAPPER)
    source_ip_type_mapper = reverse_dict(AC_SENDER_IP_TYPE_MAPPER)

    for item in updated_response:
        item["client_type"] = source_ip_type_mapper.get(item.get("client_type", ""))
        item["server_type"] = destination_mapper.get(item.get("server_type", ""))
        item["action"] = ip_action_mapper.get(item.get("action", ""))
        item["auth_type"] = auth_mapper.get(item.get("auth_type", ""))
        item["status"] = boolean_mapper.get(item.get("status", ""))
        item["exclusive"] = boolean_mapper.get(item.get("exclusive", ""))
        item["use_smtp_auth"] = boolean_mapper.get(item.get("use_smtp_auth", ""))
        item["smtp_different"] = boolean_mapper.get(item.get("smtp_different", ""))
        item["smtp_diff_identity_ldap"] = boolean_mapper.get(item.get("smtp_diff_identity_ldap", ""))

    return updated_response


def reverse_dict(original_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Reverse the keys and values of a given dictionary.

    Args:
        original_dict (dict[str, Any]): The dictionary to be reversed.

    Returns:
        dict[str, Any]: A new dictionary with keys and values swapped.
    """
    return {value: key for key, value in original_dict.items()}


def convert_cidr_to_ip_range(item: str) -> str:
    """
    Convert CIDR to IP range.

    Args:
        item (str): optional CIDR.

    Returns:
        str: IP range.
    """
    if "-" in item:
        return item

    ip_data = item.split("/")
    return f"{ip_data[0]}-{ip_data[0]}"


def prepare_outputs_for_system_list(
    list_items: list[str],
    command_args: Dict[str, Any],
) -> Tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Update the system list API response keys names according to Fortimail UI, for the readable output.

    Args:
        list_items (list[str]): The system list items.
        command_args (Dict[str, Any]): The list command arguments.

    Returns:
        Tuple[list[dict[str, Any]], list[dict[str, Any]]]: New readable output and Updated response.
    """
    values = argToList(list_items)
    output_table = [{"item": value, "list_type": command_args.get("list_type")} for value in values]
    return output_table, output_table


def prepare_outputs_and_readable_output(
    output: list[dict[str, Any]],
    command_args: Dict[str, Any],
) -> Tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Update the API response keys names according to Fortimail UI, for the readable output.

    Args:
        output (list[dict[str, Any]]): The API response.
        command_args (Dict[str, Any]): The list command arguments.

    Returns:
        Tuple[list[dict[str, Any]], list[dict[str, Any]]]: New readable output and Updated response.
    """
    output_table = []

    for item in output:
        if list_items := item.get("listitems"):
            return prepare_outputs_for_system_list(list_items=list_items, command_args=command_args)
        # Build an ordered output table, response field value by header.
        # Map API response common fields (common for all commands).
        output_table.append(
            {
                "Name": item.get("mkey"),
                "Comment": item.get("comment"),
                "TLS level": item.get("level"),
                "Action On Failure": item.get("action"),
                "IP Group": item.get("ip_range"),
                "Server": item.get("server"),
                "Server Type": item.get("server_type"),
                "Client": item.get("client"),
                "Client Type": item.get("client_type"),
                "Auth Type": item.get("auth_type"),
                "Port": item.get("port"),
                "Status": item.get("status"),
                "Action": item.get("action"),
                "Authenticated": item.get("authenticated"),
                "Sender Type": item.get("sender_type"),
                "Sender Pattern": item.get("sender_pattern"),
                "Sender Pattern Type": item.get("sender_pattern_type"),
                "Sender Ip Type": item.get("sender_ip_type"),
                "Sender Ip Group": item.get("sender_ip_group"),
                "Sender Ip Mask": item.get("sender_ip_mask"),
                "Sender Geo IP Group": item.get("sender_geoip_group"),
                "Recipient Pattern Type": item.get("recipient_pattern_type"),
                "Recipient Pattern Regex": item.get("recipient_pattern_regex") or item.get("recipient_pattern_regexp"),
                "Anti Spam": item.get("antispam"),
                "Content": item.get("content"),
                "PKI Auth": item.get("pkiauth"),
                "Direction": item.get("direction"),
                "Antivirus": item.get("antivirus"),
                "Resource Profile": item.get("misc"),
                "Group State": item.get("groupstate"),
                "Auth State": item.get("authstate"),
                "Alias State": item.get("alias_state"),
                "Routing State": item.get("routing_state"),
                "Address Map State": item.get("address_map_state"),
                "Cache State": item.get("cache_state"),
                "Country": item.get("country"),
                "Domain Name": item.get("domain"),
                "CA Certificate": item.get("ca_certificate"),
                "Subject": item.get("subject"),
                "LDAP Profile": item.get("ldapprofile"),
                "LDAP Query": item.get("ldapquery"),
                "OCSP verify": item.get("ocspverify"),
                "OCSP URL": item.get("ocspurl"),
                "SMTP Certificate": item.get("smtp_certificate"),
                "SMTP Certificate Direction": item.get("smtp_certificate_direction"),
                "SMTP Greeting Name": item.get("smtp_greeting_reply_name"),
                "Auth Port": item.get("authport"),
                "Access Override Vendor": item.get("access_override_vendor"),
                "Domain Override Vendor": item.get("domain_override_vendor"),
                "Group Name": item.get("group_name"),
            }
        )
    # Add the group name argument to the output for group commands
    if group_name := command_args.get("group_name"):
        new_output = {"mkey": group_name, "Member": output}
        return output_table, [new_output]

    return output_table, output


def handle_recipient_policy_command_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Get and convert recipient policy command arguments.

    Args:
        args (dict[str, Any]): The command arguments.

    Returns:
        dict[str, Any]: Updated command arguments.
    """
    return remove_empty_elements(
        {
            "recipient_policy_id": args.get("recipient_policy_id"),
            "status": BOOLEAN_MAPPER.get(args.get("status", "")),
            "comment": args.get("comment"),
            "direction": RP_DIRECTION_MAPPER.get(args.get("type", "")),
            "sender_type": RP_PATTERN_TYPE_MAPPER.get(args.get("sender_type", "")),
            "sender_pattern": args.get("sender_pattern"),
            "sender_ldap_profile": args.get("sender_ldap_profile"),
            "sender_email_address_group": args.get("sender_email_address_group"),
            "recipient_email_address_group": args.get("recipient_email_address_group"),
            "recipient_type": RP_PATTERN_TYPE_MAPPER.get(args.get("recipient_type", "")),
            "recipient_pattern": args.get("recipient_pattern"),
            "recipient_ldap_profile": args.get("recipient_ldap_profile"),
            "antispam_profile": args.get("antispam_profile"),
            "antivirus_profile": args.get("antivirus_profile"),
            "content_profile": args.get("content_profile"),
            "resource_profile": args.get("resource_profile"),
            "auth_profile": args.get("auth_profile"),
            "pki_profile": args.get("pki_profile"),
            "auth_type": RP_AUTH_MAPPER.get(args.get("auth_type", "")),
            "use_smtp_auth": BOOLEAN_MAPPER.get(args.get("use_smtp_auth", "")),
            "smtp_different": BOOLEAN_MAPPER.get(args.get("smtp_different", "")),
            "smtp_diff_identity_ldap": BOOLEAN_MAPPER.get(args.get("smtp_diff_identity_ldap", "")),
            "smtp_diff_identity_ldap_profile": args.get("smtp_diff_identity_ldap_profile"),
            "enable_pki": BOOLEAN_MAPPER.get(args.get("enable_pki", "")),
            "certificate_validation": BOOLEAN_MAPPER.get(args.get("certificate_validation", "")),
        }
    )


def handle_ip_policy_command_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Get and convert IP policy command arguments.

    Args:
        args (dict[str, Any]): The command arguments.

    Returns:
        dict[str, Any]: Updated command arguments.
    """
    return remove_empty_elements(
        {
            "ip_policy_id": args.get("ip_policy_id"),
            "status": BOOLEAN_MAPPER.get(args.get("status", "")),
            "comment": args.get("comment"),
            "source": args.get("source"),
            "destination_type": DESTINATION_MAPPER.get(args.get("destination_type", "")),
            "destination": args.get("destination", ""),
            "action": IP_ACTION_MAPPER.get(args.get("action", "")),
            "source_type": AC_SENDER_IP_TYPE_MAPPER.get(args.get("source_type", "")),
            "ip_pool_profile": args.get("ip_pool_profile"),
            "antispam_profile": args.get("antispam_profile"),
            "antivirus_profile": args.get("antivirus_profile"),
            "content_profile": args.get("content_profile"),
            "session_profile": args.get("session_profile"),
            "auth_profile": args.get("auth_profile"),
            "auth_type": RP_AUTH_MAPPER.get(args.get("auth_type", "")),
            "use_smtp_auth": BOOLEAN_MAPPER.get(args.get("use_smtp_auth", "")),
            "smtp_different": BOOLEAN_MAPPER.get(args.get("smtp_different", "")),
            "smtp_diff_identity_ldap": BOOLEAN_MAPPER.get(args.get("smtp_diff_identity_ldap", "")),
            "smtp_diff_identity_ldap_profile": args.get("smtp_diff_identity_ldap_profile"),
            "exclusive": BOOLEAN_MAPPER.get(args.get("exclusive", "")),
        }
    )


def handle_access_control_command_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Get and convert access control command arguments.

    Args:
        args (dict[str, Any]): The command arguments.

    Returns:
        dict[str, Any]: Updated command arguments.
    """
    return remove_empty_elements(
        {
            "access_control_id": args.get("access_control_id"),
            "status": BOOLEAN_MAPPER.get(args.get("status", "")),
            "sender_type": AC_PATTERN_TYPE_MAPPER.get(args.get("sender_type", "")),
            "sender": args.get("sender"),
            "recipient_type": AC_PATTERN_TYPE_MAPPER.get(args.get("recipient_type", "")),
            "recipient": args.get("recipient"),
            "sender_ldap_profile": args.get("sender_ldap_profile"),
            "recipient_ldap_profile": args.get("recipient_ldap_profile"),
            "source_type": AC_SENDER_IP_TYPE_MAPPER.get(args.get("source_type", "")),
            "source": args.get("source"),
            "reverse_dns_pattern": args.get("reverse_dns_pattern"),
            "reverse_dns_pattern_regex": BOOLEAN_MAPPER.get(args.get("reverse_dns_pattern_regex", "")),
            "authentication_status": AC_AUTH_MAPPER.get(args.get("authentication_status", "")),
            "tls_profile": args.get("tls_profile"),
            "action": AC_ACTION_MAPPER.get(args.get("action", "")),
            "comment": args.get("comment"),
        }
    )


def handle_delete_command_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Get and convert delete command arguments.

    Args:
        args (dict[str, Any]): The command arguments.

    Returns:
        dict[str, Any]: Updated command arguments.
    """
    return remove_empty_elements(
        {
            "name": args.get("name"),
            "group_name": args.get("group_name"),
            "ip": args.get("ip"),
            "email": args.get("email"),
            "values": args.get("values"),
            "list_type": args.get("list_type"),
            "access_control_id": args.get("access_control_id"),
            "policy_id": args.get("policy_id"),
            "recipient_policy_id": args.get("recipient_policy_id"),
        }
    )


def handle_list_command_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Get and convert list command arguments.

    Args:
        args (dict[str, Any]): The command arguments.

    Returns:
        dict[str, Any]: Updated command arguments.
    """
    return remove_empty_elements(
        {
            "group_name": args.get("group_name"),
            "ip": args.get("ip"),
            "access_control_id": args.get("access_control_id"),
            "policy_id": args.get("policy_id"),
            "recipient_policy_id": args.get("recipient_policy_id"),
            "email": args.get("email"),
            "name": args.get("name"),
            "list_type": args.get("list_type"),
        }
    )


def modify_group_member_args_before_replace(group_members: list[str]) -> dict[str, Any]:
    """
    Get the IP/email group members and modify it for the API.

    Args:
        group_members (list[str]): The IP/email group members.

    Returns:
        dict[str, Any]: The updated payload for the API request.
    """
    updated_group_members_payload: dict[str, Any] = {f"mkey_{i}": group_member for i, group_member in enumerate(group_members)}
    # Get the total amount of items to replaces for the API call.
    updated_group_members_payload["reqObjCount"] = len(updated_group_members_payload)
    return updated_group_members_payload


def update_group_member_args(command_args: dict[str, Any]) -> dict[str, Any]:
    """
    Update the IP/email group members arguments.
    Convert CIDR to IP in case IP is provided.

    Args:
        command_args (dict[str, Any]): The command arguments.

    Returns:
        dict[str, Any]: The updated request arguments.
    """
    group_member_args = copy.deepcopy(command_args)

    if ips := group_member_args.get("ips"):
        updated_ips = [convert_cidr_to_ip_range(item) for item in ips]
        group_member_args["ips"] = modify_group_member_args_before_replace(group_members=updated_ips)

    if emails := group_member_args.get("emails"):
        group_member_args["emails"] = modify_group_member_args_before_replace(group_members=emails)

    if ip := group_member_args.get("ip"):
        group_member_args["ip"] = convert_cidr_to_ip_range(ip)
    return group_member_args


def validate_value_exist_before_delete(client: Client, command_args: dict[str, Any], command_name: str):
    """
    Validate item exist before delete it.

    Args:
        client (Client): API client.
        command_args (dict[str, Any]): The command args.
        command_name (str): The command name.

    Raises:
        ValueError: In case the item doesn't exist.
    """
    # Get the 'get' request function by command name.
    get_request: Callable = get_command_request(command_name=command_name.replace("delete", "list"), client=client)
    # Remove the 'values' argument in case exist before calling GET
    values = command_args.pop("values", None)

    # Make a GET request to insure the item is exist before delete
    try:
        get_request(**command_args)
    except DemistoException as exc:
        raise ValueError(f"Item doesn't exist. {exc}")

    # Reset the 'values' argument in case exist
    if values:
        command_args["values"] = values


def get_command_request(command_name: str, client: Client) -> Callable[..., Any]:
    """
    Get request function by command name.

    Args:
        command_name (str): The command name.
        client (Client): API client.

    Returns:
        Callable[..., Any]: The request function.
    """
    request_by_command_name = {
        "fortimail-system-safe-block-add": client.add_system_safe_block,
        "fortimail-ip-policy-create": client.create_ip_policy,
        "fortimail-ip-policy-update": client.update_ip_policy,
        "fortimail-access-control-create": client.create_access_control,
        "fortimail-access-control-update": client.update_access_control,
        "fortimail-recipient-policy-create": client.create_recipient_policy,
        "fortimail-recipient-policy-update": client.update_recipient_policy,
        "fortimail-pki-user-list": client.list_pki_user,
        "fortimail-recipient-policy-list": client.list_recipient_policy,
        "fortimail-tls-profile-list": client.list_tls_profile,
        "fortimail-ldap-group-list": client.list_ldap_group,
        "fortimail-geoip-group-list": client.list_geoip_group,
        "fortimail-antispam-profile-list": client.list_antispam_profile,
        "fortimail-antivirus-profile-list": client.list_antivirus_profile,
        "fortimail-content-profile-list": client.list_content_profile,
        "fortimail-ip-pool-list": client.list_ip_pool,
        "fortimail-session-profile-list": client.list_session_profile,
        "fortimail-access-control-list": client.list_access_control,
        "fortimail-ip-policy-list": client.list_ip_policy,
        "fortimail-email-group-member-list": client.list_email_group_member,
        "fortimail-system-safe-block-list": client.list_system_safe_block,
        "fortimail-ip-group-list": client.list_ip_group,
        "fortimail-ip-group-member-list": client.list_ip_group_member,
        "fortimail-email-group-list": client.list_email_group,
        "fortimail-smtp-auth-profile-list": client.list_smtp_auth_profile,
        "fortimail-resource-profile-list": client.list_resource_profile,
        "fortimail-imap-auth-profile-list": client.list_imap_auth_profile,
        "fortimail-radius-auth-profile-list": client.list_radius_auth_profile,
        "fortimail-pop3-auth-profile-list": client.list_pop3_auth_profile,
        "fortimail-email-group-create": client.create_email_group,
        "fortimail-ip-group-create": client.create_ip_group,
        "fortimail-email-group-update": client.update_email_group,
        "fortimail-ip-group-update": client.update_ip_group,
        "fortimail-ip-group-delete": client.delete_ip_group,
        "fortimail-ip-group-member-delete": client.delete_ip_group_member,
        "fortimail-email-group-delete": client.delete_email_group,
        "fortimail-email-group-member-delete": client.delete_email_group_member,
        "fortimail-system-safe-block-delete": client.delete_system_safe_block,
        "fortimail-ip-policy-delete": client.delete_ip_policy,
        "fortimail-access-control-delete": client.delete_access_control,
        "fortimail-recipient-policy-delete": client.delete_recipient_policy,
        "fortimail-ip-policy-move": client.move_ip_policy,
        "fortimail-access-control-move": client.move_access_control,
        "fortimail-recipient-policy-move": client.move_recipient_policy,
        "fortimail-ip-group-member-add": client.add_ip_group_member,
        "fortimail-ip-group-member-replace": client.replace_ip_group_member,
        "fortimail-email-group-member-add": client.add_email_group_member,
        "fortimail-email-group-member-replace": client.replace_email_group_member,
    }
    return request_by_command_name[command_name]


def get_command_entity(command_name: str) -> tuple[str, str]:
    """
    Return the command request name, title, and output prefix name by command name.

    Args:
        command_name (str): The command name.
    Returns:
        tuple[str, str, str]: The command request name, title, and output prefix.
    """
    command_name_parts = command_name.split("-")
    command_operator = command_name_parts[-1]
    command_entity = "_".join(command_name_parts[1:-1])
    command_entity_title = command_entity.replace("_", " ").title()
    command_outputs_prefix = OUTPUT_PREFIX_MAPPER[command_entity]

    if command_operator == "add":
        command_entity_title = f"{command_entity_title} {command_operator}ed successfully"
    elif command_operator != "list":
        command_entity_title = f"{command_entity_title} {command_operator}d successfully"

    return command_entity_title, command_outputs_prefix


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    url: str = params.get("url", "")
    user_name = params["credentials"]["identifier"]
    password = params["credentials"]["password"]
    verify_certificate: bool = not params.get("insecure", False)
    proxy: bool = params.get("proxy", False)

    command = demisto.command()
    args["command_name"] = command
    demisto.debug(f"Command being called is {command}")

    try:
        client: Client = Client(
            server_url=url,
            user_name=user_name,
            password=password,
            verify=verify_certificate,
            proxy=proxy,
        )

        commands = {
            "fortimail-system-safe-block-add": add_system_safe_block_command,
            "fortimail-ip-policy-create": ip_policy_create_update_command,
            "fortimail-ip-policy-update": ip_policy_create_update_command,
            "fortimail-access-control-create": access_control_create_update_command,
            "fortimail-access-control-update": access_control_create_update_command,
            "fortimail-recipient-policy-create": recipient_policy_create_update_command,
            "fortimail-recipient-policy-update": recipient_policy_create_update_command,
        }

        if command == "test-module":
            return_results(test_module(client))
        elif command in [
            "fortimail-pki-user-list",
            "fortimail-recipient-policy-list",
            "fortimail-tls-profile-list",
            "fortimail-ldap-group-list",
            "fortimail-geoip-group-list",
            "fortimail-antispam-profile-list",
            "fortimail-antivirus-profile-list",
            "fortimail-content-profile-list",
            "fortimail-ip-pool-list",
            "fortimail-session-profile-list",
            "fortimail-access-control-list",
            "fortimail-ip-policy-list",
            "fortimail-email-group-member-list",
            "fortimail-system-safe-block-list",
            "fortimail-ip-group-list",
            "fortimail-ip-group-member-list",
            "fortimail-email-group-list",
            "fortimail-smtp-auth-profile-list",
            "fortimail-resource-profile-list",
            "fortimail-imap-auth-profile-list",
            "fortimail-radius-auth-profile-list",
            "fortimail-pop3-auth-profile-list",
        ]:
            return_results(list_command(client, args))
        elif command in [
            "fortimail-email-group-create",
            "fortimail-ip-group-create",
            "fortimail-email-group-update",
            "fortimail-ip-group-update",
        ]:
            return_results(group_create_update_command(client, args))
        elif command in [
            "fortimail-ip-group-delete",
            "fortimail-ip-group-member-delete",
            "fortimail-email-group-delete",
            "fortimail-email-group-member-delete",
            "fortimail-system-safe-block-delete",
            "fortimail-ip-policy-delete",
            "fortimail-access-control-delete",
            "fortimail-recipient-policy-delete",
        ]:
            return_results(delete_command(client, args))
        elif command in [
            "fortimail-ip-policy-move",
            "fortimail-access-control-move",
            "fortimail-recipient-policy-move",
        ]:
            return_results(move_command(client, args))
        elif command in [
            "fortimail-ip-group-member-add",
            "fortimail-ip-group-member-replace",
            "fortimail-email-group-member-add",
            "fortimail-email-group-member-replace",
        ]:
            return_results(group_member_add_replace_command(client, args))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
