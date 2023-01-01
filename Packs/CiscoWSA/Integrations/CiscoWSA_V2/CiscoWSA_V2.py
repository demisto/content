import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


JWT_TOKEN_EXPIRATION_PERIOD = 30
V2_PREFIX = "v2.0"
V3_PREFIX = "v3.0"


class Client(BaseClient):
    """Client class to interact with Cisco WSA API."""

    def __init__(
        self, server_url: str, username: str, password: str, verify: bool, proxy: bool
    ):
        super().__init__(base_url=server_url, headers={}, verify=verify, proxy=proxy)
        self.username = username
        self.password = password
        self.handle_request_headers()

    def handle_request_headers(self):
        """Retrieve and save to integration context JWT token for authorized client class API requests."""
        integration_context = get_integration_context()
        jwt_token = integration_context.get("jwt_token")
        jwt_token_issued_time = integration_context.get("jwt_token_issued_time")
        if jwt_token and jwt_token_issued_time >= datetime.timestamp(
            datetime.now() - timedelta(minutes=JWT_TOKEN_EXPIRATION_PERIOD)
        ):
            self._headers["jwtToken"] = jwt_token
        else:
            jwt_token = self.retrieve_jwt_token()
            set_integration_context(
                {"jwt_token": jwt_token, "jwt_token_issued_time": time.time()}
            )
            self._headers["jwtToken"] = jwt_token

    def retrieve_jwt_token(self) -> str:
        """
        Retrieve JWT token from Cisco WSA.

        Returns:
            str: JWT token from Cisco WSA.
        """
        data = {
            "data": {
                "userName": b64_encode(self.username),
                "passphrase": b64_encode(self.password),
            }
        }
        try:
            response = self._http_request("POST", f"{V2_PREFIX}/login", json_data=data)
            return dict_safe_get(response, ["data", "jwtToken"])

        except DemistoException as e:
            if e.res.status_code == 401:
                raise Exception(
                    "Authorization Error: make sure username and password are set correctly."
                )
            raise e

    def access_policy_list_request(self, policy_names: str = None) -> Dict[str, Any]:
        """
        Access Policies list.

        Args:
            policy_names (str, optional): Policies names to retrieve. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco WSA.
        """
        params = assign_params(policy_names=policy_names)

        return self._http_request(
            "GET", f"{V3_PREFIX}/web_security/access_policies", params=params
        )

    # def access_policy_create_request(
    #     self,
    #     policy_status,
    #     policy_name,
    #     policy_order,
    #     profile_name,
    #     auth,
    #     predefined,
    #     custom,
    #     is_inverse,
    #     state,
    #     allow_connect_ports,
    #     block_protocols,
    #     block_custom_user_agents,
    # ):

    #     data = {
    #         "access_policies": [
    #             {
    #                 "membership": {
    #                     "identification_profiles": [
    #                         {"auth": auth, "profile_name": profile_name}
    #                     ],
    #                     "user_agents": {
    #                         "custom": custom,
    #                         "is_inverse": is_inverse,
    #                         "predefined": predefined,
    #                     },
    #                 },
    #                 "policy_name": policy_name,
    #                 "policy_order": policy_order,
    #                 "policy_status": policy_status,
    #                 "protocols_user_agents": {
    #                     "allow_connect_ports": allow_connect_ports,
    #                     "block_custom_user_agents": block_custom_user_agents,
    #                     "block_protocols": block_protocols,
    #                     "state": state,
    #                 },
    #             }
    #         ]
    #     }

    #     return self._http_request(
    #         "POST", f"{V3_PREFIX}/web_security/access_policies", json_data=data
    #     )

    def access_policy_update_request(self, policy_status, policy_name):
        data = {
            "access_policies": [
                {"policy_name": policy_name, "policy_status": policy_status}
            ]
        }

        return self._http_request(
            "PUT",
            f"{V3_PREFIX}/web_security/access_policies",
            json_data=data,
            resp_type="response",
        )

    def access_policy_delete_request(self, policy_names: str):
        """
        Delete access policy.

        Args:
            policy_names (str): Comma separated policy names to delete.

        Returns:
            Response: API response from Cisco WSA.
        """
        params = assign_params(policy_names=policy_names)

        return self._http_request(
            "DELETE",
            f"{V3_PREFIX}/web_security/access_policies",
            params=params,
            resp_type="response",
        )

    def domain_map_list_request(self) -> Dict[str, Any]:
        """
        List domain mappings.

        Returns:
            Dict[str, Any]: API response from Cisco WSA.
        """
        return self._http_request(
            "GET", f"{V2_PREFIX}/configure/web_security/domain_map"
        )

    def domain_map_create_request(self, domain_name, order, ip_addresses):
        data = [
            {"IP_addresses": ip_addresses, "domain_name": domain_name, "order": order}
        ]

        return self._http_request(
            "POST", f"{V2_PREFIX}/configure/web_security/domain_map", json_data=data
        )

    def domain_map_update_request(
        self, new_domain_name, domain_name, order, ip_addresses
    ):
        data = [
            {
                "IP_addresses": ip_addresses,
                "domain_name": domain_name,
                "new_domain_name": new_domain_name,
                "order": order,
            }
        ]

        return self._http_request(
            "PUT", f"{V2_PREFIX}/configure/web_security/domain_map", json_data=data
        )

    def domain_map_delete_request(self, domain_name):
        data = {"domain_name": domain_name}

        return self._http_request(
            "DELETE",
            f"{V2_PREFIX}/configure/web_security/domain_map",
            json_data=data,
        )

    def identification_profiles_list_request(
        self, profile_names: str
        ) -> Dict[str, Any]:
        """
        Get identification profiles.

        Returns:
            Dict[str, Any]: API response from Cisco WSA.
        """
        return self._http_request(
            "GET", f"{V3_PREFIX}/web_security/identification_profiles"
        )

    def identification_profiles_create_request(
        self,
        profile_name: str = None,
        status: str = None,
        description: str = None,
        protocols: str = None,
        order: int = None,
    ) -> Response:
        """
        Create identification profile.

        Args:
            profile_name (str): Identification profile name.
            status (str): Status - enable/disable.
            description (str): Description of identification profile.
            protocols (str): Protocols - HTTPS/SOCKS.
            order (int): Index of Identification profile in the collection.

        Returns:
            Response: API response from Cisco WSA.
        """

        data = {
            "identification_profiles": [
                {
                    "description": description,
                    "members": {
                        "protocols": ["socks"]
                        if protocols == "SOCKS"
                        else ["http", "https", "ftp"]
                    },
                    "order": order,
                    "profile_name": profile_name,
                    "status": status,
                }
            ]
        }

        return self._http_request(
            "POST",
            f"{V3_PREFIX}/web_security/identification_profiles",
            json_data=data,
            resp_type="response",
        )

    def identification_profiles_update_request(
        self,
        profile_name: str,
        new_profile_name: str = None,
        status: str = None,
        description: str = None,
        protocols: str = None,
        order: int = None,
    ) -> Response:
        """
        Update identification profile.

        Args:
            profile_name (str): Identification profile name.
            new_profile_name (str): Identification profile name to update.
            status (str): Status - enable/disable.
            description (str): Description of identification profile.
            protocols (str): Protocols - HTTPS/SOCKS.
            order (int): Index of Identification profile in the collection.

        Returns:
            Response: API response from Cisco WSA.
        """

        data = remove_empty_elements(
            {
                "identification_profiles": [
                    {
                        "profile_name": profile_name,
                        "new_profile_name": new_profile_name,
                        "description": description,
                        "status": status,
                        "identification_method": {},
                        "members": {
                            "protocols": ["socks"]
                            if protocols == "SOCKS"
                            else ["http", "https", "ftp"]
                        },
                        "order": order,
                    }
                ]
            }
        )

        return self._http_request(
            "PUT",
            f"{V3_PREFIX}/web_security/identification_profiles",
            json_data=data,
            resp_type="response",
        )

    def identification_profiles_delete_request(self, profile_names: str):
        """
        Delete identification profiles.

        Args:
            profile_names (str): Identification profile names to delete.

        Returns:
            Response: API response from Cisco WSA.
        """
        params = assign_params(profile_names=",".join(profile_names))

        return self._http_request(
            "DELETE",
            f"{V3_PREFIX}/web_security/identification_profiles",
            params=params,
        )

    def url_categories_list_request(self) -> Dict[str, Any]:
        """
        List URL categories.

        Returns:
            Dict[str, Any]: API response from Cisco WSA.
        """
        return self._http_request(
            "GET", f"{V3_PREFIX}/generic_resources/url_categories"
        )


def pagination(response: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
    page = args.get("page")
    page_size = args.get("page_size")
    limit = args.get("limit")

    if page and page_size:
        offset =  (page - 1) * page_size
        return response[offset:offset + page_size]
    elif limit:
        return response[:limit]


def access_policy_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List access policies.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    policy_names = args.get("policy_names")
    response = client.access_policy_list_request(policy_names=policy_names).get(
        "access_policies"
    )

    readable_output = tableToMarkdown(
        name=f"Access Policies",
        t=response,
        headers=["policy_name", "policy_status", "policy_order", "policy_description"],
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CiscoWSA.AccessPolicy",
        outputs_key_field="policy_name",
        outputs=response,
        raw_response=response,
    )


# def access_policy_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
#     policy_status = args.get('policy_status')
#     policy_name = args.get('policy_name')
#     policy_order = args.get('policy_order')
#     profile_name = args.get('profile_name')
#     auth = args.get('auth')
#     predefined = args.get('predefined')
#     custom = args.get('custom')
#     is_inverse = args.get('is_inverse')
#     state = args.get('state')
#     allow_connect_ports = args.get('allow_connect_ports')
#     block_protocols = args.get('block_protocols')
#     block_custom_user_agents = args.get('block_custom_user_agents')

#     response = client.access_policy_create_request(
#         policy_status,
#         policy_name,
#         policy_order,
#         profile_name,
#         auth,
#         predefined,
#         custom,
#         is_inverse,
#         state,
#         allow_connect_ports,
#         block_protocols,
#         block_custom_user_agents
#     )

#     return CommandResults(
#         # readable_output=readable_output,
#     )


def access_policy_update_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Update an access policy.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    policy_status = args.get("policy_status")
    policy_name = args.get("policy_name")

    response = client.access_policy_update_request(policy_status, policy_name)
    if response.status_code == 204:
        readable_output = f"{policy_name} policy updated successfully."
    else:
        raise Exception(response.json())

    return CommandResults(
        readable_output=readable_output,
    )


def access_policy_delete_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Delete access policy.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    policy_names = args["policy_names"]

    response = client.access_policy_delete_request(policy_names)
    if response.status_code == 204:
        readable_output = f"{policy_names} policy deleted successfully."
    else:
        raise Exception(response.json())

    return CommandResults(
        readable_output=readable_output,
    )


def domain_map_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get domain mappings.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    domain_names = args.get("domain_names")

    response = client.domain_map_list_request()
    print(response)

    readable_output = tableToMarkdown(
        name=f"Domain Map",
        t=response,
        headers=["domain_name", "IP_addresses", "order"],
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CiscoWSA.DomainMap",
        outputs_key_field="domain_name",
        outputs=response,
        raw_response=response,
    )


def domain_map_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create domain mappings.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    domain_name = args.get("domain_name")
    order = args.get("order")
    ip_addresses = args.get("ip_addresses")

    response = client.domain_map_create_request(domain_name, order, ip_addresses)

    return CommandResults(
        outputs_prefix="CiscoWSA.DomainMapCreate",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )


def domain_map_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update domain mappings.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    new_domain_name = args.get("new_domain_name")
    domain_name = args.get("domain_name")
    order = args.get("order")
    ip_addresses = args.get("ip_addresses")

    response = client.domain_map_update_request(
        new_domain_name, domain_name, order, ip_addresses
    )
    return CommandResults(
        outputs_prefix="CiscoWSA.DomainMapUpdate",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )


def domain_map_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete domain mappings.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    domain_name = args.get("domain_name")

    response = client.domain_map_delete_request(domain_name)

    return CommandResults(
        outputs_prefix="CiscoWSA.DomainMapDelete",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )


def identification_profiles_list_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Get identification profiles.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    profile_names = args.get("profile_names")

    response = client.identification_profiles_list_request().get(
        "identification_profiles", []
    )

    response = pagination(response, args)
    
    readable_output = tableToMarkdown(
        name=f"Identification Profiles",
        t=response,
        headers=[
            "order",
            "profile_name",
            "status",
            "description",
            "members",
            "identification_method",
        ],
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CiscoWSA.IdentificationProfile",
        outputs_key_field="profile_name",
        outputs=response,
        raw_response=response,
    )


def identification_profiles_create_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Create identification profiles.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    profile_name = args.get("profile_name")
    status = args.get("status")
    description = args.get("description")
    protocols = args.get("protocols")
    order = arg_to_number(args.get("order", 1))

    response = client.identification_profiles_create_request(
        status=status,
        description=description,
        profile_name=profile_name,
        protocols=protocols,
        order=order,
    )

    if response.status_code == 204:
        readable_output = f"Created profile {profile_name} successfully."
    else:
        readable_output = f"ERROR: Created profile {profile_name} successfully."

    return CommandResults(readable_output=readable_output)


def identification_profiles_update_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Update identification profiles.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    # profile_name = args["profile_name"]
    profile_name = args.get("profile_name")
    new_profile_name = args.get("new_profile_name")
    status = args.get("status")
    description = args.get("description")
    protocols = args.get("protocols")
    order = args.get("order")

    response = client.identification_profiles_update_request(
        profile_name=profile_name,
        new_profile_name=new_profile_name,
        description=description,
        status=status,
        protocols=protocols,
        order=order,
    )

    if response.status_code == 204:
        readable_output = f"Updated profile {profile_name} successfully."
    else:
        readable_output = f"ERROR: Updated profile {profile_name} successfully."

    return CommandResults(readable_output=readable_output)


def identification_profiles_delete_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Delete identification profiles.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    profile_names = argToList(args.get("profile_names"))

    response = client.identification_profiles_delete_request(profile_names)

    if response.status_code == 204:
        readable_output = f"Deleted profiles successfully."
    else:
        readable_output = f"ERROR: Deleted profiles successfully."

    return CommandResults(readable_output=readable_output)


def url_categories_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get URL categories.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    response = client.url_categories_list_request()

    readable_output = tableToMarkdown(
        name=f"URL categories",
        t=response,
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        # outputs_prefix="CiscoWSA.UrlCategory",
        # outputs_key_field="profile_name",
        # outputs=response,
        raw_response=response,
    )


def test_module(client: Client) -> str:
    """
    Validates the correctness of the instance parameters and connectivity to Cisco WSA API service.

    Args:
        client (Client): Cisco WSA API client.
    """
    client.url_categories_list_request()
    return "ok"


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    base_url = params.get("base_url")
    username = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")

    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()
    commands = {
        "cisco-wsa-access-policy-list": access_policy_list_command,
        # 'cisco-wsa-access-policy-create': access_policy_create_command,
        "cisco-wsa-access-policy-update": access_policy_update_command,
        "cisco-wsa-access-policy-delete": access_policy_delete_command,
        "cisco-wsa-domain-map-list": domain_map_list_command,
        "cisco-wsa-domain-map-create": domain_map_create_command,
        "cisco-wsa-domain-map-update": domain_map_update_command,
        "cisco-wsa-domain-map-delete": domain_map_delete_command,
        "cisco-wsa-identification-profiles-list": identification_profiles_list_command,
        "cisco-wsa-identification-profiles-create": identification_profiles_create_command,
        "cisco-wsa-identification-profiles-update": identification_profiles_update_command,
        "cisco-wsa-identification-profiles-delete": identification_profiles_delete_command,
        "cisco-wsa-url-categories-list": url_categories_list_command,
    }
    try:
        client: Client = Client(
            urljoin(base_url, "/wsa/api"),
            username,
            password,
            verify_certificate,
            proxy,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
