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

    def access_policy_list_request(
        self, policy_names: Optional[str] = None
    ) -> Dict[str, Any]:
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

    def access_policy_create_request(
        self,
        policy_name: str,
        policy_status: str,
        identification_profile_name: str,
        policy_order: int,
        policy_description: Optional[str] = None,
        policy_expiry: Optional[str] = None,
    ):

        data = remove_empty_elements(
            {
                "access_policies": [
                    {
                        "policy_name": policy_name,
                        "policy_order": policy_order,
                        "policy_status": policy_status,
                        "policy_description": policy_description,
                        "policy_expiry": policy_expiry,
                        "membership": {
                            "identification_profiles": [
                                {
                                    "auth": "No Authentication",
                                    "profile_name": identification_profile_name,
                                }
                            ],
                        },
                    }
                ]
            }
        )

        return self._http_request(
            "POST",
            f"{V3_PREFIX}/web_security/access_policies",
            json_data=data,
            resp_type="response",
        )

    def access_policy_update_request(
        self,
        policy_name: str,
        new_policy_name: Optional[str] = None,
        policy_status: Optional[str] = None,
        policy_description: Optional[str] = None,
        policy_order: Optional[int] = None,
        policy_expiry: Optional[str] = None,
    ):
        """
        Update access policies.

        Args:
            policy_name (str): Policy name to update.
            new_policy_name (Optional[str], optional): Policy status. Defaults to None.
            policy_status (Optional[str], optional): Policy status. Defaults to None.
            policy_description (Optional[str], optional): Policy description. Defaults to None.
            policy_order (Optional[str], optional): Policy order. Defaults to None.
            policy_expiry (Optional[str], optional): Policy expiry. Defaults to None.

        Returns:
            Response: API response from Cisco WSA.
        """
        data = remove_empty_elements(
            {
                "access_policies": [
                    {
                        "policy_name": policy_name,
                        "new_policy_name": new_policy_name,
                        "policy_status": policy_status,
                        "policy_description": policy_description,
                        "policy_order": policy_order,
                        "policy_expiry": policy_expiry,
                    }
                ]
            }
        )

        return self._http_request(
            "PUT",
            f"{V3_PREFIX}/web_security/access_policies",
            json_data=data,
            resp_type="response",
        )

    def access_policy_url_filtering_update_request(
        self,
        policy_name: str,
        predefined_categories_action: Optional[str] = None,
        predefined_categories: Optional[List[str]] = None,
        youtube_categories_action: Optional[str] = None,
        youtube_categories: Optional[List[str]] = None,
        custom_categories_action: Optional[str] = None,
        custom_categories: Optional[List[str]] = None,
        uncategorized_url: Optional[str] = None,
        update_categories_action: Optional[str] = None,
        content_rating_action: Optional[str] = None,
        content_rating_status: Optional[str] = None,
        safe_search_status: Optional[str] = None,
        unsupported_safe_search_engine: Optional[str] = None,
    ):
        data = remove_empty_elements(
            {
                "access_policies": [
                    {
                        "policy_name": policy_name,
                        "url_filtering": {
                            "predefined_cats": {
                                predefined_categories_action: predefined_categories
                            },
                            "yt_cats": {youtube_categories_action: youtube_categories},
                            "custom_cats": {
                                custom_categories_action: custom_categories
                            },
                            # "exception_referred_embedded_content": {"state": "disable"},
                            "uncategorized_url": uncategorized_url,
                            "update_cats_action": update_categories_action,
                            "content_rating": {
                                "status": content_rating_status,
                                "action": content_rating_action,
                            },
                            "safe_search": {
                                "status": safe_search_status,
                                "unsupported_safe_search_engine": unsupported_safe_search_engine,
                            },
                        },
                    }
                ]
            }
        )

        return self._http_request(
            "PUT",
            f"{V3_PREFIX}/web_security/access_policies",
            json_data=data,
            resp_type="response",
        )

    def access_policy_protocols_user_agents_update_request(
        self,
        policy_name: str,
        block_custom_user_agents: Optional[List[str]] = None,
        allow_connect_ports: Optional[List[str]] = None,
        block_protocols: Optional[List[str]] = None,
    ):
        data = remove_empty_elements(
            {
                "access_policies": [
                    {
                        "policy_name": policy_name,
                        "protocols_user_agents": {
                            "block_custom_user_agents": block_custom_user_agents,
                            "allow_connect_ports": allow_connect_ports,
                            "block_protocols": block_protocols,
                            "state": "custom",
                        },
                    }
                ]
            }
        )

        return self._http_request(
            "PUT",
            f"{V3_PREFIX}/web_security/access_policies",
            json_data=data,
            resp_type="response",
        )

    def access_policy_objects_update_request(
        self,
        policy_name: str,
        object_type: Optional[str] = None,
        object_action: Optional[str] = None,
        object_values: Optional[List[str]] = None,
        block_custom_mime_types: Optional[List[str]] = None,
        http_or_https_max_object_size_mb: Optional[int] = None,
        ftp_max_object_size_mb: Optional[int] = None,
    ):
        data = remove_empty_elements(
            {
                "access_policies": [
                    {
                        "policy_name": policy_name,
                        "objects": {
                            "object_type": {
                                object_type: {object_action: object_values},
                            },
                            "block_custom_mime_types": block_custom_mime_types,
                            "max_object_size_mb": {
                                "http_or_https": http_or_https_max_object_size_mb,
                                "ftp": ftp_max_object_size_mb,
                            },
                            "state": "custom",
                        },
                    }
                ]
            }
        )

        return self._http_request(
            "PUT",
            f"{V3_PREFIX}/web_security/access_policies",
            json_data=data,
            resp_type="response",
        )

    def access_policy_anti_malware_update_request(
        self,
        policy_name: str,
        web_reputation_status: Optional[str] = None,
        file_reputation_filtering_status: Optional[str] = None,
        file_reputation_action: Optional[str] = None,
        anti_malware_scanning_status: Optional[str] = None,
        suspect_user_agent_scanning: Optional[str] = None,
        malware_categories_action: Optional[str] = None,
        malware_categories_values: Optional[List[str]] = None,
        other_categories_action: Optional[str] = None,
        other_categories_values: Optional[List[str]] = None,
    ):
        data = remove_empty_elements(
            {
                "access_policies": [
                    {
                        "policy_name": policy_name,
                        "amw_reputation": {
                            "web_reputation": {"filtering": web_reputation_status},
                            "adv_malware_protection": {
                                "file_reputation_filtering": file_reputation_filtering_status,
                                "file_reputation": {
                                    file_reputation_action: "Known Malicious and High-Risk Files"
                                    if file_reputation_action
                                    else None
                                },
                            },
                            "cisco_dvs_amw": {
                                "amw_scanning": {
                                    "amw_scan_status": anti_malware_scanning_status
                                },
                                "suspect_user_agent_scanning": suspect_user_agent_scanning,
                                "malware_categories": {malware_categories_action: malware_categories_values},
                                "other_categories": {
                                    other_categories_action: other_categories_values,
                                },
                            },
                        },
                    }
                ]
            }
        )

        return self._http_request(
            "PUT",
            f"{V3_PREFIX}/web_security/access_policies",
            json_data=data,
            resp_type="response",
        )

    def access_policy_applications_update_request(
        self,
        policy_name: str,
        application: str,
        action: str,
        values: List[str],
    ):
        data = {
            "access_policies": [
                {
                    "policy_name": policy_name,
                    "avc": {
                        "applications": {
                            application: {action: {value: {} for value in values}},
                        },
                        "state": "custom",
                    },
                }
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
        params = assign_params(policy_names=",".join(policy_names))

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

    def domain_map_create_request(
        self, domain_name: str, ip_addresses: List[str], order: int
    ) -> Dict[str, Any]:
        """
        Create domain mapping.

        Args:
            domain_name (str): Domain name.
            ip_addresses (List[str]): IP addresses to map to the domain.
            order (int): Index of domain map in the collection.

        Returns:
            Dict[str, Any]: API response from Cisco WSA.
        """
        data = [
            {"IP_addresses": ip_addresses, "domain_name": domain_name, "order": order}
        ]

        return self._http_request(
            "POST", f"{V2_PREFIX}/configure/web_security/domain_map", json_data=data
        )

    def domain_map_update_request(
        self,
        domain_name: str,
        new_domain_name: Optional[str] = None,
        ip_addresses: Optional[str] = None,
        order: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Update domain map.

        Args:
            domain_name (str): Domain name to update.
            new_domain_name (Optional[str], optional): New domain name. Defaults to None.
            ip_addresses (Optional[str], optional): IP addresses to map. Defaults to None.
            order (Optional[str], optional): Index of domain map. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco WSA.
        """
        data = remove_empty_elements(
            [
                {
                    "domain_name": domain_name,
                    "new_domain_name": new_domain_name,
                    "IP_addresses": ip_addresses,
                    "order": order,
                }
            ]
        )

        return self._http_request(
            "PUT", f"{V2_PREFIX}/configure/web_security/domain_map", json_data=data
        )

    def domain_map_delete_request(self, domain_name: str) -> Dict[str, Any]:
        """
        Delete domain map.

        Args:
            domain_name (str): Domain name to delete.

        Returns:
            Dict[str, Any]: API response from Cisco WSA.
        """
        data = {"domain_name": domain_name}

        return self._http_request(
            "DELETE",
            f"{V2_PREFIX}/configure/web_security/domain_map",
            json_data=data,
        )

    def identification_profiles_list_request(
        self, profile_names: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get identification profiles.

        Args:
            profile_names (Optional[str], optional): Profile names to list. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco WSA.
        """
        params = assign_params(profile_names=",".join(profile_names))

        return self._http_request(
            "GET", f"{V3_PREFIX}/web_security/identification_profiles", params=params
        )

    def identification_profiles_create_request(
        self,
        profile_name: Optional[str] = None,
        status: Optional[str] = None,
        description: Optional[str] = None,
        protocols: Optional[str] = None,
        order: Optional[int] = None,
    ):
        """
        Create identification profile.

        Args:
            profile_name (str): Identification profile name.
            status (str): Status - enable/disable.
            description (str): Description of identification profile.
            protocols (str): Protocols - HTTPS/SOCKS.
            order (Optional[str]): Index of Identification profile in the collection.

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
        new_profile_name: Optional[str] = None,
        status: Optional[str] = None,
        description: Optional[str] = None,
        protocols: Optional[str] = None,
        order: Optional[int] = None,
    ):
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
            resp_type="response",
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
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))

    if page and page_size:
        offset = (page - 1) * page_size
        return response[offset : offset + page_size]
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

    paginated_response = pagination(response=response, args=args)

    readable_output = tableToMarkdown(
        name=f"Access Policies",
        t=paginated_response,
        headers=[
            "policy_name",
            "policy_status",
            "policy_order",
            "policy_description",
            "policy_expiry",
        ],
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CiscoWSA.AccessPolicy",
        outputs_key_field="policy_name",
        outputs=paginated_response,
        raw_response=paginated_response,
    )


def access_policy_create_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    policy_name = args["policy_name"]
    policy_status = args["policy_status"]
    policy_order = arg_to_number(args["policy_order"])
    identification_profile_name = args["identification_profile_name"]
    policy_description = args.get("policy_description")
    policy_expiry = args.get("policy_expiry")

    response = client.access_policy_create_request(
        policy_name=policy_name,
        policy_status=policy_status,
        policy_order=policy_order,
        identification_profile_name=identification_profile_name,
        policy_description=policy_description,
        policy_expiry=policy_expiry,
    )

    if response.status_code == 204:
        return CommandResults(
            readable_output=f'Created "{policy_name}" access policy successfully.'
        )
    else:
        raise DemistoException(response.json())


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
    policy_name = args["policy_name"]
    new_policy_name = args.get("new_policy_name")
    policy_status = args.get("policy_status")
    policy_description = args.get("policy_description")
    policy_order = arg_to_number(args.get("policy_order"))
    policy_expiry = args.get("policy_expiry")

    response = client.access_policy_update_request(
        policy_name=policy_name,
        new_policy_name=new_policy_name,
        policy_status=policy_status,
        policy_description=policy_description,
        policy_order=policy_order,
        policy_expiry=policy_expiry,
    )

    if response.status_code == 204:
        readable_output = f'"{policy_name}" access policy updated successfully.'
    else:
        raise Exception(response.json())

    return CommandResults(
        readable_output=readable_output,
    )


def access_policy_protocols_user_agents_update_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Update access policy's protocols and user agents settings.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    policy_name = args["policy_name"]
    block_custom_user_agents = argToList(args.get("block_custom_user_agents"))
    allow_connect_ports = argToList(args.get("allow_connect_ports"))
    block_protocols = argToList(args.get("block_protocols"))

    response = client.access_policy_protocols_user_agents_update_request(
        policy_name=policy_name,
        block_custom_user_agents=block_custom_user_agents,
        allow_connect_ports=allow_connect_ports,
        block_protocols=block_protocols,
    )

    if response.status_code == 204:
        readable_output = f'"{policy_name}" access policy updated successfully.'
    else:
        raise Exception(response.json())

    return CommandResults(
        readable_output=readable_output,
    )


def access_policy_url_filtering_update_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Update access policy's URL filtering settings.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    policy_name = args["policy_name"]
    predefined_categories_action = args.get("predefined_categories_action")
    predefined_categories = argToList(args.get("predefined_categories"))
    youtube_categories_action = args.get("youtube_categories_action")
    youtube_categories = argToList(args.get("youtube_categories"))
    custom_categories_action = args.get("custom_categories_action")
    custom_categories = argToList(args.get("custom_categories"))
    uncategorized_url = args.get("uncategorized_url")
    update_categories_action = args.get("update_categories_action")
    content_rating_action = args.get("content_rating_action")
    content_rating_status = args.get("content_rating_status")
    safe_search_status = args.get("safe_search_status")
    unsupported_safe_search_engine = args.get("unsupported_safe_search_engine")

    response = client.access_policy_url_filtering_update_request(
        policy_name=policy_name,
        predefined_categories_action=predefined_categories_action,
        predefined_categories=predefined_categories,
        youtube_categories_action=youtube_categories_action,
        youtube_categories=youtube_categories,
        custom_categories_action=custom_categories_action,
        custom_categories=custom_categories,
        uncategorized_url=uncategorized_url,
        update_categories_action=update_categories_action,
        content_rating_action=content_rating_action,
        content_rating_status=content_rating_status,
        safe_search_status=safe_search_status,
        unsupported_safe_search_engine=unsupported_safe_search_engine,
    )

    if response.status_code == 204:
        readable_output = f'"{policy_name}" access policy updated successfully.'
    else:
        raise Exception(response.json())

    return CommandResults(
        readable_output=readable_output,
    )


def access_policy_applications_update_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Update access policy's applications settings.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    policy_name = args["policy_name"]
    application = args["application"]
    action = args["action"]
    values = argToList(args["values"])

    response = client.access_policy_applications_update_request(
        policy_name=policy_name,
        application=application,
        action=action,
        values=values,
    )

    if response.status_code == 204:
        readable_output = f'"{policy_name}" access policy updated successfully.'
    else:
        raise Exception(response.json())

    return CommandResults(
        readable_output=readable_output,
    )


def access_policy_objects_update_command(
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
    policy_name = args["policy_name"]
    object_type = args.get("object_type")
    object_action = args.get("object_action")
    object_values = argToList(args.get("object_values"))
    block_custom_mime_types = argToList(args.get("block_custom_mime_types"))
    http_or_https_max_object_size_mb = arg_to_number(
        args.get("http_or_https_max_object_size_mb")
    )
    ftp_max_object_size_mb = arg_to_number(args.get("ftp_max_object_size_mb"))

    response = client.access_policy_objects_update_request(
        policy_name=policy_name,
        object_type=object_type,
        object_action=object_action,
        object_values=object_values,
        block_custom_mime_types=block_custom_mime_types,
        http_or_https_max_object_size_mb=http_or_https_max_object_size_mb,
        ftp_max_object_size_mb=ftp_max_object_size_mb,
    )

    if response.status_code == 204:
        readable_output = f'"{policy_name}" access policy updated successfully.'
    else:
        raise Exception(response.json())

    return CommandResults(
        readable_output=readable_output,
    )


def access_policy_anti_malware_update_command(
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
    policy_name = args["policy_name"]
    web_reputation_status = args.get('web_reputation_status')
    file_reputation_filtering_status = args.get('file_reputation_filtering_status')
    file_reputation_action = args.get('file_reputation_action')
    anti_malware_scanning_status = args.get('anti_malware_scanning_status')
    suspect_user_agent_scanning = args.get('suspect_user_agent_scanning')
    malware_categories_action = args.get('malware_categories_action')
    malware_categories_values = args.get('malware_categories_values')
    other_categories_action = args.get('other_categories_action')
    other_categories_values = args.get('other_categories_values')

    response = client.access_policy_anti_malware_update_request(
        policy_name=policy_name,
        web_reputation_status=web_reputation_status,
        file_reputation_filtering_status=file_reputation_filtering_status,
        file_reputation_action=file_reputation_action,
        anti_malware_scanning_status=anti_malware_scanning_status,
        suspect_user_agent_scanning=suspect_user_agent_scanning,
        malware_categories_action=malware_categories_action,
        malware_categories_values=malware_categories_values,
        other_categories_action=other_categories_action,
        other_categories_values=other_categories_values,
    )

    if response.status_code == 204:
        readable_output = f'"{policy_name}" access policy updated successfully.'
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
    policy_names = argToList(args["policy_names"])

    response = client.access_policy_delete_request(policy_names)

    if response.status_code == 204:
        readable_output = f"{policy_names} access policy deleted successfully."
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
    domain_names = argToList(args.get("domain_names"))

    response = client.domain_map_list_request().get("res_data", [])

    if domain_names:
        response = [
            domain for domain in response if domain.get("domain_name") in domain_names
        ]

    paginated_response = pagination(response=response, args=args)

    readable_output = tableToMarkdown(
        name=f"Domain Map",
        t=paginated_response,
        headers=["domain_name", "IP_addresses", "order"],
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CiscoWSA.DomainMap",
        outputs_key_field="domain_name",
        outputs=paginated_response,
        raw_response=paginated_response,
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
    domain_name = args["domain_name"]
    ip_addresses = argToList(args["ip_addresses"])
    order = arg_to_number(args["order"])

    response = client.domain_map_create_request(
        domain_name=domain_name,
        ip_addresses=ip_addresses,
        order=order,
    )

    if response.get("res_code") == 201:
        readable_output = response.get("res_message")
    else:
        raise DemistoException(response)

    return CommandResults(readable_output=readable_output)


def domain_map_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update domain mappings.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    domain_name = args["domain_name"]
    new_domain_name = args.get("new_domain_name")
    ip_addresses = argToList(args.get("ip_addresses"))
    order = args.get("order")

    response = client.domain_map_update_request(
        domain_name=domain_name,
        new_domain_name=new_domain_name,
        ip_addresses=ip_addresses,
        order=order,
    )

    if response.get("res_code") == 200:
        readable_output = response.get("res_message")
    else:
        raise DemistoException(response)

    return CommandResults(readable_output=readable_output)


def domain_map_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete domain mappings.

    Args:
        client (Client): Cisco WSA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    domain_name = argToList(args["domain_names"])

    response = client.domain_map_delete_request(domain_name=domain_name)

    if response.get("res_code") == 200:
        return CommandResults(readable_output=response.get("res_message"))
    elif response.get("res_code") == 206:
        command_results_list = []
        for domain_map in dict_safe_get(response, ["res_data", "delete_success"]):
            readable_output = f"Domain {domain_map} mapping was successfully deleted."
            command_results_list.append(CommandResults(readable_output=readable_output))

        readable_output = dict_safe_get(
            response, ["res_data", "delete_failure", "error_msg"]
        )
        command_results_list.append(CommandResults(readable_output=readable_output))
        return command_results_list
    else:
        raise DemistoException(response)


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
    profile_names = argToList(args.get("profile_names"))

    response = client.identification_profiles_list_request(
        profile_names=profile_names
    ).get("identification_profiles", [])

    paginated_response = pagination(response, args)

    readable_output = tableToMarkdown(
        name=f"Identification Profiles",
        t=paginated_response,
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
        outputs=paginated_response,
        raw_response=paginated_response,
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
    profile_name = args["profile_name"]
    status = args["status"]
    description = args["description"]
    protocols = args["protocols"]
    order = arg_to_number(args["order"])

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
        raise DemistoException(response.json())

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
    profile_name = args["profile_name"]
    new_profile_name = args.get("new_profile_name")
    status = args.get("status")
    description = args.get("description")
    protocols = args.get("protocols")
    order = arg_to_number(args.get("order"))

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
        raise DemistoException(response.json())

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
        return CommandResults(readable_output=f"Deleted profiles successfully.")
    elif response.status_code == 207:
        response = response.json()
        command_results_list = []
        for profile in response.get("success_list"):
            readable_output = (
                f'Identification profile "{profile.get("profile_name")}" '
                f"was successfully deleted."
            )
            command_results_list.append(CommandResults(readable_output=readable_output))
        for profile in response.get("failure_list"):
            readable_output = (
                f'Identification profile "{profile.get("profile_name")}" '
                f'deletion failed, message: "{profile.get("message")}".'
            )
            command_results_list.append(CommandResults(readable_output=readable_output))

        return command_results_list
    else:
        raise DemistoException(response.json())


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
        outputs_prefix="CiscoWSA.UrlCategory",
        outputs=response,
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
        "cisco-wsa-access-policy-create": access_policy_create_command,
        "cisco-wsa-access-policy-update": access_policy_update_command,
        "cisco-wsa-access-policy-protocols-user-agents-update": access_policy_protocols_user_agents_update_command,
        "cisco-wsa-access-policy-url-filtering-update": access_policy_url_filtering_update_command,
        "cisco-wsa-access-policy-applications-update": access_policy_applications_update_command,
        "cisco-wsa-access-policy-objects-update": access_policy_objects_update_command,
        "cisco-wsa-access-policy-anti-malware-update": access_policy_anti_malware_update_command,
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
