import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

demisto.debug("pack name = Microsoft Graph Identity and Access, pack version = 1.2.60")
"""
An integration to MS Graph Identity and Access endpoint.
https://docs.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0
"""

import urllib3


from MicrosoftApiModule import *  # noqa: E402


# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

REQUIRED_PERMISSIONS = (
    "offline_access",  # allows device-flow login
    "IdentityRiskEvent.Read.All",
    "IdentityRiskyUser.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.Read.All",
)


class Client:  # pragma: no cover
    def __init__(
        self,
        app_id: str,
        verify: bool,
        proxy: bool,
        azure_ad_endpoint: str = "https://login.microsoftonline.com",
        client_credentials: bool = False,
        tenant_id: str = None,
        enc_key: str = None,
        managed_identities_client_id: Optional[str] = None,
        private_key: Optional[str] = None,
        certificate_thumbprint: Optional[str] = None,
    ):
        if app_id and "@" in app_id:
            app_id, refresh_token = app_id.split("@")
            integration_context = get_integration_context()
            integration_context["current_refresh_token"] = refresh_token
            set_integration_context(integration_context)
        elif client_credentials and (not enc_key and not (certificate_thumbprint and private_key)):
            raise DemistoException(
                "Either enc_key or (Certificate Thumbprint and Private Key) must be provided. For further "
                "information see "
                "https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication"
            )
        args = {
            "azure_ad_endpoint": azure_ad_endpoint,
            "self_deployed": True,
            "auth_id": app_id,
            "grant_type": CLIENT_CREDENTIALS if client_credentials else DEVICE_CODE,
            "base_url": "https://graph.microsoft.com",
            "verify": verify,
            "proxy": proxy,
            "tenant_id": tenant_id,
            "enc_key": enc_key,
            "managed_identities_client_id": managed_identities_client_id,
            "managed_identities_resource_uri": Resources.graph,
            "certificate_thumbprint": certificate_thumbprint,
            "private_key": private_key,
            "command_prefix": "msgraph-identity",
        }
        if not client_credentials:
            args["scope"] = " ".join(REQUIRED_PERMISSIONS)
            args["token_retrieval_url"] = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
        self.ms_client = MicrosoftClient(**args)  # type: ignore

    def get_directory_roles(self, limit: int) -> list:
        """Get all service principals.

        Args:
            limit: Maximum of services to get.

        Returns:
            All given service principals

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0&tabs=http
        """
        results = []
        res = self.ms_client.http_request("GET", "v1.0/directoryRoles")
        results.extend(res.get("value"))
        while (next_link := res.get("@odata.nextLink")) and len(results) < limit:
            res = self.ms_client.http_request("GET", "", next_link)
            results.extend(res.get("value"))
        return results[:limit]

    def get_role_members(self, role_id: str, limit: int) -> dict:
        """Get all members of a specific role

        Args:
            role_id: a role id to get its members.
            limit: Maximum roles to get.

        Returns:
            directoryObject

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-list-members?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request("GET", f"v1.0/directoryRoles/{role_id}/members")["value"][:limit]

    def get_ip_named_location(self, ip_id: str) -> dict:
        """Get an IP named location by id

        Args:
            ip_id: the id of the requested IP named location.

        Returns:
            a dictionary with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/ipnamedlocation-get?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request("GET", f"v1.0/identity/conditionalAccess/namedLocations/{ip_id}")

    def update_ip_named_location(self, ip_id: str, data: dict) -> dict:
        """Update an IP named location by id

        Args:
            data: the request necessary to create the IP named location, json body.
            ip_id: the id of the IP named location to update.

        Returns:
            None

        Docs:
            https://docs.microsoft.com/en-us/graph/api/ipnamedlocation-update?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            "PUT", f"v1.0/identity/conditionalAccess/namedLocations/{ip_id}", return_empty_response=True, json_data=data
        )

    def delete_ip_named_location(self, ip_id: str) -> dict:
        """Delete an IP named location by id

        Args:
            ip_id: the id of the requested IP named location.

        Returns:
            None

        Docs:
            https://docs.microsoft.com/en-us/graph/api/ipnamedlocation-delete?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            "DELETE", f"v1.0/identity/conditionalAccess/namedLocations/{ip_id}", return_empty_response=True
        )

    def create_ip_named_location(self, data: dict) -> dict:
        """Create an IP named location

        Args:
            data: the request necessary to create the IP named location, json body.

        Returns:
            THe created IP named location

        Docs:
            https://docs.microsoft.com/en-us/graph/api/conditionalaccessroot-post-namedlocations?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request("POST", "v1.0/identity/conditionalAccess/namedLocations", json_data=data)

    def compromise_users(self, data: dict) -> dict:
        """Compromise users in active directory

        Args:
            data: the request necessary to compromise the users, json body.

        Returns:


        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskyuser-confirmcompromised?view=graph-rest-1.0&tabs=http # noqa
        """
        return self.ms_client.http_request(
            "POST", "v1.0/identityProtection/riskyUsers/confirmCompromised", json_data=data, return_empty_response=True
        )

    def dismiss_users(self, data: dict) -> dict:
        """dismiss users in active directory

        Args:
            data: the request necessary to dismiss the users, json body.

        Returns:


        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskyuser-dismiss?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            "POST", "v1.0/identityProtection/riskyUsers/dismiss", json_data=data, return_empty_response=True
        )

    def list_ip_named_location(self, limit: str, page: str, odata: str) -> list:
        """Get a list of all IP named locations

        Args:
            limit: Maximum IP named locations to get.
            page: The page to take the data from.
            odata: An odata query to use in the api call.

        Returns:
            a list of dictionaries with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/conditionalaccessroot-list-namedlocations?view=graph-rest-1.0&tabs=http
        """
        odata_query = "?"
        if limit:
            odata_query += f"$top={limit}&"
        if page:
            odata_query += f"$skip={page}&"
        if odata:
            odata_query += f"{odata}&"
        return self.ms_client.http_request("GET", f"v1.0/identity/conditionalAccess/namedLocations{odata_query}")["value"]

    def list_risk_detections(self, limit: str, odata: str, odata_filter: str) -> list:
        """Get a list of all risk detections

        Args:
            limit: Maximum IP named locations to get.
            page: The page to take the data from.
            odata: An odata query to use in the api call.
            odata_filter: An odata filter

        Returns:
            a list of dictionaries with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0&tabs=http
        """
        odata_query = "?"
        if limit:
            odata_query += f"$top={limit}&"
        if odata:
            odata_query += odata
        if odata_filter:
            odata_query += f"$filter={odata_filter}"
        return self.ms_client.http_request("GET", f"v1.0/identityProtection/riskDetections{odata_query}")["value"]

    def list_risky_users(self, limit: str, odata: str, odata_filter: str = None) -> list:
        """Get a list of all risky users

        Args:
            limit: Maximum IP named locations to get.
            page: The page to take the data from.
            odata: An odata query to use in the api call.
            odata_filter: An odata filter

        Returns:
            a list of dictionaries with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0&tabs=http
        """
        odata_query = "?"
        if limit:
            odata_query += f"$top={limit}&"
        if odata:
            odata_query += odata
        if odata_filter:
            odata_query += f"$filter={odata_filter}"
        return self.ms_client.http_request("GET", f"v1.0/identityProtection/riskyUsers{odata_query}")["value"]

    def list_risky_users_history(self, limit: str, odata: str, user_id: str) -> list:
        """Get a list of all risky user history

        Args:
            limit: Maximum IP named locations to get.
            page: The page to take the data from.
            odata: An odata query to use in the api call.
            user_id: The user id to get the history for.

        Returns:
            a list of dictionaries with the object from the api

        Docs:
            https://docs.microsoft.com/en-us/graph/api/riskyuser-list-history?view=graph-rest-1.0&tabs=http
        """
        odata_query = "?"
        if limit:
            odata_query += f"$top={limit}&"
        if odata:
            odata_query += odata
        return self.ms_client.http_request("GET", f"v1.0/identityProtection/riskyUsers/{user_id}/history{odata_query}")["value"]

    def activate_directory_role(self, template_id: str) -> dict:
        """Activating a role in the directory.
        Args:
            template_id: A template id to activate

        Returns:
            directoryRole object.

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-post-directoryroles?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request("POST", "v1.0/directoryRoles", json_data={"roleTemplateId": template_id})

    def add_member_to_role(self, role_object_id: str, user_id: str):
        """Adds a member to a specific role.

        Args:
            role_object_id: A role to add the user to.
            user_id: The user to add to the role.

        Return:
            True if succeeded.

        Raises:
            Error on failed add (as long with requests errors).

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-post-members?view=graph-rest-1.0&tabs=http
        """
        body = {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"}
        self.ms_client.http_request(
            "POST", f"v1.0/directoryRoles/{role_object_id}/members/$ref", json_data=body, return_empty_response=True
        )

    def remove_member_from_role(self, role_object_id: str, user_id: str):
        """Removing a member from a specific role.

        Args:
            role_object_id: A role to remove the user from.
            user_id: The user to remove from the role.

        Return:
            True if succeeded.

        Raises:
            Error on failed removal (as long with requests errors).

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-delete-member?view=graph-rest-1.0&tabs=http
        """
        self.ms_client.http_request(
            "DELETE", f"v1.0/directoryRoles/{role_object_id}/members/{user_id}/$ref", return_empty_response=True
        )

    def list_conditional_access_policies(self, policy_id: str, filter_query: Optional[str] = None) -> list:
        """
        Retrieve Conditional Access policies, or a specific one by ID.

        Args:
            policy_id (str): The ID of the policy to retrieve. If not provided, lists all.
            filter_query (str, optional): An OData filter query to apply when listing policies
                                            (only relevant when policy_id is not provided).

        Returns:
            list: A list containing the retrieved policy or policies.
                - If policy_id is provided, returns a list with a single policy.
                - If policy_id is not provided, returns a list of all policies.
                - If no policies are found, returns an empty list.

        Raises:
            DemistoException: If an error occurs during the API request.
        """
        if policy_id:
            url_suffix = f"v1.0/identity/conditionalAccess/policies/{policy_id}"
        else:
            url_suffix = "v1.0/identity/conditionalAccess/policies"
            if filter_query:
                url_suffix += f"?$filter={filter_query}"

        res = self.ms_client.http_request(method="GET", url_suffix=url_suffix, resp_type="json")
        # if a single policy is returned (dict), make it a list to standardize the structure
        if not res:
            return []
        if not policy_id:
            return res.get("value") or []
        else:
            return [res]

    def delete_conditional_access_policy(self, policy_id: str) -> CommandResults:
        """
        Delete specific Conditional Access policy by ID.

        Args:
            policy_id (str, required): The ID of the policy to delete.

        Returns:
            CommandResults: Success message or error information.
        """
        url_suffix = f"v1.0/identity/conditionalAccess/policies/{policy_id}"
        res = self.ms_client.http_request(method="DELETE", url_suffix=url_suffix, resp_type="response")

        if res.status_code != 204:
            demisto.error(
                f"Failed to delete Conditional Access policy {policy_id}. Status code: {res.status_code},"
                f" Response: {res.text}"
            )
            raise DemistoException(f"Error deleting Conditional Access policy {policy_id}.:\n{str(res)}")

        demisto.info(f"Conditional Access policy {policy_id} was successfully deleted.")
        return CommandResults(readable_output=f"Conditional Access policy {policy_id} was successfully deleted.")

    def create_conditional_access_policy(self, policy: Dict[str, Any]) -> CommandResults:
        """
        Sends a request to create a new Conditional Access policy in Microsoft Graph API.

        Args:
            policy (str | dict): The policy definition as a JSON string or dictionary.

        Returns:
            CommandResults: Results containing the created policy (context) and
            success message or error information.
        """
        res = self.ms_client.http_request(
            method="POST",
            url_suffix="v1.0/identity/conditionalAccess/policies",
            json_data=policy,
        )

        policy_id = res.get("id")
        if not policy_id:
            demisto.error(f"Error creating Conditional Access policy:\n{str(res)}")
            raise DemistoException(f"Error creating Conditional Access policy:\n{str(res)}")

        demisto.info(f"Conditional Access policy {policy_id} was successfully created:\n{str(res)}")

        return CommandResults(
            outputs_prefix="MSGraphIdentity.ConditionalAccessPolicy",
            outputs=res,
            readable_output=f"Conditional Access policy {policy_id} was successfully created.",
            raw_response=res,
        )

    def update_conditional_access_policy(self, policy_id: str, policy: Union[dict, str]) -> CommandResults:
        """
        Updates a Conditional Access policy using its ID and the provided policy data.

        Args:
            policy_id (str): The ID of the policy to update.
            policy (dict | str): The policy data to update with. Can be a dictionary or a JSON string.

        Returns:
            CommandResults: Object containing the operation outcome.
        """
        res = self.ms_client.http_request(
            method="PATCH",
            url_suffix=f"v1.0/identity/conditionalAccess/policies/{policy_id}",
            json_data=policy,
            resp_type="response",
        )

        if res.status_code != 204:
            demisto.error(f"Conditional Access policy {policy_id} could not be updated:\n{res}")
            raise DemistoException(
                f"Conditional Access policy {policy_id} could not be updated:\n{res}",
            )

        demisto.info(f"Conditional Access policy {policy_id} was successfully updated:\n {res}")

        return CommandResults(
            readable_output=f"Conditional Access policy {policy_id} was successfully updated.",
        )


""" UTILITIES"""


def build_policy(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Builds a Conditional Access policy object from the provided arguments.

    Args:
        args (dict): Command arguments containing policy details.
            policy_name (str): Display name for the policy.
            state (str): State of the policy (enabled, disabled, etc.).
            sign_in_risk_levels (str): Risk levels for sign-in.
            user_risk_levels (str): Risk levels for users.
            client_app_types (str): List of client application types.
            include_applications (str, optional): Applications to include.
            exclude_applications (str, optional): Applications to exclude.
            include_user_actions (str, optional): User actions to include.
            include_users (str, optional): Users to include.
            exclude_users (str, optional): Users to exclude.
            include_roles (str, optional): Roles to include.
            exclude_roles (str, optional): Roles to exclude.
            include_groups (str, optional): Groups to include.
            exclude_groups (str, optional): Groups to exclude.
            include_platforms (str, optional): Platforms to include.
            exclude_platforms (str, optional): Platforms to exclude.
            include_locations (str, optional): Locations to include.
            exclude_locations (str, optional): Locations to exclude.
            grant_control_operator (str, optional): Operator for grant controls, default is AND.
            grant_control_enforcement (str, optional): Enforcement controls, default is mfa.

    Returns:
        dict: A structured policy object ready to be used in creating a Conditional Access policy.

    """

    policy = {
        "displayName": args.get("policy_name"),
        "state": args.get("state"),
        "conditions": {
            "clientAppTypes": argToList(args.get("client_app_types")),
            "applications": {
                "includeApplications": argToList(args.get("include_applications")),
                "excludeApplications": argToList(args.get("exclude_applications")),
                "includeUserActions": argToList(args.get("include_user_actions")),
            },
            "users": {
                "includeUsers": argToList(args.get("include_users")),
                "excludeUsers": argToList(args.get("exclude_users")),
                "includeRoles": argToList(args.get("include_roles")),
                "excludeRoles": argToList(args.get("exclude_roles")),
                "includeGroups": argToList(args.get("include_groups")),
                "excludeGroups": argToList(args.get("exclude_groups")),
            },
            "platforms": {
                "includePlatforms": argToList(args.get("include_platforms")),
                "excludePlatforms": argToList(args.get("exclude_platforms")),
            },
            "locations": {
                "includeLocations": argToList(args.get("include_locations")),
                "excludeLocations": argToList(args.get("exclude_locations")),
            },
            "signInRiskLevels": argToList(args.get("sign_in_risk_levels")),
            "userRiskLevels": argToList(args.get("user_risk_levels")),
        },
        "grantControls": {
            "operator": args.get("grant_control_operator"),
            "builtInControls": argToList(args.get("grant_control_enforcement")),
        },
    }

    return policy


def deep_get(root: dict[str, Any], path: list[str]) -> Any | None:
    """
    Return the value at a nested path in a dictionary.

    Args:
        root (dict[str, Any]): The root dictionary to traverse.
        path (list[str]): The path to follow, with each element being a key in the dictionary.

    Returns:
        Any | None: The value at the specified path, or None if any key in the path doesn't exist.
    """
    try:
        demisto.debug(f"Getting value from path {path} in dictionary")
        acc = root

        for i, key in enumerate(path):
            demisto.debug(f"Accessing key '{key}' ({i+1}/{len(path)})")
            acc = acc[key]

        demisto.debug(f"Successfully retrieved value from path {path}")
        return acc

    except (KeyError, TypeError) as e:
        demisto.info(f"Failed to get value from path {path}: {str(e)}")
        return None


def deep_set(root: dict[str, Any], path: list[str], value: Any) -> None:
    """
    Set a value at a nested path in a dictionary.

    Args:
        root (dict[str, Any]): The root dictionary to modify.
        path (list[str]): The path to follow, with each element being a key in the dictionary.
        value (Any): The value to set at the specified path.

    Note:
        This function creates any missing dictionaries along the path.

    Example:
        For a path like ['a', 'b', 'c'] and a value 42, if 'a' or 'b' don't exist,
        they will be created as empty dictionaries using setdefault:

        root = {}
        deep_set(root, ['a', 'b', 'c'], 42)
        # Results in: {'a': {'b': {'c': 42}}}

        The setdefault method returns the value for a key if it exists,
        otherwise it sets the key to a default value and returns that value.
    """
    for key in path[:-1]:
        root = root.setdefault(key, {})
    root[path[-1]] = value


def resolve_merge_value(
    field: str,
    existing: List[str],
    new: List[str],
    messages: List[str],
) -> List[str]:
    """
    Merge two lists of values based on field-specific rules.

    Args:
        field (str): The field name whose values are being merged.
        existing (List[str]): The existing list of values.
        new (List[str]): The new list of values to merge with existing.
        messages (List[str]): A list to collect messages about merge decisions.

    Returns:
        List[str]: The merged list of values based on specific rules:
            1. For 'signInRiskLevels', performs a direct set union
            2. If existing list only contains 'None' values, returns the new list
            3. If existing list contains special values like 'All', keeps existing
            4. If new list only contains special values, returns the new list
            5. Otherwise, performs a set union of both lists
    """
    specials = {"All", "all", "AllTrusted"}
    none_values = {"None", "none"}

    demisto.debug(f"resolve_merge_value: Merging '{field}' values. Existing: {existing}, New: {new}")

    # Sign-in risk levels are a straight set-union because this filed can contain combination of
    # "none" and other values like "low", "medium", "high" (i.e: signInRiskLevels = "none", "low")
    if field == "signInRiskLevels":
        result = list(set(existing) | set(new))
        demisto.debug(f"resolve_merge_value: Field '{field}' is a sign-in risk level. Merged result: {result}")
        return result

    # Existing == ['None'] → take the new list
    if set(existing).issubset(none_values):
        demisto.debug(f"resolve_merge_value: Existing values for '{field}' are 'None'. Using new values: {new}")
        return new

    # Existing is a blocking special value → keep it, warn once
    if existing and existing[0] in specials:
        message = (
            f"Field '{field}' kept as '{existing[0]}' (special value cannot be merged).\n"
            f"To update this field, use update_action='override'."
        )
        messages.append(message)
        demisto.debug(f"resolve_merge_value: {message}")
        return existing

    # Incoming list is itself only a special value → take it
    if set(new).issubset(specials):
        demisto.debug(f"resolve_merge_value: New values for '{field}' contain only special values: {new}. Using new values.")
        return new

    # Otherwise, normal union
    result = list(set(existing) | set(new))
    demisto.debug(f"resolve_merge_value: Performed normal union for '{field}'. Merged result: {result}")
    return result


def merge_policy_section(
    base_existing: Dict[str, Any],
    new: Dict[str, Any],
    messages: List[str],
) -> None:
    """
    Merges new policy section values into an existing policy structure.

    This function walks through the new policy dictionary and merges list values with
    existing ones according to specific rules defined in resolve_merge_value().

    Args:
        base_existing (Dict[str, Any]): The existing policy configuration to merge into.
        new (Dict[str, Any]): The new policy configuration with values to merge.
        messages (List[str]): A list to collect messages about merge decisions.

    Returns:
        None: The function modifies the 'new' dictionary in place.
    """

    def walk(node_new: Dict[str, Any], path: List[str]) -> None:
        for key, val in node_new.items():
            current_path_to_key = path + [key]
            demisto.debug(f"Processing key {key} at path {'/'.join(current_path_to_key)}")

            # ── dive deeper
            if isinstance(val, dict):
                demisto.debug(f"Found dictionary at {'/'.join(current_path_to_key)}, diving deeper")
                walk(val, current_path_to_key)
                continue

            # ── override non-list leaves
            if not isinstance(val, list):
                demisto.debug("setting to the new policy value.")
                messages.append(f"Field `{'/'.join(current_path_to_key)}` is not a list - overriding the value.")
                continue

            existing_val = deep_get(base_existing, current_path_to_key)
            demisto.debug(f"Existing value at {'/'.join(current_path_to_key)}: {existing_val}")

            if isinstance(existing_val, list):
                merged = resolve_merge_value(key, existing_val, val, messages)
                demisto.debug(f"Merged result for {'/'.join(current_path_to_key)}: {merged}")
                deep_set(new, current_path_to_key, merged)

            else:
                # no existing list (or wrong type) → leave new value as-is
                if existing_val is None:
                    messages.append(f"Field `{'/'.join(current_path_to_key)}` was empty - new list left untouched.")
                    demisto.debug(f"No existing value at {'/'.join(current_path_to_key)}, new value is {val}")
                else:
                    demisto.debug(f"Existing value at {'/'.join(current_path_to_key)} is not a list, new list left untouched.")
                    messages.append(
                        f"Field `{'/'.join(current_path_to_key)}` exists but is not a list - new list left untouched."
                    )

    demisto.debug("merge_policy_section: Starting policy merge process")
    walk(new, [])
    demisto.debug("merge_policy_section: Completed policy merge process")


""" COMMAND FUNCTIONS """


def start_auth(client: Client) -> CommandResults:  # pragma: no cover
    result = client.ms_client.start_auth("!msgraph-identity-auth-complete")
    return CommandResults(readable_output=result)


def complete_auth(client: Client) -> str:  # pragma: no cover
    client.ms_client.get_access_token()
    return "✅ Authorization completed successfully."


def test_connection(client: Client) -> str:  # pragma: no cover
    client.ms_client.get_access_token()
    return "✅ Success!"


def list_directory_roles(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover
    """Lists all service principals

    Args:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    limit_str = args.get("limit", "")
    try:
        limit = int(limit_str)
    except ValueError:
        raise DemistoException(f'Limit must be an integer, not "{limit_str}"')
    results = ms_client.get_directory_roles(limit)
    return CommandResults(
        "MSGraphIdentity.Role",
        "id",
        outputs=results,
        readable_output=tableToMarkdown(
            "Directory roles:",
            results,
            ["id", "displayName", "description", "roleTemplateId", "deletedDateTime"],
            removeNull=True,
        ),
    )


def list_role_members_command(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover
    """Lists all service principals

    Args:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    limit_str = args.get("limit", "")
    try:
        limit = int(limit_str)
    except ValueError:
        raise DemistoException(f'Limit must be an integer, not "{limit_str}"')
    role_id = args.get("role_id")
    try:
        if results := ms_client.get_role_members(role_id, limit):  # type: ignore
            ids = [member["id"] for member in results]
            context = {"role_id": role_id, "user_id": ids}
            return CommandResults(
                "MSGraphIdentity.RoleMember",
                "role_id",
                outputs=context,
                raw_response=results,
                readable_output=tableToMarkdown(f"Role '{role_id}' members:", context),
            )
        else:
            return CommandResults(readable_output=f"No members found in {role_id}")
    except Exception as e:
        demisto.debug(f"Role ID: {role_id} was not found or invalid - {e}")
        return CommandResults(readable_output=f"Role ID: {role_id}, was not found or invalid")


def activate_directory_role_command(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover
    template_id = args.get("role_template_id")
    results = ms_client.activate_directory_role(template_id)  # type: ignore
    return CommandResults(
        "MSGraphIdentity.Role",
        "id",
        outputs=results,
        readable_output=tableToMarkdown(
            "Role has been activated", results, ["id", "roleTemplateId", "displayName", "description", "deletedDateTime"]
        ),
    )


def add_member_to_role_command(client: Client, args: dict) -> str:  # pragma: no cover
    user_id = args.get("user_id")
    role_object_id = args.get("role_id")
    client.add_member_to_role(role_object_id, user_id)  # type: ignore
    return f"User ID {user_id} has been added to role {role_object_id}"


def remove_member_from_role(client: Client, args: dict) -> str:  # pragma: no cover
    role_object_id = args.get("role_id")
    user_id = args.get("user_id")
    client.remove_member_from_role(role_object_id, user_id)  # type: ignore
    return f"User ID {user_id} has been removed from role {role_object_id}"


def ip_named_location_get(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover
    ip_id = args.get("ip_id")
    if results := ms_client.get_ip_named_location(ip_id):  # type: ignore
        context = {
            "id": ip_id,
            "display_name": results.get("displayName"),
            "time_created": results.get("createdDateTime"),
            "time_modified": results.get("modifiedDateTime"),
            "is_trusted": results.get("isTrusted"),
            "ip_ranges": results.get("ipRanges"),
        }
        return CommandResults(
            "MSGraph.conditionalAccess.namedIpLocations",
            "namedIpLocations",
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(f"IP named location '{ip_id}':", context),
        )
    return CommandResults(readable_output=f"No IP location found for {ip_id}")


def ip_named_location_update(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover
    ip_id = args.get("ip_id")
    if results := ms_client.get_ip_named_location(ip_id):  # type: ignore
        data = {
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "displayName": results.get("displayName"),
            "isTrusted": results.get("isTrusted"),
            "ipRanges": results.get("ipRanges"),
        }
        ips = args.get("ips")
        is_trusted = args.get("is_trusted")
        display_name = args.get("display_name")
        if ips:
            ips = ms_ip_string_to_list(ips)
            data["ipRanges"] = ips
        if is_trusted:
            data["isTrusted"] = is_trusted
        if display_name:
            data["displayName"] = display_name
        ms_client.update_ip_named_location(ip_id, data)  # type: ignore
        return CommandResults(
            "MSGraph.conditionalAccess.namedIpLocations",
            "namedIpLocations",
            outputs={},
            raw_response={},
            ignore_auto_extract=True,
            readable_output=f"Successfully  updated IP named location '{ip_id}'",
        )
    return CommandResults(readable_output=f"Could not update IP named location '{ip_id}'")


def ip_named_location_create(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover
    ips = args.get("ips")
    is_trusted = args.get("is_trusted")
    display_name = args.get("display_name")
    if ips and display_name and is_trusted:
        is_trusted = str(is_trusted).lower() == "true"
        ips_arr = ms_ip_string_to_list(ips)
        data = {
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "displayName": display_name,
            "isTrusted": is_trusted,
            "ipRanges": ips_arr,
        }
        if results := ms_client.create_ip_named_location(data):
            id = results.get("id")
            context = {
                "id": id,
                "display_name": results.get("displayName"),
                "time_created": results.get("createdDateTime"),
                "time_modified": results.get("modifiedDateTime"),
                "is_trusted": results.get("isTrusted"),
                "ip_ranges": results.get("ipRanges"),
            }
            return CommandResults(
                "MSGraph.conditionalAccess.namedIpLocations",
                "namedIpLocations",
                outputs=context,
                raw_response=results,
                ignore_auto_extract=True,
                readable_output=tableToMarkdown(f"created IP named location '{id}':", context),
            )
    return CommandResults(readable_output="Could not create IP named location")


def azure_ad_identity_protection_confirm_compromised_command(
    ms_client: Client, args: dict
) -> CommandResults:  # pragma: no cover  # noqa
    user_ids = str(args.get("user_ids")).split(",")
    data = {"userIds": user_ids}
    try:
        ms_client.compromise_users(data)
        return CommandResults(raw_response={}, ignore_auto_extract=True, readable_output=f"Successfully compromised {user_ids!s}")
    except Exception as e:
        return CommandResults(readable_output=f"Could not compromised {user_ids!s}:\n{e}")


def azure_ad_identity_protection_risky_users_dismiss_command(
    ms_client: Client, args: dict
) -> CommandResults:  # pragma: no cover  # noqa
    user_ids = str(args.get("user_ids")).split(",")
    data = {"userIds": user_ids}
    try:
        ms_client.dismiss_users(data)
        return CommandResults(raw_response={}, ignore_auto_extract=True, readable_output=f"Successfully dismissed {user_ids!s}")
    except Exception as e:
        return CommandResults(readable_output=f"Could not dismiss {user_ids!s}:\n{e}")


def ip_named_location_delete(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover
    ip_id = args.get("ip_id")
    if results := ms_client.delete_ip_named_location(ip_id):  # type: ignore  # noqa
        return CommandResults(
            "MSGraph.conditionalAccess.namedIpLocations",
            "namedIpLocations",
            outputs={},
            raw_response={},
            ignore_auto_extract=True,
            readable_output=f"Successfully deleted IP named location '{ip_id}'",
        )
    return CommandResults(readable_output=f"Could not delete IP named location '{ip_id}'")


def ip_named_location_list(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover
    limit = args.get("limit")
    page = args.get("page")
    odata = args.get("odata_query")
    if results := ms_client.list_ip_named_location(limit, page, odata):  # type: ignore
        ip_named_locations = []
        for result in results:
            ip_named_location = {
                "id": result.get("id"),
                "display_name": result.get("displayName"),
                "time_created": result.get("createdDateTime"),
                "time_modified": result.get("modifiedDateTime"),
                "is_trusted": result.get("isTrusted"),
                "ip_ranges": result.get("ipRanges"),
            }
            ip_named_locations.append(ip_named_location)
        context = {"ip_named_locations": ip_named_locations}
        return CommandResults(
            "MSGraph.conditionalAccess.namedIpLocations",
            "namedIpLocations",
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(
                "IP named locations:",
                ip_named_locations,
            ),
        )
    else:
        return CommandResults(readable_output="could not list IP named locations")


def azure_ad_identity_protection_risky_users_list(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover  # noqa
    limit = args.get("limit")
    odata = args.get("odata_query")
    if results := ms_client.list_risky_users(limit, odata):  # type: ignore
        risky_users = []
        for result in results:
            risky_user = {
                "id": result.get("id"),
                "isDeleted": result.get("isDeleted"),
                "isProcessing": result.get("isProcessing"),
                "riskLevel": result.get("riskLevel"),
                "riskState": result.get("riskState"),
                "riskDetail": result.get("riskDetail"),
                "riskLastUpdatedDateTime": result.get("riskLastUpdatedDateTime"),
                "userDisplayName": result.get("userDisplayName"),
                "userPrincipalName": result.get("userPrincipalName"),
            }
            risky_users.append(risky_user)
        context = {"riskyUsers": risky_users}
        return CommandResults(
            "MSGraph.identityProtection.riskyUsers",
            "riskyUsers",
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(
                "Risky users:",
                risky_users,
            ),
        )
    else:
        return CommandResults(readable_output="could not list IP named locations")


def azure_ad_identity_protection_risky_users_history_list(
    ms_client: Client, args: dict
) -> CommandResults:  # pragma: no cover  # noqa
    limit = args.get("limit")
    odata = args.get("odata_query")
    user_id = args.get("user_id")
    if results := ms_client.list_risky_users_history(limit, odata, user_id):  # type: ignore
        risky_users = []
        for result in results:
            risky_user = {
                "id": result.get("id"),
                "isDeleted": result.get("isDeleted"),
                "isProcessing": result.get("isProcessing"),
                "riskLevel": result.get("riskLevel"),
                "riskState": result.get("riskState"),
                "riskDetail": result.get("riskDetail"),
                "riskLastUpdatedDateTime": result.get("riskLastUpdatedDateTime"),
                "userDisplayName": result.get("userDisplayName"),
                "userPrincipalName": result.get("userPrincipalName"),
                "userId": result.get("userId"),
                "initiatedBy": result.get("initiatedBy"),
                "activity": result.get("activity"),
            }
            risky_users.append(risky_user)
        context = {"riskyUsers": risky_users}
        return CommandResults(
            "MSGraph.identityProtection.riskyUsers",
            "riskyUsers",
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(
                "Risky users history:",
                risky_users,
            ),
        )
    else:
        return CommandResults(readable_output="could not list IP named locations")


def azure_ad_identity_protection_risk_detection_list(ms_client: Client, args: dict) -> CommandResults:  # pragma: no cover  # noqa
    limit = args.get("limit")
    odata = args.get("odata_query")
    odata_filter = args.get("filter")
    if results := ms_client.list_risk_detections(limit, odata, odata_filter):  # type: ignore
        risks = []
        for result in results:
            risk = {
                "id": result.get("id"),
                "requestId": result.get("requestId"),
                "correlationId": result.get("correlationId"),
                "riskEventType": result.get("riskEventType"),
                "riskState": result.get("riskState"),
                "riskLevel": result.get("riskLevel"),
                "riskDetail": result.get("riskDetail"),
                "source": result.get("source"),
                "detectionTimingType": result.get("detectionTimingType"),
                "activity": result.get("activity"),
                "ipAddress": result.get("ipAddress"),
                "activityDateTime": result.get("activityDateTime"),
                "detectedDateTime": result.get("detectedDateTime"),
                "lastUpdatedDateTime": result.get("lastUpdatedDateTime"),
                "userId": result.get("userId"),
                "userDisplayName": result.get("userDisplayName"),
                "userPrincipalName": result.get("userPrincipalName"),
                "additionalInfo": result.get("additionalInfo"),
                "location": result.get("location"),
            }
            risks.append(risk)
        context = {"riskDetections": risks}
        return CommandResults(
            "MSGraph.identityProtection.risks",
            "riskDetections",
            outputs=context,
            raw_response=results,
            ignore_auto_extract=True,
            readable_output=tableToMarkdown(
                "Risks detected:",
                risks,
            ),
        )
    else:
        return CommandResults(readable_output="could not list IP named locations")


def ms_ip_string_to_list(ips: str) -> list:
    ips_arr = []
    ips = ips.split(",")
    for ip in ips:
        temp = {"cidrAddress": ip}
        # ipv4 check
        if "." in ip:
            temp["@odata.type"] = "#microsoft.graph.iPv4CidrRange"
        # ipv6 check
        elif ":" in ip:
            temp["@odata.type"] = "#microsoft.graph.iPv6CidrRange"
        else:
            continue
        ips_arr.append(temp)
    return ips_arr


def get_last_fetch_time(last_run: dict, params: dict):
    last_fetch = last_run.get("latest_detection_found")
    if not last_fetch:
        demisto.debug("[AzureADIdentityProtection] First run")
        # handle first time fetch
        first_fetch = f"{params.get('first_fetch') or '1 days'} ago"
        default_fetch_datetime = dateparser.parse(date_string=first_fetch, date_formats=[DATE_FORMAT])
        assert default_fetch_datetime is not None, f"failed parsing {first_fetch}"
        last_fetch = str(default_fetch_datetime.isoformat(timespec="milliseconds")) + "Z"

    demisto.debug(f"[AzureADIdentityProtection] last_fetch: {last_fetch}")
    return last_fetch


def date_str_to_azure_format(date_str: str) -> str:
    """
    Given a string representing a date in some general format, modifies the date to Azure format.
    That means removing the Z at the end and adding nanoseconds if they don't exist.
    Moreover, sometimes the date has too many digits for
    """
    date_str = date_str[:-1] if date_str[-1].lower() == "z" else date_str
    if "." not in date_str:
        date_str = f"{date_str}.000"
    else:
        date_without_ns, ns = date_str.split(".")
        ns = ns[:6]
        date_str = f"{date_without_ns}.{ns}"

    return date_str


def detection_to_incident(detection: dict, detection_date: str) -> dict:
    detection_id: str = detection.get("id", "")
    detection_type: str = detection.get("riskEventType", "")
    detection_detail: str = detection.get("riskDetail", "")
    incident = {
        "name": f"Azure AD: {detection_id} {detection_type} {detection_detail}",
        "occurred": f"{detection_date}Z",
        "rawJSON": json.dumps(detection),
    }
    return incident


def detections_to_incidents(
    detections: List[Dict[str, str]], last_fetch_datetime: str
) -> tuple[List[Dict[str, str]], str]:  # pragma: no cover  # noqa
    """
    Given the detections retrieved from Azure Identity Protection, transforms their data to incidents format.
    """
    incidents: List[Dict[str, str]] = []
    latest_incident_time = last_fetch_datetime

    for detection in detections:
        detection_datetime = detection.get("detectedDateTime", "")
        detection_datetime_in_azure_format = date_str_to_azure_format(detection_datetime)
        incident = detection_to_incident(detection, detection_datetime_in_azure_format)
        incidents.append(incident)

        if datetime.strptime(detection_datetime_in_azure_format, DATE_FORMAT) > datetime.strptime(
            date_str_to_azure_format(latest_incident_time), DATE_FORMAT
        ):
            latest_incident_time = detection_datetime

    return incidents, latest_incident_time


def risky_user_to_incident(riskyuser: dict, riskyuser_date: str) -> dict:
    riskyuser_upn: str = riskyuser.get("userPrincipalName", "")
    riskyuser_risk_level: str = riskyuser.get("riskLevel", "")
    riskyuser_risk_state: str = riskyuser.get("riskState", "")
    incident = {
        "name": f"Azure User at Risk: {riskyuser_upn} - {riskyuser_risk_state} - {riskyuser_risk_level}",
        "occurred": f"{riskyuser_date}Z",
        "rawJSON": json.dumps(riskyuser),
    }

    return incident


def risky_users_to_incidents(riskyusers: List[Dict[str, str]], last_fetch_datetime: str) -> tuple[List[Dict[str, str]], str]:
    """
    Given the risky users retrieved from Azure Identity Protection, transforms their data to incidents format.
    """

    incidents: List[Dict[str, str]] = []
    latest_incident_time = last_fetch_datetime

    for riskyuser in riskyusers:
        riskyuser_datetime = riskyuser.get("riskLastUpdatedDateTime", "")
        riskyuser_datetime_in_azure_format = date_str_to_azure_format(riskyuser_datetime)
        incident = risky_user_to_incident(riskyuser, riskyuser_datetime_in_azure_format)
        incidents.append(incident)

        if datetime.strptime(riskyuser_datetime_in_azure_format, DATE_FORMAT) > datetime.strptime(
            date_str_to_azure_format(latest_incident_time), DATE_FORMAT
        ):
            latest_incident_time = riskyuser_datetime

    return incidents, latest_incident_time


def build_filter(last_fetch: datetime, params: dict) -> str:
    if params.get("alerts_to_fetch", "Risk Detections") == "Risky Users":
        start_time_enforcing_filter = f"riskLastUpdatedDateTime gt {last_fetch}"
    else:
        start_time_enforcing_filter = f"detectedDateTime gt {last_fetch}"

    user_supplied_filter = params.get("fetch_filter_expression", "")
    query_filter = (
        f"({user_supplied_filter}) and {start_time_enforcing_filter}" if user_supplied_filter else start_time_enforcing_filter
    )
    demisto.debug(f"[AzureADIdentityProtection] query_filter: {query_filter}")
    return query_filter


def fetch_incidents(client: Client, params: Dict[str, str]):  # pragma: no cover
    last_run: Dict[str, str] = demisto.getLastRun()
    demisto.debug(f"[AzureIdentityProtection] last run: {last_run}")

    last_fetch = get_last_fetch_time(last_run, params)
    query_filter = build_filter(last_fetch, params)
    demisto.debug(f"last fetch is: {last_fetch}, filter is: {query_filter}")

    limit = params.get("max_fetch", "50")
    filter_expression = query_filter

    if params.get("alerts_to_fetch", "Risk Detections") == "Risky Users":
        riskyusers: list = client.list_risky_users(limit, None, filter_expression)  # type: ignore
        incidents, latest_detection_time = risky_users_to_incidents(riskyusers, last_fetch_datetime=last_fetch)  # type: ignore
    else:
        detections: list = client.list_risk_detections(limit, None, filter_expression)  # type: ignore
        incidents, latest_detection_time = detections_to_incidents(detections, last_fetch_datetime=last_fetch)  # type: ignore

    demisto.debug(f"Fetched {len(incidents)} incidents")

    demisto.debug(f"next run latest_detection_found: {latest_detection_time}")
    last_run = {
        "latest_detection_found": latest_detection_time,
    }

    return incidents, last_run


def list_conditional_access_policies_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves a list of Conditional Access policies or a specific one by ID.

    Args:
        client (Client): Microsoft Graph client.
        args (dict): Command arguments. Supports optional 'policy_id'.

    Returns:
        CommandResults: Results to return to Cortex XSOAR.
    """
    policy_id = args.get("policy_id", "")
    filter_query = args.get("filter")
    limit = args.get("limit")
    all_results = argToBoolean(args.get("all_results", True))

    if policy_id and filter_query:
        raise DemistoException("Cannot provide both policy_id and filter_query at the same time.\nPlease choose one.")

    policies: list[dict[str, Any]] = client.list_conditional_access_policies(policy_id, filter_query)

    if len(policies) == 0:
        demisto.info("no conditional policies were found")
        return CommandResults(readable_output="No Conditional Access policies were found.")

    elif limit:
        max_items = int(limit)
    elif all_results:
        max_items = len(policies)
    else:
        max_items = min(len(policies), 50)  # Default limit

    policies_to_process = policies[:max_items]

    context = []
    readable_policies = []

    for policy in policies_to_process:
        context.append(policy)
        readable_policy = {
            "ID": policy.get("id"),
            "DisplayName": policy.get("displayName"),
            "CreatedDateTime": policy.get("createdDateTime"),
            "State": policy.get("state"),
            "GrantControls": policy.get("GrantControls"),
            "Platforms": policy.get("platforms"),
            "Locations": policy.get("locations"),
            "Devices": policy.get("devices"),
            "IncludeUsers": policy.get("conditions", {}).get("users", {}).get("includeUsers", []),
            "ExcludeUsers": policy.get("conditions", {}).get("users", {}).get("excludeUsers", []),
        }
        readable_policy = remove_empty_elements(readable_policy)
        readable_policies.append(readable_policy)

    return CommandResults(
        outputs_prefix="MSGraphIdentity.ConditionalAccessPolicy",
        outputs_key_field="ID",
        outputs=context,
        readable_output=tableToMarkdown("Conditional Access Policies", readable_policies),
        raw_response=policies,
    )


def delete_conditional_access_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Deletes a Conditional Access policy by its ID.

    Required Permissions:
        Policy.Read.All (Delegated or Application)
        Policy.ReadWrite.ConditionalAccess (Delegated or Application)

    Args:
        client (Client): Microsoft Graph client.
        args (dict): Command arguments.
            policy_id (str): The ID of the Conditional Access policy to delete.

    Returns:
        CommandResults: Results to return to Cortex XSOAR.
    """
    policy_id = args.get("policy_id", "")
    return client.delete_conditional_access_policy(policy_id)


def create_conditional_access_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates a Conditional Access policy.

    Args:
        client (Client): Microsoft Graph client.
        args (dict): Command arguments containing policy details.

    Returns:
        CommandResults: In case of success created policy data for Context and
                        and success message for the user, otherwise error message
    """

    policy = args.get("policy", {})
    # in case user send json policy
    try:
        if isinstance(policy, str):
            policy = json.loads(policy)

    except json.JSONDecodeError as e:
        raise DemistoException(f"The provided policy string is not a valid JSON.\nError: {e}")

    if not policy:
        required_fields = ["policy_name", "state", "sign_in_risk_levels", "user_risk_levels", "client_app_types"]
        missing_fields = [field for field in required_fields if not args.get(field)]

        if missing_fields:
            missing_list = ", ".join(missing_fields)
            demisto.debug(f"Missing required field(s): {missing_list}.")
            raise DemistoException(f"Missing required field(s): {missing_list}.")

        policy = build_policy(args)

    policy = cast(Dict[str, Any], remove_empty_elements(policy))

    return client.create_conditional_access_policy(policy)


def update_conditional_access_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update an existing Conditional Access policy using either full override or append logic.

    Args:
        client (Client): An authenticated Microsoft Graph API client.
        args (Dict[str, Any]): Command arguments including:
            - policy_id (str): ID of the policy to update.
            - policy (str or dict, optional): A complete policy in JSON format (used if provided).
            - update_action (str, optional): 'override' (default) or 'append'.
            - Other individual fields like include_users, state, etc., depending on mode.

    Returns:
        CommandResults: A result object indicating success or failure, along with messages.
    """

    policy_id = args.get("policy_id", "")
    update_action = args.get("update_action", "append")
    messages: list[str] = []

    policy = args.get("policy")

    if policy:
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError as e:
            raise ValueError(f"The provided policy string is not a valid JSON. {str(e)}")

        return client.update_conditional_access_policy(policy_id, policy)

    new_policy = build_policy(args)

    new_policy = cast(Dict[str, Any], remove_empty_elements(new_policy))

    if update_action == "append":
        existing_policy = client.list_conditional_access_policies(policy_id)

        if not existing_policy:
            demisto.info(f"No existing policy found with ID: {policy_id}")
            raise DemistoException(f"No existing policy found with ID: {policy_id}")

        merge_policy_section(existing_policy[0], new_policy, messages)
        new_policy = cast(Dict[str, Any], remove_empty_elements(new_policy))

    result = client.update_conditional_access_policy(policy_id, new_policy)

    if messages and result.readable_output and not result.readable_output.startswith("Error"):
        result.readable_output += "\n\nNote:\n" + "\n".join(messages)

    return result


def main():  # pragma: no cover
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        command = demisto.command()
        params = demisto.params()
        args = demisto.args()
        handle_proxy()
        client = Client(
            app_id=params.get("app_id"),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            azure_ad_endpoint=params.get("azure_ad_endpoint", "https://login.microsoftonline.com")
            or "https://login.microsoftonline.com",
            tenant_id=params.get("tenant_id"),
            client_credentials=params.get("client_credentials", False),
            enc_key=(params.get("credentials") or {}).get("password"),
            managed_identities_client_id=get_azure_managed_identities_client_id(params),
            certificate_thumbprint=params.get("creds_certificate", {}).get("identifier"),
            private_key=(replace_spaces_in_credential(params.get("creds_certificate", {}).get("password"))),
        )
        if command == "test-module":
            if client.ms_client.managed_identities_client_id or client.ms_client.grant_type == CLIENT_CREDENTIALS:
                test_connection(client=client)
                return_results("ok")
            else:
                return_results("The test module is not functional, run the msgraph-identity-auth-start command instead.")
        elif command == "msgraph-identity-auth-start":
            return_results(start_auth(client))
        elif command == "msgraph-identity-auth-complete":
            return_results(complete_auth(client))
        elif command == "msgraph-identity-auth-test":
            return_results(test_connection(client))
        elif command == "msgraph-identity-auth-reset":
            return_results(reset_auth())
        elif command == "msgraph-identity-directory-roles-list":
            return_results(list_directory_roles(client, args))
        elif command == "msgraph-identity-directory-role-members-list":
            return_results(list_role_members_command(client, args))
        elif command == "msgraph-identity-directory-role-activate":
            return_results(activate_directory_role_command(client, args))
        elif command == "msgraph-identity-directory-role-member-add":
            return_results(add_member_to_role_command(client, args))
        elif command == "msgraph-identity-directory-role-member-remove":
            return_results(remove_member_from_role(client, args))
        elif command == "msgraph-identity-ip-named-locations-create":
            return_results(ip_named_location_create(client, args))
        elif command == "msgraph-identity-ip-named-locations-get":
            return_results(ip_named_location_get(client, args))
        elif command == "msgraph-identity-ip-named-locations-update":
            return_results(ip_named_location_update(client, args))
        elif command == "msgraph-identity-ip-named-locations-delete":
            return_results(ip_named_location_delete(client, args))
        elif command == "msgraph-identity-ip-named-locations-list":
            return_results(ip_named_location_list(client, args))
        elif command == "msgraph-identity-protection-risks-list":
            return_results(azure_ad_identity_protection_risk_detection_list(client, args))
        elif command == "msgraph-identity-protection-risky-user-list":
            return_results(azure_ad_identity_protection_risky_users_list(client, args))
        elif command == "msgraph-identity-protection-risky-user-history-list":
            return_results(azure_ad_identity_protection_risky_users_history_list(client, args))
        elif command == "msgraph-identity-protection-risky-user-confirm-compromised":
            return_results(azure_ad_identity_protection_confirm_compromised_command(client, args))
        elif command == "msgraph-identity-protection-risky-user-dismiss":
            return_results(azure_ad_identity_protection_risky_users_dismiss_command(client, args))
        elif command == "msgraph-identity-ca-policies-list":
            return_results(list_conditional_access_policies_command(client, args))
        elif command == "msgraph-identity-ca-policy-delete":
            return_results(delete_conditional_access_policy_command(client, args))
        elif command == "msgraph-identity-ca-policy-create":
            return_results(create_conditional_access_policy_command(client, args))
        elif command == "msgraph-identity-ca-policy-update":
            return_results(update_conditional_access_policy_command(client, args))
        elif command == "fetch-incidents":
            incidents, last_run = fetch_incidents(client, params)
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        else:
            raise NotImplementedError(f"Command '{command}' not found.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
