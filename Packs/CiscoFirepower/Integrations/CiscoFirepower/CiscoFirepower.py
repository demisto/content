import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
Cisco Firepower Management Center API Integration for Cortex XSOAR (aka Demisto).
"""
import copy
from http import HTTPStatus
from typing import Callable, Dict, List, MutableMapping, MutableSequence, Tuple, Union

from CommonServerUserPython import *  # pylint: disable=wildcard-import


''' GLOBAL/PARAMS '''  # pylint: disable=pointless-string-statement


INTEGRATION_NAME = 'Cisco Firepower'
INTEGRATION_CONTEXT_NAME = 'CiscoFP'
INTRUSION_POLICY_CONTEXT = 'IntrusionPolicy'
INTRUSION_RULE_CONTEXT = 'IntrusionRule'
INTRUSION_RULE_UPLOAD_CONTEXT = 'IntrusionRuleUpload'
INTRUSION_RULE_GROUP_CONTEXT = 'IntrusionRuleGroup'
NETWORK_ANALYSIS_POLICY_CONTEXT = 'NetworkAnalysisPolicy'
OUTPUT_KEYS_DICTIONARY = {
    'id': 'ID'
}

API_LIMIT = 1000
EXECUTION_TIMEOUT = 600

INTRUSION_POLICY_TITLE = 'Intrusion Policy Information'
INTRUSION_POLICY_HEADERS_BY_KEYS = {
    'ID': ['id'],
    'Name': ['name'],
    'Description': ['description'],
    'Detection': ['detection'],
    'Inspection Mode': ['inspectionMode'],
    'Base Policy ID': ['basePolicy', 'id'],
}
INTRUSION_RULE_TITLE = 'Intrusion Rule Information'
INTRUSION_RULE_HEADERS_BY_KEYS = {
    'ID': ['id'],
    'Name': ['name'],
    'Snort ID': ['sid'],
    'Revision': ['revision'],
    'Rule Data': ['ruleData'],
    'Rule Group': ['ruleGroups'],
}
INTRUSION_RULE_UPLOAD_TITLE = 'Intrusion Rule Upload Information'
INTRUSION_RULE_UPLOAD_HEADERS_BY_KEYS = {
    'Added Count': ['summary', 'added', 'count'],
    'Added Rules': ['summary', 'added', 'rules'],
    'Updated Count': ['summary', 'updated', 'count'],
    'Updated Rules': ['summary', 'updated', 'rules'],
    'Deleted Count': ['summary', 'deleted', 'count'],
    'Deleted Rules': ['summary', 'deleted', 'rules'],
    'Skipped Count': ['summary', 'skipped', 'count'],
    'Skipped Rules': ['summary', 'skipped', 'rules'],
    'Unassociated Count': ['summary', 'unassociated', 'count'],
    'Unassociated Rules': ['summary', 'unassociated', 'rules'],
}
INTRUSION_RULE_GROUP_TITLE = 'Intrusion Rule Group Information'
INTRUSION_RULE_GROUP_HEADERS_BY_KEYS = {
    'ID': ['id'],
    'Name': ['name'],
    'Description': ['description'],
}
NETWORK_ANALYSIS_POLICY_TITLE = 'Network Analysis Policy Information'
NETWORK_ANALYSIS_POLICY_HEADERS_BY_KEYS = {
    'ID': ['id'],
    'Name': ['name'],
    'Description': ['description'],
    'Inspection Mode': ['inspectionMode'],
    'Base Policy ID': ['basePolicy', 'id'],
    'Base Policy Name': ['basePolicy', 'name'],
}


def pagination(
    api_limit: int,
    items_key_path: list[str] = None,
    has_limit: Optional[bool] = True,
    has_offset: Optional[bool] = True,
    start_count_from_zero: Optional[bool] = True,
    default_limit: int = 50,
) -> Callable:
    """
    Pagination decorator wrapper to control functionality within the decorator.

    Args:
        api_limit (int): Maximum number of items that can be returned from the API request.
        items_key_path (list[str], optional): A list of keys to the items within an API response.
            Defaults to None.
        has_offset (Optional[bool]): Whether to use an "limit" in API requests.
            Defaults to True.
        has_offset (Optional[bool]): Whether to use an "offset" in API requests.
            Defaults to True.
        start_count_from_zero (Optional[bool]): Whether the count of the first item is 0 or 1.
            Defaults to True.

    Returns:
        Callable: Pagination decorator.
    """
    def dec(func: Callable) -> Callable:
        """
        Pagination decorator holding the callable function.

        Args:
            func (Callable): API request for list command.

        Returns:
            Callable: inner function that handles the pagination request.
        """

        def inner(
            self,
            page: Optional[int],
            page_size: Optional[int],
            limit: Optional[int],
            *args,
            **kwarg
        ) -> tuple[Union[list, dict], Union[list, dict]]:
            """
            Handle pagination arguments to return multiple response from an API.

            Args:
                page (Optional[int]): Page number to return.
                page_size (Optional[int]): Number of items to return in a page.
                limit (Optional[int]): Number of items to return.

            Raises:
                ValueError: In case the user has mixed between automatic and manual pagination arguments.

            Returns:
                tuple[Union[list, dict], Union[list, dict]]:
                    All the items combined within raw response, All the raw responses combined
            """
            is_automatic = bool(limit is not None and limit > 0)
            is_manual = bool((page is not None and page > 0) or (page_size is not None and page_size > 0))

            if all((is_manual, is_automatic)):
                raise ValueError('page or page_size can not be entered with limit.')

            remaining_items: int

            # Automatic Pagination
            if is_automatic and limit is not None:
                remaining_items = limit
                offset = None

            # Manual Pagination
            elif is_manual:
                page = page or 1
                page_size = page_size or default_limit

                remaining_items = page_size
                offset = (page - 1) * page_size + (0 if start_count_from_zero else 1)

            # No Pagination
            else:
                remaining_items = default_limit
                offset = None

            # API only supports limit parameter.
            if not has_offset:
                if has_limit:
                    limit = (offset or 0) + remaining_items

                    raw_response = func(
                        self,
                        limit=min(limit, api_limit),
                        *args,
                        **kwarg
                    )

                else:
                    raw_response = func(
                        self,
                        *args,
                        **kwarg
                    )

                items = raw_response

                if items_key_path:
                    items = dict_safe_get(items, items_key_path)

                if is_manual and page is not None:
                    stop = page * remaining_items
                    items = items[offset:stop]

                else:  # is_automatic or no pagination.
                    items = items[:remaining_items]

                return items, raw_response

            raw_items: list[dict[str, Any]] = []
            raw_responses: list[dict[str, Any]] = []

            # Keep calling the API until the required amount of items have been met.
            while remaining_items > 0:
                raw_response = func(
                    self,
                    limit=min(remaining_items, api_limit),
                    offset=offset,
                    *args,
                    **kwarg
                )

                raw_item = raw_response

                if items_key_path:
                    raw_item = dict_safe_get(raw_item, items_key_path)

                if raw_item is None:
                    break

                raw_responses.append(raw_response)
                raw_items += raw_item

                # Calculate the offset and limit for the next run.
                received_items = len(raw_item)
                remaining_items -= received_items
                offset = (offset or 0) + received_items

            return raw_items, raw_responses
        return inner
    return dec


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = False,
        proxy: bool = False
    ):
        """
        Initialize the client by generating a token.
        Add  the token to the headers and add the Domain UUID to the base URL.

        Args:
            server_url (str): Cisco Firepower URL.
            username (str): Username to connect to the server.
            password (str): Password to connect to the server.
            verify (bool, optional): SSL verification handled by BaseClient.
                Defaults to False.
            proxy (bool, optional): System proxy is handled by BaseClient.
                Defaults to False.
        """
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth=(username, password)
        )

        header = self._http_request(
            method='POST',
            url_suffix='api/fmc_platform/v1/auth/generatetoken',
            resp_type='response',
        ).headers

        auth_token: str = header['X-auth-access-token']
        domain_uuid: str = header['DOMAIN_UUID']

        self._base_url = urljoin(self._base_url, f'api/fmc_config/v1/domain/{domain_uuid}')
        self._headers = {
            'X-auth-access-token': auth_token,
        }

    def get_list(self, limit: int, offset: int, object_path: str) -> Dict:
        """
        Bridge command to list requests.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.
            object_path (str): Endpoint suffix.

        Returns:
            Dict: API response with the requested items.
        """
        params = {'expanded': 'true', 'limit': limit, 'offset': offset}
        suffix = f'object/{object_path}'
        return self._http_request('GET', suffix, params=params)

    def get_policy_assignments(self, policy_assignment_id: str) -> Dict[str, Any]:
        """
        Retrieves the policy assignment associated with the specified ID.

        Args:
            policy_assignment_id (str): ID of the policy assignment to retrieve.

        Returns:
            Dict[str, Any]: Information about the policy assignment.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'assignment/policyassignments/{policy_assignment_id}'
        )

    def list_policy_assignments(self, limit: int, offset: int) -> Dict:
        """
        Retrieves a list of all policy assignments to target devices.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.

        Returns:
            Dict: Information about policy assignments.
        """
        params = {'expanded': 'true', 'limit': limit, 'offset': offset}
        suffix = 'assignment/policyassignments'
        return self._http_request('GET', suffix, params=params)

    def get_deployable_devices(self, limit: int, offset: int, container_uuid: str) -> Dict:
        """
        Retrieves a list of all devices with configuration changes that are ready to deploy.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.
            container_uuid (str): Container Universally Unique Identifier.

        Returns:
            Dict: Information about deployable devices.
        """
        params = {'expanded': 'true', 'limit': limit, 'offset': offset}
        end_suffix = '/' + container_uuid + '/deployments' if container_uuid else ''
        suffix = f'deployment/deployabledevices{end_suffix}'
        return self._http_request('GET', suffix, params=params)

    def get_device_records(self, limit: int, offset: int) -> Dict:
        """
        Retrieves a list of all device records.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.

        Returns:
            Dict: Information about device records.
        """
        params = {'expanded': 'true', 'limit': limit, 'offset': offset}
        suffix = 'devices/devicerecords'
        return self._http_request('GET', suffix, params=params)

    def get_network_objects(self, limit: int, offset: int, object_id: str) -> Dict:
        """
        Retrieves the network objects associated with the specified ID.
        If not supplied, retrieves a list of all network objects.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.
            object_id (str): Network object ID.

        Returns:
            Dict: Information about network objects.
        """
        end_suffix = f'/{object_id}' if object_id else f'?expanded=true&limit={limit}&offset={offset}'
        suffix = f'object/networks{end_suffix}'
        return self._http_request('GET', suffix)

    def get_hosts_objects(self, limit: int, offset: int, object_id: str) -> Dict:
        """
        Retrieves the groups of host objects associated with the specified ID.
        If no ID is passed, the input ID retrieves a list of all network objects.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.
            object_id (str): Host object ID.

        Returns:
            Dict: Information about host objects.
        """
        end_suffix = f'/{object_id}' if object_id else f'?expanded=true&limit={limit}&offset={offset}'
        suffix = f'object/hosts{end_suffix}'
        return self._http_request('GET', suffix)

    def create_network_objects(self, name: str, value: str, description: str, overridable: bool) -> Dict:
        """
        Create a network object.

        Args:
            name (str): The name of the new object.
            value (str): CIDR.
            description (str): The object description.
            overridable (bool): Boolean indicating whether objects can be overridden.

        Returns:
            Dict: Information about the created network
        """
        data = {'name': name, 'value': value, 'description': description, 'overridable': overridable}
        suffix = 'object/networks'
        return self._http_request('POST', suffix, json_data=data)

    def create_host_objects(self, name: str, value: str, description: str, overridable: bool) -> Dict:
        """
        Create a host object.

        Args:
            name (str): The name of the new object.
            value (str): The IP address.
            description (str): A description of the new object.
            overridable (bool): Boolean indicating whether object values can be overridden.

        Returns:
            Dict: Information about the created host.
        """
        data = {'name': name, 'value': value, 'description': description, 'overridable': overridable}
        suffix = 'object/hosts'
        return self._http_request('POST', suffix, json_data=data)

    def update_network_objects(
            self, name: str, value: str, description: str, overridable: bool, object_id: str) -> Dict:
        """
        Update the specified network object.

        Args:
            name (str): The object name.
            value (str): CIDR.
            description (str): The object description.
            overridable (bool): Boolean indicating whether the object can be overridden.
            object_id (str): ID of the object to update.

        Returns:
            Dict: Information about the updated network.
        """
        data = assign_params(id=object_id, name=name, value=value, description=description, overridable=overridable)
        suffix = f'object/networks/{object_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def update_host_objects(self, name: str, value: str, description: str, overridable: bool, object_id: str) -> Dict:
        """
        Update the specified host object.

        Args:
            name (str): Name of the object.
            value (str): The IP address.
            description (str): Description of the object.
            overridable (bool): Boolean indicating whether object values can be overridden.
            object_id (str): ID of the object to update.

        Returns:
            Dict: Information about the updated host.
        """
        data = assign_params(id=object_id, name=name, value=value, description=description, overridable=overridable)
        suffix = f'object/hosts/{object_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def delete_network_objects(self, object_id: str) -> Dict:
        """
        Delete the specified network object.

        Args:
            object_id (str): ID of the object to delete.

        Returns:
            Dict: Information about the deleted object.
        """
        suffix = f'object/networks/{object_id}'
        return self._http_request('DELETE', suffix)

    def delete_host_objects(self, object_id: str) -> Dict:
        """
        Delete the specified host object.

        Args:
            object_id (str): ID of the host object to delete.

        Returns:
            Dict: Information about the deleted host.
        """
        suffix = f'object/hosts/{object_id}'
        return self._http_request('DELETE', suffix)

    def get_network_groups_objects(self, limit: int, offset: int, object_id: str) -> Dict:
        """
        Retrieves the groups of network objects and addresses associated with the specified ID.
        If not supplied, retrieves a list of all network objects.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.
            object_id (str): ID of the object group for which to return groups and addresses.

        Returns:
            Dict: Information about network groups.
        """
        end_suffix = f'/{object_id}' if object_id else f'?expanded=true&limit={limit}&offset={offset}'
        suffix = f'object/networkgroups{end_suffix}'
        return self._http_request('GET', suffix)

    def get_url_groups_objects(self, limit: int, offset: int, object_id: str) -> Dict:
        """
        Retrieves the groups of url objects and addresses associated with the specified ID.
        If not supplied, retrieves a list of all url objects.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.
            object_id (str): ID of the group. If not supplied, retrieves a list of all url objects.

        Returns:
            Dict: Information about url groups.
        """
        end_suffix = f'/{object_id}' if object_id else f'?expanded=true&limit={limit}&offset={offset}'
        suffix = f'object/urlgroups{end_suffix}'
        return self._http_request('GET', suffix)

    def create_network_groups_objects(
            self, name: str, ids: str, values: str, description: str, overridable: bool) -> Dict:
        """
        Creates a group of network objects.

        Args:
            name (str): The group name.
            ids (str): A comma-separated list of object IDs to add to the group.
            values (str): A comma-separated list of IP addresses or CIDR ranges to add the group.
            description (str): The object description.
            overridable (bool): Boolean indicating whether object values can be overridden.

        Returns:
            Dict: Information about the created network group.
        """
        objects = [{'id': curr_id} for curr_id in argToList(ids)]
        values = [{'value': curr_value} for curr_value in argToList(values)]
        data = assign_params(
            name=name, objects=objects, literals=values, description=description, overridable=overridable)
        suffix = 'object/networkgroups'
        return self._http_request('POST', suffix, json_data=data)

    def update_network_groups_objects(
            self, name: str, ids: str, values: str, group_id: str, description: str, overridable: bool) -> Dict:
        """
        Updates a group of network objects.

        Args:
            name (str): The group name.
            ids (str): A comma-separated list of object IDs to add the group.
            values (str): A comma-separated list of IP addresses or CIDR ranges to add the group.
            group_id (str): The ID of the group to update.
            description (str): The new description for the object.
            overridable (bool): Boolean indicating whether object values can be overridden.

        Returns:
            Dict: Information about the updated group.
        """
        objects = [{'id': curr_id} for curr_id in argToList(ids)]
        values = [{'value': curr_value} for curr_value in argToList(values)]
        data = assign_params(name=name, id=group_id, objects=objects, literals=values,
                             description=description, overridable=overridable)
        suffix = f'object/networkgroups/{group_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def update_url_groups_objects(
            self, name: str, ids: str, values: str, group_id: str, description: str, overridable: bool) -> Dict:
        """
        Update the ID of a group of url objects.

        Args:
            name (str): The group name.
            ids (str): A comma-separated list of object IDs to add the url.
            values (str): A comma-separated list of url to add the group.
            group_id (str): The ID of the group to update.
            description (str): The new description for the object.
            overridable (bool): Boolean indicating whether object values can be overridden.

        Returns:
            Dict: Information about the updated url group.
        """
        objects = [{'id': curr_id} for curr_id in argToList(ids)]
        values = [{'url': curr_value} for curr_value in argToList(values)]
        data = assign_params(name=name, id=group_id, objects=objects, literals=values,
                             description=description, overridable=overridable)
        suffix = f'object/urlgroups/{group_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def delete_network_groups_objects(self, object_id: str) -> Dict:
        """
        Deletes a group of network objects.

        Args:
            object_id (str): ID of the object to delete.

        Returns:
            Dict: Information about the deleted network group.
        """
        suffix = f'object/networkgroups/{object_id}'
        return self._http_request('DELETE', suffix)

    def get_access_policy(self, limit: int, offset: int, policy_id: str) -> Dict:
        """
        Retrieves the access control policy associated with the specified ID.
        If no access policy ID is passed, all access control policies are returned.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.
            policy_id (str): ID of the access policy.

        Returns:
            Dict: Information about access policies.
        """
        end_suffix = f'/{policy_id}' if policy_id else f'?expanded=true&limit={limit}&offset={offset}'
        suffix = f'policy/accesspolicies{end_suffix}'
        return self._http_request('GET', suffix)

    def create_access_policy(self, name: str, action: str) -> Dict:
        """
        Create an access control policy.

        Args:
            name (str): The name of the new access policy.
            action (str): The action to take. Can be "BLOCK", "TRUST", "PERMIT", or "NETWORK_DISCOVERY".

        Returns:
            Dict: Information about the created access policy.
        """
        data = {'name': name, 'defaultAction': {'action': action}}
        suffix = 'policy/accesspolicies'
        return self._http_request('POST', suffix, json_data=data)

    def update_access_policy(self, name: str, policy_id: str, action: str, action_id: str) -> Dict:
        """
        Update the specified access control policy.

        Args:
            name (str): The access policy name.
            policy_id (str): ID of the access policy.
            action (str): The action to take. Can be "BLOCK", "TRUST", "PERMIT", or "NETWORK_DISCOVERY".
            action_id (str): ID of the default action.

        Returns:
            Dict: Information about the updated access policy.
        """
        data = {
            'name': name,
            'id': policy_id,
            'defaultAction': {
                'action': action,
                'id': action_id
            }}
        suffix = f'policy/accesspolicies/{policy_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def delete_access_policy(self, policy_id: str) -> Dict:
        """
        Deletes the specified access control policy.

        Args:
            policy_id (str): ID of the access policy.

        Returns:
            Dict: Information about the deleted access policy.
        """
        suffix = f'policy/accesspolicies/{policy_id}'
        return self._http_request('DELETE', suffix)

    def get_task_status(self, task_id: str) -> Dict:
        """
        The ID of the task for which to check the status.

        Args:
            task_id (str): Retrieves information about a previously submitted pending job or task with the specified ID.
                Used for deploying.

        Returns:
            Dict: Information about the task status.
        """
        suffix = f'job/taskstatuses/{task_id}'
        return self._http_request('GET', suffix)

    def create_policy_assignments(self, policy_id: str, device_ids: str, device_group_ids: str) -> Dict:
        """
        Creates policy assignments to target devices.

        Args:
            policy_id (str): The policy ID.
            device_ids (str): A list of device IDs.
            device_group_ids (str): A list of device group IDs.

        Returns:
            Dict: Information about the created policy assignment.
        """
        targets = [{'id': curr_id, 'type': 'Device'} for curr_id in argToList(device_ids)]
        targets.extend([{'id': curr_id, 'type': 'DeviceGroup'} for curr_id in argToList(device_group_ids)])
        data_to_post = assign_params(policy={'id': policy_id}, type='PolicyAssignment', targets=targets)
        suffix = 'assignment/policyassignments'
        return self._http_request('POST', suffix, json_data=data_to_post)

    def update_policy_assignments(self, policy_id: str, device_ids: str, device_group_ids: str) -> Dict:
        """
        Update the specified policy assignments to target devices.

        Args:
            policy_id (str): The policy ID.
            device_ids (str): A list of device IDs.
            device_group_ids (str): A list of device group IDs.

        Returns:
            Dict: Information about the updated policy assignment.
        """
        targets = [{'id': curr_id, 'type': 'Device'} for curr_id in argToList(device_ids)]
        targets.extend([{'id': curr_id, 'type': 'DeviceGroup'} for curr_id in argToList(device_group_ids)])
        data_to_post = assign_params(policy={'id': policy_id}, type='PolicyAssignment', targets=targets)
        suffix = f'assignment/policyassignments/{policy_id}'
        return self._http_request('PUT', suffix, json_data=data_to_post)

    def get_access_rules(self, limit: int, offset: int, policy_id: str, rule_id: str) -> Dict:
        """
        Retrieves the access control rule associated with the specified policy ID and rule ID.
        If no rule ID is specified, retrieves a list of all access rules associated with the specified policy ID.

        Args:
            limit (int): Maximum number of items to return.
            offset (int): Item number to start looking from.
            policy_id (str): Policy ID.
            rule_id (str): Rule ID.

        Returns:
            Dict: Information about access rules.
        """
        end_suffix = f'?expanded=true&limit={limit}&offset={offset}' if rule_id == '' else '/' + rule_id
        suffix = f'policy/accesspolicies/{policy_id}/accessrules{end_suffix}'
        return self._http_request('GET', suffix)

    def create_access_rules(
            self,
            source_zone_object_ids: str,
            destination_zone_object_ids: str,
            vlan_tag_object_ids: str,
            source_network_object_ids: str,
            source_network_addresses: str,
            destination_network_object_ids: str,
            destination_network_addresses: str,
            source_port_object_ids: str,
            destination_port_object_ids: str,
            source_security_group_tag_object_ids: str,
            application_object_ids: str,
            url_object_ids: str,
            url_addresses: str,
            enabled: bool,
            name: str,
            policy_id: str,
            action: str
    ) -> Dict:
        """
        Creates an access control rule.

        Args:
            source_zone_object_ids (str): A list of source zones object IDs.
            destination_zone_object_ids (str): A list of destination zones object IDs.
            vlan_tag_object_ids (str): A list of vlan tag object IDs.
            source_network_object_ids (str): A list of source network object IDs.
            source_network_addresses (str): A list of addresses.
            destination_network_object_ids (str): A list of destination network object IDs.
            destination_network_addresses (str): A list of addresses.
            source_port_object_ids (str): A list of port object IDs.
            destination_port_object_ids (str): A list of port object IDs.
            source_security_group_tag_object_ids (str): A list of security group tag object IDs.
            application_object_ids (str):A list of application object IDs.
            url_object_ids (str): A list of URL object IDs.
            url_addresses (str): A list of URL addresses.
            enabled (bool): Boolean indicating whether to enable the rule.
            name (str): The rule name.
            policy_id (str): The policy ID for which to create the new rule.
            action (str): The rule action that determines how the system handles matching traffic.
                Can be "ALLOW", "TRUST", "BLOCK", "MONITOR", "BLOCK_RESET", "BLOCK_INTERACTIVE", or
                "BLOCK_RESET_INTERACTIVE".

        Returns:
            Dict: Information about the created access rule.
        """
        sourceZones = {'objects': [{'id': curr_id, 'type': 'SecurityZone'
                                    } for curr_id in argToList(source_zone_object_ids)]}
        destinationZones = {'objects': [{'id': curr_id, 'type': 'SecurityZone'
                                         } for curr_id in argToList(destination_zone_object_ids)]}
        vlanTags = {'objects': [{'id': curr_id, 'type': 'vlanTags'} for curr_id in argToList(vlan_tag_object_ids)]}
        sourceNetworks = assign_params(
            objects=[{'id': curr_id, 'type': 'NetworkGroup'} for curr_id in argToList(source_network_object_ids)],
            literals=[{'value': curr_id, 'type': 'Host'} for curr_id in argToList(source_network_addresses)])
        destinationNetworks = assign_params(
            objects=[{'id': curr_id, 'type': 'NetworkGroup'} for curr_id in argToList(destination_network_object_ids)],
            literals=[{'value': curr_id, 'type': 'Host'} for curr_id in argToList(destination_network_addresses)])
        sourcePorts = {'objects': [{'id': curr_id, 'type': 'ProtocolPortObject'
                                    } for curr_id in argToList(source_port_object_ids)]}
        destinationPorts = {'objects': [{'id': curr_id, 'type': 'ProtocolPortObject'
                                         } for curr_id in argToList(destination_port_object_ids)]}
        sourceSecurityGroupTags = {'objects': [{'id': curr_id, 'type': 'SecurityGroupTag'
                                                } for curr_id in argToList(source_security_group_tag_object_ids)]}
        applications = {'applications': [{'id': curr_id, 'type': 'Application'
                                          } for curr_id in argToList(application_object_ids)]}
        urls = assign_params(
            objects=[{'id': curr_id, 'type': 'Url'} for curr_id in argToList(url_object_ids)],
            literals=[{'url': curr_id, 'type': 'Url'} for curr_id in argToList(url_addresses)])
        data = assign_params(name=name, action=action, enabled=enabled, sourceZones=sourceZones,
                             destinationZones=destinationZones, vlanTags=vlanTags, sourceNetworks=sourceNetworks,
                             destinationNetworks=destinationNetworks, sourcePorts=sourcePorts,
                             destinationPorts=destinationPorts, sourceSecurityGroupTags=sourceSecurityGroupTags,
                             applications=applications, urls=urls)
        suffix = f'policy/accesspolicies/{policy_id}/accessrules'
        return self._http_request('POST', suffix, json_data=data)

    def update_access_rules(
            self,
            update_strategy: str,
            source_zone_object_ids: str,
            destination_zone_object_ids: str,
            vlan_tag_object_ids: str,
            source_network_object_ids: str,
            source_network_addresses: str,
            destination_network_object_ids: str,
            destination_network_addresses: str,
            source_port_object_ids: str,
            destination_port_object_ids: str,
            source_security_group_tag_object_ids: str,
            application_object_ids: str,
            url_object_ids: str,
            url_addresses: str,
            enabled: bool,
            name: str,
            policy_id: str,
            action: str,
            rule_id: str
    ) -> Dict:
        """
        Update the specified access control rule.

        Args:
            update_strategy (str): The method by which to update the rule. Can be "merge" or "override".
                If merge, will add the changes requested to the existing rule.
                If override, will override the fields with the inputs provided and will delete any fields that were
                not provided.
            source_zone_object_ids (str): A list of source zones object IDs.
            destination_zone_object_ids (str): A list of destination zones object IDs.
            vlan_tag_object_ids (str): A list of vlan tag object IDs.
            source_network_object_ids (str): A list of source network object IDs.
            source_network_addresses (str): A list of addresses.
            destination_network_object_ids (str): A list of destination network object IDs.
            destination_network_addresses (str): A list of addresses.
            source_port_object_ids (str): A list of port object IDs.
            destination_port_object_ids (str): A list of port object IDs.
            source_security_group_tag_object_ids (str): A list of security group tag object IDs.
            application_object_ids (str):A list of application object IDs.
            url_object_ids (str): A list of URL object IDs.
            url_addresses (str): A list of URL addresses.
            enabled (bool): Boolean indicating whether to enable the rule.
            name (str): The rule name.
            policy_id (str): The policy ID for which to create the new rule.
            action (str): The rule action that determines how the system handles matching traffic.
                Can be "ALLOW", "TRUST", "BLOCK", "MONITOR", "BLOCK_RESET", "BLOCK_INTERACTIVE", or
                "BLOCK_RESET_INTERACTIVE".

        Returns:
            Dict: Information about the updated access rule.
        """
        suffix = f'policy/accesspolicies/{policy_id}/accessrules/{rule_id}'

        sourceZones = assign_params(
            objects=[{'id': curr_id, 'type': 'SecurityZone'} for curr_id in argToList(source_zone_object_ids)])
        destinationZones = assign_params(
            objects=[{'id': curr_id, 'type': 'SecurityZone'} for curr_id in argToList(destination_zone_object_ids)])
        vlanTags = assign_params(
            objects=[{'id': curr_id, 'type': 'vlanTags'} for curr_id in argToList(vlan_tag_object_ids)])
        sourceNetworks = assign_params(
            objects=[{'id': curr_id, 'type': 'NetworkGroup'} for curr_id in argToList(source_network_object_ids)],
            literals=[{'value': curr_id, 'type': 'Host'} for curr_id in argToList(source_network_addresses)])
        destinationNetworks = assign_params(
            objects=[{'id': curr_id, 'type': 'NetworkGroup'} for curr_id in argToList(destination_network_object_ids)],
            literals=[{'value': curr_id, 'type': 'Host'} for curr_id in argToList(destination_network_addresses)])
        sourcePorts = assign_params(
            objects=[{'id': curr_id, 'type': 'ProtocolPortObject'} for curr_id in argToList(source_port_object_ids)])
        destinationPorts = assign_params(
            objects=[{'id': curr_id, 'type': 'ProtocolPortObject'} for curr_id in
                     argToList(destination_port_object_ids)])
        sourceSecurityGroupTags = assign_params(objects=[{'id': curr_id, 'type': 'SecurityGroupTag'} for curr_id in
                                                         argToList(source_security_group_tag_object_ids)])
        applications = assign_params(
            applications=[{'id': curr_id, 'type': 'Application'} for curr_id in argToList(application_object_ids)])
        urls = assign_params(
            objects=[{'id': curr_id, 'type': 'Url'} for curr_id in argToList(url_object_ids)],
            literals=[{'url': curr_id, 'type': 'Url'} for curr_id in argToList(url_addresses)])
        data = assign_params(name=name, action=action, id=rule_id, enabled=enabled, sourceZones=sourceZones,
                             destinationZones=destinationZones, vlanTags=vlanTags, sourceNetworks=sourceNetworks,
                             destinationNetworks=destinationNetworks, sourcePorts=sourcePorts,
                             destinationPorts=destinationPorts, sourceSecurityGroupTags=sourceSecurityGroupTags,
                             applications=applications, urls=urls)

        data_from_get = self.get_access_rules(0, 0, rule_id=rule_id, policy_id=policy_id)
        if update_strategy == 'override':
            if 'name' not in data:
                data['name'] = data_from_get.get('name')
            if 'action' not in data:
                data['action'] = data_from_get.get('action')
            return self._http_request('PUT', suffix, json_data=data)
        else:
            for key, value in data.items():
                if type(value) is dict:
                    for in_key in value:
                        if in_key in data_from_get[key]:
                            data_from_get[key][in_key].extend(value[in_key])
                        else:
                            data_from_get[key][in_key] = value[in_key]
                else:
                    data_from_get[key] = value
            del data_from_get['metadata']
            del data_from_get['links']
            return self._http_request('PUT', suffix, json_data=data_from_get)

    def delete_access_rules(self, policy_id, rule_id) -> Dict:
        suffix = f'policy/accesspolicies/{policy_id}/accessrules/{rule_id}'
        return self._http_request('DELETE', suffix)

    def deploy_to_devices(self, force_deploy, ignore_warning, version, device_ids) -> Dict:
        data_to_post = assign_params(forceDeploy=force_deploy, ignoreWarning=ignore_warning, version=version,
                                     deviceList=argToList(device_ids), type="DeploymentRequest")
        suffix = 'deployment/deploymentrequests'
        return self._http_request('POST', suffix, json_data=data_to_post)

    def create_intrusion_policy(
        self,
        name: str,
        basepolicy_id: str,
        description: str = None,
        inspection_mode: str = None
    ) -> Dict[str, Any]:
        """
        Creates an Intrusion Policy with the specified parameters.

        Args:
            name (str): Name of the Intrusion Policy.
            basepolicy_id (str): Unique identifier representing the base policy.
            description (str, optional): Description of the Intrusion Policy.
                Defaults to None.
            inspection_mode (str, optional): Indicates the inspection mode. Can be either DETECTION or PREVENTION.
                Defaults to None.

        Returns:
            Dict[str, Any]: New Intrusion Policy's information.
        """
        body: Dict[str, Any] = remove_empty_elements({
            'name': name,
            'description': description,
            'inspection_mode': inspection_mode,
            'basePolicy': {
                'id': basepolicy_id
            }
        })

        return self._http_request(
            method='POST',
            url_suffix='policy/intrusionpolicies',
            json_data=body,
            timeout=EXECUTION_TIMEOUT,
        )

    def get_intrusion_policy(self, intrusion_policy_id: str, include_count: bool = None) -> Dict[str, Any]:
        """
        Retrieves the intrusion policy associated with the specified ID.

        Args:
            intrusion_policy_id (str): Identifier for intrusion policy.
            include_count (bool, optional): Whether the count of rules should be calculated in the response.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about the specific intrusion policy
        """
        params = assign_params(
            includeCount=include_count
        )

        return self._http_request(
            method='GET',
            url_suffix=f'policy/intrusionpolicies/{intrusion_policy_id}',
            params=params,
        )

    @pagination(api_limit=API_LIMIT, items_key_path=['items'])
    def list_intrusion_policy(
        self,
        limit: int = None,
        offset: int = None,
        expanded_response: bool = None
    ) -> Dict[str, Any]:
        """
        Retrieves a list of intrusion policies.

        Args:
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.
            expanded_response (bool, optional): If set to true,
                the response displays a list of objects with additional attributes.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about intrusion policies.
        """
        params = assign_params(
            limit=limit,
            offset=offset,
            expanded=expanded_response,
        )

        return self._http_request(
            method='GET',
            url_suffix='policy/intrusionpolicies',
            params=params,
        )

    def update_intrusion_policy(
        self,
        intrusion_policy_id: str,
        name: str,
        basepolicy_id: str,
        description: str = None,
        inspection_mode: str = None,
        replicate_inspection_mode: bool = None,
    ) -> Dict[str, Any]:
        """
        Modifies the Intrusion Policy associated with the specified ID.

        Args:
            intrusion_policy_id (str): Identifier for Intrusion Policy.
            name (str): Name of the Intrusion Policy.
            basepolicy_id (str): Unique identifier representing the base policy.
            description (str, optional): Description of the Intrusion Policy.
                Defaults to None.
            inspection_mode (str, optional): Indicates the inspection mode. Can be either DETECTION or PREVENTION.
                Only applicable for Snort 3 engine.
                Defaults to None.
            replicate_inspection_mode (bool, optional):
                Flag to replicate inspection mode from snort 3 version to snort 2 version.
                Defaults to None.

        Returns:
            Dict[str, Any]: Updated Intrusion Policy information.
        """
        params = assign_params(
            replicateInspectionMode=replicate_inspection_mode
        )
        body: Dict[str, Any] = remove_empty_elements({
            'id': intrusion_policy_id,
            'name': name,
            'description': description,
            'inspection_mode': inspection_mode,
            'basePolicy': {
                'id': basepolicy_id
            }
        })

        return self._http_request(
            method='PUT',
            url_suffix=f'policy/intrusionpolicies/{intrusion_policy_id}',
            params=params,
            json_data=body,
            timeout=EXECUTION_TIMEOUT,
        )

    def delete_intrusion_policy(
        self,
        intrusion_policy_id: str
    ) -> Dict[str, Any]:
        """
        Deletes the Intrusion Policy associated with the specified ID.

        Args:
            intrusion_policy_id (str): Identifier for Intrusion Policy.

        Returns:
            Dict[str, Any]: Information about the deleted Intrusion Policy.
        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'policy/intrusionpolicies/{intrusion_policy_id}',
        )

    def create_intrusion_rule(
            self,
            rule_data: str,
            rule_group_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Creates or overrides the Snort3 Intrusion rule group with the specified parameters.

        Args:
            rule_data (str): Snort Rule structure data.
            rule_group_ids (str): Unique identifier representing the rule group.

        Returns:
            Dict[str, Any]: New Intrusion Rule's information.
        """
        body: Dict[str, Any] = {
            'ruleData': rule_data,
            'ruleGroups': [
                {
                    'id': rule_group_id
                } for rule_group_id in rule_group_ids
            ]
        }

        return self._http_request(
            method='POST',
            url_suffix='object/intrusionrules',
            json_data=body,
        )

    def update_intrusion_rule(
            self,
            intrusion_rule_id: str,
            rule_data: str,
            rule_group_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Modifies the Snort3 Intrusion rule group with the specified ID.

        Args:
            intrusion_rule_id (str): Identifier of a Snort 3 intrusion rule.
            rule_data (str): Snort Rule structure data.
            rule_group_ids (str): Unique identifier representing the rule group.

        Returns:
            Dict[str, Any]: Modified Intrusion Rule's information.
        """
        body: Dict[str, Any] = {
            'id': intrusion_rule_id,
            'ruleData': rule_data,
            'ruleGroups': [
                {
                    'id': rule_group_id
                } for rule_group_id in rule_group_ids
            ]
        }

        return self._http_request(
            method='PUT',
            url_suffix=f'object/intrusionrules/{intrusion_rule_id}',
            json_data=body,
        )

    def delete_intrusion_rule(
            self,
            intrusion_rule_id: str,
    ) -> Dict[str, Any]:
        """
        Deletes the specified Snort3 rule.

        Args:
            intrusion_rule_id (str): Identifier of a Snort 3 intrusion rule.

        Returns:
            Dict[str, Any]: Deleted Intrusion Rule's information.
        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'object/intrusionrules/{intrusion_rule_id}',
        )

    def get_intrusion_rule(self, intrusion_rule_id: str) -> Dict[str, Any]:
        """
        Retrieves the Snort3 Intrusion rule group.

        Args:
            intrusion_rule_id (str): Identifier of a Snort 3 intrusion rule.

        Returns:
            Dict[str, Any]: Information about the specific intrusion rule.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'object/intrusionrules/{intrusion_rule_id}',
        )

    @pagination(api_limit=API_LIMIT, items_key_path=['items'], start_count_from_zero=False)
    def list_intrusion_rule(
        self,
        limit: int = None,
        offset: int = None,
        sort: List[str] = None,
        filter_string: str = None,
        expanded_response: bool = None,
    ) -> Dict[str, Any]:
        """
        Retrieves a list of intrusion policies.

        Args:
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.
            sort (List[str], optional): Sorting parameters to be provided e.g. sid,-sid,gid,-gid,msg,-msg.
                Defaults to None.
            filter_string (str, optional): Filter the list with arguments.
                Defaults to None.
            expanded_response (bool, optional): If set to true,
                the response displays a list of objects with additional attributes.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about intrusion rules.
        """
        params = assign_params(
            limit=limit,
            offset=offset,
            sort=','.join(sort) if sort else None,
            filter=filter_string,
            expanded=expanded_response,
        )

        return self._http_request(
            method='GET',
            url_suffix='object/intrusionrules',
            params=params,
        )

    def upload_intrusion_rule_file(
        self,
        filename: str,
        payload_file: str,
        validate_only: bool,
        rule_import_mode: str = None,
        rule_group_ids: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Imports or validate custom Snort 3 intrusion rules within a file.

        Args:
            filename (str): Name of the file containing the custom Snort 3 intrusion rules.
                .rules and .txt are supported file formats.
            payload_file (bytes): File containing the custom Snort 3 intrusion rules.
                .rules and .txt are supported file formats.
            validate_only (bool): Boolean identifier to validate or import rules. True is the default value.
            rule_import_mode (str, optional): Merge or replace the rules in the rulegroups.
                Defaults to None.
            rule_group_ids (List[str], optional): Rule groups to which rules should be associated.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about the intrusion rules format or about the merged/replaced intrusion rules.
        """
        form_data = remove_empty_elements({
            'payloadFile': (filename, payload_file),
            'ruleImportMode': rule_import_mode,
            'ruleGroups': ','.join(rule_group_ids) if rule_group_ids else None,
            'validateOnly': validate_only,
        })

        ok_codes = (
            HTTPStatus.OK,
            HTTPStatus.CREATED,
            HTTPStatus.UNPROCESSABLE_ENTITY,
        )

        return self._http_request(
            method='POST',
            url_suffix='object/intrusionrulesupload',
            files=form_data,
            ok_codes=ok_codes,
        )

    def create_intrusion_rule_group(
        self,
        name: str,
        description: str = None,
    ) -> Dict[str, Any]:
        """
        Creates or overrides the Snort3 Intrusion rule group with the specified parameters.

        Args:
            name (str): Name of the Snort 3 intrusion rulegroup.
            description (str, optional): Description of the Snort 3 intrusion rulegroup.
                Defaults to None.

        Returns:
            Dict[str, Any]: New Intrusion Rule Group's information.
        """
        body: Dict[str, Any] = remove_empty_elements({
            'name': name,
            'description': description,
        })

        return self._http_request(
            method='POST',
            url_suffix='object/intrusionrulegroups',
            json_data=body,
        )

    def get_intrusion_rule_group(self, rule_group_id: str) -> Dict[str, Any]:
        """
        Retrieves the Snort3 Intrusion rule group.

        Args:
            rule_group_id (str): Identifier of a Snort 3 intrusion rulegroup.

        Returns:
            Dict[str, Any]: Information about the specific intrusion rule group.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'object/intrusionrulegroups/{rule_group_id}',
        )

    @pagination(api_limit=API_LIMIT, items_key_path=['items'], start_count_from_zero=False)
    def list_intrusion_rule_group(
        self,
        limit: int = None,
        offset: int = None,
        filter_string: str = None,
        expanded_response: bool = None,
    ) -> Dict[str, Any]:
        """
        Retrieves a list of all Snort3 Intrusion rule groups.

        Args:
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.
            filter_string (str, optional): Filter the list with arguments.
                Defaults to None.
            expanded_response (bool, optional): If set to true,
                the response displays a list of objects with additional attributes.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about intrusion rule groups.
        """
        params = assign_params(
            limit=limit,
            offset=offset,
            filter=filter_string,
            expanded=expanded_response,
        )

        return self._http_request(
            method='GET',
            url_suffix='object/intrusionrulegroups',
            params=params,
        )

    def update_intrusion_rule_group(
        self,
        rule_group_id: str,
        name: str,
        description: str = None,
    ) -> Dict[str, Any]:
        """
        Modifies the Snort3 Intrusion rule group with the specified ID.

        Args:
            rule_group_id (str): Identifier of a Snort 3 intrusion rulegroup.
            name (str): Name of the Snort 3 intrusion rulegroup.
            description (str, optional): Description of the Snort 3 intrusion rulegroup.
                Defaults to None.

        Returns:
            Dict[str, Any]: Modified Intrusion Rule Group's information.
        """
        body: Dict[str, Any] = remove_empty_elements({
            'id': rule_group_id,
            'name': name,
            'description': description,
        })

        return self._http_request(
            method='PUT',
            url_suffix=f'object/intrusionrulegroups/{rule_group_id}',
            json_data=body,
        )

    def delete_intrusion_rule_group(
        self,
        rule_group_id: str,
        delete_related_rules: bool = None,
    ) -> Dict[str, Any]:
        """
        Deletes the specified Snort3 intrusion rule group.

        Args:
            rule_group_id (str): Identifier of a Snort 3 intrusion rulegroup.
            delete_related_rules (bool, optional): Boolean value for deleting orphan rules.
                Mandatory if custom rulegroup has unique/unshared rules which becomes orphan
                after custom rule Group delete.
                Defaults to None.

        Returns:
            Dict[str, Any]: Deleted Intrusion Rule Group's information.
        """
        params = assign_params(
            cascadeDeleteOrphanedRules=delete_related_rules
        )

        return self._http_request(
            method='DELETE',
            url_suffix=f'object/intrusionrulegroups/{rule_group_id}',
            params=params,
        )

    def create_network_analysis_policy(
        self,
        name: str,
        basepolicy_id: str,
        description: str = None,
        inspection_mode: str = None,
    ) -> Dict[str, Any]:
        """
        Creates a network analysis policy.

        Args:
            name (str): Name of the Network Analysis Policy.
            basepolicy_id (str): Unique identifier representing the base network analysis policy.
            description (str, optional): Description of the Network Analysis Policy.
                Defaults to None.
            inspection_mode (str, optional): Indicates the inspection mode. Can be either DETECTION or PREVENTION.
                Only applicable for Snort 3 engine.
                Defaults to None.

        Returns:
            Dict[str, Any]: New network analysis policy's information.
        """
        body: Dict[str, Any] = remove_empty_elements({
            'name': name,
            'description': description,
            'inspectionMode': inspection_mode,
            'basePolicy': {
                'id': basepolicy_id
            },
        })

        return self._http_request(
            method='POST',
            url_suffix='policy/networkanalysispolicies',
            json_data=body,
            timeout=EXECUTION_TIMEOUT,
        )

    def get_network_analysis_policy(self, network_analysis_policy_id: str) -> Dict[str, Any]:
        """
        Retrieves the network analysis policy with the specified ID

        Args:
            network_analysis_policy_id (str): Unique identifier of the Network Analysis Policy.

        Returns:
            Dict[str, Any]: Information about the specific network analysis policy.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'policy/networkanalysispolicies/{network_analysis_policy_id}',
        )

    @pagination(api_limit=API_LIMIT, items_key_path=['items'])
    def list_network_analysis_policy(
        self,
        limit: int = None,
        offset: int = None,
        expanded_response: bool = None,
    ) -> Dict[str, Any]:
        """
        Retrieves list of all network analysis policies.

        Args:
            limit (int, optional): Maximum number of items to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.
            expanded_response (bool, optional): If set to true,
                the response displays a list of objects with additional attributes.
                Defaults to None.

        Returns:
            Dict[str, Any]: Information about network analysis policies.
        """
        params = assign_params(
            limit=limit,
            offset=offset,
            expanded=expanded_response,
        )

        return self._http_request(
            method='GET',
            url_suffix='policy/networkanalysispolicies',
            params=params,
        )

    def update_network_analysis_policy(
        self,
        network_analysis_policy_id: str,
        name: str,
        basepolicy_id: str,
        description: str = None,
        inspection_mode: str = None,
        replicate_inspection_mode: bool = None,
    ) -> Dict[str, Any]:
        """
        Modifies the network analysis policy associated with the specified ID.

        Args:
            network_analysis_policy_id (str): Unique identifier of the Network Analysis Policy.
            name (str): Name of the Network Analysis Policy.
            basepolicy_id (str): Unique identifier representing the base network analysis policy.
            description (str, optional): Description of the Network Analysis Policy.
                Defaults to None.
            inspection_mode (str, optional): Indicates the inspection mode. Can be either DETECTION or PREVENTION.
                Only applicable for Snort 3 engine.
                Defaults to None.
            replicate_inspection_mode (bool, optional): Flag to replicate inspection mode from snort 3 version
                to snort 2 version.
                Defaults to None.

        Returns:
            Dict[str, Any]: Modified Intrusion Rule Group's information.
        """
        params = assign_params(
            replicateInspectionMode=replicate_inspection_mode,
        )
        body: Dict[str, Any] = remove_empty_elements({
            'id': network_analysis_policy_id,
            'name': name,
            'description': description,
            'inspectionMode': inspection_mode,
            'basePolicy': {
                'id': basepolicy_id,
            },
        })

        return self._http_request(
            method='PUT',
            url_suffix=f'policy/networkanalysispolicies/{network_analysis_policy_id}',
            params=params,
            json_data=body,
            timeout=EXECUTION_TIMEOUT,
        )

    def delete_network_analysis_policy(
        self,
        network_analysis_policy_id: str,
    ) -> Dict[str, Any]:
        """
        Deletes the network analysis policy associated with the specified ID.

        Args:
            network_analysis_policy_id (str): Unique identifier of the Network Analysis Policy.

        Returns:
            Dict[str, Any]: Deleted network analysis policy's information.
        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'policy/networkanalysispolicies/{network_analysis_policy_id}',
        )


''' HELPER FUNCTIONS '''  # pylint: disable=pointless-string-statement


def switch_list_to_list_counter(data: Union[Dict, List]) -> Union[Dict, List]:
    """Receives a list of dictionaries or a dictionary,
    and if one of the keys contains a list or dictionary with lists,
    returns the size of the lists
        Examples:
        >>> switch_list_to_list_counter({'name': 'n', 'type': 't', 'devices': [1, 2, 3]})
        {'name': 'name', 'type': 'type', 'devices': 3}

        >>> switch_list_to_list_counter({'name': 'n', 'type': 't', 'devices': {'new': [1, 2, 3], 'old': [1, 2, 3]}}
        {'name': 'name', 'type': 'type', 'devices': 6}

        >>> switch_list_to_list_counter({'name': 'n', 'type': 't', 'devices': {'new': 'my new'}
        {'name': 'name', 'type': 'type', 'devices': 1}

    :type data: ``list`` or ``dict``
    :param data:  context entry

    :return: ``list`` or ``dict``
    :rtype: context entry for human readable`
    """
    if isinstance(data, list):
        return [switch_list_to_list_counter(dat) for dat in data]
    new_data = {}
    for item in data:
        if type(data[item]) is list:
            new_data[item] = len(data[item])
        elif data[item] and type(data[item]) is dict:
            counter = 0
            for in_item in data[item]:
                if type(data[item][in_item]) is list:
                    counter += len(data[item][in_item])
                elif data[item][in_item]:
                    counter = 1 if counter == 0 else counter
            new_data[item] = counter
        else:
            new_data[item] = data[item]
    return new_data


def raw_response_to_context_list(list_key: List, items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives a dictionary or list of dictionaries and returns only the keys that exist in the list_key
    and changes the keys by Context Standards

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :type list_key: ``list``
    :keyword list_key: Selected keys to copy on context_entry
    """
    if isinstance(items, list):
        return [raw_response_to_context_list(list_key, item) for item in items]

    list_to_output = {OUTPUT_KEYS_DICTIONARY.get(key, key.capitalize()): items.get(key, '') for key in list_key}
    return list_to_output


def raw_response_to_context_network_groups(items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives raw response and returns Context entry to network groups command

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :return: ``list`` or ``dict``
    :rtype: context entry`
    """
    if isinstance(items, list):
        return [raw_response_to_context_network_groups(item) for item in items]
    return {
        'Name': items.get('name'),
        'ID': items.get('id'),
        'Overridable': items.get('overridable'),
        'Description': items.get('description'),
        'Objects': [
            {
                'Name': obj.get('name'),
                'ID': obj.get('id'),
                'Type': obj.get('type')
            } for obj in items.get('objects', [])
        ],
        'Addresses': [
            {
                'Value': obj.get('value'),
                'Type': obj.get('type')
            } for obj in items.get('literals', [])
        ]
    }


def raw_response_to_context_url_groups(items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives raw response and returns Context entry to url groups command
    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request
    :return: ``list`` or ``dict``
    :rtype: context entry`
    """
    if isinstance(items, list):
        return [raw_response_to_context_url_groups(item) for item in items]
    return {
        'Name': items.get('name'),
        'ID': items.get('id'),
        'Overridable': items.get('overridable'),
        'Description': items.get('description'),
        'Objects': [
            {
                'Name': obj.get('name'),
                'ID': obj.get('id'),
                'Type': obj.get('type')
            } for obj in items.get('objects', [])
        ],
        'Addresses': [
            {
                'Url': obj.get('url'),
                'Type': obj.get('type')
            } for obj in items.get('literals', [])
        ]
    }


def raw_response_to_context_policy_assignment(items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives raw response and returns Context entry to policy assignment command

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :return: ``list`` or ``dict``
    :rtype: context entry`
    """
    if isinstance(items, list):
        return [raw_response_to_context_policy_assignment(item) for item in items]
    return {
        'Name': items.get('name'),
        'ID': items.get('id'),
        'PolicyName': items.get('policy', {}).get('name', ''),
        'PolicyID': items.get('policy', {}).get('id', ''),
        'PolicyDescription': items.get('policy', {}).get('description', ''),
        'Targets': [
            {
                'Name': obj.get('name'),
                'ID': obj.get('id'),
                'Type': obj.get('type')
            } for obj in items.get('targets', [])
        ]
    }


def raw_response_to_context_access_policy(items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives raw response and returns Context entry to access policy command

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :return: ``list`` or ``dict``
    :rtype: context entry`
    """
    if isinstance(items, list):
        return [raw_response_to_context_access_policy(item) for item in items]
    return {
        'Name': items.get('name'),
        'ID': items.get('id'),
        'DefaultActionID': items.get('defaultAction', {}).get('id', '')
    }


def raw_response_to_context_rules(items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives raw response and returns Context entry to rules command

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :return: ``list`` or ``dict``
    :rtype: context entry`
    """
    if isinstance(items, list):
        return [raw_response_to_context_rules(item) for item in items]
    return {
        'ID': items.get('id'),
        'Name': items.get('name'),
        'Action': items.get('action'),
        'Enabled': items.get('enabled'),
        'SendEventsToFMC': items.get('sendEventsToFMC'),
        'RuleIndex': items.get('metadata', {}).get('ruleIndex', ''),
        'Section': items.get('metadata', {}).get('section', ''),
        'Category': items.get('metadata', {}).get('category', ''),
        'Urls': {
            'Addresses': [{
                'URL': obj.get('url', '')
            } for obj in items.get('urls', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', '')
            } for obj in items.get('urls', {}).get('objects', [])
            ]
        },
        'VlanTags': {
            'Numbers': [{
                'EndTag': obj.get('endTag', ''),
                'StartTag': obj.get('startTag', '')
            } for obj in items.get('vlanTags', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('vlanTags', {}).get('objects', [])
            ]
        },
        'SourceZones': {
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('sourceZones', {}).get('objects', [])
            ]
        },
        'Applications': [{
            'Name': obj.get('name', ''),
            'ID': obj.get('id', '')
        } for obj in items.get('applications', {}).get('applications', [])
        ],
        'DestinationZones': {
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('destinationZones', {}).get('objects', [])
            ]
        },
        'SourceNetworks': {
            'Addresses': [{
                'Type': obj.get('type', ''),
                'Value': obj.get('value', '')
            } for obj in items.get('sourceNetworks', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('sourceNetworks', {}).get('objects', [])
            ]
        },
        'DestinationNetworks': {
            'Addresses': [{
                'Type': obj.get('type', ''),
                'Value': obj.get('value', '')
            } for obj in items.get('destinationNetworks', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('destinationNetworks', {}).get('objects', [])
            ]
        },
        'SourcePorts': {
            'Addresses': [{
                'Port': obj.get('port', ''),
                'Protocol': obj.get('protocol', '')
            } for obj in items.get('sourcePorts', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', ''),
                'Protocol': obj.get('protocol', '')
            } for obj in items.get('sourcePorts', {}).get('objects', [])
            ]
        },
        'DestinationPorts': {
            'Addresses': [{
                'Port': obj.get('port', ''),
                'Protocol': obj.get('protocol', '')
            } for obj in items.get('destinationPorts', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', ''),
                'Protocol': obj.get('protocol', '')
            } for obj in items.get('destinationPorts', {}).get('objects', [])
            ]
        },
        'SourceSecurityGroupTags': {
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('sourceSecurityGroupTags', {}).get('objects', [])
            ]
        }
    }


def get_readable_output(
    response: Dict[str, Any],
    header_by_keys: Dict[str, List[str]],
    keys_to_items: List[str] = None,
    title: str = '',
) -> str:
    """
    Get a response's readable output by formatting it through its headers.
    Args:
        response (Dict[str, Any]): API response.
        header_by_keys (Dict[str, List[str]]): headers by a list of keys to the response value.
        keys_to_items (List[str]): list of keys 1st option to the response value.
            Defaults to None.
        title (str, optional): readable output title.
            Defaults to ''.
    Returns:
        str: readable output of the API response.
    """
    items = dict_safe_get(response, keys_to_items) if keys_to_items else response
    headers = list(header_by_keys.keys())

    item_readable_arguments: List[Dict[str, Any]] = []

    if isinstance(items, Dict):
        items = [items]

    for item in items:
        dictionary = {
            key: dict_safe_get(item, value)
            for key, value in header_by_keys.items()
        }

        item_readable_arguments.append(dictionary)

    readable_output = tableToMarkdown(
        title,
        item_readable_arguments,
        headers=headers,
        removeNull=True,
    )

    return readable_output


def delete_keys_from_dict(
    dictionary: MutableMapping,
    keys_to_delete: Union[List[str], Set[str]]
) -> Dict[str, Any]:
    """
    Get a modified dictionary without the requested keys
    Args:
        dictionary (Dict[str, Any]): Dictionary to modify according to.
        keys_to_delete (List[str]): Keys to not include in the modified dictionary.
    Returns:
        Dict[str, Any]: Modified dictionary without requested keys.
    """
    keys_set = set(keys_to_delete)
    modified_dict: Dict[str, Any] = {}

    for key, value in dictionary.items():
        if key not in keys_set:
            if isinstance(value, MutableMapping):
                modified_dict[key] = delete_keys_from_dict(value, keys_set)

            elif isinstance(value, MutableSequence) \
                    and len(value) > 0 \
                    and isinstance(value[0], MutableMapping):
                modified_dict[key] = []

                for val in value:
                    modified_dict[key].append(delete_keys_from_dict(val, keys_set))

            else:
                modified_dict[key] = copy.deepcopy(value)

    return modified_dict


def get_context_output(
    response: Dict[str, Any],
    contexts_to_delete: List[str],
    item_to_add: Tuple[str, Any] = None,
    keys_to_items: List[str] = None,
) -> List[Dict[str, Any]]:
    """
    Get context output from the response.
    Loop through each value and create a modified response without the contexts_to_delete.

    Args:
        response Dict[str, Any]: Raw response from the API.
        contexts_to_delete List[str]: Context outputs to leave out.
        item_to_add Tuple[str, Any]: Items to add to the context output.
            Defaults to None.
        keys_to_items List[str]: A list of keys to the items information.
            Defaults to None.
    Returns:
        List[Dict[str, Any]]: Context output for the response.
    """
    items = dict_safe_get(response, keys_to_items) if keys_to_items else response

    if isinstance(items, Dict):
        items = [items]

    context_outputs: List[Dict[str, Any]] = []

    for item in items:
        context_output: Dict[str, Any] = {}

        if contexts_to_delete:
            context_output = delete_keys_from_dict(item, contexts_to_delete)

        if item_to_add:
            context_output = {
                item_to_add[0]: item_to_add[1],
                **context_output
            }

        context_outputs.append(context_output or item)

    return context_outputs


def parse_results(
    raw_response: Dict[str, Any],
    command_headers_by_keys: Dict[str, Any],
    command_title: str,
    command_context: str,
    raw_responses: Union[List, Dict] = None
) -> CommandResults:
    """
    Create a CommandResults from a given response.

    Args:
        raw_response (Dict[str, Any]): API response to create readable and context outputs.
        command_headers_by_keys (Dict[str, Any]): Headers by a list of keys to the response value.
        command_title (str): Readable output title.
        command_context (str): Command context path.
        raw_responses (Union[List, Dict], optional): Potentially multiple API responses from a LIST request.
            This argument will replace raw_response in the CommandResults incase it exists.
            Defaults to None.

    Returns:
        CommandResults: Created CommandResults from the API response.
    """
    context_output = get_context_output(
        response=raw_response,
        contexts_to_delete=['links']
    )
    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=command_headers_by_keys,
        title=command_title,
    )

    command_results = CommandResults(
        outputs_prefix='.'.join((INTEGRATION_CONTEXT_NAME, command_context)),
        outputs_key_field='id',
        outputs=context_output,
        readable_output=readable_output,
        raw_response=raw_response,
    )

    if raw_responses:
        command_results.raw_response = raw_responses

    return command_results


def append_items_to_value(raw_response: Dict[str, Any], value: str, items_key: str, inner_key: str) -> str:
    """
    Appends items within the raw_response to the current value.

    Args:
        raw_response (Dict[str, Any]): Dictionary to extract items from.
        value (str): value to append items to.
        items_key (str): Key to a list of items.
        inner_key (str): Key to inner item within the items list.

    Returns:
        str: Items from raw_response or value + items from raw_response.
    """
    if not (items := raw_response.get(items_key)):
        return ''

    prev_value = ','.join(item[inner_key] for item in items)

    return prev_value if not value else prev_value + f',{value}'


def check_is_get_request(get_args: list, list_args: list) -> bool:
    """
    Validate whether the request arguments are GET or LIST.

    Args:
        get_args (list): GET request arguments.
        list_args (list): LIST request arguments.

    Raises:
        ValueError: In case the user has entered both GET and LIST arguments, raise an error.

    Returns:
        bool: Are the GET arguments true.
    """
    is_get_request = any(get_args)
    is_list_request = any(list_args)

    if is_get_request and is_list_request:
        raise ValueError('GET and LIST arguments can not be supported simultaneously.')

    return is_get_request


def arg_to_optional_bool(arg: Optional[Any]) -> Optional[bool]:
    """
    Wrapper to argToBoolean function that will allow Optional arguments.

    Args:
        arg (Optional[Any]): The value to evaluate.
            Defaults to None.

    Returns:
        Optional[bool]: a boolean representation of 'arg' or None.
    """
    return argToBoolean(arg) if arg else None


''' COMMANDS '''  # pylint: disable=pointless-string-statement


def list_zones_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of all security zone objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about security zones.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'securityzones')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List zones:'
        context_entry = [{
            'ID': item.get('id', ''),
            'Name': item.get('name', ''),
            'InterfaceMode': item.get('interfaceMode', ''),
            'Interfaces': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id' '')
            } for obj in item.get('interfaces', {})
            ]
        } for item in items
        ]
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Zone(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'InterfaceMode', 'Interfaces']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any zone.'
        )


def list_ports_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of all port objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about ports.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'ports')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List ports:'
        list_to_output = ['id', 'name', 'protocol', 'port']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Port(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Protocol', 'Port']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any port.'
        )


def list_url_categories_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of all URL category objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about URL category.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'urlcategories')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List url categories:'
        list_to_output = ['id', 'name']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Category(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any category.'
        )


def get_network_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves the network objects associated with the specified ID.
    If not supplied, retrieves a list of all network objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about network objects.
    """
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    object_id = args.get('object_id', '')

    raw_response = client.get_network_objects(limit, offset, object_id)
    items: Union[List, Dict] = raw_response.get('items')    # type:ignore
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List network objects:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - get network object {object_id}'
            items = raw_response
        list_to_output = ['id', 'name', 'value', 'overridable', 'description']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Network(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any network object.'
        )


def get_host_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves the groups of host objects associated with the specified ID.
    If no ID is passed, the input ID retrieves a list of all network objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about network objects.
    """
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    object_id = args.get('object_id', '')

    raw_response = client.get_hosts_objects(limit, offset, object_id)
    items: Union[List, Dict] = raw_response.get('items')    # type:ignore
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List host objects:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - get host object {object_id}'
            items = raw_response
        list_to_output = ['id', 'name', 'value', 'overridable', 'description']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Host(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any host object.'
        )


def create_network_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Creates a network object.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created network object.
    """
    name: str = args.get('name')    # type:ignore
    value: str = args.get('value')    # type:ignore
    description: str = args.get('description', '')    # type:ignore
    overridable = args.get('overridable', '')
    raw_response = client.create_network_objects(name, value, description, overridable)
    title = f'{INTEGRATION_NAME} - network object has been created.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']
    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Network(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def create_host_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Creates a host object.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created host object.
    """
    name: str = args.get('name')    # type:ignore
    value: str = args.get('value')    # type:ignore
    description: str = args.get('description', '')    # type:ignore
    overridable = args.get('overridable', '')
    raw_response = client.create_host_objects(name, value, description, overridable)
    title = f'{INTEGRATION_NAME} - host object has been created.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']
    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Host(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def update_network_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Updates the specified network object.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the updated network object.
    """
    object_id: str = args.get('id')    # type:ignore
    name: str = args.get('name')    # type:ignore
    value: str = args.get('value')    # type:ignore
    description: str = args.get('description', '')    # type:ignore
    overridable = args.get('overridable', '')
    raw_response = client.update_network_objects(name, value, description, overridable, object_id)
    title = f'{INTEGRATION_NAME} - network object has been updated.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']

    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Network(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def update_host_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Updates the specified host object.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the updated host object.
    """
    object_id: str = args.get('id')    # type:ignore
    name: str = args.get('name')    # type:ignore
    value: str = args.get('value')    # type:ignore
    description: str = args.get('description', '')    # type:ignore
    overridable = args.get('overridable', '')
    raw_response = client.update_host_objects(name, value, description, overridable, object_id)
    title = f'{INTEGRATION_NAME} - host object has been updated.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']

    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Host(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def delete_network_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Deletes the specified network object.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the deleted network object.
    """
    object_id: str = args.get('id')    # type:ignore
    raw_response = client.delete_network_objects(object_id)
    title = f'{INTEGRATION_NAME} - network object has been deleted.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']
    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Network(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def delete_host_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Deletes the specified host object.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the deleted host object.
    """
    object_id: str = args.get('id')    # type:ignore
    raw_response = client.delete_host_objects(object_id)
    title = f'{INTEGRATION_NAME} - host object has been deleted.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']
    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Host(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def get_network_groups_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves the groups of network objects and addresses associated with the specified ID.
    If not supplied, retrieves a list of all network objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about network groups.
    """
    object_id = args.get('id', '')
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    raw_response = client.get_network_groups_objects(limit, offset, object_id)
    items: Union[List, Dict] = raw_response.get('items')    # type:ignore
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List of network groups object:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - network group object:'
            items = raw_response
        context_entry = raw_response_to_context_network_groups(items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not get the network groups.')


def get_url_groups_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves the groups of url objects and addresses associated with the specified ID.
    If not supplied, retrieves a list of all url objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about url groups.
    """
    object_id = args.get('id', '')
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    raw_response = client.get_url_groups_objects(limit, offset, object_id)
    items: Union[List, Dict] = raw_response.get('items')    # type:ignore
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List of url groups object:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - url group object:'
            items = raw_response
        context_entry = raw_response_to_context_url_groups(items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.URLGroups(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not get the URL groups.')


def create_network_groups_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Creates a group of network objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created network group.
    """
    name: str = args.get('name')    # type:ignore
    ids = args.get('network_objects_id_list', '')
    values = args.get('network_address_list', '')
    description = args.get('description', '')
    overridable = args.get('overridable', '')
    if ids or values:
        raw_response = client.create_network_groups_objects(name, ids, values, description, overridable)
        title = f'{INTEGRATION_NAME} - network group has been created.'
        context_entry = raw_response_to_context_network_groups(raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }

        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not create new group, Missing value or ID.')


def update_network_groups_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Updates a group of network objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the updated network group.
    """
    group_id: str = args.get('id')   # type:ignore
    name: str = args.get('name')    # type:ignore
    ids = args.get('network_objects_id_list', '')
    values = args.get('network_address_list', '')
    description = args.get('description', '')
    overridable = args.get('overridable', '')
    update_strategy = args.get('update_strategy', 'OVERRIDE')

    is_merge = update_strategy == 'MERGE'

    if ids or values:
        if is_merge or not name:
            raw_response = client.get_network_groups_objects(
                limit=0,
                offset=0,
                object_id=group_id
            )

            name = name or raw_response['name']

            if is_merge:
                ids = append_items_to_value(
                    raw_response=raw_response,
                    value=ids,
                    items_key='objects',
                    inner_key='id',
                )
                values = append_items_to_value(
                    raw_response=raw_response,
                    value=values,
                    items_key='literals',
                    inner_key='value',
                )

        raw_response = client.update_network_groups_objects(name, ids, values, group_id, description, overridable)
        title = f'{INTEGRATION_NAME} - network group has been updated.'
        context_entry = raw_response_to_context_network_groups(raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }

        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not update the group, Missing value or ID.')


def update_url_groups_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Updates the ID of a group of url objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the updated url group.
    """
    group_id: str = args.get('id')   # type:ignore
    name: str = args.get('name')    # type:ignore
    ids = args.get('url_objects_id_list', '')
    values = args.get('url_list', '')
    description = args.get('description', '')
    overridable = args.get('overridable', '')
    update_strategy = args.get('update_strategy', 'OVERRIDE')

    is_merge = update_strategy == 'MERGE'

    if ids or values:
        if is_merge or not name:
            raw_response = client.get_url_groups_objects(
                limit=0,
                offset=0,
                object_id=group_id
            )

            name = name or raw_response['name']

            if is_merge:
                ids = append_items_to_value(
                    raw_response=raw_response,
                    value=ids,
                    items_key='objects',
                    inner_key='id',
                )
                values = append_items_to_value(
                    raw_response=raw_response,
                    value=values,
                    items_key='literals',
                    inner_key='url',
                )

        raw_response = client.update_url_groups_objects(name, ids, values, group_id, description, overridable)
        title = f'{INTEGRATION_NAME} - url group has been updated.'
        context_entry = raw_response_to_context_url_groups(raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.UrlGroups(val.ID && val.ID === obj.ID)': context_entry
        }

        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not update the group, Missing value or ID.')


def delete_network_groups_objects_command(client: Client, args: Dict) -> CommandResults:
    """
    Deletes a group of network objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the deleted network group.
    """
    object_id = args['id']
    raw_response = client.delete_network_groups_objects(object_id)
    title = f'{INTEGRATION_NAME} - network group - {object_id} - has been delete.'
    context_entry = raw_response_to_context_network_groups(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def get_access_policy_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves the access control policy associated with the specified ID.
    If no access policy ID is passed, all access control policies are returned.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about access policies.
    """
    policy_id = args.get('id', '')
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    raw_response = client.get_access_policy(limit, offset, policy_id)
    items: Union[List, Dict] = raw_response.get('items')    # type:ignore
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List access policy:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - get access policy'
            items = raw_response
        context_entry = raw_response_to_context_access_policy(items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'DefaultActionID']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any access policy.'
        )


def create_access_policy_command(client: Client, args: Dict) -> CommandResults:
    """
    Creates an access control policy.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created access policy.
    """
    name: str = args.get('name')    # type:ignore
    action: str = args.get('action')    # type:ignore
    raw_response = client.create_access_policy(name, action)
    title = f'{INTEGRATION_NAME} - access policy has been created.'
    context_entry = raw_response_to_context_access_policy(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'DefaultActionID']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def update_access_policy_command(client: Client, args: Dict) -> CommandResults:
    """
    Updates the specified access control policy.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the updated access policy.
    """
    name: str = args.get('name')    # type:ignore
    policy_id: str = args.get('id')    # type:ignore
    action: str = args.get('action')    # type:ignore
    action_id: str = args.get('default_action_id')    # type:ignore

    raw_response = client.update_access_policy(name, policy_id, action, action_id)
    title = f'{INTEGRATION_NAME} - access policy has been updated.'
    context_entry = raw_response_to_context_access_policy(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'DefaultActionID']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def delete_access_policy_command(client: Client, args: Dict) -> CommandResults:
    """
    Deletes the specified access control policy.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the deleted access policy.
    """
    policy_id: str = args.get('id')    # type:ignore
    raw_response = client.delete_access_policy(policy_id)
    title = f'{INTEGRATION_NAME} - access policy deleted.'
    context_entry = raw_response_to_context_access_policy(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'DefaultActionID']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def list_security_group_tags_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of all custom security group tag objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about security tags.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'securitygrouptags')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List security group tags:'
        list_to_output = ['id', 'name', 'tag']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.SecurityGroupTags(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Tag']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any security group tags.'
        )


def list_ise_security_group_tags_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of all ISE security group tag objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about security tags.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'isesecuritygrouptags')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List ise security group tags:'
        list_to_output = ['id', 'name', 'tag']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.IseSecurityGroupTags(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Tag']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any ise security group tags.'
        )


def list_vlan_tags_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of all vlan tag objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about vlan tags.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'vlantags')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List vlan tags:'
        context_entry = [
            {
                'Name': item.get('name'),
                'ID': item.get('id'),
                'Overridable': item.get('overridable'),
                'Description': item.get('description'),
                'StartTag': item.get('data', {}).get('startTag'),
                'EndTag': item.get('data', {}).get('endTag')
            } for item in items
        ]
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.VlanTags(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'StartTag', 'EndTag']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any vlan tags.'
        )


def list_vlan_tags_group_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of all vlan group tag objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about vlan tag groups.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'vlangrouptags')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List of vlan tags groups objects:'
        context_entry = [
            {
                'Name': item.get('name'),
                'ID': item.get('id'),
                'Overridable': item.get('overridable'),
                'Description': item.get('description'),
                'Objects': [
                    {
                        'Name': obj.get('name'),
                        'ID': obj.get('id'),
                        'Overridable': obj.get('overridable'),
                        'Description': obj.get('description'),
                        'StartTag': obj.get('data', {}).get('startTag'),
                        'EndTag': obj.get('data', {}).get('endTag')
                    } for obj in item.get('object', [])
                ]
            } for item in items
        ]
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.VlanTagsGroup(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Objects']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any vlan tags group.'
        )


def list_applications_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of all application objects.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about applications.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'applications')
    items = raw_response.get('items')
    if items:
        context_entry = [
            {
                'Name': item.get('name'),
                'ID': item.get('id'),
                'Risk': item.get('risk', {}).get('name', ''),
                'AppProductivity': item.get('appProductivity', {}).get('name', ''),
                'ApplicationTypes': [
                    {
                        'Name': obj.get('name')
                    } for obj in item.get('applicationTypes', [])
                ],
                'AppCategories': [
                    {
                        'Name': obj.get('name'),
                        'ID': obj.get('id'),
                        'Count': obj.get('metadata', {}).get('count', '')
                    } for obj in item.get('appCategories', [])
                ]
            } for item in items
        ]
        title = f'{INTEGRATION_NAME} - List of applications objects:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Applications(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'Risk', 'AppProductivity', 'ApplicationTypes', 'AppCategories']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any applications.'
        )


def get_access_rules_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves the access control rule associated with the specified policy ID and rule ID.
    If no rule ID is specified, retrieves a list of all access rules associated with the specified policy ID.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about access rules.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    policy_id: str = args.get('policy_id')    # type:ignore
    rule_id = args.get('rule_id', '')
    raw_response = client.get_access_rules(limit, offset, policy_id, rule_id)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List of access rules:'
    elif 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - access rule:'
        items = raw_response
    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any access rule.'
        )

    context_entry = raw_response_to_context_rules(items)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Action', 'Enabled', 'SendEventsToFMC', 'RuleIndex', 'Section', 'Category',
                        'Urls', 'VlanTags', 'SourceZones', 'Applications', 'DestinationZones', 'SourceNetworks',
                        'DestinationNetworks', 'SourcePorts', 'DestinationPorts', 'SourceSecurityGroupTags']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def create_access_rules_command(client: Client, args: Dict) -> CommandResults:
    """
    Creates an access control rule.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created access rules.
    """
    source_zone_object_ids = args.get('source_zone_object_ids', '')
    destination_zone_object_ids = args.get('destination_zone_object_ids', '')
    vlan_tag_object_ids = args.get('vlan_tag_object_ids', '')
    source_network_object_ids = args.get('source_network_object_ids', '')
    source_network_addresses = args.get('source_network_addresses', '')
    destination_network_object_ids = args.get('destination_network_object_ids', '')
    destination_network_addresses = args.get('destination_network_addresses', '')
    source_port_object_ids = args.get('source_port_object_ids', '')
    destination_port_object_ids = args.get('destination_port_object_ids', '')
    source_security_group_tag_object_ids = args.get('source_security_group_tag_object_ids', '')
    application_object_ids = args.get('application_object_ids', '')
    url_object_ids = args.get('url_object_ids', '')
    url_addresses = args.get('url_addresses', '')
    enabled = args.get('enabled', '')
    name = args.get('rule_name', '')
    policy_id = args.get('policy_id', '')
    action = args.get('action', '')

    raw_response = client.create_access_rules(source_zone_object_ids,
                                              destination_zone_object_ids,
                                              vlan_tag_object_ids,
                                              source_network_object_ids,
                                              source_network_addresses,
                                              destination_network_object_ids,
                                              destination_network_addresses,
                                              source_port_object_ids,
                                              destination_port_object_ids,
                                              source_security_group_tag_object_ids,
                                              application_object_ids,
                                              url_object_ids,
                                              url_addresses,
                                              enabled,
                                              name,
                                              policy_id,
                                              action)
    title = f'{INTEGRATION_NAME} - the new access rule:'
    context_entry = raw_response_to_context_rules(raw_response)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Action', 'Enabled', 'SendEventsToFMC', 'RuleIndex', 'Section', 'Category',
                        'Urls', 'VlanTags', 'SourceZones', 'Applications', 'DestinationZones', 'SourceNetworks',
                        'DestinationNetworks', 'SourcePorts', 'DestinationPorts', 'SourceSecurityGroupTags']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def update_access_rules_command(client: Client, args: Dict) -> CommandResults:
    """
    Updates the specified access control rule.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the updated access rules.
    """
    update_strategy: str = args.get('update_strategy')     # type:ignore
    source_zone_object_ids = args.get('source_zone_object_ids', '')
    destination_zone_object_ids = args.get('destination_zone_object_ids', '')
    vlan_tag_object_ids = args.get('vlan_tag_object_ids', '')
    source_network_object_ids = args.get('source_network_object_ids', '')
    source_network_addresses = args.get('source_network_addresses', '')
    destination_network_object_ids = args.get('destination_network_object_ids', '')
    destination_network_addresses = args.get('destination_network_addresses', '')
    source_port_object_ids = args.get('source_port_object_ids', '')
    destination_port_object_ids = args.get('destination_port_object_ids', '')
    source_security_group_tag_object_ids = args.get('source_security_group_tag_object_ids', '')
    application_object_ids = args.get('application_object_ids', '')
    url_object_ids = args.get('url_object_ids', '')
    url_addresses = args.get('url_addresses', '')
    enabled = args.get('enabled', '')
    name = args.get('rule_name', '')
    policy_id = args.get('policy_id', '')
    action = args.get('action', '')
    rule_id: str = args.get('rule_id')    # type:ignore

    raw_response = client.update_access_rules(update_strategy,
                                              source_zone_object_ids,
                                              destination_zone_object_ids,
                                              vlan_tag_object_ids,
                                              source_network_object_ids,
                                              source_network_addresses,
                                              destination_network_object_ids,
                                              destination_network_addresses,
                                              source_port_object_ids,
                                              destination_port_object_ids,
                                              source_security_group_tag_object_ids,
                                              application_object_ids,
                                              url_object_ids,
                                              url_addresses,
                                              enabled,
                                              name,
                                              policy_id,
                                              action,
                                              rule_id)
    title = f'{INTEGRATION_NAME} - access rule:'
    context_entry = raw_response_to_context_rules(raw_response)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Action', 'Enabled', 'SendEventsToFMC', 'RuleIndex', 'Section', 'Category',
                        'Urls', 'VlanTags', 'SourceZones', 'Applications', 'DestinationZones', 'SourceNetworks',
                        'DestinationNetworks', 'SourcePorts', 'DestinationPorts', 'SourceSecurityGroupTags']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def delete_access_rules_command(client: Client, args: Dict) -> CommandResults:
    """
    Deletes the specified access control rule.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the deleted access rules.
    """
    policy_id = args.get('policy_id')
    rule_id = args.get('rule_id')
    raw_response = client.delete_access_rules(policy_id, rule_id)
    title = f'{INTEGRATION_NAME} - deleted access rule:'
    context_entry = raw_response_to_context_rules(raw_response)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Action', 'Enabled', 'SendEventsToFMC', 'RuleIndex', 'Section', 'Category',
                        'Urls', 'VlanTags', 'SourceZones', 'Applications', 'DestinationZones', 'SourceNetworks',
                        'DestinationNetworks', 'SourcePorts', 'DestinationPorts', 'SourceSecurityGroupTags']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def list_policy_assignments_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves the policy assignment associated with the specified ID.
    If no ID is specified, retrieves a list of all policy assignments to target devices.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about policy assignments.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.list_policy_assignments(limit, offset)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List of policy assignments:'
        context_entry = raw_response_to_context_policy_assignment(items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.PolicyAssignments(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'PolicyName', 'PolicyID', 'PolicyDescription', 'Targets']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any policy assignments.'
        )


def create_policy_assignments_command(client: Client, args: Dict) -> CommandResults:
    """
    Creates policy assignments to target devices.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created policy assignments.
    """
    device_ids: str = args.get('device_ids')    # type:ignore
    device_group_ids: str = args.get('device_group_ids')    # type:ignore
    policy_id: str = args.get('policy_id')    # type:ignore
    raw_response = client.create_policy_assignments(policy_id, device_ids, device_group_ids)
    title = f'{INTEGRATION_NAME} - Policy assignments has been done.'
    context_entry = raw_response_to_context_policy_assignment(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.PolicyAssignments(val.ID && val.ID === obj.ID)': context_entry
    }
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    presented_output = ['ID', 'Name', 'PolicyName', 'PolicyID', 'PolicyDescription', 'Targets']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def update_policy_assignments_command(client: Client, args: Dict) -> CommandResults:
    """
    Updates the specified policy assignments to target devices.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the updated policy assignments.
    """
    device_ids: str = args.get('device_ids')    # type:ignore
    device_group_ids: str = args.get('device_group_ids')    # type:ignore
    policy_id: str = args.get('policy_id')    # type:ignore
    update_strategy = args.get('update_strategy', 'OVERRIDE')

    if update_strategy == 'MERGE':
        raw_response = client.get_policy_assignments(
            policy_assignment_id=policy_id
        )

        targets = raw_response['targets']
        prev_device_ids = ','.join(target['id'] for target in targets if target['type'] == 'Device')
        device_ids = prev_device_ids if not device_ids else prev_device_ids + f',{device_ids}'

        prev_device_group_ids = ','.join(target['id'] for target in targets if target['type'] == 'DeviceGroup')
        device_group_ids = prev_device_group_ids if not device_group_ids else \
            prev_device_group_ids + f',{device_group_ids}'

    raw_response = client.update_policy_assignments(policy_id, device_ids, device_group_ids)
    title = f'{INTEGRATION_NAME} - policy update has been done.'
    context_entry = raw_response_to_context_policy_assignment(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.PolicyAssignments(val.ID && val.ID === obj.ID)': context_entry
    }
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    presented_output = ['ID', 'Name', 'PolicyName', 'PolicyID', 'PolicyDescription', 'Targets']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def get_deployable_devices_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of all devices with configuration changes that are ready to deploy.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about deployable devices.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    container_uuid = args.get('container_uuid', '')
    raw_response = client.get_deployable_devices(limit, offset, container_uuid)
    items = raw_response.get('items')
    if container_uuid:
        if items:
            context_entry = [{
                'EndTime': item.get('endTime', ''),
                'ID': item.get('id', ''),
                'Name': item.get('name', ''),
                'StartTime': item.get('startTime', ''),
                'Status': item.get('status', ''),
                'Type': item.get('type', '')
            } for item in items
            ]
        else:
            context_entry = []
            demisto.debug(f"no {items=}")
        title = f'{INTEGRATION_NAME} - List of devices status pending deployment:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.PendingDeployment(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['EndTime', 'ID', 'Name', 'StartTime', 'Status', 'Type']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    if items:
        context_entry = [{
            'CanBeDeployed': item.get('canBeDeployed', ''),
            'UpToDate': item.get('upToDate', ''),
            'DeviceID': item.get('device', {}).get('id', ''),
            'DeviceName': item.get('device', {}).get('name', ''),
            'DeviceType': item.get('device', {}).get('type', ''),
            'Version': item.get('version', '')
        } for item in items
        ]
        title = f'{INTEGRATION_NAME} - List of deployable devices:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.DeployableDevices(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['CanBeDeployed', 'UpToDate', 'DeviceID', 'DeviceName', 'DeviceType', 'Version']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any deployable devices.'
        )


def get_device_records_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of all device records.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about devices records.
    """
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_device_records(limit, offset)
    items = raw_response.get('items')
    if items:
        context_entry = [{
            'ID': item.get('id', ''),
            'Name': item.get('name', ''),
            'HostName': item.get('hostName', ''),
            'Type': item.get('type', ''),
            'DeviceGroupID': item.get('deviceGroup', {}).get('id', '')
        } for item in items
        ]
        title = f'{INTEGRATION_NAME} - List of device records:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.DeviceRecords(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'HostName', 'Type', 'DeviceGroupID']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any device records.'
        )


def deploy_to_devices_command(client: Client, args: Dict) -> CommandResults:
    """
    Creates a request for deploying configuration changes to devices.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about deployed device.
    """
    force_deploy = args.get('force_deploy', '')
    ignore_warning = args.get('ignore_warning', '')
    version = args.get('version', '')
    device_list = args.get('device_ids', '')

    raw_response = client.deploy_to_devices(force_deploy, ignore_warning, version, device_list)
    title = f'{INTEGRATION_NAME} - devices requests to deploy.'
    context_entry = {
        'TaskID': raw_response.get('metadata', {}).get('task', {}).get('id', ''),
        'ForceDeploy': raw_response.get('forceDeploy'),
        'IgnoreWarning': raw_response.get('ignoreWarning'),
        'Version': raw_response.get('version'),
        'DeviceList': raw_response.get('deviceList')
    }
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Deploy(val.ID && val.ID === obj.ID)': context_entry
    }
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    presented_output = ['TaskID', 'ForceDeploy', 'IgnoreWarning', 'Version', 'DeviceList']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)

    return CommandResults(
        readable_output=human_readable,
        outputs=context,
        raw_response=raw_response,
    )


def get_task_status_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves information about a previously submitted pending job or task with the specified ID.
    Used for deploying.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about task status.
    """
    task_id: str = args.get('task_id')    # type:ignore
    raw_response = client.get_task_status(task_id)
    if 'status' in raw_response:
        context_entry = {
            'Status': raw_response.get('status')
        }
        title = f'{INTEGRATION_NAME} - {task_id} status:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.TaskStatus(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry, headers=['Status'])

        return CommandResults(
            readable_output=human_readable,
            outputs=context,
            raw_response=raw_response,
        )

    else:
        return CommandResults(
            readable_output=f'{INTEGRATION_NAME} - Could not find any status.'
        )


def create_intrusion_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates an Intrusion Policy with the specified parameters.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created Intrusion Policy
    """
    name = args['name']
    basepolicy_id = args['basepolicy_id']
    description = args.get('description')
    inspection_mode = args.get('inspection_mode')

    raw_response = client.create_intrusion_policy(
        name=name,
        basepolicy_id=basepolicy_id,
        description=description,
        inspection_mode=inspection_mode,
    )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_POLICY_HEADERS_BY_KEYS,
        command_title=f'Created {INTRUSION_POLICY_TITLE}',
        command_context=INTRUSION_POLICY_CONTEXT,
    )


def list_intrusion_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the intrusion policy associated with the specified ID.
    If no ID is specified, retrieves list of intrusion policies.
    - GET arguments: intrusion_policy_id, include_count.
    - LIST arguments: expanded_response, limit, page, page_size.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about Intrusion Policies.
    """
    # GET arguments
    intrusion_policy_id = args.get('intrusion_policy_id', '')
    include_count = argToBoolean(args.get('include_count', 'False'))
    # LIST arguments
    limit = arg_to_number(args.get('limit', 0))
    page = arg_to_number(args.get('page', 0))
    page_size = arg_to_number(args.get('page_size', 0))
    expanded_response = argToBoolean(args.get('expanded_response', 'False'))

    raw_responses = None

    if check_is_get_request(
        get_args=[intrusion_policy_id, include_count],
        list_args=[limit, page, page_size, expanded_response]
    ):
        raw_response = client.get_intrusion_policy(
            intrusion_policy_id=intrusion_policy_id,
            include_count=include_count,
        )

    else:  # is_list_request
        raw_response, raw_responses = client.list_intrusion_policy(
            page=page,
            page_size=page_size,
            limit=limit,
            expanded_response=expanded_response,
        )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_POLICY_HEADERS_BY_KEYS,
        command_title=f'Fetched {INTRUSION_POLICY_TITLE}',
        command_context=INTRUSION_POLICY_CONTEXT,
        raw_responses=raw_responses,
    )


def update_intrusion_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Modifies the Intrusion Policy associated with the specified ID.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: In case none of the update arguments were entered.

    Returns:
        CommandResults: Information about the created Intrusion Policy
    """
    intrusion_policy_id = args['intrusion_policy_id']
    name = args.get('name', '')
    basepolicy_id = args.get('basepolicy_id', '')
    description = args.get('description')
    inspection_mode = args.get('inspection_mode')
    replicate_inspection_mode = arg_to_optional_bool(args.get('replicate_inspection_mode'))

    update_arguments = (name, basepolicy_id, description, inspection_mode)

    if not any(update_arguments):
        raise ValueError('Please enter one of the update arguments: name, basepolicy_id, description, inspection_mode')

    if not all(update_arguments):
        previous_data = client.get_intrusion_policy(
            intrusion_policy_id=intrusion_policy_id,
        )

        name = name or previous_data['name']
        basepolicy_id = basepolicy_id or previous_data['basePolicy']['id']
        description = description or previous_data.get('description')
        inspection_mode = inspection_mode or previous_data.get('inspectionMode')

    raw_response = client.update_intrusion_policy(
        intrusion_policy_id=intrusion_policy_id,
        name=name,
        basepolicy_id=basepolicy_id,
        description=description,
        inspection_mode=inspection_mode,
        replicate_inspection_mode=replicate_inspection_mode,
    )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_POLICY_HEADERS_BY_KEYS,
        command_title=f'Updated {INTRUSION_POLICY_TITLE}',
        command_context=INTRUSION_POLICY_CONTEXT,
    )


def delete_intrusion_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Deletes the Intrusion Policy associated with the specified ID.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the deleted Intrusion Policy
    """
    intrusion_policy_id = args['intrusion_policy_id']

    try:
        raw_response = client.delete_intrusion_policy(
            intrusion_policy_id=intrusion_policy_id,
        )

    except DemistoException as exc:
        if 'UUID cannot be null' in str(exc):
            return CommandResults(
                readable_output=f'The Intrusion Policy ID: "{intrusion_policy_id}" does not exist.'
            )

        raise

    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=INTRUSION_POLICY_HEADERS_BY_KEYS,
        title=f'Deleted {INTRUSION_POLICY_TITLE}',
    )

    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
    )


def create_intrusion_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates or overrides the Snort3 Intrusion rule group with the specified parameters.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created Intrusion Rule.
    """
    rule_data = args['rule_data']
    rule_group_ids = argToList(args['rule_group_ids'])

    raw_response = client.create_intrusion_rule(
        rule_data=rule_data,
        rule_group_ids=rule_group_ids,
    )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_RULE_HEADERS_BY_KEYS,
        command_title=f'Created {INTRUSION_RULE_TITLE}',
        command_context=INTRUSION_RULE_CONTEXT,
    )


def list_intrusion_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the Snort3 Intrusion rule group.
    If no ID is specified, retrieves a list of all Snort3 Intrusion rule groups.
    - GET argument: intrusion_rule_id.
    - LIST arguments: sort, filter, expanded_response, limit, page, page_size.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: In case the user has entered both GET and LIST arguments, raise an error.

    Returns:
        CommandResults: Information about Intrusion Rules.
    """
    # GET arguments
    intrusion_rule_id = args.get('intrusion_rule_id', '')
    # LIST arguments
    limit = arg_to_number(args.get('limit', 0))
    page = arg_to_number(args.get('page', 0))
    page_size = arg_to_number(args.get('page_size', 0))
    sort = argToList(args.get('sort'))
    filter_string = args.get('filter')
    expanded_response = argToBoolean(args.get('expanded_response', 'False'))

    raw_responses = None

    if check_is_get_request(
        get_args=[intrusion_rule_id],
        list_args=[sort, filter_string, expanded_response, limit, page, page_size]
    ):
        raw_response = client.get_intrusion_rule(
            intrusion_rule_id=intrusion_rule_id,
        )

    else:  # is_list_request
        raw_response, raw_responses = client.list_intrusion_rule(
            page=page,
            page_size=page_size,
            limit=limit,
            sort=sort,
            filter_string=filter_string,
            expanded_response=expanded_response,
        )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_RULE_HEADERS_BY_KEYS,
        command_title=f'Fetched {INTRUSION_RULE_TITLE}',
        command_context=INTRUSION_RULE_CONTEXT,
        raw_responses=raw_responses,
    )


def update_intrusion_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Modifies the Snort3 Intrusion rule group with the specified ID.
    Must enter at least one of the following if not both: rule_data or rule_group_ids.
    The variable that was not entered will stay the same.
    If merging rule_group_ids must be entered.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: In case the user hasn't entered both rule_data and rule_group_ids.
        ValueError: In case the user hasn't entered rule_group_ids while update_strategy is set to MERGE.

    Returns:
        CommandResults: Information about the updated Intrusion Rule.
    """
    intrusion_rule_id = args['intrusion_rule_id']
    rule_data = args.get('rule_data', '')
    rule_group_ids = argToList(args.get('rule_group_ids'))
    update_strategy = args.get('update_strategy', 'OVERRIDE')

    is_merge = update_strategy == 'MERGE'

    if not any((rule_data, rule_group_ids)):
        raise ValueError('rule_data, rule_group_ids or both must be populated.')

    # Rule groups must be entered when merging.
    if is_merge and not rule_group_ids:
        raise ValueError('rule_group_ids must be populated when merging.')

    # If on of the main arguments are missing, fill there data through a GET request.
    if bool(rule_data) != bool(rule_group_ids):
        raw_response = client.get_intrusion_rule(
            intrusion_rule_id=intrusion_rule_id
        )

        rule_data = rule_data or raw_response['ruleData']
        rule_group_ids = rule_group_ids or [rule_group['id'] for rule_group in raw_response['ruleGroups']]

    if is_merge:
        rule_group_ids += [rule_group['id'] for rule_group in raw_response['ruleGroups']]

    raw_response = client.update_intrusion_rule(
        intrusion_rule_id=intrusion_rule_id,
        rule_data=rule_data,
        rule_group_ids=rule_group_ids,
    )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_RULE_HEADERS_BY_KEYS,
        command_title=f'Updated {INTRUSION_RULE_TITLE}',
        command_context=INTRUSION_RULE_CONTEXT,
    )


def delete_intrusion_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Deletes the specified Snort3 rule.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the Deleted Intrusion Rule.
    """
    intrusion_rule_id = args['intrusion_rule_id']

    raw_response = client.delete_intrusion_rule(
        intrusion_rule_id=intrusion_rule_id
    )

    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=INTRUSION_RULE_HEADERS_BY_KEYS,
        title=f'Deleted {INTRUSION_RULE_TITLE}',
    )

    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
    )


def upload_intrusion_rule_file_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Imports or validate custom Snort 3 intrusion rules within a file.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: In case import arguments weren't inserted when validate_only is false.
        ValueError: In case the file is in the wrong format.

    Returns:
        CommandResults: Information about the intrusion rules format or about the merged/replaced intrusion rules.
    """
    entry_id = args['entry_id']
    # Import Arguments
    rule_import_mode = args.get('rule_import_mode')
    rule_group_ids = argToList(args.get('rule_group_ids'))
    # Validation Argument
    validate_only = argToBoolean(args.get('validate_only', 'True'))

    # In case import arguments weren't inserted when validate_only is false.
    if not validate_only and not all((rule_import_mode, rule_group_ids)):
        raise ValueError('rule_import_mode and rule_group_ids must be inserted when validate_only is "False".')

    file_entry = demisto.getFilePath(entry_id)
    filename = file_entry['name']
    file_type = os.path.splitext(filename)[1]

    if file_type not in ('.txt', '.rules'):
        raise ValueError(f'Supported file formats are ".txt" and ".rules", got {file_type}')

    with open(file_entry['path'], 'r') as file_handler:
        raw_response = client.upload_intrusion_rule_file(
            filename=filename,
            payload_file=file_handler.read(),
            rule_import_mode=rule_import_mode,
            rule_group_ids=rule_group_ids,
            validate_only=validate_only,
        )

    category = dict_safe_get(raw_response, ['error', 'category'])

    if validate_only and category == 'VALIDATION':
        readable_output = tableToMarkdown(
            f'Validation for Intrusion Rules within: "{filename}"',
            dict_safe_get(raw_response, ['error', 'messages']),
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        return CommandResults(
            readable_output=readable_output,
            raw_response=raw_response,
        )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_RULE_UPLOAD_HEADERS_BY_KEYS,
        command_title=INTRUSION_RULE_UPLOAD_TITLE,
        command_context=INTRUSION_RULE_UPLOAD_CONTEXT,
    )


def create_intrusion_rule_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates an Intrusion Rule Group with the specified parameters.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created Intrusion Rule Group.
    """
    name = args['name']
    description = args.get('description')

    raw_response = client.create_intrusion_rule_group(
        name=name,
        description=description,
    )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_RULE_GROUP_HEADERS_BY_KEYS,
        command_title=f'Created {INTRUSION_RULE_GROUP_TITLE}',
        command_context=INTRUSION_RULE_GROUP_CONTEXT,
    )


def list_intrusion_rule_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the Snort3 Intrusion rule group.
    If no ID is specified, retrieves a list of all Snort3 Intrusion rule groups.
    GET arguments: intrusion_rule_group_id.
    LIST arguments: expanded_response, filter, limit, page, page_size.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about Intrusion Rule Groups.
    """
    # GET arguments
    rule_group_id = args.get('rule_group_id', '')
    # LIST arguments
    limit = arg_to_number(args.get('limit', 0))
    page = arg_to_number(args.get('page', 0))
    page_size = arg_to_number(args.get('page_size', 0))
    filter_string = args.get('filter')
    expanded_response = argToBoolean(args.get('expanded_response', 'False'))

    raw_responses = None

    if check_is_get_request(
        get_args=[rule_group_id],
        list_args=[filter_string, expanded_response, limit, page, page_size]
    ):
        raw_response = client.get_intrusion_rule_group(
            rule_group_id=rule_group_id,
        )

    else:  # is_list_request
        raw_response, raw_responses = client.list_intrusion_rule_group(
            page=page,
            page_size=page_size,
            limit=limit,
            filter_string=filter_string,
            expanded_response=expanded_response,
        )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_RULE_GROUP_HEADERS_BY_KEYS,
        command_title=f'Fetched {INTRUSION_RULE_GROUP_TITLE}',
        command_context=INTRUSION_RULE_GROUP_CONTEXT,
        raw_responses=raw_responses,
    )


def update_intrusion_rule_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Updates an Intrusion Rule Group with the specified parameters.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the modified Intrusion Rule Group.
    """
    rule_group_id = args['rule_group_id']
    name = args['name']
    description = args.get('description')

    if not description:
        description = client.get_intrusion_rule_group(
            rule_group_id=rule_group_id,
        ).get('description')

    raw_response = client.update_intrusion_rule_group(
        rule_group_id=rule_group_id,
        name=name,
        description=description,
    )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=INTRUSION_RULE_GROUP_HEADERS_BY_KEYS,
        command_title=f'Updated {INTRUSION_RULE_GROUP_TITLE}',
        command_context=INTRUSION_RULE_GROUP_CONTEXT,
    )


def delete_intrusion_rule_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Deletes an Intrusion Rule Group with the specified parameters.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the deleted Intrusion Rule Group.
    """
    rule_group_id = args['rule_group_id']
    delete_related_rules = arg_to_optional_bool(args.get('delete_related_rules'))

    raw_response = client.delete_intrusion_rule_group(
        rule_group_id=rule_group_id,
        delete_related_rules=delete_related_rules,
    )

    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=INTRUSION_RULE_GROUP_HEADERS_BY_KEYS,
        title=f'Deleted {INTRUSION_RULE_GROUP_TITLE}',
    )

    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
    )


def create_network_analysis_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates a network analysis policy.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the created network analysis policy.
    """
    name = args['name']
    basepolicy_id = args['basepolicy_id']
    description = args.get('description')
    inspection_mode = args.get('inspection_mode')

    raw_response = client.create_network_analysis_policy(
        name=name,
        basepolicy_id=basepolicy_id,
        description=description,
        inspection_mode=inspection_mode,
    )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=NETWORK_ANALYSIS_POLICY_HEADERS_BY_KEYS,
        command_title=f'Created {NETWORK_ANALYSIS_POLICY_TITLE}',
        command_context=NETWORK_ANALYSIS_POLICY_CONTEXT,
    )


def list_network_analysis_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves the network analysis policy with the specified ID.
    If no ID is specified, retrieves list of all network analysis policies.
    GET arguments: network_analysis_policy_id.
    LIST arguments: expanded_response, limit, page, page_size.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about network analysis policies.
    """
    # GET arguments
    network_analysis_policy_id = args.get('network_analysis_policy_id', '')
    # LIST arguments
    limit = arg_to_number(args.get('limit', 0))
    page = arg_to_number(args.get('page', 0))
    page_size = arg_to_number(args.get('page_size', 0))
    expanded_response = argToBoolean(args.get('expanded_response', 'False'))

    raw_responses = None

    if check_is_get_request(
        get_args=[network_analysis_policy_id],
        list_args=[expanded_response, limit, page, page_size]
    ):
        raw_response = client.get_network_analysis_policy(
            network_analysis_policy_id=network_analysis_policy_id,
        )

    else:  # is_list_request
        raw_response, raw_responses = client.list_network_analysis_policy(
            page=page,
            page_size=page_size,
            limit=limit,
            expanded_response=expanded_response,
        )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=NETWORK_ANALYSIS_POLICY_HEADERS_BY_KEYS,
        command_title=f'Fetched {NETWORK_ANALYSIS_POLICY_TITLE}',
        command_context=NETWORK_ANALYSIS_POLICY_CONTEXT,
        raw_responses=raw_responses,
    )


def update_network_analysis_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        Modifies the network analysis policy associated with the specified ID.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: In case none of the update arguments were entered.

    Returns:
        CommandResults: Information about the modified network analysis policy.
    """
    network_analysis_policy_id = args['network_analysis_policy_id']
    basepolicy_id = args.get('basepolicy_id', '')
    name = args.get('name', '')
    description = args.get('description')
    inspection_mode = args.get('inspection_mode')
    replicate_inspection_mode = arg_to_optional_bool(args.get('replicate_inspection_mode'))

    update_arguments = (name, basepolicy_id, description, inspection_mode)

    if not any(update_arguments):
        raise ValueError('Please enter one of the update arguments: name, basepolicy_id, description, inspection_mode')

    if not all(update_arguments):
        previous_data = client.get_network_analysis_policy(
            network_analysis_policy_id=network_analysis_policy_id,
        )

        name = name or previous_data['name']
        basepolicy_id = basepolicy_id or previous_data['basePolicy']['id']
        description = description or previous_data.get('description')
        inspection_mode = inspection_mode or previous_data.get('inspectionMode')

    raw_response = client.update_network_analysis_policy(
        network_analysis_policy_id=network_analysis_policy_id,
        basepolicy_id=basepolicy_id,
        name=name,
        description=description,
        inspection_mode=inspection_mode,
        replicate_inspection_mode=replicate_inspection_mode,
    )

    return parse_results(
        raw_response=raw_response,
        command_headers_by_keys=NETWORK_ANALYSIS_POLICY_HEADERS_BY_KEYS,
        command_title=f'Updated {NETWORK_ANALYSIS_POLICY_TITLE}',
        command_context=NETWORK_ANALYSIS_POLICY_CONTEXT,
    )


def delete_network_analysis_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Deletes the network analysis policy associated with the specified ID.

    Args:
        client (Client): Session to Cisco Firepower Management Center to run desired requests.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Information about the deleted network analysis policy.
    """
    network_analysis_policy_id = args['network_analysis_policy_id']

    raw_response = client.delete_network_analysis_policy(
        network_analysis_policy_id=network_analysis_policy_id,
    )

    readable_output = get_readable_output(
        response=raw_response,
        header_by_keys=NETWORK_ANALYSIS_POLICY_HEADERS_BY_KEYS,
        title=f'Deleted {NETWORK_ANALYSIS_POLICY_TITLE}',
    )

    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
    )


''' COMMANDS MANAGER / SWITCH PANEL '''  # pylint: disable=pointless-string-statement


def main():  # pragma: no cover
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    command: str = demisto.command()

    base_url = params['url']
    username = params['credentials']['identifier']
    password = params['credentials']['password']
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    commands: Dict[str, Callable] = {
        'ciscofp-list-zones': list_zones_command,
        'ciscofp-list-ports': list_ports_command,
        'ciscofp-list-url-categories': list_url_categories_command,
        'ciscofp-get-network-object': get_network_objects_command,
        'ciscofp-create-network-object': create_network_objects_command,
        'ciscofp-update-network-object': update_network_objects_command,
        'ciscofp-delete-network-object': delete_network_objects_command,
        'ciscofp-get-host-object': get_host_objects_command,
        'ciscofp-create-host-object': create_host_objects_command,
        'ciscofp-update-host-object': update_host_objects_command,
        'ciscofp-delete-host-object': delete_host_objects_command,
        'ciscofp-get-network-groups-object': get_network_groups_objects_command,
        'ciscofp-create-network-groups-objects': create_network_groups_objects_command,
        'ciscofp-update-network-groups-objects': update_network_groups_objects_command,
        'ciscofp-delete-network-groups-objects': delete_network_groups_objects_command,
        'ciscofp-get-url-groups-object': get_url_groups_objects_command,
        'ciscofp-update-url-groups-objects': update_url_groups_objects_command,
        'ciscofp-get-access-policy': get_access_policy_command,
        'ciscofp-create-access-policy': create_access_policy_command,
        'ciscofp-update-access-policy': update_access_policy_command,
        'ciscofp-delete-access-policy': delete_access_policy_command,
        'ciscofp-list-security-group-tags': list_security_group_tags_command,
        'ciscofp-list-ise-security-group-tag': list_ise_security_group_tags_command,
        'ciscofp-list-vlan-tags': list_vlan_tags_command,
        'ciscofp-list-vlan-tags-group': list_vlan_tags_group_command,
        'ciscofp-list-applications': list_applications_command,
        'ciscofp-get-access-rules': get_access_rules_command,
        'ciscofp-create-access-rules': create_access_rules_command,
        'ciscofp-update-access-rules': update_access_rules_command,
        'ciscofp-delete-access-rules': delete_access_rules_command,
        'ciscofp-list-policy-assignments': list_policy_assignments_command,
        'ciscofp-create-policy-assignments': create_policy_assignments_command,
        'ciscofp-update-policy-assignments': update_policy_assignments_command,
        'ciscofp-get-deployable-devices': get_deployable_devices_command,
        'ciscofp-get-device-records': get_device_records_command,
        'ciscofp-deploy-to-devices': deploy_to_devices_command,
        'ciscofp-get-task-status': get_task_status_command,
        'ciscofp-create-intrusion-policy': create_intrusion_policy_command,
        'ciscofp-list-intrusion-policy': list_intrusion_policy_command,
        'ciscofp-update-intrusion-policy': update_intrusion_policy_command,
        'ciscofp-delete-intrusion-policy': delete_intrusion_policy_command,
        'ciscofp-create-intrusion-rule': create_intrusion_rule_command,
        'ciscofp-list-intrusion-rule': list_intrusion_rule_command,
        'ciscofp-update-intrusion-rule': update_intrusion_rule_command,
        'ciscofp-delete-intrusion-rule': delete_intrusion_rule_command,
        'ciscofp-upload-intrusion-rule-file': upload_intrusion_rule_file_command,
        'ciscofp-create-intrusion-rule-group': create_intrusion_rule_group_command,
        'ciscofp-list-intrusion-rule-group': list_intrusion_rule_group_command,
        'ciscofp-update-intrusion-rule-group': update_intrusion_rule_group_command,
        'ciscofp-delete-intrusion-rule-group': delete_intrusion_rule_group_command,
        'ciscofp-create-network-analysis-policy': create_network_analysis_policy_command,
        'ciscofp-list-network-analysis-policy': list_network_analysis_policy_command,
        'ciscofp-update-network-analysis-policy': update_network_analysis_policy_command,
        'ciscofp-delete-network-analysis-policy': delete_network_analysis_policy_command,
    }

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=verify_ssl,
            proxy=proxy,
        )

        if command == 'test-module':
            # In the Client __init__ there is a already a request made to receive a Bearer token.
            # If the token has been received successfully, then that means that the test connections has passed.
            return_results('ok')

        elif command in commands:
            return_results(commands[command](client, args))

        else:
            raise NotImplementedError(f'Command doesn\'t exist - {command}')

    except Exception as exc:  # pylint: disable=broad-except
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(exc)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
