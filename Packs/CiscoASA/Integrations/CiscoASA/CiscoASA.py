from requests import Response

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
from collections.abc import Callable
from functools import wraps
from copy import deepcopy
from http import HTTPStatus

import urllib3
import traceback

from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARIABLES'''

API_LIMIT = 100
INTEGRATION_COMMAND = "cisco-asa"
OBJECT_TYPES_DICT = {
    'IPv4': 'IPv4Address',
    'IP-Network': 'IPv4Network'
}
DEFAULT_LIMIT = 50
DEFAULT_KEYS_MAPPING = {
    'objectId': 'object_id',
    'name': 'name',
    'description': 'description',
    'members': {
        '_include': True,
        'kind': 'kind',
        'objectId': 'object_id',
        'value': 'value',
    },
}


'''PAGINATION DECORATOR '''


class Pagination:
    """
    Pagination decorator wrapper to control functionality within the decorator.

    Args:
        api_limit (int): Maximum number of items that can be returned from the API request.
        items_key_path (list[str], optional): A list of keys to the items within an API response.
            Defaults to None.
        start_count_from_zero (bool | None): Whether the count of the first item is 0 or 1.
            Defaults to True.
        default_limit (int): The number of default items to return with an API request.
            Defaults to DEFAULT_LIMIT.

    Returns:
        Callable: Pagination decorator.
    """

    def __init__(
        self,
        api_limit: int,
        items_key_path: list[str] | None = None,
        start_count_from_zero: bool = True,
        default_limit: int = DEFAULT_LIMIT,
    ) -> None:
        self.api_limit = api_limit
        self.items_key_path = items_key_path
        self.start_count_from_zero = start_count_from_zero
        self.default_limit = default_limit

    def __call__(self, func: Callable) -> Callable:
        """
        The __call__ method takes a function and returns a wrapped function that handles the pagination logic.

        Args:
            func (Callable): The function to be wrapped with pagination.

        Returns:
            Callable: The wrapped function with added pagination functionality.
        """
        @wraps(func)
        def wrapper(
            client_instance: BaseClient,
            page: int | None,
            page_size: int | None,
            limit: int = DEFAULT_LIMIT,
            *args,
            **kwargs,
        ) -> tuple[list | dict, list | dict]:
            """
            The wrapper function handles the pagination logic before calling the original function.

            Args:
                client_instance (BaseClient): The instance of the Client class used to call the API request function.
                page (int | None): Page number to return.
                page_size (int | None): Number of items to return in a page.
                *args: Positional arguments to be passed to the original function.
                **kwargs: Keyword arguments to be passed to the original function.

            Returns:
                tuple[list | dict, list | dict]: All the items combined within raw response,
                    All the raw responses combined.
            """
            remaining_items, offset = self._get_pagination_arguments(
                page=page,
                page_size=page_size,
                limit=limit
            )

            return self._handle_pagination(
                client_instance,
                func,
                remaining_items,
                offset,
                *args,
                **kwargs,
            )

        return wrapper

    def _get_pagination_arguments(
        self,
        page: int | None,
        page_size: int | None,
        limit: int = DEFAULT_LIMIT
    ) -> tuple[int, int | None]:
        """
        Determine if pagination is automatic or manual and compute remaining items and offset values.

        Args:
            page (int | None): Page number to return.
            page_size (int | None): Number of items to return in a page.

        Returns:
            tuple[bool, int, int | None]:
                remaining_items: The number of remaining items to fetch.
                offset: The offset for the next API request.
        """
        is_manual = page is not None

        if is_manual:
            page = page or 1
            page_size = page_size or self.default_limit

            remaining_items = page_size
            offset = (page - 1) * page_size + (0 if self.start_count_from_zero else 1)
        else:
            remaining_items = page_size or limit
            offset = None

        return remaining_items, offset

    def _handle_pagination(
        self,
        client_instance: BaseClient,
        func: Callable,
        remaining_items: int,
        offset: int | None,
        *args,
        **kwargs,
    ) -> tuple[list | dict, list | dict]:
        """
        Handle pagination when the API supports both limit and offset parameters.

        Args:
            client_instance (BaseClient): The instance of the Client class used to call the API request function.
            func (Callable): API request function to be called.
            remaining_items (int): The number of remaining items to fetch.
            offset (int | None): The offset for the next API request.
            args: Positional arguments to be passed to the API request function.
            kwarg: Keyword arguments to be passed to the API request function.

        Returns:
            tuple[list | dict, list | dict]:
                All the items combined within raw response, All the raw responses combined
        """
        kwargs['self'] = client_instance

        raw_items: list[dict[str, Any]] = []
        raw_responses: list[dict[str, Any]] = []

        # Keep calling the API until the required amount of items have been met.
        while remaining_items > 0:
            limit = min(remaining_items, self.api_limit)
            kwargs |= {
                'limit': limit,
                'offset': offset,
            }

            raw_response = func(
                *args,
                **kwargs,
            )

            raw_item = raw_response

            if self.items_key_path:
                raw_item = dict_safe_get(raw_item, self.items_key_path)

            if raw_item is None:
                break

            raw_responses.append(raw_response)
            raw_items += raw_item

            if (received_items := len(raw_item)) < limit:
                break

            # Calculate the offset and limit for the next run.
            remaining_items -= received_items
            offset = (offset or 0) + received_items

        return raw_items, raw_responses


'''Client'''


class Client(BaseClient):
    isASAv = False
    auth_token = ""

    def login(self, isASAv) -> None:
        """
        Receive an auth token from the headers after a basic authentication has been made.

        Args:
            isASAv (bool): Whether Cisco Adaptive Security Virtual Appliance is in use.
        """
        if isASAv:
            self.isASAv = True
            res = self._http_request('POST', '/api/tokenservices', resp_type='response')
            auth_token = res.headers._store.get('x-auth-token')[1]
            self._headers['X-Auth-Token'] = auth_token
            self.auth_token = auth_token

    def logoff(self):
        """
        Delete the generated auth token.
        """
        try:
            if self.isASAv and self.auth_token:
                self._http_request('DELETE', f'/api/tokenservices/{self.auth_token}', resp_type='response')
        except Exception as e:
            # if failed to logoof just write to log. no need to raise error
            demisto.debug(f'Logoff error: {str(e)}')

    def get_all_rules(self, specific_interface: str | None = None, rule_type: str = 'All') -> list:
        """
        Gets a list all rules for the supplied interface.

        Args:
             specific_interface): the name of the interface
             rule_type: All/Global/In

        Returns:
             all rules in Cisco ASA of the specified type/interface
        """
        rules = []  # type: list
        # Get global rules
        if specific_interface is None and rule_type in ['All', 'Global']:
            res = self._http_request('GET', '/api/access/global/rules')
            items = res.get('items', [])
            for item in items:
                item['interface_type'] = "Global"
            rules.extend(items)

        # Get in rules
        if rule_type in ['All', 'In']:
            res = self._http_request('GET', '/api/access/in')
            interfaces = []
            for item in res.get('items', []):
                interface_name = item.get('interface', {}).get('name')
                if interface_name and specific_interface and specific_interface == interface_name:
                    interfaces.append(interface_name)
                if interface_name and not specific_interface:
                    interfaces.append(interface_name)
            for interface in interfaces:
                res = self._http_request('GET', f'/api/access/in/{interface}/rules')
                items = res.get('items', [])
                for item in items:
                    item['interface'] = interface
                    item['interface_type'] = "In"
                rules.extend(items)

        # Get out rules
        if rule_type in ['All', 'Out']:
            res = self._http_request('GET', '/api/access/out')
            interfaces = []
            for item in res.get('items', []):
                interface_name = item.get('interface', {}).get('name')
                if interface_name and specific_interface and specific_interface == interface_name:
                    interfaces.append(interface_name)
                if interface_name and not specific_interface:
                    interfaces.append(interface_name)
            for interface in interfaces:
                res = self._http_request('GET', f'/api/access/out/{interface}/rules')
                items = res.get('items', [])
                for item in items:
                    item['interface'] = interface
                    item['interface_type'] = "Out"
                rules.extend(items)

        return rules

    def rule_action(self, rule_id: str, interface_name: str, interface_type: str, command: str = 'GET',
                    data: dict = None) -> dict:
        """
        Get, update or delete a rule.

        Args:
            rule_id: The Rule ID.
            interface_name: the name of the interface.
            interface_type: The type of interface.
            command: The operation to do on the rule.
            data: The data of the rule to update.

        Returns:
            Does the command on the rule.
            Delete - delete rule
            GET - rule info
            PATCH - edit rule
        """
        rule = {}
        resp_type = {"GET": "json",
                     "DELETE": "text",
                     "PATCH": "response"
                     }
        if interface_type == "Global":
            rule = self._http_request(command, f'/api/access/global/rules/{rule_id}', resp_type=resp_type[command],
                                      json_data=data)
        if interface_type == "In":
            rule = self._http_request(command, f'/api/access/in/{interface_name}/rules/{rule_id}',
                                      resp_type=resp_type[command], json_data=data)
        if interface_type == 'Out':
            rule = self._http_request(command, f'/api/access/out/{interface_name}/rules/{rule_id}',
                                      resp_type=resp_type[command], json_data=data)
        if command == 'GET':
            rule['interface'] = interface_name
            rule['interface_type'] = interface_type
        return rule

    def create_rule(self, interface_type: str, interface_name: str, rule_body: dict) -> dict:
        """
        Create a rule.

        Args:
            interface_type: The interface type of the rule, can be one of: Global/In/Out.
            interface_name: The name of the provided interface, applies to In/Out interface types.
            rule_body: The information about the rule.

        Returns:
            The new created rule's information.
        """
        res = Response()
        if interface_type == "Global":
            res = self._http_request("POST", '/api/access/global/rules', json_data=rule_body, resp_type="response")
        if interface_type == 'In':
            res = self._http_request("POST", f'/api/access/in/{interface_name}/rules', json_data=rule_body,
                                     resp_type="response")
        if interface_type == 'Out':
            res = self._http_request("POST", f'/api/access/out/{interface_name}/rules', json_data=rule_body,
                                     resp_type="response")
        loc = res.headers.get("Location", "")
        rule = self._http_request('GET', loc[loc.find('/api'):])
        rule['interface'] = interface_name
        rule['interface_type'] = interface_type
        return rule

    def test_command(self):
        """
        A command to test the connection to the Cisco ASA server.
        """
        self._http_request("GET", "/api/aaa/authorization")

    def backup(self, data: dict):
        """
        Creates a backup of the current settings (i.e., the backup.cfg file).

        Args:
            data (dict): The backup name and passphrase.
        """
        self._http_request("POST", "/api/backup", json_data=data, resp_type="response")

    def restore(self, data: dict):
        """
        Restore a backup. Currently this command isn't in use through XSOAR.

        Args:
            data (dict): The backup name and passphrase.
        """
        self._http_request("POST", "/api/restore", json_data=data, resp_type='response')

    def get_network_obejcts(self):
        """
        Gets a list of all the configured network objects.
        """
        obj_res = self._http_request('GET', '/api/objects/networkobjects')
        return obj_res.get('items', [])

    def create_object(self, obj_name, obj_type, obj_value):
        """
        Creates a network object.

        Args:
            obj_name (str): The name of the network object.
            obj_type (str): The kind of the network object.
            obj_value (_type_): The value of the network object.

        Returns:
            Whether the network object was created successfully.
        """
        data = {
            "kind": "object#NetworkObj",
            "name": obj_name,
            "host": {
                "kind": OBJECT_TYPES_DICT.get(obj_type),
                "value": obj_value
            }
        }
        try:
            return self._http_request('POST', '/api/objects/networkobjects', json_data=data, ok_codes=(200, 201, 204),
                                      resp_type='response')
        except Exception:
            raise

    def list_interfaces(self):
        """
        Returns a list of interfaces.
        """
        interfaces = []  # type: ignore
        for type in ['global', 'in', 'out']:
            resp = self._http_request('GET', f'/api/access/{type}')
            interfaces.extend(resp.get('items', []))
        return interfaces

    @Pagination(api_limit=API_LIMIT, items_key_path=['items'])
    def list_network_object_group(self, limit: int = DEFAULT_LIMIT, offset: int = None) -> dict[str, Any]:
        """
        This command is decorated by Pagination class,
        therefore the arguments that must be passed to it are: page, page_size and limit.

        Retrieves information about network object groups.

        Args:
            limit (int, optional): The number of results to return.
                Defaults to None.
            offset (int, optional): The offset from where to start returning results.
                Defaults to None.

        Returns:
            dict[str, Any]: Information about network object groups.
        """
        return self._http_request(
            method='GET',
            url_suffix='api/objects/networkobjectgroups',
            params=assign_params(limit=limit, offset=offset),
        )

    def get_network_object_group(self, object_id: str) -> dict[str, Any]:
        """
        Retrieve information about a network object group.

        Args:
            object_id (str): The object ID of the network group to retrieve

        Returns:
            dict[str, Any]: Information about a network object group.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'api/objects/networkobjectgroups/{object_id}',
        )

    @Pagination(api_limit=API_LIMIT, items_key_path=['items'])
    def list_local_user_group(self, limit: int = DEFAULT_LIMIT, offset: int = None) -> dict[str, Any]:
        """
        This command is decorated by Pagination class,
        therefore the arguments that must be passed to it are: page, page_size and limit.

        Retrieves information about local user groups.

        Args:
            limit (int, optional): The number of results to return.
                Defaults to None.
            offset (int, optional): The offset from where to start returning results.
                Defaults to None.

        Returns:
            dict[str, Any]: Information about local user groups.
        """
        return self._http_request(
            'GET',
            'api/objects/localusergroups',
            params=assign_params(limit=limit, offset=offset),
        )

    def get_local_user_group(self, object_id: str) -> dict[str, Any]:
        """
        Retrieve information about a local user group.

        Args:
            object_id (str): The object ID of the local user group to retrieve

        Returns:
            dict[str, Any]: Information about the local user group.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'api/objects/localusergroups/{object_id}',
        )

    @Pagination(api_limit=API_LIMIT, items_key_path=['items'])
    def list_local_user(self, limit: int = DEFAULT_LIMIT, offset: int = None) -> dict[str, Any]:
        """
        This command is decorated by Pagination class,
        therefore the arguments that must be passed to it are: page, page_size and limit.

        Retrieves information about local users.

        Args:
            limit (int, optional): The number of results to return.
                Defaults to None.
            offset (int, optional): The offset from where to start returning results.
                Defaults to None.

        Returns:
            dict[str, Any]: Information about local users.
        """
        return self._http_request(
            method='GET',
            url_suffix='api/objects/localusers',
            params=assign_params(limit=limit, offset=offset),
        )

    def get_local_user(self, object_id: str) -> dict[str, Any]:
        """
        Retrieve information about a local user.

        Args:
            object_id (str): The object ID of the local user to retrieve

        Returns:
            dict[str, Any]: Information about the local user.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'api/objects/localusers/{object_id}',
        )

    @Pagination(api_limit=API_LIMIT, items_key_path=['items'])
    def list_time_range(self, limit: int = DEFAULT_LIMIT, offset: int = None) -> dict[str, Any]:
        """
        This command is decorated by Pagination class,
        therefore the arguments that must be passed to it are: page, page_size and limit.

        Retrieves information about time ranges.

        Args:
            limit (int, optional): The number of results to return.
                Defaults to None.
            offset (int, optional): The offset from where to start returning results.
                Defaults to None.

        Returns:
            dict[str, Any]: Information about time ranges.
        """
        return self._http_request(
            method='GET',
            url_suffix='api/objects/timeranges',
            params=assign_params(limit=limit, offset=offset),
        )

    def get_time_range(self, object_id: str) -> dict[str, Any]:
        """
        Retrieve information about a time range.

        Args:
            object_id (str): The object ID of the time range to retrieve

        Returns:
            dict[str, Any]: Information about the time range.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'api/objects/timeranges/{object_id}',
        )

    @Pagination(api_limit=API_LIMIT, items_key_path=['items'])
    def list_security_object_group(self, limit: int = DEFAULT_LIMIT, offset: int = None) -> dict[str, Any]:
        """
        This command is decorated by Pagination class,
        therefore the arguments that must be passed to it are: page, page_size and limit.

        Retrieves information about security object groups.

        Args:
            limit (int, optional): The number of results to return.
                Defaults to None.
            offset (int, optional): The offset from where to start returning results.
                Defaults to None.

        Returns:
            dict[str, Any]: Information about security object groups.
        """
        return self._http_request(
            method='GET',
            url_suffix='api/objects/securityobjectgroups',
            params=assign_params(limit=limit, offset=offset),
        )

    def get_security_object_group(self, object_id: str) -> dict[str, Any]:
        """
        Retrieve information about a security object group.

        Args:
            object_id (str): The object ID of the security object group to retrieve

        Returns:
            dict[str, Any]: Information about the security object group.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'api/objects/securityobjectgroups/{object_id}',
        )

    @Pagination(api_limit=API_LIMIT, items_key_path=['items'])
    def list_user_object(self, limit: int = DEFAULT_LIMIT, offset: int = None) -> dict[str, Any]:
        """
        This command is decorated by Pagination class,
        therefore the arguments that must be passed to it are: page, page_size and limit.

        Retrieves information about user objects.

        Args:
            limit (int, optional): The number of results to return.
                Defaults to None.
            offset (int, optional): The offset from where to start returning results.
                Defaults to None.

        Returns:
            dict[str, Any]: Information about user objects.
        """
        return self._http_request(
            method='GET',
            url_suffix='api/objects/userobjects',
            params=assign_params(limit=limit, offset=offset),
        )

    def get_user_object(self, object_id: str) -> dict[str, Any]:
        """
        Retrieve information about a user object.

        Args:
            object_id (str): The object ID of the user object to retrieve

        Returns:
            dict[str, Any]: Information about the user object.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'api/objects/userobjects/{object_id}',
        )

    def write_memory(self) -> dict[str, Any]:
        """
        The write memory command saves the running configuration to the default location for the startup configuration.

        Returns:
            dict[str, Any]: shows a successful 'writemem' command execution on a Cisco ASA device,
                building the configuration and generating a cryptochecksum for integrity.
                The process is completed with an "[OK]" message.
        """
        return self._http_request(
            method='POST',
            url_suffix='api/commands/writemem',
            headers=self._headers | {'Content-Type': 'application/json'}
        )


'''HELPER COMMANDS'''


@logger
def set_up_ip_kind(dict_body: dict, field_to_add: str, data: str) -> None:
    """
    Takes the data, checks what kind of source/dest it is (IP, network, any or network object) and inserts to the
    dict the field_to_add as key and the source/dest as value in the correct format.

    Args:
        dict_body: The dict to add the data to.
        field_to_add: the name of the field to add to json.
        data: the string to check its kind and insert to dict.
    """
    if is_ip_valid(data):
        dict_body[field_to_add] = {"kind": "IPv4Address",
                                   "value": data}
    elif data == 'any':
        dict_body[field_to_add] = {"kind": "AnyIPAddress",
                                   "value": "any4"}
    elif '/' in data:
        dict_body[field_to_add] = {"kind": "IPv4Network",
                                   "value": data}
    else:
        dict_body[field_to_add] = {"kind": "objectRef#NetworkObj",
                                   "objectId": data}


@logger
def raw_to_rules(raw_rules):
    """
    :param raw_rules:
    :return:
    Gets raw rules as received from API and extracts only the relevant fields
    """
    rules = []
    for rule in raw_rules:
        source_services = rule.get('sourceService', {})

        if isinstance(source_services, list):
            source_services_list = [v['value'] for v in source_services]
        else:
            source_services_list = source_services.get('value')

        dest_services = rule.get('destinationService', {})
        if isinstance(dest_services, list):
            dest_services_list = [v['value'] for v in dest_services]
        else:
            dest_services_list = dest_services.get('value')

        rule_object_mapping: dict = remove_empty_elements({
            new_object_key: {
                'kind': dict_safe_get(rule, [object_key, 'kind']),
                'value': dict_safe_get(rule, [object_key, 'value']),
                'objectId': dict_safe_get(rule, [object_key, 'objectId']),
            }
            for new_object_key, object_key in [
                ('SourceSecurity', 'srcSecurity'),
                ('DestinationSecurity', 'dstSecurity'),
                ('User', 'user'),
                ('TimeRange', 'timeRange'),
            ]
        })

        rules.append(
            {
                'Source': safe_get_all_values(obj=rule.get('sourceAddress'), key='value'),
                'SourceService': source_services_list,
                'Dest': safe_get_all_values(obj=rule.get('destinationAddress'), key='value'),
                'DestService': dest_services_list,
                'IsActive': rule.get('active'),
                'Interface': rule.get('interface'),
                'InterfaceType': rule.get('interface_type'),
                'Remarks': rule.get('remarks'),
                'Position': rule.get('position'),
                'ID': rule.get('objectId'),
                'Permit': rule.get('permit'),
                'SourceKind': dict_safe_get(rule, ['sourceAddress', 'kind']),
                'DestKind': dict_safe_get(rule, ['destinationAddress', 'kind']),
            } | rule_object_mapping
        )
        if not rules[-1].get('Source'):
            rules[-1]['Source'] = safe_get_all_values(obj=rule.get('sourceAddress'), key='objectId')
        if not rules[-1].get('Dest'):
            rules[-1]['Dest'] = safe_get_all_values(obj=rule.get('destinationAddress'), key='objectId')

    return rules


@logger
def is_get_request_type(get_args: list, list_args: list) -> bool:
    """
    Determine whether the request arguments are for a GET or LIST request.

    Args:
        get_args (list): GET request arguments.
        list_args (list): LIST request arguments.

    Raises:
        ValueError: In case the user has entered both GET and LIST arguments, raise an error.

    Returns:
        bool: True if the arguments are for a GET request, False otherwise.
    """
    is_get_request = any(get_args)
    is_list_request = any(list_args)

    if is_get_request and is_list_request:
        raise ValueError('GET and LIST arguments can not be supported simultaneously.')

    return is_get_request


@logger
def extract_data(
    obj: list[dict | list] | dict[str, Any],
    keys_mapping: dict[str, Any]
) -> list[dict | list] | dict[str, Any]:
    """
    Extract specific keys from a nested dictionary or a list of dictionaries
    based on the provided keys_mapping structure.

    Args:
        obj (list[dict | list] | dict[str, Any]): The input object, either a dictionary or a list of dictionaries.
        keys_mapping (dict[str, Any]): A dictionary specifying the mapping of keys to extract and their new names.

    Returns:
        list[dict | list] | dict[str, Any]:
            The extracted object, either a dictionary or a list of dictionaries.
    """
    if isinstance(obj, list):
        return [extract_data(nested_obj, keys_mapping) for nested_obj in obj]

    return extract_data_from_dict(obj, keys_mapping)


@logger
def extract_data_from_dict(dict_obj: dict[str, Any], keys_mapping: dict[str, Any]) -> dict[str, Any]:
    """
    Extract specific keys from a dictionary based on the provided keys_mapping structure.

    Args:
        dict_obj (dict[str, Any]): The input dictionary to extract keys from.
        keys_mapping (dict[str, Any]): A dictionary specifying the mapping of keys to extract and their new names.
            The keys of this dictionary should correspond to keys in the dict_obj. The values can be either:
            - a string: the corresponding key in the output dictionary will have the same name.
            - a nested dictionary: the key-value pairs in the nested dictionary will be extracted recursively.

    Returns:
        dict[str, Any]: The extracted dictionary.
    """
    extracted: dict[str, Any] = {}

    for key, new_key in keys_mapping.items():
        if isinstance(new_key, dict) and (nested_obj := dict_obj.get(key)) is not None:
            nested_keys_mapping = deepcopy(new_key)
            include_key = nested_keys_mapping.pop('_include', True)

            extracted_data = extract_data(nested_obj, nested_keys_mapping)
            extracted |= {key: extracted_data} if include_key else extracted_data

        elif (value := dict_obj.get(key)) is not None:
            extracted[new_key] = value

    return extracted


def arg_to_optional_bool(arg: Any | None) -> bool | None:
    """
    Wrapper to argToBoolean function that will allow Optional arguments.

    Args:
        arg (Optional[Any]): The value to evaluate.
            Defaults to None.

    Returns:
        Optional[bool]: a boolean representation of 'arg' or None.
    """
    return argToBoolean(arg) if arg is not None else None


def setup_address(
    rule_body: dict[str, Any],
    address_direction: str,
    address_value: str,
    address_kind: str,
) -> None:
    """
    Sets up the source or destination address in the rule_body.

    Args:
        rule_body (dict[str, Any]): The rule body to set up the address.
        address_direction (str): 'sourceAddress' or 'destinationAddress'.
        address_value (str): The value of the address.
        address_kind (str): The kind of the address.
    """
    if address_kind in ['NetworkObj', 'NetworkObjGroup']:
        key = 'objectId'
        address_kind = f'objectRef#{address_kind}'
    else:
        key = 'value'

    rule_body[address_direction] = {'kind': address_kind, key: address_value}


def handle_address_in_rule(
    rule_body: dict[str, Any],
    direction: str,
    address_value: str = None,
    address_kind: str = None,
) -> None:
    """
    Handles the address kind and value in the rule update.

    Args:
        rule_body (dict[str, Any]): The rule body to set up the address.
        direction (str): The direction of the address, 'source' or 'destination'.
        address_value (str, optional): The value of the address.
            Defaults to None.
        address_kind (str, optional): The kind of the address.
            Defaults to None.
    """
    address_direction = f'{direction}Address'

    if address_value and address_kind:
        setup_address(
            rule_body=rule_body,
            address_direction=address_direction,
            address_value=address_value,
            address_kind=address_kind,
        )
    elif address_value:
        set_up_ip_kind(rule_body, address_direction, address_value)


def setup_service(
    rule_body: dict[str, Any],
    source_service: str,
    source_service_kind: str = None,
    destination_service: str = None,
    destination_service_kind: str = None,
) -> None:
    """
    Sets up the source and destination services.

    Args:
        rule_body (dict[str, Any]): The rule body to update.
        source_service (str): The source service.
        source_service_kind (str, optional): The kind of the source service.
            Defaults to None.
        destination_service (str, optional): The destination service.
            Defaults to None.
        destination_service_kind (str, optional): The kind of the destination service.
            Defaults to None.

    Raises:
        ValueError: Incase the user has only provided one of the destination service arguments.
    """
    rule_body['sourceService'] = {'kind': source_service_kind or 'NetworkProtocol', 'value': source_service}

    if destination_service and destination_service_kind:
        rule_body['destinationService'] = {'kind': destination_service_kind, 'value': destination_service}
    elif destination_service or destination_service_kind:
        raise ValueError('Missing arg in destination service, please provide both destination kind and value.')
    else:
        rule_body['destinationService'] = {'kind': 'NetworkProtocol', 'value': source_service}


def setup_security(
    rule_body: dict[str, Any],
    direction: str,
    security_kind: str = None,
    security_value: str = None,
) -> None:
    """
    Sets up the source or destination security in the rule_body.

    Args:
        rule_body (dict[str, Any]): The rule body to set up the security.
        direction (str): The direction of the security, 'source' or 'destination'.
        security_kind (str, optional): The kind of the security.
            Defaults to None.
        security_value (str, optional): The value of the security.
            Defaults to None.

    Raises:
        ValueError: Incase the user has only provided one of the security arguments.
    """
    if security_kind and security_value:
        if security_kind == 'SecurityObjGroup':
            security_kind = f'objectRef#{security_kind}'
            key = 'objectId'
        else:
            key = 'value'

        rule_body[f'{direction}Security'] = {'kind': security_kind, key: security_value}

    elif security_kind or security_value:
        raise ValueError(f'Missing arg in {direction} security, please provide both security kind and value.')


def setup_user(
    rule_body: dict[str, Any],
    user: str = None,
    user_kind: str = None,
) -> None:
    """
    Sets up the user in the rule_body.

    Args:
        rule_body (dict[str, Any]): The rule body to set up the user.
        user (str, optional): The user.
            Defaults to None.
        user_kind (str, optional): The kind of the user.
            Defaults to None.

    Raises:
        ValueError: Incase the user has only provided one of the user arguments.
    """
    if user_kind and user:
        rule_body['user'] = {'kind': f'objectRef#{user_kind}', 'objectId': user}
    elif user_kind or user:
        raise ValueError('Missing arg in user. Please provide both user kind and value.')


def setup_time_range(rule_body: dict[str, Any], time_range: str = None) -> None:
    """
    Sets up the time range in the rule_body.

    Args:
        rule_body (dict[str, Any]): The rule body to set up the time range.
        time range (str, optional): The time range to add.
            Defaults to None.
    """
    if time_range:
        rule_body['timeRange'] = {'kind': 'objectRef#TimeRange', 'objectId': time_range}


def handle_rule_configurations_setup(rule_body: dict[str, Any], args: dict[str, Any]) -> None:
    """ Sets up the configurations for the rule.

    Add to the given rule_body the service, security, user and time range objects if they exist within args.

    Args:
        rule_body (dict[str, Any]): A reference to the dictionary to modify.
        args (dict[str, Any]): The args to add to the rule_body.
    """
    if service := args.get('service'):
        setup_service(
            rule_body=rule_body,
            source_service=service,
            source_service_kind=args.get('service_kind'),
            destination_service=args.get('destination_service'),
            destination_service_kind=args.get('destination_service_kind'),
        )

    setup_security(
        rule_body=rule_body,
        direction='src',
        security_kind=args.get('source_security_kind'),
        security_value=args.get('source_security'),
    )
    setup_security(
        rule_body=rule_body,
        direction='dst',
        security_kind=args.get('destination_security_kind'),
        security_value=args.get('destination_security'),
    )
    setup_user(
        rule_body=rule_body,
        user=args.get('user'),
        user_kind=args.get('user_kind'),
    )
    setup_time_range(
        rule_body=rule_body,
        time_range=args.get('time_range')
    )

    rule_body['active'] = argToBoolean(args['active'])

    if position := args.get('position'):
        rule_body['position'] = position
    if log_level := args.get('log_level'):
        rule_body['ruleLogging'] = {'logStatus': log_level}
    if permit := args.get('permit'):
        rule_body['permit'] = arg_to_optional_bool(permit)
    if remarks := argToList(args.get('remarks')):
        rule_body['remarks'] = remarks


def safe_get_all_values(
    obj: list[dict[str, Any]] | dict[str, Any] | None,
    key: str,
    default_value: Any = None,
) -> Any:
    """ Get all values from a list of dicts or a dict.

    Args:
        obj (list[dict[str, Any]] | dict[str, Any] | None): The object to extract values from.
        key (str): The key to the value to be extracted.
        default_value (Any, optional): The default value to return in case of failure.
            Defaults to None.

    Returns:
        Any: _description_
    """
    if not obj:
        return default_value

    if isinstance(obj, dict):
        return obj.get(key, default_value)

    return [item.get(key, default_value) for item in obj if key in obj]


'''COMMANDS'''


@logger
def list_rules_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Gets a list all rules for the supplied interface.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
            Interface_name - get rules from a specific interface.
            Interface_type - get rules from a specific type of interface.

    Raises:
        ValueError: The given interface couldn't be found.
        e: Unknown error.

    Returns:
        CommandResults: A CommandResults object containing the results of the rules.
    """
    interface = args.get('interface_name')
    interface_type = args.get('interface_type', 'All')

    try:
        raw_rules = client.get_all_rules(interface, interface_type)  # demisto.getRules() #
        rules = raw_to_rules(raw_rules)
        hr = tableToMarkdown("Rules:", rules, ["ID", "Source", "Dest", "Permit", "Interface", "InterfaceType",
                                               "IsActive", "Position", "SourceService", "DestService"])
        return CommandResults(
            readable_output=hr,
            outputs_prefix='CiscoASA.Rules',
            outputs=rules,
            raw_response=raw_rules,
        )

    except Exception as e:
        if "404" in str(e) and interface:
            raise ValueError("Could not find interface") from e
        else:
            raise e


@logger
def backup_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates a backup. Returns a message if backup was created successfully.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of the backup operation.
    """
    location = "disk0:/" + args.get("backup_name", "")
    passphrase = args.get("passphrase")
    data = {'location': location}
    if passphrase:
        data['passphrase'] = passphrase

    client.backup(data)
    return CommandResults(
        readable_output=f"Created backup successfully in:\nLocation: {location}\nPassphrase: {passphrase}"
    )


@logger
def restore_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Restore a backup. Currently this command isn't in use through XSOAR.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of the restore operation.
    """
    location = "disk0:/" + args.get("backup_name", "")
    passphrase = args.get("passphrase")
    data = {'location': location}
    if passphrase:
        data['passphrase'] = passphrase

    client.restore(data)
    return CommandResults(readable_output="Restored backup successfully.")


@logger
def rule_by_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Gets a specific rule by rule ID.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        ValueError: The provided interface type was inbound/outbound and no interface name was given.

    Returns:
        CommandResults: A CommandResults object containing the results of the rule.
    """
    rule_id = args.get('rule_id', '')
    interface_type = args.get('interface_type', '')
    interface = args.get('interface_name', '')

    if interface_type != "Global" and not interface:
        raise ValueError("Please state the name of the interface when it's not a global interface.")
    interface = "" if interface_type == "Global" else interface

    raw_rules = client.rule_action(rule_id, interface, interface_type, 'GET')
    rules = raw_to_rules([raw_rules])
    hr = tableToMarkdown(f"Rule {rule_id}:", rules, ["ID", "Source", "Dest", "Permit", "Interface",
                                                     "InterfaceType", "IsActive", "Position", "SourceService",
                                                     "DestService"])
    return CommandResults(
        readable_output=hr,
        outputs_prefix='CiscoASA.Rules',
        outputs=rules,
        raw_response=raw_rules,
    )


@logger
def create_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates a rule.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        ValueError: The provided interface type was inbound/outbound and no interface name was given.
        ValueError: The rule already exists.
        ValueError: The interface couldn't be found.
        ValueError: Unknown error.

    Returns:
        CommandResults: A CommandResults object containing the results of the created rule.
    """
    interface_name = args.get('interface_name')
    interface_type = args.get('interface_type', '')

    if interface_type == 'Global':
        interface_name = ''
    elif not interface_name:
        raise ValueError('For In/Out interfaces, an interface name is mandatory.')

    rule_body = {}  # type: dict

    # setup the source and destination address
    handle_address_in_rule(
        rule_body=rule_body,
        direction='source',
        address_value=args.get('source'),
        address_kind=args.get('source_kind'),
    )
    handle_address_in_rule(
        rule_body=rule_body,
        direction='destination',
        address_value=args.get('destination'),
        address_kind=args.get('destination_kind'),
    )

    args['service'] = args.get('service', 'ip')
    handle_rule_configurations_setup(rule_body, args)

    try:
        raw_rule = client.create_rule(interface_type, interface_name, rule_body)
        rules = raw_to_rules([raw_rule])

        hr = tableToMarkdown(
            f'Created new rule. ID: {raw_rule.get("objectId")}',
            rules,
            [
                'ID',
                'Source',
                'Dest',
                'Permit',
                'Interface',
                'InterfaceType',
                'IsActive',
                'Position',
                'SourceService',
                'DestService'
            ]
        )

        return CommandResults(
            readable_output=hr,
            outputs_prefix='CiscoASA.Rules',
            outputs=rules,
            raw_response=raw_rule,
        )

    except Exception as e:
        if 'DUPLICATE' in str(e):
            raise ValueError('You are trying to create a rule that already exists.') from e
        if '[500]' in str(e):
            raise ValueError(f'Could not find interface: {interface_name}') from e
        else:
            raise ValueError(f'Could not create rule. Error {str(e)}')


@logger
def delete_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Deletes a rule.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        ValueError: The provided interface type was inbound/outbound and no interface name was given.
        ValueError: Incase the rule doesn't exist.
        ValueError: The rule cannot be deleted.

    Returns:
        CommandResults: A CommandResults object containing the results of the deleted rule.
    """
    rule_id = args.get('rule_id', '')
    interface = args.get('interface_name', '')
    interface_type = args.get('interface_type', '')
    if interface_type != "Global" and not interface:
        raise ValueError("Please state the name of the interface when it's not a global interface.")

    try:
        client.rule_action(rule_id, interface, interface_type, 'DELETE')
    except Exception as e:
        if 'Not Found' in str(e):
            raise ValueError(f"Rule {rule_id} does not exist in interface {interface} of type {interface_type}.") from e
        else:
            raise ValueError(f"Could not delete rule. Error {str(e)}")

    return CommandResults(readable_output=f"Rule {rule_id} deleted successfully.")


@logger
def edit_rule_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Updates an existing rule.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        ValueError: In case the rule already exists.
        ValueError: The provided interface cannot be found.
        ValueError: Unexpected error.

    Returns:
        CommandResults: A CommandResults object containing the results of the edited rule.
    """
    rule_id = args.get('rule_id', '')
    interface_type = args.get('interface_type', '')
    interface_name = args.get('interface_name')

    if interface_type == 'Global':
        interface_name = ''
    elif not interface_name:
        raise ValueError('Please state the name of the interface when it\'s not a global interface.')

    rule_body = {}  # type: dict

    # setup the source and destination address
    handle_address_in_rule(
        rule_body=rule_body,
        direction='source',
        address_value=args.get('source'),
        address_kind=args.get('source_kind'),
    )
    handle_address_in_rule(
        rule_body=rule_body,
        direction='destination',
        address_value=args.get('destination'),
        address_kind=args.get('destination_kind'),
    )

    handle_rule_configurations_setup(rule_body, args)

    try:
        rule = client.rule_action(rule_id, interface_name, interface_type, 'PATCH', rule_body)
        try:
            raw_rule = client.rule_action(rule_id, interface_name, interface_type, 'GET')
        except Exception:
            location = rule.headers._store.get('location')[1]  # type: ignore
            rule_id = location[location.rfind('/') + 1:]
            raw_rule = client.rule_action(rule_id, interface_name, interface_type, 'GET')

        rules = raw_to_rules([raw_rule])

        hr = tableToMarkdown(
            f'Edited rule {raw_rule.get("objectId")}',
            rules,
            [
                'ID',
                'Source',
                'Dest',
                'Permit',
                'Interface',
                'InterfaceType',
                'IsActive',
                'Position',
                'SourceService',
                'DestService',
            ],
        )

        return CommandResults(
            readable_output=hr,
            outputs_prefix='CiscoASA.Rules',
            outputs=rules,
            raw_response=raw_rule,
        )

    except Exception as e:
        if 'DUPLICATE' in str(e):
            raise ValueError('You are trying to create a rule that already exists.') from e

        if '[500]' in str(e):
            raise ValueError(f'Could not find interface: {interface_name}.') from e

        raise


@logger
def list_objects_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Gets a list of all the configured network objects.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of network objects.
    """
    objects = client.get_network_obejcts()
    obj_names = argToList(args.get('object_name'))
    obj_ids = argToList(args.get('object_id'))
    formated_objects = []
    for object in objects:
        if (not obj_names and not obj_ids) or object.get('name') in obj_names or object.get('objectId') in obj_ids:
            object.pop('selfLink')
            object.pop('kind')
            formated_obj = camelize(object)
            formated_obj['ID'] = formated_obj.pop('Objectid')
            formated_objects.append(formated_obj)
    hr = tableToMarkdown("Network Objects", formated_objects, headers=['ID', 'Name', 'Host', 'Description'])

    return CommandResults(
        readable_output=hr,
        outputs_prefix='CiscoASA.NetworkObject',
        outputs=formated_objects,
        raw_response=formated_objects,
    )


@logger
def create_object_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates a network object.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Raises:
        ValueError: Incase a user hasn't entered an object type from the provided list.

    Returns:
        CommandResults: A CommandResults object containing the results of the created network object.
    """
    obj_type = args.get('object_type')
    obj_name = args.get('object_name')
    obj_value = args.get('object_value')
    if obj_type not in OBJECT_TYPES_DICT.keys():
        raise ValueError("Please enter an object type from the given dropdown list.")
    client.create_object(obj_name, obj_type, obj_value)
    return list_objects_command(client, {'object_name': obj_name})


@logger
def list_interfaces_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Gets a list of all interfaces.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of the interfaces.
    """
    raw_interfaces = client.list_interfaces()
    interface_list = []
    for interface in raw_interfaces:

        temp_interface = {'Type': interface.get('direction', '').capitalize(),
                          'ID': interface.get('interface', {}).get('objectId', '-1'),
                          'Name': interface.get('interface', {}).get('name')}
        interface_list.append(temp_interface)
    ec = {'CiscoASA.Interface(val.ID && val.ID== obj.ID)': interface_list}
    hr = tableToMarkdown('Interfaces', interface_list, ['Type', 'ID', 'Name'])
    return CommandResults(
        readable_output=hr,
        outputs=ec,
        raw_response=raw_interfaces,
    )


@logger
def test_command(client: Client, isASAv: bool) -> str:
    """
    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        isASAv (bool): Whether Cisco Adaptive Security Virtual Appliance is in use.

    Returns:
        Runs a random GET API request just to see if successful.
    """

    try:
        client.login(isASAv)
        client.test_command()

    except DemistoException as exc:
        if exc.res is not None and exc.res.status_code == HTTPStatus.UNAUTHORIZED:
            return 'Authorization Error: invalid username or password'

        return exc.message

    return 'ok'


@logger
def list_object_command(
    client_get_command: Callable,
    client_list_command: Callable,
    args: dict[str, Any],
    keys_mapping: dict[str, Any],
    title: str,
    outputs_prefix: str,
    readable_headers: list[str] = None,
) -> CommandResults:
    """
    A generic function to list objects using the provided get and list commands.

    Args:
        client_get_command (Callable): The client's GET method for a single object.
        client_list_command (Callable): The client's LIST method for multiple objects.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
        keys_mapping (dict[str, Any]): A dictionary to map response keys to desired output keys.
        title (str): The title for the table in the human-readable output.
        outputs_prefix (str): The prefix for the output context path.

    Returns:
        CommandResults: A CommandResults object containing the command's results.
    """
    # GET arguments
    object_id = args.get('object_id', '')
    # LIST arguments
    limit = arg_to_number(args.get('limit'), required=False)
    page = arg_to_number(args.get('page'), required=False)
    page_size = arg_to_number(args.get('page_size'), required=False)

    raw_items = None

    if is_get_request_type(
        get_args=[object_id],
        list_args=[page, page_size],
    ):
        raw_response = client_get_command(object_id)
    else:  # is_list_request
        raw_items, raw_response = client_list_command(
            page=page,
            page_size=page_size,
            limit=limit,
        )

    outputs = extract_data(
        obj=raw_items or raw_response,
        keys_mapping=keys_mapping,
    )

    readable_output = tableToMarkdown(
        name=title,
        t=outputs,
        headers=readable_headers or [camel_case_to_underscore(key) for key in keys_mapping],
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f'CiscoASA.{outputs_prefix}',
        outputs_key_field='object_id',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_network_object_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Lists network object groups using the provided client and arguments.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of the network object group.
    """
    return list_object_command(
        client_get_command=client.get_network_object_group,
        client_list_command=client.list_network_object_group,
        args=args,
        keys_mapping=DEFAULT_KEYS_MAPPING,
        title='Network Object Groups',
        outputs_prefix='NetworkObjectGroup',
    )


@logger
def list_local_user_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Lists local user groups using the provided client and arguments.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of the local user groups.
    """
    return list_object_command(
        client_get_command=client.get_local_user_group,
        client_list_command=client.list_local_user_group,
        args=args,
        keys_mapping=DEFAULT_KEYS_MAPPING,
        title='Local User Groups',
        outputs_prefix='LocalUserGroup',
    )


@logger
def list_local_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Lists local users using the provided client and arguments.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of the local user.
    """
    return list_object_command(
        client_get_command=client.get_local_user,
        client_list_command=client.list_local_user,
        args=args,
        keys_mapping={
            'objectId': 'object_id',
            'name': 'name',
            'MSCHAPauthenticated': 'mschap_authenticated',
            'privilegeLevel': 'privilege_level',
            'ASDM_CLIAccessType': 'asdm_cli_access_type',
        },
        title='Local Users',
        outputs_prefix='LocalUser',
    )


@logger
def list_time_range_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Lists time ranges using the provided client and arguments.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of the time range.
    """
    return list_object_command(
        client_get_command=client.get_time_range,
        client_list_command=client.list_time_range,
        args=args,
        keys_mapping={
            'objectId': 'object_id',
            'name': 'name',
            'value': {
                '_include': False,
                'start': 'start',
                'end': 'end',
                'periodic': {
                    '_include': True,
                    'frequency': 'frequency',
                    'startHour': 'start_hour',
                    'startMinute': 'start_minute',
                    'endHour': 'end_hour',
                    'endMinute': 'end_minute',
                },
            },
        },
        title='Time Ranges',
        outputs_prefix='TimeRange',
        readable_headers=['object_id', 'name', 'start', 'end', 'periodic'],
    )


@logger
def list_security_object_group_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Lists security object groups using the provided client and arguments.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of the security object group.
    """
    return list_object_command(
        client_get_command=client.get_security_object_group,
        client_list_command=client.list_security_object_group,
        args=args,
        keys_mapping=DEFAULT_KEYS_MAPPING,
        title='Security Object Groups',
        outputs_prefix='SecurityObjectGroup',
    )


@logger
def list_user_object_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Lists user objects using the provided client and arguments.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: A CommandResults object containing the results of the user object.
    """
    return list_object_command(
        client_get_command=client.get_user_object,
        client_list_command=client.list_user_object,
        args=args,
        keys_mapping={
            'objectId': 'object_id',
            'userName': 'user_name',
            'user': {
                '_include': False,
                'objectId': 'local_user_object_id',
                'value': 'value',
            },
        },
        title='User Objects',
        outputs_prefix='UserObject',
    )


@logger
def write_memory_command(client: Client, *_) -> CommandResults:
    """
    The write memory command saves the running configuration to the default location for the startup configuration.

    Args:
        client (Client): Session to Cisco ASA to run desired requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: shows a successful 'write memory' command execution on a Cisco ASA device,
            building the configuration and generating a cryptochecksum for integrity.
            The process is completed with an "[OK]" message.
    """
    raw_response = client.write_memory()

    return CommandResults(
        outputs_prefix='CiscoASA.WriteMemory',
        outputs=raw_response,
        raw_response=raw_response
    )


'''MAIN'''


def main():
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    command: str = demisto.command()

    username = params['credentials'].get('identifier')
    password = params['credentials'].get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    isASAv = params.get('isASAv', False)
    # Remove trailing slash to prevent wrong URL path to service
    server_url = params.get('server', '').rstrip('/')

    commands = {
        f'{INTEGRATION_COMMAND}-list-rules': list_rules_command,
        f'{INTEGRATION_COMMAND}-backup': backup_command,
        f'{INTEGRATION_COMMAND}-get-rule-by-id': rule_by_id_command,
        f'{INTEGRATION_COMMAND}-create-rule': create_rule_command,
        f'{INTEGRATION_COMMAND}-delete-rule': delete_rule_command,
        f'{INTEGRATION_COMMAND}-edit-rule': edit_rule_command,
        f'{INTEGRATION_COMMAND}-list-network-objects': list_objects_command,
        f'{INTEGRATION_COMMAND}-create-network-object': create_object_command,
        f'{INTEGRATION_COMMAND}-list-interfaces': list_interfaces_command,
        f'{INTEGRATION_COMMAND}-list-network-object-group': list_network_object_group_command,
        f'{INTEGRATION_COMMAND}-list-local-user-group': list_local_user_group_command,
        f'{INTEGRATION_COMMAND}-list-local-user': list_local_user_command,
        f'{INTEGRATION_COMMAND}-list-time-range': list_time_range_command,
        f'{INTEGRATION_COMMAND}-list-security-object-group': list_security_object_group_command,
        f'{INTEGRATION_COMMAND}-list-user-object': list_user_object_command,
        f'{INTEGRATION_COMMAND}-write-memory': write_memory_command,
    }

    LOG(f'Command being called is {command}')
    client = Client(
        server_url,
        auth=(username, password),
        verify=verify_certificate,
        proxy=proxy,
        headers={},
    )

    try:
        if command == 'test-module':
            return_results(test_command(client, isASAv))
        elif command in commands:
            client.login(isASAv)
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    # Log exceptions
    except Exception as exc:  # pylint: disable=broad-except
        return_error(f'Failed to execute {command} command. Error: {exc}', error=traceback.format_exc())

    finally:
        client.logoff()


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
