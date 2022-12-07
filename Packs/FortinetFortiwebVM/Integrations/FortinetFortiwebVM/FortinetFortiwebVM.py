from http import HTTPStatus
from typing import Any, Dict, Tuple, Optional, Callable
from urllib.parse import urljoin
from abc import abstractmethod
from CommonServerPython import *
import demistomock as demisto
import re

LIMIT_SIZE = 50


class Client(BaseClient):
    """Fortiweb VM Client

    Args:
        BaseClient (BaseClient): Demisto base client parameters.
    """

    def __init__(self, base_url: str, api_key: str, version: str, endpoint_prefix: str, proxy: bool, verify: bool):
        self.base_url = urljoin(base_url, endpoint_prefix)
        self.version = version
        headers = {'Content-Type': 'application/json', 'Authorization': api_key}
        super().__init__(base_url=self.base_url, verify=verify, headers=headers, proxy=proxy)

    def _http_request(self, *args, **kwargs):
        return super()._http_request(*args, error_handler=self.error_handler, **kwargs)

    @property
    @abstractmethod
    def user_to_api_mapper(self) -> Dict[str, Any]:
        pass

    @property
    @abstractmethod
    def api_to_user_mapper(self) -> Dict[Any, Any]:
        pass

    @abstractmethod
    def error_handler(self, res):
        pass

    @abstractmethod
    def protected_hostname_create_request(self, name: str, default_action: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_update_request(self, name: str, default_action: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_delete_request(self, name: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_list_request(self, **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_member_create_request(self, protected_hostname_group: str, host: str, action: str,
                                                 **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_member_update_request(self, protected_hostname_group: str, member_id: str, host: str,
                                                 **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_member_delete_request(self, group_name: str, member_id: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def protected_hostname_member_list_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_group_create_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_group_delete_request(self, group_name: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_group_list_request(self, **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_member_create_request(self, group_name: str, member_type: str, ip_address: str,
                                      **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_member_update_request(self, group_name: str, member_id: str, member_type: Optional[str],
                                      ip_address: Optional[str], **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_member_delete_request(self, group_name: str, member_id: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def ip_list_member_list_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_member_add_request(self, policy_name: str, http_content_routing_policy: str,
                                                is_default: str, inherit_webprotection_profile: str,
                                                **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_member_update_request(self, policy_name: str, member_id: str,
                                                   http_content_routing_policy: str, is_default: Optional[str],
                                                   inherit_webprotection_profile: Optional[str],
                                                   **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_member_delete_request(self, policy_name: str, member_id: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_member_list_request(self, policy_name: str, **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_group_create_request(self, name: str, severity: str, trigger_policy: Optional[str],
                                    exception: Optional[str], **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_group_update_request(self, name: str, severity: Optional[str], trigger_policy: Optional[str],
                                    exception: Optional[str], **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_group_delete_request(self, name: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_group_list_request(self, **kwargs) -> Dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_member_add_request(self, group_name: str, countries_list: List[str]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_member_delete_request(self, group_name: str, member_id: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def geo_ip_member_list_request(self, group_name: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def operation_status_get_request(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def policy_status_get_request(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def system_status_get_request(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def server_pool_list_request(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def http_service_list_request(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def inline_protction_profile_list_request(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def virtual_server_list_request(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def http_content_routing_poicy_list_request(self) -> Dict[str, Any]:
        pass


class ClientV1(Client):
    """Fortiweb VM V1 Client

    Args:
        Client (Client): Client class with abstract functions.
    """
    API_VER = 'V1'
    NOT_EXIST_ERROR_MSGS = ['Entry not found.', 'Invalid length of value.']
    EXIST_ERROR_MSGS = ['A duplicate entry already exists.', 'The IP has already existed in the table.']
    WRONG_PARAMETER_ERROR_MSGS = ['Empty values are not allowed.']

    def __init__(self, base_url: str, api_key: str, version: str, proxy: bool, verify: bool):
        endpoint_prefix = 'api/v1.0/'
        super().__init__(base_url=base_url,
                         api_key=api_key,
                         version=version,
                         endpoint_prefix=endpoint_prefix,
                         verify=verify,
                         proxy=proxy)

    @property
    def user_to_api_mapper(self) -> Dict[str, Any]:
        """Mapping the user input to the API input

        Returns:
            Dict[str, Any]: Mapped dictionary.
        """
        return {
            'protected_hostname': {
                'Allow': 1,
                'Deny': 6,
                'Deny (no log)': 4
            },
            'get_protected_group_id': '_id',
            'get_protected_member_id': '_id',
            'get_protected_index': 'id',
            'get_protected_group_action': 'defaultAction',
            'get_protected_group_members_count': 'protectedHostnameCount',
            'get_ip_list_member_ip': 'iPv4IPv6',
            'ip_list': {
                'type': {
                    'Trust IP': 1,
                    'Black IP': 2
                },
                'severity': {
                    'High': 1,
                    'Medium': 2,
                    'Low': 3,
                    'Informative': 4
                }
            },
            'http_content_routing_member': {
                'inherit_webprotection_profile': {
                    'enable': 'true',
                    'disable': 'false'
                },
                'is_default': {
                    'no': '0',
                    'yes': '1'
                }
            },
            'geo_ip': {
                'severity': {
                    'High': 1,
                    'Medium': 2,
                    'Low': 3,
                    'Info': 4
                }
            }
        }

    @property
    def api_to_user_mapper(self) -> Dict[Any, Any]:
        """Mapping the API output to the user output

        Returns:
            Dict[str, Any]: Mapped dictionary.
        """

        return {
            'protected_hostname': {
                1: 'Allow',
                6: 'Deny',
                4: 'Deny (no log)'
            },
            'ip_list': {
                'severity': {
                    1: 'High',
                    2: 'Medium',
                    3: 'Low',
                    4: 'Informative'
                },
                'type': {
                    1: 'Trust IP',
                    2: 'Black IP'
                }
            },
            'http_content_routing_member': {
                'is_default': {
                    'Yes': 'yes',
                    'No': 'no'
                },
                'inherit_webprotection_profile': {
                    True: 'enable',
                    False: 'disable'
                },
            },
            'geo_ip': {
                'severity': {
                    1: 'High',
                    2: 'Medium',
                    3: 'Low',
                    4: 'Info',
                }
            }
        }

    def error_handler(self, res):
        """Error handler for Fortiweb v1 response.

        Args:
            res (Response): Error response.

        Raises:
            DemistoException: The object does not exist.
            DemistoException: The object already exist.
            DemistoException: There is a problem with one or more arguments.
            DemistoException: One or more of the specified fields are invalid. Please validate them.
        """
        error = res.json()
        error_code = res.status_code
        error_msg = error['msg']
        if error_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            # update & delete
            if error_msg in self.NOT_EXIST_ERROR_MSGS:
                raise DemistoException(f'The object does not exist. {error}', res=res)
            # create
            elif error_msg in self.EXIST_ERROR_MSGS:
                raise DemistoException(f'The object already exist. {error}', res=res)
            elif error_msg in self.WRONG_PARAMETER_ERROR_MSGS:
                raise DemistoException(f'There is a problem with one or more arguments. {error}', res=res)
        raise DemistoException(f'One or more of the specified fields are invalid. Please validate them. {error}',
                               res=res)

    def protected_hostname_create_request(self, name: str, default_action: str) -> Dict[str, Any]:
        """Create a new protected hostname.

        Args:
            name (str): Protected hostname name.
            default_action (int): Http requests action. (allow,deny and no log,deny)

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        data = {
            'name': name,
            'defaultAction': dict_safe_get(self.user_to_api_mapper, ['protected_hostname', default_action])
        }
        response = self._http_request(method='POST',
                                      url_suffix='ServerObjects/ProtectedHostnames/ProtectedHostnames',
                                      json_data=data)
        return response

    def protected_hostname_update_request(self, name: str, default_action: str) -> Dict[str, Any]:
        """Update a protected hostname.

        Args:
            name (str): Protected hostname name.
            action (int): Http requests action. (allow,deny and no log,deny)

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        data = {
            'name': name,
            'defaultAction': dict_safe_get(self.user_to_api_mapper, ['protected_hostname', default_action])
        }
        response = self._http_request(method='PUT',
                                      url_suffix=f'ServerObjects/ProtectedHostnames/ProtectedHostnames/{name}',
                                      json_data=data)
        return response

    def protected_hostname_delete_request(self, name: str) -> Dict[str, Any]:
        """Delete a protected hostname.

        Args:
            name (str): Protected hostname name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        response = self._http_request(method='DELETE',
                                      url_suffix=f'ServerObjects/ProtectedHostnames/ProtectedHostnames/{name}')
        return response

    def protected_hostname_list_request(self, **kwargs) -> Dict[str, Any]:
        """Get protected hostnames.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        response = self._http_request(method='GET', url_suffix='ServerObjects/ProtectedHostnames/ProtectedHostnames')
        return response

    def protected_hostname_member_create_request(self, protected_hostname_group: str, host: str, action: str,
                                                 **kwargs) -> Dict[str, Any]:
        """Create a new protected hostname member.

        Args:
            protected_hostname_group (str): Protected hostname group.
            host (str): IP address or FQDN of a virtual or real web host.
            action (str): Select whether to accept or deny HTTP requests whose Host.
        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        endpoint = f'ServerObjects/ProtectedHostnames/ProtectedHostnames/{protected_hostname_group}/ProtectedHostnamesNewHost'
        action_val = dict_safe_get(self.user_to_api_mapper, ['protected_hostname', action])
        data = {'action': action_val, 'host': host}
        response = self._http_request(method='POST', url_suffix=endpoint, json_data=data)
        return response

    def protected_hostname_member_update_request(self, protected_hostname_group: str, member_id: str, host: str,
                                                 **kwargs) -> Dict[str, Any]:
        """Update a protected hostname member.

        Args:
            protected_hostname_group (str): Protected hostname group id.
            member_id (str): Protected hostname member id
            host (str): IP address or FQDN of a virtual or real web host.
            kwargs (optional): action (str): Action.
        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        endpoint = f'ServerObjects/ProtectedHostnames/ProtectedHostnames/{protected_hostname_group}/ProtectedHostnamesNewHost/{member_id}'
        data = remove_empty_elements({
            'host':
            host,
            'action':
            dict_safe_get(self.user_to_api_mapper, ['protected_hostname', kwargs.get('action')])
        })
        response = self._http_request(method='PUT', url_suffix=endpoint, json_data=data)
        return response

    def protected_hostname_member_delete_request(self, group_name: str, member_id: str) -> Dict[str, Any]:
        """Delete a protected hostname member.

        Args:
            group_name (str): Protected hostname group id.
            member_id (str): Protected hostname member id.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        endpoint = f'ServerObjects/ProtectedHostnames/ProtectedHostnames/{group_name}/ProtectedHostnamesNewHost/{member_id}'
        response = self._http_request(method='DELETE', url_suffix=endpoint)
        return response

    def protected_hostname_member_list_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
        """List protected hostname members.

        Args:
            group_name (str): Protected hostname group id.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        response = self._http_request(
            method='GET',
            url_suffix=f'ServerObjects/ProtectedHostnames/ProtectedHostnames/{group_name}/ProtectedHostnamesNewHost')
        return response

    def ip_list_group_create_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
        """Create a new ip list group.

        Args:
            group_name (str): IP list group name.
            kwargs: page: Page Number.
            kwargs: page_size: Page Size Number.
            kwargs: Limit: Limit Number.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1.
        """
        data = {'name': group_name}
        response = self._http_request(method='POST', url_suffix='WebProtection/Access/IPList', json_data=data)
        return response

    def ip_list_group_delete_request(self, group_name: str) -> Dict[str, Any]:
        """Delete a ip list group.

        Args:
            group_name (str): IP List group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f'WebProtection/Access/IPList/{group_name}'
        response = self._http_request(method='DELETE', url_suffix=endpoint)
        return response

    def ip_list_group_list_request(self, **kwargs) -> Dict[str, Any]:
        """List the IP list groups.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        response = self._http_request(method='GET', url_suffix='WebProtection/Access/IPList')
        return response

    def ip_list_member_create_request(self, group_name: str, member_type: str, ip_address: str,
                                      **kwargs) -> Dict[str, Any]:
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
        type_val = dict_safe_get(self.user_to_api_mapper, ['ip_list', 'type', member_type])
        data = {'type': type_val, 'iPv4IPv6': ip_address}
        if member_type == 'Black IP':
            data.update(
                remove_empty_elements({
                    'severity':
                    dict_safe_get(self.user_to_api_mapper,
                                  ['ip_list', 'severity', kwargs.get('severity')]),
                    'triggerPolicy':
                    kwargs.get('trigger_policy')
                }))
        response = self._http_request(
            method='POST',
            url_suffix=f'WebProtection/Access/IPList/{group_name}/IPListCreateIPListPolicyMember',
            json_data=data)
        return response

    def ip_list_member_update_request(self, group_name: str, member_id: str, member_type: Optional[str],
                                      ip_address: Optional[str], **kwargs) -> Dict[str, Any]:
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
        data = remove_empty_elements({
            'iPv4IPv6': ip_address,
            'type': dict_safe_get(self.user_to_api_mapper, ['ip_list', 'type', member_type])
        })
        if member_type := 'Black IP':
            data.update(
                remove_empty_elements({
                    'severity':
                    dict_safe_get(self.user_to_api_mapper,
                                  ['ip_list', 'severity', kwargs.get('severity')]),
                    'triggerPolicy':
                    kwargs.get('trigger_policy')
                }))
        response = self._http_request(
            method='PUT',
            url_suffix=f'WebProtection/Access/IPList/{group_name}/IPListCreateIPListPolicyMember/{member_id}',
            json_data=data)
        return response

    def ip_list_member_delete_request(self, group_name: str, member_id: str) -> Dict[str, Any]:
        """Delete an IP list member.

        Args:
            group_name (str): IP list group name.
            member_id (str): IP list member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f'WebProtection/Access/IPList/{group_name}/IPListCreateIPListPolicyMember/{member_id}'
        response = self._http_request(method='DELETE', url_suffix=endpoint)
        return response

    def ip_list_member_list_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
        """List IP list members.

        Args:
            group_name (str): IP list group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        response = self._http_request(
            method='GET', url_suffix=f'WebProtection/Access/IPList/{group_name}/IPListCreateIPListPolicyMember')
        return response

    def http_content_routing_member_add_request(self, policy_name: str, http_content_routing_policy: str,
                                                is_default: str, inherit_webprotection_profile: str,
                                                **kwargs) -> Dict[str, Any]:
        """Add a new HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            http_content_routing_policy (str): HTTP content routing policy name.
            is_default (str): Is FortiWeb applies the protection profile to any traffic that does not match conditions
            specified in the HTTP content routing policies?
            inherit_webprotection_profile (str): Enable inherit web protection profile..
            kwargs: profile (str): Web protection profile.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        is_default_val = dict_safe_get(self.user_to_api_mapper,
                                       ['http_content_routing_member', 'is_default', is_default])
        inherit_profile_val = dict_safe_get(
            self.user_to_api_mapper,
            ['http_content_routing_member', 'inherit_webprotection_profile', inherit_webprotection_profile])
        data = remove_empty_elements({
            'http_content_routing_policy': http_content_routing_policy,
            'defaultpage': is_default_val,
            'inheritWebProtectionProfile': inherit_profile_val,
            'profile': kwargs.get('profile')
        })
        response = self._http_request(method='POST',
                                      url_suffix=f'Policy/ServerPolicy/ServerPolicy/{policy_name}/EditContentRouting',
                                      json_data=data)
        return response

    def http_content_routing_member_update_request(self, policy_name: str, member_id: str,
                                                   http_content_routing_policy: str, is_default: Optional[str],
                                                   inherit_webprotection_profile: Optional[str],
                                                   **kwargs) -> Dict[str, Any]:
        """Update an HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            member_id (str): Member ID.
            http_content_routing_policy (str): HTTP content routing policy name.
            is_default (str): Is FortiWeb applies the protection profile to any traffic that does not match conditions
            specified in the HTTP content routing policies?
            inherit_webprotection_profile (str): Enable inherit web protection profile..
            kwargs: profile (str): Web protection profile.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements({
            'http_content_routing_policy':
            http_content_routing_policy,
            'defaultpage':
            dict_safe_get(self.user_to_api_mapper, ['http_content_routing_member', 'is_default', is_default]),
            'inheritWebProtectionProfile':
            dict_safe_get(self.user_to_api_mapper, ['http_content_routing_member', 'inherit_webprotection_profile'],
                          inherit_webprotection_profile),
            'profile':
            kwargs.get('profile')
        })
        response = self._http_request(
            method='PUT',
            url_suffix=f'Policy/ServerPolicy/ServerPolicy/{policy_name}/EditContentRouting/{member_id}',
            json_data=data)
        return response

    def http_content_routing_member_delete_request(self, policy_name: str, member_id: str) -> Dict[str, Any]:
        """Delete an HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            member_id (str): Member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        response = self._http_request(
            method='DELETE',
            url_suffix=f'Policy/ServerPolicy/ServerPolicy/{policy_name}/EditContentRouting/{member_id}')
        return response

    def http_content_routing_member_list_request(self, policy_name: str, **kwargs) -> Dict[str, Any]:
        """List HTTP content routing members.

        Args:
            policy_name (str): Server policy name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        response = self._http_request(method='GET',
                                      url_suffix=f'Policy/ServerPolicy/ServerPolicy/{policy_name}/EditContentRouting')
        return response

    def geo_ip_group_create_request(self, name: str, severity: str, trigger_policy: Optional[str],
                                    exception: Optional[str], **kwargs) -> Dict[str, Any]:
        """Create a new Geo IP group.

        Args:
            name (str): Geo IP group name.
            severity (str): Severity.
            trigger_policy (Optional[str]): Trigger policy.
            exception (Optional[str]): Exception rule.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements({
            'name': name,
            'severity': self.user_to_api_mapper['geo_ip']['severity'][severity],
            'triggerPolicy': trigger_policy,
            'except': exception
        })
        response = self._http_request(method='POST', url_suffix='WebProtection/Access/GeoIP', json_data=data)
        return response

    def geo_ip_group_update_request(self, name: str, severity: Optional[str], trigger_policy: Optional[str],
                                    exception: Optional[str], **kwargs) -> Dict[str, Any]:
        """Update a Geo IP group.

        Args:
            name (str): Geo IP group name.
            severity (Optional[str]): Severity.
            trigger_policy (Optional[str]): Trigger policy.
            exception (Optional[str]): Exception rule.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = remove_empty_elements({
            'severity':
            dict_safe_get(self.user_to_api_mapper, ['geo_ip', 'severity', severity]),
            'triggerPolicy':
            trigger_policy,
            'except':
            exception
        })
        response = self._http_request(method='PUT', url_suffix=f'WebProtection/Access/GeoIP/{name}', json_data=data)
        return response

    def geo_ip_group_delete_request(self, name: str) -> Dict[str, Any]:
        """Delete Geo IP group.

        Args:
            name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """

        endpoint = f'WebProtection/Access/GeoIP/{name}'
        response = self._http_request(method='DELETE', url_suffix=endpoint)
        return response

    def geo_ip_group_list_request(self, **kwargs) -> Dict[str, Any]:
        """List the Geo IP groups.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        response = self._http_request(method='GET', url_suffix='WebProtection/Access/GeoIP')
        return response

    def geo_ip_member_add_request(self, group_name: str, countries_list: List[str]) -> Dict[str, Any]:
        """Add a new Geo IP member.

        Args:
            group_name (str): Geo IP group name.
            countries_list (List[str]): List of countries to add.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        data = {"picker": countries_list}
        response = self._http_request(method='POST',
                                      url_suffix=f'WebProtection/Access/GeoIP/{group_name}/AddCountry',
                                      json_data=data)
        return response

    def geo_ip_member_delete_request(self, group_name: str, member_id: str) -> Dict[str, Any]:
        """Delete a new Geo IP member.

        Args:
            group_name (str): Geo IP group name.
            member_id (str): Geo IP member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f'WebProtection/Access/GeoIP/{group_name}/AddCountry/{member_id}'
        response = self._http_request(method='DELETE', url_suffix=endpoint)
        return response

    def geo_ip_member_list_request(self, group_name: str) -> Dict[str, Any]:
        """List the Geo IP members.

        Args:
            group_name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        endpoint = f'WebProtection/Access/GeoIP/{group_name}/AddCountry'
        response = self._http_request(method='GET', url_suffix=endpoint)
        return response

    def operation_status_get_request(self) -> Dict[str, Any]:
        """Gets operation status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method='GET', url_suffix='System/Status/StatusOperation')

    def policy_status_get_request(self) -> Dict[str, Any]:
        """Gets policy status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method='GET', url_suffix='System/Status/PolicyStatus')

    def system_status_get_request(self) -> Dict[str, Any]:
        """Gets system status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method='GET', url_suffix='System/Status/Status')

    def server_pool_list_request(self) -> Dict[str, Any]:
        """List the Server pools.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method='GET', url_suffix='ServerObjects/Server/ServerPool')

    def http_service_list_request(self) -> Dict[str, Any]:
        """List the HTTP services.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method='GET', url_suffix='ServerObjects/Service/HttpServiceList')

    def inline_protction_profile_list_request(self) -> Dict[str, Any]:
        """List the Inline protection profiles.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method='GET', url_suffix='Policy/WebProtectionProfile/InlineProtectionProfile')

    def virtual_server_list_request(self) -> Dict[str, Any]:
        """List the Virtual servers.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method='GET', url_suffix='ServerObjects/Server/VirtualServer')

    def http_content_routing_poicy_list_request(self) -> Dict[str, Any]:
        """List the HTTP content routing policies.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V1
        """
        return self._http_request(method='GET', url_suffix='ServerObjects/Server/HTTPContentRoutingPolicy')


class ClientV2(Client):
    """Fortiweb VM V2 Client

    Args:
        Client (Client): Client class with abstract functions.
    """
    API_VER = 'V2'
    NOT_EXIST_ERROR_CODES = [-3, 0, -1, -23]
    EXIST_ERROR_CODES = [-5, -6014]
    WRONG_PARAMETER_ERROR_CODES = [-651]

    def __init__(self, base_url: str, api_key: str, version: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url,
                         api_key=api_key,
                         version=version,
                         endpoint_prefix='api/v2.0/',
                         verify=verify,
                         proxy=proxy)

    @property
    def user_to_api_mapper(self) -> Dict[str, Any]:
        """Mapping the user input to the API input

        Returns:
            Dict[str, Any]: Mapped dictionary.
        """
        return {
            'protected_hostname': {
                'Allow': 'allow',
                'Deny': 'deny',
                'Deny (no log)': 'deny_no_log'
            },
            'ip_list': {
                'action': {
                    'Alert deny': 'alert_deny',
                    'Block period': 'block-period',
                    'Deny (no log)': 'deny_no_log',
                },
                'type': {
                    'Trust IP': 'trust-ip',
                    'Black IP': 'black-ip',
                    'Allow Only Ip': 'allow-only-ip',
                }
            },
            'geo_ip': {
                'action': {
                    'Alert deny': 'alert_deny',
                    'Block period': 'block-period',
                    'Deny (no log)': 'deny_no_log'
                }
            },
            'get_protected_group_id': 'name',
            'get_protected_member_id': 'id',
            'get_protected_index': '_id',
            'get_protected_group_action': 'default-action',
            'get_protected_group_members_count': 'sz_host-list',
            'get_ip_list_member_ip': 'ip',
        }

    @property
    def api_to_user_mapper(self) -> Dict[Any, Any]:
        """Mapping the API output to the user output

        Returns:
            Dict[str, Any]: Mapped dictionary.
        """
        return {
            'protected_hostname': {
                'allow': 'Allow',
                'deny': 'Deny',
                'deny_no_log': 'Deny (no log)'
            },
            'ip_list': {
                'type': {
                    'black-ip': 'Black IP',
                    'trust-ip': 'Trust IP',
                    'allow-only-ip': 'Allow Only IP',
                }
            },
            'geo_ip': {
                'action': {
                    'alert_deny': 'Alert deny',
                    'block-period': 'Block period',
                    'deny_no_log': 'Deny (no log)',
                }
            }
        }

    def error_handler(self, res):
        """Error handler for Fortiweb v2 response.

        Args:
            res (Response): Error response.

        Raises:
            DemistoException: The object does not exist.
            DemistoException: The object already exist.
            DemistoException: There is a problem with one or more arguments.
            DemistoException: One or more of the specified fields are invalid. Please validate them.
        """
        error_code = res.status_code
        error_msg = res.json()
        sub_error_code = dict_safe_get(error_msg, ['results', 'errcode'])
        # Only if we add Geo IP member to group that dose'nt exist.
        if not sub_error_code:
            raise DemistoException(f'The object does not exist. {error_msg}', res=res)
        if error_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            # update & delete & get
            if sub_error_code in self.NOT_EXIST_ERROR_CODES:
                raise DemistoException(f'The object does not exist. {error_msg}', res=res)
            # create
            elif sub_error_code in self.EXIST_ERROR_CODES:
                raise DemistoException(f'The object already exist. {error_msg}', res=res)
            elif sub_error_code in self.WRONG_PARAMETER_ERROR_CODES:
                raise DemistoException(f'There is a problem with one or more arguments. {error_msg}', res=res)
        raise DemistoException(f'One or more of the specified fields are invalid. Please validate them. {error_msg}',
                               res=res)

    def protected_hostname_create_request(self, name: str, default_action: str) -> Dict[str, Any]:
        """Create a new protected hostname.

        Args:
            name (str): Protected hostname name.
            default_action (int): Http requests action. (allow,deny and no log,deny)

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """

        action_val = dict_safe_get(self.user_to_api_mapper, ['protected_hostname', default_action])
        data = {'data': {'name': name, 'default-action': action_val}}
        response = self._http_request(method='POST', url_suffix='cmdb/server-policy/allow-hosts', json_data=data)
        return response

    def protected_hostname_update_request(self, name: str, default_action: str) -> Dict[str, Any]:
        """Update a protected hostname.

        Args:
            name (str): Protected hostname name.
            action (int): Http requests action. (allow,deny and no log,deny)

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = {'mkey': name}
        data = {
            'data':
            remove_empty_elements({
                'name':
                name,
                'default-action':
                dict_safe_get(self.user_to_api_mapper, ['protected_hostname', default_action])
            })
        }
        response = self._http_request(method='PUT',
                                      url_suffix='cmdb/server-policy/allow-hosts',
                                      json_data=data,
                                      params=params)

        return response

    def protected_hostname_delete_request(self, name: str) -> Dict[str, Any]:
        """Delete a protected hostname.

        Args:
            name (str): Protected hostname name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = {'mkey': name}
        response = self._http_request(method='DELETE', url_suffix='cmdb/server-policy/allow-hosts', params=params)
        return response

    def protected_hostname_list_request(self, **kwargs) -> Dict[str, Any]:
        """Get protected hostnames.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = remove_empty_elements({'mkey': kwargs.get('name')})
        response = self._http_request(method='GET', url_suffix='cmdb/server-policy/allow-hosts', params=params)
        return response

    def protected_hostname_member_create_request(self, protected_hostname_group: str, host: str, action: str,
                                                 **kwargs) -> Dict[str, Any]:
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
        endpoint = 'cmdb/server-policy/allow-hosts/host-list'
        params = {'mkey': protected_hostname_group}
        action_val = dict_safe_get(self.user_to_api_mapper, ['protected_hostname', action])
        data = {
            "data": {
                "action": action_val,
                "ignore-port": kwargs['ignore_port'],
                "include-subdomains": kwargs['include_subdomains'],
                "host": host
            }
        }
        response = self._http_request(method='POST', url_suffix=endpoint, json_data=data, params=params)
        return response

    def protected_hostname_member_update_request(self, protected_hostname_group: str, member_id: str, host: str,
                                                 **kwargs) -> Dict[str, Any]:
        """Update a protected hostname member.

        Args:
            protected_hostname_group (str): Protected hostname group id.
            member_id (str): Protected hostname member id
            host (str): IP address or FQDN of a virtual or real web host.
            kwargs (optional): action (str): Action.
            kwargs (optional): ignore_port (str): Ignore Port.
            kwargs (optional): include_subdomains (str): Include Subdomains.
        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        endpoint = 'cmdb/server-policy/allow-hosts/host-list'
        params = {'mkey': protected_hostname_group, 'sub_mkey': member_id}
        data = {
            "data":
            remove_empty_elements({
                'host':
                host,
                'action':
                dict_safe_get(self.user_to_api_mapper,
                              ['protected_hostname', kwargs.get('action')]),
                'ignore-port':
                kwargs.get('ignore_port'),
                'include-subdomains':
                kwargs.get('include_subdomains')
            })
        }
        response = self._http_request(method='PUT', url_suffix=endpoint, json_data=data, params=params)
        return response

    def protected_hostname_member_delete_request(self, group_name: str, member_id: str) -> Dict[str, Any]:
        """Delete a protected hostname member.

        Args:
            group_name (str): Protected hostname group id.
            member_id (str): Protected hostname member id.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        endpoint = 'cmdb/server-policy/allow-hosts/host-list'
        params = {'mkey': group_name, 'sub_mkey': member_id}
        response = self._http_request(method='DELETE', url_suffix=endpoint, params=params)
        return response

    def protected_hostname_member_list_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
        """List protected hostname members.

        Args:
            group_name (str): Protected hostname group id.
            kwargs (optional): member_id (str) Protected hostname member id.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = {'mkey': group_name}
        if member_id := kwargs.get('member_id'):
            params.update({'sub_mkey': member_id})
        response = self._http_request(method='GET',
                                      url_suffix='cmdb/server-policy/allow-hosts/host-list',
                                      params=params)
        return response

    def ip_list_group_create_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
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
        action_val = dict_safe_get(self.user_to_api_mapper, ['ip_list', 'action', kwargs['action']])
        data = {
            'data': {
                'name': group_name,
                'action': action_val,
                'block-period': kwargs['block_period'],
                'severity': kwargs['severity'],
                'ignore-x-forwarded-for': kwargs['ignore_x_forwarded_for'],
                'trigger-policy': kwargs.get('trigger_policy')
            }
        }
        response = self._http_request(method='POST', url_suffix='cmdb/waf/ip-list', json_data=data)
        return response

    def ip_list_group_update_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
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
        params = {'mkey': group_name}
        data = {
            'data':
            remove_empty_elements({
                'name':
                group_name,
                'action':
                dict_safe_get(self.user_to_api_mapper, ['ip_list', 'action', kwargs.get('action')]),
                'block-period':
                kwargs.get('block_period'),
                'severity':
                kwargs.get('severity'),
                'ignore-x-forwarded-for':
                kwargs.get('ignore_x_forwarded_for'),
                'trigger-policy':
                kwargs.get('trigger_policy')
            })
        }
        response = self._http_request(method='PUT', url_suffix='cmdb/waf/ip-list', json_data=data, params=params)
        return response

    def ip_list_group_delete_request(self, group_name: str) -> Dict[str, Any]:
        """Delete an IP list group.

        Args:
            group_name (str): IP list group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        params = {'mkey': group_name}
        response = self._http_request(method='DELETE', url_suffix='cmdb/waf/ip-list', params=params)
        return response

    def ip_list_group_list_request(self, **kwargs) -> Dict[str, Any]:
        """List the IP list groups.

        Args:
            kwargs: group_name (str): IP list group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        group_name = kwargs.get('group_name')
        params = {'mkey': group_name} if group_name else {}
        response = self._http_request(method='GET', url_suffix='cmdb/waf/ip-list', params=params)
        return response

    def ip_list_member_create_request(self, group_name: str, member_type: str, ip_address: str,
                                      **kwargs) -> Dict[str, Any]:
        """Create an IP list member.

        Args:
            group_name (str): IP list group name.
            member_type (str): IP list member type.
            ip_address (str): IP address.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {'mkey': group_name}
        type_val = dict_safe_get(self.user_to_api_mapper, ['ip_list', 'type', member_type])
        data = {'data': {'type': type_val, 'ip': ip_address}}
        response = self._http_request(method='POST',
                                      url_suffix='cmdb/waf/ip-list/members',
                                      json_data=data,
                                      params=params)
        return response

    def ip_list_member_update_request(self, group_name: str, member_id: str, member_type: Optional[str],
                                      ip_address: Optional[str], **kwargs) -> Dict[str, Any]:
        """Update an IP list member.

        Args:
            group_name (str): IP list group name.
            member_id (str): IP list member ID.
            member_type (str): IP list member type.
            ip_address (str): IP address.

        Returns:
            Dict[str, Any]: API response from FortiwebVM 2
        """
        params = {'mkey': group_name, 'sub_mkey': member_id}
        data: Dict[str, Any] = {
            'data':
            remove_empty_elements({
                'type': dict_safe_get(self.user_to_api_mapper, ['ip_list', 'type', member_type]),
                'ip': ip_address
            })
        }
        response = self._http_request(method='PUT',
                                      url_suffix='cmdb/waf/ip-list/members',
                                      json_data=data,
                                      params=params)
        return response

    def ip_list_member_delete_request(self, group_name: str, member_id: str) -> Dict[str, Any]:
        """Delete an IP list member.

        Args:
            group_name (str): IP list group name.
            member_id (str): IP list member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        endpoint = 'cmdb/waf/ip-list/members'
        params = {'mkey': group_name, 'sub_mkey': member_id}
        response = self._http_request(method='DELETE', url_suffix=endpoint, params=params)
        return response

    def ip_list_member_list_request(self, group_name: str, **kwargs) -> Dict[str, Any]:
        """List IP list members.

        Args:
            group_name (str): IP list group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {'mkey': group_name}
        if member_id := kwargs.get('member_id'):
            params.update({'sub_mkey': member_id})
        response = self._http_request(method='GET', url_suffix='cmdb/waf/ip-list/members', params=params)
        return response

    def http_content_routing_member_add_request(self, policy_name: str, http_content_routing_policy: str,
                                                is_default: str, inherit_webprotection_profile: str, **kwargs):
        """Add a new HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            http_content_routing_policy (str): HTTP content routing policy name.
            is_default (str): Is FortiWeb applies the protection profile to any traffic that does not match conditions
            specified in the HTTP content routing policies?
            inherit_webprotection_profile (str): Enable inherit web protection profile..
            kwargs: status (str): Status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {'mkey': policy_name}
        data = {
            'data':
            remove_empty_elements({
                'content-routing-policy-name': http_content_routing_policy,
                'is-default': is_default,
                'profile-inherit': inherit_webprotection_profile,
                'status': kwargs.get('status')
            })
        }
        response = self._http_request(method='POST',
                                      url_suffix='cmdb/server-policy/policy/http-content-routing-list',
                                      json_data=data,
                                      params=params)
        return response

    def http_content_routing_member_update_request(self, policy_name: str, member_id: str,
                                                   http_content_routing_policy: str, is_default: Optional[str],
                                                   inherit_webprotection_profile: Optional[str], **kwargs):
        """Update an HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            member_id (str): Member ID.
            http_content_routing_policy (str): HTTP content routing policy name.
            is_default (str): Is FortiWeb applies the protection profile to any traffic that does not match conditions
            specified in the HTTP content routing policies?
            inherit_webprotection_profile (str): Enable inherit web protection profile..
            kwargs: profile (str): Web protection profile.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {'mkey': policy_name, 'sub_mkey': member_id}
        data = {
            'data':
            remove_empty_elements({
                'is-default': is_default,
                'profile-inherit': inherit_webprotection_profile,
                'status': kwargs.get('status')
            })
        }
        response = self._http_request(method='PUT',
                                      url_suffix='cmdb/server-policy/policy/http-content-routing-list',
                                      json_data=data,
                                      params=params)
        return response

    def http_content_routing_member_delete_request(self, policy_name: str, member_id: str) -> Dict[str, Any]:
        """Delete an HTTP content routing member.

        Args:
            policy_name (str): Server policy name.
            member_id (str): Member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {'mkey': policy_name, 'sub_mkey': member_id}
        response = self._http_request(method='DELETE',
                                      url_suffix='cmdb/server-policy/policy/http-content-routing-list',
                                      params=params)
        return response

    def http_content_routing_member_list_request(self, policy_name: str, **kwargs) -> Dict[str, Any]:
        """List HTTP content routing members.

        Args:
            policy_name (str): Server policy name.
            kwargs: member_id (str): Member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {'mkey': policy_name}
        if member_id := kwargs.get('member_id'):
            params.update({'sub_mkey': member_id})
        response = self._http_request(method='GET',
                                      url_suffix='cmdb/server-policy/policy/http-content-routing-list',
                                      params=params)
        return response

    def geo_ip_group_create_request(self, name: str, severity: str, trigger_policy: Optional[str],
                                    exception: Optional[str], **kwargs) -> Dict[str, Any]:
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
            'data': {
                'name': name,
                'action': self.user_to_api_mapper['geo_ip']['action'][kwargs['action']],
                'block-period': kwargs['block_period'],
                'severity': severity,
                'trigger': trigger_policy,
                'exception-rule': exception,
                'ignore-x-forwarded-for': kwargs['ignore_x_forwarded_for']
            }
        }
        response = self._http_request(method='POST', url_suffix='cmdb/waf/geo-block-list', json_data=data)
        return response

    def geo_ip_group_update_request(self, name: str, severity: Optional[str], trigger_policy: Optional[str],
                                    exception: Optional[str], **kwargs) -> Dict[str, Any]:
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

        params = {'mkey': name}
        data = remove_empty_elements({
            'data': {
                'action': dict_safe_get(self.user_to_api_mapper,
                                        ['geo_ip', 'action', kwargs.get('action')]),
                'block-period': kwargs.get('block_period'),
                'ignore-x-forwarded-for': kwargs.get('ignore_x_forwarded_for'),
                'severity': severity,
                'trigger-policy': trigger_policy,
                'exception-rule': exception
            }
        })
        return self._http_request(method='PUT', url_suffix='cmdb/waf/geo-block-list', json_data=data, params=params)

    def geo_ip_group_delete_request(self, name: str) -> Dict[str, Any]:
        """Delete a Geo IP group.

        Args:
            name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """

        params = {'mkey': name}
        response = self._http_request(method='DELETE', url_suffix='cmdb/waf/geo-block-list', params=params)
        return response

    def geo_ip_group_list_request(self, **kwargs) -> Dict[str, Any]:
        """List the Geo IP groups.

        Args:
            kwargs: name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """

        name = kwargs.get('name')
        params = {'mkey': name} if name else {}
        response = self._http_request(method='GET', url_suffix='cmdb/waf/geo-block-list', params=params)
        return response

    def geo_ip_member_add_request(self, group_name: str, countries_list: List[str]) -> Dict[str, Any]:
        """Add a new Geo IP member.

        Args:
            group_name (str): Geo IP group name.
            countries_list (List[str]): List of countries.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {'mkey': group_name}
        data = {'data': {'add': countries_list}}
        response = self._http_request(method='POST', url_suffix='waf/geoip.setCountrys', json_data=data, params=params)
        return response

    def geo_ip_member_delete_request(self, group_name: str, member_id: str) -> Dict[str, Any]:
        """Delete a Geo IP member.

        Args:
            group_name (str): Geo IP group name.
            member_id (str): Geo IP member ID.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """

        endpoint = 'cmdb/waf/geo-block-list/country-list'
        params = {'mkey': group_name, 'sub_mkey': member_id}
        response = self._http_request(method='DELETE', url_suffix=endpoint, params=params)
        return response

    def geo_ip_member_list_request(self, group_name: str) -> Dict[str, Any]:
        """List the Geo IP members.

        Args:
            group_name (str): Geo IP group name.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2
        """
        params = {'mkey': group_name}
        response = self._http_request(method='GET', url_suffix='cmdb/waf/geo-block-list/country-list', params=params)
        return response

    def operation_status_get_request(self) -> Dict[str, Any]:
        """Gets operation status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method='GET', url_suffix='system/status.systemoperation')

    def policy_status_get_request(self) -> Dict[str, Any]:
        """Gets policy status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method='GET', url_suffix='policy/policystatus')

    def system_status_get_request(self) -> Dict[str, Any]:
        """Gets system status.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method='GET', url_suffix='system/status.systemstatus')

    def server_pool_list_request(self) -> Dict[str, Any]:
        """List the server pools.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method='GET', url_suffix='cmdb/server-policy/server-pool')

    def http_service_list_request(self) -> Dict[str, Any]:
        """List the HTTP services.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method='GET', url_suffix='cmdb/server-policy/service.predefined')

    def inline_protction_profile_list_request(self) -> Dict[str, Any]:
        """List the Inline protection profiles.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method='GET', url_suffix='cmdb/waf/web-protection-profile.inline-protection')

    def virtual_server_list_request(self) -> Dict[str, Any]:
        """List the virtual servers.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method='GET', url_suffix='cmdb/server-policy/vserver')

    def http_content_routing_poicy_list_request(self) -> Dict[str, Any]:
        """List the HTTP content routing policies.

        Returns:
            Dict[str, Any]: API response from FortiwebVM V2.
        """
        return self._http_request(method='GET', url_suffix='cmdb/server-policy/http-content-routing-policy')


def protected_hostname_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create a new protected hostname.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args['name']
    default_action = args.get('default_action', 'Allow')
    response = client.protected_hostname_create_request(name=name, default_action=default_action)
    command_results = generate_simple_command_results('name', name, response, 'Hostname group successfully created!')
    return command_results


def protected_hostname_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Update a protected hostname.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args['name']
    default_action = args.get('default_action', 'Allow')
    response = client.protected_hostname_update_request(name, default_action)
    command_results = generate_simple_command_results('name', name, response, 'Hostname group successfully updated!')
    return command_results


def protected_hostname_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Delete a protected hostname.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args['name']
    response = client.protected_hostname_delete_request(name)
    command_results = generate_simple_command_results('name', name, response, 'Hostname group successfully deleted!')
    return command_results


def protected_hostname_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get protected hostname list / object.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    protected_hostname = args.get('name')
    response = client.protected_hostname_list_request(name=protected_hostname)
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, protected_hostname_group_parser, protected_hostname)
    headers = create_headers(client.version, ['id', 'default_action', 'protected_hostname_count'], ['can_delete'], [])
    readable_output = tableToMarkdown(name='Protected Hostnames Groups:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.ProtectedHostnameGroup',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def protected_hostname_member_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create a new protected hostname member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    protected_hostname_group = args['group_name']
    host = args['host']
    action = args.get('action', 'allow')
    ignore_port = args.get('ignore_port', 'disable')
    include_subdomains = args.get('include_subdomains', 'disable')
    response = client.protected_hostname_member_create_request(protected_hostname_group=protected_hostname_group,
                                                               host=host,
                                                               action=action,
                                                               ignore_port=ignore_port,
                                                               include_subdomains=include_subdomains)
    member_id = get_sub_object_id(client, protected_hostname_group, response, 'host', host,
                                  client.protected_hostname_member_list_request)

    outputs = {'id': member_id}
    readable_output = tableToMarkdown('Hostname member successfully created!',
                                      outputs,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.ProtectedHostnameMember',
                                     outputs_key_field='id',
                                     outputs=outputs,
                                     raw_response=response)
    return command_results


def protected_hostname_member_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Update a protected hostname member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    protected_hostname = args['group_name']
    member_id = args['member_id']
    host = args['host']
    action = args.get('action')
    ignore_port = args.get('ignore_port')
    include_subdomains = args.get('include_subdomains')
    response = client.protected_hostname_member_update_request(protected_hostname_group=protected_hostname,
                                                               member_id=member_id,
                                                               action=action,
                                                               host=host,
                                                               ignore_port=ignore_port,
                                                               include_subdomains=include_subdomains)
    command_results = generate_simple_command_results('id', member_id, response,
                                                      'Protected hostname member succesfuly updated!')

    return command_results


def protected_hostname_member_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Delete a protected hostname member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    protected_hostname = args['group_name']
    protected_hostname_member_id = args['member_id']
    response = client.protected_hostname_member_delete_request(protected_hostname, protected_hostname_member_id)
    command_results = generate_simple_command_results('id', protected_hostname_member_id, response,
                                                      'Protected hostname member successfully deleted!')
    return command_results


def protected_hostname_member_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List protected hostname members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    group_name = args['group_name']
    member_id = args.get('member_id')
    response = client.protected_hostname_member_list_request(group_name=group_name, member_id=member_id)
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, protected_hostname_member_parser, member_id)
    headers = create_headers(client.version, ['id', 'action', 'host'], [], ['ignore_port', 'include_subdomains'])
    readable_output = tableToMarkdown(name='Protected Hostnames Members:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.ProtectedHostnameMember',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def ip_list_group_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create an IP list group.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    group_name = args['name']
    action = args.get('action', 'alert deny')
    block_period = arg_to_number(args.get('block_period', 600))
    if block_period and not 1 <= block_period <= 600:
        return_error('Block period should be a number in range of 1-600.')
    severity = args.get('severity', 'Low')
    ignore_x_forwarded_for = args.get('ignore_x_forwarded_for', 'disable')
    trigger_policy = args.get('trigger_policy')
    response = client.ip_list_group_create_request(group_name=group_name,
                                                   action=action,
                                                   block_period=block_period,
                                                   severity=severity,
                                                   ignore_x_forwarded_for=ignore_x_forwarded_for,
                                                   trigger_policy=trigger_policy)

    command_results = generate_simple_command_results('name', group_name, response, 'IP list group succesfuly created!')

    return command_results


def ip_list_group_update_command(client: Client, args: Dict[str, Any]) -> Optional[CommandResults]:
    """Update an IP list group.

    Args:
        client (Client): FortiwebVM V2 API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    if isinstance(client, ClientV1):
        return_error('Update command not supported in version 1.')
    group_name = args['name']
    action = args.get('action')
    block_period = arg_to_number(args.get('block_period'))
    block_period_validation(client.version, block_period)
    severity = args.get('severity')
    ignore_x_forwarded_for = args.get('ignore_x_forwarded_for')
    trigger_policy = args.get('trigger_policy')

    response = client.ip_list_group_update_request(group_name,
                                                   action=action,
                                                   block_period=block_period,
                                                   severity=severity,
                                                   ignore_x_forwarded_for=ignore_x_forwarded_for,
                                                   trigger_policy=trigger_policy)
    command_results = generate_simple_command_results('name', group_name, response, 'IP list group succesfuly updated!')

    return command_results


def ip_list_group_delete_command(client: Client, args: Dict[str, Any]) -> Optional[CommandResults]:
    group_name = args['name']
    response = client.ip_list_group_delete_request(group_name)
    command_results = generate_simple_command_results('id', group_name, response, 'IP list group successfully deleted!')

    return command_results


def ip_list_group_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List IP list groups.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    group_name = args.get('name')
    response = client.ip_list_group_list_request(group_name=group_name)
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, ip_list_group_parser, group_name)
    headers = create_headers(client.version, ['id', 'ip_list_count'], [],
                             ['action', 'block_period', 'severity', 'trigger_policy'])
    readable_output = tableToMarkdown(name='Protected Hostnames Groups:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.IpListGroup',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def ip_list_member_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create a new IP list member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    group_name = args['group_name']
    member_type = args['type']
    ip_address = args['ip_address']
    severity = args.get('severity', 'Medium')
    trigger_policy = args.get('trigger_policy')
    if client.version == ClientV1.API_VER and member_type == 'Allow Only Ip':
        return_error('Allow only ip not supported by version 1.')
    if not re.match(ipv4Regex, ip_address):
        raise DemistoException(f'{ipv4Regex} is not a valid IPv4 address.')
    response = client.ip_list_member_create_request(group_name=group_name,
                                                    member_type=member_type,
                                                    ip_address=ip_address,
                                                    severity=severity,
                                                    trigger_policy=trigger_policy)
    member_id = get_sub_object_id(client, group_name, response, 'iPv4IPv6', ip_address,
                                  client.ip_list_member_list_request)

    outputs = {'id': member_id}
    readable_output = tableToMarkdown('IP list member successfully created!',
                                      outputs,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.IpListMember',
                                     outputs_key_field='id',
                                     outputs=outputs,
                                     raw_response=response)

    return command_results


def ip_list_member_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Update an IP list member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    group_name = args['group_name']
    member_id = args['member_id']
    member_type = args.get('type')
    ip_address = args.get('ip_address')
    severity = args.get('severity')
    severity = 'Medium' if member_type == 'Black IP' and not severity else severity
    trigger_policy = args.get('trigger_policy')
    if client.version == ClientV1.API_VER and member_type == 'Allow Only Ip':
        return_error('Allow only ip not supported by version 1.')
    if ip_address and not re.match(ipv4Regex, ip_address):
        return_error('Please insert correct IP address.')
    response = client.ip_list_member_update_request(group_name=group_name,
                                                    member_id=member_id,
                                                    member_type=member_type,
                                                    ip_address=ip_address,
                                                    severity=severity,
                                                    trigger_policy=trigger_policy)
    command_results = generate_simple_command_results('id', member_id, response, 'IP list member succesfuly updated!')
    return command_results


def ip_list_member_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Delete an IP list member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    group_name = args['group_name']
    member_id = args['member_id']
    response = client.ip_list_member_delete_request(group_name, member_id)
    command_results = generate_simple_command_results('id', member_id, response, 'IP list member successfully deleted!')
    return command_results


def ip_list_member_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List IP list members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    group_name = args['group_name']
    member_id = args.get('member_id')
    response = client.ip_list_member_list_request(group_name=group_name, member_id=member_id)
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, ip_list_member_parser, member_id)
    headers = create_headers(client.version, ['id', 'type', 'ip'], ['severity', 'trigger_policy'], [])
    readable_output = tableToMarkdown(name='Protected Hostnames Members:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.IpListPolicyMember',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def http_content_routing_member_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Add an HTTP content routing members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    policy_name = args['policy_name']
    http_content_routing_policy = args['http_content_routing_policy']
    is_default = args.get('is_default', 'no')
    inherit_webprotection_profile = args.get('inherit_web_protection_profile', 'disable')
    status = args.get('status', 'enable')
    profile = args.get('profile')
    response = client.http_content_routing_member_add_request(
        policy_name=policy_name,
        http_content_routing_policy=http_content_routing_policy,
        is_default=is_default,
        inherit_webprotection_profile=inherit_webprotection_profile,
        profile=profile,
        status=status)
    member_id = get_sub_object_id(client, policy_name, response, 'http_content_routing_policy',
                                  http_content_routing_policy, client.http_content_routing_member_list_request)
    command_results = generate_simple_command_results('id', member_id, response,
                                                      'HTTP content routing member succesfuly created!')
    return command_results


def http_content_routing_member_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Update an HTTP content routing members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    policy_name = args['policy_name']
    http_content_routing_policy = args['http_content_routing_policy']
    id = args['id']
    is_default = args.get('is_default')
    inherit_webprotection_profile = args.get('inherit_web_protection_profile')
    status = args.get('status')
    profile = args.get('profile')
    response = client.http_content_routing_member_update_request(
        policy_name=policy_name,
        member_id=id,
        http_content_routing_policy=http_content_routing_policy,
        is_default=is_default,
        inherit_webprotection_profile=inherit_webprotection_profile,
        profile=profile,
        status=status)
    command_results = generate_simple_command_results('id', id, response,
                                                      'HTTP content routing member succesfuly updated!')
    return command_results


def http_content_routing_member_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Delete an HTTP content routing members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    policy_name = args['policy_name']
    id = args['id']
    response = client.http_content_routing_member_delete_request(policy_name, id)
    command_results = generate_simple_command_results('id', id, response,
                                                      "HTTP content routing member succesfuly deleted!")
    return command_results


def http_content_routing_member_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List HTTP content routing members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    policy_name = args['policy_name']
    member_id = args.get('id')
    response = client.http_content_routing_member_list_request(policy_name, member_id=member_id)
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, http_content_routing_member_parser, member_id)
    headers = create_headers(
        client.version, ['id', 'default', 'http_content_routing_policy', 'inherit_web_protection_profile', 'profile'],
        [], ['status'])
    readable_output = tableToMarkdown(name='HTTP Content Routing Policy Members:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.HttpContentRoutingMember',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def geo_ip_group_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create a Geo IP group.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    name = args['name']
    trigger_policy = args.get('trigger_policy')
    severity = args.get('severity', 'Low')
    exception_rule = args.get('exception_rule')
    action = args.get('action', 'Block Period')
    block_period = arg_to_number(args.get('block_period', 600))
    block_period_validation(client.version, block_period)
    ignore_x_forwarded_for = args.get('ignore_x_forwarded_for', 'disable')
    response = client.geo_ip_group_create_request(name=name,
                                                  trigger_policy=trigger_policy,
                                                  severity=severity,
                                                  exception=exception_rule,
                                                  action=action,
                                                  block_period=block_period,
                                                  ignore_x_forwarded_for=ignore_x_forwarded_for)
    command_results = generate_simple_command_results('name', name, response, 'Geo IP group succesfuly created!')

    return command_results


def geo_ip_group_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Update a Geo IP group.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    name = args['name']
    trigger_policy = args.get('trigger_policy')
    severity = args.get('severity')
    exception_rule = args.get('exception_rule')
    action = args.get('action')
    block_period = arg_to_number(args.get('block_period'))
    block_period_validation(client.version, block_period)
    ignore_x_forwarded_for = args.get('ignore_x_forwarded_for')
    response = client.geo_ip_group_update_request(name=name,
                                                  trigger_policy=trigger_policy,
                                                  severity=severity,
                                                  exception=exception_rule,
                                                  action=action,
                                                  block_period=block_period,
                                                  ignore_x_forwarded_for=ignore_x_forwarded_for)
    command_results = generate_simple_command_results('name', name, response, 'Geo IP group succesfuly updated!')

    return command_results


def geo_ip_group_delete_command(client: Client, args: Dict[str, Any]) -> Optional[CommandResults]:
    """Delete a Geo IP group.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    name = args['name']
    response = client.geo_ip_group_delete_request(name)
    command_results = generate_simple_command_results('id', name, response, 'Geo IP group successfully deleted!')

    return command_results


def geo_ip_group_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List the Geo IP groups.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args.get('name')
    response = client.geo_ip_group_list_request(name=name)
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, geo_ip_group_parser, name)
    headers = create_headers(client.version, ['id', 'count', 'trigger_policy', 'severity', 'except'], [],
                             ['action', 'block_period', 'ignore_x_forwarded_for'])
    readable_output = tableToMarkdown(name='Protected Hostnames Groups:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.GeoIpGroup',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def geo_ip_member_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Add a Geo IP member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    group_name = args['group_name']
    countries = argToList(args['countries'])
    all_countries = countries
    if client.version == ClientV1.API_VER:
        # Get last countries
        old_countries_list: List[str] = client.geo_ip_member_list_request(group_name=group_name)[0]['SSet']
        all_countries = set(countries)
        all_countries = list(all_countries.union(old_countries_list))
    response = client.geo_ip_member_add_request(group_name=group_name, countries_list=all_countries)
    # Get the new IDs
    get_response = client.geo_ip_member_list_request(group_name=group_name)
    results = get_response['results'] if client.version == ClientV2.API_VER else get_response
    parsed_data = list_response_parser(client, results, geo_ip_member_parser)
    countries_data = find_dict_in_array(parsed_data, 'country', countries)

    readable_output = tableToMarkdown(name='Geo IP members:',
                                      t=countries_data,
                                      headers=['id', 'country'],
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.GeoIpMember',
                                     outputs_key_field='id',
                                     outputs=countries_data,
                                     raw_response=response)
    return command_results


def geo_ip_member_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Delete a Geo IP member.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    group_name = args['group_name']
    member_id = args['member_id']
    response = client.geo_ip_member_delete_request(group_name=group_name, member_id=member_id)
    command_results = generate_simple_command_results('member_id', member_id, response,
                                                      'Geo IP member succesfuly deleted!')

    return command_results


def geo_ip_member_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List the Geo IP members.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    group_name = args['group_name']
    response = client.geo_ip_member_list_request(group_name=group_name)
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, geo_ip_member_parser)
    headers = ['id', 'country']
    readable_output = tableToMarkdown(name='Protected Hostnames Groups:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.GeoIpMember',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def operation_status_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get operation status.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    response = client.operation_status_get_request()
    results = response['results']['network'] if client.version == ClientV2.API_VER else response['network']
    parsed_data = list_response_parser(client, results, operation_status_parser)
    headers = ['id', 'name', 'label', 'alias', 'ip_netmask', 'speed_duplex', 'tx', 'rx', 'link']
    readable_output = tableToMarkdown(name='Operation networks:',
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.SystemOperation',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def policy_status_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get policy status.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    response = client.policy_status_get_request()
    results = response['results'] if client.version == ClientV2.API_VER else response
    parsed_data = list_response_parser(client, results, policy_status_parser)
    headers = create_headers(
        client.version,
        ['id', 'name', 'status', 'vserver', 'http_port', 'https_port', 'mode', 'session_count', 'connction_per_second'],
        [], ['policy', 'client_rtt', 'server_rtt', 'app_response_time'])
    readable_output = tableToMarkdown(name='Policy status:',
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.SystemPolicy',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def system_status_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get system status.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    response = client.system_status_get_request()
    results = response['results'] if client.version == ClientV2.API_VER else response
    parsed_data = system_status_parser(client, results)
    headers = create_headers(client.version, [
        'high_ability_status', 'host_name', 'serial_number', 'operation_mode', 'system_time', 'firmware_version',
        'administrative_domain'
    ], ['system_uptime', 'fips_and_cc_mode', 'log_disk'],
                             ['manager_status', 'sysyem_up_days', 'sysyem_up_hrs', 'sysyem_up_mins'])
    readable_output = tableToMarkdown(name='System Status:',
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.SystemStatus',
                                     outputs_key_field='id',
                                     outputs=results,
                                     raw_response=response)
    return command_results


def server_pool_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List the Server pools.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.server_pool_list_request()
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, simple_id_parser)
    headers = ['id']
    readable_output = tableToMarkdown(name='Server pool:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.ServerPool',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def http_service_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List the HTTP services.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.http_service_list_request()
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, http_service_parser)
    headers = ['id']
    readable_output = tableToMarkdown(name='HTTP services:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.HttpServiceList',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def inline_protection_profile_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List the Inline protection profiles.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.inline_protction_profile_list_request()
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, simple_id_parser)
    headers = ['id']
    readable_output = tableToMarkdown(name='Inline Protection Profile:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.InlineProtectionProfile',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def virtual_server_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List the Virtual servers.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.virtual_server_list_request()
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, simple_id_parser)
    headers = ['id']
    readable_output = tableToMarkdown(name='Virtual Servers:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=headers,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.VirtualServer',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def http_content_routing_policy_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List the HTTP content routing policies.

    Args:
        client (Client): FortiwebVM API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.http_content_routing_poicy_list_request()
    formatted_response, pagination_message = paginate_results(client.version, response, args)
    parsed_data = list_response_parser(client, formatted_response, simple_id_parser)
    readable_output = tableToMarkdown(name='Content Routing Policy:',
                                      metadata=pagination_message,
                                      t=parsed_data,
                                      headers=['id'],
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='FortiwebVM.HttpContentRoutingPolicy',
                                     outputs_key_field='id',
                                     outputs=parsed_data,
                                     raw_response=response)
    return command_results


def create_headers(version: str, common_headers: List[str], v1_only_headers: List[str],
                   v2_only_headers: List[str]) -> List[str]:
    """Create headers for xsoar output.

    Args:
        version (str): Client version.
        common_headers (List[str]): Common headers field for both versions.
        v1_only_headers (List[str]): Headers for V1 only.
        v2_only_headers (List[str]): Header for V2 only.

    Returns:
        List[str]: List of headers.
    """
    headers = common_headers
    if version == ClientV1.API_VER:
        headers = headers + v1_only_headers
    if version == ClientV2.API_VER:
        headers = headers + v2_only_headers
    return headers


def list_response_parser(client: Client,
                         response: List[Dict[str, Any]],
                         data_parser: Callable,
                         sub_object_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Parse the list output response to xsoar output.

    Args:
        client (Client): Fortiweb VM client.
        response (List[Dict[str, Any]]): Response from list request.
        data_parser (_type_): Parser command.
        object_id (Optional[str]): Sub Object ID.

    Returns:
        List[Dict[str, Any]]: Filtered output to xsoar.
    """

    if sub_object_id and client.version == ClientV1.API_VER:
        group_dict = find_dict_in_array(response, '_id', sub_object_id)
        response = [group_dict] if group_dict else []
        if not response:
            return_error('The object does not exist.')

    parsed_data = []
    for protected_hostname_group in response:
        group = data_parser(client, protected_hostname_group)
        parsed_data.append(group)

    return parsed_data


def protected_hostname_group_parser(client: Client, protected_hostname_group: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for protected hostname group.

    Args:
        client (Client): Fortiweb VM client.
        protected_hostname_group (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """
    action_dict = dict_safe_get(client.api_to_user_mapper, ['protected_hostname'])
    if client.version == ClientV1.API_VER:
        action_val = action_dict[protected_hostname_group['defaultAction']]
        group = {
            'id': protected_hostname_group['_id'],
            'can_delete': protected_hostname_group['can_delete'],
            'default_action': action_val,
            'protected_hostname_count': protected_hostname_group['protectedHostnameCount']
        }
    else:
        action_val = action_dict[protected_hostname_group['default-action']]
        group = {
            'id': protected_hostname_group['name'],
            'default_action': action_val,
            'protected_hostname_count': protected_hostname_group['sz_host-list']
        }

    return group


def protected_hostname_member_parser(client: Client, protected_hostname_member: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for protected hostname member.

    Args:
        client (Client): Fortiweb VM client.
        protected_hostname_member (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """

    action_api_val = protected_hostname_member['action']
    if client.version == ClientV1.API_VER:
        action_val = dict_safe_get(client.api_to_user_mapper, ['protected_hostname', action_api_val])
        group = {
            'id': protected_hostname_member['_id'],
            'action': action_val,
            'host': protected_hostname_member['host'],
        }
    else:
        action_val = dict_safe_get(client.api_to_user_mapper, ['protected_hostname', action_api_val])
        group = {
            'id': protected_hostname_member['id'],
            'action': action_val,
            'host': protected_hostname_member['host'],
            'ignore_port': protected_hostname_member['ignore-port'],
            'include_subdomains': protected_hostname_member['include-subdomains']
        }
    return group


def ip_list_group_parser(client: Client, ip_list_group: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for protected hostname group.

    Args:
        client (Client): Fortiweb VM client.
        ip_list_group (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """
    group = {}
    if client.version == ClientV1.API_VER:
        group = {
            'id': ip_list_group['_id'],
            'ip_list_count': ip_list_group['ipListCount'],
            'can_delete': ip_list_group['can_delete']
        }
    else:
        group = {
            'id': ip_list_group['name'],
            'ip_list_count': ip_list_group['sz_members'],
            'can_view': ip_list_group['can_view'],
            'q_ref': ip_list_group['q_ref'],
            'can_clone': ip_list_group['can_clone'],
            'q_type': ip_list_group['q_type'],
            'action': ip_list_group['action'],
            'block_period': ip_list_group['block-period'],
            'severity': ip_list_group['severity'],
            'trigger_policy': ip_list_group['trigger-policy']
        }
    return group


def ip_list_member_parser(client: Client, ip_list_member: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for IP list member.

    Args:
        client (Client): Fortiweb VM client.
        ip_list_member (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """
    type_val = dict_safe_get(client.api_to_user_mapper, ['ip_list', 'type', ip_list_member['type']])
    if client.version == ClientV1.API_VER:
        severity_val = dict_safe_get(client.api_to_user_mapper, ['ip_list', 'severity', ip_list_member['severity']])
        parsed_data = {
            'id': ip_list_member['_id'],
            'type': type_val,
            'severity': severity_val,
            'trigger_policy': ip_list_member['triggerPolicy'],
            'ip': ip_list_member['iPv4IPv6'],
        }
    else:
        parsed_data = {
            'id': ip_list_member['id'],
            'type': type_val,
            'ip': ip_list_member['ip'],
        }
    return parsed_data


def http_content_routing_member_parser(client: Client, http_content_routing_member: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for HTTP content routing member.

    Args:
        client (Client): Fortiweb VM client.
        http_content_routing_member (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """
    if client.version == ClientV1.API_VER:
        id_default = dict_safe_get(
            client.api_to_user_mapper,
            ['http_content_routing_member', 'is_default', http_content_routing_member['default']])
        inherit_web_protection_profile = dict_safe_get(client.api_to_user_mapper, [
            'http_content_routing_member', 'inherit_webprotection_profile',
            http_content_routing_member['inheritWebProtectionProfile']
        ])
        parsed_data = {
            'id': http_content_routing_member['_id'],
            'default': id_default,
            'http_content_routing_policy': http_content_routing_member['http_content_routing_policy'],
            'inherit_web_protection_profile': inherit_web_protection_profile,
            'profile': http_content_routing_member['profile'],
        }
    else:
        parsed_data = {
            'id': http_content_routing_member['id'],
            'default': http_content_routing_member['is-default'],
            'http_content_routing_policy': http_content_routing_member['content-routing-policy-name'],
            'inherit_web_protection_profile': http_content_routing_member['profile-inherit'],
            'profile': http_content_routing_member['web-protection-profile'],
            'status': http_content_routing_member['status']
        }
    return parsed_data


def geo_ip_group_parser(client: Client, geo_ip_group: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for Geo IP Group.

    Args:
        client (Client): Fortiweb VM client.
        geo_ip_group (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """
    if client.version == ClientV1.API_VER:
        severity = dict_safe_get(client.api_to_user_mapper, ['geo_ip', 'severity', geo_ip_group['severity']])
        parsed_data = {
            'id': geo_ip_group['_id'],
            'count': geo_ip_group['count'],
            'trigger_policy': geo_ip_group['triggerPolicy'],
            'severity': severity,
            'except': geo_ip_group['except'],
            'can_delete': geo_ip_group['can_delete'],
        }
    else:
        action = dict_safe_get(client.api_to_user_mapper, ['geo_ip', 'action', geo_ip_group['action']])
        parsed_data = {
            'id': geo_ip_group['name'],
            'count': geo_ip_group['sz_country-list'],
            'trigger_policy': geo_ip_group['trigger'],
            'severity': geo_ip_group['severity'],
            'except': geo_ip_group['exception-rule'],
            'action': action,
            'block_period': geo_ip_group['block-period'],
            'ignore_x_forwarded_for': geo_ip_group['ignore-x-forwarded-for'],
        }
    return parsed_data


def geo_ip_member_parser(client: Client, geo_ip_member: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for Geo IP member.

    Args:
        client (Client): Fortiweb VM client.
        geo_ip_member (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """
    if client.version == ClientV1.API_VER:
        parsed_data = {
            'id': geo_ip_member['_id'],
            'country': geo_ip_member['value'],
        }
    else:
        parsed_data = {
            'id': geo_ip_member['id'],
            'country': geo_ip_member['country-name'],
        }
    return parsed_data


def operation_status_parser(client: Client, operation_network: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for operation status.

    Args:
        client (Client): Fortiweb VM client.
        ip_list_member (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """
    parsed_data = {
        'id': operation_network['id'],
        'name': operation_network['name'],
        'label': operation_network['label'],
        'alias': operation_network['alias'],
        'ip_netmask': operation_network['ip_netmask'],
        'speed_duplex': operation_network['speedDuplex'],
        'tx': operation_network['tx'],
        'rx': operation_network['rx'],
        'link': operation_network['link'],
    }
    return parsed_data


def policy_status_parser(client: Client, policy: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for operation status.

    Args:
        client (Client): Fortiweb VM client.
        ip_list_member (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """
    if client.version == ClientV1.API_VER:
        parsed_data = {
            'id': policy['_id'],
            'name': policy['name'],
            'status': policy['status'],
            'vserver': policy['vserver'],
            'http_port': policy['httpPort'],
            'https_port': policy['httpsPort'],
            'mode': policy['mode'],
            'session_count': policy['sessionCount'],
            'connction_per_second': policy['connCntPerSec'],
        }
    else:
        parsed_data = {
            'id': policy['_id'],
            'policy': policy['policy'],
            'name': policy['name'],
            'status': policy['status'],
            'protocol': policy['protocol'],
            'vserver': policy['vserver'],
            'http_port': policy['httpPort'],
            'https_port': policy['httpsPort'],
            'mode': policy['mode'],
            'session_count': policy['sessionCount'],
            'connction_per_second': policy['connCntPerSec'],
            'client_rtt': policy['client_rtt'],
            'server_rtt': policy['server_rtt'],
            'app_response_time': policy['app_response_time'],
        }
    return parsed_data


def system_status_parser(client: Client, policy: Dict[str, Any]) -> Dict[str, Any]:
    """Parser for operation status.

    Args:
        client (Client): Fortiweb VM client.
        ip_list_member (Dict[str, Any]): A dictionary output from API.

    Returns:
        Dict[str, Any]: Parsed dictionary.
    """
    if client.version == ClientV1.API_VER:
        parsed_data = {
            'high_ability_status': policy['haStatus'],
            'host_name': policy['hostName'],
            'serial_number': policy['serialNumber'],
            'operation_mode': policy['operationMode'],
            'system_time': policy['systemTime'],
            'firmware_version': policy['firmwareVersion'],
            'system_uptime': policy['systemUptime'],
            'administrative_domain': policy['administrativeDomain'],
            'fips_and_cc_mode': policy['fipcc'],
            'log_disk': policy['logDisk'],
        }
    else:
        parsed_data = {
            'high_ability_status': policy['haStatus'],
            'host_name': policy['hostName'],
            'manager_status': policy['managerMode'],
            'serial_number': policy['serialNumber'],
            'operation_mode': policy['operationMode'],
            'system_time': policy['systemTime'],
            'firmware_version': policy['firmwareVersion'],
            'sysyem_up_days': policy['up_days'],
            'sysyem_up_hrs': policy['up_hrs'],
            'sysyem_up_mins': policy['up_mins'],
            'administrative_domain': policy['administrativeDomain'],
        }
    return parsed_data


def http_service_parser(client: Client, policy: Dict[str, Any]) -> Dict[str, Any]:
    return {'id': policy['name']}


def simple_id_parser(client: Client, data_dict: Dict[str, Any]) -> Dict[str, Any]:
    return {'id': data_dict['_id'] if client.version == ClientV1.API_VER else data_dict['name']}


def paginate_results(version: str, response: Union[List, Dict[str, Any]], args: Dict[str, Any]) -> Tuple[list, str]:
    """ Executing Manual paginate_results  (using the page and page size arguments)
        or Automatic paginate_results  (display a number of total results).
    Args:
        response (Union[Dict[str, Any], List[Dict[str, Any]]]): API response.
        page (int, optional): Page number of paginated results.
        page_size (int, optional): Number of ip-list per page.
        limit (int, optional): The maximum number of records to retrieve.
    Returns:
        Tuple[dict,str]: Output and paginate_results  message for Command Results.
    """
    if version == ClientV2.API_VER:
        response = response['results']  # type: ignore # V2 always returns a Dict.
    response = response if isinstance(response, list) else [response]
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit', LIMIT_SIZE))

    output = response

    if page and page_size:
        if page_size < len(response):
            first_item = page_size * (page - 1)
            output = response[first_item:first_item + page_size]
        else:
            output = response[:page_size]
        pagination_message = f'Showing page {page}. \n Current page size: {page_size}'
    else:
        output = response[:limit]
        pagination_message = f'Showing {len(output)} rows out of {len(response)}.'

    return output, pagination_message


def find_dict_in_array(container: List[Dict[str, Any]], key: str,
                       value: Union[str, List[str]]) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
    """Gets dictionary object in list of dictionaries.The search is by key that exist in each dictionary.

    Args:
        container (list): List of dictionaries.
        key (str): Key to recognize the correct dictionary.
        value (Union[str, List[str]]): The value/values for the key.

    Returns:
        Union[Dict[str, Any], List[Dict[str, Any]],None]: The dictionary / List of dictionaries / None if there is no match.
    """

    if isinstance(value, str):
        for obj in container:
            if obj[key] == value:
                return obj
    elif isinstance(value, list):
        return [obj for obj in container if obj[key] in value] or None
    return None


def get_sub_object_id(client: Client, object_id: str, create_response: Dict[str, Any], by_key: str, value: str,
                      get_request) -> str:
    """Get sub object id. After create sub (member) object we should get list of all members and get our id by some key.

    Args:
        client (Client): Fortiweb VM Client.
        object_id (str): Object ID (not sub object)!
        create_response (Dict[str, Any]): Response from create request.
        by_key (str): Unique key to search the sub object.
        value (str): The sub object value to the key.
        get_request (_type_): Get request (for Fortiweb VM 1)

    Returns:
        str: Member ID
    """
    if client.version == ClientV2.API_VER:
        member_id = create_response['results']['id']
    else:
        if members_list := get_request(object_id):
            member_data = find_dict_in_array(members_list, by_key, value)
        member_id = member_data['_id'] if member_data else 'Can not find the id'
    return member_id


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
        if error.res.status_code == HTTPStatus.UNAUTHORIZED:
            return 'Authorization Error: make sure API key is correctly set'
        raise error
    except Exception as error:
        return f'Connection error : {error}'
    return 'ok'


def generate_simple_command_results(key: str, value: str, response: Dict[str, Any], message: str) -> CommandResults:
    """Genarte a simple command result with output (without context data).

    Args:
        key (str): Output key.
        value (str): Output value.
        response (Dict[str, Any]): Response dictionary from Fortiweb VM
        message (str): Output message.

    Returns:
        CommandResults: CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    outputs = {key: value}
    readable_output = tableToMarkdown(message, outputs, headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output, raw_response=response)
    return command_results


def block_period_validation(version: str, block_period: Optional[int]):
    if version == ClientV2.API_VER and block_period and not 1 <= block_period <= 600:
        return_error('Block period should be a number in range of 1-600.')


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    base_url = str(params.get('url'))
    api_key = params.get('credentials', {}).get('password')
    version = params['api_version']
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'fortiwebvm-protected-hostname-group-create': protected_hostname_create_command,
        'fortiwebvm-protected-hostname-group-update': protected_hostname_update_command,
        'fortiwebvm-protected-hostname-group-delete': protected_hostname_delete_command,
        'fortiwebvm-protected-hostname-group-list': protected_hostname_list_command,
        'fortiwebvm-protected-hostname-member-create': protected_hostname_member_create_command,
        'fortiwebvm-protected-hostname-member-update': protected_hostname_member_update_command,
        'fortiwebvm-protected-hostname-member-delete': protected_hostname_member_delete_command,
        'fortiwebvm-protected-hostname-member-list': protected_hostname_member_list_command,
        'fortiwebvm-ip-list-group-create': ip_list_group_create_command,
        'fortiwebvm-ip-list-group-update': ip_list_group_update_command,
        'fortiwebvm-ip-list-group-delete': ip_list_group_delete_command,
        'fortiwebvm-ip-list-group-list': ip_list_group_list_command,
        'fortiwebvm-ip-list-member-create': ip_list_member_create_command,
        'fortiwebvm-ip-list-member-update': ip_list_member_update_command,
        'fortiwebvm-ip-list-member-delete': ip_list_member_delete_command,
        'fortiwebvm-ip-list-member-list': ip_list_member_list_command,
        'fortiwebvm-http-content-routing-member-add': http_content_routing_member_add_command,
        'fortiwebvm-http-content-routing-member-update': http_content_routing_member_update_command,
        'fortiwebvm-http-content-routing-member-delete': http_content_routing_member_delete_command,
        'fortiwebvm-http-content-routing-member-list': http_content_routing_member_list_command,
        'fortiwebvm-geo-ip-group-create': geo_ip_group_create_command,
        'fortiwebvm-geo-ip-group-update': geo_ip_group_update_command,
        'fortiwebvm-geo-ip-group-delete': geo_ip_group_delete_command,
        'fortiwebvm-geo-ip-group-list': geo_ip_group_list_command,
        'fortiwebvm-geo-ip-member-add': geo_ip_member_add_command,
        'fortiwebvm-geo-ip-member-delete': geo_ip_member_delete_command,
        'fortiwebvm-geo-ip-member-list': geo_ip_member_list_command,
        'fortiwebvm-system-operation-status-get': operation_status_get_command,
        'fortiwebvm-system-policy-status-get': policy_status_get_command,
        'fortiwebvm-system-status-get': system_status_get_command,
        'fortiwebvm-server-pool-list': server_pool_list_command,
        'fortiwebvm-http-service-list': http_service_list_command,
        'fortiwebvm-inline-protection-profile-list': inline_protection_profile_list_command,
        'fortiwebvm-virtual-server-list': virtual_server_list_command,
        'fortiwebvm-content-routing-policy-list': http_content_routing_policy_list_command,
    }
    try:
        client_class = {'V1': ClientV1, 'V2': ClientV2}[version]
        client: Client = client_class(base_url=base_url,
                                      api_key=api_key,
                                      version=version,
                                      proxy=proxy,
                                      verify=verify_certificate)
        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as error:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(error)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
