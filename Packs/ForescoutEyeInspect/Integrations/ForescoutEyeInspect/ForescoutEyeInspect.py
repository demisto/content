import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from copy import deepcopy
from typing import Any
from urllib.parse import urljoin  # type: ignore

import urllib3

from CommonServerUserPython import *

# disable insecure warnings
urllib3.disable_warnings()

CUSTOM_TABLE_HEADERS = {
    'Id': 'ID',
    'Ip': 'IP',
    'Mac': 'MAC',
    'Src': 'Source',
    'Dst': 'Destination',
    'Proto': 'Protocol',
}

XSOAR_SEVERITY_MAPPING = {
    0: IncidentSeverity.UNKNOWN,
    1: IncidentSeverity.INFO,
    2: IncidentSeverity.LOW,
    3: IncidentSeverity.MEDIUM,
    4: IncidentSeverity.HIGH,
    5: IncidentSeverity.CRITICAL,
}

DEFAULT_PAGE = 1
DEFAULT_LIMIT = 50
DEFAULT_FIRST_FETCH = '7 days'
MAX_LIMIT = 100
DEFAULT_FETCH_INCIDENTS = 50
MAX_FETCH_INCIDENTS = 200


class Client(BaseClient):
    """
    Client for ForescoutEyeInspect RESTful API.

    Args:
        base_url (str): The base URL of ForescoutEyeInspect.
        use_ssl (bool): Specifies whether to verify the SSL certificate or not.
        use_proxy (bool): Specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, username: str, password: str, use_ssl: bool, use_proxy: bool):
        super().__init__(urljoin(base_url, '/api/v1/'),
                         auth=(username, password),
                         verify=use_ssl,
                         proxy=use_proxy)

    def list_hosts_request(self,
                           offset: Optional[int] = None,
                           limit: Optional[int] = None,
                           last_seen: Optional[str] = None,
                           id_min: Optional[int] = None,
                           sort_field: Optional[str] = None,
                           sort_ascending: Optional[bool] = None) -> List[dict[str, Any]]:
        """
        Retrieves information about the hosts in the eyeInspect CC database.

        Args:
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.
            last_seen (Optional[int]): List only records with the last seen timestamp
                bigger or equal to the provided parameter.
            id_min (Optional[int]): Retrieve hosts from a minimum ID value onward.
            sort_field (Optional[int]): List records and sort them based on a specific field, as well as on ID.
            sort_ascending (Optional[bool]): Indicates whether the result list should be sorted ascending or descending.

        Returns:
            List[Dict[str, Any]]: Forescout EyeInspect hosts.
        """

        params = remove_empty_elements({
            'offset': offset,
            'limit': limit,
            'last_seen': last_seen,
            'id_min': id_min,
            'sort_field': sort_field,
            'sort_ascending': sort_ascending
        })

        return self._http_request(method='GET', url_suffix='hosts', params=params)

    def list_links_request(self,
                           offset: Optional[int] = None,
                           limit: Optional[int] = None,
                           src_host_id: Optional[int] = None,
                           dst_host_id: Optional[int] = None,
                           proto: Optional[str] = None,
                           port: Optional[str] = None,
                           last_seen: Optional[str] = None,
                           id_min: Optional[int] = None,
                           sort_field: Optional[str] = None,
                           sort_ascending: Optional[bool] = None) -> List[dict[str, Any]]:
        """
        Retrieves information about the links in the eyeInspect CC database.

        Args:
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.
            src_host_id (Optional[int]): List only records with the src_host_id property set to the specified value.
            dst_host_id (Optional[int]): List only records with the dst_host_id property set to the specified value.
            proto (Optional[str]): List only records with the provided protocol.
            port (Optional[str]): List only records with one of the values of the port property equal to the provided parameter.
            last_seen (Optional[str]): List only records with the last_seen timestamp bigger or equal to the provided parameter.
            id_min (Optional[int]): Retrieve links from a minimum ID value onward.
            sort_field (Optional[str]): List records and sort them based on a specific field, as well as on ID.
            sort_ascending (Optional[bool]): Indicates whether the result list should be sorted ascending or descending.

        Returns:
            List[Dict[str, Any]]: Link between 2 hosts.
        """

        params = remove_empty_elements({
            'offset': offset,
            'limit': limit,
            'src_host_id': src_host_id,
            'dst_host_id': dst_host_id,
            'proto': proto,
            'port': port,
            'last_seen': last_seen,
            'id_min': id_min,
            'sort_field': sort_field,
            'sort_ascending': sort_ascending
        })

        return self._http_request(method='GET', url_suffix='links', params=params)

    def get_vulnerability_info_request(self, cve_id: str) -> dict[str, Any]:
        """
        Retrieves information about a specific vulnerability stored in the eyeInspect CC database.

        Args:
            cve_id (str): The unique ID of the vulnerability information record to be retrieved.

        Returns:
            Dict[str, Any]: Information about the CVE.
        """

        return self._http_request(method='GET', url_suffix=f'cve_info/{cve_id}')

    def list_alerts_request(self,
                            offset: Optional[int] = None,
                            limit: Optional[int] = None,
                            start_timestamp: Optional[str] = None,
                            end_timestamp: Optional[str] = None,
                            event_type_id: Optional[str] = None,
                            l4_proto: Optional[str] = None,
                            l7_proto: Optional[str] = None,
                            src_ip: Optional[str] = None,
                            dst_ip: Optional[str] = None,
                            ip: Optional[str] = None,
                            dst_port: Optional[int] = None,
                            src_host_id: Optional[int] = None,
                            dst_host_id: Optional[int] = None,
                            host_id: Optional[int] = None) -> List[dict[str, Any]]:
        """
        Retrieves information about the alerts inside eyeInspect CC.

        Args:
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.
            start_timestamp (Optional[str]): List only records with the timestamp property bigger or equal to the specified value.
            end_timestamp (Optional[str]): List only records with the timestamp property smaller or equal to the specified value.
            event_type_id (Optional[str]): List records that have the event_type_id property containing the specified parameter.
            l4_proto (Optional[str]): List records that have the l4_proto property equal to the specified parameter.
            l7_proto (Optional[str]): List records that have the l7_proto property equal to the specified parameter.
            src_ip (Optional[str]): List records that have the src_ip property equal to the specified parameter,
                or contained in the given CIDR-defined network.
            dst_ip (Optional[str]): List records that have the dst_ip property equal to the specified parameter,
                or contained in the given CIDR-defined network.
            ip (Optional[str]): List records that have either the src_ip or the dst_ip property equal to the specified parameter,
                or contained in the given CIDR-defined network.
            dst_port (Optional[int]): Fetch records that have dst_port equal to the specified parameter.
            src_host_id (Optional[int]): Fetch records that have the src_ip or src_mac equal to the specified host id.
            dst_host_id (Optional[int]): Fetch records that have the dst_ip or dst_mac equal to the specified host id.
            host_id (Optional[int]): Fetch records that have either the IP or MAC address equal to the specified host id.

        Returns:
            List[Dict[str, Any]]: Forescout EyeInspect alert.
        """

        params = remove_empty_elements({
            'offset': offset,
            'limit': limit,
            'start_timestamp': start_timestamp,
            'end_timestamp': end_timestamp,
            'event_type_id': event_type_id,
            'l4_proto': l4_proto,
            'l7_proto': l7_proto,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'ip': ip,
            'dst_port': dst_port,
            'src_host_id': src_host_id,
            'dst_host_id': dst_host_id,
            'host_id': host_id
        })

        return self._http_request(method='GET', url_suffix='alerts', params=params)

    def get_alert_pcap_request(self, alert_id: int) -> bytes:
        """
        Retrieves the PCAP file associated to a given Alert.

        Args:
            alert_id (int): The unique ID of the Alert to get the PCAP of.

        Returns:
            Dict[str, Any]: Alert PCAP file.
        """

        return self._http_request(method='GET',
                                  url_suffix=f'alert_pcaps/{alert_id}',
                                  resp_type='content')

    def list_sensors_request(self,
                             offset: Optional[int] = None,
                             limit: Optional[int] = None,
                             all_sensors: Optional[bool] = None) -> List[dict[str, Any]]:
        """
        Retrieves information about the sensors associated to the eyeInspect CC.

        Args:
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.
            all_sensors (Optional[bool]): Whether to retrieve all the sensors (ICS Patrol and passive) or only the passive ones.

        Returns:
            List[Dict[str, Any]]: Forescout EyeInspect sensors.
        """

        params = remove_empty_elements({
            'offset': offset,
            'limit': limit,
            'all_sensors': all_sensors
        })

        return self._http_request(method='GET', url_suffix='sensors', params=params)

    def list_sensor_modules_request(self,
                                    sensor_id: int,
                                    offset: Optional[int] = None,
                                    limit: Optional[int] = None) -> List[dict[str, Any]]:
        """
        Retrieves information about the Modules of the specified Sensor.

        Args:
            sensor_id (int): The unique ID of the Sensor to query for modules.
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.

        Returns:
            List[Dict[str, Any]]: Forescout EyeInspect sensor module.
        """

        params = remove_empty_elements({'offset': offset, 'limit': limit})

        return self._http_request(method='GET',
                                  url_suffix=f'sensors/{sensor_id}/modules',
                                  params=params)

    def update_sensor_module_request(self,
                                     sensor_id: int,
                                     module_id: int,
                                     name: Optional[str] = None,
                                     description: Optional[str] = None,
                                     started: Optional[bool] = None,
                                     operational_mode: Optional[str] = None) -> dict[str, Any]:
        """
        Changes the specified properties of the specified Module.

        Args:
            sensor_id (int): The unique ID of the Sensor which the Module to update.
            module_id (int): The unique ID of the Module to update.
            name (Optional[str]): Name of the module.
            description (Optional[str]): Description of the module.
            started (Optional[bool]): If set to true the module will be started.
            operational_mode (Optional[str]): Changes the operational mode of the Module to the specified value.

        Returns:
            Dict[str, Any]: Forescout EyeInspect sensor module.
        """

        params = remove_empty_elements({
            'name': name,
            'description': description,
            'started': started,
            'operational_mode': operational_mode
        })

        return self._http_request(method='PUT',
                                  url_suffix=f'sensors/{sensor_id}/modules/{module_id}',
                                  params=params)

    def delete_sensor_module_request(self, sensor_id: int, module_id: int) -> None:
        """
        Deletes the specified Module from the specified Sensor and from the eyeInspect CC database.

        Args:
            sensor_id (int): The unique ID of the Sensor which the Module to delete.
            module_id (int): The unique ID of the Module to delete.
        """

        self._http_request(method='DELETE',
                           url_suffix=f'sensors/{sensor_id}/modules/{module_id}',
                           resp_type='text')

    def get_ip_blacklist_request(self,
                                 sensor_id: int,
                                 offset: Optional[int] = None,
                                 limit: Optional[int] = None) -> List[dict[str, Any]]:
        """
        Retrieves the IP blacklist from the Industrial Threat Library of the specified Sensor.

        Args:
            sensor_id (int): The unique ID of the Sensor of which the IP blacklist is to be retrieved.
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.

        Returns:
            List[Dict[str, Any]]: The IP addresses of the blacklist.
        """

        params = remove_empty_elements({'offset': offset, 'limit': limit})

        return self._http_request(method='GET',
                                  url_suffix=f'sensors/{sensor_id}/itl/itl_sec_udb_bip/blacklist',
                                  params=params)

    def add_ip_blacklist_request(self, sensor_id: int, address: str, comment: str = '') -> None:
        """
        Adds a new entry to the IP blacklist from the Industrial Threat Library of the specified Sensor.

        Args:
            sensor_id (int): The unique ID of the Sensor of which the IP blacklist is to be updated.
            address (str): The IP to add to the blacklist.
            comment (str): A comment about the blacklisted IP.
        """

        body = [{'address': address, 'comment': comment}]

        self._http_request(method='POST',
                           url_suffix=f'sensors/{sensor_id}/itl/itl_sec_udb_bip/blacklist',
                           json_data=body,
                           resp_type='text')

    def get_domain_blacklist_request(self,
                                     sensor_id: int,
                                     offset: Optional[int] = None,
                                     limit: Optional[int] = None) -> List[dict[str, Any]]:
        """
        Retrieves the domain name blacklist from the Industrial Threat Library of the specified Sensor.

        Args:
            sensor_id (int): The unique ID of the Sensor that contains the domain blacklist.
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.

        Returns:
            Dict[str, Any]: The domain names from the blacklist.
        """

        params = remove_empty_elements({'offset': offset, 'limit': limit})

        return self._http_request(
            method='GET',
            url_suffix=f'sensors/{sensor_id}/itl/itl_sec_udb_dns_bd/blacklist',
            params=params)

    def add_domain_blacklist_request(self,
                                     sensor_id: int,
                                     domain_name: str,
                                     comment: str = '') -> None:
        """
        Adds a new entry to the domain name blacklist from the Industrial Threat Library of the specified Sensor.

        Args:
            sensor_id (int): The unique ID of the Sensor of which the domain to be updated.
            domain_name (str): The domain name to add to the blacklist.
            comment (str): A comment about the domain name.
        """

        body = [{'domain_name': domain_name, 'comment': comment}]

        self._http_request(method='POST',
                           url_suffix=f'sensors/{sensor_id}/itl/itl_sec_udb_dns_bd/blacklist',
                           json_data=body,
                           resp_type='text')

    def get_ssl_client_blacklist_request(self,
                                         sensor_id: int,
                                         offset: Optional[int] = None,
                                         limit: Optional[int] = None) -> List[dict[str, Any]]:
        """
        Retrieves the SSL client application blacklist from the Industrial Threat Library of the specified Sensor.

        Args:
            sensor_id (int): The unique ID of the Sensor of which the SSL client blacklist to be retrieved.
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.

        Returns:
            List[Dict[str, Any]]: The SSL client applications from the specified sensor's blacklist.
        """

        params = remove_empty_elements({'offset': offset, 'limit': limit})

        return self._http_request(
            method='GET',
            url_suffix=f'sensors/{sensor_id}/itl/itl_sec_udb_ssl_bja3/blacklist',
            params=params)

    def add_ssl_client_blacklist_request(self,
                                         sensor_id: int,
                                         application_name: str,
                                         ja3_hash: str,
                                         comment: str = '') -> None:
        """
        Adds a new entry to the SSL client application blacklist from the Industrial Threat Library of the specified Sensor.

        Args:
            sensor_id (int): The unique ID of the Sensor of which the SSL client.
            application_name (str): The application name related to add to blacklist.
            ja3_hash (str): The JA3 hash of a blacklisted client application.
            comment (str): Comment about the SSL client application.

        Returns:
            Dict[str, Any]: Forescout EyeInspect ITL SSL client applications blacklist.
        """

        body = [{'application_name': application_name, 'ja3_hash': ja3_hash, 'comment': comment}]

        self._http_request(method='POST',
                           url_suffix=f'sensors/{sensor_id}/itl/itl_sec_udb_ssl_bja3/blacklist',
                           json_data=body,
                           resp_type='text')

    def get_file_operation_blacklist_request(self,
                                             sensor_id: int,
                                             offset: Optional[int] = None,
                                             limit: Optional[int] = None) -> List[dict[str, str]]:
        """
        Retrieves the file operation blacklist from the Industrial Threat Library of the specified Sensor.

        Args:
            sensor_id (int): The unique ID of the Sensor of which the file operation blacklist to be retrieved.
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.

        Returns:
            List[Dict[str, Any]]: The file operations from the specified sensor's blacklist.
        """

        params = remove_empty_elements({'offset': offset, 'limit': limit})

        return self._http_request(method='GET',
                                  url_suffix=f'sensors/{sensor_id}/itl/itl_sec_udb_bfo/blacklist',
                                  params=params)

    def add_file_operation_blacklist_request(self,
                                             sensor_id: int,
                                             matching_type: str,
                                             file_or_folder: str,
                                             operation: str,
                                             comment: str = '') -> None:
        """
        Adds entries to the file operation blacklist from the Industrial Threat Library of the specified Sensor.

        Args:
            sensor_id (int): The unique ID of the Sensor of which the file operation blacklist is to be updated.
            matching_type (str): The way file_or_folder should be matched.
            file_or_folder (str): The name of the file or folder the entry applies to.
            operation (str): The name of the file operation.
            comment (str): A comment provided by the user.
        """

        body = [{
            'matching_type': matching_type,
            'file_or_folder': file_or_folder,
            'operation': operation,
            'comment': comment
        }]

        self._http_request(method='POST',
                           url_suffix=f'sensors/{sensor_id}/itl/itl_sec_udb_bfo/blacklist',
                           json_data=body,
                           resp_type='text')

    def get_diagnostics_information_request(self) -> dict[str, Any]:
        """
        Retrieves information about all monitored Command Center resources and their health status excluding the logs.

        Returns:
            Dict[str, Any]: The command center diagnostics.
        """

        return self._http_request(method='GET', url_suffix='cc_info')

    def get_diagnostic_logs_request(self,
                                    cc_info: Optional[bool] = None,
                                    sensor_id: Optional[str] = None) -> bytes:
        """
        Download the ZIP file which contains diagnostic logs of the Command Center.

        Args:
            cc_info (Optional[bool]): Whether to include Command Center diagnostic logs inside the downloaded zip,
                                      in addition to sensors logs.
            sensor_id (Optional[str]): Include logs from specific sensor by its ID, or all sensors (by specifying All).

        Returns:
            bytes: Diagnostics logs ZIP file.
        """

        params = remove_empty_elements({'cc_info': cc_info, 'sensor_id': sensor_id})
        return self._http_request(method='GET',
                                  url_suffix='diagnostic_logs',
                                  params=params,
                                  resp_type='content')

    def list_group_policies_request(self,
                                    offset: Optional[int] = None,
                                    limit: Optional[int] = None) -> List[dict[str, Any]]:
        """
        Get all group policies.

        Args:
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.

        Returns:
            List[Dict[str, Any]]: Forescout EyeInspect group policies.
        """

        params = remove_empty_elements({'offset': offset, 'limit': limit})

        return self._http_request(method='GET', url_suffix='group_policy', params=params)

    def create_group_policy_request(self, name: str, description: str,
                                    constraints: List[dict[str, Any]]) -> dict[str, Any]:
        """
        Create a new group policy.

        Args:
            name (str): The name of the group policy.
            description (str): The description of the group policy.
            constraints (List[Dict[str, Any]]): List of constraints of the policy.

        Returns:
            Dict[str, Any]: Forescout EyeInspect group policy.
        """

        body = {'name': name, 'description': description, 'constraints': constraints}

        return self._http_request(method='POST', url_suffix='group_policy', json_data=body)

    def update_group_policy_request(self, policy_id: int, name: str, description: str,
                                    constraints: List[dict[str, Any]]) -> dict[str, Any]:
        """
        Update a group policy.

        Args:
            policy_id (int): The unique ID of the Policy of which the hosts will be added to.
            name (str): The name of the group policy.
            description (str): The description of the group policy.
            constraints (List[Dict[str, Any]]): List of constraints of the policy.

        Returns:
            Dict[str, Any]: Forescout EyeInspect group policy.
        """

        body = {'name': name, 'description': description, 'constraints': constraints}

        return self._http_request(method='PUT',
                                  url_suffix=f'group_policy/{policy_id}',
                                  json_data=remove_empty_elements(body))

    def delete_group_policy_request(self, policy_id: int) -> None:
        """
        Delete an existing group policy.

        Args:
            policy_id (int): The unique ID of the Policy of which the hosts will be added to.
        """

        self._http_request(method='DELETE',
                           url_suffix=f'group_policy/{policy_id}',
                           resp_type='text')

    def assign_group_policy_hosts_request(self, policy_id: int, filter_type: str,
                                          filter_value: str) -> dict[str, Any]:
        """
        Add all hosts not assigned to any policy (individual or group) matching the filter to the group policy.

        Args:
            policy_id (int): The unique ID of the Policy of which the hosts will be added to.
            filter_type (str): The type of the filter.
            filter_value (str): The value of the filter.

        Returns:
            Dict[str, Any]: The response with the number of assigned hosts.
        """

        body = [{'type': filter_type, 'value': filter_value}]

        return self._http_request(method='POST',
                                  url_suffix=f'group_policy/{policy_id}/add_hosts',
                                  json_data=body)

    def unassign_group_policy_hosts_request(self, policy_id: int, filter_type: str,
                                            filter_value: str) -> dict[str, Any]:
        """
        Unassign all hosts assigned to the group policy matching the filter.

        Args:
            policy_id (int): The unique ID of the Policy of which the hosts will be removed.
            filter_type (str): The type of the filter.
            filter_value (str): The value of the filter.

        Returns:
            Dict[str, Any]: The response with the number of assigned hosts.
        """

        body = [{'type': filter_type, 'value': filter_value}]

        return self._http_request(method='POST',
                                  url_suffix=f'group_policy/{policy_id}/remove_hosts',
                                  json_data=body)

    def list_ip_reuse_domains_request(self,
                                      offset: Optional[int] = None,
                                      limit: Optional[int] = None) -> List[dict[str, Any]]:
        """
        Get all IP reuse domains.

        Args:
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.

        Returns:
            List[Dict[str, Any]]: Forescout EyeInspect IP reuse domains.
        """

        params = remove_empty_elements({'offset': offset, 'limit': limit})

        return self._http_request(method='GET', url_suffix='ip_reuse_domains', params=params)

    def list_hosts_changelog_request(self,
                                     offset: Optional[int] = None,
                                     limit: Optional[int] = None,
                                     host_id: Optional[int] = None,
                                     start_timestamp: Optional[str] = None,
                                     end_timestamp: Optional[str] = None,
                                     event_type_id: Optional[str] = None,
                                     event_category: Optional[str] = None) -> List[dict[str, Any]]:
        """
        Retrieves information about the changes of host properties and configuration from the eyeInspect CC database.

        Args:
            offset (Optional[int]): List records starting from the given offset (minimum is 0).
            limit (Optional[int]): List only up to limit records.
            host_id (Optional[int]): List only records with the host_id property equal to the provided parameter.
            start_timestamp (Optional[str]): List only records with the timestamp property bigger or equal to the specified value.
            end_timestamp (Optional[str]): List only records with the timestamp property smaller or equal to the specified value.
            event_type_id (Optional[str]): List only records with the event_type_id property equal to the specified value.
            event_category (Optional[str]): List only records with the event_type_id property equal to the specified value.

        Returns:
            List[Dict[str, Any]]: changelog about a host.
        """

        params = remove_empty_elements({
            'offset': offset,
            'limit': limit,
            'host_id': host_id,
            'start_timestamp': start_timestamp,
            'end_timestamp': end_timestamp,
            'event_type_id': event_type_id,
            'event_category': event_category
        })

        return self._http_request(method='GET', url_suffix='host_change_logs', params=params)

    def get_alert_link(self, alert_id: int) -> str:
        return f'{urljoin(self._base_url, "/evt")}?id={alert_id}'

    def _http_request(self,
                      method: str,
                      url_suffix: str = '',
                      full_url: str = None,
                      headers: dict[str, str] = None,
                      *args,
                      **kwargs):
        if method in ['POST', 'PUT', 'DELETE']:
            headers = headers or {}
            headers['X-CSRF-Token'] = self._get_csrf_token()

        return super()._http_request(method, url_suffix, full_url, headers, *args, **kwargs)

    def _get_csrf_token(self) -> str:
        session_response = self._http_request(method='GET',
                                              url_suffix='sensors',
                                              resp_type='response')
        session_id = session_response.cookies.get('CCJSESSIONID')

        old_auth = self._auth
        self._auth = None
        token_response = self._http_request(method='GET',
                                            url_suffix='sensors',
                                            resp_type='response',
                                            headers={'X-CSRF-Token': 'Fetch'},
                                            cookies={'CCJSESSIONID': session_id})
        self._auth = old_auth

        return token_response.headers['X-CSRF-Token']


def arg_to_type_list(arg: str, item_type: type[Any]) -> List[Any]:
    """
    Converts XSOAR argument to list with certain type.

    Args:
        arg (str): The XSOAR argument.
        item_type (Type[Any]): The type of items inside the converted list.

    Returns:
        List[Any]: The converted list.
    """

    return [item_type(item) for item in argToList(arg)]


def arg_to_boolean(arg: Optional[str]) -> Optional[bool]:
    """
    Converts XSOAR argument to a Python boolean value.

    Args:
        arg (Optional[str]): The XSOAR argument.

    Returns:
        Optional[bool]: None if argument is None, otherwise the converted boolean.
    """

    if arg is None:
        return None

    return argToBoolean(arg)


def arg_to_datetime_string(arg: Optional[str]) -> Optional[str]:
    """
    Converts argument from XSOAR datetime to datetime string in API format.

    Args:
        arg (Optional[str]): The datetime argument from the user.

    Returns:
        str: The datetime string in API format.
    """

    date = arg_to_datetime(arg)
    return date.astimezone().isoformat() if date else None


def get_pagination_readable_message(page: int, limit: int) -> str:
    """
    Gets a readable output message for commands with pagination.

    Args:
        page (int): The page used in the command.
        limit (int): The limit used in the command.

    Returns:
        str: The message that describes the pagination.
    """

    return f'Current page size: {limit}\n Showing page {page} out of others that may exist.'


def to_table_header(string: str) -> str:
    """
    Converts a name from API data to a readable header.

    Args:
        string (str): The name from the API data.

    Returns:
        str: The readable table header.
    """

    new_string = string_to_table_header(string)
    return ' '.join(CUSTOM_TABLE_HEADERS.get(word, word) for word in new_string.split())


def matches_one_item(items: List[Any], container_list: List[Any]) -> bool:
    """
    Checks if one of the items inside a list is inside another list.

    Args:
        items (List[Any]): The first list to iterate its items.
        container_list (List[Any]): The list to check if the items inside it.

    Returns:
        bool: Whether one of the items is inside container_list.
    """

    return any(True for item in items if item in container_list)


def filter_single_result(result: dict[str, Any], **fields: List[Any]) -> bool:
    """
    Filters a single result of the API, based on the results fields.

    Args:
        result (Dict[str, Any]): A single object from Forescout EyeInspect API.

    Returns:
        bool: Whether the result passed the filter or not.
    """

    for name, values in fields.items():
        result_value = result.get(name)

        if not values:
            continue
        if isinstance(result_value, list) and matches_one_item(values, result_value):
            continue
        if not isinstance(result_value, list) and result_value in values:
            continue

        return False

    return True


def filter_results(results: List[dict[str, Any]], **fields: List[Any]) -> List[dict[str, Any]]:
    """
    Filters records from the API based on the provided fields.
    This is required due to lack of essential fields inside the API filtering.

    Args:
        results (List[Dict[str, Any]]): The results from the API.

    Returns:
        List[Dict[str, Any]]: The results after filtering it.
    """

    return [result for result in results if filter_single_result(result, **fields)]


def add_alerts_fields(client: Client, alerts: List[dict[str, Any]]) -> None:
    """
    Adds additional data to the alerts.

    Args:
        client (Client): The client of ForescoutEyeInspect.
        alerts (List[Dict[str, Any]]): The alert to add the additional data.
    """

    for alert in alerts:
        alert['link'] = client.get_alert_link(alert['alert_id'])
        alert['xsoar_severity'] = XSOAR_SEVERITY_MAPPING.get(alert['severity'], alert['severity'])


def get_pagination_arguments(args: dict[str, Any]) -> tuple[int, int, int]:
    """
    Gets and validates pagination arguments for client (offset and limit).

    Args:
        args (Dict[str, Any]): The command arguments (page and limit).

    Returns:
        Tuple[int, int, int]: The page, calculated offset, and limit after validation.
    """

    page = arg_to_number(args.get('page', DEFAULT_PAGE))
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))

    if page < 1:  # type: ignore[operator]
        raise DemistoException('Page argument must be greater than 1')
    if not 1 <= limit <= MAX_LIMIT:  # type: ignore[operator]
        raise DemistoException(f'Limit argument must be between 1 to {MAX_LIMIT}')

    return page, (page - 1) * limit, limit  # type: ignore[operator,return-value]


def validate_fetch_params(max_fetch: int, first_fetch: str) -> None:
    """
    Validates the parameters for fetch incident command.

    Args:
        max_fetch: (int): The maximum number of incidents for one fetch.
        first_fetch: (str): First fetch time in words.
    """

    try:
        arg_to_datetime(first_fetch)
    except ValueError:
        return_error('First fetch parameter is not a valid datetime')

    if max_fetch > MAX_FETCH_INCIDENTS:
        return_error(
            f'The Maximum number of incidents per fetch should not exceed {MAX_FETCH_INCIDENTS}.')


def list_hosts_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves information about the hosts in the eyeInspect CC database.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    page, offset, limit = get_pagination_arguments(args)
    last_seen = arg_to_datetime_string(args.get('last_seen'))
    id_min = arg_to_number(args.get('id_min'))
    sort_field = args.get('sort_field')
    sort_ascending = arg_to_boolean(args.get('sort_ascending'))

    response = client.list_hosts_request(offset=offset,
                                         limit=limit,
                                         last_seen=last_seen,
                                         id_min=id_min,
                                         sort_field=sort_field,
                                         sort_ascending=sort_ascending)
    outputs = response['results']  # type: ignore[call-overload]

    ip_addresses = argToList(args.get('ip'))
    vlan_ids = argToList(args.get('vlan_id'))
    mac_addresses = argToList(args.get('mac_address'))
    sensor_ids = arg_to_type_list(args.get('sensor_id'), int)  # type: ignore[arg-type]
    outputs = filter_results(outputs,
                             ip=ip_addresses,
                             vlans=vlan_ids,
                             mac_addresses=mac_addresses,
                             sensor_ids=sensor_ids)

    readable_output = tableToMarkdown(
        'Hosts List:',
        outputs,
        removeNull=True,
        headers=['id', 'main_name', 'description', 'os_version', 'ip', 'mac_addresses'],
        headerTransform=to_table_header,
        metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.Host',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def list_links_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves information about the links in the eyeInspect CC database.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    page, offset, limit = get_pagination_arguments(args)
    src_host_id = arg_to_number(args.get('src_host_id'))
    dst_host_id = arg_to_number(args.get('dst_host_id'))
    proto = args.get('proto')
    port = args.get('port')
    last_seen = arg_to_datetime_string(args.get('last_seen'))
    id_min = arg_to_number(args.get('id_min'))
    sort_field = args.get('sort_field')
    sort_ascending = arg_to_boolean(args.get('sort_ascending'))

    response = client.list_links_request(offset=offset,
                                         limit=limit,
                                         src_host_id=src_host_id,
                                         dst_host_id=dst_host_id,
                                         proto=proto,
                                         port=port,
                                         last_seen=last_seen,
                                         id_min=id_min,
                                         sort_field=sort_field,
                                         sort_ascending=sort_ascending)
    outputs = response['results']  # type: ignore[call-overload]

    readable_output = tableToMarkdown('Host Links List:',
                                      outputs,
                                      removeNull=True,
                                      headers=['id', 'src_host_id', 'dst_host_id', 'proto'],
                                      headerTransform=to_table_header,
                                      metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.Link',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def get_vulnerability_info_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves information about a specific vulnerability stored in the eyeInspect CC database.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    cve_id = args['cve_id']

    response = client.get_vulnerability_info_request(cve_id=cve_id)
    readable_output = tableToMarkdown(
        f'CVE {cve_id} Information:',
        response,
        removeNull=True,
        headers=['id', 'title', 'description', 'published_date', 'cvss_score'],
        headerTransform=to_table_header)

    return CommandResults(outputs_prefix='ForescoutEyeInspect.CVE',
                          outputs_key_field='id',
                          outputs=response,
                          readable_output=readable_output,
                          raw_response=response)


def list_alerts_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves information about the alerts inside eyeInspect CC.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    page, offset, limit = get_pagination_arguments(args)
    start_timestamp = arg_to_datetime_string(args.get('start_timestamp'))
    end_timestamp = arg_to_datetime_string(args.get('end_timestamp'))
    event_type_id = args.get('event_type_id')
    l4_proto = args.get('l4_proto')
    l7_proto = args.get('l7_proto')
    src_ip = args.get('src_ip')
    dst_ip = args.get('dst_ip')
    ip = args.get('ip')

    response = client.list_alerts_request(offset=offset,
                                          limit=limit,
                                          start_timestamp=start_timestamp,
                                          end_timestamp=end_timestamp,
                                          event_type_id=event_type_id,
                                          l4_proto=l4_proto,
                                          l7_proto=l7_proto,
                                          src_ip=src_ip,
                                          dst_ip=dst_ip,
                                          ip=ip)
    outputs = response['results']  # type: ignore[call-overload]

    sensor_names = argToList(args.get('sensor_name'))
    vlan_ids = argToList(args.get('vlan_id'))
    severities = arg_to_type_list(args.get('severity'), int)  # type: ignore[arg-type]
    statuses = argToList(args.get('status'))
    outputs = filter_results(outputs,
                             sensor_name=sensor_names,
                             vlan=vlan_ids,
                             severity=severities,
                             status=statuses)
    add_alerts_fields(client, outputs)

    readable_output = tableToMarkdown(
        'Alerts List:',
        outputs,
        removeNull=True,
        headers=['alert_id', 'description', 'timestamp', 'src_ip', 'dst_ip'],
        headerTransform=to_table_header,
        metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.Alert',
                          outputs_key_field='alert_id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def get_alert_pcap_command(client: Client, args: dict[str, str]) -> dict[str, Any]:
    """
    Retrieves the PCAP file associated to a given Alert.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        Dict[str, Any]: File entry of the alert PCAP.
    """

    alert_id = arg_to_number(args['alert_id'])
    response = client.get_alert_pcap_request(alert_id=alert_id)  # type: ignore[arg-type]

    return fileResult(filename=f'alert_{alert_id}_sniff.pcap',
                      data=response,
                      file_type=EntryType.ENTRY_INFO_FILE)


def list_sensors_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves information about the sensors associated to the eyeInspect CC.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    page, offset, limit = get_pagination_arguments(args)
    all_sensors = arg_to_boolean(args.get('all_sensors'))

    response = client.list_sensors_request(offset=offset, limit=limit, all_sensors=all_sensors)
    outputs = response['results']  # type: ignore[call-overload]

    names = argToList(args.get('name'))
    addresses = argToList(args.get('address'))
    ports = arg_to_type_list(args.get('port'), int)  # type: ignore[arg-type]
    sensor_types = argToList(args.get('type'))
    states = argToList(args.get('state'))
    outputs = filter_results(outputs,
                             name=names,
                             address=addresses,
                             port=ports,
                             type=sensor_types,
                             state=states)

    readable_output = tableToMarkdown('Sensors List:',
                                      outputs,
                                      removeNull=True,
                                      headers=['id', 'name', 'address', 'port', 'type'],
                                      headerTransform=to_table_header,
                                      metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.Sensor',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def list_sensor_modules_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves information about the Modules of the specified Sensor.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    page, offset, limit = get_pagination_arguments(args)

    response = client.list_sensor_modules_request(sensor_id=sensor_id, offset=offset, limit=limit)  # type: ignore[arg-type]
    outputs = response['results']  # type: ignore[call-overload]

    readable_output = tableToMarkdown(f'Sensor {sensor_id} Modules List:',
                                      outputs,
                                      removeNull=True,
                                      headers=['id', 'name', 'description', 'engine', 'started'],
                                      headerTransform=to_table_header,
                                      metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.SensorModule',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def update_sensor_module_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Changes the specified properties of the specified Module.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    module_id = arg_to_number(args['module_id'])
    name = args.get('name')
    description = args.get('description')
    started = arg_to_boolean(args.get('started'))
    operational_mode = args.get('operational_mode')

    response = client.update_sensor_module_request(sensor_id=sensor_id,  # type: ignore[arg-type]
                                                   module_id=module_id,  # type: ignore[arg-type]
                                                   name=name,
                                                   description=description,
                                                   started=started,
                                                   operational_mode=operational_mode)
    readable_output = tableToMarkdown(f'Updated Module {module_id} of Sensor {sensor_id}:',
                                      response,
                                      removeNull=True,
                                      headers=['name', 'description', 'engine', 'started'],
                                      headerTransform=to_table_header)

    return CommandResults(outputs_prefix='ForescoutEyeInspect.SensorModule',
                          outputs_key_field='id',
                          outputs=response,
                          readable_output=readable_output,
                          raw_response=response)


def delete_sensor_module_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Deletes the specified Module from the specified Sensor and from the eyeInspect CC database.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    module_id = arg_to_number(args['module_id'])

    client.delete_sensor_module_request(sensor_id=sensor_id, module_id=module_id)  # type: ignore[arg-type]
    readable_output = f'## The module {module_id} of sensor {sensor_id} was successfully deleted!'

    return CommandResults(readable_output=readable_output)


def get_ip_blacklist_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves the IP blacklist from the Industrial Threat Library of the specified Sensor.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    page, offset, limit = get_pagination_arguments(args)

    response = client.get_ip_blacklist_request(sensor_id=sensor_id, offset=offset, limit=limit)  # type: ignore[arg-type]

    outputs = deepcopy(response['results'])  # type: ignore[call-overload]
    for entry in outputs:
        entry['sensor_id'] = sensor_id

    readable_output = tableToMarkdown(f'IP Blacklist of Sensor {sensor_id}:',
                                      outputs,
                                      removeNull=True,
                                      headers=['address', 'comment'],
                                      headerTransform=to_table_header,
                                      metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.IPBlacklist',
                          outputs_key_field='address',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def add_ip_blacklist_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Adds a new entry to the IP blacklist from the Industrial Threat Library of the specified Sensor.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    address = args['address']
    comment = args.get('comment', '')

    client.add_ip_blacklist_request(sensor_id=sensor_id, address=address, comment=comment)  # type: ignore[arg-type]

    outputs = {'address': address, 'comment': comment}
    readable_output = tableToMarkdown(f'New IP Blacklist Entry of Sensor {sensor_id}:',
                                      outputs,
                                      removeNull=True,
                                      headers=['address', 'comment'],
                                      headerTransform=to_table_header)

    return CommandResults(readable_output=readable_output)


def get_domain_blacklist_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves the domain name blacklist from the Industrial Threat Library of the specified Sensor.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    page, offset, limit = get_pagination_arguments(args)

    response = client.get_domain_blacklist_request(sensor_id=sensor_id, offset=offset, limit=limit)  # type: ignore[arg-type]

    outputs = deepcopy(response['results'])  # type: ignore[call-overload]
    for entry in outputs:
        entry['sensor_id'] = sensor_id

    readable_output = tableToMarkdown(f'Domain Blacklist of Sensor {sensor_id}:',
                                      outputs,
                                      removeNull=True,
                                      headers=['domain_name', 'comment'],
                                      headerTransform=to_table_header,
                                      metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.DomainBlacklist',
                          outputs_key_field='domain_name',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def add_domain_blacklist_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Adds a new entry to the domain name blacklist from the Industrial Threat Library of the specified Sensor.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    domain_name = args['domain_name']
    comment = args.get('comment', '')

    client.add_domain_blacklist_request(sensor_id=sensor_id,  # type: ignore[arg-type]
                                        domain_name=domain_name,
                                        comment=comment)

    outputs = {'domain_name': domain_name, 'comment': comment}
    readable_output = tableToMarkdown(f'New Domain Blacklist Entry of Sensor {sensor_id}',
                                      outputs,
                                      removeNull=True,
                                      headers=['domain_name', 'comment'],
                                      headerTransform=to_table_header)

    return CommandResults(readable_output=readable_output)


def get_ssl_client_blacklist_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves the SSL client application blacklist from the Industrial Threat Library of the specified Sensor.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    page, offset, limit = get_pagination_arguments(args)

    response = client.get_ssl_client_blacklist_request(sensor_id=sensor_id,  # type: ignore[arg-type]
                                                       offset=offset,
                                                       limit=limit)

    outputs = deepcopy(response['results'])  # type: ignore[call-overload]
    for entry in outputs:
        entry['sensor_id'] = sensor_id

    readable_output = tableToMarkdown(f'SSL Client Applications Blacklist of Sensor {sensor_id}:',
                                      outputs,
                                      removeNull=True,
                                      headers=['application_name', 'ja3_hash', 'comment'],
                                      headerTransform=to_table_header,
                                      metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.SSLClientBlacklist',
                          outputs_key_field='ja3_hash',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def add_ssl_client_blacklist_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Adds a new entry to the SSL client application blacklist from the Industrial Threat Library of the specified Sensor.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    application_name = args['application_name']
    ja3_hash = args['ja3_hash']
    comment = args.get('comment', '')

    client.add_ssl_client_blacklist_request(sensor_id=sensor_id,  # type: ignore[arg-type]
                                            application_name=application_name,
                                            ja3_hash=ja3_hash,
                                            comment=comment)

    outputs = {
        'application_name': application_name,
        'ja3_hash': ja3_hash,
        'comment': comment,
    }
    readable_output = tableToMarkdown(f'New SSL Client Blacklist Entry of Sensor {sensor_id}:',
                                      outputs,
                                      removeNull=True,
                                      headers=['application_name', 'ja3_hash', 'comment'],
                                      headerTransform=to_table_header)

    return CommandResults(readable_output=readable_output)


def get_file_operation_blacklist_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves the file operation blacklist from the Industrial Threat Library of the specified Sensor.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    page, offset, limit = get_pagination_arguments(args)

    response = client.get_file_operation_blacklist_request(sensor_id=sensor_id,  # type: ignore[arg-type]
                                                           offset=offset,
                                                           limit=limit)

    outputs = deepcopy(response['results'])  # type: ignore[call-overload]
    for entry in outputs:
        entry['sensor_id'] = sensor_id

    readable_output = tableToMarkdown(
        f'File Operation Blacklist of Sensor {sensor_id}:',
        outputs,
        removeNull=True,
        headers=['matching_type', 'file_or_folder', 'operation', 'comment'],
        headerTransform=to_table_header,
        metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.FileOperationBlacklist',
                          outputs_key_field='file_or_folder',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def add_file_operation_blacklist_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Adds entries to the file operation blacklist from the Industrial Threat Library of the specified Sensor.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    sensor_id = arg_to_number(args['sensor_id'])
    matching_type = args['matching_type']
    file_or_folder = args['file_or_folder']
    operation = args['operation']
    comment = args.get('comment', '')

    client.add_file_operation_blacklist_request(sensor_id=sensor_id,  # type: ignore[arg-type]
                                                matching_type=matching_type,
                                                file_or_folder=file_or_folder,
                                                operation=operation,
                                                comment=comment)

    outputs = {
        'matching_type': matching_type,
        'file_or_folder': file_or_folder,
        'operation': operation,
        'comment': comment
    }
    readable_output = tableToMarkdown(
        f'New File Operation Blacklist Entry of Sensor {sensor_id}:',
        outputs,
        removeNull=True,
        headers=['matching_type', 'file_or_folder', 'operation', 'comment'],
        headerTransform=to_table_header)

    return CommandResults(readable_output=readable_output)


def get_diagnostics_information_command(client: Client, *_) -> CommandResults:
    """
    Retrieves information about all monitored Command Center resources and their health status excluding the logs.

    Args:
        client (client): The ForescoutEyeInspect client.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    response = client.get_diagnostics_information_request()
    readable_output = tableToMarkdown(
        'Command Center Diagnostics Information:',
        response,
        removeNull=True,
        headers=['ip_address', 'hostname', 'open_ports', 'cc_version'],
        headerTransform=to_table_header)

    return CommandResults(outputs_prefix='ForescoutEyeInspect.CCInfo',
                          outputs_key_field='ip_address',
                          outputs=response,
                          readable_output=readable_output,
                          raw_response=response)


def get_diagnostic_logs_command(client: Client, args: dict[str, str]) -> dict[str, Any]:
    """
    Download the ZIP file which contains diagnostic logs of the Command Center.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        Dict[str, Any]: Command results with raw response, outputs and readable outputs.
    """

    cc_info = arg_to_boolean(args.get('cc_info'))
    sensor_id = args.get('sensor_id')

    response = client.get_diagnostic_logs_request(cc_info=cc_info, sensor_id=sensor_id)

    return fileResult(filename='command_center_diagnostic_logs.zip',
                      data=response,
                      file_type=EntryType.ENTRY_INFO_FILE)


def list_group_policies_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Get all group policies.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    page, offset, limit = get_pagination_arguments(args)

    response = client.list_group_policies_request(offset=offset, limit=limit)
    outputs = response['results']  # type: ignore[call-overload]

    readable_output = tableToMarkdown('Group Policies List:',
                                      outputs,
                                      removeNull=True,
                                      headers=['id', 'name', 'description'],
                                      headerTransform=to_table_header,
                                      metadata=get_pagination_readable_message(page, limit))

    return CommandResults(
        outputs_prefix='ForescoutEyeInspect.GroupPolicy',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def create_group_policy_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Create a group policy.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    name = args['name']
    description = args['description']
    constraints = argToList(args['constraints'])

    response = client.create_group_policy_request(name=name,
                                                  description=description,
                                                  constraints=constraints)
    readable_output = tableToMarkdown('Group Policy Information:',
                                      response,
                                      removeNull=True,
                                      headers=['id', 'name', 'description'],
                                      headerTransform=to_table_header)

    readable_output += tableToMarkdown('Group Policy Constraints:',
                                       response.get('constraints', []),
                                       removeNull=True,
                                       headers=[
                                           'type', 'operator', 'os_version', 'firmware_version',
                                           'open_ports_tcp', 'open_ports_udp'
                                       ],
                                       headerTransform=to_table_header)

    return CommandResults(outputs_prefix='ForescoutEyeInspect.GroupPolicy',
                          outputs_key_field='id',
                          outputs=response,
                          readable_output=readable_output,
                          raw_response=response)


def update_group_policy_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Update a group policy.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    policy_id = arg_to_number(args['policy_id'])
    name = args['name']
    description = args['description']
    constraints = argToList(args['constraints'])

    response = client.update_group_policy_request(policy_id=policy_id,  # type: ignore[arg-type]
                                                  name=name,
                                                  description=description,
                                                  constraints=constraints)
    readable_output = tableToMarkdown('Updated Group Policy:',
                                      response,
                                      removeNull=True,
                                      headers=['id', 'name', 'description'],
                                      headerTransform=to_table_header)

    readable_output += tableToMarkdown('Group Policy Constraints:',
                                       response.get('constraints', []),
                                       removeNull=True,
                                       headers=[
                                           'type', 'operator', 'os_version', 'firmware_version',
                                           'open_ports_tcp', 'open_ports_udp'
                                       ],
                                       headerTransform=to_table_header)

    return CommandResults(
        outputs_prefix='ForescoutEyeInspect.GroupPolicy',
        outputs_key_field='id',
        outputs=response,
        readable_output=readable_output,
        raw_response=response,
    )


def delete_group_policy_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Delete a group policy.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    policy_id = arg_to_number(args['policy_id'])

    client.delete_group_policy_request(policy_id=policy_id)  # type: ignore[arg-type]
    return CommandResults(
        readable_output=f'## The group policy {policy_id} was successfully deleted!')


def assign_group_policy_hosts_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Add all hosts not assigned to any policy (individual or group) matching the filter to the group policy.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    policy_id = arg_to_number(args['policy_id'])
    filter_type = args['filter_type']
    filter_value = args['filter_value']

    response = client.assign_group_policy_hosts_request(policy_id=policy_id,  # type: ignore[arg-type]
                                                        filter_type=filter_type,
                                                        filter_value=filter_value)
    readable_output = f'## {response["count"]} Additional Hosts Were Assigned to Group Policy {policy_id}!'

    return CommandResults(readable_output=readable_output, raw_response=response)


def unassign_group_policy_hosts_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Unassign all hosts assigned to the group policy matching the filter.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    policy_id = arg_to_number(args['policy_id'])
    filter_type = args['filter_type']
    filter_value = args['filter_value']

    response = client.unassign_group_policy_hosts_request(policy_id=policy_id,  # type: ignore[arg-type]
                                                          filter_type=filter_type,
                                                          filter_value=filter_value)
    readable_output = f'## {response["count"]} Additional Hosts Were Unassigned from Group Policy {policy_id}!'

    return CommandResults(readable_output=readable_output, raw_response=response)


def list_ip_reuse_domains_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Get all IP reuse domains.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    page, offset, limit = get_pagination_arguments(args)

    response = client.list_ip_reuse_domains_request(offset=offset, limit=limit)
    outputs = response['results']  # type: ignore[call-overload]

    readable_output = tableToMarkdown('IP Reuse Domains List:',
                                      outputs,
                                      removeNull=True,
                                      headers=['id', 'name', 'description', 'address'],
                                      headerTransform=to_table_header,
                                      metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.IPReuseDomain',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def list_hosts_changelog_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieves information about the changes of host properties and configuration from the eyeInspect CC database.

    Args:
        client (client): The ForescoutEyeInspect client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    page, offset, limit = get_pagination_arguments(args)
    host_id = arg_to_number(args.get('host_id'))
    start_timestamp = arg_to_datetime_string(args.get('start_timestamp'))
    end_timestamp = arg_to_datetime_string(args.get('end_timestamp'))
    event_type_id = args.get('event_type_id')
    event_category = args.get('event_category')

    response = client.list_hosts_changelog_request(offset=offset,
                                                   limit=limit,
                                                   host_id=host_id,
                                                   start_timestamp=start_timestamp,
                                                   end_timestamp=end_timestamp,
                                                   event_type_id=event_type_id,
                                                   event_category=event_category)
    outputs = response['results']  # type: ignore[call-overload]

    readable_output = tableToMarkdown(
        'Hosts Changes List:',
        outputs,
        removeNull=True,
        headers=['id', 'host_id', 'host_name', 'event_type_name', 'old_value', 'new_value'],
        headerTransform=to_table_header,
        metadata=get_pagination_readable_message(page, limit))

    return CommandResults(outputs_prefix='ForescoutEyeInspect.HostChangeLog',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def test_module(client: Client, should_fetch: bool, first_fetch: str, max_fetch: int) -> str:
    """
    Validates integration parameters and tests connection to Forescout EyeInspect.

    Args:
        client (Client): The Forescout EyeInspect client.
        should_fetch (str): Whether the integration should fetch incidents or not.
        first_fetch (str): The initial time to fetch the alerts as incidents.
        max_fetch (int): The maximum amount of incidents per execution.

    Returns:
        str: ok for success, or anything else for failure.
    """

    if should_fetch:
        validate_fetch_params(max_fetch=max_fetch, first_fetch=first_fetch)

    try:
        client.list_hosts_request(offset=0, limit=1)
    except DemistoException as e:
        if 'Error in API call [401]' in str(e):
            return_error(
                'The provided credentials are invalid. Please check you entered the right username and password.'
            )
        else:
            raise

    return 'ok'


def fetch_alerts(client: Client, last_time: datetime, max_fetch: int,
                 last_incident_id: int) -> List[dict[str, Any]]:
    """
    Fetches alerts with pagination.
    This is essential since the API might return earlier alerts
    than the start timestamp.

    Args:
        client (Client): The Forescout EyeInspect client.
        last_time (datetime): The time of the last fetched incident.
        max_fetch (int): The maximum amount of alerts to fetch.
        last_incident_id (int): The ID of the last fetched incident.

    Returns:
        List[Dict[str, Any]]: The new fetched alerts.
    """

    alerts = []  # type: ignore[var-annotated]

    offset = 0
    while max_fetch > 0:
        results = client.list_alerts_request(offset=offset,  # type: ignore[union-attr,call-overload]
                                             limit=max_fetch,
                                             start_timestamp=last_time.isoformat())['results']
        offset += len(results)

        if not results:
            return alerts

        count = 0
        for result in results:
            if not last_incident_id or result['alert_id'] > last_incident_id:
                count += 1
                alerts.append(result)
        max_fetch -= count

    return alerts


def fetch_incidents(client: Client, first_fetch: str, max_fetch: int) -> None:
    """
    Fetches new alerts as incidents.

    Args:
        client (Client): The ForescoutEyeInspect client.
        first_fetch (str): The time to fetch the incidents for the first execution.
        max_fetch (int): Maximum amount of alert to fetch at one request.
    """

    validate_fetch_params(max_fetch=max_fetch, first_fetch=first_fetch)

    last_run = demisto.getLastRun() or {}
    last_time = arg_to_datetime(last_run.get('time') or first_fetch).astimezone()  # type: ignore[union-attr]
    last_incident_id = last_run.get('incident_id')

    alerts = fetch_alerts(client, last_time, max_fetch, last_incident_id)  # type: ignore[arg-type]
    add_alerts_fields(client, alerts)

    incidents = []
    for alert in alerts:
        incidents.append({
            'name': alert['event_type_names'][0],
            'occurred': alert['timestamp'],
            'rawJSON': json.dumps(alert)
        })

    if alerts:
        last_incident_id = alerts[-1]['alert_id']
        last_time = datetime.fromisoformat(alerts[-1]['timestamp'])

    demisto.setLastRun({'time': last_time.isoformat(), 'incident_id': last_incident_id})
    demisto.incidents(incidents)


def main():
    params = demisto.params()

    server_url = params['server_url']
    username = params['credentials']['identifier']
    password = params['credentials']['password']
    use_ssl = not params.get('insecure', False)
    use_proxy = params.get('proxy', False)

    client = Client(server_url, username, password, use_ssl, use_proxy)

    max_fetch = arg_to_number(params.get('max_fetch', DEFAULT_FETCH_INCIDENTS))
    max_fetch = min(max_fetch, MAX_FETCH_INCIDENTS)  # type: ignore[type-var]
    first_fetch = params.get('first_fetch', DEFAULT_FIRST_FETCH)

    commands = {
        'forescout-ei-host-list': list_hosts_command,
        'forescout-ei-link-list': list_links_command,
        'forescout-ei-vulnerability-info-get': get_vulnerability_info_command,
        'forescout-ei-alert-list': list_alerts_command,
        'forescout-ei-alert-pcap-get': get_alert_pcap_command,
        'forescout-ei-sensor-list': list_sensors_command,
        'forescout-ei-sensor-module-list': list_sensor_modules_command,
        'forescout-ei-sensor-module-update': update_sensor_module_command,
        'forescout-ei-sensor-module-delete': delete_sensor_module_command,
        'forescout-ei-ip-blacklist-get': get_ip_blacklist_command,
        'forescout-ei-ip-blacklist-add': add_ip_blacklist_command,
        'forescout-ei-domain-blacklist-get': get_domain_blacklist_command,
        'forescout-ei-domain-blacklist-add': add_domain_blacklist_command,
        'forescout-ei-ssl-client-blacklist-get': get_ssl_client_blacklist_command,
        'forescout-ei-ssl-client-blacklist-add': add_ssl_client_blacklist_command,
        'forescout-ei-file-operation-blacklist-get': get_file_operation_blacklist_command,
        'forescout-ei-file-operation-blacklist-add': add_file_operation_blacklist_command,
        'forescout-ei-diagnostics-information-get': get_diagnostics_information_command,
        'forescout-ei-diagnostic-logs-get': get_diagnostic_logs_command,
        'forescout-ei-group-policy-list': list_group_policies_command,
        'forescout-ei-group-policy-create': create_group_policy_command,
        'forescout-ei-group-policy-update': update_group_policy_command,
        'forescout-ei-group-policy-delete': delete_group_policy_command,
        'forescout-ei-group-policy-hosts-assign': assign_group_policy_hosts_command,
        'forescout-ei-group-policy-hosts-unassign': unassign_group_policy_hosts_command,
        'forescout-ei-ip-reuse-domain-list': list_ip_reuse_domains_command,
        'forescout-ei-hosts-changelog-list': list_hosts_changelog_command,
    }

    try:
        command = demisto.command()

        if command == 'fetch-incidents':
            fetch_incidents(client, first_fetch, max_fetch)  # type: ignore[arg-type]
        elif command == 'test-module':
            should_fetch = arg_to_boolean(params.get('isFetch'))
            return_results(test_module(client, should_fetch, first_fetch, max_fetch))  # type: ignore[arg-type]
        elif command in commands:
            return_results(commands[command](client, demisto.args()))  # type: ignore[operator]
        else:
            raise NotImplementedError(f'The command {command} does not exist!')
    except Exception as e:
        demisto.error(fix_traceback_line_numbers(traceback.format_exc()))

        if 'Error in API call [401]' in str(e):
            return_error(
                'You are not authorized to use Forescout EyeInspect. Please validate your username and password.'
            )

        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
