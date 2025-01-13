import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests import Response
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
import base64
import re

# Disable insecure warnings
urllib3.disable_warnings()

V10 = "V10x"
V9 = "V9x"
VERSION = demisto.params().get('version', V9)
DEFAULT_LIMIT = 50
HOST = 'HOST'
ADDRESS_RANGE = 'ADDRESS_RANGE'
STATE_TO_NUMBER = {"Disabled": 0, "Enabled": 1}
DEPLOY_ARGUMENT_MAPPER = {"push_ssl_key": "SSLPercentageComplete",
                          "push_gam_updates": "GamUpdatePercentageComplete",
                          "push_configuration_signature_set": "sigsetConfigPercentageComplete",
                          "push_botnet": "botnetPercentageComplete"}

MESSAGE_MAP = {"push_ssl_key": "SSLStatusMessage",
               "push_gam_updates": "GamUpdateStatusMessage",
               "push_configuration_signature_set": "sigsetConfigStatusMessage",
               "push_botnet": "botnetStatusMessage"}

ADDRESS_LIST_MAP = {"IPv6AddressRange": "IPV6RangeList",
                    "IPv4AddressRange": "IPV4RangeList",
                    "HostIPv4": "hostIPv4AddressList",
                    "HostIPv6": "hostIPv6AddressList",
                    "Network_IPV_6": "networkIPV6List",
                    "Network_IPV_4": "networkIPV4List",
                    }
INTERVAL = arg_to_number(demisto.args().get("interval_in_seconds", 30))

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, url: str, auth: tuple, headers: dict, proxy: bool = False, verify: bool = False):
        self.url = url
        self.headers = headers
        super().__init__(base_url=url, verify=verify, proxy=proxy, auth=auth, headers=headers)

    def get_session_request(self, encoded_str: str) -> dict:
        """ Gets a session from the API.
            Args:
                encoded_str: str - The string that contains username:password in base64.
            Returns:
                A dictionary with the session details.
        """
        url_suffix = '/session'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)

    def list_domain_firewall_policy_request(self, domain_id: int) -> dict:
        """ Gets the list of Firewall Policies defined in a particular domain.
            Args:
                domain_id: int - The id of the domain.
            Returns:
                A dictionary with the firewall policy list.
        """
        url_suffix = f'/domain/{domain_id}/firewallpolicy'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_firewall_policy_request(self, policy_id: int) -> dict:
        """ Gets the Firewall Policy details.
            Args:
                policy_id: int - The id of the policy.
            Returns:
                A dictionary with the policy details.
        """
        url_suffix = f'/firewallpolicy/{policy_id}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def create_firewall_policy_request(self, body: dict) -> dict:
        """ Adds a new Firewall Policy and Access Rules.
            Args:
                body: Dict - The params to the API call.
            Returns:
                A dictionary with the id of the newly created policy.
        """
        url_suffix = '/firewallpolicy'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def update_firewall_policy_request(self, body: dict, policy_id: int) -> dict:
        """ Updates an existing Firewall Policy and Access Rules.
            Args:
                body: Dict - The params to the API call.
                policy_id: int - The id of the updated policy.
            Returns:
                A dictionary with the request status, if it succeeded or not.
        """
        url_suffix = f'/firewallpolicy/{policy_id}'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def delete_firewall_policy_request(self, policy_id: int) -> dict:
        """ Updates an existing Firewall Policy and Access Rules.
            Args:
                policy_id: int - The id of the updated policy.
            Returns:
                A dictionary with the request status, if it succeeded or not.
        """
        url_suffix = f'/firewallpolicy/{policy_id}'
        return self._http_request(method='DELETE', url_suffix=url_suffix)

    def list_domain_rule_objects_request(self, domain_id: int, rule_type: str) -> dict:
        """ Gets the list of rule objects defined in a particular domain.
            Args:
                domain_id: int - The id of the domain.
                rule_type: str - The type of the rules to be returned.
            Returns:
                A dictionary with the rule objects list.
        """
        url_suffix = f'/domain/{domain_id}/ruleobject?type={rule_type}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_rule_object_request(self, rule_id: int) -> dict:
        """ Gets the list of rule objects defined in a particular domain.
            Args:
                rule_id: int - The id of the rule.
            Returns:
                A dictionary with the rule object information.
        """
        url_suffix = f'/ruleobject/{rule_id}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def create_rule_object_request(self, body: dict) -> dict:
        """ Gets the list of rule objects defined in a particular domain.
            Args:
                body: Dict - The params to the API call.
            Returns:
                A dictionary with the id of the new rule object.
        """
        url_suffix = '/ruleobject'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def update_rule_object_request(self, body: dict, rule_id: int) -> dict:
        """ Updates a Rule Object.
            Args:
                body: Dict - The params to the API call.
                rule_id: int - The rule id.
            Returns:
                A dictionary with the status of the request.
        """
        url_suffix = f'/ruleobject/{rule_id}'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body, resp_type='response')

    def delete_rule_object_request(self, rule_id: int) -> dict:
        """ Updates a Rule Object.
            Args:
                rule_id: int - The rule id.
            Returns:
                A dictionary with the status of the request.
        """
        url_suffix = f'/ruleobject/{rule_id}'
        return self._http_request(method='DELETE', url_suffix=url_suffix)

    def get_alerts_request(self, time_period: str, start_time: str, end_time: str, state: str,
                           search: str, filter_arg: str, domain_id: int, page: str = None) -> dict:
        """ Retrieves All Alerts.
            Args:
                time_period: str - The time period of the alert.
                start_time: str - The start time of the alert.
                end_time: str - The end time of the alert.
                state: str - The state of the alert.
                search: str - Search string in alert details.
                filter_arg: str - Filter alert by fields.
                page: str - Next/Previous page.
                domain_id: int - The id of the domain
            Returns:
                A dictionary with the list of alerts and info about the list.
        """
        params = {}
        if time_period:
            params['timeperiod'] = time_period
            if time_period == 'CUSTOM':
                params['starttime'] = start_time
                params['endtime'] = end_time
        if state:
            params['alertstate'] = state
        if search:
            params['search'] = search
        if filter_arg:
            params['filter'] = filter_arg
        if page:
            params['page'] = page
        if domain_id:
            params['domainId'] = f'{domain_id}'
        url_suffix = '/alerts'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_alert_details_request(self, alert_id: int, sensor_id: int) -> dict:
        """ Retrieves the alert details.
            Args:
                alert_id: int - The id of the relevant alert.
                sensor_id: int - The id of the relevant sensor.
            Returns:
                A dictionary with the alert details.
        """
        url_suffix = f'/alerts/{alert_id}'
        params = {
            'sensorId': sensor_id
        }
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_attacks_request(self, attack_id: Optional[str]) -> dict:
        """ If an attack id is given The command returns the details of the specific attack. Else, gets all available
        attack definitions in the Manager UI.
            Args:
                attack_id: str - The id of the relevant attack.
            Returns:
                A dictionary with the attack list of the specific attack details.
        """
        if attack_id:
            url_suffix = f'/attack/{attack_id}'
        else:
            url_suffix = '/attacks'
        response = self._http_request(method='GET', timeout=5000, url_suffix=url_suffix)
        return response

    def get_domains_request(self, domain_id: Optional[int]) -> dict:
        """ If a domain id is given The command returns the details of the specific domain.
            Else, gets all available domains.
            Args:
                domain_id: Optional[int] - The id of the relevant attack.
            Returns:
                A dictionary with the attack list of the specific attack details.
        """
        url_suffix = '/domain'
        if domain_id:
            url_suffix = f'{url_suffix}/{domain_id}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_sensors_request(self, domain_id: Optional[int]) -> dict:
        """ If a domain id is given The command returns the details of the sensors in the specific domain.
            Else, gets all available sensors.
            Args:
                domain_id: Optional[int] - The id of the relevant domain.
            Returns:
                A dictionary with the domains list of the specific domain details.
        """
        url_suffix = '/sensors'
        params = {}
        if domain_id:
            params['domain'] = domain_id
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_ips_policies_request(self, domain_id: int) -> dict:
        """ Gets all the IPS Policies defined in the specific domain.
            Args:
                domain_id: int - The id of the relevant domain.
            Returns:
                A dictionary with ips policies list of the specific domain details.
        """
        url_suffix = f'/domain/{domain_id}/ipspolicies'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_ips_policy_details_request(self, policy_id: int) -> dict:
        """ Gets the policy details for the specific IPS policy.
            Args:
                policy_id: int - The id of the relevant ips policy.
            Returns:
                A dictionary with the ips policy details.
        """
        url_suffix = f'/ipspolicy/{policy_id}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def update_alerts_request(self, time_period: str, start_time: str, end_time: str, state: str,
                              search: str, filter_arg: str, body: dict) -> dict:
        """ Updates all relevant alerts.
            Args:
                time_period: str - The time period of the alert.
                start_time: str - The start time of the alert.
                end_time: str - The end time of the alert.
                state: str - The state of the alert.
                search: str - Search string in alert details.
                filter_arg: str - Filter alert by fields.
                body: Dict - The body of the request.
            Returns:
                A dictionary with the request status.
        """
        params = {}
        if time_period:
            params['timeperiod'] = time_period
            if time_period == 'CUSTOM':
                params['starttime'] = start_time
                params['endtime'] = end_time
        if state:
            params['alertstate'] = state
        if search:
            params['search'] = search
        if filter_arg:
            params['filter'] = filter_arg
        url_suffix = '/alerts'
        return self._http_request(method='PUT', url_suffix=url_suffix, params=params, json_data=body)

    def list_pcap_file_request(self, sensor_id: int) -> dict:
        """ Retrieves the list of captured PCAP files.
            Args:
                sensor_id: int - the relevant sensor id.
            Returns:
                A dictionary with a list of PCAP file names.
        """
        url_suffix = f'/sensor/{sensor_id}/packetcapturepcapfiles'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def export_pcap_file_request(self, sensor_id: int, body: dict) -> Response:
        """ Retrieves the list of captured PCAP files.
            Args:
                sensor_id: int - The relevant sensor id.
                body: Dict - The parameter for the http request (file name).
            Returns:
                A dictionary with a list of PCAP file names.
        """
        url_suffix = f'/sensor/{sensor_id}/packetcapturepcapfile/export'
        self.headers['Accept'] = 'application/octet-stream'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body, resp_type='response')

    def list_domain_device_request(self, domain_id: int) -> dict:
        """ Retrieves the list of devices in a domain.
            Args:
                domain_id: int - The relevant domain id.
            Returns:
                A dictionary with a list of devices.
        """
        url_suffix = f'/domain/{domain_id}/device'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def list_device_interface_request(self, domain_id: int, device_id: int) -> dict[str, List]:
        """ Retrieves the list of interfaces related to a device.
            Args:
                device_id: int - The relevant device id.
                domain_id: int - The relevant domain id.
            Returns:
                A dictionary with a list of interfaces.
        """
        url_suffix = f'/domain/{domain_id}/sensor/{device_id}/allocatedinterfaces'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def assign_device_policy_request(self, domain_id: int, device_id: int, pre_firewall_policy: Optional[str],
                                     post_firewall_policy: Optional[str]) -> dict:
        """ Assigns a policy to a device.
            Args:
                device_id: int - The relevant device id.
                domain_id: int - The relevant domain id.
                pre_firewall_policy: Optional[str] - The pre firewall policy.
                post_firewall_policy: Optional[str] - The post firewall policy.
            Returns:
                A success or failure code.
        """
        url_suffix = f'/domain/{domain_id}/policyassignments/device/{device_id}'
        json_data = {"firewallPolicyLast": post_firewall_policy,
                     "firewallPolicyFirst": pre_firewall_policy}
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=json_data)

    def list_device_policy_request(self, domain_id: int, device_id: Optional[int]) -> dict:
        """ Retrieves the list of policies assigned to a device.
            Args:
                device_id: int - The relevant device id.
                domain_id: int - The relevant domain id.
            Returns:
                A dictionary with a list of policies.
        """
        if device_id:
            url_suffix = f'/domain/{domain_id}/policyassignments/device/{device_id}'
        else:
            url_suffix = f'/domain/{domain_id}/policyassignments/device'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def assign_interface_policy_request(self, domain_id: int, interface_id: int, firewall_policy: Optional[str],
                                        firewall_port_policy: Optional[str], ips_policy: Optional[str],
                                        custom_policy_json: Optional[dict]) -> dict:
        """ Assigns a policy to an interface.
            Args:
                domain_id: int - The relevant domain id.
                interface_id: int - The relevant interface id.
                firewall_policy: str - The firewall policy.
                firewall_port_policy: str - The firewall port policy.
                ips_policy: str - The IPS policy.
                custom_policy_json: Dict - A dict of custom policies.
            Returns:
                A success or failure code.

        """
        url_suffix = f'/domain/{domain_id}/policyassignments/interface/{interface_id}'
        json_data = {"firewallPolicy": firewall_policy,
                     "firewallPortPolicy": firewall_port_policy,
                     "ipsPolicy": ips_policy}
        if custom_policy_json:
            json_data |= custom_policy_json

        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=json_data)

    def list_interface_policy_request(self, domain_id: int, interface_id: Optional[int]) -> dict:
        """ Retrieves the list of policies assigned to an interface.
            Args:
                domain_id: int - The relevant domain id.
                interface_id: int - The relevant interface id.
            Returns:
                A dictionary with a list of policies.
        """
        if interface_id:
            url_suffix = f'/domain/{domain_id}/policyassignments/interface/{interface_id}'
        else:
            url_suffix = f'/domain/{domain_id}/policyassignments/interface'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_device_configuration_request(self, device_id: int) -> dict:
        """ Retrieves the configuration of a device.
            Args:
                device_id: int - The relevant device id.
            Returns:
                A dictionary with the device configuration.
        """
        url_suffix = f'/sensor/{device_id}/action/update_sensor_config'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def deploy_device_configuration_request(self, device_id: int, is_SSL_Push_Required: bool = False,
                                            is_GAM_Update_Required: bool = False,
                                            is_Sigset_Config_Push_Required: bool = False,
                                            is_Botnet_Push_Required: bool = False) -> dict:
        """ Deploy a device configuration.
            Args:
                device_id: int - The relevant device id.
                is_SSL_Push_Required: bool - Is SSL push required.
                is_GAM_Update_Required: bool - Is GAM update required.
                is_Sigset_Config_Push_Required: bool - Is signature set configuration push required.
                is_Botnet_Push_Required: bool - Is botnet push required.

            Returns:
                A success or failure code.
        """
        json_data = {"isSSLPushRequired": is_SSL_Push_Required,
                     "isGAMUpdateRequired": is_GAM_Update_Required,
                     "isSigsetConfigPushRequired": is_Sigset_Config_Push_Required,
                     "isBotnetPushRequired": is_Botnet_Push_Required}

        url_suffix = f'/sensor/{device_id}/action/update_sensor_config'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=json_data)

    def check_deploy_device_configuration_request_status(self, device_id, request_id):
        """
        Checks the status of a device configuration deployment.
        Args:
            device_id (int): The relevant device id.
            request_id (int): The relevant request id.

        Returns: A dictionary with the status of deployment for all optional deployment categories.
        """
        url_suffix = f'/sensor/{device_id}/action/update_sensor_config/{request_id}'
        return self._http_request(method='GET', url_suffix=url_suffix)


''' HELPER FUNCTIONS '''


def encode_to_base64(str_to_convert: str) -> str:
    """ Converts a string to base64 string.
    Args:
        str_to_convert: str - The string that needs to be converted to base64.
    Returns:
        The converted string.
    """
    b = base64.b64encode(bytes(str_to_convert, 'utf-8'))  # bytes
    base64_str = b.decode('utf-8')  # convert bytes to string
    return base64_str


def get_session(client: Client, user_name_n_password: str) -> str:
    """ Gets the session string.
    Args:
        client: Client - A McAfeeNSM client.
        user_name_n_password: str - The username and password that needs to be encoded to base64
            in order to get the session information.
    Returns:
        The converted string.
    """
    user_name_n_password_encoded = encode_to_base64(user_name_n_password)
    session = client.get_session_request(user_name_n_password_encoded)
    return encode_to_base64(f'{session.get("session")}:{session.get("userId")}')


def pagination(records_list: List, limit: int, page: Optional[int], page_size: Optional[int]) -> List[dict]:
    """ Returns the wanted records.
    Args:
        records_list: List - The original list of objects.
        limit: str - The amount of records to be returned
        page: Optional[int] - The page of the results (The results in page 1, 2 ...)
        page_size: Optional[int] - the number of records that will be in the page.
    Returns:
        The wanted records.
    """
    if page and page_size:
        num_rec_2_remove = (page_size * (page - 1))
        results_list = records_list[num_rec_2_remove:]
        return results_list[:page_size]
    else:
        return records_list[:limit]


def alerts_list_pagination(records_list: List, limit: int, page: Optional[int], page_size: Optional[int],
                           time_period: str, start_time: str, end_time: str, state: str, search: str, filter_arg: str,
                           client: Client, domain_id: int) -> List:
    """ Returns the wanted records.
    Args:
        records_list: List - The original list of objects.
        limit: int - The amount of records to be returned
        page: Optional[int] - The page of the results (The results in page 1, 2 ...)
        page_size: Optional[int] - The number of records in a page.
        time_period: str - The time period of the alert.
        start_time: str - The start time of the alert.
        end_time: str - The end time of the alert.
        state: str - The state of the alert.
        search: str - Search string in alert details.
        filter_arg: str - Filter alert by fields.
        client: Client - McAfeeNSMv2 client
        domain_id: str - The id of the domain.
    Returns:
        The wanted records.
    """
    if page and page_size:
        offset = (page_size * (page - 1))
        results_list = []
        while (offset + page_size > 1000) and (len(records_list) == 1000):
            records_list = records_list[offset:]
            results_list.extend(records_list)
            page_size = page_size - len(records_list)
            offset = 0 if offset <= 1000 else offset - 1000
            response = client.get_alerts_request(time_period, start_time, end_time, state, search, filter_arg,
                                                 domain_id, 'next')
            records_list = response.get('alertsList', [])

        records_list = records_list[offset:]
        results_list.extend(records_list[:page_size])
        return results_list
    else:
        results_list = []
        while limit > 1000 and (len(records_list) == 1000):
            results_list.extend(records_list)
            limit = limit - len(records_list)
            response = client.get_alerts_request(time_period, start_time, end_time, state, search, filter_arg,
                                                 domain_id, 'next')
            records_list = response.get('alertsList', [])
        results_list.extend(records_list[:limit])
        return results_list


def response_cases(response_str: str) -> str:
    """ Checks the response param and returns the correct response string.
    Args:
        response_str: str - The response string.
    Returns:
        The correct response string.
    Example:
        Scan -> SCAN
        Drop -> DROP
        Deny -> DENY
        Ignore -> IGNORE
        Stateless Ignore -> STATELESS_IGNORE
        Stateless Drop -> STATELESS_DROP
        Require Authentication-> REQUIRE_AUTHENTICATION
    """
    split_str = response_str.upper().split()
    if len(split_str) == 1:
        return split_str[0]
    else:
        return '_'.join(split_str)


def rule_object_type_cases(str_type: str, case: str) -> str:
    """ Checks the rule_object_type params and returns the correct format of them.
    Args:
        str_type: str - The type string.
        case: str - In what case should the letters be, upper or lower case.
    Returns:
        The correct rule_object_type string.
    Examples:
        - In list_domain_rule_objects_command the arguments should be in lower case and in this form:
            Endpoint IP V.4 -> hostipv4
            Range IP V.4 -> ipv4addressrange
            Network IP V.4 -> networkipv4
            Endpoint IP V.6 -> hostipv6
            Range IP V.6 -> ipv6addressrange
            Network IP V.6 -> networkipv6
        - In all the other commands that use this function, the arguments should be in upper case and in this form:
            Endpoint IP V.4 -> HOST_IPV_4
            Range IP V.4 -> IPV_4_ADDRESS_RANGE
            Network IP V.4 -> NETWORK_IPV_4
            Endpoint IP V.6 -> HOST_IPV_6
            Range IP V.6 -> IPV_6_ADDRESS_RANGE
            Network IP V.6 -> NETWORK_IPV_6
    """
    type_split = str_type.upper().replace('.', ' ').split()
    if 'ENDPOINT' in type_split[0]:
        r_type = f'HOST_IPV_{type_split[-1]}'
    elif 'RANGE' in type_split[0]:
        r_type = f'IPV_{type_split[-1]}_ADDRESS_RANGE'
    else:
        r_type = f'NETWORK_IPV_{type_split[-1]}'
    if case == 'low':
        return r_type.lower().replace('_', '')
    return r_type


def reverse_rule_object_type_cases(rule_type: str) -> str:
    """ Checks the rule_object_type params that return from the API call and returns the matching string in the UI.
    Args:
        rule_type: str - The type string.
    Returns:
        The matching string.
    Example:
        HOST_IPV_4 -> Endpoint IP V.4
        IPV_4_ADDRESS_RANGE -> Range IP V.4
        NETWORK_IPV_4 -> Network IP V.4
        HOST_IPV_6 -> Endpoint IP V.6
        IPV_6_ADDRESS_RANGE -> Range IP V.6
        NETWORK_IPV_6 -> Network IP V.6
    """
    number = '4' if ('4' in rule_type) else '6'
    if HOST in rule_type:
        return f'Endpoint IP V.{number}'
    elif ADDRESS_RANGE in rule_type:
        return f'Range IP V.{number}'
    else:
        return f'Network IP V.{number}'


def check_source_and_destination(source_rule_object_id: Optional[int], source_rule_object_type: Optional[str],
                                 destination_rule_object_id: Optional[int], destination_rule_object_type: Optional[str],
                                 create_or_update: str):
    """ Checks the source and destination objects.
    Args:
        source_rule_object_id: Optional[int] - Unique Rule Object ID.
        source_rule_object_type: Optional[str] - Source / Destination Mode.
        destination_rule_object_id: Optional[int] - Unique Rule Object ID.
        destination_rule_object_type: Optional[str] - Source / Destination Mode.
        create_or_update: str - From what function it was called.
    Returns:
        Throws exception .
    """
    if (source_rule_object_id and not source_rule_object_type and source_rule_object_id != -1) or (
            not source_rule_object_id and source_rule_object_type):
        # If the user provides source_rule_object_id he must provide source_rule_object_type and vice versa
        raise Exception('Please provide both source_rule_object_id and source_rule_object_type.')
    if (destination_rule_object_id and not destination_rule_object_type and destination_rule_object_id != -1) or \
            (not destination_rule_object_id and destination_rule_object_type):
        # If the user provides destination_rule_object_id he must provide destination_rule_object_type and vice versa
        raise Exception('Please provide both destination_rule_object_id and destination_rule_object_type.')
    if create_or_update == 'create':    # noqa: SIM102
        # if the user wants to create a new firewall policy, he must provide a source rule or destination rule or both.
        if source_rule_object_id == -1 and destination_rule_object_id == -1:
            raise Exception('You must provide the source fields or destination fields or both.')


def create_body_firewall_policy(domain: int, name: str, visible_to_child: bool, description: str, is_editable: bool,
                                policy_type: str, rule_description: str, response_param: str, rule_enabled: bool,
                                direction: str, source_object: List, destination_object: List) -> dict:
    """
    Args:
        domain: int - The id of the domain.
        name: str - The name of the policy.
        visible_to_child: bool - Will the policy be visible to the child domain.
        description: str - the policy description.
        is_editable: bool - Is the policy editable.
        policy_type: str - The type of the policy.
        rule_description: str - The description of the rule.
        response_param: str - Action to be performed if the traffic matches this rule.
        rule_enabled: bool - Is Rule Enabled or not.
        direction: str - The rule direction.
        source_object: List - Information about the source addresses.
        destination_object: List - Information about the destination addresses.
    Returns:
        Returns the body for the request.
    """
    return {
        'Name': name,
        'DomainId': domain,
        'VisibleToChild': visible_to_child,
        'Description': description,
        'IsEditable': is_editable,
        'PolicyType': policy_type,
        'MemberDetails': {
            'MemberRuleList': [
                {
                    'Description': rule_description,
                    'Enabled': rule_enabled,
                    'Response': response_param,
                    'Direction': direction,
                    'SourceAddressObjectList': source_object,
                    'DestinationAddressObjectList': destination_object,
                    "SourceUserObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Any",
                            "RuleObjectType": "USER"
                        }
                    ],
                    "ServiceObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Any",
                            "RuleObjectType": None,
                            "ApplicationType": None
                        }
                    ],
                    "ApplicationObjectList": [],
                    "TimeObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Always",
                            "RuleObjectType": None
                        }
                    ]
                }
            ]
        }
    }


def create_body_create_rule(rule_type: str, address: List, number: int,
                            from_to_list: list[dict[str, Optional[Any]]]) -> tuple:
    """ create part of the body for the command create_rule_object
        Args:
            rule_type: str - The type of the rule.
            address: List - A list of addresses, if relevant.
            number: int - The number of the IPV.
            from_to_list: List - A list that contains dictionaries with from and to addresses.
        Returns:
            Returns the body for the request.
        """
    if HOST in rule_type:
        return f'HostIPv{number}', {
            f'hostIPv{number}AddressList': address
        }
    elif ADDRESS_RANGE in rule_type:
        return f'IPv{number}AddressRange', {
            f'IPV{number}RangeList': from_to_list
        }
    else:
        return f'Network_IPV_{number}', {
            f'networkIPV{number}List': address
        }


def create_body_create_rule_for_v10(rule_type: str, address: List, number: int,
                                    from_to_list: List[dict[str, Optional[Any]]], state: str = "Enabled") -> tuple:
    """ create part of the body for the command create_rule_object for v10
        Args:
            rule_type: str - The type of the rule.
            address: List - A list of addresses, if relevant.
            number: int - The number of the IPV.
            from_to_list: List - A list that contains dictionaries with from and to addresses.
            state: str - An Enabled or Disabled state.
        Returns:
            Returns the body for the request.
        """
    # build a list of dictionaries with the state and the address
    list_to_send: list[dict] = [
        {"value": single_address, "state": STATE_TO_NUMBER.get(state)}
        for single_address in address]
    # for parameters with a range, we need to add the state to the dictionary
    if from_to_list:
        from_to_list[0].update({"state": STATE_TO_NUMBER.get(state)})

    if HOST in rule_type:
        return f'HostIPv{number}', {
            f'hostIPv{number}AddressList': list_to_send
        }
    elif ADDRESS_RANGE in rule_type:
        return f'IPv{number}AddressRange', {
            f'IPV{number}RangeList': from_to_list
        }
    else:
        return f'Network_IPV_{number}', {
            f'networkIPV{number}List': list_to_send
        }


def create_body_update_rule_for_v10(rule_type: str, address: List, number: int,
                                    from_to_list: List[dict[str, Optional[Any]]], state: str = "Enabled") -> tuple:
    """ create part of the body for the command update_rule_object for v10
        Args:
            rule_type: str - The type of the rule.
            address: List - A list of addresses, if relevant.
            number: int - The number of the IPV.
            from_to_list: List - A list that contains dictionaries with from and to addresses.
            state: str - An Enabled or Disabled state.
        Returns:
            Returns the body for the request.
        """
    # build a list of dictionaries with the state, the address, and changedState for update or delete
    # code explanations:
    # changedState: 1 = add, 3 = delete, depends on the choice of the user to overwrite or not
    # AS you can tell from the 'update_rule_object_command', address is a list of dictionaries or strings.
    # The existing addresses are dictionaries and the upcoming addresses are strings
    # if the address is a dictionary, the user wants to delete and overwrite that's the reason we kept that address in the list.
    list_to_send: list[dict] = []
    for single_address in address:
        if type(single_address) is dict:  # if its a dict == its an existing address to overwrite, we saved from the 'get' call
            list_to_send.append({"value": single_address.get("value"),
                                 "state": STATE_TO_NUMBER.get(state),
                                 "changedState": 3})
        else:       # its a new address the user wants to add
            list_to_send.append({"value": single_address,
                                 "state": STATE_TO_NUMBER.get(state),
                                 "changedState": 1})

    # for parameters with a range, we need to add the state and the changeState to the dictionary
    # Similar logic to above, if "state" is in the dictionary, the user wants to delete and overwrite that's the reason
    # we kept that range in the list.
    if from_to_list:
        for dictionary in from_to_list:
            if "state" in dictionary:  # if the state is in the dictionary, it means the user wants to delete that range.
                dictionary.update({"changedState": 3})
            else:  # if the state is not in the dictionary, it means the user wants to add that range of addresses
                dictionary.update({"state": STATE_TO_NUMBER.get(state), "changedState": 1})

    if HOST in rule_type:
        return f'HostIPv{number}', {
            f'hostIPv{number}AddressList': list_to_send
        }
    elif ADDRESS_RANGE in rule_type:
        return f'IPv{number}AddressRange', {
            f'IPV{number}RangeList': from_to_list
        }
    else:
        return f'Network_IPV_{number}', {
            f'networkIPV{number}List': list_to_send
        }


def modify_v10_results_to_v9_format(response: List[dict[Any, Any]]) -> List[dict[Any, Any]]:
    """
    Modify the response of v10 to be in the same format as in v9.
    The main difference is that in v10 the API returns the addresses in a list of dictionaries,
    A dictionary for each address with extra information, and in v9 all the addresses are in one list.

    This function takes a v10 response and returns a v9 response (to maintain backward compatibility).
    Args:
        response: List[Dict[Any, Any]] - The response of the command of v10.
    Returns:
        A list of dictionaries in the same format as in v9.
    """
    key_list = ['IPv6AddressRange', 'HostIPv6', 'Network_IPV_6', 'Network_IPV_4',
                'HostIPv4', 'IPv4AddressRange']
    for record in response:
        for key, value in record.items():
            if key in key_list and value:   # find the key that its value is the dict contains the addresses
                address_list: list = []
                my_key = key

                # The value of the first (and only) key is a list containing dict with addresses
                addresses = value[ADDRESS_LIST_MAP.get(key)]
                for inner_dict in addresses:
                    temp_dict = {}
                    for key in inner_dict:
                        # choose the relevant keys and values and saves them in a temp dict
                        if key == 'value':
                            address_list.append(inner_dict[key])
                        elif key in ['FromAddress', 'ToAddress']:
                            temp_dict[key] = inner_dict[key]

                    address_list.append(temp_dict) if temp_dict else None

                if address_list:
                    # replace the list of dicts in the original record with a list of strings containing the addresses
                    record[my_key] = {ADDRESS_LIST_MAP.get(my_key): address_list}

    return response


def capitalize_key_first_letter(input_lst: List[dict], check_lst: List = []) -> List[dict]:
    """
        Capitalize the first letter of all keys in all given dictionaries,
        while keeping the rest of the key as it is.(can't use 'capitalize()').
        Args:
            input_lst: List - A list of dictionaries.
            check_lst: List - A list of keys to check if they exist in the dictionary.
        Returns:
            Returns the dict with the first letter of all keys capitalized.
    """
    capitalize_lst = []
    for my_dict in input_lst:
        my_dict = (
            {
                k[:1].upper() + k[1:]: v
                for k, v in my_dict.items()
                if k in check_lst
            }
            if check_lst
            else {k[:1].upper() + k[1:]: v for k, v in my_dict.items()}
        )
        capitalize_lst.append(my_dict) if my_dict else None
    return capitalize_lst


def flatten_and_capitalize(main_dict: dict, inner_dict_key: str, check_lst: List = []) -> dict:
    """
         Flatten a nested dictionary and capitalize the first letter of all the nested dictionary's key
        Args:
            main_dict: Dict - A dictionary with a nested dict.
            inner_dict_key: str - The key of the nested dictionary.
            check_lst: List - A list of keys to check if they exist in the dictionary.
        Returns:
            Returns a flat dict with the first letter of all keys capitalized.
    """
    if inner_dict := main_dict.pop(inner_dict_key, None):
        capitalized_inner = capitalize_key_first_letter(input_lst=[inner_dict], check_lst=check_lst)[0]
        main_dict |= capitalized_inner
    return main_dict


def deploy_polling_message(status: dict, args: dict):
    """
    Builds a message and a fail or success list for the polling command
    Args:
        status: the status of the deployment
        args: the arguments of the deployment command
    Returns:
        fail_or_success_list: a list of 0 or 1, 0 for failure and 1 for success
        message: a message to be printed to the user
    """
    fail_or_success_list = []
    build_a_massage = ""
    for k, v in args.items():
        if v == "true":  # if the value is true that is one of the arguments to deploy and we need to check its status
            current_percentage_status = status.get(DEPLOY_ARGUMENT_MAPPER.get(str(k)))
            current_message_status = status.get(MESSAGE_MAP.get(str(k)))
            if current_percentage_status != 100 or current_message_status != "DOWNLOAD COMPLETE":
                fail_or_success_list.append(0)
                build_a_massage += f"""\nThe current percentage of deployment for '{k}' is: {current_percentage_status}%
                \nAnd the current message is: {current_message_status}\n"""
            else:
                fail_or_success_list.append(1)
    return fail_or_success_list, build_a_massage


def check_required_arg(arg_name: str, arg_value: int | None) -> int:
    """ Check if the required arguments are present in the command.
        Args:
            arg_value: int - The expected value for the argument.
            arg_name: str - The name of the argument.
    """
    if not arg_value and arg_value != 0:
        raise DemistoException(f'Please provide a {arg_name} argument.')
    return arg_value


def check_args_create_rule(rule_type: str, address: List, from_address: str, to_address: str, number: int):
    """ Validate the arguments of the function
        Args:
            rule_type: str - The type of the rule.
            address: List - A list of addresses, if relevant.
            from_address: str - The from address, if relevant.
            to_address: str - The to address, if relevant.
            number: int - The number of the addresses IP V.
    """
    if not address and not from_address and not to_address:
        raise Exception('Please enter a matching address.')
    if ('4' in rule_type and number == 6) or ('6' in rule_type and number == 4):
        raise Exception('The version of the IP in "rule_object_type" should match the addresses version.')
    if (HOST in rule_type or 'NETWORK' in rule_type) and (not address or from_address or to_address):
        raise Exception(f'If the "rule_object_type" is “Endpoint IP V.{number}” or “Network IP V.{number}” than only'
                        f' the argument “address_ip_v.{number}” must contain a value. The other address arguments '
                        f'should be empty.')
    if ADDRESS_RANGE in rule_type and (not to_address or not from_address or address):
        raise Exception(f'If the "rule_object_type" is “Range IP V.{number}” than only the arguments '
                        f'“from_address_ip_v.{number}” and “to_address_ip_v.{number}” must contain a value, the other'
                        f' address arguments should be empty.')


def h_r_get_domains(children: List[dict], contents: List):
    """ Creates the human readable for the command get_domains.
        Args:
            children: List[Dict] - A list of the children.
            contents: List - The human readable object.
        Returns:
            The human readable contains the relevant values.
    """
    for child in children:
        child['ID'] = child.get('id')
        del child['id']
        child['Name'] = child.get('name')
        del child['name']
        d = {
            'ID': child.get('ID'),
            'Name': child.get('Name')
        }
        contents.append(d)
        if child.get('childdomains', []):
            h_r_get_domains(child.get('childdomains', []), contents)


def update_source_destination_object(obj: List[dict], rule_object_id: Optional[int], rule_object_type: Optional[str]) -> \
        List[dict]:
    """ Updates the source and destination objects in the command update_firewall_policy.
        Args:
            obj: List[Dict] - The relevant object.
            rule_object_id: Optional[int] - The id of the rule.
            rule_object_type: Optional[str] - The type of the rule
        Returns:
            The updated object.
    """
    if rule_object_id:
        if rule_object_id == -1:
            raise Exception('If you want to delete an address please provide is_overwrite=true and the relevant '
                            'rule_object_id=-1.')
        new_object = {
            'RuleObjectId': rule_object_id,
            'RuleObjectType': rule_object_type
        }
        old_id = obj[0].get('RuleObjectId')
        # if the old id is -1, it means that there wasn't any specific rule before, and we need to overwrite the
        # "placeholder" rule.
        if old_id == '-1':
            obj = [new_object]
        else:
            obj.append(new_object)
    return obj


def overwrite_source_destination_object(rule_object_id: Optional[int], rule_object_type: Optional[str], dest_or_src: str,
                                        member_rule_list: dict) -> List:
    """ overwrite the source and destination objects in the command update_firewall_policy.
        Args:
            rule_object_id: Optional [int] - The id of the rule.
            rule_object_type: Optional[str] - The type of the rule.
            dest_or_src: str - Overwrite the destination or source object.
            member_rule_list: Dict - The first object in MemberRuleList in the API response.
        Returns:
            The overwrite object.
    """
    if rule_object_id:
        if rule_object_id == -1:
            return [{
                'RuleObjectId': -1,
                'RuleObjectType': None
            }]
        else:
            return [{
                'RuleObjectId': rule_object_id,
                'RuleObjectType': rule_object_type
            }]
    else:
        return member_rule_list.get(f'{dest_or_src}AddressObjectList', [dict])


def update_filter(filter_arg: str) -> str:
    """ Removes the special characters from the name argument in filter, because tha api do not work with special
        characters.
        Args:
            filter_arg: str - The original filter
        Returns:
            The updated filter, without special chars.
        Example:
            - name:HTTP: IIS 6.0 (CVE-0000-0000) -> name:HTTP  IIS 6 0  CVE 0000 0000
    """
    split_filter = filter_arg.split(';')
    for index, s in enumerate(split_filter):
        if 'name' in s:
            s = s.replace('name:', '')
            s = re.sub('[^a-zA-Z0-9]', ' ', s)
            s = f'name:{s}'
            split_filter[index] = s
            break
    return ';'.join(split_filter)


def get_addresses_from_response(response: dict) -> List:
    """ Returns the addresses from the response, for the human-readable in the command get_rule_object.
        Args:
            response: Dict - The response from the API.
        Returns:
            The list of addresses.
    """
    rule_type = response.get('ruleobjType', '')
    number = 4 if '4' in rule_type else 6
    if HOST in rule_type:
        return response.get(f'HostIPv{number}', {}).get(f'hostIPv{number}AddressList', [])
    elif ADDRESS_RANGE in rule_type:
        return response.get(f'IPv{number}AddressRange', {}).get(f'IPV{number}RangeList', [dict])
    else:  # 'NETWORK'
        return response.get(f'Network_IPV_{number}', {}).get(f'networkIPV{number}List', [])


''' COMMAND FUNCTIONS '''


def test_module(client: Client, username_n_password: str) -> str:
    """ Test the connection to McAfee NSM.
    Args:
        client: Client - A McAfeeNSM client.
        username_n_password: str - The string that contains username:password to be encoded.
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    try:
        get_session(client, username_n_password)
        return 'ok'
    except DemistoException as e:
        raise Exception(e.message)


def list_domain_firewall_policy_command(client: Client, args: dict) -> CommandResults:
    """ Gets the list of Firewall Policies defined in a particular domain.
    Args:
        client: client - A McAfeeNSM client.
        args: Dict - The function arguments.
    Returns:
        A CommandResult object with the list of Firewall Policies defined in a particular domain.
    """
    domain_id = int(args.get('domain_id', 0))
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT)) or DEFAULT_LIMIT
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    if (page and not page_size) or (not page and page_size):
        raise Exception('Please provide both page and page_size arguments.')

    response = client.list_domain_firewall_policy_request(domain_id)
    result = sorted(response.get('FirewallPoliciesForDomainResponseList', []), key=lambda k: k['policyId'],
                    reverse=True)
    result = pagination(result, limit, page, page_size)
    contents = []
    for value in result:
        d = {'policyId': value.get('policyId'),
             'policyName': value.get('policyName'),
             'domainId': value.get('domainId'),
             'visibleToChild': value.get('visibleToChild'),
             'description': value.get('description'),
             'isEditable': value.get('isEditable'),
             'policyType': value.get('policyType'),
             'policyVersion': value.get('policyVersion'),
             'lastModUser': value.get('lastModUser')}
        contents.append(d)

    headers = ['policyId', 'policyName', 'domainId', 'visibleToChild', 'description', 'isEditable', 'policyType',
               'policyVersion', 'lastModUser']
    readable_output = tableToMarkdown(
        name='Firewall Policies List',
        t=contents,
        removeNull=True,
        headers=headers
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Policy',
        outputs_key_field='policyId',
        outputs=result,
        raw_response=result
    )


def get_firewall_policy_command(client: Client, args: dict) -> CommandResults:
    """ Gets the Firewall Policy details.
    Args:
        client: client - A McAfeeNSM client.
        args: Dict - The function arguments.
    Returns:
        A CommandResult object with the Firewall Policy details.
    """
    policy_id = int(args.get('policy_id', ''))
    include_rule_objects = argToBoolean(args.get('include_rule_objects', False))
    response = client.get_firewall_policy_request(policy_id)
    if not include_rule_objects:
        member_rule_list = response.get('MemberDetails', {}).get('MemberRuleList', [dict])
        updated_member_rule_list = []
        for member in member_rule_list:
            d = {
                'Description': member.get('Description'),
                'Direction': member.get('Direction'),
                'Enabled': member.get('Enabled'),
                'Response': member.get('Response'),
                'IsLogging': member.get('IsLogging')
            }
            updated_member_rule_list.append(d)
        response.get('MemberDetails', {})['MemberRuleList'] = updated_member_rule_list
    contents = {'FirewallPolicyId': response.get('FirewallPolicyId'),
                'Name': response.get('Name'),
                'Description': response.get('Description'),
                'VisibleToChild': response.get('VisibleToChild'),
                'IsEditable': response.get('IsEditable'),
                'PolicyType': response.get('PolicyType'),
                'PolicyVersion': response.get('PolicyVersion'),
                'LastModifiedUser': response.get('LastModifiedUser'),
                'LastModifiedTime': response.get('LastModifiedTime')}
    headers = ['PolicyId', 'Name', 'Description', 'VisibleToChild', 'IsEditable', 'PolicyType', 'PolicyVersion',
               'LastModifiedUser', 'LastModifiedTime']
    readable_output = tableToMarkdown(
        name=f'Firewall Policy {policy_id}',
        t=contents,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Policy',
        outputs=response,
        raw_response=response,
        outputs_key_field='FirewallPolicyId'
    )


def create_firewall_policy_command(client: Client, args: dict) -> CommandResults:
    """ Adds a new Firewall Policy and Access Rules.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    domain = arg_to_number(args.get('domain', '0'), required=True) or 0
    name = args.get('name', '')
    visible_to_child = argToBoolean(args.get('visible_to_child', True))
    description = args.get('description', '')
    is_editable = argToBoolean(args.get('is_editable', True)) or True
    policy_type = args.get('policy_type', '').upper()
    rule_description = args.get('rule_description', '')
    rule_enabled = argToBoolean(args.get('rule_enabled', True))
    response_param = response_cases(args.get('response', ''))
    direction = args.get('direction', '').upper()
    source_rule_object_id = arg_to_number(args.get('source_rule_object_id', -1))
    source_rule_object_type = args.get('source_rule_object_type', None)
    destination_rule_object_id = arg_to_number(args.get('destination_rule_object_id', -1))
    destination_rule_object_type = args.get('destination_rule_object_type', None)

    check_source_and_destination(source_rule_object_id, source_rule_object_type, destination_rule_object_id,
                                 destination_rule_object_type, 'create')

    source_rule_object_type = rule_object_type_cases(source_rule_object_type, 'up') if source_rule_object_type else None
    destination_rule_object_type = rule_object_type_cases(destination_rule_object_type, 'up') if \
        destination_rule_object_type else None
    source_object = overwrite_source_destination_object(source_rule_object_id, source_rule_object_type, '', {})
    destination_object = overwrite_source_destination_object(destination_rule_object_id, destination_rule_object_type,
                                                             '', {})

    body = create_body_firewall_policy(domain, name, visible_to_child, description, is_editable, policy_type,
                                       rule_description, response_param, rule_enabled, direction, source_object,
                                       destination_object)

    response = client.create_firewall_policy_request(body)
    response = {
        'FirewallPolicyId': response.get('createdResourceId')
    }
    new_firewall_policy_id = response.get('FirewallPolicyId')
    return CommandResults(readable_output=f'The firewall policy no.{new_firewall_policy_id} was created successfully',
                          outputs_prefix='NSM.Policy',
                          outputs=response,
                          raw_response=response,
                          outputs_key_field='FirewallPolicyId'
                          )


def update_firewall_policy_command(client: Client, args: dict) -> CommandResults:
    """ Updates the Firewall Policy details.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    policy_id = int(args.get('policy_id', ''))
    domain = args.get('domain')
    name = args.get('name')
    visible_to_child = args.get('visible_to_child')
    description = args.get('description')
    is_editable = args.get('is_editable')
    policy_type = args.get('policy_type')
    rule_description = args.get('rule_description')
    response_param = args.get('response')
    rule_enabled = args.get('rule_enabled')
    direction = args.get('direction')
    source_rule_object_id = arg_to_number(args.get('source_rule_object_id', None))
    source_rule_object_type = args.get('source_rule_object_type', None)
    source_rule_object_type = rule_object_type_cases(source_rule_object_type, 'up') if source_rule_object_type else None
    destination_rule_object_id = arg_to_number(args.get('destination_rule_object_id', None))
    destination_rule_object_type = args.get('destination_rule_object_type')
    destination_rule_object_type = rule_object_type_cases(destination_rule_object_type, 'up') \
        if destination_rule_object_type else None
    is_overwrite = argToBoolean(args.get('is_overwrite', False))

    if is_overwrite and (not source_rule_object_id and not destination_rule_object_id):
        raise Exception('If is_overwrite=true than at least one of the rules (source or destination) must be provided.')

    check_source_and_destination(source_rule_object_id, source_rule_object_type, destination_rule_object_id,
                                 destination_rule_object_type, 'update')

    policy_get_details = client.get_firewall_policy_request(policy_id)

    if not policy_get_details.get('IsEditable'):
        raise Exception(f"The policy no.{policy_id} can't be edited")

    member_rule_list = policy_get_details.get('MemberDetails', {}).get('MemberRuleList', [dict])[0]
    domain = domain if domain else policy_get_details.get("DomainId")
    name = name if name else policy_get_details.get("Name")
    visible_to_child = policy_get_details.get('VisibleToChild') if not visible_to_child \
        else argToBoolean(visible_to_child)
    description = description if description else policy_get_details.get("Description")
    is_editable = policy_get_details.get('IsEditable') if not is_editable else argToBoolean(is_editable)
    policy_type = policy_get_details.get('PolicyType') if not policy_type else policy_type.upper()
    rule_description = member_rule_list.get('Description') if not rule_description else argToBoolean(rule_description)
    response_param = member_rule_list.get('Response') if not response_param else response_cases(response_param)
    rule_enabled = member_rule_list.get('Enabled') if not rule_enabled else argToBoolean(rule_enabled)
    direction = member_rule_list.get('Direction') if not direction else direction.upper()

    if is_overwrite:
        source_object = overwrite_source_destination_object(source_rule_object_id, source_rule_object_type, 'Source',
                                                            member_rule_list)
        destination_object = overwrite_source_destination_object(destination_rule_object_id,
                                                                 destination_rule_object_type, 'Destination',
                                                                 member_rule_list)
    else:
        source_object = member_rule_list.get('SourceAddressObjectList', [dict])
        source_object = update_source_destination_object(source_object, source_rule_object_id, source_rule_object_type)

        destination_object = member_rule_list.get('DestinationAddressObjectList', [])
        destination_object = update_source_destination_object(destination_object, destination_rule_object_id,
                                                              destination_rule_object_type)

    body = create_body_firewall_policy(
        domain,  # type: ignore[arg-type]
        name,  # type: ignore[arg-type]
        visible_to_child,  # type: ignore[arg-type]
        description,  # type: ignore[arg-type]
        is_editable,  # type: ignore[arg-type]
        policy_type,  # type: ignore[arg-type]
        rule_description,
        response_param,
        rule_enabled,
        direction,
        source_object,
        destination_object
    )

    client.update_firewall_policy_request(body, policy_id)
    return CommandResults(readable_output=f'The firewall policy no.{policy_id} was updated successfully')


def delete_firewall_policy_command(client: Client, args: dict) -> CommandResults:
    """ Deletes the specified Firewall Policy.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    policy_id = int(args.get('policy_id', ''))
    client.delete_firewall_policy_request(policy_id)
    return CommandResults(readable_output=f'The firewall policy no.{policy_id} was deleted successfully')


def list_domain_rule_objects_command(client: Client, args: dict) -> CommandResults:
    """ Gets the list of rule objects defined in a particular domain.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with the list.
    """
    domain_id = arg_to_number(args.get('domain_id'), required=True) or 0
    rule_type = args.get('type', 'All')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT)) or DEFAULT_LIMIT
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))

    if (page and not page_size) or (not page and page_size):
        raise Exception('Please provide both page and page_size arguments.')

    if rule_type == 'All':
        rule_type = 'hostipv4,hostipv6,ipv4addressrange,ipv6addressrange,networkipv4,networkipv6'
    else:
        rule_type = rule_object_type_cases(rule_type, 'low')
    response = client.list_domain_rule_objects_request(domain_id, rule_type)
    results = pagination(response.get('RuleObjDef', []), limit, page, page_size)
    # modify the results in v10 to match the v9 pattern
    if VERSION == V10:
        results = modify_v10_results_to_v9_format(results)

    contents = []
    for record in results:
        record['ruleobjType'] = reverse_rule_object_type_cases(record.get('ruleobjType', None))
        d = {
            'RuleId': record.get('ruleobjId'),
            'Name': record.get('name'),
            'Description': record.get('description'),
            'VisibleToChild': record.get('visibleToChild'),
            'RuleType': record.get('ruleobjType')
        }
        contents.append(d)
    headers = ['RuleId', 'Name', 'Description', 'VisibleToChild', 'RuleType']
    readable_output = tableToMarkdown(name='List of Rule Objects',
                                      t=contents,
                                      removeNull=True,
                                      headers=headers)

    return CommandResults(readable_output=readable_output,
                          outputs_prefix='NSM.Rule',
                          outputs=results,
                          raw_response=results,
                          outputs_key_field='ruleobjId')


def get_rule_object_command(client: Client, args: dict) -> CommandResults:
    """ Gets the details of a Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with information about the rule object.
    """
    rule_id = int(args.get('rule_id', ''))
    response = client.get_rule_object_request(rule_id)
    response = response.get('RuleObjDef', {})
    addresses = get_addresses_from_response(response)
    # modify the results in v10 to match the v9 pattern
    if VERSION == V10:
        response = modify_v10_results_to_v9_format([response])[0]
    addresses = get_addresses_from_response(response)
    response['ruleobjType'] = reverse_rule_object_type_cases(response.get('ruleobjType'))
    contents = {
        'RuleId': response.get('ruleobjId'),
        'Name': response.get('name'),
        'Description': response.get('description'),
        'VisibleToChild': response.get('visibleToChild'),
        'RuleType': response.get('ruleobjType'),
        'Addresses': addresses
    }
    headers = ['RuleId', 'Name', 'Description', 'VisibleToChild', 'RuleType', 'Addresses']
    readable_output = tableToMarkdown(name=f'Rule Objects {rule_id}',
                                      t=contents,
                                      removeNull=True,
                                      headers=headers)
    return CommandResults(readable_output=readable_output,
                          outputs_prefix='NSM.Rule',
                          outputs=response,
                          raw_response=response,
                          outputs_key_field='ruleobjId')


def create_rule_object_command(client: Client, args: dict) -> CommandResults:
    """ Adds a new Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    domain = arg_to_number(args.get('domain', 0))
    rule_type = rule_object_type_cases(args.get('rule_object_type', ''), 'up')
    name = args.get('name')
    visible_to_child = argToBoolean(args.get('visible_to_child', True))
    description = args.get('description')
    address_ip_v_4 = argToList(args.get('address_ip_v.4', None))
    from_address_ip_v_4 = args.get('from_address_ip_v.4')
    to_address_ip_v_4 = args.get('to_address_ip_v.4')
    address_ip_v_6 = argToList(args.get('address_ip_v.6'))
    from_address_ip_v_6 = args.get('from_address_ip_v.6')
    to_address_ip_v_6 = args.get('to_address_ip_v.6')
    state: str = args.get('state', 'Enabled')

    if (address_ip_v_4 and address_ip_v_6) or (from_address_ip_v_4 and from_address_ip_v_6) or \
            (to_address_ip_v_4 and to_address_ip_v_6):
        raise Exception('Those pairs of arguments (address_ip_v_4 and address_ip_v_6) or '
                        '(from_address_ip_v_4 and from_address_ip_v_6) or (to_address_ip_v_4 and to_address_ip_v_6)'
                        'should not have values in parallel, only one at a time.')
    address = address_ip_v_4 if address_ip_v_4 else address_ip_v_6
    number = 4 if (address_ip_v_4 or from_address_ip_v_4) else 6
    from_address = from_address_ip_v_4 if from_address_ip_v_4 else from_address_ip_v_6
    to_address = to_address_ip_v_4 if to_address_ip_v_4 else to_address_ip_v_6

    check_args_create_rule(rule_type, address, from_address, to_address, number)  # type: ignore[arg-type]

    body = {
        'RuleObjDef': {
            "domain": domain,
            "ruleobjType": rule_type,
            "visibleToChild": visible_to_child,
            "description": description,
            "name": name
        }
    }

    from_to_list = [{
        'FromAddress': from_address,
        'ToAddress': to_address
    }]
    # create the body according to the version of the NSM
    if VERSION == V10:
        d_name, extra_body = create_body_create_rule_for_v10(rule_type=rule_type, address=address,
                                                             number=number, from_to_list=from_to_list,
                                                             state=state)
    else:
        d_name, extra_body = create_body_create_rule(rule_type, address, number, from_to_list)

    rule_obj_def = body.get('RuleObjDef', {})
    rule_obj_def[d_name] = extra_body
    response = client.create_rule_object_request(body)
    response = {
        'ruleobjId': response.get('createdResourceId')
    }

    return CommandResults(readable_output=f'The rule object no.{response.get("ruleobjId")} '
                                          f'was created successfully',
                          outputs_prefix='NSM.Rule',
                          outputs=response,
                          raw_response=response,
                          outputs_key_field='ruleobjId'
                          )


def update_rule_object_command(client: Client, args: dict) -> CommandResults:
    """ Updates a Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    domain = arg_to_number(args.get('domain', 0)) or 0
    rule_id = int(args.get('rule_id', ''))
    name = args.get('name')
    visible_to_child = args.get('visible_to_child')
    description = args.get('description')
    address_ip_v_4 = argToList(args.get('address_ip_v.4', None))
    from_address_ip_v_4 = args.get('from_address_ip_v.4')
    to_address_ip_v_4 = args.get('to_address_ip_v.4')
    address_ip_v_6 = argToList(args.get('address_ip_v.6'))
    from_address_ip_v_6 = args.get('from_address_ip_v.6')
    to_address_ip_v_6 = args.get('to_address_ip_v.6')
    is_overwrite = argToBoolean(args.get('is_overwrite', False))
    state: str = args.get('state', 'Enabled')
    response_get = client.get_rule_object_request(rule_id)
    response_get = response_get.get('RuleObjDef', {})

    rule_type = response_get.get('ruleobjType')
    if (rule_type == 'HOST_IPV_4' or rule_type == 'NETWORK_IPV_4') and \
            (from_address_ip_v_4 or to_address_ip_v_4 or address_ip_v_6 or from_address_ip_v_6 or to_address_ip_v_6):
        raise Exception('If the rule object type is Endpoint IP V.4 or Network IP V.4 than only the argument '
                        '"address_ip_v_4" should contain a value')
    elif (rule_type == 'IPV_4_ADDRESS_RANGE') and \
            ((from_address_ip_v_4 and not to_address_ip_v_4) or (not from_address_ip_v_4 and to_address_ip_v_4)):
        raise Exception('If the rule object type is Range IP V.4 than both "from_address_ip_v_4" and '
                        '"to_address_ip_v_4" must contain a value or be empty.')
    elif (rule_type == 'IPV_4_ADDRESS_RANGE') and \
            (address_ip_v_4 or address_ip_v_6 or from_address_ip_v_6 or to_address_ip_v_6):
        raise Exception('If the rule object type is Range IP V.4 than only the arguments "from_address_ip_v_4" and '
                        '"to_address_ip_v_4" should contain a value')
    elif (rule_type == 'HOST_IPV_6' or rule_type == 'NETWORK_IPV_6') and \
            (address_ip_v_4 or from_address_ip_v_4 or to_address_ip_v_4 or from_address_ip_v_6 or to_address_ip_v_6):
        raise Exception('If the rule object type is Endpoint IP V.6 or Network IP V.6 than only the argument '
                        '"address_ip_v_6" should contain a value')
    elif (rule_type == 'IPV_6_ADDRESS_RANGE') and \
            ((from_address_ip_v_6 and not to_address_ip_v_6) or (not from_address_ip_v_6 and to_address_ip_v_6)):
        raise Exception('If the rule object type is Range IP V.6 than both "from_address_ip_v_6" and '
                        '"to_address_ip_v_6" must contain a value or be empty.')
    elif (rule_type == 'IPV_6_ADDRESS_RANGE') and \
            (address_ip_v_4 or address_ip_v_6 or from_address_ip_v_4 or to_address_ip_v_4):
        raise Exception('If the rule object type is Range IP V.6 than only the arguments "from_address_ip_v_6" and '
                        '"to_address_ip_v_6" should contain a value')

    name = name if name else response_get.get('name')
    visible_to_child = argToBoolean(visible_to_child) if visible_to_child else response_get.get('visibleToChild')
    description = description if description else response_get.get('description')
    from_to_address_ip_v_6 = []
    from_to_address_ip_v_4 = []
    # in v9 if the user wants to overwrite the addresses we send only the new values,
    # in v10 we do the same thing if the user dose not want to overwrite the addresses
    if VERSION == V9 and is_overwrite or VERSION == V10 and not is_overwrite:
        if rule_type == 'HOST_IPV_4':
            address_ip_v_4 = address_ip_v_4 if address_ip_v_4 else response_get.get('HostIPv4', {}) \
                .get('hostIPv4AddressList')
        if rule_type == 'NETWORK_IPV_4':
            address_ip_v_4 = address_ip_v_4 if address_ip_v_4 else response_get.get('Network_IPV_4', {}) \
                .get('networkIPV4List')
        if from_address_ip_v_4:
            from_to_address_ip_v_4 = [{
                'FromAddress': from_address_ip_v_4,
                'ToAddress': to_address_ip_v_4
            }]
        elif not from_address_ip_v_4 and rule_type == 'IPV_4_ADDRESS_RANGE':
            from_to_address_ip_v_4 = response_get.get('IPv4AddressRange', {}).get('IPV4RangeList')
        if rule_type == 'HOST_IPV_6':
            address_ip_v_6 = address_ip_v_6 if address_ip_v_6 else response_get.get('HostIPv6', {}) \
                .get('hostIPv6AddressList')
        if rule_type == 'NETWORK_IPV_6':
            address_ip_v_6 = address_ip_v_6 if address_ip_v_6 else response_get.get('Network_IPV_6', {}) \
                .get('networkIPV6List')
        if from_address_ip_v_6:
            from_to_address_ip_v_6 = [{
                'FromAddress': from_address_ip_v_6,
                'ToAddress': to_address_ip_v_6
            }]
        elif not from_address_ip_v_6 and rule_type == 'IPV_6_ADDRESS_RANGE':
            from_to_address_ip_v_6 = response_get.get('IPv6AddressRange', {}).get('IPV6RangeList')
    # in v9 if the user wants to add new addresses we send the old values and the new addresses,
    # in v10 we do the same thing if the user wants to overwrite the addresses
    elif VERSION == V9 and not is_overwrite or VERSION == V10 and is_overwrite:
        if rule_type == 'HOST_IPV_4':
            old_address_ip_v_4 = response_get.get('HostIPv4', {}).get('hostIPv4AddressList', [])
            if address_ip_v_4:
                old_address_ip_v_4.extend(address_ip_v_4)
            address_ip_v_4 = old_address_ip_v_4
        elif rule_type == 'NETWORK_IPV_4':
            old_address_ip_v_4 = response_get.get('Network_IPV_4', {}).get('networkIPV4List', [])
            if address_ip_v_4:
                old_address_ip_v_4.extend(address_ip_v_4)
            address_ip_v_4 = old_address_ip_v_4
        elif rule_type == 'IPV_4_ADDRESS_RANGE':
            from_to_address_ip_v_4 = response_get.get('IPv4AddressRange', {}).get('IPV4RangeList', [])
            if from_address_ip_v_4 and to_address_ip_v_4:
                from_to_address_ip_v_4.append({
                    'FromAddress': from_address_ip_v_4,
                    'ToAddress': to_address_ip_v_4
                })
        elif rule_type == 'HOST_IPV_6':
            old_address_ip_v_6 = response_get.get('HostIPv6', {}).get('hostIPv6AddressList', [])
            if address_ip_v_6:
                old_address_ip_v_6.extend(address_ip_v_6)
            address_ip_v_6 = old_address_ip_v_6
        elif rule_type == 'NETWORK_IPV_6':
            old_address_ip_v_6 = response_get.get('Network_IPV_6', {}).get('hostIPv6AddressList', [])
            if address_ip_v_6:
                old_address_ip_v_6.extend(address_ip_v_6)
            address_ip_v_6 = old_address_ip_v_6
        elif rule_type == 'IPV_6_ADDRESS_RANGE':
            from_to_address_ip_v_6 = response_get.get('IPv6AddressRange', {}).get('networkIPV6List', [])
            if from_address_ip_v_6 and to_address_ip_v_6:
                from_to_address_ip_v_6.append({
                    'FromAddress': from_address_ip_v_6,
                    'ToAddress': to_address_ip_v_6
                })

    body = {
        'RuleObjDef': {
            "domain": domain,
            "ruleobjType": rule_type,
            "visibleToChild": visible_to_child,
            "description": description,
            "name": name
        }
    }
    address = address_ip_v_4 if address_ip_v_4 else address_ip_v_6
    number = 4 if (address_ip_v_4 or from_to_address_ip_v_4) else 6
    from_to_list = from_to_address_ip_v_4 if from_to_address_ip_v_4 else from_to_address_ip_v_6
    # create the body according to the version of the NSM
    if VERSION == V10:
        d_name, extra_body = create_body_update_rule_for_v10(rule_type=rule_type, address=address,
                                                             number=number, from_to_list=from_to_list,
                                                             state=state)

    else:
        d_name, extra_body = create_body_create_rule(rule_type, address, number, from_to_list)

    rule_obj_def = body.get('RuleObjDef', {})
    rule_obj_def[d_name] = extra_body
    client.update_rule_object_request(body, rule_id)
    return CommandResults(readable_output=f'The rule object no.{rule_id} was updated successfully.')


def delete_rule_object_command(client: Client, args: dict) -> CommandResults:
    """ Deletes a Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    rule_id = int(args.get('rule_id', ''))
    client.delete_rule_object_request(rule_id)
    return CommandResults(readable_output=f'The rule object no.{rule_id} was deleted successfully')


def get_alerts_command(client: Client, args: dict) -> CommandResults:
    """ Retrieves All Alerts.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a list of alerts.
    """
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT)) or DEFAULT_LIMIT
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    time_period = args.get('time_period', 'LAST_7_DAYS')
    start_time = args.get('start_time', None)
    end_time = args.get('end_time', None)
    state = args.get('state', None)
    search = args.get('search', None)
    filter_arg = args.get('filter', None)
    domain_id = arg_to_number(args.get('domain_id')) or 0
    if args.get('new_state'):
        state = args.get('new_state')

    if (page and not page_size) or (not page and page_size):
        raise Exception('Please provide both page and page_size arguments.')
    if (start_time and not end_time) or (not start_time and end_time):
        raise Exception('If you provide one of the time parameters, you must provide the other as well.')
    if start_time and time_period != 'CUSTOM':
        time_period = 'CUSTOM'
    if time_period == 'CUSTOM' and not start_time:
        raise Exception('If you enter "time_period=CUSTOM" please enter start_time and end_time as well.')

    if filter_arg and 'name' in filter_arg:
        filter_arg = update_filter(filter_arg)

    response = client.get_alerts_request(time_period, start_time, end_time, state, search, filter_arg, domain_id)
    total_alerts_count = response.get('totalAlertsCount', 0)
    alerts_list = alerts_list_pagination(response.get('alertsList', []), limit, page, page_size, time_period,
                                         start_time, end_time, state, search, filter_arg, client, domain_id)
    result_list = []
    for alert in alerts_list:
        record = {
            'ID': alert.get('event', {}).get('alertId'),
            'Name': alert.get('name'),
            'State': alert.get('alertState'),
            'CreatedTime': alert.get('event', {}).get('time'),
            'Assignee': alert.get('assignTo'),
            'AttackSeverity': alert.get('attackSeverity'),
            'Application': alert.get('application'),
            'EventResult': alert.get('event', {}).get('result'),
            'SensorID': alert.get('detection', {}).get('deviceId'),
            'uniqueAlertId': alert.get('uniqueAlertId'),
            'Event': alert.get('event'),
            'Attack': alert.get('attack'),
            'Attacker': alert.get('attacker'),
            'Target': alert.get('target'),
            'MalwareFile': alert.get('malwareFile'),
            'endpointExcutable': alert.get('endpointExcutable'),
            'detection': alert.get('detection'),
            'layer7Data': alert.get('layer7Data')
        }
        event_obj = record.get('Event', {})
        event_obj['domain'] = alert.get('detection', {}).get('domain')
        event_obj['interface'] = alert.get('detection', {}).get('interface')
        event_obj['device'] = alert.get('detection', {}).get('device')
        result_list.append(record)
    alerts_list = result_list
    contents = []
    for alert_info in alerts_list:
        d = {'ID': alert_info.get('ID'),
             'Name': alert_info.get('Name'),
             'Event Time': alert_info.get('CreatedTime'),
             'Severity': alert_info.get('AttackSeverity'),
             'State': alert_info.get('State'),
             'Direction': alert_info.get('Event', {}).get('direction'),
             'Result': alert_info.get('Event.result'),
             'Attack Count': alert_info.get('EventResult'),
             'Attacker IP': alert_info.get('Attacker', {}).get('ipAddrs'),
             'Target IP': alert_info.get('Target', {}).get('ipAddrs')}
        contents.append(d)

    headers = ['ID', 'Name', 'Event Time', 'Severity', 'State', 'Direction', 'Result', 'Attack Count', 'Attacker IP',
               'Target IP']
    if args.get('new_state'):
        title = f'Updated Alerts list. Showing {len(alerts_list)} of {total_alerts_count}'
    else:
        title = f'Alerts list. Showing {len(alerts_list)} of {total_alerts_count}'
    readable_output = tableToMarkdown(
        name=title,
        t=contents,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Alerts',
        outputs=alerts_list,
        raw_response=response,
        outputs_key_field='ID'
    )


def get_alert_details_command(client: Client, args: dict) -> CommandResults:
    """ Retrieves the relevant alert.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with the alert details.
    """
    alert_id = int(args.get('alert_id', ''))
    sensor_id = int(args.get('sensor_id', ''))
    response = client.get_alert_details_request(alert_id, sensor_id)
    response = {
        'ID': response.get('summary', {}).get('event', {}).get('alertId'),
        'Name': response.get('name'),
        'State': response.get('alertState'),
        'CreatedTime': response.get('summary', {}).get('event', {}).get('time'),
        'Assignee': response.get('assignTo'),
        'Description': response.get('description', {}).get('definition'),
        'EventResult': response.get('summary', {}).get('event', {}).get('result'),
        'Attack': {
            'attackCategory': response.get('description', {}).get('attackCategory'),
            'attackSubCategory': response.get('description', {}).get('attackSubCategory'),
            'nspId': response.get('description', {}).get('reference', {}).get('nspId')
        },
        'Protocols': response.get('description', {}).get('protocols'),
        'SensorID': response.get('summary', {}).get('event', {}).get('deviceId'),
        'Event': response.get('summary', {}).get('event'),
        'Attacker': response.get('summary', {}).get('attacker'),
        'Target': response.get('summary', {}).get('target'),
        'MalwareFile': response.get('details', {}).get('malwareFile'),
        'Details': response.get('details'),
        'uniqueAlertId': response.get('uniqueAlertId'),
        'summary': response.get('summary'),
        'description': response.get('description')
    }
    summary_obj = response.get('summary', {})
    del summary_obj['event']
    del summary_obj['attacker']
    del summary_obj['target']
    contents = {
        'ID': response.get('ID'),
        'Name': response.get('Name'),
        'Event Time': response.get('CreatedTime'),
        'State': response.get('State'),
        'Direction': response.get('Event', {}).get('direction'),
        'Result': response.get('EventResult'),
        'Attack Count': response.get('Event', {}).get('attackCount'),
        'Attacker IP': response.get('Attacker', {}).get('ipAddrs'),
        'Target IP': response.get('Target', {}).get('ipAddrs')
    }
    headers = ['ID', 'Name', 'Event Time', 'State', 'Direction', 'Result', 'Attack Count', 'Attacker IP', 'Target IP']
    readable_output = tableToMarkdown(
        name=f'Alert no.{alert_id}',
        t=contents,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Alerts',
        outputs=response,
        raw_response=response,
        outputs_key_field='uniqueAlertId'
    )


def get_attacks_command(client: Client, args: dict) -> List:
    """ If an attack id is given The command returns the details for the specific attack.
        Else, gets all available attack definitions in the Manager UI.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The attack details or attacks list.
    """
    attack_id = args.get('attack_id')
    if attack_id and not re.match('^0x[0-9A-Fa-f]{8}$', attack_id):
        raise Exception('Error! Attack ID must be formatted as 32-bit hexadecimal number. for example: 0x1234BEEF')

    response = client.get_attacks_request(attack_id)

    if not attack_id:
        title = 'Attacks List'
        attacks_list = response.get('AttackDescriptorDetailsList', [])
    else:
        title = f'Attack no.{attack_id}'
        attacks_list = [response.get('AttackDescriptor', {})]
    result_list = []
    for attack in attacks_list:
        record = {
            'ID': attack.get('attackId'),
            'Name': attack.get('name'),
            'Direction': attack.get('DosDirection'),
            'Category': attack.get('description', {}).get('attackCategory'),
            'Severity': attack.get('Severity'),
            'description': attack.get('description')
        }
        result_list.append(record)
    attacks_list = result_list
    contents = []
    for attack in attacks_list:
        d = {
            'ID': attack.get('ID'),
            'Name': attack.get('Name'),
            'Direction': attack.get('Direction'),
            'Severity': attack.get('Severity'),
            'Category': attack.get('Category')
        }
        contents.append(d)
    headers = ['ID', 'Name', 'Direction', 'Severity', 'Category']
    readable_outputs = tableToMarkdown(
        name=title,
        t=contents,
        removeNull=True,
        headers=headers
    )
    if not attack_id:
        file_ = fileResult(filename='get-attacks-file-result', data=readable_outputs,
                           file_type=entryTypes['entryInfoFile'])
        return [file_]
    else:
        return [CommandResults(
            readable_output=readable_outputs,
            outputs_prefix='NSM.Attacks',
            outputs=attacks_list,
            raw_response=attacks_list,
            outputs_key_field='ID'
        )]


def get_domains_command(client: Client, args: dict) -> CommandResults:
    """ If a domain id is given The command returns the details for the specific domain.
        Else, gets all available domains.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The domain details or domains list.
    """
    domain_id = arg_to_number(args.get('domain_id', None))
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT)) or DEFAULT_LIMIT
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    if (page and not page_size) or (not page and page_size):
        raise Exception('Please provide both page and page_size arguments.')

    response = client.get_domains_request(domain_id)
    results = response.get('DomainDescriptor', {})
    contents = []
    if domain_id is not None:
        title = f'Domain no.{domain_id}'
        results = {
            'ID': results.get('id'),
            'Name': results.get('name'),
            'childdomains': results.get('childdomains')
        }
        contents = [{
            'ID': results.get('ID'),
            'Name': results.get('Name')
        }]
    else:
        title = 'List of Domains'
        children = [results]
        h_r_get_domains(children, contents)
    contents = pagination(contents, limit, page, page_size)
    readable_outputs = tableToMarkdown(
        name=title,
        t=contents,
        removeNull=True
    )
    return CommandResults(
        readable_output=readable_outputs,
        outputs_prefix='NSM.Domains',
        outputs=results,
        raw_response=results,
        outputs_key_field='ID'
    )


def get_sensors_command(client: Client, args: dict) -> CommandResults:
    """ Gets the list of sensors available in the specified domain. If the domain is not specified, details of all
        the sensors in all domains will be provided.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The relevant sensors.
    """
    domain_id = arg_to_number(args.get('domain_id'))
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT)) or DEFAULT_LIMIT
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    if (page and not page_size) or (not page and page_size):
        raise Exception('Please provide both page and page_size arguments.')

    response = client.get_sensors_request(domain_id)
    sensors_list = pagination(response.get('SensorDescriptor', [dict]), limit, page, page_size)
    result_list = []
    for sensor in sensors_list:
        record = {
            'ID': sensor.get('sensorId'),
            'Name': sensor.get('name'),
            'Description': sensor.get('Description'),
            'DomainID': sensor.get('DomainID'),
            'IPSPolicyID': sensor.get('IPSPolicyID'),
            'IP Address': sensor.get('sensorIPAddress'),
            'model': sensor.get('model'),
            'isFailOver': sensor.get('isFailOver'),
            'isNTBA': sensor.get('isNTBA'),
            'isLoadBalancer': sensor.get('isLoadBalancer'),
            'SerialNumber': sensor.get('SerialNumber'),
            'SigsetVersion': sensor.get('SigsetVersion'),
            'DATVersion': sensor.get('DATVersion'),
            'SoftwareVersion': sensor.get('SoftwareVersion'),
            'LastSignatureUpdateTs': sensor.get('LastSignatureUpdateTs'),
            'ReconPolicyID': sensor.get('ReconPolicyID'),
            'LastModTs': sensor.get('LastModTs'),
            'nsmVersion': sensor.get('nsmVersion'),
            'MemberSensors': sensor.get('MemberSensors')
        }
        result_list.append(record)
    sensors_list = result_list
    contents = []
    for sensor in sensors_list:
        d = {
            'ID': sensor.get('ID'),
            'Name': sensor.get('Name'),
            'Description': sensor.get('Description'),
            'DomainID': sensor.get('DomainID'),
            'IPSPolicyID': sensor.get('IPSPolicyID'),
            'IP Address': sensor.get('IP Address')
        }
        contents.append(d)
    headers = ['ID', 'Name', 'Description', 'DomainID', 'IPSPolicyID', 'IP Address']
    if domain_id:
        title = f'The Sensors of Domain no.{domain_id}'
    else:
        title = 'Sensors List'
    readable_output = tableToMarkdown(
        name=title,
        t=contents,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Sensors',
        outputs=sensors_list,
        raw_response=sensors_list,
        outputs_key_field='ID'
    )


def get_ips_policies_command(client: Client, args: dict) -> CommandResults:
    """ Gets all the IPS Policies defined in the specific domain.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The relevant ips policies.
    """
    domain_id = arg_to_number(args.get('domain_id')) or 0
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT)) or DEFAULT_LIMIT
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    if (page and not page_size) or (not page and page_size):
        raise Exception('Please provide both page and page_size arguments.')

    response = client.get_ips_policies_request(domain_id)
    policies_list = pagination(response.get('PolicyDescriptorDetailsList', [dict]), limit, page, page_size)
    result_list = []
    for policy in policies_list:
        record = {
            'ID': policy.get('policyId'),
            'Name': policy.get('name'),
            'DomainID': policy.get('DomainId'),
            'VisibleToChildren': policy.get('VisibleToChild'),
            'IsEditable': policy.get('IsEditable'),
        }
        result_list.append(record)
    policies_list = result_list
    contents = []
    for policy in policies_list:
        d = {
            'ID': policy.get('ID'),
            'Name': policy.get('Name'),
            'DomainID': policy.get('DomainID'),
            'IsEditable': policy.get('IsEditable'),
            'VisibleToChildren': policy.get('VisibleToChildren')
        }
        contents.append(d)
    headers = ['ID', 'Name', 'DomainID', 'IsEditable', 'VisibleToChildren']
    readable_output = tableToMarkdown(
        name=f'IPS Policies List of Domain no.{domain_id}',
        t=contents,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.IPSPolicies',
        outputs=policies_list,
        raw_response=policies_list,
        outputs_key_field='ID'
    )


def get_ips_policy_details_command(client: Client, args: dict) -> CommandResults:
    """ gets the policy details for the specific IPS policy.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The relevant ips policy details.
    """
    policy_id = int(args.get('policy_id', ''))
    response = client.get_ips_policy_details_request(policy_id)
    policy_details = response.get('PolicyDescriptor', {})
    policy_details = {
        'ID': policy_id,
        'Name': policy_details.get('PolicyName'),
        'CreatedTime': policy_details.get('Timestamp'),
        'VisibleToChildren': policy_details.get('IsVisibleToChildren'),
        'Version': policy_details.get('VersionNum'),
        'ExploitAttacks': policy_details.get('AttackCategory', {}).get('ExpolitAttackList'),
        'Description': policy_details.get('Description'),
        'InboundRuleSet': policy_details.get('InboundRuleSet'),
        'OutboundRuleSet': policy_details.get('OutboundRuleSet'),
        'OutboundAttackCategory': policy_details.get('OutboundAttackCategory'),
        'DosPolicy': policy_details.get('DosPolicy'),
        'DosResponseSensitivityLevel': policy_details.get('DosResponseSensitivityLevel'),
        'IsEditable': policy_details.get('IsEditable'),
        'IsLightWeightPolicy': policy_details.get('IsLightWeightPolicy')
    }
    contents = {
        'ID': policy_details.get('ID'),
        'Name': policy_details.get('Name'),
        'Description': policy_details.get('Description'),
        'CreatedTime': policy_details.get('CreatedTime'),
        'IsEditable': policy_details.get('IsEditable'),
        'VisibleToChildren': policy_details.get('VisibleToChildren'),
        'Version': policy_details.get('Version'),
        'InboundRuleSet': policy_details.get('InboundRuleSet'),
        'OutboundRuleSet': policy_details.get('OutboundRuleSet'),
    }
    headers = ['ID', 'Name', 'Description', 'CreatedTime', 'IsEditable', 'VisibleToChildren',
               'Version', 'InboundRuleSet', 'OutboundRuleSet']
    readable_output = tableToMarkdown(
        name=f'IPS Policy no.{policy_id} Details',
        t=contents,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.IPSPolicies',
        outputs=policy_details,
        raw_response=policy_details,
        outputs_key_field='ID'
    )


def update_alerts_command(client: Client, args: dict) -> CommandResults:
    """ Updates all the relevant alerts.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with the list of the changed alerts.
    """
    state = args.get('state', 'Any')
    time_period = args.get('time_period', None)
    start_time = args.get('start_time', None)
    end_time = args.get('end_time', None)
    new_state = args.get('new_state', None)
    new_assignee = args.get('new_assignee', None)
    search = args.get('search', None)
    filter_arg = args.get('filter', None)

    if not new_state and not new_assignee:
        raise Exception('Error! You must specify a new alert state or a new assignee')
    if (start_time and not end_time) or (not start_time and end_time):
        raise Exception('If you provide one of the time parameters, you must provide the other as well')
    if start_time and time_period != 'CUSTOM':
        time_period = 'CUSTOM'

    if filter_arg and 'name' in filter_arg:
        filter_arg = update_filter(filter_arg)

    body = {
        'alertState': new_state,
        'assignTo': new_assignee
    }

    response = client.update_alerts_request(time_period, start_time, end_time, state, search, filter_arg, body)

    if response.get('status') != 1:
        raise Exception('Error! Failed to update alerts.')
    return get_alerts_command(client, args)


def list_pcap_file_command(client: Client, args: dict) -> CommandResults:
    """ Retrieves the list of captured PCAP files.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a list of captured PCAP files.
    """
    sensor_id = int(args.get('sensor_id', ''))
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT)) or DEFAULT_LIMIT
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    if (page and not page_size) or (not page and page_size):
        raise Exception('Please provide both page and page_size arguments.')

    response = client.list_pcap_file_request(sensor_id)
    files_list = pagination(response.get('files', []), limit, page, page_size)
    contents = []
    for file_name in files_list:
        d = {
            'FileName': file_name
        }
        contents.append(d)
    readable_output = tableToMarkdown(
        name='PCAP files List',
        t=contents,
        removeNull=True
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.PcapFile',
        outputs=files_list,
        raw_response=files_list
    )


def export_pcap_file_command(client: Client, args: dict) -> List:
    """ Exports the captured PCAP file.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a list of captured PCAP files.
    """
    sensor_id = int(args.get('sensor_id', ''))
    file_name = args.get('file_name')
    body = {
        'fileName': file_name
    }
    response = client.export_pcap_file_request(sensor_id, body)
    file_ = fileResult(filename=file_name, data=response.content, file_type=EntryType.ENTRY_INFO_FILE)
    return [file_]


def list_domain_device_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves the list of devices related to a given domain.
    Args:
        client(Client): client - A McAfeeNSM client.
        args(Dict): - The function arguments.
    Returns:
        A CommandResult object with a list of domain devices.
    """
    domain_id = arg_to_number(args.get('domain_id'), arg_name='domain_id', required=True)
    domain_id = check_required_arg(arg_name="domain_id", arg_value=domain_id)
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', False))

    response = client.list_domain_device_request(domain_id)
    devices: List = response.get('DeviceResponseList', [])

    capitalize_devices = capitalize_key_first_letter(devices) if all_results else capitalize_key_first_letter(devices)[:limit]

    readable_output = tableToMarkdown(
        name='Domain devices List', t=capitalize_devices, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Device',
        outputs=capitalize_devices,
        raw_response=response,
    )


def list_device_interface_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves the list of interfaces related to a given device.
    Args:
        client(Client): client - A McAfeeNSM client.
        args(Dict): - The function arguments.
    Returns:
        A CommandResult object with a list of device interfaces.
    """
    device_id = arg_to_number(args.get('device_id'), arg_name='device_id', required=True)
    device_id = check_required_arg(arg_name="device_id", arg_value=device_id)
    domain_id = arg_to_number(args.get('domain_id'), arg_name='domain_id', required=True)
    domain_id = check_required_arg(arg_name="domain_id", arg_value=domain_id)
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', False))

    response = client.list_device_interface_request(domain_id=domain_id, device_id=device_id)
    interfaces = (response.get('allocatedInterfaceList', []))

    key_list = ['interfaceId', 'interfaceName', 'interfaceType']
    capitalize_interfaces = capitalize_key_first_letter(interfaces, key_list) if all_results else \
        capitalize_key_first_letter(interfaces, key_list)[:limit]

    readable_output = tableToMarkdown(
        name='Device interfaces List', t=capitalize_interfaces, removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Interface',
        outputs=capitalize_interfaces,
        raw_response=response
    )


def assign_device_policy_command(client: Client, args: dict) -> CommandResults:
    """
    Assigns a policy to a device.
    Args:
        client(Client): client - A McAfeeNSM client.
        args(Dict): - The function arguments.
    Returns:
        A CommandResult object with a success or failure message.
    """
    device_id = arg_to_number(args.get('device_id'), arg_name='device_id', required=True)
    device_id = check_required_arg(arg_name="device_id", arg_value=device_id)
    domain_id = arg_to_number(args.get('domain_id'), arg_name='domain_id', required=True)
    domain_id = check_required_arg(arg_name="domain_id", arg_value=domain_id)
    pre_firewall_policy = args.get('pre_firewall_policy_name')
    post_firewall_policy = args.get('post_firewall_policy_name')

    response = client.assign_device_policy_request(domain_id=domain_id, device_id=device_id,
                                                   pre_firewall_policy=pre_firewall_policy,
                                                   post_firewall_policy=post_firewall_policy
                                                   )
    readable_output = 'Policy assigned successfully.' if response.get('status') == 1 else 'Policy assignment failed.'
    return CommandResults(
        readable_output=readable_output,
        raw_response=response)


def list_device_policy_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of policies related to the domain or a specific device.
    Args:
        client(Client): client - A McAfeeNSM client.
        args(Dict): - The function arguments.

    Returns:
         A CommandResult object with a list of device policies.
    """
    device_id = arg_to_number(args.get('device_id'))
    domain_id = arg_to_number(args.get('domain_id'), arg_name='domain_id', required=True)
    domain_id = check_required_arg(arg_name="domain_id", arg_value=domain_id)
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', False))

    response = client.list_device_policy_request(domain_id=domain_id, device_id=device_id)
    all_policies = response.get('policyAssignmentsList', [])

    capitalize_policies = capitalize_key_first_letter(all_policies) if all_results else \
        capitalize_key_first_letter(all_policies)[:limit]

    readable_output = tableToMarkdown(
        name='Device policy List', t=capitalize_policies, removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.DevicePolicy',
        outputs=capitalize_policies,
        raw_response=response
    )


def assign_interface_policy_command(client: Client, args: dict) -> CommandResults:
    """
    Assigns an existing policy to an interface.
    Args:
        client(Client): - A McAfeeNSM client.
        args(Dict): - The function arguments.
    Returns:
        A CommandResult object with a success or failure message.
    """
    domain_id = arg_to_number(args.get('domain_id'), arg_name='domain_id', required=True)
    domain_id = check_required_arg(arg_name="domain_id", arg_value=domain_id)
    interface_id = arg_to_number(args.get('interface_id'), arg_name='interface_id', required=True)
    interface_id = check_required_arg(arg_name="interface_id", arg_value=interface_id)
    firewall_policy = args.get('firewall_policy_name')
    firewall_port_policy = args.get('firewall_port_policy_name')
    ips_policy = args.get('ips_policy_name')
    custom_policy_json: str = args.get('custom_policy_json') or ""
    custom_policy_json = json.loads(custom_policy_json) if custom_policy_json else {}

    # Check if at least one policy was provided
    if not firewall_policy and not firewall_port_policy and not ips_policy and not custom_policy_json:
        raise DemistoException("Please provide at least one policy to assign.")

    response = client.assign_interface_policy_request(domain_id=domain_id,
                                                      interface_id=interface_id,
                                                      firewall_policy=firewall_policy,
                                                      firewall_port_policy=firewall_port_policy,
                                                      ips_policy=ips_policy,
                                                      custom_policy_json=custom_policy_json
                                                      )
    readable_output = 'Policy assigned successfully.' if response.get('status') == 1 else 'Policy assignment failed.'
    return CommandResults(
        readable_output=readable_output,
        raw_response=response
    )


def list_interface_policy_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of policies related to the domain or a specific interface.
    Args:
        client (Client):  - A McAfeeNSM client.
        args (Dict): - The function arguments.

    Returns:
        A CommandResult object with a list of policies.
    """
    domain_id = arg_to_number(args.get('domain_id'), arg_name='domain_id', required=True)
    domain_id = check_required_arg(arg_name="domain_id", arg_value=domain_id)
    interface_id = arg_to_number(args.get('interface_id'))
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', False))

    response = client.list_interface_policy_request(domain_id=domain_id, interface_id=interface_id)
    all_policies: list = [response] if interface_id else response.get('policyAssignmentsList') or []

    capitalize_policies = capitalize_key_first_letter(all_policies) if all_results else \
        capitalize_key_first_letter(all_policies)[:limit]
    return CommandResults(
        readable_output=tableToMarkdown(
            name='Interface policy List', t=capitalize_policies, removeNull=True
        ),
        outputs_prefix='NSM.InterfacePolicy',
        outputs=capitalize_policies,
        raw_response=response
    )


def get_device_configuration_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves the configuration of a device(e.g pending changes).
    Args:
        client (Client):  - A McAfeeNSM client.
        args (Dict): - The function arguments.

    Returns:
        A CommandResult object with the device configuration information.
    """
    device_id = arg_to_number(args.get('device_id'), arg_name='device_id', required=True)
    device_id = check_required_arg(arg_name="device_id", arg_value=device_id)

    response = client.get_device_configuration_request(device_id=device_id)
    capitalize_response = capitalize_key_first_letter([response])[0]
    flattened_response = flatten_and_capitalize(main_dict=capitalize_response,
                                                inner_dict_key='PendingChanges')

    readable_output = tableToMarkdown(
        name='Device Configuration', t=flattened_response, removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.DeviceConfiguration',
        outputs=flattened_response,
        raw_response=response
    )


@polling_function(name='nsm-deploy-device-configuration', interval=INTERVAL, requires_polling_arg=False)
def deploy_device_configuration_command(args: dict, client: Client) -> PollResult:
    """
    Deploy the configuration of a device.(e.g activate pending changes).
    Args:
        args (Dict): - The function arguments.
        client (Client): - A McAfeeNSM client.

    Returns:
        A PollResult object with a success or failure message.
    """

    request_id = arg_to_number(args.get('request_id'))
    device_id = arg_to_number(args.get('device_id'), arg_name='device_id', required=True)
    device_id = check_required_arg(arg_name="device_id", arg_value=device_id)

    if not request_id:   # if this is the first time the function is called
        is_ssl_push_required = argToBoolean(args.get('push_ssl_key', False))
        is_gam_update_required = argToBoolean(args.get('push_gam_updates', False))
        is_sigset_config_push_required = argToBoolean(args.get('push_configuration_signature_set', False))
        is_botnet_push_required = argToBoolean(args.get('push_botnet', False))

        if not any([is_ssl_push_required, is_gam_update_required, is_sigset_config_push_required, is_botnet_push_required]):
            raise DemistoException("Please provide at least one argument to deploy.")

        if requests_id := client.deploy_device_configuration_request(
            device_id=device_id,
            is_SSL_Push_Required=is_ssl_push_required,
            is_GAM_Update_Required=is_gam_update_required,
            is_Sigset_Config_Push_Required=is_sigset_config_push_required,
            is_Botnet_Push_Required=is_botnet_push_required,
        ).get('RequestId'):
            args["request_id"] = requests_id

        else:
            raise DemistoException("Failed to deploy the device configuration.")

    status = client.check_deploy_device_configuration_request_status(device_id=device_id,
                                                                     request_id=request_id)

    fail_or_success_list, message_to_return = deploy_polling_message(args=args, status=status)
    message = CommandResults(
        readable_output=f"{message_to_return}\n\nChecking again in {INTERVAL} seconds...")

    if not all(fail_or_success_list):  # if one of the arguments was not fully deployed yet, the polling will continue
        return PollResult(
            partial_result=message,
            response=None,
            continue_to_poll=True,
            args_for_next_run={"request_id": request_id,
                               "device_id": device_id,
                               **args})

    message = CommandResults(
        readable_output='The device configuration has been deployed successfully.')
    return PollResult(
        response=message,
        continue_to_poll=False)


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover

    args = demisto.args()
    command = demisto.command()
    params = demisto.params()

    url = f"{params.get('url')}/sdkapi"
    user_name = params.get('credentials', {}).get('identifier', "")
    password = params.get('credentials', {}).get('password', "")
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    auth = (user_name, password)

    demisto.debug(f'Command being called is {command}')
    try:

        headers: dict = {
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }

        client = Client(url=url, auth=auth, headers=headers, proxy=proxy, verify=verify_certificate)
        if command != 'test-module':
            session_str = get_session(client, f'{user_name}:{password}')
            headers['NSM-SDK-API'] = session_str
            client = Client(url=url, auth=auth, headers=headers, proxy=proxy, verify=verify_certificate)
        results: Union[CommandResults, list[CommandResults], str]
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            results = test_module(client, f'{user_name}:{password}')
            # return_results(str_results)
        elif command == 'nsm-list-domain-firewall-policy':
            results = list_domain_firewall_policy_command(client, args)
        elif command == 'nsm-get-firewall-policy':
            results = get_firewall_policy_command(client, args)
        elif command == 'nsm-create-firewall-policy':
            results = create_firewall_policy_command(client, args)
        elif command == 'nsm-update-firewall-policy':
            results = update_firewall_policy_command(client, args)
        elif command == 'nsm-delete-firewall-policy':
            results = delete_firewall_policy_command(client, args)
        elif command == 'nsm-list-domain-rule-object':
            results = list_domain_rule_objects_command(client, args)
        elif command == 'nsm-get-rule-object':
            results = get_rule_object_command(client, args)
        elif command == 'nsm-create-rule-object':
            results = create_rule_object_command(client, args)
        elif command == 'nsm-update-rule-object':
            results = update_rule_object_command(client, args)
        elif command == 'nsm-delete-rule-object':
            results = delete_rule_object_command(client, args)
        elif command == 'nsm-get-alerts':
            results = get_alerts_command(client, args)
        elif command == 'nsm-get-alert-details':
            results = get_alert_details_command(client, args)
        elif command == 'nsm-get-attacks':
            results = get_attacks_command(client, args)
        elif command == 'nsm-get-domains':
            results = get_domains_command(client, args)
        elif command == 'nsm-get-sensors':
            results = get_sensors_command(client, args)
        elif command == 'nsm-get-ips-policies':
            results = get_ips_policies_command(client, args)
        elif command == 'nsm-get-ips-policy-details':
            results = get_ips_policy_details_command(client, args)
        elif command == 'nsm-update-alerts':
            results = update_alerts_command(client, args)
        elif command == 'nsm-list-pcap-file':
            results = list_pcap_file_command(client, args)
        elif command == 'nsm-export-pcap-file':
            results = export_pcap_file_command(client, args)
        elif command == 'nsm-list-device-interface':
            results = list_device_interface_command(client, args)
        elif command == 'nsm-list-domain-device':
            results = list_domain_device_command(client, args)
        elif command == 'nsm-assign-device-policy':
            results = assign_device_policy_command(client, args)
        elif command == 'nsm-list-device-policy':
            results = list_device_policy_command(client, args)
        elif command == 'nsm-assign-interface-policy':
            results = assign_interface_policy_command(client, args)
        elif command == 'nsm-list-interface-policy':
            results = list_interface_policy_command(client, args)
        elif command == 'nsm-get-device-configuration':
            results = get_device_configuration_command(client, args)
        elif command == 'nsm-deploy-device-configuration':
            results = deploy_device_configuration_command(args, client)
        else:
            raise NotImplementedError('This command is not implemented yet.')
        return_results(results)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
