from requests import Response
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any
import base64
import re

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, url: str, auth: tuple, headers: Dict, proxy: bool = False, verify: bool = True):
        self.url = url
        self.headers = headers
        super().__init__(base_url=url, verify=verify, proxy=proxy, auth=auth, headers=headers)

    def get_session_request(self, encoded_str: str) -> Dict:
        """ Gets a session from the API.
            Args:
                encoded_str: str - The string that contains username:password in base64.
            Returns:
                A dictionary with the session details.
        """
        url_suffix = '/session'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)

    def list_domain_firewall_policy_request(self, domain_id: Optional[int]) -> Dict:
        """ Gets the list of Firewall Policies defined in a particular domain.
            Args:
                domain_id: Optional[int] - The id of the domain.
            Returns:
                A dictionary with the firewall policy list.
        """
        url_suffix = f'/domain/{domain_id}/firewallpolicy'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_firewall_policy_request(self, policy_id: Optional[int]) -> Dict:
        """ Gets the Firewall Policy details.
            Args:
                policy_id: Optional[int] - The id of the policy.
            Returns:
                A dictionary with the policy details.
        """
        url_suffix = f'/firewallpolicy/{policy_id}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def create_firewall_policy_request(self, body: Dict) -> Dict:
        """ Adds a new Firewall Policy and Access Rules.
            Args:
                body: Dict - The params to the API call.
            Returns:
                A dictionary with the id of the newly created policy.
        """
        url_suffix = '/firewallpolicy'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def update_firewall_policy_request(self, body: Dict, policy_id: Optional[int]) -> Dict:
        """ Updates an existing Firewall Policy and Access Rules.
            Args:
                body: Dict - The params to the API call.
                policy_id: Optional[int] - The id of the updated policy.
            Returns:
                A dictionary with the request status, if it succeeded or not.
        """
        url_suffix = f'/firewallpolicy/{policy_id}'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def delete_firewall_policy_request(self, policy_id: Optional[int]) -> Dict:
        """ Updates an existing Firewall Policy and Access Rules.
            Args:
                policy_id: Optional[int] - The id of the updated policy.
            Returns:
                A dictionary with the request status, if it succeeded or not.
        """
        url_suffix = f'/firewallpolicy/{policy_id}'
        return self._http_request(method='DELETE', url_suffix=url_suffix)

    def list_domain_rule_objects_request(self, domain_id: int, rule_type: str) -> Dict:
        """ Gets the list of rule objects defined in a particular domain.
            Args:
                domain_id: int - The id of the domain.
                rule_type: str - The type of the rules to be returned.
            Returns:
                A dictionary with the rule objects list.
        """
        url_suffix = f'/domain/{domain_id}/ruleobject?type={rule_type}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_rule_object_request(self, rule_id: Optional[int]) -> Dict:
        """ Gets the list of rule objects defined in a particular domain.
            Args:
                rule_id: Optional[int] - The id of the rule.
            Returns:
                A dictionary with the rule object information.
        """
        url_suffix = f'/ruleobject/{rule_id}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def create_rule_object_request(self, body: Dict) -> Dict:
        """ Gets the list of rule objects defined in a particular domain.
            Args:
                body: Dict - The params to the API call.
            Returns:
                A dictionary with the id of the new rule object.
        """
        url_suffix = '/ruleobject'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def update_rule_object_request(self, body: Dict, rule_id: Optional[int]) -> Dict:
        """ Updates a Rule Object.
            Args:
                body: Dict - The params to the API call.
                rule_id: Optional[int] - The rule id.
            Returns:
                A dictionary with the status of the request.
        """
        url_suffix = f'/ruleobject/{rule_id}'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body, resp_type='response')

    def delete_rule_object_request(self, rule_id: Optional[int]) -> Dict:
        """ Updates a Rule Object.
            Args:
                rule_id: Optional[int] - The rule id.
            Returns:
                A dictionary with the status of the request.
        """
        url_suffix = f'/ruleobject/{rule_id}'
        return self._http_request(method='DELETE', url_suffix=url_suffix)

    def get_alerts_request(self, time_period: str, start_time: str, end_time: str, state: str,
                           search: str, filter_arg: str, domain_id: int, page: str = None) -> Dict:
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

    def get_alert_details_request(self, alert_id: Optional[int], sensor_id: Optional[int]) -> Dict:
        """ Retrieves the alert details.
            Args:
                alert_id: Optional[int] - The id of the relevant alert.
                sensor_id: Optional[int] - The id of the relevant sensor.
            Returns:
                A dictionary with the alert details.
        """
        url_suffix = f'/alerts/{alert_id}'
        params = {
            'sensorId': sensor_id
        }
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_attacks_request(self, attack_id: str) -> Dict:
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

    def get_domains_request(self, domain_id: Optional[int]) -> Dict:
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

    def get_sensors_request(self, domain_id: Optional[int]) -> Dict:
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

    def get_ips_policies_request(self, domain_id: int) -> Dict:
        """ Gets all the IPS Policies defined in the specific domain.
            Args:
                domain_id: int - The id of the relevant domain.
            Returns:
                A dictionary with ips policies list of the specific domain details.
        """
        url_suffix = f'/domain/{domain_id}/ipspolicies'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_ips_policy_details_request(self, policy_id: Optional[int]) -> Dict:
        """ Gets the policy details for the specific IPS policy.
            Args:
                policy_id: Optional[int] - The id of the relevant ips policy.
            Returns:
                A dictionary with the ips policy details.
        """
        url_suffix = f'/ipspolicy/{policy_id}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def update_alerts_request(self, time_period: str, start_time: str, end_time: str, state: str,
                              search: str, filter_arg: str, body: Dict) -> Dict:
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

    def list_pcap_file_request(self, sensor_id: Optional[int]) -> Dict:
        """ Retrieves the list of captured PCAP files.
            Args:
                sensor_id: Optional[int] - the relevant sensor id.
            Returns:
                A dictionary with a list of PCAP file names.
        """
        url_suffix = f'/sensor/{sensor_id}/packetcapturepcapfiles'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def export_pcap_file_request(self, sensor_id: Optional[int], body: Dict) -> Response:
        """ Retrieves the list of captured PCAP files.
            Args:
                sensor_id: Optional[int] - The relevant sensor id.
                body: Dict - The parameter for the http request (file name).
            Returns:
                A dictionary with a list of PCAP file names.
        """
        url_suffix = f'/sensor/{sensor_id}/packetcapturepcapfile/export'
        self.headers['Accept'] = 'application/octet-stream'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body, resp_type='response')


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


def pagination(records_list: List, limit: int, page: Optional[int], page_size: Optional[int]) -> List[Dict]:
    """ Returns the wanted records.
    Args:
        records_list: List - The original list of objects.
        limit: str - The amount of records to be returned
        page: Optional[int] - The page of the results (The results in page 1, 2 ...)
        page_siOptional[int]ze: int - the number of records that will be in the page.
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
        num_rec_2_remove = (page_size * (page - 1))
        results_list = []
        while (num_rec_2_remove + page_size > 1000) and (len(records_list) == 1000):
            records_list = records_list[num_rec_2_remove:]
            results_list.extend(records_list)
            page_size = page_size - len(records_list)
            num_rec_2_remove = 0 if num_rec_2_remove <= 1000 else num_rec_2_remove - 1000
            response = client.get_alerts_request(time_period, start_time, end_time, state, search, filter_arg,
                                                 domain_id, 'next')
            records_list = response.get('alertsList', [])

        records_list = records_list[num_rec_2_remove:]
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
    """ Checks the rule_object_type params that return from the API call and returns the matching string.
    Args:
        rule_type: str - The type string.
    Returns:
        The matching string.
    """
    number = '4' if ('4' in rule_type) else '6'
    if 'HOST' in rule_type:
        return f'Endpoint IP V.{number}'
    elif 'ADDRESS_RANGE' in rule_type:
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
    if (source_rule_object_id and not source_rule_object_type) or (
            not source_rule_object_id and source_rule_object_type):
        raise Exception('If you provide at least one of the source fields, you must provide all of them.')
    if (destination_rule_object_id and not destination_rule_object_type) or \
            (not destination_rule_object_id and destination_rule_object_type):
        raise Exception('If you provide at least one of the destination fields, you must provide all of them.')
    if create_or_update == 'create':
        if (not source_rule_object_id) and (not destination_rule_object_id):
            raise Exception('You must provide the source fields or destination fields or both.')


def create_body_firewall_policy(domain: int, name: str, visible_to_child: bool, description: str, is_editable: bool,
                                policy_type: str, rule_description: str, response_param: str, rule_enabled: bool,
                                direction: str, source_object: List, destination_object: List) -> Dict:
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
                            from_to_list: list[dict[str, Any | None]]) -> tuple:
    """ create part of the body for the command create_rule_object
        Args:
            rule_type: str - The type of the rule.
            address: List - A list of addresses, if relevant.
            number: int - The number of the IPV.
            from_to_list: List - A list that contains dictionaries with from and do addresses.
        Returns:
            Returns the body for the request.
        """
    if 'HOST' in rule_type:
        return f'HostIPv{number}', {
            f'hostIPv{number}AddressList': address
        }
    elif 'ADDRESS_RANGE' in rule_type:
        return f'IPv{number}AddressRange', {
            f'IPV{number}RangeList': from_to_list
        }
    else:
        return f'Network_IPV_{number}', {
            f'networkIPV{number}List': address
        }


def check_args_create_rule(rule_type: str, address: List, from_address: str, to_address: str, number: int):
    """ Validate the arguments of the function
        Args:
            rule_type: str - The type of the rule.
            address: List - A list of addresses, if relevant.
            from_address: str - The from address, if relevant.
            to_address: str - The to address, if relevant.
            number: int - The number of the addresses IP V.
    """
    if ('4' in rule_type and number == 6) or ('6' in rule_type and number == 4):
        raise Exception('The version of the IP in "rule_object_type" should match the addresses version.')
    if ('HOST' in rule_type or 'NETWORK' in rule_type) and not address:
        raise Exception(
            f'If the "rule_object_type" is “Endpoint IP V.{number}” or “Network IP V.{number}” than the argument '
            f'“address_ip_v.{number}” must contain a value.')
    if ('HOST' in rule_type or 'NETWORK' in rule_type) and (from_address or to_address):
        raise Exception('If the "rule_object_type" is Endpoint or Network than from_address and to_addresses parameters'
                        ' should not contain value.')
    if 'ADDRESS_RANGE' in rule_type and not to_address and not from_address:
        raise Exception(f'If the "rule_object_type" is “Range IP V.{number}” than the arguments '
                        f'“from_address_ip_v.{number}” and “to_address_ip_v.{number}” must contain a value.')
    if 'ADDRESS_RANGE' in rule_type and address:
        raise Exception(f'If the "rule_object_type" is “Range IP V.{number} than the both address_ip_v.4 and '
                        f'address_ip_v.6 should not contain a value')


def add_entries_to_alert_list(alert_list: List[Dict]) -> List[Dict]:
    """ Add entries to the alert_list and update what is needed in order not to break backward.
        Args:
            alert_list: List[Dict] - a list of the alerts that returned from the API.
        Returns:
            Returns the updated alert list.
    """
    for alert in alert_list:
        alert['ID'] = alert.get('event', {}).get('alertId')
        alert['Name'] = alert.get('name')
        alert['Event'] = alert.get('event')
        alert['State'] = alert.get('alertState')
        alert['AttackSeverity'] = alert.get('attackSeverity')
        alert['CreatedTime'] = alert.get('event', {}).get('time')
        alert['Assignee'] = alert.get('assignTo')
        alert['Application'] = alert.get('application')
        alert['EventResult'] = alert.get('event', {}).get('result')
        alert['SensorID'] = alert.get('detection', {}).get('deviceId')
        event_obj = alert.get('Event', {})
        event_obj['domain'] = alert.get('detection', {}).get('domain')
        event_obj['interface'] = alert.get('detection', {}).get('interface')
        event_obj['device'] = alert.get('detection', {}).get('device')
        alert['Attack'] = alert.get('attack')
        alert['Attacker'] = alert.get('attacker')
        alert['Target'] = alert.get('target')
        alert['MalwareFile'] = alert.get('malwareFile')
        del alert['assignTo']
        del alert['application']
        del alert['attack']
        del alert['attacker']
        del alert['target']
        del alert['malwareFile']
        del alert['event']
        del alert['name']
        del alert['attackSeverity']
        del alert['alertState']
    return alert_list


def update_sensors_list(sensors_list: List[Dict]) -> List[Dict]:
    """ Add entries to the sensors_list and update it in order not to break backward.
        Args:
            sensors_list: List[Dict] - a list of the sensors that returned from the API.
        Returns:
            Returns the updated sensors list.
    """
    for sensor in sensors_list:
        sensor['ID'] = sensor.get('sensorId')
        sensor['Name'] = sensor.get('name')
        sensor['IP Address'] = sensor.get('sensorIPAddress')
        del sensor['sensorId']
        del sensor['name']
        del sensor['sensorIPAddress']
    return sensors_list


def update_attacks_list_entries(attacks_list: list[Dict]) -> list[Dict]:
    """ Add entries to the attacks_list and update it in order not to break backward.
        Args:
            attacks_list: List[Dict] - a list of the attacks that returned from the API.
        Returns:
            Returns the updated attack list.
    """
    for attack in attacks_list:
        attack['ID'] = attack.get('attackId')
        attack['Name'] = attack.get('name')
        attack['Direction'] = attack.get('DosDirection')
        attack['Category'] = attack.get('description', {}).get('attackCategory')
        del attack['attackId']
        del attack['name']
        del attack['DosDirection']
    return attacks_list


def update_policies_list_entries(policies_list: list[dict]) -> list[dict]:
    """ Add entries to the policies_list and update it in order not to break backward.
        Args:
            policies_list: List[Dict] - a list of the ips policies that returned from the API.
        Returns:
            Returns the updated ips policies list.
    """
    for policy in policies_list:
        policy['ID'] = policy.get('policyId')
        policy['Name'] = policy.get('name')
        policy['DomainID'] = policy.get('DomainId')
        policy['VisibleToChildren'] = policy.get('VisibleToChild')
        del policy['policyId']
        del policy['name']
        del policy['DomainId']
        del policy['VisibleToChild']
    return policies_list


def update_ips_policy_entries(policy_details: Dict, policy_id: Optional[int]) -> Dict:
    """ update the entries to the policy_details in order not to break backward.
        Args:
            policy_details: Dict - the details of the specific ips policy.
            policy_id: Optional[int] - The id of the current policy.
        Returns:
            Returns the updated ips policies list.
    """
    policy_details['ID'] = policy_id
    policy_details['Name'] = policy_details.get('PolicyName')
    policy_details['CreatedTime'] = policy_details.get('Timestamp')
    policy_details['VisibleToChildren'] = policy_details.get('IsVisibleToChildren')
    policy_details['Version'] = policy_details.get('VersionNum')
    policy_details['ExploitAttacks'] = policy_details.get('AttackCategory', {}).get('ExpolitAttackList')
    del policy_details['PolicyName']
    del policy_details['Timestamp']
    del policy_details['IsVisibleToChildren']
    del policy_details['VersionNum']
    attack_category = policy_details.get('AttackCategory', {})
    del attack_category['ExpolitAttackList']
    return policy_details


def h_r_get_domains(children: List[Dict], human_readable: List):
    """ Creates the human readable for the command get_domains.
        Args:
            children: List[Dict] - A list of the children.
            human_readable: List - The human readable object.
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
        human_readable.append(d)
        if child.get('childdomains', []):
            h_r_get_domains(child.get('childdomains', []), human_readable)


def update_source_destination_object(obj: List[Dict], rule_object_id: int | None, rule_object_type: Optional[str]) -> List[Dict]:
    """ Updates the source and destination objects in the command update_firewall_policy.
        Args:
            obj: List[Dict] - The relevant object.
            rule_object_id: int | None - The id of the rule.
            rule_object_type: Optional[str] - The type of the rule
        Returns:
            The updated object.
    """
    if rule_object_id:
        new_object = {
            'RuleObjectId': rule_object_id,
            'RuleObjectType': rule_object_type
        }
        old_id = obj[0].get('RuleObjectId')
        if old_id == '-1':
            obj = [new_object]
        else:
            obj.append(new_object)
    return obj


def overwrite_source_destination_object(rule_object_id: int | None, rule_object_type: Optional[str], dest_or_src: str,
                                        member_rule_list: Dict) -> List:
    """ overwrite the source and destination objects in the command update_firewall_policy.
        Args:
            rule_object_id: int | None - The id of the rule.
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
                'RuleObjectType': 'Any'
            }]
        else:
            return [{
                'RuleObjectId': rule_object_id,
                'RuleObjectType': rule_object_type
            }]
    else:
        return member_rule_list.get(f'{dest_or_src}AddressObjectList', [Dict])


def update_filter(filter_arg: str) -> str:
    """ Removes the special characters from the name argument filter.
        Args:
            filter_arg: str - The original filter
        Returns:
            The updated filter, without special chars.
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


def update_alert_entries(alert_det: Dict) -> Dict:
    """ Updates the entries to an alert object (the entries that we gwt here are different from get_alerts).
        Args:
            alert_det: Dict - The dictionary with the alert details.
        Returns:
            The updated alert details dictionary.
    """
    alert_det['ID'] = alert_det.get('summary', {}).get('event', {}).get('alertId')
    alert_det['Name'] = alert_det.get('name')
    alert_det['State'] = alert_det.get('alertState')
    alert_det['CreatedTime'] = alert_det.get('summary', {}).get('event', {}).get('time')
    alert_det['Assignee'] = alert_det.get('assignTo')
    alert_det['Description'] = alert_det.get('description', {}).get('definition')
    alert_det['EventResult'] = alert_det.get('summary', {}).get('event', {}).get('result')
    alert_det['Attack'] = {
        'attackCategory': alert_det.get('description', {}).get('attackCategory'),
        'attackSubCategory': alert_det.get('description', {}).get('attackSubCategory'),
        'nspId': alert_det.get('description', {}).get('reference', {}).get('nspId')
    }
    alert_det['Protocols'] = alert_det.get('description', {}).get('protocols')
    alert_det['SensorID'] = alert_det.get('summary', {}).get('event', {}).get('deviceId')
    alert_det['Event'] = alert_det.get('summary', {}).get('event')
    alert_det['Attacker'] = alert_det.get('summary', {}).get('attacker')
    alert_det['Target'] = alert_det.get('summary', {}).get('target')
    alert_det['MalwareFile'] = alert_det.get('details', {}).get('malwareFile')
    alert_det['Details'] = alert_det.get('details')
    details_obj = alert_det.get('details', {})
    summary_obj = alert_det.get('summary', {})
    description_obj = alert_det.get('description', {})
    reference_obj = alert_det.get('description', {}).get('reference', {})
    del details_obj['malwareFile']
    del summary_obj['target']
    del summary_obj['attacker']
    del summary_obj['event']
    del description_obj['protocols']
    del description_obj['attackSubCategory']
    del description_obj['attackCategory']
    del description_obj['definition']
    del alert_det['assignTo']
    del alert_det['alertState']
    del alert_det['name']
    del alert_det['details']
    del reference_obj['nspId']
    return alert_det


def get_addresses_from_response(response: Dict) -> List:
    """ Updates the entries to an alert object (the entries that we gwt here are different from get_alerts).
        Args:
            response: Dict - The response from the API.
        Returns:
            The list of addresses.
    """
    rule_type = response.get('ruleobjType', '')
    if 'HOST_IPV_4' in rule_type:
        return response.get('HostIPv4', {}).get('hostIPv4AddressList', [])
    elif 'IPV_4_ADDRESS_RANGE' in rule_type:
        addresses_list = response.get('IPv4AddressRange', {}).get('IPV4RangeList', [Dict])
        result_list = []
        for address in addresses_list:
            result_list.append(f'{address.get("FromAddress")} - {address.get("ToAddress")}')
        return result_list
    elif 'NETWORK_IPV_4' in rule_type:
        return response.get('Network_IPV_4', {}).get('networkIPV4List', [])
    elif 'HOST_IPV_6' in rule_type:
        return response.get('HostIPv6', {}).get('hostIPv6AddressList', [])
    elif 'IPV_6_ADDRESS_RANGE' in rule_type:
        addresses_list = response.get('IPv6AddressRange', {}).get('IPV6RangeList', [Dict])
        result_list = []
        for address in addresses_list:
            result_list.append(f'{address.get("FromAddress")} - {address.get("ToAddress")}')
        return result_list
    else:  # NETWORK_IPV_6
        return response.get('Network_IPV_6', {}).get('networkIPV6List', [])


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


def list_domain_firewall_policy_command(client: Client, args: Dict) -> CommandResults:
    """ Gets the list of Firewall Policies defined in a particular domain.
    Args:
        client: client - A McAfeeNSM client.
        args: Dict - The function arguments.
    Returns:
        A CommandResult object with the list of Firewall Policies defined in a particular domain.
    """
    domain_id = arg_to_number(args.get('domain_id', None))
    limit = arg_to_number(args.get('limit', 50)) or 50
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    if (page and not page_size) or (not page and page_size):
        raise Exception('If you enter one of the parameters page or page_size, you have to enter both.')

    response = client.list_domain_firewall_policy_request(domain_id)
    result = response.get('FirewallPoliciesForDomainResponseList', [])
    result = pagination(result, limit, page, page_size)
    human_readable = []
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
        human_readable.append(d)

    hr_title = 'Firewall Policies List'
    headers = ['policyId', 'policyName', 'domainId', 'visibleToChild', 'description', 'isEditable', 'policyType',
               'policyVersion', 'lastModUser']
    readable_output = tableToMarkdown(
        name=hr_title,
        t=human_readable,
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


def get_firewall_policy_command(client: Client, args: Dict) -> CommandResults:
    """ Gets the Firewall Policy details.
    Args:
        client: client - A McAfeeNSM client.
        args: Dict - The function arguments.
    Returns:
        A CommandResult object with the Firewall Policy details.
    """
    policy_id = args.get('policy_id', '')
    include_rule_objects = argToBoolean(args.get('include_rule_objects', False))
    response = client.get_firewall_policy_request(policy_id)
    if not include_rule_objects:
        member_rule_list = response.get('MemberDetails', {}).get('MemberRuleList', [Dict])
        for member in member_rule_list:
            del member['SourceAddressObjectList']
            del member['DestinationAddressObjectList']
            del member['SourceUserObjectList']
            del member['ServiceObjectList']
            del member['ApplicationObjectList']
            del member['TimeObjectList']
    human_readable = {'FirewallPolicyId': response.get('FirewallPolicyId'),
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
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Policy',
        outputs=response,
        raw_response=response,
        outputs_key_field='name'
    )


def create_firewall_policy_command(client: Client, args: Dict) -> CommandResults:
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
    is_editable = argToBoolean(args.get('is_editable')) or True
    policy_type = args.get('policy_type', '').upper()
    rule_description = args.get('rule_description', '')
    rule_enabled = argToBoolean(args.get('rule_enabled', True))
    response_param = response_cases(args.get('response', ''))
    direction = args.get('direction', '').upper()
    source_rule_object_id = arg_to_number(args.get('source_rule_object_id', None))
    source_rule_object_type = args.get('source_rule_object_type', None)
    destination_rule_object_id = arg_to_number(args.get('destination_rule_object_id', None))
    destination_rule_object_type = args.get('destination_rule_object_type', None)

    check_source_and_destination(source_rule_object_id, source_rule_object_type, destination_rule_object_id,
                                 destination_rule_object_type, 'create')

    source_rule_object_id = arg_to_number(args.get('source_rule_object_id', -1))
    destination_rule_object_id = arg_to_number(args.get('destination_rule_object_id', -1))
    source_rule_object_type = rule_object_type_cases(source_rule_object_type, 'up') if source_rule_object_type else None
    destination_rule_object_type = rule_object_type_cases(destination_rule_object_type, 'up') if \
        destination_rule_object_type else None
    source_object = [{
        'RuleObjectId': source_rule_object_id,
        'RuleObjectType': source_rule_object_type
    }]
    destination_object = [{
        'RuleObjectId': destination_rule_object_id,
        'RuleObjectType': destination_rule_object_type
    }]

    body = create_body_firewall_policy(domain, name, visible_to_child, description, is_editable, policy_type,
                                       rule_description, response_param, rule_enabled, direction, source_object,
                                       destination_object)

    response = client.create_firewall_policy_request(body)
    new_firewall_policy_id = response.get('createdResourceId')
    return CommandResults(readable_output=f'The firewall policy no.{new_firewall_policy_id} was created successfully')


def update_firewall_policy_command(client: Client, args: Dict) -> CommandResults:
    """ Updates the Firewall Policy details.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    policy_id = arg_to_number(args.get('policy_id'))
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

    member_rule_list = policy_get_details.get('MemberDetails', {}).get('MemberRuleList', [Dict])[0]
    domain = policy_get_details.get('DomainId') if not domain else domain
    name = policy_get_details.get('Name') if not name else name
    visible_to_child = policy_get_details.get('VisibleToChild') if not visible_to_child \
        else argToBoolean(visible_to_child)
    description = policy_get_details.get('Description') if not description else description
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
        source_object = member_rule_list.get('SourceAddressObjectList', [Dict])
        source_object = update_source_destination_object(source_object, source_rule_object_id, source_rule_object_type)

        destination_object = member_rule_list.get('DestinationAddressObjectList', [])
        destination_object = update_source_destination_object(destination_object, destination_rule_object_id,
                                                              destination_rule_object_type)

    body = create_body_firewall_policy(domain, name, visible_to_child, description, is_editable, policy_type,
                                       rule_description, response_param, rule_enabled, direction, source_object,
                                       destination_object)

    client.update_firewall_policy_request(body, policy_id)
    return CommandResults(readable_output=f'The firewall policy no.{policy_id} was updated successfully')


def delete_firewall_policy_command(client: Client, args: Dict) -> CommandResults:
    """ Deletes the specified Firewall Policy.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    policy_id = arg_to_number(args.get('policy_id'))
    client.delete_firewall_policy_request(policy_id)
    return CommandResults(readable_output=f'The firewall policy no.{policy_id} was deleted successfully')


def list_domain_rule_objects_command(client: Client, args: Dict) -> CommandResults:
    """ Gets the list of rule objects defined in a particular domain.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with the list.
    """
    domain_id = arg_to_number(args.get('domain_id'), required=True) or 0
    rule_type = args.get('type', 'All')
    limit = arg_to_number(args.get('limit', 50)) or 50
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    if rule_type == 'All':
        rule_type = 'hostipv4,hostipv6,ipv4addressrange,ipv6addressrange,networkipv4,networkipv6'
    else:
        rule_type = rule_object_type_cases(rule_type, 'low')
    response = client.list_domain_rule_objects_request(domain_id, rule_type)
    results = pagination(response.get('RuleObjDef', []), limit, page, page_size)

    human_readable = []
    for record in results:
        record['ruleobjType'] = reverse_rule_object_type_cases(record.get('ruleobjType', None))
        d = {
            'RuleId': record.get('ruleobjId'),
            'Name': record.get('name'),
            'Description': record.get('description'),
            'VisibleToChild': record.get('visibleToChild'),
            'RuleType': record.get('ruleobjType')
        }
        human_readable.append(d)
    headers = ['RuleId', 'Name', 'Description', 'VisibleToChild', 'RuleType']
    readable_output = tableToMarkdown(name='List of Rule Objects',
                                      t=human_readable,
                                      removeNull=True,
                                      headers=headers)

    return CommandResults(readable_output=readable_output,
                          outputs_prefix='NSM.Rule',
                          outputs=results,
                          raw_response=results,
                          outputs_key_field='ruleobjId')


def get_rule_object_command(client: Client, args: Dict) -> CommandResults:
    """ Gets the details of a Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with information about the rule object.
    """
    rule_id = arg_to_number(args.get('rule_id'))
    response = client.get_rule_object_request(rule_id)
    response = response.get('RuleObjDef', {})
    addresses = get_addresses_from_response(response)
    response['ruleobjType'] = reverse_rule_object_type_cases(response.get('ruleobjType'))
    human_readable = {
        'RuleId': response.get('ruleobjId'),
        'Name': response.get('name'),
        'Description': response.get('description'),
        'VisibleToChild': response.get('visibleToChild'),
        'RuleType': response.get('ruleobjType'),
        'Addresses': addresses
    }
    headers = ['RuleId', 'Name', 'Description', 'VisibleToChild', 'RuleType', 'Addresses']
    readable_output = tableToMarkdown(name=f'Rule Objects {rule_id}',
                                      t=human_readable,
                                      removeNull=True,
                                      headers=headers)
    return CommandResults(readable_output=readable_output,
                          outputs_prefix='NSM.Rule',
                          outputs=response,
                          raw_response=response,
                          outputs_key_field='ruleobjId')


def create_rule_object_command(client: Client, args: Dict) -> CommandResults:
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

    if (address_ip_v_4 and address_ip_v_6) or (from_address_ip_v_4 and from_address_ip_v_6) or \
            (to_address_ip_v_4 and to_address_ip_v_6):
        raise Exception('This pair arguments (address_ip_v_4 and address_ip_v_6) or '
                        '(from_address_ip_v_4 and from_address_ip_v_6) or (to_address_ip_v_4 and to_address_ip_v_6)'
                        'should not have values in parallel, only one at a time.')
    address = address_ip_v_4 if address_ip_v_4 else address_ip_v_6
    number = 4 if (address_ip_v_4 or from_address_ip_v_4) else 6
    from_address = from_address_ip_v_4 if from_address_ip_v_4 else from_address_ip_v_6
    to_address = to_address_ip_v_4 if to_address_ip_v_4 else to_address_ip_v_6

    check_args_create_rule(rule_type, address, from_address, to_address, number)

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

    d_name, extra_body = create_body_create_rule(rule_type, address, number, from_to_list)
    rule_obj_def = body.get('RuleObjDef', {})
    rule_obj_def[d_name] = extra_body
    response = client.create_rule_object_request(body)

    return CommandResults(readable_output=f'The rule object no.{response.get("createdResourceId")} '
                                          f'was created successfully')


def update_rule_object_command(client: Client, args: Dict) -> CommandResults:
    """ Updates a Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    domain = arg_to_number(args.get('domain', 0)) or 0
    rule_id = arg_to_number(args.get('rule_id'))
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
    visible_to_child = argToBoolean(visible_to_child) if visible_to_child else response_get.get('visible_to_child')
    description = description if description else response_get.get('description')
    from_to_address_ip_v_6 = []
    from_to_address_ip_v_4 = []
    if is_overwrite:
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
    else:
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
    d_name, extra_body = create_body_create_rule(rule_type, address, number, from_to_list)
    rule_obj_def = body.get('RuleObjDef', {})
    rule_obj_def[d_name] = extra_body
    client.update_rule_object_request(body, rule_id)
    return CommandResults(readable_output=f'The rule object no.{rule_id} was updated successfully.')


def delete_rule_object_command(client: Client, args: Dict) -> CommandResults:
    """ Deletes a Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a success message.
    """
    rule_id = arg_to_number(args.get('rule_id'))
    client.delete_rule_object_request(rule_id)
    return CommandResults(readable_output=f'The rule object no.{rule_id} was deleted successfully')


def get_alerts_command(client: Client, args: Dict) -> CommandResults:
    """ Retrieves All Alerts.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a list of alerts.
    """
    limit = arg_to_number(args.get('limit', 50)) or 50
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
        raise Exception('If you enter one of the parameters page or page_size, you have to enter both.')
    if (start_time and not end_time) or (not start_time and end_time):
        raise Exception('If you provide one of the time parameters, you must provide the other as well.')
    if (start_time or end_time) and time_period != 'CUSTOM':
        raise Exception('If you provided a start time or end time, you must assign the time_period parameter with the '
                        'value "CUSTOM"')
    if time_period == 'CUSTOM' and not start_time:
        raise Exception('If you enter "time_period=CUSTOM" please enter start_time and end_time as well.')

    if filter_arg and 'name' in filter_arg:
        filter_arg = update_filter(filter_arg)

    response = client.get_alerts_request(time_period, start_time, end_time, state, search, filter_arg, domain_id)
    total_alerts_count = response.get('totalAlertsCount', 0)
    alerts_list = alerts_list_pagination(response.get('alertsList', []), limit, page, page_size, time_period,
                                         start_time, end_time, state, search, filter_arg, client, domain_id)
    alerts_list = add_entries_to_alert_list(alerts_list)
    human_readable = []
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
        human_readable.append(d)

    headers = ['ID', 'Name', 'Event Time', 'Severity', 'State', 'Direction', 'Result', 'Attack Count', 'Attacker IP',
               'Target IP']
    if args.get('new_state'):
        title = f'Updated Alerts list. Showing {len(alerts_list)} of {total_alerts_count}'
    else:
        title = f'Alerts list. Showing {len(alerts_list)} of {total_alerts_count}'
    readable_output = tableToMarkdown(
        name=title,
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.Alerts',
        outputs=alerts_list,
        raw_response=alerts_list,
        outputs_key_field='uniqueAlertId'
    )


def get_alert_details_command(client: Client, args: Dict) -> CommandResults:
    """ Retrieves the relevant alert.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with the alert details.
    """
    alert_id = arg_to_number(args.get('alert_id'))
    sensor_id = arg_to_number(args.get('sensor_id'))
    response = client.get_alert_details_request(alert_id, sensor_id)
    response = update_alert_entries(response)
    human_readable = {
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
        t=human_readable,
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


def get_attacks_command(client: Client, args: Dict) -> List:
    """ If an attack id is given The command returns the details for the specific attack.
        Else, gets all available attack definitions in the Manager UI.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The attack details or attacks list.
    """
    attack_id = args.get('attack_id')
    if attack_id:
        if not re.match('^0x[0-9A-Fa-f]{8}$', attack_id):
            raise Exception('Error! Attack ID must be formatted as 32-bit hexadecimal number. for example: 0x1234BEEF')

    response = client.get_attacks_request(attack_id)

    if not attack_id:
        title = 'Attacks List'
        attacks_list = response.get('AttackDescriptorDetailsList', [])
    else:
        title = f'Attack no.{attack_id}'
        attacks_list = [response.get('AttackDescriptor', {})]
    human_readable = []
    attacks_list = update_attacks_list_entries(attacks_list)
    for attack in attacks_list:
        d = {
            'ID': attack.get('ID'),
            'Name': attack.get('Name'),
            'Direction': attack.get('Direction'),
            'Severity': attack.get('Severity'),
            'Category': attack.get('Category')
        }
        human_readable.append(d)
    headers = ['ID', 'Name', 'Direction', 'Severity', 'Category']
    readable_outputs = tableToMarkdown(
        name=title,
        t=human_readable,
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


def get_domains_command(client: Client, args: Dict) -> CommandResults:
    """ If a domain id is given The command returns the details for the specific domain.
        Else, gets all available domains.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The domain details or domains list.
    """
    domain_id = arg_to_number(args.get('domain_id', None))
    limit = arg_to_number(args.get('limit', 50)) or 50
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    response = client.get_domains_request(domain_id)
    results = response.get('DomainDescriptor', {})
    human_readable = []
    if domain_id is not None:
        title = f'Domain no.{domain_id}'
        results['ID'] = results.get('id')
        del results['id']
        results['Name'] = results.get('name')
        del results['name']
        human_readable = [{
            'ID': results.get('ID'),
            'Name': results.get('Name')
        }]
    else:
        title = 'List of Domains'
        children = [results]
        h_r_get_domains(children, human_readable)
    human_readable = pagination(human_readable, limit, page, page_size)
    readable_outputs = tableToMarkdown(
        name=title,
        t=human_readable,
        removeNull=True
    )
    return CommandResults(
        readable_output=readable_outputs,
        outputs_prefix='NSM.Domains',
        outputs=human_readable,
        raw_response=human_readable,
        outputs_key_field='id'
    )


def get_sensors_command(client: Client, args: Dict) -> CommandResults:
    """ Gets the list of sensors available in the specified domain. If the domain is not specified, details of all
        the sensors in all domains will be provided.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The relevant sensors.
    """
    domain_id = arg_to_number(args.get('domain_id'))
    limit = arg_to_number(args.get('limit', 50)) or 50
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    response = client.get_sensors_request(domain_id)
    sensors_list = pagination(response.get('SensorDescriptor', [Dict]), limit, page, page_size)
    sensors_list = update_sensors_list(sensors_list)
    human_readable = []
    for sensor in sensors_list:
        d = {
            'ID': sensor.get('ID'),
            'Name': sensor.get('Name'),
            'Description': sensor.get('Description'),
            'DomainID': sensor.get('DomainID'),
            'IPSPolicyID': sensor.get('IPSPolicyID'),
            'IP Address': sensor.get('IP Address')
        }
        human_readable.append(d)
    headers = ['ID', 'Name', 'Description', 'DomainID', 'IPSPolicyID', 'IP Address']
    if domain_id:
        title = f'The Sensors of Domain no.{domain_id}'
    else:
        title = 'Sensors List'
    readable_output = tableToMarkdown(
        name=title,
        t=human_readable,
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


def get_ips_policies_command(client: Client, args: Dict) -> CommandResults:
    """ Gets all the IPS Policies defined in the specific domain.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The relevant ips policies.
    """
    domain_id = arg_to_number(args.get('domain_id')) or 0
    limit = arg_to_number(args.get('limit', 50)) or 50
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    response = client.get_ips_policies_request(domain_id)
    policies_list = pagination(response.get('PolicyDescriptorDetailsList', [Dict]), limit, page, page_size)
    policies_list = update_policies_list_entries(policies_list)
    human_readable = []
    for policy in policies_list:
        d = {
            'ID': policy.get('ID'),
            'Name': policy.get('Name'),
            'DomainID': policy.get('DomainID'),
            'IsEditable': policy.get('IsEditable'),
            'VisibleToChildren': policy.get('VisibleToChildren')
        }
        human_readable.append(d)
    headers = ['ID', 'Name', 'DomainID', 'IsEditable', 'VisibleToChildren']
    readable_output = tableToMarkdown(
        name=f'IPS Policies List of Domain no.{domain_id}',
        t=human_readable,
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


def get_ips_policy_details_command(client: Client, args: Dict) -> CommandResults:
    """ gets the policy details for the specific IPS policy.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with The relevant ips policy details.
    """
    policy_id = arg_to_number(args.get('policy_id'))
    response = client.get_ips_policy_details_request(policy_id)
    policy_details = update_ips_policy_entries(response.get('PolicyDescriptor', {}), policy_id)
    human_readable = {
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
        t=human_readable,
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


def update_alerts_command(client: Client, args: Dict) -> CommandResults:
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
    if (start_time or end_time) and time_period != 'CUSTOM':
        raise Exception('If you provided a start time or end time, you must assign the time_period parameter with the '
                        'value "CUSTOM"')

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


def list_pcap_file_command(client: Client, args: Dict) -> CommandResults:
    """ Retrieves the list of captured PCAP files.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a list of captured PCAP files.
    """
    sensor_id = arg_to_number(args.get('sensor_id'))
    limit = arg_to_number(args.get('limit', 50)) or 50
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    response = client.list_pcap_file_request(sensor_id)
    files_list = pagination(response.get('files', []), limit, page, page_size)
    human_readable = []
    for file_name in files_list:
        d = {
            'FileName': file_name
        }
        human_readable.append(d)
    readable_output = tableToMarkdown(
        name='PCAP files List',
        t=human_readable,
        removeNull=True
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='NSM.PcapFile',
        outputs=files_list,
        raw_response=files_list
    )


def export_pcap_file_command(client: Client, args: Dict) -> List:
    """ Exports the captured PCAP file.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with a list of captured PCAP files.
    """
    sensor_id = arg_to_number(args.get('sensor_id'))
    file_name = args.get('file_name')
    body = {
        'fileName': file_name
    }
    response = client.export_pcap_file_request(sensor_id, body)
    file_ = fileResult(filename=file_name, data=response.content, file_type=EntryType.ENTRY_INFO_FILE)
    return [file_]


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    url = f"{demisto.params().get('url')}/sdkapi"
    user_name = demisto.params().get('credentials', {}).get('identifier', "")
    password = demisto.params().get('credentials', {}).get('password', "")
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    auth = (user_name, password)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: Dict = {
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }

        client = Client(url=url, auth=auth, headers=headers, proxy=proxy, verify=verify_certificate)
        if demisto.command() != 'test-module':
            session_str = get_session(client, f'{user_name}:{password}')
            headers['NSM-SDK-API'] = session_str
            client = Client(url=url, auth=auth, headers=headers, proxy=proxy, verify=verify_certificate)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result_str = test_module(client, f'{user_name}:{password}')
            return_results(result_str)
        elif demisto.command() == 'nsm-list-domain-firewall-policy':
            result = list_domain_firewall_policy_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-get-firewall-policy':
            result = get_firewall_policy_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-create-firewall-policy':
            result = create_firewall_policy_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-update-firewall-policy':
            result = update_firewall_policy_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-delete-firewall-policy':
            result = delete_firewall_policy_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-list-domain-rule-object':
            result = list_domain_rule_objects_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-get-rule-object':
            result = get_rule_object_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-create-rule-object':
            result = create_rule_object_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-update-rule-object':
            result = update_rule_object_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-delete-rule-object':
            result = delete_rule_object_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-get-alerts':
            result = get_alerts_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-get-alert-details':
            result = get_alert_details_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-get-attacks':
            results_list = get_attacks_command(client, demisto.args())
            return_results(results_list)
        elif demisto.command() == 'nsm-get-domains':
            result = get_domains_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-get-sensors':
            result = get_sensors_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-get-ips-policies':
            result = get_ips_policies_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-get-ips-policy-details':
            result = get_ips_policy_details_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-update-alerts':
            result = update_alerts_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-list-pcap-file':
            result = list_pcap_file_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'nsm-export-pcap-file':
            results_list = export_pcap_file_command(client, demisto.args())
            return_results(results_list)
        else:
            raise NotImplementedError('This command is not implemented yet.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
