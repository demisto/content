from requests import Response
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any
import base64

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
        url_suffix = '/sdkapi/session'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)

    def list_domain_firewall_policy_request(self, encoded_str: str, domain_id: int) -> Dict:
        """ Gets the list of Firewall Policies defined in a particular domain.
            Args:
                encoded_str: str - The session id.
                domain_id: int - The id of the domain.
            Returns:
                A dictionary with the firewall policy list.
        """
        url_suffix = f'/sdkapi/domain/{domain_id}/firewallpolicy'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_firewall_policy_request(self, encoded_str: str, policy_id: str) -> Dict:
        """ Gets the Firewall Policy details.
            Args:
                encoded_str: str - The session id.
                policy_id: str - The id of the policy.
            Returns:
                A dictionary with the policy details.
        """
        url_suffix = f'/sdkapi/firewallpolicy/{policy_id}'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)

    def create_firewall_policy_request(self, encoded_str: str, body: Dict) -> Dict:
        """ Adds a new Firewall Policy and Access Rules.
            Args:
                encoded_str: str - The session id.
                body: Dict - The params to the API call.
            Returns:
                A dictionary with the id of the newly created policy.
        """
        url_suffix = '/sdkapi/firewallpolicy'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def update_firewall_policy_request(self, encoded_str: str, body: Dict, policy_id: str) -> Dict:
        """ Updates an existing Firewall Policy and Access Rules.
            Args:
                encoded_str: str - The session id.
                body: Dict - The params to the API call.
                policy_id: str - The id of the updated policy.
            Returns:
                A dictionary with the request status, if it succeeded or not.
        """
        url_suffix = f'/sdkapi/firewallpolicy/{policy_id}'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def delete_firewall_policy_request(self, encoded_str: str, policy_id: str) -> Dict:
        """ Updates an existing Firewall Policy and Access Rules.
            Args:
                encoded_str: str - The session id.
                policy_id: str - The id of the updated policy.
            Returns:
                A dictionary with the request status, if it succeeded or not.
        """
        url_suffix = f'/sdkapi/firewallpolicy/{policy_id}'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='DELETE', url_suffix=url_suffix)

    def list_domain_rule_objects_request(self, encoded_str: str, domain_id: int, rule_type: str) -> Dict:
        """ Gets the list of rule objects defined in a particular domain.
            Args:
                encoded_str: str - The session id.
                domain_id: int - The id of the domain.
                rule_type: str - The type of the rules to be returned.
            Returns:
                A dictionary with the rule objects list.
        """
        url_suffix = f'/sdkapi/domain/{domain_id}/ruleobject?type={rule_type}'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)

    def get_rule_object_request(self, session_str: str, rule_id: str) -> Dict:
        """ Gets the list of rule objects defined in a particular domain.
            Args:
                session_str: str - The session id.
                rule_id: int - The id of the rule.
            Returns:
                A dictionary with the rule object information.
        """
        url_suffix = f'/sdkapi/ruleobject/{rule_id}'
        self.headers['NSM-SDK-API'] = session_str
        return self._http_request(method='GET', url_suffix=url_suffix)

    def create_rule_object_request(self, session_str: str, body: Dict) -> Dict:
        """ Gets the list of rule objects defined in a particular domain.
            Args:
                session_str: str - The session id.
                body: Dict - The params to the API call.
            Returns:
                A dictionary with the id of the new rule object.
        """
        url_suffix = '/sdkapi/ruleobject'
        self.headers['NSM-SDK-API'] = session_str
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def update_rule_object_request(self, session_str: str, body: Dict, rule_id: str) -> Dict:
        """ Updates a Rule Object.
            Args:
                session_str: str - The session id.
                body: Dict - The params to the API call.
                rule_id: str - The rule id.
            Returns:
                A dictionary with the status of the request.
        """
        url_suffix = f'/sdkapi/ruleobject/{rule_id}'
        self.headers['NSM-SDK-API'] = session_str
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body, resp_type='response')

    def delete_rule_object_request(self, session_str: str, rule_id: str) -> Dict:
        """ Updates a Rule Object.
            Args:
                session_str: str - The session id.
                rule_id: str - The rule id.
            Returns:
                A dictionary with the status of the request.
        """
        url_suffix = f'/sdkapi/ruleobject/{rule_id}'
        self.headers['NSM-SDK-API'] = session_str
        return self._http_request(method='DELETE', url_suffix=url_suffix)

    def get_alerts_request(self, session_str: str, time_period: str, start_time: str, end_time: str, state: str,
                           search: str, filter_arg: str, domain_id: str, page: str = None) -> Dict:
        """ Retrieves All Alerts.
            Args:
                session_str: str - The session id.
                time_period: str - The time period of the alert.
                start_time: str - The start time of the alert.
                end_time: str - The end time of the alert.
                state: str - The state of the alert.
                search: str - Search string in alert details.
                filter_arg: str - Filter alert by fields.
                page: str - Next/Previous page.
                domain_id: str - The id of the domain
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
            params['domainId'] = domain_id
        url_suffix = '/sdkapi/alerts'
        self.headers['NSM-SDK-API'] = session_str
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_alert_details_request(self, session_str: str, alert_id: str, sensor_id: str) -> Dict:
        """ Retrieves the alert details.
            Args:
                session_str: str - The session id.
                alert_id: str - The id of the relevant alert.
                sensor_id: str - The id of the relevant sensor.
            Returns:
                A dictionary with the alert details.
        """
        url_suffix = f'/sdkapi/alerts/{alert_id}'
        self.headers['NSM-SDK-API'] = session_str
        params = {
            'sensorId': sensor_id
        }
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_attacks_request(self, session_str: str, attack_id: str) -> Dict:
        """ If an attack id is given The command returns the details for the specific attack. Else, gets all available attack definitions in the Manager UI..
            Args:
                session_str: str - The session id.
                attack_id: str - The id of the relevant attack.
            Returns:
                A dictionary with the attack list of the specific attack details.
        """
        url_suffix = f'/sdkapi/attacks'
        if attack_id:
            url_suffix = f'{url_suffix}/{attack_id}'
        self.headers['NSM-SDK-API'] = session_str
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)


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


def pagination(records_list: List, limit: int, page: int) -> List:
    """ Returns the wanted records.
    Args:
        records_list: List - The original list of objects.
        limit: str - The amount of records to be returned
        page: int - The page of the results (The results in page 1, 2 ...)
    Returns:
        The wanted records.
    """
    num_rec_2_remove = (limit * (page - 1))
    results_list = records_list[num_rec_2_remove:]
    return results_list[:limit]


def alerts_list_pagination(records_list: List, limit: int, page: int, session_str: str, time_period: str,
                           start_time: str, end_time: str, state: str, search: str, filter_arg: str,
                           total_alerts_count: int, client: Client, domain_id: str) -> List:
    """ Returns the wanted records.
    Args:
        records_list: List - The original list of objects.
        limit: str - The amount of records to be returned
        page: int - The page of the results (The results in page 1, 2 ...)
        session_str: str - The session id of the alert.
        time_period: str - The time period of the alert.
        start_time: str - The start time of the alert.
        end_time: str - The end time of the alert.
        state: str - The state of the alert.
        search: str - Search string in alert details.
        filter_arg: str - Filter alert by fields.
        total_alerts_count: int - the total alerts number.
        client: Client - McAfeeNSMv2 client
        domain_id: str - The id of the domain.
    Returns:
        The wanted records.
    """
    if page == 1 and limit < 1000:
        return records_list[:limit]
    else:
        num_rec_2_remove = (limit * (page - 1))
        results_list = []
        if total_alerts_count > 1000:
            while num_rec_2_remove + limit > 1000:
                records_list = records_list[num_rec_2_remove:]
                results_list.extend(records_list)
                limit = limit - len(results_list)
                num_rec_2_remove = 0 if num_rec_2_remove <= 1000 else num_rec_2_remove - 1000
                response = client.get_alerts_request(session_str, time_period, start_time, end_time, state, search,
                                                     filter_arg, domain_id, 'next')
                records_list = response.get('alertsList')

        records_list = records_list[num_rec_2_remove:]
        results_list.extend(records_list[:limit])
        return results_list


def response_cases(response_str: str) -> None | str:
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


def rule_object_type_cases(str_type: str, case: str) -> str | None:
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


def check_source_and_destination(source_rule_object_id: int, source_rule_object_type: str,
                                 destination_rule_object_id: int, destination_rule_object_type: str,
                                 create_or_update: str):
    """ Checks the source and destination objects.
    Args:
        source_rule_object_id: int - Unique Rule Object ID.
        source_rule_object_type: str - Source / Destination Mode.
        destination_rule_object_id: int - Unique Rule Object ID.
        destination_rule_object_type: str - Source / Destination Mode.
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
                                direction: str, source_object: Dict, destination_object: Dict) -> Dict:
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
        source_object: Dict - Information about the source addresses.
        destination_object: Dict - Information about the destination addresses.
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
            from_to_list: List = None - A list that contains dictionaries with from and do addresses.
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
        return f'NETWORK_IPV_{number}', {
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
        raise Exception('If the "rule_object_type" is Endpoint or Network than from_address and to_adresses parameters '
                        'should not contain value.')
    if 'ADDRESS_RANGE' in rule_type and not to_address and not from_address:
        raise Exception(f'If the "rule_object_type" is “Range IP V.{number}” than the arguments '
                        f'“from_address_ip_v.{number}” and “to_address_ip_v.{number}” must contain a value.')
    if 'ADDRESS_RANGE' in rule_type and address:
        raise Exception(f'If the "rule_object_type" is “Range IP V.{number} than the both address_ip_v.4 and '
                        f'address_ip_v.6 should not contain a value')


def add_entries_to_alert_list(alert_list: List[Dict]) -> List[Dict]:
    """ Add entries to the alert_list and update what needed in order not to break backward.
        Args:
            alert_list: List[Dict] - a list of the alerts that returned from the API.
        Returns:
            Returns the updated alert list.
    """
    for alert in alert_list:
        alert['ID'] = alert.get('event', {}).get('alertId')
        alert['Event'] = alert.get('event')
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
    return alert_list


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


def list_domain_firewall_policy_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Gets the list of Firewall Policies defined in a particular domain.
    Args:
        client: client - A McAfeeNSM client.
        args: Dict - The function arguments.
        session_str: str - The session string for authentication.
    Returns:
        A CommandResult object with the list of Firewall Policies defined in a particular domain.
    """
    domain_id = args.get('domain_id')
    limit = arg_to_number(args.get('limit', 50)) or 50
    page = arg_to_number(args.get('page', 1)) or 1

    response = client.list_domain_firewall_policy_request(session_str, domain_id)
    result = response.get('FirewallPoliciesForDomainResponseList', [])
    result = pagination(result, limit, page)
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


def get_firewall_policy_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Gets the Firewall Policy details.
    Args:
        client: client - A McAfeeNSM client.
        args: Dict - The function arguments.
        session_str: str - The session string for authentication.
    Returns:
        A CommandResult object with the Firewall Policy details.
    """
    policy_id = args.get('policy_id')
    response = client.get_firewall_policy_request(session_str, policy_id)
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


def create_firewall_policy_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Adds a new Firewall Policy and Access Rules.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with a success message.
    """
    domain = arg_to_number(args.get('domain', '0'))
    name = args.get('name')
    visible_to_child = argToBoolean(args.get('visible_to_child', True))
    description = args.get('description')
    is_editable = argToBoolean(args.get('is_editable'))
    policy_type = args.get('policy_type', '').upper()
    rule_description = args.get('rule_description')
    rule_enabled = argToBoolean(args.get('rule_enabled', True))
    response_param = response_cases(args.get('response'))
    direction = args.get('direction', '').upper()
    source_rule_object_id = args.get('source_rule_object_id')
    source_rule_object_type = args.get('source_rule_object_type')
    destination_rule_object_id = args.get('destination_rule_object_id')
    destination_rule_object_type = args.get('destination_rule_object_type')

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

    response = client.create_firewall_policy_request(session_str, body)
    new_firewall_policy_id = response.get('createdResourceId')
    return CommandResults(readable_output=f'The firewall policy no.{new_firewall_policy_id} was created successfully')


def update_firewall_policy_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Updates the Firewall Policy details.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with a success message.
    """
    policy_id = args.get('policy_id')
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
    source_rule_object_id = args.get('source_rule_object_id')
    source_rule_object_type = args.get('source_rule_object_type')
    destination_rule_object_id = args.get('destination_rule_object_id')
    destination_rule_object_type = args.get('destination_rule_object_type')
    is_overwrite = argToBoolean(args.get('is_overwrite', False))

    check_source_and_destination(source_rule_object_id, source_rule_object_type, destination_rule_object_id,
                                 destination_rule_object_type, 'update')

    policy_get_details = client.get_firewall_policy_request(session_str, policy_id)

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
    rule_enabled = member_rule_list.get('Enabled') if not rule_enabled else rule_enabled
    direction = member_rule_list.get('Direction') if not direction else direction.upper()

    if is_overwrite:
        source_rule_object_id = member_rule_list.get('SourceAddressObjectList', [Dict])[0].get('RuleObjectId') if not \
            source_rule_object_id else source_rule_object_id
        source_rule_object_type = member_rule_list.get('SourceAddressObjectList', [Dict])[0].get('RuleObjectId') if \
            not source_rule_object_type else rule_object_type_cases(source_rule_object_type, 'up')
        source_object = [{
            'RuleObjectId': source_rule_object_id,
            'RuleObjectType': source_rule_object_type
        }]
        destination_rule_object_id = member_rule_list.get('DestinationAddressObjectList', [Dict])[0]. \
            get('RuleObjectId') if not destination_rule_object_id else destination_rule_object_id
        destination_rule_object_type = member_rule_list.get('DestinationAddressObjectList', [Dict])[0]. \
            get('RuleObjectId') if not destination_rule_object_type else \
            rule_object_type_cases(destination_rule_object_type, 'up')
        destination_object = [{
            'RuleObjectId': destination_rule_object_id,
            'RuleObjectType': destination_rule_object_type
        }]
    else:
        source_object = member_rule_list.get('SourceAddressObjectList', [])
        if source_rule_object_id:
            new_source_object = {
                'RuleObjectId': source_rule_object_id,
                'RuleObjectType': source_rule_object_type
            }
            source_object.append(new_source_object)
        destination_object = member_rule_list.get('DestinationAddressObjectList', [])
        if destination_rule_object_id:
            new_destination_object = {
                'RuleObjectId': destination_rule_object_id,
                'RuleObjectType': destination_rule_object_type
            }
            destination_object.append(new_destination_object)
    body = create_body_firewall_policy(domain, name, visible_to_child, description, is_editable, policy_type,
                                       rule_description, response_param, rule_enabled, direction, source_object,
                                       destination_object)

    client.update_firewall_policy_request(session_str, body, policy_id)
    return CommandResults(readable_output=f'The firewall policy no.{policy_id} was updated successfully')


def delete_firewall_policy_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Deletes the specified Firewall Policy.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with a success message.
    """
    policy_id = args.get('policy_id')
    client.delete_firewall_policy_request(session_str, policy_id)
    return CommandResults(readable_output=f'The firewall policy no.{policy_id} was deleted successfully')


def list_domain_rule_objects_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Gets the list of rule objects defined in a particular domain.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with the list.
    """
    domain_id = args.get('domain_id')
    rule_type = args.get('type', 'All')
    limit = arg_to_number(args.get('limit', 50))
    page = arg_to_number(args.get('page', 1))
    if rule_type == 'All':
        rule_type = 'hostipv4,hostipv6,ipv4addressrange,ipv6addressrange,networkipv4,networkipv6'
    else:
        rule_type = rule_object_type_cases(rule_type, 'low')
    response = client.list_domain_rule_objects_request(session_str, domain_id, rule_type)
    results = pagination(response.get('RuleObjDef', []), limit, page)

    human_readable = []
    for record in results:
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


def get_rule_object_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Gets the details of a Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with information about the rule object.
    """
    rule_id = args.get('rule_id')
    response = client.get_rule_object_request(session_str, rule_id)
    response = response.get('RuleObjDef', {})
    human_readable = {
        'RuleId': response.get('ruleobjId'),
        'Name': response.get('name'),
        'Description': response.get('description'),
        'VisibleToChild': response.get('visibleToChild'),
        'RuleType': response.get('ruleobjType')
    }
    headers = ['RuleId', 'Name', 'Description', 'VisibleToChild', 'RuleType']
    readable_output = tableToMarkdown(name=f'Rule Objects {rule_id}',
                                      t=human_readable,
                                      removeNull=True,
                                      headers=headers)
    return CommandResults(readable_output=readable_output,
                          outputs_prefix='NSM.Rule',
                          outputs=response,
                          raw_response=response,
                          outputs_key_field='ruleobjId')


def create_rule_object_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Adds a new Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with a success message.
    """
    domain = arg_to_number(args.get('domain', 0))
    rule_type = rule_object_type_cases(args.get('rule_object_type'), 'up')
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
    body.get('RuleObjDef')[d_name] = extra_body
    response = client.create_rule_object_request(session_str, body)

    return CommandResults(readable_output=f'The rule object no.{response.get("createdResourceId")} '
                                          f'was created successfully')


def update_rule_object_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Updates a Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with a success message.
    """
    domain = arg_to_number(args.get('domain', 0))
    rule_id = args.get('rule_id')
    name = args.get('name')
    visible_to_child = argToBoolean(args.get('visible_to_child', True))
    description = args.get('description')
    address_ip_v_4 = argToList(args.get('address_ip_v.4', None))
    from_address_ip_v_4 = args.get('from_address_ip_v.4')
    to_address_ip_v_4 = args.get('to_address_ip_v.4')
    address_ip_v_6 = argToList(args.get('address_ip_v.6'))
    from_address_ip_v_6 = args.get('from_address_ip_v.6')
    to_address_ip_v_6 = args.get('to_address_ip_v.6')
    is_overwrite = argToBoolean(args.get('is_overwrite', False))

    response_get = client.get_rule_object_request(session_str, rule_id)
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
        if rule_type == 'HOST_IPV_4' or rule_type == 'NETWORK_IPV_4':
            address_ip_v_4 = address_ip_v_4 if address_ip_v_4 else response_get.get('HostIPv4', {}) \
                .get('hostIPv4AddressList')
        if from_address_ip_v_4:
            from_to_address_ip_v_4 = [{
                'FromAddress': from_address_ip_v_4,
                'ToAddress': to_address_ip_v_4
            }]
        elif not from_address_ip_v_4 and rule_type == 'IPV_4_ADDRESS_RANGE':
            from_to_address_ip_v_4 = response_get.get('IPv4AddressRange', {}).get('IPV4RangeList')
        if rule_type == 'HOST_IPV_6' or rule_type == 'NETWORK_IPV_6':
            address_ip_v_6 = address_ip_v_6 if address_ip_v_6 else response_get.get('HostIPv6', {}) \
                .get('hostIPv6AddressList')
        if from_address_ip_v_6:
            from_to_address_ip_v_6 = [{
                'FromAddress': from_address_ip_v_6,
                'ToAddress': to_address_ip_v_6
            }]
        elif not from_address_ip_v_6 and rule_type == 'IPV_6_ADDRESS_RANGE':
            from_to_address_ip_v_6 = response_get.get('IPv6AddressRange', {}).get('IPV6RangeList')
    else:
        if rule_type == 'HOST_IPV_4' or rule_type == 'NETWORK_IPV_4':
            old_address_ip_v_4 = response_get.get('HostIPv4', {}).get('hostIPv4AddressList', [])
            old_address_ip_v_4.extend(address_ip_v_4)
            address_ip_v_4 = old_address_ip_v_4
        elif rule_type == 'IPV_4_ADDRESS_RANGE':
            from_to_address_ip_v_4 = response_get.get('IPv4AddressRange', {}).get('IPV4RangeList', [])
            from_to_address_ip_v_4.append({
                'FromAddress': from_address_ip_v_4,
                'ToAddress': to_address_ip_v_4
            })
        elif rule_type == 'HOST_IPV_6' or rule_type == 'NETWORK_IPV_6':
            old_address_ip_v_6 = response_get.get('HostIPv6', {}).get('hostIPv6AddressList', [])
            old_address_ip_v_6.extend(address_ip_v_6)
            address_ip_v_6 = old_address_ip_v_6
        elif rule_type == 'IPV_6_ADDRESS_RANGE':
            from_to_address_ip_v_6 = response_get.get('IPv6AddressRange', {}).get('IPV6RangeList', [])
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
    number = 4 if (address_ip_v_4 or from_address_ip_v_4) else 6
    from_to_list = from_to_address_ip_v_4 if from_address_ip_v_4 else from_to_address_ip_v_6
    d_name, extra_body = create_body_create_rule(rule_type, address, number, from_to_list)
    body.get('RuleObjDef')[d_name] = extra_body
    client.update_rule_object_request(session_str, body, rule_id)
    return CommandResults(readable_output=f'The rule object no.{rule_id} was updated successfully')


def delete_rule_object_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Deletes a Rule Object.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with a success message.
    """
    rule_id = args.get('rule_id')
    client.delete_rule_object_request(session_str, rule_id)
    return CommandResults(readable_output=f'The rule object no.{rule_id} was deleted successfully')


def get_alerts_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Retrieves All Alerts.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with a list of alerts.
    """
    limit = arg_to_number(args.get('limit', 50)) or 50
    page = arg_to_number(args.get('page', 1)) or 1
    time_period = args.get('time_period')
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    state = args.get('state')
    search = args.get('search')
    filter_arg = args.get('filter')
    domain_id = args.get('domain_id')
    response = client.get_alerts_request(session_str, time_period, start_time, end_time, state, search, filter_arg,
                                         domain_id)
    total_alerts_count = response.get('totalAlertsCount')
    alerts_list = alerts_list_pagination(response.get('alertsList', []), limit, page, session_str, time_period,
                                         start_time, end_time, state, search, filter_arg, total_alerts_count, client,
                                         domain_id)
    alerts_list = add_entries_to_alert_list(alerts_list)
    human_readable = []
    for alert_info in alerts_list:
        d = {'ID': alert_info.get('ID'),
             'Name': alert_info.get('name'),
             'Event Time': alert_info.get('event.time'),
             'Severity': alert_info.get('attackSeverity'),
             'State': alert_info.get('alertState'),
             'Direction': alert_info.get('event.direction'),
             'Result': alert_info.get('event.result'),
             'Attack Count': alert_info.get('event.attackCount'),
             'Attacker IP': alert_info.get('attacker.ipAddrs'),
             'Target IP': alert_info.get('target.ipAddrs')}
        human_readable.append(d)

    headers = ['ID', 'Name', 'Event Time', 'Severity', 'State', 'Direction', 'Result', 'Attack Count', 'Attacker IP',
               'Target IP']
    readable_output = tableToMarkdown(
        name=f'Alerts list. Showing {limit} of {total_alerts_count}',
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


def get_alert_details_command(client: Client, args: Dict, session_str: str) -> CommandResults:
    """ Retrieves the relevant alert.
        Args:
            client: client - A McAfeeNSM client.
            args: Dict - The function arguments.
            session_str: str - The session string for authentication.
        Returns:
            A CommandResult object with a success message.
    """
    alert_id = args.get('alert_id')
    sensor_id = args.get('sensor_id')
    response = client.get_alert_details_request(session_str, alert_id, sensor_id)
    response['ID'] = alert_id

    human_readable = {
        'ID': response.get('ID'),
        'Name': response.get('name'),
        'Event Time': response.get('summary', {}).get('event', {}).get('time'),
        'State': response.get('alertState'),
        'Direction': response.get('summary', {}).get('event', {}).get('direction'),
        'Result': response.get('summary', {}).get('event', {}).get('result'),
        'Attack Count': response.get('summary', {}).get('event', {}).get('attackCount'),
        'Attacker IP': response.get('summary', {}).get('attacker', {}).get('ipAddrs'),
        'Target IP': response.get('summary', {}).get('target', {}).get('ipAddrs')
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


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    url = demisto.params().get('url')
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
        session_str = ''
        if demisto.command() != 'test-module':
            session_str = get_session(client, f'{user_name}:{password}')

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, f'{user_name}:{password}')
            return_results(result)
        elif demisto.command() == 'nsm-list-domain-firewall-policy':
            result = list_domain_firewall_policy_command(client, demisto.args(), session_str)
            return_results(result)
        elif demisto.command() == 'nsm-get-firewall-policy':
            results = get_firewall_policy_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-create-firewall-policy':
            results = create_firewall_policy_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-update-firewall-policy':
            results = update_firewall_policy_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-delete-firewall-policy':
            results = delete_firewall_policy_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-list-domain-rule-object':
            results = list_domain_rule_objects_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-get-rule-object':
            results = get_rule_object_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-create-rule-object':
            results = create_rule_object_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-update-rule-object':
            results = update_rule_object_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-delete-rule-object':
            results = delete_rule_object_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-get-alerts':
            results = get_alerts_command(client, demisto.args(), session_str)
            return_results(results)
        elif demisto.command() == 'nsm-get-alert-details':
            results = get_alert_details_command(client, demisto.args(), session_str)
            return_results(results)
        else:
            raise NotImplementedError('This command is not implemented yet.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
