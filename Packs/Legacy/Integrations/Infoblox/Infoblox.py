import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Dict, Tuple, Optional, Union, Callable, Any
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'Infoblox Integration'
INTEGRATION_COMMAND_NAME = 'infoblox'
INTEGRATION_CONTEXT_NAME = 'Infoblox'
REQUEST_PARAM_EXTRA_ATTRIBUTES = {'_return_fields+': 'extattrs'}
REQUEST_PARAM_ZONE = {'_return_fields+': 'fqdn,rpz_policy,rpz_severity,rpz_type,substitute_name,comment,disable'}
REQUEST_PARAM_CREATE_RULE = {'_return_fields+': 'name,rp_zone,comment,canonical,disable'}
REQUEST_PARAM_LIST_RULES = {'_return_fields+': 'name,zone,comment,disable,type'}
REQUEST_PARAM_SEARCH_RULES = {'_return_fields+': 'name,zone,comment,disable'}
REQUEST_PARAM_PAGING_FLAG = {'_paging': '1'}

RESPONSE_TRANSLATION_DICTIONARY = {
    '_ref': 'ReferenceID',
    'fqdn': 'FQDN',
    'rp_zone': 'Zone'
}

RPZ_RULES_DICT = {
    'Passthru': {
        'Domain Name': {
            'infoblox_object_type': 'record:rpz:cname'
        },
        'IP address': {
            'infoblox_object_type': 'record:rpz:a:ipaddress'
        },
        'Client IP address': {
            'infoblox_object_type': 'record:rpz:cname:clientipaddress'
        }
    },
    'Block (No such domain)': {
        'Domain Name': {
            'infoblox_object_type': 'record:rpz:cname'
        },
        'IP address': {
            'infoblox_object_type': 'record:rpz:cname:ipaddress'
        },
        'Client IP address': {
            'infoblox_object_type': 'record:rpz:cname:clientipaddress'
        }
    },
    'Block (No data)': {
        'Domain Name': {
            'infoblox_object_type': 'record:rpz:cname'
        },
        'IP address': {
            'infoblox_object_type': 'record:rpz:cname:ipaddress'
        },
        'Client IP address': {
            'infoblox_object_type': 'record:rpz:cname:clientipaddress'
        }
    },
    'Substitute (domain name)': {
        'Domain Name': {
            'infoblox_object_type': 'record:rpz:cname'
        },
        'IP address': {
            'infoblox_object_type': 'record:rpz:a:ipaddress'
        },
        'Client IP address': {
            'infoblox_object_type': 'record:rpz:cname:clientipaddressdn'
        }
    }
}


class Client(BaseClient):
    def __init__(self, base_url, verify=True, proxy=False, ok_codes=tuple(), headers=None, auth=None, params=None):
        super(Client, self).__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self.params = params

    def _http_request(self, method, url_suffix, full_url=None, headers=None, auth=None, json_data=None, params=None,
                      data=None, files=None, timeout=10, resp_type='json', ok_codes=None, **kwargs):
        if params:
            self.params.update(params)
        try:
            return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                         auth=auth, json_data=json_data, params=self.params, data=data, files=files,
                                         timeout=timeout, resp_type=resp_type, ok_codes=ok_codes, **kwargs)
        except DemistoException as error:
            raise parse_demisto_exception(error, 'text')

    def test_module(self) -> Dict:
        """Performs basic GET request (List Response Policy Zones) to check if the API is reachable and authentication
        is successful.

        Returns:
            Response JSON
        """
        return self.list_response_policy_zones()

    def list_response_policy_zones(self, max_results: Optional[str] = None) -> Dict:
        """List all response policy zones.
        Args:
                max_results:  maximum number of results
        Returns:
            Response JSON
        """
        suffix = 'zone_rp'
        request_params = assign_params(_max_results=max_results)
        request_params.update(REQUEST_PARAM_ZONE)
        return self._http_request('GET', suffix, params=request_params)

    def get_ip(self, ip: Optional[str]) -> Dict:
        """Get ip information.
        Args:
            ip: ip to retrieve.

        Returns:
            Response JSON
        """
        # The server endpoint to request from
        suffix = 'ipv4address'

        # Dictionary of params for the request
        request_params = assign_params(ip_address=ip)
        request_params.update(REQUEST_PARAM_EXTRA_ATTRIBUTES)
        return self._http_request('GET', suffix, params=request_params)

    def search_related_objects_by_ip(self, ip: Optional[str], max_results: Optional[str]) -> Dict:
        """Search ip related objects.
        Args:
            ip: ip to retrieve.
            max_results: maximum number of results

        Returns:
            Response JSON
        """
        # The server endpoint to request from
        suffix = 'search'

        # Dictionary of params for the request
        request_params = assign_params(address=ip, _max_results=max_results)
        return self._http_request('GET', suffix, params=request_params)

    def list_response_policy_zone_rules(self, zone: Optional[str], max_results: Optional[str],
                                        next_page_id: Optional[str]) -> Dict:
        """List response policy zones rules by a given zone name.
        Args:
            zone: response policy zone name.
            max_results: maximum number of results.
            next_page_id: ID of the next page to retrieve, if given all other arguments are ignored.

        Returns:
            Response JSON
        """
        # The server endpoint to request from
        suffix = 'allrpzrecords'
        # Dictionary of params for the request
        request_params = assign_params(zone=zone, _max_results=max_results, _page_id=next_page_id)
        request_params.update(REQUEST_PARAM_PAGING_FLAG)
        request_params.update(REQUEST_PARAM_LIST_RULES)

        return self._http_request('GET', suffix, params=request_params)

    def create_response_policy_zone(self, fqdn: Optional[str], rpz_policy: Optional[str],
                                    rpz_severity: Optional[str], substitute_name: Optional[str],
                                    rpz_type: Optional[str]) -> Dict:
        """Creates new response policy zone
        Args:
            fqdn: The name of this DNS zone.
            rpz_policy: The response policy zone override policy.
            rpz_severity: The severity of this response policy zone.
            substitute_name: The canonical name of redirect target in substitute policy.
            rpz_type: The type of rpz zone.
        Returns:
            Response JSON
        """

        data = assign_params(fqdn=fqdn, rpz_policy=rpz_policy, rpz_severity=rpz_severity,
                             substitute_name=substitute_name, rpz_type=rpz_type)
        suffix = 'zone_rp'
        return self._http_request('POST', suffix, data=json.dumps(data), params=REQUEST_PARAM_ZONE)

    def delete_response_policy_zone(self, ref_id: Optional[str]) -> Dict:
        """Delete new response policy zone
        Args:
            ref_id: Zone reference id to delete.
        Returns:
            Response JSON
        """

        suffix = ref_id
        return self._http_request('DELETE', suffix)

    def create_rpz_rule(self, rule_type: Optional[str], object_type: Optional[str], name: Optional[str],
                        rp_zone: Optional[str], substitute_name: Optional[str],
                        comment: Optional[str] = None) -> Dict:
        """Creates new response policy zone rule.
        Args:
            rule_type: Type of rule to create.
            object_type: Type of object to assign the rule on.
            name: Rule name.
            rp_zone: The zone to assign the rule.
            substitute_name: The substitute name to assign (In case of substitute domain only)
            comment: A comment for this rule.
        Returns:
            Response JSON
        """
        canonical: Optional[str] = ''
        if rule_type == 'Passthru':
            canonical = 'rpz-passthru' if object_type == 'Client IP address' else name
        elif rule_type == 'Block (No data)':
            canonical = '*'
        elif rule_type == 'Substitute (domain name)':
            canonical = substitute_name

        data = assign_params(name=name, canonical=canonical, rp_zone=rp_zone, comment=comment)
        request_params = REQUEST_PARAM_CREATE_RULE
        suffix = demisto.get(RPZ_RULES_DICT, f'{rule_type}.{object_type}.infoblox_object_type')

        rule = self._http_request('POST', suffix, data=json.dumps(data), params=request_params)
        rule['result']['type'] = suffix
        return rule

    def create_substitute_record_rule(self, suffix: Optional[str], **kwargs: Union[str, int, None]) -> Dict:
        """Creates new response policy zone substitute rule.
        Args:
            suffix: The infoblox object to be used as a url path.
            kwargs: A dict of arguments to be passed to the rule body. The following may appear:
                - name
                - rp_zone
                - comment
                - ipv4addr
                - ipv6addr
                - mail_exchanger
                - preference
                - order
                - preference
                - replacement
                - ptrdname
                - priority
                - target
                - weight
                - port
                - text
        Returns:
            Response JSON
        """
        request_data = {key: val for key, val in kwargs.items() if val is not None}
        request_params = {'_return_fields+': ','.join(request_data.keys()) + ',disable,name'}
        rule = self._http_request('POST', suffix, data=json.dumps(request_data), params=request_params)
        rule['result']['type'] = suffix
        return rule

    def change_rule_status(self, reference_id: Optional[str], disable: Optional[bool]) -> Dict:
        """Changes a given rule status.
        Args:
            reference_id: Rule reference ID
            disable: true or false string
        Returns:
            Response JSON
        """
        request_data = assign_params(disable=disable)
        suffix = reference_id
        return self._http_request('PUT', suffix, data=json.dumps(request_data), params=REQUEST_PARAM_SEARCH_RULES)

    def get_object_fields(self, object_type: Optional[str]) -> Dict:
        """Retrieve a given object fields.
        Args:
            object_type: Infoblox object type
        Returns:
            Response JSON
        """
        request_params = {'_schema': object_type}
        suffix = object_type
        return self._http_request('GET', suffix, params=request_params)

    def search_rule(self, object_type: Optional[str], rule_name: Optional[str],
                    output_fields: Optional[str]) -> Dict:
        """Search rule by its name
        Args:
            object_type: Infoblox object type
            rule_name: Full rule name
            output_fields: Fields to include in the return object
        Returns:
            Response JSON
        """
        request_params = assign_params(name=rule_name)
        if output_fields:
            request_params['_return_fields+'] = output_fields
        suffix = object_type
        return self._http_request('GET', suffix, params=request_params)

    def delete_rpz_rule(self, reference_id: Optional[str]) -> Dict:
        """Deletes a rule by its reference id
        Args:
            reference_id: Rule reference ID
        Returns:
            Response JSON
        """

        suffix = reference_id
        return self._http_request('DELETE', suffix)


''' HELPER FUNCTIONS '''


def parse_demisto_exception(error: DemistoException, field_in_error: str = 'text'):
    err_msg = err_string = error.args[0]
    if '[401]' in err_string:
        err_msg = 'Authorization error, check your credentials.'
    elif 'Failed to parse json object' in err_string:
        err_msg = 'Cannot connect to Infoblox server, check your proxy and connection.'
    elif 'Error in API call' in err_string:
        err_lines = err_string.split('\n')
        infoblox_err = err_lines[1] if len(err_lines) > 1 else '{}'
        infoblox_json = json.loads(infoblox_err)
        err_msg = infoblox_json.get(field_in_error, 'text') if infoblox_json else err_string
    return DemistoException(err_msg)


''' COMMANDS '''


def test_module_command(client: Client, *_) -> Tuple[str, Dict, Dict]:
    client.test_module()
    return 'ok', {}, {}


def get_ip_command(client: Client, args: Dict[str, str]) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    ip = args.get('ip')
    raw_response = client.get_ip(ip)
    ip_list = raw_response.get('result')

    # If no IP object was returned
    if not ip_list:
        return f'{INTEGRATION_NAME} - Could not find any data corresponds to: {ip}', {}, {}
    fixed_keys_obj = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                      ip_list[0].items()}
    title = f'{INTEGRATION_NAME} - IP: {ip} info.'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.IP(val.ReferenceID && val.ReferenceID === obj.ReferenceID)': fixed_keys_obj}
    human_readable = tableToMarkdown(title, fixed_keys_obj, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def search_related_objects_by_ip_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    ip = args.get('ip')
    max_results = args.get('max_results')
    raw_response = client.search_related_objects_by_ip(ip, max_results)
    obj_list = raw_response.get('result')
    if not obj_list:
        return f'{INTEGRATION_NAME} - No objects associated with ip: {ip} were found', {}, {}
    fixed_keys_obj_list = []
    for obj in obj_list:
        fixed_keys_obj = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                          obj.items()}
        fixed_keys_obj_list.append(fixed_keys_obj)

    title = f'{INTEGRATION_NAME} - IP: {ip} search results.'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.IPRelatedObjects(val.ReferenceID && val.ReferenceID === obj.ReferenceID)':
            fixed_keys_obj_list}
    human_readable = tableToMarkdown(title, fixed_keys_obj_list, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def list_response_policy_zone_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    zone = args.get('response_policy_zone_name')
    max_results = args.get('page_size', 50)
    next_page_id = args.get('next_page_id')
    if not zone and not next_page_id:
        raise DemistoException('To run this command either a zone or a next page ID must be given')
    raw_response = client.list_response_policy_zone_rules(zone, max_results, next_page_id)
    new_next_page_id = raw_response.get('next_page_id')

    rules_list = raw_response.get('result')
    if not rules_list:
        return f'{INTEGRATION_NAME} - No rules associated to zone: {zone} were found', {}, {}

    fixed_keys_rule_list = []
    for rule in rules_list:
        fixed_keys_rule = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items() if key != '_ref'}
        fixed_keys_rule_list.append(fixed_keys_rule)
    zone_name = zone.capitalize() if zone else fixed_keys_rule_list[0].get('Name')
    title = f'{INTEGRATION_NAME} - Zone: {zone_name} rule list.'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ResponsePolicyZoneRulesList(val.Name && val.Name === obj.Name)':
            fixed_keys_rule_list
    }
    if new_next_page_id:
        context.update({
            f'{INTEGRATION_CONTEXT_NAME}.RulesNextPage(val.NextPageID !== obj.NextPageID)': {   # type: ignore
                'NextPageID': new_next_page_id}
        })
    human_readable = tableToMarkdown(title, fixed_keys_rule_list,
                                     headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def list_response_policy_zones_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    max_results = args.get('max_results', 50)
    raw_response = client.list_response_policy_zones(max_results)
    zones_list = raw_response.get('result')
    if not zones_list:
        return f'{INTEGRATION_NAME} - No Response Policy Zones were found', {}, {}
    fixed_keys_zone_list = []
    for zone in zones_list:
        fixed_keys_zone = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           zone.items()}
        fixed_keys_zone_list.append(fixed_keys_zone)
    display_first_x_results = f'(first {max_results} results)' if max_results else ''
    title = f'{INTEGRATION_NAME} - Response Policy Zones list {display_first_x_results}:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ResponsePolicyZones(val.FQDN && val.FQDN === obj.FQDN)': fixed_keys_zone_list}
    human_readable = tableToMarkdown(title, fixed_keys_zone_list, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_response_policy_zone_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    fqdn = args.get('FQDN')
    rpz_policy = args.get('rpz_policy')
    rpz_severity = args.get('rpz_severity')
    substitute_name = args.get('substitute_name')
    rpz_type = args.get('rpz_type')
    if rpz_policy == 'SUBSTITUTE' and not substitute_name:
        raise DemistoException(f'Response policy zone with policy SUBSTITUTE requires a substitute name')
    raw_response = client.create_response_policy_zone(fqdn, rpz_policy, rpz_severity, substitute_name, rpz_type)
    zone = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           zone.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone: {fqdn} has been created'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ResponsePolicyZones(val.FQDN && val.FQDN === obj.FQDN)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def delete_response_policy_zone_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    ref_id = args.get('reference_id')
    raw_response = client.delete_response_policy_zone(ref_id)
    deleted_rule_ref_id = raw_response.get('result', {})
    human_readable = f'{INTEGRATION_NAME} - Response Policy Zone with the following id was deleted: \n ' \
        f'{deleted_rule_ref_id}'
    return human_readable, {}, raw_response


def create_rpz_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    rule_type = args.get('rule_type')
    object_type = args.get('object_type')
    name = args.get('name')
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    substitute_name = args.get('substitute_name')
    if rule_type == 'Substitute (domain name)' and not substitute_name:
        raise DemistoException(f'Substitute (domain name) rules requires a substitute name argument')
    raw_response = client.create_rpz_rule(rule_type, object_type, name, rp_zone, comment, substitute_name)
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_a_substitute_record_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    name = args.get('name')
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    ipv4addr = args.get('ipv4addr')
    infoblox_object_type = 'record:rpz:a'

    raw_response = client.create_substitute_record_rule(infoblox_object_type, name=name, rp_zone=rp_zone,
                                                        comment=comment, ipv4addr=ipv4addr)
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_aaaa_substitute_record_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    name = args.get('name')
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    ipv6addr = args.get('ipv6addr')
    infoblox_object_type = 'record:rpz:aaaa'

    raw_response = client.create_substitute_record_rule(infoblox_object_type, name=name, rp_zone=rp_zone,
                                                        comment=comment, ipv6addr=ipv6addr)
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_mx_substitute_record_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    name = args.get('name')
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    mail_exchanger = args.get('mail_exchanger')
    preference = int(args.get('preference', 0))
    infoblox_object_type = 'record:rpz:mx'

    raw_response = client.create_substitute_record_rule(infoblox_object_type, name=name, rp_zone=rp_zone,
                                                        comment=comment, mail_exchanger=mail_exchanger,
                                                        preference=preference)
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_naptr_substitute_record_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    name = args.get('name')
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    order = int(args.get('order', 0))
    preference = int(args.get('preference', 0))
    replacement = args.get('replacement')
    infoblox_object_type = 'record:rpz:naptr'

    raw_response = client.create_substitute_record_rule(infoblox_object_type, name=name, rp_zone=rp_zone,
                                                        comment=comment, order=order, preference=preference,
                                                        replacement=replacement)

    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_ptr_substitute_record_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    ptrdname = args.get('ptrdname')
    name = args.get('name')
    ipv4addr = args.get('ipv4addr')
    ipv6addr = args.get('ipv6addr')
    infoblox_object_type = 'record:rpz:ptr'
    if all([not name, not ipv4addr, not ipv6addr]):
        raise DemistoException('To run this command either \'name\', \'ipv4addr\' or \'ipv6addr\' should be given.')
    raw_response = client.create_substitute_record_rule(infoblox_object_type, name=name, rp_zone=rp_zone,
                                                        comment=comment, ptrdname=ptrdname, ipv4addr=ipv4addr,
                                                        ipv6addr=ipv6addr)
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_srv_substitute_record_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    name = args.get('name')
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    port = int(args.get('port', 0))
    priority = int(args.get('priority', 0))
    target = args.get('target')
    weight = int(args.get('weight', 0))
    infoblox_object_type = 'record:rpz:srv'

    raw_response = client.create_substitute_record_rule(infoblox_object_type, name=name, rp_zone=rp_zone,
                                                        comment=comment, port=port, priority=priority, target=target,
                                                        weight=weight)
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_txt_substitute_record_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    name = args.get('name')
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    text = args.get('text')
    infoblox_object_type = 'record:rpz:txt'

    raw_response = client.create_substitute_record_rule(infoblox_object_type, name=name, rp_zone=rp_zone,
                                                        comment=comment, text=text)
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_ipv4_substitute_record_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    name = args.get('name')
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    ipv4addr = args.get('ipv4addr')
    infoblox_object_type = 'record:rpz:a:ipaddress'

    raw_response = client.create_substitute_record_rule(infoblox_object_type, name=name, rp_zone=rp_zone,
                                                        comment=comment, ipv4addr=ipv4addr)
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_ipv6_substitute_record_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    name = args.get('name')
    rp_zone = args.get('rp_zone')
    comment = args.get('comment')
    ipv6addr = args.get('ipv6addr')
    infoblox_object_type = 'record:rpz:aaaa:ipaddress'

    raw_response = client.create_substitute_record_rule(infoblox_object_type, name=name, rp_zone=rp_zone,
                                                        comment=comment, ipv6addr=ipv6addr)
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def enable_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    reference_id = args.get('reference_id')
    raw_response = client.change_rule_status(reference_id, disable=False)

    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {fixed_keys_rule_res.get("Name")} has been enabled'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def disable_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    reference_id = args.get('reference_id')
    raw_response = client.change_rule_status(reference_id, disable=True)

    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {fixed_keys_rule_res.get("Name")} has been disabled'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def get_object_fields_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    object_type = args.get('object_type')
    raw_response = client.get_object_fields(object_type)

    fields = raw_response.get('result', {}).get('fields', {})
    name_list = [field_obj.get('name') for field_obj in fields]
    title = f'{INTEGRATION_NAME} - Object {object_type} supported fields: '
    context_entry = {
        'ObjectType': object_type,
        'SupportedFields': name_list
    }
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ObjectFields(val.ObjectType && val.ObjectType === obj.ObjectType)': context_entry
    }
    human_readable = tableToMarkdown(title, name_list, headers=['Field Names'], headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def search_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    object_type = args.get('object_type')
    rule_name = args.get('rule_name')
    output_fields = args.get('output_fields')
    raw_response = client.search_rule(object_type, rule_name, output_fields)
    rule_list = raw_response.get('result')
    if not rule_list:
        return f'No rules with name: {rule_name} of type: {object_type} were found', {}, raw_response
    fixed_keys_rule_list = []
    for rule in rule_list:
        fixed_keys_rule = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
        fixed_keys_rule_list.append(fixed_keys_rule)
    title = f'{INTEGRATION_NAME} - Search result for: {rule_name}: '
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.RulesSearchResults(val.Name && val.Name === obj.Name)': fixed_keys_rule_list
    }
    human_readable = tableToMarkdown(title, fixed_keys_rule_list, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def delete_rpz_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    reference_id = args.get('reference_id')
    raw_response = client.delete_rpz_rule(reference_id)
    rule_reference_id = raw_response.get('result')
    title = f'{INTEGRATION_NAME} - A rule with the following id was deleted: \n {rule_reference_id}'
    return title, {}, raw_response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    base_url = f"{params.get('url', '').rstrip('/')}/wapi/v2.3/"
    verify = not params.get('insecure', False)
    proxy = params.get('proxy') == 'true'
    user = demisto.get(params, 'credentials.identifier')
    password = demisto.get(params, 'credentials.password')
    default_request_params = {
        '_return_as_object': '1'
    }
    client = Client(base_url, verify=verify, proxy=proxy, auth=(user, password), params=default_request_params)
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    # Switch case
    commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
        'test-module': test_module_command,
        f'{INTEGRATION_COMMAND_NAME}-get-ip': get_ip_command,
        f'{INTEGRATION_COMMAND_NAME}-search-related-objects-by-ip': search_related_objects_by_ip_command,
        f'{INTEGRATION_COMMAND_NAME}-list-response-policy-zones': list_response_policy_zones_command,
        f'{INTEGRATION_COMMAND_NAME}-list-response-policy-zone-rules': list_response_policy_zone_rules_command,
        f'{INTEGRATION_COMMAND_NAME}-create-response-policy-zone': create_response_policy_zone_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-response-policy-zone': delete_response_policy_zone_command,
        f'{INTEGRATION_COMMAND_NAME}-create-rpz-rule': create_rpz_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-create-a-substitute-record-rule': create_a_substitute_record_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-create-aaaa-substitute-record-rule': create_aaaa_substitute_record_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-create-mx-substitute-record-rule': create_mx_substitute_record_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-create-naptr-substitute-record-rule': create_naptr_substitute_record_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-create-ptr-substitute-record-rule': create_ptr_substitute_record_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-create-srv-substitute-record-rule': create_srv_substitute_record_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-create-txt-substitute-record-rule': create_txt_substitute_record_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-create-ipv4-substitute-record-rule': create_ipv4_substitute_record_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-create-ipv6-substitute-record-rule': create_ipv6_substitute_record_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-enable-rule': enable_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-disable-rule': disable_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-get-object-fields': get_object_fields_command,
        f'{INTEGRATION_COMMAND_NAME}-search-rule': search_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-rpz-rule': delete_rpz_rule_command,
    }
    try:
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} - {e}'
        return_error(err_msg, error=e)


if __name__ in ["__builtin__", "builtins", '__main__']:  # pragma: no cover
    main()
