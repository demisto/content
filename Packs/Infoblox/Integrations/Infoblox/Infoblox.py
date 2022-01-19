import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
from typing import Any, Callable, Dict, Optional, Tuple, Union, List

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

    def _http_request(self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
                      params=None, data=None, files=None, timeout=10, resp_type='json', ok_codes=None,
                      return_empty_response=False, retries=0, status_list_to_retry=None,
                      backoff_factor=5, raise_on_redirect=False, raise_on_status=False,
                      error_handler=None, empty_valid_codes=None, **kwargs):
        if params:
            self.params.update(params)
        try:
            return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                         auth=auth, json_data=json_data, params=self.params, data=data, files=files,
                                         timeout=timeout, resp_type=resp_type, ok_codes=ok_codes,
                                         return_empty_response=return_empty_response, retries=retries,
                                         status_list_to_retry=status_list_to_retry, backoff_factor=backoff_factor,
                                         raise_on_redirect=raise_on_redirect, raise_on_status=raise_on_status,
                                         error_handler=error_handler, empty_valid_codes=empty_valid_codes, **kwargs)
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

    def get_ip(self, ip: str) -> Dict:
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

    def search_related_objects_by_ip(self, ip: str, max_results: Optional[str]) -> Dict:
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

    def list_response_policy_zone_rules(self, zone: str, view: Optional[str], max_results: Optional[str],
                                        next_page_id: Optional[str]) -> Dict:
        """List response policy zones rules by a given zone name.
        Args:
            zone: response policy zone name.
            view: The DNS view in which the records are located. By default, the 'default' DNS view is searched.
            max_results: maximum number of results.
            next_page_id: ID of the next page to retrieve, if given all other arguments are ignored.

        Returns:
            Response JSON
        """
        # The server endpoint to request from
        suffix = 'allrpzrecords'
        # Dictionary of params for the request
        request_params = assign_params(zone=zone, view=view, _max_results=max_results, _page_id=next_page_id)
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
                        rp_zone: Optional[str], view: Optional[str], substitute_name: Optional[str],
                        comment: Optional[str] = None) -> Dict:
        """Creates new response policy zone rule.
        Args:
            rule_type: Type of rule to create.
            object_type: Type of object to assign the rule on.
            name: Rule name.
            rp_zone: The zone to assign the rule.
            view: The DNS view in which the records are located. By default, the 'default' DNS view is searched.
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

        data = assign_params(name=name, rp_zone=rp_zone, view=view, comment=comment)
        # if rule_type is 'Block (No such domain)', then 'canonical' is '' (empty string) but API still requires 'canonical'
        data.update(
            {
                'canonical': canonical
            }
        )
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

    def list_records(self, zone: str):
        params = {
            "zone": zone,
            "_return_as_object": 1
        }
        res = self._http_request('GET', 'allrecords', params=params)
        return res

    def list_hosts(self):
        params = {
            "_return_fields": "ipv4addrs",
            "_return_as_object": 1
        }
        res = self._http_request('GET', "record:host", params=params)
        return res

    def search_host_record(self, name: str):
        params = {
            "name": name,
            "_return_as_object": 1
        }
        res = self._http_request('GET', "record:host", params=params)
        return res

    def create_record(self, suffix: Optional[str], **kwargs: Union[str, int, None]) -> Dict:
        """Creates new record.
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

    def add_host(self, host: Optional[str], ipadd: Optional[str]) -> Dict:
        """Add a host record.
        Args:
            host: FQDN to change
            ipadd: IP Address

        Returns:
            Response JSON
        """
        suffix = "record:host"
        payload = '{ "name":"' + str(host) + '","ipv4addrs":[{"ipv4addr":"' + str(ipadd) + '"}]}'
        headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

        rule = self._http_request('POST', suffix, headers=headers, data=payload)
        return rule

    def update_host_ip(self, refid: str, ipv4addr: str):
        params = {
            "_return_fields": "ipv4addrs",
            "_return_as_object": 1
        }
        payload = {
            "ipv4addrs": [
                {"ipv4addr": str(ipv4addr)}
            ]
        }
        res = self._http_request('PUT', f"{refid}", params=params, json_data=payload)
        return res

    def update_a_record(self, refid: str, ipv4addr: str, name: Optional[str], comment: Optional[str]):
        params = {
            "_return_fields": "ipv4addrs",
            "_return_as_object": 1
        }
        payload = {
            "ipv4addrs": [
                {"ipv4addr": str(ipv4addr)}
            ],
            "name": name,
            "comment": comment
        }
        res = self._http_request('PUT', f"{refid}", params=params, json_data=payload)
        return res

    def delete_host(self, refid: Optional[str]) -> Dict:
        """Deletes a host record.
        Args:
            refid: Reference ID from Infoblox

        Returns:
            Response JSON
        """
        headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

        suffix = "record:host/" + str(refid)

        rule = self._http_request('DELETE', suffix, headers=headers)
        return rule


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


def results_to_context_data(results: Dict, to_list: bool) -> Union[Dict, List]:
    if to_list:
        context_data = []
        for result in results:
            fixed_keys_obj = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                              result.items()}
            context_data.append(fixed_keys_obj)
    else:
        context_data = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                        results.items()}
    return context_data


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
    results = raw_response.get('result')
    if not raw_response.get('result'):
        return f'{INTEGRATION_NAME} - No objects associated with ip: {ip} were found', {}, {}
    context_data = results_to_context_data(results, to_list=True)
    title = f'{INTEGRATION_NAME} - IP: {ip} search results.'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.IPRelatedObjects(val.ReferenceID && val.ReferenceID === obj.ReferenceID)':
            context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    view = args.get('view')
    max_results = args.get('page_size', 50)
    next_page_id = args.get('next_page_id')
    if not zone and not next_page_id:
        raise DemistoException('To run this command either a zone or a next page ID must be given')
    raw_response = client.list_response_policy_zone_rules(zone, view, max_results, next_page_id)
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
            f'{INTEGRATION_CONTEXT_NAME}.RulesNextPage(val.NextPageID !== obj.NextPageID)': {  # type: ignore
                'NextPageID': new_next_page_id}
        })
    human_readable = tableToMarkdown(title, fixed_keys_rule_list,
                                     headerTransform=pascalToSpace, removeNull=True)
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
    results = raw_response.get('result')
    if not results:
        return f'{INTEGRATION_NAME} - No Response Policy Zones were found', {}, {}
    context_data = results_to_context_data(results, to_list=True)
    display_first_x_results = f'(first {max_results} results)' if max_results else ''
    title = f'{INTEGRATION_NAME} - Response Policy Zones list {display_first_x_results}:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ResponsePolicyZones(val.FQDN && val.FQDN === obj.FQDN)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_response_policy_zone_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    fqdn = args.get('fqdn')
    rpz_policy = args.get('rpz_policy')
    rpz_severity = args.get('rpz_severity')
    substitute_name = args.get('substitute_name')
    rpz_type = args.get('rpz_type')
    if rpz_policy == 'SUBSTITUTE' and not substitute_name:
        raise DemistoException('Response policy zone with policy SUBSTITUTE requires a substitute name')
    raw_response = client.create_response_policy_zone(fqdn, rpz_policy, rpz_severity, substitute_name, rpz_type)
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone: {fqdn} has been created'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ResponsePolicyZones(val.FQDN && val.FQDN === obj.FQDN)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    view = args.get('view')

    # need to append 'rp_zone' or else this error is returned: "'<name>'. FQDN must belong to zone '<rp_zone>'."
    if name and not name.endswith(f'.{rp_zone}'):
        name = f'{name}.{rp_zone}'

    if rule_type == 'Substitute (domain name)' and not substitute_name:
        raise DemistoException('Substitute (domain name) rules requires a substitute name argument')
    raw_response = client.create_rpz_rule(rule_type, object_type, name, rp_zone, view, substitute_name, comment)
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace, removeNull=True)
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
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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

    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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

    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {context_data.get("Name")} has been enabled'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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

    results = raw_response.get('result', {})
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {context_data.get("Name")} has been disabled'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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
    results = raw_response.get('result')
    if not results:
        return f'No rules with name: {rule_name} of type: {object_type} were found', {}, raw_response
    context_data = results_to_context_data(results, to_list=True)
    title = f'{INTEGRATION_NAME} - Search result for: {rule_name}: '
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.RulesSearchResults(val.Name && val.Name === obj.Name)': context_data
    }
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
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


def list_hosts_command(client: Client, args: Dict):
    raw_response = client.list_hosts()
    results = raw_response.get('result')
    context_data = results_to_context_data(results, to_list=True)
    title = f'{INTEGRATION_NAME} - List of Host Records: '
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ListHosts(???)': context_data}

    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def list_records_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    zone = str(args.get('zone'))
    raw_response = client.list_records(zone)
    results = raw_response.get('result')
    context_data = results_to_context_data(results, to_list=True)
    title = f'{INTEGRATION_NAME} - List of All Records: '
    context = {f'{INTEGRATION_CONTEXT_NAME}.ListAllRecords(???)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def search_host_record_command(client: Client, args: Dict):
    name = str(args.get("name"))
    raw_response = client.search_host_record(name)
    results = raw_response.get("result")
    context_data = results_to_context_data(results, to_list=True)
    title = f'{INTEGRATION_NAME} - Search for a Host Record: {name}'
    context = {f'{INTEGRATION_CONTEXT_NAME}.SearchHostResults(???)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def create_a_record_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    name = args.get('name')
    ipv4addr = args.get('ipv4addr')
    infoblox_object_type = 'record:a'

    raw_response = client.create_record(infoblox_object_type, name=name, ipv4addr=ipv4addr)
    results = raw_response.get('result')
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Host Record: {name} has been created:'
    context = {f'{INTEGRATION_CONTEXT_NAME}.CreatedARecord(???)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)

    return human_readable, context, raw_response


def add_host_record_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    host = args.get('host')
    ipadd = args.get('ipadd')

    raw_response = client.add_host(host, ipadd)
    results = raw_response.get('result')
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Added a Host Record: {host} with IP address: {ipadd}'
    context = {f'{INTEGRATION_CONTEXT_NAME}.AddedHostRecord(???)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def update_host_ip_command(client: Client, args: Dict):
    refid = str(args.get("refid"))
    ipv4addr = str(args.get("ipv4addr"))
    raw_response = client.update_host_ip(refid, ipv4addr)
    results = raw_response.get('result')
    context_data = results_to_context_data(results, to_list=False)
    title = f'{INTEGRATION_NAME} - Updated a Host Record with the ReferenceID: {refid} with IP address: {ipv4addr}'
    context = {f'{INTEGRATION_CONTEXT_NAME}.UpdatedHostIP(???)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def update_a_record_command(client: Client, args: Dict):
    refid = str(args.get("refid"))
    ipv4addr = str(args.get("ipv4addr"))
    name = str(args.get("name"))
    comment = str(args.get("comment"))

    raw_response = client.update_a_record(refid, ipv4addr, name, comment)
    results = raw_response.get('result')
    title = f'{INTEGRATION_NAME} - Updated a Host Record with the ReferenceID: {refid} with IP address: {ipv4addr}'
    context_data = results_to_context_data(results, to_list=False)
    context = {f'{INTEGRATION_CONTEXT_NAME}.UpdatedARecord(???)': context_data}
    human_readable = tableToMarkdown(title, context_data, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def delete_host_record_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """

    refid = args.get('refid')

    if "/" in str(refid):
        refIDStr = str(refid).split("/")
        refIDStr = refIDStr[1].split(":")
        refid = refIDStr[0]

    if refid:
        raw_response = client.delete_host(refid)
        demisto.results(raw_response)
        title = f'{INTEGRATION_NAME} - ' + raw_response['result']
        return title, {}, {}
    else:
        title = f'{INTEGRATION_NAME} - No RefID'
        return title, {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    base_url = f"{params.get('url', '').rstrip('/')}/wapi/v2.3/"
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
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
        f'{INTEGRATION_COMMAND_NAME}-list-hosts': list_hosts_command,
        f'{INTEGRATION_COMMAND_NAME}-list-records': list_records_command,
        f'{INTEGRATION_COMMAND_NAME}-search-host-record': search_host_record_command,
        f'{INTEGRATION_COMMAND_NAME}-create-a-record': create_a_record_command,
        f'{INTEGRATION_COMMAND_NAME}-add-host-record': add_host_record_command,
        f'{INTEGRATION_COMMAND_NAME}-update-host-ip': update_host_ip_command,
        f'{INTEGRATION_COMMAND_NAME}-update-a-record': update_a_record_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-host-record': delete_host_record_command
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
