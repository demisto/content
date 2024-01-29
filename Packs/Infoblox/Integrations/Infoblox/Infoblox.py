from enum import Enum
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

''' IMPORTS '''
from typing import Any
from collections.abc import Callable

import urllib3
import ipaddress

# Disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'Infoblox Integration'
INTEGRATION_COMMAND_NAME = 'infoblox'
INTEGRATION_CONTEXT_NAME = 'Infoblox'
INTEGRATION_HOST_RECORDS_CONTEXT_NAME = "Host"
INTEGRATION_IPV4_CONTEXT_NAME = "IP"
RESULTS_LIMIT_DEFAULT = 50
REQUEST_PARAMS_RETURN_AS_OBJECT = {'_return_as_object': '1'}
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

NETWORK_NOT_FOUND = "A network was not found for this address"


class InvalidIPAddress(ValueError):
    pass


class InvalidNetmask(ValueError):
    pass


class InvalidIPRange(ValueError):
    pass


class IPv4AddressStatus(Enum):
    """Possible statuses for an IPv4 address."""
    ACTIVE = "ACTIVE"
    UNUSED = "UNUSED"
    USED = "USED"


class InfoBloxNIOSClient(BaseClient):

    GET_HOST_RECORDS_ENDPOINT = "record:host"
    IPV4ADDRESS_ENDPOINT = "ipv4address"

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=(), headers=None, auth=None, params=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
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

    def test_module(self) -> dict:
        """Performs basic GET request (List Response Policy Zones) to check if the API is reachable and authentication
        is successful.

        Returns:
            Response JSON
        """
        return self.list_response_policy_zones()

    def list_response_policy_zones(self, max_results: str | None = None) -> dict:
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

    def get_ipv4_address_from_ip(self, ip: str, status: str, ext_attrs: list[dict] | None) -> dict:
        """
        Get IPv4 information based on an IP address.
        Args:
        - `ip` (``str``): ip to retrieve.
        - `status` (``str``): status of the IP address.
        - `ext_attrs` (``list[dict]``): list of extended attribute dictionaries to include in request.

        Returns:
            Response JSON
        """

        # Dictionary of params for the request
        request_params = assign_params(ip_address=ip, status=status)

        if ext_attrs:
            request_params.update(REQUEST_PARAM_EXTRA_ATTRIBUTES)

            for e in ext_attrs:
                request_params.update(e)

        return self._get_ipv4_addresses(params=request_params)

    def get_ipv4_address_from_netmask(self, network: str, status: str, ext_attrs: list[dict] | None) -> dict:
        """
        Get IPv4 network information based on a netmask.

        Args:
        - `network` (``str``): Netmask to retrieve the IPv4 for.
        - `status` (``str``): Status of the network.
        - `ext_attrs` (``list[dict]``): List of extended attribute dictionaries to include in request.

        Returns:
        - `dict` with response.
        """

        request_params = assign_params(network=network, status=status)

        if ext_attrs:
            request_params.update(REQUEST_PARAM_EXTRA_ATTRIBUTES)

            for e in ext_attrs:
                request_params.update(e)

        return self._get_ipv4_addresses(params=request_params)

    def get_ipv4_address_range(self, start_ip: str, end_ip: str, ext_attrs: list[dict] | None) -> dict:
        """
        Get IPv4 address range information based on a start and end IP.

        Args:
        - `start_ip` (``str``): Start IP of the range.
        - `end_ip` (``str``): End IP of the range.
        - `ext_attrs` (``list[dict]``): List of extended attribute dictionaries to include in request.

        Returns:
        - `dict` with response.
        """

        request_params = assign_params(transform_ipv4_range(start_ip, end_ip))

        if ext_attrs:
            request_params.update(REQUEST_PARAM_EXTRA_ATTRIBUTES)

            for e in ext_attrs:
                request_params.update(e)

        return self._get_ipv4_addresses(params=request_params)

    def _get_ipv4_addresses(self, params: dict[str, Any]) -> dict:
        return self._http_request('GET', self.IPV4ADDRESS_ENDPOINT, params=params)

    def search_related_objects_by_ip(self, ip: str | None, max_results: str | None) -> dict:
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

    def list_response_policy_zone_rules(self, zone: str | None, view: str | None, max_results: str | None,
                                        next_page_id: str | None) -> dict:
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

    def create_response_policy_zone(self, fqdn: str | None, rpz_policy: str | None,
                                    rpz_severity: str | None, substitute_name: str | None,
                                    rpz_type: str | None) -> dict:
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

    def delete_response_policy_zone(self, ref_id: str | None) -> dict:
        """Delete new response policy zone
        Args:
            ref_id: Zone reference id to delete.
        Returns:
            Response JSON
        """

        suffix = ref_id
        return self._http_request('DELETE', suffix)

    def create_rpz_rule(self, rule_type: str | None, object_type: str | None, name: str | None,
                        rp_zone: str | None, view: str | None, substitute_name: str | None,
                        comment: str | None = None) -> dict:
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
        canonical: str | None = ''
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

    def create_substitute_record_rule(self, suffix: str | None, **kwargs: str | int | None) -> dict:
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

    def change_rule_status(self, reference_id: str | None, disable: bool | None) -> dict:
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

    def get_object_fields(self, object_type: str | None) -> dict:
        """Retrieve a given object fields.
        Args:
            object_type: Infoblox object type
        Returns:
            Response JSON
        """
        request_params = {'_schema': object_type}
        suffix = object_type
        return self._http_request('GET', suffix, params=request_params)

    def search_rule(self, object_type: str | None, rule_name: str | None,
                    output_fields: str | None) -> dict:
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

    def delete_rpz_rule(self, reference_id: str | None) -> dict:
        """Deletes a rule by its reference id
        Args:
            reference_id: Rule reference ID
        Returns:
            Response JSON
        """

        suffix = reference_id
        return self._http_request('DELETE', suffix)

    def get_host_records(self, name: str | None, extattrs: list[dict] | None) -> dict:
        """
        Get the host records.

        Args:
        - `name` (``str``): Name of the host record to search for.
        - `extattrs` (``list[dict]``): List of extra attribute dicts with "name" and "value" keys.

        Returns:
        - Response JSON
        """

        params = assign_params(name=name)

        if extattrs:
            params.update(REQUEST_PARAM_EXTRA_ATTRIBUTES)

            for e in extattrs:
                params.update(e)

        return self._http_request('GET', self.GET_HOST_RECORDS_ENDPOINT, params=params)


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


def transform_ext_attrs(ext_attrs: str) -> list[dict] | None:
    """
    Helper function to transform the extension attributes.
    The user supplies a string of key/value pairs separated by commas.

    This function parses that string and returns a list of dictionaries with "name" and "value" keys.

    Args:
    - `ext_attrs` (`str`): The string of key/value pairs separated by commas.

    Returns:
    - `list[dict]` or `None`: A `list[dict]` representing the extension attributes.
    Returns `None` in case there were no delimiters present.

    For example:

    ```python
    >>>> transform_ext_attrs("Site=Tel-Aviv")
    [{"Site": "Tel-Aviv"}]

    >>>> transform_ext_attrs("IB Discovery Owned=EMEA,Site=Tel-Aviv")
    [{"*IB Discovery Owned": "EMEA", "*Site": "Tel-Aviv"}]
    ```
    """

    # In case there are no delimiters present in the input
    if "," not in ext_attrs and "=" not in ext_attrs:
        return None

    l_ext_attrs: list[dict] = []

    attributes = ext_attrs.split(",")

    for ext_attr in attributes:
        try:
            key, value = ext_attr.split("=")
            if key and value:
                l_ext_attrs.append({f"*{key.strip()}": value.strip()})
        except ValueError:
            demisto.error(f"Unable to parse ext_attrs: {ext_attrs}")
            continue

    return l_ext_attrs


def valid_ip(ip: str):
    """Validate IP address format"""

    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise InvalidIPAddress(f"'{ip}' is not a valid IPv4 address")


def valid_netmask(address: str):
    """Validate netmask format"""

    try:
        ipaddress.ip_network(address, strict=False)
    except ValueError:
        raise InvalidNetmask(f"'{address}' is not a valid netmask")


def valid_ip_range(from_ip: str, to_ip: str):
    """Validate IP range format"""
    try:
        from_address = ipaddress.IPv4Address(from_ip)
        to_address = ipaddress.IPv4Address(to_ip)
        list(ipaddress.summarize_address_range(from_address, to_address))
    except ValueError as err:
        raise InvalidIPRange(f"'{from_ip}' to '{to_ip}' is not a valid IPv4 range: {err}")


def transform_ipv4_range(from_ip: str, to_ip: str) -> list[dict[str, str]]:
    """Transform IPv4 range to list of IPs.

    Args:
        from_ip: Start of IPv4 range.
        to_ip: End of IPv4 range.

    Returns:
        List of IPv4 addresses in range.
    """

    return [
        {"ip_address>": from_ip},
        {"ip_address<": to_ip},
    ]


''' COMMANDS '''


def test_module_command(client: InfoBloxNIOSClient, *_) -> tuple[str, dict, dict]:
    client.test_module()
    return 'ok', {}, {}


def get_ip_command(client: InfoBloxNIOSClient, args: dict[str, str]) -> tuple[str, dict, dict]:
    """
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    ip = args.get('ip', None)
    network = args.get('network', None)
    from_ip = args.get('from_ip', None)
    to_ip = args.get('to_ip', None)

    # Input validation

    # If too many arguments are supplied, return an error
    if sum(arg is not None for arg in [ip, network, from_ip, to_ip]) > 1:
        raise ValueError("Please specify only one of the `ip`, `network` or `from_ip`/`to_ip` arguments")

    # If neither ip, network nor from/to_ip were specified, return an error.
    if not ip and not network and not (from_ip and to_ip):
        raise ValueError("Please specify either the `ip`, `network` or `from_ip`/`to_ip` argument")

    extended_attributes = transform_ext_attrs(args.get("extended_attrs")) if args.get("extended_attrs") else None
    # Check if the network/IPs supplied are valid.
    if ip:
        valid_ip(ip)
        status = args.get('status', IPv4AddressStatus.USED.value)
        raw_response = client.get_ipv4_address_from_ip(ip, status=status, ext_attrs=extended_attributes)
    elif network:
        valid_netmask(network)
        status = args.get('status', IPv4AddressStatus.USED.value)
        raw_response = client.get_ipv4_address_from_netmask(network, status=status, ext_attrs=extended_attributes)
    elif from_ip and to_ip:
        valid_ip_range(from_ip, to_ip)
        raw_response = client.get_ipv4_address_range(from_ip, to_ip, ext_attrs=extended_attributes)

    ip_list = raw_response.get('result')

    # If no IP object was returned
    if not ip_list:
        return f'{INTEGRATION_NAME} - Could not find any data corresponds to: {ip}', {}, {}
    fixed_keys_obj = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                      ip_list[0].items()}
    title = f'{INTEGRATION_NAME} - IP: {ip} info.'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_IPV4_CONTEXT_NAME}(val.ReferenceID && val.ReferenceID === obj.ReferenceID)': fixed_keys_obj}
    human_readable = tableToMarkdown(title, fixed_keys_obj, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def search_related_objects_by_ip_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def list_response_policy_zone_rules_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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
            f'{INTEGRATION_CONTEXT_NAME}.RulesNextPage(val.NextPageID !== obj.NextPageID)': {   # type: ignore
                'NextPageID': new_next_page_id}
        })
    human_readable = tableToMarkdown(title, fixed_keys_rule_list,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, context, raw_response


def list_response_policy_zones_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_response_policy_zone_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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
        raise DemistoException('Response policy zone with policy SUBSTITUTE requires a substitute name')
    raw_response = client.create_response_policy_zone(fqdn, rpz_policy, rpz_severity, substitute_name, rpz_type)
    zone = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           zone.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone: {fqdn} has been created'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ResponsePolicyZones(val.FQDN && val.FQDN === obj.FQDN)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def delete_response_policy_zone_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_rpz_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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
    rule = raw_response.get('result', {})
    fixed_keys_rule_res = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
    title = f'{INTEGRATION_NAME} - Response Policy Zone rule: {name} has been created:'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.ModifiedResponsePolicyZoneRules(val.Name && val.Name === obj.Name)': fixed_keys_rule_res}
    human_readable = tableToMarkdown(title, fixed_keys_rule_res, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, context, raw_response


def create_a_substitute_record_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_aaaa_substitute_record_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_mx_substitute_record_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_naptr_substitute_record_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_ptr_substitute_record_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_srv_substitute_record_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_txt_substitute_record_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_ipv4_substitute_record_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def create_ipv6_substitute_record_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def enable_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def disable_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def get_object_fields_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def search_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def delete_rpz_rule_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict]:
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


def get_host_records_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict[str, Any]]:
    """
    Get host records.

    Args:
    - `client` (``InfoBloxNIOSClient``): Client object
    - `args` (``dict``): Usually demisto.args()

    Returns:
    - `Tuple[str, Dict, Dict]`: The human readable output, the records and the raw response.
    """

    hostname = args.get("host_name", None)
    extension_attributes = args.get("extattrs", None)
    max_records = args.get("max_records", RESULTS_LIMIT_DEFAULT)

    # We need to add an asterisk (*) to the extension attributes
    if extension_attributes:
        extension_attributes = transform_ext_attrs(extension_attributes)

    raw = client.get_host_records(name=hostname, extattrs=extension_attributes)
    records = raw.get("result", [])[:max_records]

    demisto.debug(f"Found {len(records)} host records")

    if not hostname:
        title = f"Host records (first {max_records})"
    else:
        title = f"Host records for {hostname} (first {max_records})"

    human_readable = tableToMarkdown(title, records)

    demisto.debug(f"returning human readable: {str(human_readable)}")
    demisto.debug(f"returning records: {str(records)}")
    demisto.debug(f"returning raw: {str(raw)}")

    if records:
        context = {
            f"{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_HOST_RECORDS_CONTEXT_NAME}(val._ref && val._ref === obj._ref)": records
        }
    else:
        human_readable = "No host records found"
        context = {}

    return human_readable, context, raw


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    base_url = f"{params.get('url', '').rstrip('/')}/wapi/v2.3/"
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    user = demisto.get(params, 'credentials.identifier')
    password = demisto.get(params, 'credentials.password')
    client = InfoBloxNIOSClient(
        base_url,
        verify=verify,
        proxy=proxy,
        auth=(user, password),
        params=REQUEST_PARAMS_RETURN_AS_OBJECT
    )
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    # Switch case
    commands: dict[str, Callable[[InfoBloxNIOSClient, dict[str, str]], tuple[str, dict[Any, Any], dict[Any, Any]]]] = {
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
        f'{INTEGRATION_COMMAND_NAME}-list-host-info': get_host_records_command
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
