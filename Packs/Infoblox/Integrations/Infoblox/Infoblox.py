import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from enum import Enum, unique


import json

''' IMPORTS '''
from typing import Any, cast
from collections.abc import Callable

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'Infoblox Integration'
INTEGRATION_COMMAND_NAME = 'infoblox'
INTEGRATION_CONTEXT_NAME = 'Infoblox'
INTEGRATION_HOST_RECORDS_CONTEXT_NAME = "Host"
INTEGRATION_NETWORK_INFO_CONTEXT_KEY = "NetworkInfo"
INTEGRATION_AUTHORIZATION_EXCEPTION_MESSAGE = "Authorization error, check your credentials."

# COMMON RAW RESULT KEYS
INTEGRATION_COMMON_RAW_RESULT_REFERENCE_KEY = "_ref"
INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY = "extattrs"
INTEGRATION_COMMON_RAW_RESULT_NETWORK_KEY = "network"
INTEGRATION_COMMON_RAW_RESULT_NETWORKVIEW_KEY = "network_view"

# COMMON CONTEXT KEYS
INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY = "Reference"
INTEGRATION_COMMON_REFERENCE_ID_CONTEXT_KEY = "ReferenceID"
INTEGRATION_COMMON_NAME_CONTEXT_KEY = "Name"
INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY = "ExtendedAttributes"
INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY = "AdditionalFields"
INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY = "NetworkView"

# IP RAW RESULT KEYS
INTEGRATION_IP_RAW_RESULT_MAC_ADDRESS_KEY = "mac_address"
INTEGRATION_IP_RAW_RESULT_NETWORK = "network"
INTEGRATION_IP_RAW_RESULT_STATUS_KEY = "status"
INTEGRATION_IP_RAW_RESULT_FQDN_KEY = "fqdn"
INTEGRATION_IP_RAW_RESULT_RP_ZONE_KEY = "rp_zone"
INTEGRATION_IP_RAW_RESULT_IS_CONFLICT_KEY = "is_conflict"
INTEGRATION_IP_RAW_RESULT_OBJECTS_KEY = "objects"
INTEGRATION_IP_RAW_RESULT_TYPES_KEY = "types"
INTEGRATION_IP_RAW_RESULT_NAMES_KEY = "names"
INTEGRATION_IP_RAW_RESULT_IP_ADDRESS_KEY = "ip_address"
INTEGRATION_IP_RAW_RESULT_USAGE_KEY = "usage"

# IP CONTEXT KEYS
INTEGRATION_IP_RP_ZONE_CONTEXT_KEY = "Zone"
INTEGRATION_IP_FQDN_CONTEXT_KEY = "FQDN"


IP_MAPPING = {
    INTEGRATION_COMMON_RAW_RESULT_REFERENCE_KEY: INTEGRATION_COMMON_REFERENCE_ID_CONTEXT_KEY,
    INTEGRATION_IP_RAW_RESULT_MAC_ADDRESS_KEY: string_to_context_key(INTEGRATION_IP_RAW_RESULT_MAC_ADDRESS_KEY),
    INTEGRATION_COMMON_RAW_RESULT_NETWORK_KEY: string_to_context_key(INTEGRATION_COMMON_RAW_RESULT_NETWORK_KEY),
    INTEGRATION_COMMON_RAW_RESULT_NETWORKVIEW_KEY: string_to_context_key(INTEGRATION_COMMON_RAW_RESULT_NETWORKVIEW_KEY),
    INTEGRATION_IP_RAW_RESULT_TYPES_KEY: string_to_context_key(INTEGRATION_IP_RAW_RESULT_TYPES_KEY),
    INTEGRATION_IP_RAW_RESULT_NAMES_KEY: string_to_context_key(INTEGRATION_IP_RAW_RESULT_NAMES_KEY),
    INTEGRATION_IP_RAW_RESULT_OBJECTS_KEY: string_to_context_key(INTEGRATION_IP_RAW_RESULT_OBJECTS_KEY),
    INTEGRATION_IP_RAW_RESULT_STATUS_KEY: string_to_context_key(INTEGRATION_IP_RAW_RESULT_STATUS_KEY),
    INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY: string_to_context_key(INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY),  # noqa: E501
    INTEGRATION_IP_RAW_RESULT_IP_ADDRESS_KEY: string_to_context_key(INTEGRATION_IP_RAW_RESULT_IP_ADDRESS_KEY),
    INTEGRATION_IP_RAW_RESULT_USAGE_KEY: string_to_context_key(INTEGRATION_IP_RAW_RESULT_USAGE_KEY),
    INTEGRATION_IP_RAW_RESULT_IS_CONFLICT_KEY: string_to_context_key(INTEGRATION_IP_RAW_RESULT_IS_CONFLICT_KEY),
    INTEGRATION_IP_RAW_RESULT_FQDN_KEY: INTEGRATION_IP_FQDN_CONTEXT_KEY,
    INTEGRATION_IP_RAW_RESULT_RP_ZONE_KEY: INTEGRATION_IP_RP_ZONE_CONTEXT_KEY
}

# Host info mapping
INTEGRATION_HOST_RECORDS_RAW_RESULT_IPV4ADDRESSES_KEY = "ipv4addrs"
INTEGRATION_HOST_RECORDS_RAW_RESULT_IPV4ADDRESS_KEY = "ipv4addr"
INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY = "IPv4Address"
INTEGRATION_HOST_RECORDS_RAW_RESULT_CONFIGURE_FOR_DHCP_KEY = "configure_for_dhcp"
INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY = "ConfigureForDHCP"
INTEGRATION_HOST_RECORDS_RAW_RESULT_NAME_KEY = "name"
INTEGRATION_HOST_RECORDS_RAW_RESULT_HOST_KEY = "host"
INTEGRATION_HOST_RECORDS_RAW_RESULT_VIEW_KEY = "view"
HOST_INFO_MAPPING: dict[str, str] = {
    INTEGRATION_COMMON_RAW_RESULT_REFERENCE_KEY: INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY,
    INTEGRATION_HOST_RECORDS_RAW_RESULT_IPV4ADDRESS_KEY: INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY,
    INTEGRATION_HOST_RECORDS_RAW_RESULT_CONFIGURE_FOR_DHCP_KEY: INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY,
    INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY: INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY,
    INTEGRATION_HOST_RECORDS_RAW_RESULT_HOST_KEY: INTEGRATION_COMMON_NAME_CONTEXT_KEY
}


# Network info mapping

INTEGRATION_COMMON_RAW_RESULT_NETWORKVIEW_KEY = "network_view"
INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY = "NetworkView"
NETWORK_INFO_MAPPING: dict[str, str] = {
    INTEGRATION_COMMON_RAW_RESULT_REFERENCE_KEY: INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY,
    INTEGRATION_COMMON_RAW_RESULT_NETWORK_KEY: INTEGRATION_COMMON_NAME_CONTEXT_KEY,
    INTEGRATION_COMMON_RAW_RESULT_NETWORKVIEW_KEY: INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY,
    INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY: INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY
}

INTEGRATION_IPV4_CONTEXT_NAME = "IP"
INTEGRATION_MAX_RESULTS_DEFAULT = 50

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


@unique
class IPv4AddressStatus(Enum):
    """Possible statuses for an IPv4 address."""
    ACTIVE = "ACTIVE"
    UNUSED = "UNUSED"
    USED = "USED"


def inject_cookies(func: Callable) -> Callable:
    """
    Decorator to manage session persistence and handle authentication for API requests.

    This decorator attempts to execute the provided function using existing session cookies
    stored in the 'integration_context'. If no valid cookies are available, or if the existing
    session is no longer valid the auth generate new cookies to save, bad credentials force the
    storage clean.

    The decorator handles saving and loading cookies between different executions, allowing for
    session persistence across multiple API calls.

    Args:
        func (Callable): The API request function to be executed.

    Raises:
        DemistoException: If the API request fails.

    Returns:
        Callable: The result from executing 'func' with the provided arguments and keyword arguments.
    """

    @wraps(wrapped=func)
    def wrapper(client: "InfoBloxNIOSClient", *args, **kwargs):

        def save_cookies_to_context(client: "InfoBloxNIOSClient") -> None:
            cookies_dict = {}
            for cookie in client._session.cookies:
                cookies_dict[cookie.name] = {
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path
                }
            set_integration_context({'cookies': cookies_dict})

        def load_cookies(client: "InfoBloxNIOSClient", cookies_dict: dict) -> None:
            for name, cookie_data in cookies_dict.items():
                client._session.cookies.set(
                    name,
                    cookie_data['value'],
                    domain=cookie_data['domain'],
                    path=cookie_data['path']
                )

        integration_context = get_integration_context()
        if (
            integration_context
            and (context_cookies := integration_context.get("cookies"))
        ):
            load_cookies(client, context_cookies)

        try:
            response = func(client, *args, **kwargs)
            save_cookies_to_context(client)
            return response
        except DemistoException as error:
            if error.message and error.message == INTEGRATION_AUTHORIZATION_EXCEPTION_MESSAGE:
                set_integration_context({})
            raise error

    return wrapper


class InfoBloxNIOSClient(BaseClient):

    REQUEST_PARAMS_RETURN_AS_OBJECT_KEY = '_return_as_object'
    REQUEST_PARAM_RETURN_FIELDS_KEY = '_return_fields+'

    REQUEST_PARAM_EXTRA_ATTRIBUTES = {REQUEST_PARAM_RETURN_FIELDS_KEY: INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY}
    REQUEST_PARAM_ZONE = {
        REQUEST_PARAM_RETURN_FIELDS_KEY: 'fqdn,rpz_policy,rpz_severity,rpz_type,substitute_name,comment,disable'
    }
    REQUEST_PARAM_CREATE_RULE = {REQUEST_PARAM_RETURN_FIELDS_KEY: 'name,rp_zone,comment,canonical,disable'}
    REQUEST_PARAM_LIST_RULES = {REQUEST_PARAM_RETURN_FIELDS_KEY: 'name,zone,comment,disable,type'}
    REQUEST_PARAM_SEARCH_RULES = {REQUEST_PARAM_RETURN_FIELDS_KEY: 'name,zone,comment,disable'}

    REQUEST_PARAM_PAGING_FLAG = {'_paging': '1'}
    REQUEST_PARAM_MAX_RESULTS_KEY = "_max_results"
    REQUEST_PARAM_MAX_RESULTS_VALUE_DEFAULT = 1000

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=(), headers=None, auth=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self.params: dict[str, Any] = {self.REQUEST_PARAMS_RETURN_AS_OBJECT_KEY: '1'}

    @inject_cookies
    def _http_request(  # type: ignore[override]
        self, method, url_suffix, full_url=None, headers=None, auth=None,
        json_data=None, params=None, data=None, files=None,
        timeout=10, resp_type='json', ok_codes=None, **kwargs
    ):
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

    def list_response_policy_zones(self, max_results: int | None = None) -> dict:
        """List all response policy zones.
        Args:
                max_results:  maximum number of results
        Returns:
            Response JSON
        """
        suffix = 'zone_rp'
        request_params = assign_params(_max_results=max_results)
        request_params.update(self.REQUEST_PARAM_ZONE)
        return self._http_request('GET', suffix, params=request_params)

    def get_ipv4_address_from_ip(
        self,
        ip: str,
        status: str,
        extended_attributes: Optional[str],
        max_results: Optional[int] = INTEGRATION_MAX_RESULTS_DEFAULT,
    ) -> dict:
        """
        Get IPv4 information based on an IP address.
        Args:
        - `ip` (``str``): ip to retrieve.
        - `status` (``str``): status of the IP address.
        - `extended_attributes` (``str``): comma-separated list of extended attributes to return.
        - `max_results` (``int``): maximum number of results to return.

        Returns:
            Response JSON
        """

        # Dictionary of params for the request
        request_params = assign_params(ip_address=ip, status=status, _max_results=max_results)

        # Add extended attributes param if provided
        if extended_attributes:
            request_params.update(self.REQUEST_PARAM_EXTRA_ATTRIBUTES)
            extended_attributes_params = transform_ext_attrs(extended_attributes)

            for e in extended_attributes_params:
                request_params.update(e)

        return self._get_ipv4_addresses(params=request_params)

    def get_ipv4_address_from_netmask(
        self,
        network: str,
        status: str,
        extended_attributes: Optional[str],
        max_results: Optional[int] = INTEGRATION_MAX_RESULTS_DEFAULT,
    ) -> dict:
        """
        Get IPv4 network information based on a netmask.

        Args:
        - `network` (``str``): Netmask to retrieve the IPv4 for.
        - `status` (``str``): Status of the network.
        - `extended_attributes` (``str``): comma-separated list of extended attributes to return.
        - `max_results` (``int``): maximum number of results to return.

        Returns:
        - `dict` with response.
        """

        request_params = assign_params(network=network, status=status, _max_results=max_results)

        # Add extended attributes param if provided
        if extended_attributes:
            request_params.update(self.REQUEST_PARAM_EXTRA_ATTRIBUTES)
            extended_attributes_params = transform_ext_attrs(extended_attributes)

            for e in extended_attributes_params:
                request_params.update(e)

        return self._get_ipv4_addresses(params=request_params)

    def get_ipv4_address_range(
        self,
        start_ip: str,
        end_ip: str,
        extended_attributes: Optional[str],
        max_results: Optional[int] = INTEGRATION_MAX_RESULTS_DEFAULT,
    ) -> dict:
        """
        Get IPv4 address range information based on a start and end IP.

        Args:
        - `start_ip` (``str``): Start IP of the range.
        - `end_ip` (``str``): End IP of the range.
        - `extended_attributes` (``str``): comma-separated list of extended attributes to return.
        - `max_results` (``int``): maximum number of results to return.

        Returns:
        - `dict` with response.
        """

        request_params = assign_params(_max_results=max_results)
        request_params.update(transform_ipv4_range(start_ip, end_ip))

        # Add extended attributes param if provided
        if extended_attributes:
            request_params.update(self.REQUEST_PARAM_EXTRA_ATTRIBUTES)
            extended_attributes_params = transform_ext_attrs(extended_attributes)

            for e in extended_attributes_params:
                request_params.update(e)

        return self._get_ipv4_addresses(params=request_params)

    def _get_ipv4_addresses(self, params: dict[str, Any]) -> dict:
        return self._http_request('GET', "ipv4address", params=params)

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
        request_params.update(self.REQUEST_PARAM_PAGING_FLAG)
        request_params.update(self.REQUEST_PARAM_LIST_RULES)

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
        return self._http_request('POST', "zone_rp", data=json.dumps(data), params=self.REQUEST_PARAM_ZONE)

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
        request_params = self.REQUEST_PARAM_CREATE_RULE
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
        return self._http_request('PUT', suffix, data=json.dumps(request_data), params=self.REQUEST_PARAM_SEARCH_RULES)

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

    def get_host_records(
        self,
        name: str | None,
        additional_return_fields: str,
        extended_attributes: Optional[str],
        max_results: Optional[int] = INTEGRATION_MAX_RESULTS_DEFAULT,
    ) -> dict:
        """
        Get the host records.

        Args:
        - `name` (``str``): Name of the host record to search for.
        - `additional_return_fields` (``Optional[str]``): Comma-separated list of additional fields to return.
        - `extended_attributes` (``str``): comma-separated list of extended attributes to return.
        - `max_results` (``int``): maximum number of results to return.

        Returns:
        - Response JSON
        """

        request_params = assign_params(name=name, _max_results=max_results)
        request_params.update({self.REQUEST_PARAM_RETURN_FIELDS_KEY: additional_return_fields})

        # Add extended attributes param if provided
        if extended_attributes:

            # If the extended attributes return field is not specified
            # add it.
            if INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY not in request_params.get(self.REQUEST_PARAM_RETURN_FIELDS_KEY):  # noqa: E501
                request_params[self.REQUEST_PARAM_RETURN_FIELDS_KEY] += f",{INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY}"  # noqa: E501
            extended_attributes_params = transform_ext_attrs(extended_attributes)

            for e in extended_attributes_params:
                request_params.update(e)

        return self._http_request('GET', "record:host", params=request_params)

    def get_network_info(
        self,
        pattern: str | None,
        additional_return_fields: Optional[str],
        extended_attributes: Optional[str],
        max_results: Optional[int] = INTEGRATION_MAX_RESULTS_DEFAULT,
    ) -> dict:
        """
        Get the network information.

        Args:
        - `pattern` (``str | None``): Filter networks by pattern, e.g. '.0/24' for netmask, '192.168' for subnet.
        - `additional_return_fields` (``Optional[str]``): Comma-separated list of additional fields to return.
        - `extended_attributes` (``str``): comma-separated list of extended attributes to return.
        - `max_results` (``int``): maximum number of results to return.

        Returns:
        - Response JSON
        """

        request_params = assign_params(_max_results=max_results)

        if pattern:
            request_params["network~"] = pattern

        request_params.update({self.REQUEST_PARAM_RETURN_FIELDS_KEY: additional_return_fields})

        # Add extended attributes param if provided
        if extended_attributes:
            # If the extended attributes return field is not specified
            # add it.
            if INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY not in request_params.get(self.REQUEST_PARAM_RETURN_FIELDS_KEY):  # noqa: E501
                request_params[self.REQUEST_PARAM_RETURN_FIELDS_KEY] += f",{INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY}"  # noqa: E501
            extended_attributes_params = transform_ext_attrs(extended_attributes)

            for e in extended_attributes_params:
                request_params.update(e)

        return self._http_request("GET", "network", params=request_params)


''' HELPER FUNCTIONS '''


def parse_demisto_exception(error: DemistoException, field_in_error: str = 'text'):
    err_msg = err_string = error.args[0]
    if '[401]' in err_string:
        err_msg = INTEGRATION_AUTHORIZATION_EXCEPTION_MESSAGE
    elif 'Failed to parse json object' in err_string:
        err_msg = 'Cannot connect to Infoblox server, check your proxy and connection.'
    elif 'Error in API call' in err_string:
        err_lines = err_string.split('\n')
        infoblox_err = err_lines[1] if len(err_lines) > 1 else '{}'
        infoblox_json = json.loads(infoblox_err)
        err_msg = infoblox_json.get(field_in_error, 'text') if infoblox_json else err_string
    return DemistoException(err_msg)


def transform_ext_attrs(ext_attrs: str) -> list:
    """
    Helper function to transform the extension attributes.
    The user supplies a string of key/value pairs separated by commas.

    This function parses that string and returns a list of dictionaries with "name" and "value" keys.

    Args:
    - `ext_attrs` (`str`): The string of key/value pairs separated by commas.

    Returns:
    - `list[dict]` or `None`: A `list[dict]` representing the extension attributes.
    Returns `None` in case there were no delimiters present. If the attributes
    cannot be parsed, an exception is raised.

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
        return []

    l_ext_attrs: list[dict] = []

    attributes = ext_attrs.split(",")

    for ext_attr in attributes:
        try:
            key, value = ext_attr.split("=")
            if key and value:
                l_ext_attrs.append({f"*{key.strip()}": value.strip()})
        except ValueError:
            raise DemistoException(f"Unable to parse provided {ext_attrs=}. Expected format is 'ExtKey1=ExtVal1,ExtKeyN=ExtValN'")

    return l_ext_attrs


def transform_ipv4_range(from_ip: str, to_ip: str) -> dict[str, str]:
    """Transform IPv4 range to list of IPs.

    Args:
        from_ip: Start of IPv4 range.
        to_ip: End of IPv4 range.

    Returns:
        dictionary of IPv4 addresses in range.
    """

    return {"ip_address>": from_ip, "ip_address<": to_ip}


def transform_network_info_context(network_info: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Helper function to transform the network info
    raw response to the expected context structure.

    Args:
    - `network_info` (``list[dict[str, Any]]``): The network info request result.

    Returns:
    - `list[dict[str, Any]]` context output.
    """

    output: list[dict[str, Any]] = []
    additional_options: list[dict[str, Any]] = []

    for network in network_info:
        n: dict[str, Any] = {}
        for k, v in network.items():
            if k == INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY:
                n[NETWORK_INFO_MAPPING[k]] = get_extended_attributes_context(v)
            elif k in NETWORK_INFO_MAPPING:
                n[NETWORK_INFO_MAPPING[k]] = v
            else:
                additional_options.append(v)
        if additional_options:
            n[INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY] = additional_options
        output.append(n)

    return output


def transform_ip_context(ip_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Helper function to transform the IP info
    raw response to the expected context structure.

    Args:
    - `network_info` (``list[dict[str, Any]]``): The network info request result.

    Returns:
    - `list[dict[str, Any]]` context output.
    """

    output: list[dict[str, Any]] = []

    for ip in ip_list:
        i: dict[str, Any] = {}
        for k, v in ip.items():
            key_transform = IP_MAPPING[k] if IP_MAPPING.get(k) else string_to_context_key(k)
            i[key_transform] = v
        output.append(i)

    return output


def transform_host_records_context(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Helper function to transform the host records
    raw response to the expected context structure.

    Args:
    - `records` (``list[dict[str, Any]]``): The host records request result.

    Returns:
    - `list[dict[str, Any]]` context output.
    """

    output: list[dict[str, Any]] = []
    additional_options: list[dict[str, Any]] = []

    for record in records:
        r: dict[str, Any] = {}
        for record_key, record_value in record.items():
            # We're interested in the ref ID of the first host address
            ipv4_addresses = record.get(INTEGRATION_HOST_RECORDS_RAW_RESULT_IPV4ADDRESSES_KEY, [])

            # We're not interested in these fields
            if record_key == INTEGRATION_COMMON_RAW_RESULT_REFERENCE_KEY:
                continue
            elif record_key == INTEGRATION_HOST_RECORDS_RAW_RESULT_VIEW_KEY:
                continue
            elif record_key == INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY:
                r[NETWORK_INFO_MAPPING[record_key]] = get_extended_attributes_context(record_value)
            elif record_key == INTEGRATION_HOST_RECORDS_RAW_RESULT_IPV4ADDRESSES_KEY:
                # We're interested in the first host address
                ipv4_addresses = record.get(INTEGRATION_HOST_RECORDS_RAW_RESULT_IPV4ADDRESSES_KEY, [])

                if ipv4_addresses:
                    first_address: dict[str, Any] = ipv4_addresses[0]
                    try:
                        for k, v in first_address.items():
                            r[HOST_INFO_MAPPING[k]] = v
                    except KeyError as err:
                        demisto.debug(f"Unable to parse key '{err}' from first host record address {str(record)}: {err}")

            elif record_key == INTEGRATION_HOST_RECORDS_RAW_RESULT_NAME_KEY:
                r[INTEGRATION_COMMON_NAME_CONTEXT_KEY] = record_value
            else:
                # TODO take this out to a new function as it's used twice
                additional_options.append({string_to_context_key(record_key): record_value})
        if additional_options:
            r[INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY] = additional_options

        output.append(r)

    return output


def get_extended_attributes_context(v: dict[str, Any]) -> dict:
    """
    Helper function to transform extended attributes.

    Extended attributes are returned in the following structure:

    ```json
    {
        "EXTATTR_KEY_1": {
            "value": "EXTATTR_VALUE_1"
        },
        "EXTATTR_KEY_2": {
            "value": "EXTATTR_VALUE_2"
        }
    }
    ```

    This method returns it in the following strucutre:

    ```json
    {
        "EXTATTR_KEY_1": "EXTATTR_VALUE_1",
        "EXTATTR_KEY_2": "EXTATTR_VALUE_2"
    }
    ```

    Args:
    - `v` (``dict[str, Any]``): The extended attributes dict to process.

    Returns:
    - `dict[str, Any]` Extended attributes in the expected context structure.

    """

    ext_attr_value = {}

    if isinstance(v, dict) and v:
        for ext_attr_key, ext_attr_val in v.items():
            if isinstance(ext_attr_val, dict) and ext_attr_val.get("value"):
                ext_attr_value[ext_attr_key] = cast(dict[str, Any], ext_attr_val).get("value")
            else:
                ext_attr_value[ext_attr_key] = "N/A"

    return ext_attr_value


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
    ip = args.get('ip')
    network = args.get('network')
    from_ip = args.get('from_ip')
    to_ip = args.get('to_ip')
    max_results = arg_to_number(args.get('max_results', INTEGRATION_MAX_RESULTS_DEFAULT), required=False)

    # Input validation

    # If too many arguments are supplied, return an error
    if sum(bool(arg) for arg in [ip, network, from_ip or to_ip]) > 1:
        raise ValueError("Please specify only one of the `ip`, `network` or `from_ip`/`to_ip` arguments")

    # If neither ip, network nor from/to_ip were specified, return an error.
    elif not any([ip, network, from_ip and to_ip]):
        raise ValueError("Please specify either the `ip`, `network` or `from_ip`/`to_ip` argument")

    extended_attributes = args.get("extended_attrs")

    if ip:
        status = args.get('status', IPv4AddressStatus.USED.value)
        raw_response = client.get_ipv4_address_from_ip(
            ip,
            status=status,
            max_results=max_results,
            extended_attributes=extended_attributes
        )
    elif network:
        status = args.get('status', IPv4AddressStatus.USED.value)
        raw_response = client.get_ipv4_address_from_netmask(
            network,
            status=status,
            max_results=max_results,
            extended_attributes=extended_attributes
        )
    elif from_ip and to_ip:
        raw_response = client.get_ipv4_address_range(
            from_ip,
            to_ip,
            max_results=max_results,
            extended_attributes=extended_attributes
        )
    else:
        raw_response = {}
        demisto.debug(f"No condition was met, {raw_response=}")

    ip_list = raw_response.get('result')

    if not ip_list:
        human_readable = f'{INTEGRATION_NAME} - Could not find any data'
        context = {}
    else:
        output = transform_ip_context(ip_list)
        title = f'{INTEGRATION_NAME}'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_IPV4_CONTEXT_NAME}': output
        }
        human_readable = tableToMarkdown(title, output)
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
    max_results = args.get('page_size', INTEGRATION_MAX_RESULTS_DEFAULT)
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
    max_results = arg_to_number(args.get('max_results', INTEGRATION_MAX_RESULTS_DEFAULT), required=False)
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
    - `tuple[str, Dict, Dict]`: The human readable output, the records and the raw response.
    """

    hostname = args.get("host_name")
    max_results = arg_to_number(args.get("max_results", INTEGRATION_MAX_RESULTS_DEFAULT))
    additional_return_fields = args.get("additional_return_fields", INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY)
    extended_attributes = args.get(INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY)

    raw = client.get_host_records(
        name=hostname,
        additional_return_fields=additional_return_fields,
        extended_attributes=extended_attributes,
        max_results=max_results
    )

    if 'Error' in raw:
        msg = raw.get("text")
        raise DemistoException(f"Error retrieving host records: {msg}", res=raw)

    records = raw.get("result", [])

    demisto.debug(f"Found {len(records)} host records")

    title = "Host records"

    if records:
        outputs = transform_host_records_context(records)
        context = {
            f"{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_HOST_RECORDS_CONTEXT_NAME}": outputs
        }
        human_readable = tableToMarkdown(title, outputs)
    else:
        human_readable = "No host records found"
        context = {}

    return human_readable, context, raw


def get_network_info_command(client: InfoBloxNIOSClient, args: dict) -> tuple[str, dict, dict[str, Any]]:
    """
    Get network information command.

    Args:
    - `client` (``InfoBloxNIOSClient``): Client object
    - `args` (``dict``): Usually demisto.args()

    Returns:
    - `tuple[str, Dict, Dict]`: The human readable output, the records and the raw response.
    """

    pattern = args.get("pattern")
    max_results = arg_to_number(args.get("max_results", INTEGRATION_MAX_RESULTS_DEFAULT))
    additional_return_fields = args.get("additional_return_fields", INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY)
    extended_attributes = args.get(INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY)

    raw_response = client.get_network_info(
        pattern,
        additional_return_fields=additional_return_fields,
        extended_attributes=extended_attributes,
        max_results=max_results
    )

    if 'Error' in raw_response:
        msg = raw_response.get("text")
        raise DemistoException(f"Error retrieving host records: {msg}", res=raw_response)

    network_info = raw_response.get("result")

    if not network_info:
        hr = "No networks found"
        context = {}
    else:
        output = transform_network_info_context(network_info)
        hr = tableToMarkdown("Network information", output)
        context = {
            f"{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_NETWORK_INFO_CONTEXT_KEY}": output
        }

    return hr, context, raw_response


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
        auth=(user, password)
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
        f'{INTEGRATION_COMMAND_NAME}-list-host-info': get_host_records_command,
        f'{INTEGRATION_COMMAND_NAME}-list-network-info': get_network_info_command
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
