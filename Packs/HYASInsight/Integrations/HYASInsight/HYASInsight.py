from typing import Tuple, Callable

from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CORTEX XSOAR COMMAND CONSTANTS
INTEGRATION_NAME = 'HYAS INSIGHT'
INTEGRATION_COMMAND_NAME = 'hyas'
INTEGRATION_CONTEXT_NAME = 'HYAS'
PASSIVE_DNS_SUB_CONTEXT = 'PassiveDNS'
DYNAMIC_DNS_SUB_CONTEXT = 'DynamicDNS'
WHOIS_SUB_CONTEXT = 'WHOIS'
WHOIS_CURRENT_SUB_CONTEXT = 'WHOISCurrent'
MALWARE_SUB_CONTEXT = 'MalwareSamples'
HASH_IP_SUB_CONTEXT = 'HASH-IP'
HASH_DOMAIN_SUB_CONTEXT = 'HASH-DOMAIN'
C2_ATTRIBUTION_SUB_CONTEXT = "C2_Attribution"

# HYAS API BASE URL
HYAS_API_BASE_URL = 'https://insight.hyas.com/api/ext/'
WHOIS_CURRENT_BASE_URL = "https://api.hyas.com/"
TIMEOUT = 60

# HYAS API endpoints
PASSIVE_DNS_ENDPOINT = 'passivedns'
DYNAMIC_DNS_ENDPOINT = 'dynamicdns'
WHOIS_ENDPOINT = 'whois'
MALWARE_ENDPOINT = 'sample'
WHOIS_CURRENT_ENDPOINT = 'whois/v1'
C2_ATTRIBUTION_ENDPOINT = "c2attribution"

# HYAS API INPUT PARAMETERS
PASSIVE_DNS_QUERY_PARAMS = ['domain', 'ipv4']
DYNAMIC_DNS_QUERY_PARAMS = ['ip', 'domain', 'email']
WHOIS_QUERY_PARAMS = ['domain', 'email', 'phone']
MALWARE_QUERY_PARAMS = ['domain', 'ipv4', 'md5']
C2_ATTRIBUTION_QUERY_PARAMS = ['domain', 'ip', 'email', 'sha256']
DOMAIN_PARAM = 'domain'
MD5_PARAM = 'md5'
IP_PARAM = 'ip'
IPV4_PARAM = 'ipv4'
EMAIL_PARAM = 'email'
PHONE_PARAM = 'phone'
SHA256 = 'sha256'


class Client(BaseClient):
    def __init__(self, base_url: str, apikey: str, verify=None, proxy=None):
        BaseClient.__init__(
            self,
            base_url,
            verify=verify,
            headers={
                'Content-type': 'application/json',
                'X-API-Key': apikey,
            },
            proxy=proxy,
            ok_codes=(200,),
        )
        self.apikey = apikey

    def fetch_data_from_hyas_api(self, end_point: str, ind_type: str,
                                 ind_value: str, current: bool,
                                 req_method: str, limit=0) -> List[Dict]:
        """

        :param limit: "limit the number of records returned, default to 50"
        :param end_point: HYAS endpoint
        :param ind_type: indicator_type provided in the command
        :param ind_value: indicator_value provided in the command
        :param current: boolean for whois endpoint
        :param req_method: request method POST,GET
        :return: return the raw api response from HYAS API.
        """
        return self.query(end_point, ind_type, ind_value, current, req_method,
                          limit)

    def query(self, end_point: str, ind_type: str, ind_value: str,
              current: bool, method: str, limit: int) -> List[Dict]:
        """

        :param limit: "limit the number of records returned, default to 50"
        :param end_point: HYAS endpoint
        :param ind_type: indicator_type provided in the command
        :param ind_value: indicator_value provided in the command
        :param current: boolean for whois endpoint
        :param method: request method POST,GET
        :return: return the raw api response from HYAS API.

        """
        response = []
        if method == 'GET':
            url_path = f'{end_point}/search?{ind_type}={ind_value}'
            response = self._http_request(
                'GET',
                url_suffix=url_path,
                timeout=TIMEOUT
            )
        elif method == 'POST':
            url_path = f'{end_point}'
            req_body = self.request_body(ind_type, ind_value, current)
            response = self._http_request(
                'POST',
                url_suffix=url_path,
                json_data=req_body,
                timeout=TIMEOUT
            )
        if limit != 0:
            return response[:limit]
        return response

    @staticmethod
    def request_body(query_param: str, query_input: str, current: bool) -> Dict[str, Any]:
        """
        This Method returns the request body for specific endpoint.
        """

        if current:
            return {
                'applied_filters': {
                    query_param: query_input,
                    'current': True
                }
            }
        else:
            return {
                'applied_filters': {
                    query_param: query_input
                }
            }

    def test_module(self, domain: str, value: str) -> str:
        """
        :param domain: hard coded domain type
        :param value: hard coded domain value
        :return: connection ok

        """

        try:
            self.query(DYNAMIC_DNS_ENDPOINT, domain, value, False, 'POST', 2)
        except DemistoException as e:
            if '401' in str(e):
                return 'Authorization Error: Provided apikey is not valid'
            else:
                raise e
        return 'ok'


def flatten_json(y: Dict) -> Dict[str, Any]:
    """
    :param y: raw_response from HYAS api
    :return: Flatten json response

    """
    out = {}

    def flatten(x, name=''):
        # If the Nested key-value
        # pair is of dict type
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '_')
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def check_valid_indicator_type(indicator_type: str,
                               api_query_params: list) -> bool:
    """
    :param indicator_type: indicator type provided in the command
    :param api_query_params: HYAS API Endpoint query params constant defined
    :return: True if the indicator type is valid

    """
    if indicator_type not in api_query_params:
        raise ValueError(
            f'Invalid indicator_type: {indicator_type}, Valid indicator_type are {api_query_params}')
    return True


def check_valid_indicator_value(indicator_type: str,
                                indicator_value: str) -> bool:
    """

    :param indicator_type: Indicator type provided in the command
    :param indicator_value: Indicator value provided in the command
    :return: true if the indicator value provided for the indicator type is valid

    """
    # not using default urlRegex for domain validation as it is failing in some cases, for example
    # 'fluber12.duckdns.org' is validated as invalid
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)'  # Sub domain + hostname
        r'+[A-Za-z0-9][A-Za-z0-9-_]{0,61}'  # First 61 characters of the gTLD
        r'[A-Za-z]$'  # Last character of the gTLD
    )

    phone_regex = re.compile(r'^\+?[1-9]\d{1,14}$')

    if indicator_type == IPV4_PARAM:
        if not re.match(ipv4Regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == DOMAIN_PARAM:
        if not re.match(domain_regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == IP_PARAM:
        if not re.match(ipv4Regex, indicator_value):
            if not re.match(ipv6Regex, indicator_value):
                raise ValueError(
                    f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == EMAIL_PARAM:
        if not re.match(emailRegex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == MD5_PARAM:
        if not re.match(md5Regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == PHONE_PARAM:
        if not re.match(phone_regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == SHA256:
        if not re.match(sha256Regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')

    return True


def get_command_title_string(sub_context: str, indicator_type: str,
                             indicator_value: str) -> str:
    """

    :param sub_context: Commands sub_context
    :param indicator_type: Indicator type provided in the command
    :param indicator_value: Indicator value provided in the command
    :return: returns the title for the readable output

    """
    return INTEGRATION_CONTEXT_NAME + " " + sub_context + " records for " + indicator_type + " : " + indicator_value


def get_flatten_json_response(raw_api_response: List[Dict]) -> List[Dict]:
    """

    :param raw_api_response: raw_api response from the API
    :return: Flatten Json response

    """
    flatten_json_response = []
    if raw_api_response:
        for obj in raw_api_response:
            flatten_json_response.append(flatten_json(obj))

    return flatten_json_response


@logger
def passive_dns_build_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('count', 'count', str),
            ('domain', 'domain', str),
            ('first_seen', 'first_seen', str),
            ('ip', 'ip', dict),
            ('ipv4', 'ipv4', str),
            ('last_seen', 'last_seen', str),
            ('sources', 'sources', list),

    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    return ctx


@logger
def passive_dns_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('Count', 'count', str),
        ('Domain', 'domain', str),
        ('First seen', 'first_seen', str),
        ('City Name', 'ip_geo_city_name', str),
        ('Country Code', 'ip_geo_country_iso_code', str),
        ('Country Name', 'ip_geo_country_name', str),
        ('Latitude', 'ip_geo_location_latitude', str),
        ('Longitude', 'ip_geo_location_longitude', str),
        ('Postal Code', 'ip_geo_postal_code', str),
        ('IP', 'ip_ip', str),
        ('ISP ASN', 'ip_isp_autonomous_system_number', str),
        ('ISP ASN Organization', 'ip_isp_autonomous_system_organization', str),
        ('ISP IP Address', 'ip_isp_ip_address', str),
        ('ISP', 'ip_isp_isp', str),
        ('ISP Organization', 'ip_isp_organization', str),
        ('IPV4', 'ipv4', str),
        ('Last Seen', 'last_seen', str),
        ('Sources', 'sources', list),

    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def dynamic_dns_build_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('a_record', 'a_record', str),
            ('account', 'account', str),
            ('created', 'created', str),
            ('created_ip', 'created_ip', str),
            ('domain', 'domain', str),
            ('domain_creator_ip', 'domain_creator_ip', str),
            ('email', 'email', str),

    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    return ctx


@logger
def dynamic_dns_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('A Record', 'a_record', str),
        ('Account', 'account', str),
        ('Created Date', 'created', str),
        ('Account Holder IP Address', 'created_ip', str),
        ('Domain', 'domain', str),
        ('Domain Creator IP Address', 'domain_creator_ip', str),
        ('Email Address', 'email', str),

    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def whois_historic_build_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('address', 'address', list),
            ('city', 'city', list),
            ('country', 'country', list),
            ('domain', 'domain', str),
            ('domain_2tld', 'domain_2tld', str),
            ('domain_created_datetime', 'domain_created_datetime', str),
            ('domain_expires_datetime', 'domain_expires_datetime', str),
            ('domain_updated_datetime', 'domain_updated_datetime', str),
            ('email', 'email', list),
            ('idn_name', 'idn_name', str),
            ('nameserver', 'nameserver', list),
            ('phone', 'phone', list),
            ('privacy_punch', 'privacy_punch', bool),
            ('registrar', 'registrar', str),

    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    return ctx


@logger
def whois_historic_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('Address', 'address', list),
        ('City', 'city', list),
        ('Country', 'country', list),
        ('Domain', 'domain', str),
        ('Domain_2tld', 'domain_2tld', str),
        ('Domain Created Time', 'domain_created_datetime', str),
        ('Domain Expires Time', 'domain_expires_datetime', str),
        ('Domain Updated Time', 'domain_updated_datetime', str),
        ('Email Address', 'email', list),
        ('IDN Name', 'idn_name', str),
        ('Nameserver', 'nameserver', list),
        ('Phone Info', 'phone', list),
        ('Privacy_punch', 'privacy_punch', bool),
        ('Registrar', 'registrar', str),

    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def whois_current_build_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('abuse_emails', 'abuse_emails', list),
            ('address', 'address', list),
            ('city', 'city', list),
            ('country', 'country', list),
            ('domain', 'domain', str),
            ('domain_2tld', 'domain_2tld', str),
            ('domain_created_datetime', 'domain_created_datetime', str),
            ('domain_expires_datetime', 'domain_expires_datetime', str),
            ('domain_updated_datetime', 'domain_updated_datetime', str),
            ('email', 'email', list),
            ('idn_name', 'idn_name', str),
            ('nameserver', 'nameserver', list),
            ('organization', 'organization', list),
            ('phone', 'phone', list),
            ('registrar', 'registrar', str),
            ('state', 'state', list),
    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    return ctx


@logger
def whois_current_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('Abuse Emails', 'abuse_emails', list),
        ('Address', 'address', list),
        ('City', 'city', list),
        ('Country', 'country', list),
        ('Domain', 'domain', str),
        ('Domain_2tld', 'domain_2tld', str),
        ('Domain Created Time', 'domain_created_datetime', str),
        ('Domain Expires Time', 'domain_expires_datetime', str),
        ('Domain Updated Time', 'domain_updated_datetime', str),
        ('Email Address', 'email', list),
        ('IDN Name', 'idn_name', str),
        ('Nameserver', 'nameserver', list),
        ('Organization', 'organization', list),
        ('Phone Info', 'phone', list),
        ('Registrar', 'registrar', str),
        ('State', 'state', list),

    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def malware_samples_build_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('datetime', 'datetime', str),
            ('domain', 'domain', str),
            ('ipv4', 'ipv4', str),
            ('ipv6', 'ipv6', str),
            ('md5', 'md5', str),
            ('sha1', 'sha1', str),
            ('sha256', 'sha256', str),

    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    return ctx


@logger
def malware_samples_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('Datetime', 'datetime', str),
        ('Domain', 'domain', str),
        ('IPV4 Address', 'ipv4', str),
        ('IPV6 Address', 'ipv6', str),
        ('MD5 Value', 'md5', str),
        ('SHA1 Value', 'sha1', str),
        ('SHA256 Value', 'sha256', str),

    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def associated_ips_build_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('Associated IPs', 'ips', str),
    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    return ctx


@logger
def associated_ips_lookup_to_markdown(results: List, title: str) -> str:
    headers = 'Associated IPs'
    out = results
    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def associated_domains_build_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('Associated Domains', 'domains', str),
    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    return ctx


@logger
def associated_domains_lookup_to_markdown(results: List[Dict],
                                          title: str) -> str:
    headers = 'Associated Domains'
    out = results
    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def c2_attribution_build_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('actor_ipv4', 'actor_ipv4', str),
            ('c2_domain', 'c2_domain', str),
            ('c2_ip', 'c2_ip', str),
            ('c2_url', 'c2_url', str),
            ('datetime', 'datetime', str),
            ('email', 'email', str),
            ('email_domain', 'email_domain', str),
            ('referrer_domain', 'referrer_domain', str),
            ('referrer_ipv4', 'referrer_ipv4', str),
            ('referrer_url', 'referrer_url', str),
            ('sha256', 'sha256', str)

    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]
    return ctx


@logger
def c2_attribution_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('Actor IPv4', 'actor_ipv4', str),
        ('C2 Domain', 'c2_domain', str),
        ('C2 IP', 'c2_ip', str),
        ('C2 URL', 'c2_url', str),
        ('Datetime', 'datetime', str),
        ('Email', 'email', str),
        ('Email Domain', 'email_domain', str),
        ('Referrer Domain', 'referrer_domain', str),
        ('Referrer IPv4', 'referrer_ipv4', str),
        ('Referrer URL', 'referrer_url', str),
        ('SHA256', 'sha256', str)

    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def get_c2_attribution_record_by_indicator(client, args):
    flatten_json_response = []
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(indicator_type, C2_ATTRIBUTION_QUERY_PARAMS)
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(C2_ATTRIBUTION_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = C2_ATTRIBUTION_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response)
    outputs_key_field = {
        "ip": "actor_ipv4",
        "domain": "c2_domain",
        "email": "email",
        "sha256": "sha256"
    }

    return CommandResults(
        readable_output=c2_attribution_lookup_to_markdown(flatten_json_response,
                                                          title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{C2_ATTRIBUTION_SUB_CONTEXT}',
        outputs_key_field=outputs_key_field.get(indicator_type),
        outputs=[c2_attribution_build_result_context(r) for r in
                 raw_api_response],
    )


@logger
def get_passive_dns_records_by_indicator(client, args):
    flatten_json_response = []
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(indicator_type, PASSIVE_DNS_QUERY_PARAMS)
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(PASSIVE_DNS_SUB_CONTEXT, indicator_type,
                                     indicator_value)

    end_point = PASSIVE_DNS_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response)

    return CommandResults(
        readable_output=passive_dns_lookup_to_markdown(flatten_json_response,
                                                       title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{PASSIVE_DNS_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=[passive_dns_build_result_context(r) for r in raw_api_response],
    )


@logger
def get_dynamic_dns_records_by_indicator(client, args):
    flatten_json_response = []
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(indicator_type, DYNAMIC_DNS_QUERY_PARAMS)
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(DYNAMIC_DNS_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = DYNAMIC_DNS_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response)

    return CommandResults(
        readable_output=dynamic_dns_lookup_to_markdown(flatten_json_response,
                                                       title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{DYNAMIC_DNS_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=[dynamic_dns_build_result_context(r) for r in raw_api_response],
    )


@logger
def get_whois_records_by_indicator(client, args):
    flatten_json_response = []
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(indicator_type, WHOIS_QUERY_PARAMS)
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(WHOIS_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = WHOIS_ENDPOINT

    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response)

    return CommandResults(
        readable_output=whois_historic_lookup_to_markdown(flatten_json_response,
                                                          title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{WHOIS_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=[whois_historic_build_result_context(r) for r in
                 raw_api_response],
    )


@logger
def get_whois_current_records_by_domain(client, args):
    whois_current_record: List[Any] = []
    indicator_type = DOMAIN_PARAM
    indicator_value = args.get('domain')
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(WHOIS_CURRENT_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = WHOIS_CURRENT_ENDPOINT

    api_response = client.fetch_data_from_hyas_api(end_point, indicator_type,
                                                   indicator_value, True,
                                                   'POST')
    if api_response:
        whois_current_record = api_response["items"] if api_response[
            "items"] else []

    return CommandResults(
        readable_output=whois_current_lookup_to_markdown(whois_current_record,
                                                         title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{WHOIS_CURRENT_SUB_CONTEXT}',
        outputs_key_field='domain',
        outputs=[whois_current_build_result_context(r) for r in
                 whois_current_record],
    )


@logger
def get_malware_samples_records_by_indicator(client, args):
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(indicator_type, MALWARE_QUERY_PARAMS)
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(MALWARE_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = MALWARE_ENDPOINT

    api_response = client.fetch_data_from_hyas_api(end_point, indicator_type,
                                                   indicator_value, False,
                                                   'POST', limit)

    return CommandResults(
        readable_output=malware_samples_lookup_to_markdown(api_response, title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{MALWARE_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=[malware_samples_build_result_context(r) for r in api_response],
    )


@logger
def get_associated_ips_by_hash(client, args):
    indicator_type = MD5_PARAM
    indicator_value = args.get('md5')
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(HASH_IP_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = MALWARE_ENDPOINT
    api_response = client.fetch_data_from_hyas_api(end_point, indicator_type,
                                                   indicator_value, False,
                                                   'POST')

    associated_ips = [str(obj['ipv4']) for obj in api_response if obj['ipv4']]
    outputs = {'md5': indicator_value, 'ips': associated_ips}
    return CommandResults(
        readable_output=associated_ips_lookup_to_markdown(associated_ips,
                                                          title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{HASH_IP_SUB_CONTEXT}',
        outputs_key_field='md5',
        outputs=outputs,
    )


@logger
def get_associated_domains_by_hash(client, args):
    indicator_type = MD5_PARAM
    indicator_value = args.get('md5')

    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(HASH_DOMAIN_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = MALWARE_ENDPOINT
    api_response = client.fetch_data_from_hyas_api(end_point, indicator_type,
                                                   indicator_value, False,
                                                   'POST')
    associated_domains = [str(obj['domain']) for obj in api_response if
                          obj['domain']]
    outputs = {'md5': indicator_value, 'domains': associated_domains}
    return CommandResults(
        readable_output=associated_domains_lookup_to_markdown(
            associated_domains, title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{HASH_DOMAIN_SUB_CONTEXT}',
        outputs_key_field='md5',
        outputs=outputs,
    )


@logger
def test_module(client):
    return client.test_module('domain', 'www.hyas.com')


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    apikey = demisto.params().get('X-API-Key')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    try:
        command = demisto.command()
        if command == f'{INTEGRATION_COMMAND_NAME}-get-whois-current-records-by-domain':
            base_url = WHOIS_CURRENT_BASE_URL
        else:
            base_url = HYAS_API_BASE_URL
        client = Client(
            base_url,
            apikey,
            verify=verify_certificate,
            proxy=proxy)
        LOG(f'Command being called is {command}')
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-passive-dns-records-by-indicator':
            return_results(
                get_passive_dns_records_by_indicator(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-dynamic-dns-records-by-indicator':
            return_results(
                get_dynamic_dns_records_by_indicator(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-whois-records-by-indicator':
            return_results(
                get_whois_records_by_indicator(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-whois-current-records-by-domain':
            return_results(
                get_whois_current_records_by_domain(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-malware-samples-records-by-indicator':
            return_results(get_malware_samples_records_by_indicator(client,
                                                                    demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-associated-ips-by-hash':
            return_results(get_associated_ips_by_hash(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-associated-domains-by-hash':
            return_results(
                get_associated_domains_by_hash(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-c2attribution-records-by-indicator':
            return_results(
                get_c2_attribution_record_by_indicator(client, demisto.args()))
    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
