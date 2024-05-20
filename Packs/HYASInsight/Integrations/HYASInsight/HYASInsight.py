from typing import Callable, Tuple  # noqa:F401
from urllib3 import disable_warnings
from CommonServerPython import *

# Disable insecure warnings
disable_warnings()

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
PASSIVE_HASH_SUB_CONTEXT = "Passive_Hash"
SSL_CERTIFICATE_SUB_CONTEXT = "SSL_Certificate"
OS_INDICATORS_SUB_CONTEXT = "OS_Indicators"
DEVICE_GEO_SUB_CONTEXT = "Device_Geo"
SINKHOLE_SUB_CONTEXT = "Sinkhole"
MALWARE_INFO_SUB_CONTEXT = "Malware_Information"
# HYAS API BASE URL
HYAS_API_BASE_URL = 'https://apps.hyas.com/api/ext/'
WHOIS_CURRENT_BASE_URL = "https://api.hyas.com/"
TIMEOUT = 60

# HYAS API endpoints
PASSIVE_DNS_ENDPOINT = 'passivedns'
DYNAMIC_DNS_ENDPOINT = 'dynamicdns'
WHOIS_ENDPOINT = 'whois'
MALWARE_ENDPOINT = 'sample'
WHOIS_CURRENT_ENDPOINT = 'whois/v1'
C2_ATTRIBUTION_ENDPOINT = "c2attribution"
PASSIVE_HASH_ENDPOINT = "passivehash"
SSL_CERTIFICATE_ENDPOINT = "ssl_certificate"
OS_INDICATORS_ENDPOINT = "os_indicators"
DEVICE_GEO_ENDPOINT = "device_geo"
SINKHOLE_ENDPOINT = "sinkhole"
MALWARE_INFO_ENDPOINT = "sample/information"

# HYAS API INPUT PARAMETERS
PASSIVE_DNS_QUERY_PARAMS = ['domain', 'ipv4']
DYNAMIC_DNS_QUERY_PARAMS = ['ip', 'domain', 'email']
WHOIS_QUERY_PARAMS = ['domain', 'email', 'phone']
MALWARE_QUERY_PARAMS = ['domain', 'ipv4', 'md5']
C2_ATTRIBUTION_QUERY_PARAMS = ['domain', 'ip', 'email', 'sha256']
PASSIVE_HASH_QUERY_PARAMS = ['domain', 'ipv4']
SSL_CERTIFICATE_QUERY_PARAMS = ['domain', 'ip', 'sha1']
OS_INDICATORS_QUERY_PARAMS = ['domain', 'ipv4', 'ipv6', 'sha1', 'sha256', 'md5']
DEVICE_GEO_QUERY_PARAMS = ['ipv4', 'ipv6']
SINKHOLE_QUERY_PARAMS = ['ipv4']
MALWARE_INFO_QUERY_PARAMS = ['hash']

DOMAIN_PARAM = 'domain'
IP_PARAM = 'ip'
IPV4_PARAM = 'ipv4'
IPV6_PARAM = 'ipv6'
EMAIL_PARAM = 'email'
PHONE_PARAM = 'phone'
MD5_PARAM = 'md5'
SHA1_PARAM = 'sha1'
SHA256_PARAM = 'sha256'
SHA512_PARAM = 'sha512'
HASH_PARAM = 'hash'


class Client(BaseClient):
    def __init__(self, base_url: str, apikey: str, verify=None, proxy=None):
        BaseClient.__init__(
            self,
            base_url,
            verify=verify,
            headers={
                'Content-type': 'application/json',
                'X-API-Key': apikey,
                'User-Agent': 'Cortex XSOAR'
            },
            proxy=proxy,
            ok_codes=(200,),
        )
        self.apikey = apikey

    def fetch_data_from_hyas_api(self, end_point: str, ind_type: str,
                                 ind_value: str, current: bool,
                                 req_method: str, limit=0) -> list[Dict]:
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
              current: bool, method: str, limit: int) -> list[Dict]:
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


def check_valid_hash_type(hash_type: list, hash_value: str, check_all: bool = False):
    """
        :param hash_type: hash_type
        :param hash_value: hash_value
        :param check_all: test all the values
        :return: true if the hash value is valid

        """
    if not check_all:
        if MD5_PARAM in hash_type:
            if not re.match(md5Regex, hash_value):
                raise ValueError(
                    f'Invalid indicator_value: {hash_value} for indicator_type {MD5_PARAM}')
        elif SHA1_PARAM in hash_type:
            if not re.match(sha1Regex, hash_value):
                raise ValueError(
                    f'Invalid indicator_value: {hash_value} for indicator_type {SHA1_PARAM}')
        elif SHA256_PARAM in hash_type:
            if not re.match(sha256Regex, hash_value):
                raise ValueError(
                    f'Invalid indicator_value: {hash_value} for indicator_type {SHA256_PARAM}')
        elif SHA512_PARAM in hash_type and not re.match(sha512Regex, hash_value):
            raise ValueError(
                f'Invalid indicator_value: {hash_value} for indicator_type {SHA512_PARAM}')
    else:
        if re.match(md5Regex, hash_value) or re.match(sha1Regex, hash_value) \
                or re.match(sha256Regex, hash_value) or re.match(sha512Regex, hash_value):
            pass
        else:
            raise ValueError(
                f'Invalid indicator_value: {hash_value} for indicator_type {HASH_PARAM}')


def check_valid_indicator_value(indicator_type: str,
                                indicator_value: str) -> bool:
    """

    :param indicator_type: Indicator type provided in the command
    :param indicator_value: Indicator value provided in the command
    :return: true if the indicator value provided for the indicator type is valid

    """

    phone_regex = re.compile(r'^\+?[1-9]\d{1,14}$')

    if indicator_type == IPV4_PARAM:
        if not re.match(ipv4Regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == IPV6_PARAM:
        if not re.match(ipv6Regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == DOMAIN_PARAM:
        if not re.match(domainRegex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == IP_PARAM:
        if not is_ip_valid(indicator_value, accept_v6_ips=True):  # check IP's validity
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == EMAIL_PARAM:
        if not re.match(emailRegex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == PHONE_PARAM:
        if not re.match(phone_regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value} for indicator_type {indicator_type}')
    elif indicator_type == MD5_PARAM:
        check_valid_hash_type([MD5_PARAM], indicator_value)
    elif indicator_type == SHA1_PARAM:
        check_valid_hash_type([SHA1_PARAM], indicator_value)
    elif indicator_type == SHA256_PARAM:
        check_valid_hash_type([SHA256_PARAM], indicator_value)
    elif indicator_type == SHA512_PARAM:
        check_valid_hash_type([SHA512_PARAM], indicator_value)
    elif indicator_type == HASH_PARAM:
        check_valid_hash_type([MD5_PARAM, SHA1_PARAM, SHA256_PARAM, SHA512_PARAM], indicator_value, True)

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


def get_flatten_json_response(raw_api_response: list[Dict], endpoint: str) -> \
        list[Dict]:
    """

    :param raw_api_response: raw_api response from the API
    :param endpoint: Endpoint
    :return: Flatten Json response

    """
    flatten_json_response = []
    if raw_api_response:
        for obj in raw_api_response:
            if endpoint == OS_INDICATORS_ENDPOINT:
                data = json.loads(obj.get("data", "{}"))
                obj = {**obj, **data}
            flatten_json_response.append(flatten_json(obj))

    return flatten_json_response


@logger
def passive_dns_lookup_to_markdown(results: list[Dict], title: str) -> str:
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
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def dynamic_dns_lookup_to_markdown(results: list[Dict], title: str) -> str:
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
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def whois_historic_lookup_to_markdown(results: list[Dict], title: str) -> str:
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
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def whois_current_lookup_to_markdown(results: list[Dict], title: str) -> str:
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
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def malware_samples_lookup_to_markdown(results: list[Dict], title: str) -> str:
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
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def associated_ips_lookup_to_markdown(results: list, title: str) -> str:
    headers = 'Associated IPs'
    out = results
    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def associated_domains_lookup_to_markdown(results: list[Dict],
                                          title: str) -> str:
    headers = 'Associated Domains'
    out = results
    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def c2_attribution_lookup_to_markdown(results: list[Dict], title: str) -> str:
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
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def passive_hash_lookup_to_markdown(results: list[Dict], title: str) -> str:
    out = []

    keys = [
        ('Domain', 'domain', str),
        ('MD5 Count', 'md5_count', str)
    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def ssl_certificate_lookup_to_markdown(results: list[Dict], title: str) -> str:
    out = []

    keys = [
        ('Geo City Name', 'geo_geo_city_name', str),
        ('Geo Country ISO code', 'geo_geo_country_iso_code', str),
        ('Geo Country Name', 'geo_geo_country_name', str),
        ('Latitude', 'geo_geo_location_latitude', str),
        ('Longitude', 'geo_geo_location_longitude', str),
        ('Postal Code', 'geo_geo_postal_code', str),
        ('ISP Autonomous System Number',
         'geo_isp_autonomous_system_number', str),
        ('ISP Autonomous System Organization',
         'geo_isp_autonomous_system_organization', str),
        ('Geo ISP', 'geo_isp_isp', str),
        ('Geo ISP Organization', 'geo_isp_organization', str),
        ('IP', 'ip', str),
        ('SSL Certificate Key', 'ssl_cert_cert_key', str),
        ('Expire Date', 'ssl_cert_expire_date', str),
        ('Issue Date', 'ssl_cert_issue_date', str),
        ('Issuer Common Name', 'ssl_cert_issuer_commonName', str),
        ('Issuer Country Name', 'ssl_cert_issuer_countryName', str),
        ('Issuer Locality Name', 'ssl_cert_issuer_localityName', str),
        ('Issuer Organization Name', 'ssl_cert_issuer_organizationName',
         str),
        ('Issuer Organizational UnitName',
         'ssl_cert_issuer_organizationalUnitName', str),
        ('Issuer State/Province Name',
         'ssl_cert_issuer_stateOrProvinceName', str),
        ('Certificate MD5', 'ssl_cert_md5', str),
        ('Certificate Serial Number', 'ssl_cert_serial_number', str),
        ('Certificate SHA1', 'ssl_cert_sha1', str),
        ('Certificate SHA256', 'ssl_cert_sha_256', str),
        ('Certificate Signature Algo', 'ssl_cert_sig_algo', str),
        ('Certificate SSL Version', 'ssl_cert_ssl_version', str),
        ('Certificate Subject Common Name',
         'ssl_cert_subject_commonName', str),
        ('Certificate Subject Country Name',
         'ssl_cert_subject_countryName', str),
        ('Certificate Subject Locality Name',
         'ssl_cert_subject_localityName', str),
        ('Certificate Subject Organization Name',
         'ssl_cert_subject_organizationName', str),
        ('Certificate Subject Organizational Unit Name',
         'ssl_cert_subject_organizationalUnitName', str),
        ('Certificate Subject State/Province Name',
         'ssl_cert_subject_stateOrProvinceName', str),
        ('Certificate Timestamp', 'ssl_cert_timestamp', str)
    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def open_source_indicators_lookup_to_markdown(results: list[Dict], title: str) -> str:
    out = []
    # print(results)
    keys = [
        ('Correlation Score', 'map_correlation_score', float),
        ('Host IP', 'map_host_ips_myArrayList', list),
        ('Nameserver', 'map_nameservers_myArrayList', list),
        ('Stub Count', 'map_stub_count', int),
        ('Type', 'map_type', str),
        ('Context', 'context', str),
        ('Date Time', 'datetime', str),
        ('Domain', 'domain', str),
        ('Domain 2TLD', 'domain_2tld', str),
        ('First Seen', 'first_seen', str),
        ('IPV4', 'ipv4', str),
        ('IPV6', 'ipv6', str),
        ('Last Seen', 'last_seen', str),
        ('MD5', 'md5', str),
        ('SHA1', 'sha1', str),
        ('SHA256', 'sha256', str),
        ('Source Name', 'source_name', str),
        ('Source Url', 'source_url', str),
        ('URI', 'uri', str)
    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def device_geo_indicators_lookup_to_markdown(results: list[Dict], title: str) -> str:
    out = []

    keys = [
        ('Date Time', 'datetime', str),
        ('Device User Agent', 'device_user_agent', str),
        ('Geo Country Alpha 2', 'geo_country_alpha_2', str),
        ('Geo Horizontal Accuracy', 'geo_horizontal_accuracy', str),
        ('IPV4', 'ipv4', str),
        ('IPV6', 'ipv6', str),
        ('Latitude', 'latitude', int),
        ('Longitude', 'longitude', int),
        ('WiFi BSSID', 'wifi_bssid', str)
    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def sinkhole_indicators_lookup_to_markdown(results: list[Dict], title: str) -> str:
    out = []

    keys = [
        ('Count', 'count', str),
        ('Country Name', 'country_name', str),
        ('Data Port', 'data_port', str),
        ('Date Time', 'datetime', str),
        ('IPV4', 'ipv4', str),
        ('Last Seen', 'last_seen', str),
        ('Organization Name', 'organization_name', str),
        ('Sink Source', 'sink_source', str)
    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = {}  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def malware_info_lookup_to_markdown(results: Dict, title: str) -> str:
    scan_results = results.get('scan_results', [])
    out = []
    if scan_results:
        for res in scan_results:
            malware_info_data = {
                "AV Scan Score": results.get(
                    "avscan_score", ''),
                "MD5": results.get("md5", ''),
                'AV Name': res.get(
                    "av_name", ''),
                'AV DateTime': res.get(
                    "def_time", ''),
                'Source': res.get(
                    'threat_found', ''),
                'Scan Time': results.get("scan_time", ''),
                'SHA1': results.get('sha1', ''),
                'SHA256': results.get('sha256', ''),
                'SHA512': results.get('sha512', '')
            }
            out.append(malware_info_data)
    else:
        malware_info_data = {
            "AV Scan Score": results.get("avscan_score", ''),
            "MD5": results.get("md5", ''),
            'AV Name': '',
            'AV DateTime': '',
            'Source': '',
            'Scan Time': results.get("scan_time", ''),
            'SHA1': results.get('sha1', ''),
            'SHA256': results.get('sha256', ''),
            'SHA512': results.get('sha512', '')
        }
        out.append(malware_info_data)

    headers = out[0]
    headers = list(headers.keys())
    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def get_malware_sample_information_by_hash(client, args):
    hash_value = args.get('hash')
    check_valid_indicator_type(HASH_PARAM, MALWARE_INFO_QUERY_PARAMS)
    check_valid_indicator_value(HASH_PARAM, hash_value)
    title = get_command_title_string(MALWARE_INFO_SUB_CONTEXT, HASH_PARAM,
                                     hash_value)
    end_point = MALWARE_INFO_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       HASH_PARAM,
                                                       hash_value, False,
                                                       'POST')
    lookup_result: str = ''
    if raw_api_response:
        lookup_result = malware_info_lookup_to_markdown(raw_api_response, title)
    return CommandResults(
        readable_output=lookup_result,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{MALWARE_INFO_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=raw_api_response,
    )


@logger
def get_sinkhole_records_by_ipv4_address(client, args):
    flatten_json_response = []
    ipv4_value = args.get('ipv4')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(IPV4_PARAM, SINKHOLE_QUERY_PARAMS)
    check_valid_indicator_value(IPV4_PARAM, ipv4_value)
    title = get_command_title_string(SINKHOLE_SUB_CONTEXT, IPV4_PARAM,
                                     ipv4_value)
    end_point = SINKHOLE_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       IPV4_PARAM,
                                                       ipv4_value, False,
                                                       'POST', limit)
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return CommandResults(
        readable_output=sinkhole_indicators_lookup_to_markdown(flatten_json_response,
                                                               title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{SINKHOLE_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=raw_api_response,
    )


@logger
def get_device_geo_records_by_ip_address(client, args):
    flatten_json_response = []
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(indicator_type, DEVICE_GEO_QUERY_PARAMS)
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(DEVICE_GEO_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = DEVICE_GEO_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return CommandResults(
        readable_output=device_geo_indicators_lookup_to_markdown(flatten_json_response,
                                                                 title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{DEVICE_GEO_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=raw_api_response,
    )


@logger
def get_opensource_indicator_records_by_indicator(client, args):
    flatten_json_response = []
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(indicator_type, OS_INDICATORS_QUERY_PARAMS)
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(OS_INDICATORS_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = OS_INDICATORS_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return CommandResults(
        readable_output=open_source_indicators_lookup_to_markdown(flatten_json_response,
                                                                  title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{OS_INDICATORS_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=raw_api_response,
    )


@logger
def get_ssl_certificate_records_by_indicator(client, args):
    flatten_json_response = []
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(indicator_type, SSL_CERTIFICATE_QUERY_PARAMS)
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(SSL_CERTIFICATE_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = SSL_CERTIFICATE_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', 0)
    if raw_api_response:
        raw_api_response = raw_api_response['ssl_certs']
        if limit and limit > 0:
            raw_api_response = raw_api_response[:limit]
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return CommandResults(
        readable_output=ssl_certificate_lookup_to_markdown(flatten_json_response,
                                                           title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{SSL_CERTIFICATE_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=raw_api_response,
    )


@logger
def get_passive_hash_records_by_indicator(client, args):
    flatten_json_response = []
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = arg_to_number(args.get('limit', 0), arg_name='limit')
    check_valid_indicator_type(indicator_type, PASSIVE_HASH_QUERY_PARAMS)
    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string(PASSIVE_HASH_SUB_CONTEXT, indicator_type,
                                     indicator_value)
    end_point = PASSIVE_HASH_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return CommandResults(
        readable_output=passive_hash_lookup_to_markdown(flatten_json_response,
                                                        title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{PASSIVE_HASH_SUB_CONTEXT}',
        outputs_key_field='domain',
        outputs=raw_api_response,
    )


@logger
def get_c2attribution_records_by_indicator(client, args):
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
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)
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
        outputs=raw_api_response,
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
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return CommandResults(
        readable_output=passive_dns_lookup_to_markdown(flatten_json_response,
                                                       title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{PASSIVE_DNS_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=raw_api_response,
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
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return CommandResults(
        readable_output=dynamic_dns_lookup_to_markdown(flatten_json_response,
                                                       title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{DYNAMIC_DNS_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=raw_api_response
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
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return CommandResults(
        readable_output=whois_historic_lookup_to_markdown(flatten_json_response,
                                                          title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{WHOIS_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=raw_api_response
    )


@logger
def get_whois_current_records_by_domain(client, args):
    whois_current_record: list[Any] = []
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
        whois_current_record = api_response.get("items", [])

    return CommandResults(
        readable_output=whois_current_lookup_to_markdown(whois_current_record,
                                                         title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{WHOIS_CURRENT_SUB_CONTEXT}',
        outputs_key_field='domain',
        outputs=api_response,
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
        outputs=api_response,
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

    associated_ips = [str(obj['ipv4']) for obj in api_response if 'ipv4' in obj]
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
    associated_domains: list[str] = [str(obj['domain']) for obj in api_response if 'domain' in obj]
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
                get_c2attribution_records_by_indicator(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-passive-hash-records-by-indicator':
            return_results(
                get_passive_hash_records_by_indicator(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-ssl-certificate-records-by-indicator':
            return_results(
                get_ssl_certificate_records_by_indicator(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-opensource-indicator-records-by-indicator':
            return_results(
                get_opensource_indicator_records_by_indicator(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-device-geo-records-by-ip-address':
            return_results(
                get_device_geo_records_by_ip_address(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-sinkhole-records-by-ipv4-address':
            return_results(
                get_sinkhole_records_by_ipv4_address(client, demisto.args()))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-malware-sample-information-by-hash':
            return_results(
                get_malware_sample_information_by_hash(client, demisto.args()))
            # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
